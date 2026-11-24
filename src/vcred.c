/* SPDX-License-Identifier: MIT */

#include "vcred.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#define VC_MAX 4096
#define OWN_MAX 8192

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static struct {
    pid_t pid;
    struct kbox_vcred c;
} g_vc[VC_MAX];
static int g_vc_n;

static struct {
    dev_t dev;
    ino_t ino;
    uint32_t uid, gid;
    int used;
} g_own[OWN_MAX];

static pid_t parent_of(pid_t pid)
{
    char path[48], buf[512];
    FILE *f;
    size_t n;
    char *p;
    long ppid;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    p = strrchr(buf, ')');
    if (!p || p[1] != ' ')
        return 0;
    /* fields after ')': state ppid ... */
    if (sscanf(p + 2, "%*c %ld", &ppid) != 1)
        return 0;
    return (pid_t) ppid;
}

static int find_locked(pid_t pid)
{
    for (int i = 0; i < g_vc_n; i++)
        if (g_vc[i].pid == pid)
            return i;
    return -1;
}

/* Index of pid's record, creating it from the nearest known ancestor. */
static int ensure_locked(pid_t pid)
{
    struct kbox_vcred c;
    pid_t cur = pid;
    int idx = find_locked(pid);

    if (idx >= 0)
        return idx;
    memset(&c, 0, sizeof(c)); /* root unless an ancestor says otherwise */
    c.had_root = 1;
    for (int depth = 0; depth < 16 && cur > 1; depth++) {
        pid_t pp = parent_of(cur);
        if (pp <= 1)
            break;
        int pi = find_locked(pp);
        if (pi >= 0) {
            c = g_vc[pi].c;
            break;
        }
        cur = pp;
    }
    if (g_vc_n == VC_MAX) {
        /* Full: recycle the oldest slot. */
        memmove(&g_vc[0], &g_vc[1], sizeof(g_vc[0]) * (VC_MAX - 1));
        g_vc_n--;
    }
    g_vc[g_vc_n].pid = pid;
    g_vc[g_vc_n].c = c;
    return g_vc_n++;
}

void kbox_vcred_get(pid_t pid, struct kbox_vcred *out)
{
    pthread_mutex_lock(&g_lock);
    *out = g_vc[ensure_locked(pid)].c;
    pthread_mutex_unlock(&g_lock);
}

static int in_set(uint32_t v, uint32_t a, uint32_t b, uint32_t c)
{
    return v == a || v == b || v == c;
}

int kbox_vcred_setresuid(pid_t pid, int64_t r, int64_t e, int64_t s)
{
    int rc = 0;
    pthread_mutex_lock(&g_lock);
    struct kbox_vcred *c = &g_vc[ensure_locked(pid)].c;
    if (c->euid != 0) {
        if ((r != -1 && !in_set((uint32_t) r, c->ruid, c->euid, c->suid)) ||
            (e != -1 && !in_set((uint32_t) e, c->ruid, c->euid, c->suid)) ||
            (s != -1 && !in_set((uint32_t) s, c->ruid, c->euid, c->suid)))
            rc = -1;
    }
    if (rc == 0) {
        if (r != -1)
            c->ruid = (uint32_t) r;
        if (e != -1)
            c->euid = (uint32_t) e;
        if (s != -1)
            c->suid = (uint32_t) s;
    }
    pthread_mutex_unlock(&g_lock);
    return rc ? -EPERM : 0;
}

int kbox_vcred_setresgid(pid_t pid, int64_t r, int64_t e, int64_t s)
{
    int rc = 0;
    pthread_mutex_lock(&g_lock);
    struct kbox_vcred *c = &g_vc[ensure_locked(pid)].c;
    if (c->euid != 0 && !c->had_root) {
        if ((r != -1 && !in_set((uint32_t) r, c->rgid, c->egid, c->sgid)) ||
            (e != -1 && !in_set((uint32_t) e, c->rgid, c->egid, c->sgid)) ||
            (s != -1 && !in_set((uint32_t) s, c->rgid, c->egid, c->sgid)))
            rc = -1;
    }
    if (rc == 0) {
        if (r != -1)
            c->rgid = (uint32_t) r;
        if (e != -1)
            c->egid = (uint32_t) e;
        if (s != -1)
            c->sgid = (uint32_t) s;
    }
    pthread_mutex_unlock(&g_lock);
    return rc ? -EPERM : 0;
}

int kbox_vcred_setuid(pid_t pid, int64_t u)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    if (c.euid == 0)
        return kbox_vcred_setresuid(pid, u, u, u); /* all three ids */
    return kbox_vcred_setresuid(pid, -1, u, -1);   /* euid only */
}

int kbox_vcred_setgid(pid_t pid, int64_t g)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    if (c.euid == 0 || c.had_root)
        return kbox_vcred_setresgid(pid, g, g, g);
    return kbox_vcred_setresgid(pid, -1, g, -1);
}

int kbox_vcred_setreuid(pid_t pid, int64_t r, int64_t e)
{
    struct kbox_vcred c;
    int64_t s = -1;
    kbox_vcred_get(pid, &c);
    /* Linux: saved id follows the new effective id when the real id is set
     * or the effective id differs from the old real id. */
    if (r != -1 || (e != -1 && (uint32_t) e != c.ruid))
        s = (e != -1) ? e : (int64_t) c.euid;
    if (c.euid != 0) {
        /* ruid may become ruid or euid; euid may become ruid, euid or suid. */
        if (r != -1 && !in_set((uint32_t) r, c.ruid, c.euid, c.euid))
            return -EPERM;
    }
    return kbox_vcred_setresuid(pid, r, e, s);
}

int kbox_vcred_setregid(pid_t pid, int64_t r, int64_t e)
{
    struct kbox_vcred c;
    int64_t s = -1;
    kbox_vcred_get(pid, &c);
    if (r != -1 || (e != -1 && (uint32_t) e != c.rgid))
        s = (e != -1) ? e : (int64_t) c.egid;
    if (c.euid != 0 && !c.had_root) {
        if (r != -1 && !in_set((uint32_t) r, c.rgid, c.egid, c.egid))
            return -EPERM;
    }
    return kbox_vcred_setresgid(pid, r, e, s);
}

int kbox_vcred_may_setgid(pid_t pid)
{
    struct kbox_vcred c;
    kbox_vcred_get(pid, &c);
    return c.euid == 0 || c.had_root;
}

int kbox_vcred_setgroups(pid_t pid, size_t n, const uint32_t *list)
{
    int idx;

    if (n > KBOX_VCRED_MAX_GROUPS)
        return -EINVAL;

    pthread_mutex_lock(&g_lock);
    idx = ensure_locked(pid);
    if (!(g_vc[idx].c.euid == 0 || g_vc[idx].c.had_root)) {
        pthread_mutex_unlock(&g_lock);
        return -EPERM;
    }
    if (n > 0)
        memcpy(g_vc[idx].c.groups, list, n * sizeof(uint32_t));
    g_vc[idx].c.ngroups = (uint32_t) n;
    g_vc[idx].c.groups_set = 1;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

/* The list getgroups reports: what setgroups stored, or the effective gid for a
 * process that never called it. */
static uint32_t groups_of(const struct kbox_vcred *c, uint32_t *out)
{
    if (!c->groups_set) {
        out[0] = c->egid;
        return 1;
    }
    if (c->ngroups > 0)
        memcpy(out, c->groups, c->ngroups * sizeof(uint32_t));
    return c->ngroups;
}

int kbox_vcred_group_count(pid_t pid)
{
    struct kbox_vcred c;
    uint32_t tmp[KBOX_VCRED_MAX_GROUPS];

    kbox_vcred_get(pid, &c);
    return (int) groups_of(&c, tmp);
}

int kbox_vcred_getgroups(pid_t pid, size_t size, uint32_t *out)
{
    struct kbox_vcred c;
    uint32_t count;

    kbox_vcred_get(pid, &c);
    count = groups_of(&c, out);
    if (size < count)
        return -EINVAL;
    return (int) count;
}

void kbox_vcred_forget(pid_t pid)
{
    pthread_mutex_lock(&g_lock);
    int i = find_locked(pid);
    if (i >= 0) {
        memmove(&g_vc[i], &g_vc[i + 1], sizeof(g_vc[0]) * (g_vc_n - i - 1));
        g_vc_n--;
    }
    pthread_mutex_unlock(&g_lock);
}

/* ---- guest ownership stored on host files ----------------------------- */

#define KBOX_OWNER_XATTR "user.kbox.owner"

int kbox_owner_xattr_format(char *buf, size_t len, int64_t uid, int64_t gid)
{
    int n;

    if (!buf || len == 0)
        return -EINVAL;
    n = snprintf(buf, len, "%lld:%lld", (long long) uid, (long long) gid);
    if (n < 0 || (size_t) n >= len)
        return -ENAMETOOLONG;
    return 0;
}

int kbox_owner_xattr_parse(const char *buf, int64_t *uid, int64_t *gid)
{
    char *end = NULL;
    long long u, g;

    if (!buf || !uid || !gid)
        return -EINVAL;
    errno = 0;
    u = strtoll(buf, &end, 10);
    if (errno != 0 || end == buf || *end != ':')
        return -EINVAL;
    const char *rest = end + 1;
    errno = 0;
    g = strtoll(rest, &end, 10);
    if (errno != 0 || end == rest || *end != '\0')
        return -EINVAL;
    if (u < 0 || g < 0)
        return -EINVAL;
    *uid = (int64_t) u;
    *gid = (int64_t) g;
    return 0;
}

/* Build the path the xattr calls work on: absolute paths are used as given, a
 * relative path is resolved through the supervisor's own descriptor, and an
 * empty path means the descriptor itself (fstatat's AT_EMPTY_PATH shape). */
static int owner_xattr_path(int dirfd, const char *path, char *out, size_t len)
{
    int n;

    if (!out || len == 0)
        return -EINVAL;
    if (!path || path[0] == '\0') {
        n = snprintf(out, len, "/proc/self/fd/%d", dirfd);
    } else if (path[0] == '/') {
        n = snprintf(out, len, "%s", path);
    } else {
        n = snprintf(out, len, "/proc/self/fd/%d/%s", dirfd, path);
    }
    if (n < 0 || (size_t) n >= len)
        return -ENAMETOOLONG;
    return 0;
}

int kbox_owner_xattr_get(int dirfd,
                         const char *path,
                         int nofollow,
                         int64_t *uid,
                         int64_t *gid)
{
    char full[1024];
    char value[64];
    ssize_t n;

    if (owner_xattr_path(dirfd, path, full, sizeof(full)) < 0)
        return 0;
    n = nofollow ? lgetxattr(full, KBOX_OWNER_XATTR, value, sizeof(value) - 1)
                 : getxattr(full, KBOX_OWNER_XATTR, value, sizeof(value) - 1);
    if (n < 0)
        return 0;
    value[n] = '\0';
    return kbox_owner_xattr_parse(value, uid, gid) == 0 ? 1 : 0;
}

int kbox_owner_xattr_set(int dirfd,
                         const char *path,
                         int nofollow,
                         int64_t uid,
                         int64_t gid)
{
    char full[1024];
    char value[64];
    int rc = owner_xattr_path(dirfd, path, full, sizeof(full));

    if (rc < 0)
        return rc;
    rc = kbox_owner_xattr_format(value, sizeof(value), uid, gid);
    if (rc < 0)
        return rc;
    if ((nofollow ? lsetxattr : setxattr)(full, KBOX_OWNER_XATTR, value,
                                          strlen(value), 0) < 0)
        return -errno;
    return 0;
}

void kbox_owner_record_host(pid_t pid,
                            int dirfd,
                            const char *path,
                            int nofollow,
                            const struct stat *st,
                            int64_t owner,
                            int64_t group)
{
    int64_t cur_uid = -1;
    int64_t cur_gid = -1;
    int64_t eff_uid;
    int64_t eff_gid;

    if (!st)
        return;
    if (owner == -1 && group == -1)
        return;
    if (owner == -1 || group == -1) {
        if (kbox_owner_xattr_get(dirfd, path, nofollow, &cur_uid, &cur_gid) !=
            1) {
            struct stat eff = *st;

            kbox_owner_apply(pid, &eff);
            cur_uid = (int64_t) eff.st_uid;
            cur_gid = (int64_t) eff.st_gid;
        }
    }
    eff_uid = (owner == -1) ? cur_uid : owner;
    eff_gid = (group == -1) ? cur_gid : group;
    kbox_owner_set(st->st_dev, st->st_ino, eff_uid, eff_gid);
    (void) kbox_owner_xattr_set(dirfd, path, nofollow, eff_uid, eff_gid);
}

void kbox_owner_set(dev_t dev, ino_t ino, int64_t uid, int64_t gid)
{
    int free_slot = -1;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < OWN_MAX; i++) {
        if (g_own[i].used && g_own[i].dev == dev && g_own[i].ino == ino) {
            if (uid != -1)
                g_own[i].uid = (uint32_t) uid;
            if (gid != -1)
                g_own[i].gid = (uint32_t) gid;
            pthread_mutex_unlock(&g_lock);
            return;
        }
        if (!g_own[i].used && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        free_slot = (int) (ino % OWN_MAX); /* table full: overwrite */
    g_own[free_slot].used = 1;
    g_own[free_slot].dev = dev;
    g_own[free_slot].ino = ino;
    g_own[free_slot].uid = uid == -1 ? 0 : (uint32_t) uid;
    g_own[free_slot].gid = gid == -1 ? 0 : (uint32_t) gid;
    pthread_mutex_unlock(&g_lock);
}

int kbox_owner_apply_overlay(struct stat *st)
{
    int found = 0;

    if (!st)
        return 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < OWN_MAX; i++) {
        if (g_own[i].used && g_own[i].dev == st->st_dev &&
            g_own[i].ino == st->st_ino) {
            st->st_uid = g_own[i].uid;
            st->st_gid = g_own[i].gid;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return found;
}

void kbox_owner_apply(pid_t pid, struct stat *st)
{
    struct kbox_vcred c;

    if (kbox_owner_apply_overlay(st))
        return;
    kbox_vcred_get(pid, &c);
    if (st->st_uid == getuid())
        st->st_uid = c.euid;
    if (st->st_gid == getgid())
        st->st_gid = c.egid;
}

void kbox_vcred_reset_for_test(void)
{
    pthread_mutex_lock(&g_lock);
    g_vc_n = 0;
    memset(g_own, 0, sizeof(g_own));
    pthread_mutex_unlock(&g_lock);
}
