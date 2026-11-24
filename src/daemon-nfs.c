/* SPDX-License-Identifier: MIT */

/* NFS-backed volumes for the kbox daemon.
 *
 * A service volume whose source starts with the hard-coded scheme name
 * "nfs:" refers to an export declared in the daemon config:
 *
 *     mounts:
 *       "nfs://mounted_here":
 *         source: 10.0.0.7:/export/data
 *         options: vers=4.2,proto=tcp,port=20490
 *
 * and is requested by a service as
 *
 *     volumes:
 *       - "nfs://mounted_here/subdir:/destination"
 *
 * The export is mounted exactly once, by the daemon, inside LKL's initial
 * mount namespace at /kbox-vol/nfs/<name>. Containers never see that path:
 * each one gets a bind mount of the requested subtree onto its own
 * destination inside its private mount namespace. Subdirectories that do not
 * exist yet are created on the export.
 *
 * The mount has to happen on the daemon side because guest processes have no
 * capabilities in LKL (CapEff=0 by construction), so a guest mount(2) of any
 * filesystem is refused with EPERM. The daemon runs with the kernel's initial
 * credentials and can mount.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "daemon.h"

/* LKL constants, spelled out to keep this file free of kernel headers. */
#define KBOX_MS_BIND 0x1000
#define KBOX_MS_REMOUNT 0x20
#define KBOX_MS_RDONLY 0x1
#define KBOX_MNT_DETACH 2

#ifndef KBOX_NFS_RETRY_NS
#define KBOX_NFS_RETRY_NS (2000L * 1000L * 1000L) /* 2s between attempts */
#endif

/* Split "nfs://mounted_here/subdir" into name and subpath.
 * Returns 0 on success, -1 if the source is not a valid nfs handle or the
 * name is malformed.
 */
int kbox_nfs_split_source(const char *source,
                          char *name,
                          size_t name_size,
                          char *subpath,
                          size_t subpath_size)
{
    const char *p;
    size_t len = 0;

    if (!source || strncmp(source, "nfs://", 6) != 0)
        return -1;
    p = source + 6; /* past "nfs://" */

    while (p[len] && p[len] != '/')
        len++;
    if (len == 0 || len >= name_size)
        return -1;
    for (size_t i = 0; i < len; i++) {
        char c = p[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok)
            return -1;
    }
    memcpy(name, p, len);
    name[len] = '\0';

    if (p[len] == '\0') {
        if (subpath_size < 2)
            return -1;
        subpath[0] = '/';
        subpath[1] = '\0';
        return 0;
    }
    /* The remainder must be a plain path: reject "..", // and stray dots. */
    {
        const char *rest = p + len;
        const char *seg = rest;
        if (strlen(rest) >= subpath_size)
            return -1;
        if (strstr(rest, "..") != NULL)
            return -1;
        while (*seg) {
            const char *slash;
            while (*seg == '/')
                seg++;
            slash = strchr(seg, '/');
            size_t seg_len = slash ? (size_t) (slash - seg) : strlen(seg);
            if (seg_len == 0)
                break;
            if (seg_len == 1 && seg[0] == '.')
                return -1;
            seg += seg_len;
        }
        snprintf(subpath, subpath_size, "%s", rest);
    }
    return 0;
}

static const struct kbox_nfs_mount *find_mount(
    const struct kbox_daemon_config *cfg,
    const char *name)
{
    if (!cfg)
        return NULL;
    for (size_t i = 0; i < cfg->nfs_count; i++) {
        if (strcmp(cfg->nfs[i].name, name) == 0)
            return &cfg->nfs[i];
    }
    return NULL;
}

/* Register or extend one declared mount. Called by the config parser for each
 * key under a "mounts:" subsection; "source"/"options" fill the entry in.
 */
int kbox_daemon_nfs_add(struct kbox_daemon_config *cfg,
                        const char *handle,
                        const char *key,
                        const char *value)
{
    struct kbox_nfs_mount *m = NULL;
    char name[KBOX_NFS_NAME_MAX];
    char subpath[8];

    if (!cfg || !handle || !key || !value)
        return -1;
    if (kbox_nfs_split_source(handle, name, sizeof(name), subpath,
                              sizeof(subpath)) < 0)
        return -1;
    if (strcmp(subpath, "/") != 0) {
        /* A mount handle must name a whole export, not a subtree of one. */
        return -1;
    }

    for (size_t i = 0; i < cfg->nfs_count; i++) {
        if (strcmp(cfg->nfs[i].handle, handle) == 0) {
            m = &cfg->nfs[i];
            break;
        }
    }
    if (!m) {
        if (cfg->nfs_count >= KBOX_NFS_MAX_MOUNTS)
            return -1;
        m = &cfg->nfs[cfg->nfs_count++];
        memset(m, 0, sizeof(*m));
        snprintf(m->handle, sizeof(m->handle), "%s", handle);
        snprintf(m->name, sizeof(m->name), "%s", name);
    }

    if (strcmp(key, "source") == 0 || strcmp(key, "server") == 0)
        snprintf(m->source, sizeof(m->source), "%s", value);
    else if (strcmp(key, "options") == 0 || strcmp(key, "opts") == 0)
        snprintf(m->options, sizeof(m->options), "%s", value);
    else
        return -1;
    return 0;
}

static void handle_path(const struct kbox_nfs_mount *m, char *out, size_t size)
{
    snprintf(out, size, "%s/%s", KBOX_NFS_ROOT, m->name);
}

static int sleep_interruptible(long ns)
{
    struct timespec ts;
    ts.tv_sec = ns / 1000000000L;
    ts.tv_nsec = ns % 1000000000L;
    while (nanosleep(&ts, &ts) < 0) {
        if (errno != EINTR)
            return -1;
        if (kbox_daemon_stopping())
            return -1;
    }
    return kbox_daemon_stopping() ? -1 : 0;
}

/* Build the option string handed to the kernel.
 *
 * mount(2) with a raw data string does not resolve the server name, unlike
 * mount.nfs, which always appends addr=. Without it the kernel rejects the
 * mount with EINVAL, so the address is derived from the source here — and
 * resolved on the host, where the daemon's sockets actually leave the pod.
 */
static int build_mount_options(const struct kbox_nfs_mount *m,
                               char *out,
                               size_t size)
{
    char server[KBOX_NFS_SOURCE_MAX];
    char addr[64];
    const char *colon;
    size_t len;
    int n;

    if (strstr(m->options, "addr=") != NULL) {
        n = snprintf(out, size, "%s", m->options);
        return (n < 0 || (size_t) n >= size) ? -1 : 0;
    }

    colon = strchr(m->source, ':');
    if (!colon || colon == m->source)
        return -1;
    len = (size_t) (colon - m->source);
    if (len >= sizeof(server))
        return -1;
    memcpy(server, m->source, len);
    server[len] = '\0';

    if (inet_pton(AF_INET, server, &(struct in_addr) {0}) == 1) {
        snprintf(addr, sizeof(addr), "%s", server);
    } else {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(server, NULL, &hints, &res) != 0 || !res)
            return -1;
        if (!inet_ntop(AF_INET,
                       &((struct sockaddr_in *) res->ai_addr)->sin_addr, addr,
                       sizeof(addr))) {
            freeaddrinfo(res);
            return -1;
        }
        freeaddrinfo(res);
    }

    if (m->options[0])
        n = snprintf(out, size, "%s,addr=%s", m->options, addr);
    else
        n = snprintf(out, size, "addr=%s", addr);
    return (n < 0 || (size_t) n >= size) ? -1 : 0;
}

/* Mount one declared export, retrying until it succeeds or the daemon is
 * asked to stop. A missing server must not abort startup: the container
 * orchestrator usually starts the NFS server alongside kbox, and the mount
 * will succeed on a later attempt.
 */
static int mount_one(const struct kbox_sysnrs *s,
                     struct kbox_nfs_mount *m,
                     int verbose)
{
    char path[KBOX_MAX_PATH];
    char opts[KBOX_NFS_OPTIONS_MAX + 80];
    unsigned attempt = 0;

    handle_path(m, path, sizeof(path));

    if (build_mount_options(m, opts, sizeof(opts)) < 0) {
        fprintf(stderr,
                "kboxd: nfs: %s: cannot derive addr= from source %s; add "
                "addr=<ip> to its options\n",
                m->handle, m->source);
        return -1;
    }
    if (verbose)
        fprintf(stderr, "kboxd: nfs: %s options: %s\n", m->handle, opts);

    for (;;) {
        long ret;

        if (kbox_daemon_stopping())
            return -1;

        lkl_mkdir_p_daemon(s, path, 0755);
        ret = kbox_lkl_mount(s, m->source, path, "nfs", 0, opts);
        if (ret >= 0) {
            m->mounted = 1;
            fprintf(stderr, "kboxd: nfs: mounted %s (%s) on %s\n", m->handle,
                    m->source, path);
            return 0;
        }

        attempt++;
        fprintf(
            stderr,
            "kboxd: nfs: mount %s (%s) failed: %s; retrying in %lds%s\n",
            m->handle, m->source, kbox_err_text(ret),
            (long) (KBOX_NFS_RETRY_NS / 1000000000L),
            (attempt % 5 == 0) ? " (still waiting for the NFS server)" : "");
        if (sleep_interruptible(KBOX_NFS_RETRY_NS) < 0)
            return -1;
    }
}

int kbox_daemon_nfs_mount_all(const struct kbox_sysnrs *s,
                              struct kbox_daemon_config *cfg,
                              int verbose)
{
    if (!cfg || cfg->nfs_count == 0)
        return 0;

    lkl_mkdir_p_daemon(s, KBOX_NFS_ROOT, 0755);

    for (size_t i = 0; i < cfg->nfs_count; i++) {
        if (mount_one(s, &cfg->nfs[i], verbose) < 0)
            return -1;
    }
    return 0;
}

/* Bind the subtree a container asked for. Called with the container's mount
 * namespace already unshared and its rootfs mounted via overlayfs, before
 * chroot, so paths are LKL-root paths of the form <rootfs><destination>.
 */
int kbox_daemon_nfs_bind_container(const struct kbox_sysnrs *s,
                                   const struct kbox_daemon_config *cfg,
                                   const char *rootfs,
                                   const struct kbox_host_bind *binds,
                                   size_t bind_count,
                                   char *err,
                                   size_t err_size)
{
    if (!cfg || cfg->nfs_count == 0 || !binds || bind_count == 0)
        return 0;

    for (size_t i = 0; i < bind_count; i++) {
        const struct kbox_host_bind *b = &binds[i];
        char name[KBOX_NFS_NAME_MAX];
        char subpath[KBOX_MAX_PATH];
        char src[KBOX_MAX_PATH];
        char dst[KBOX_MAX_PATH];
        const struct kbox_nfs_mount *m;
        long ret;

        if (!b->is_nfs)
            continue;

        if (kbox_nfs_split_source(b->host_path, name, sizeof(name), subpath,
                                  sizeof(subpath)) < 0) {
            snprintf(err, err_size, "invalid nfs volume source: %s",
                     b->host_path);
            return -1;
        }
        m = find_mount(cfg, name);
        if (!m) {
            snprintf(err, err_size,
                     "nfs volume %s is not declared in the kbox config "
                     "(mounts: \"nfs://%s\")",
                     b->host_path, name);
            return -1;
        }
        if (!m->mounted) {
            snprintf(err, err_size, "nfs volume %s is not mounted yet",
                     m->handle);
            return -1;
        }

        handle_path(m, src, sizeof(src));
        if (strcmp(subpath, "/") != 0) {
            size_t used = strlen(src);
            snprintf(src + used, sizeof(src) - used, "%s", subpath);
        }

        /* Create the requested subtree on the export if it is missing. */
        lkl_mkdir_p_daemon(s, src, 0755);

        if ((size_t) snprintf(dst, sizeof(dst), "%s%s", rootfs,
                              b->guest_path) >= sizeof(dst)) {
            snprintf(err, err_size, "destination path too long: %s",
                     b->guest_path);
            return -1;
        }
        lkl_mkdir_p_daemon(s, dst, 0755);

        ret = kbox_lkl_mount(s, src, dst, NULL, KBOX_MS_BIND, NULL);
        if (ret < 0) {
            snprintf(err, err_size, "bind %s -> %s failed: %s", src,
                     b->guest_path, kbox_err_text(ret));
            return -1;
        }
        if (b->readonly) {
            ret = kbox_lkl_mount(
                s, NULL, dst, NULL,
                KBOX_MS_BIND | KBOX_MS_REMOUNT | KBOX_MS_RDONLY, NULL);
            if (ret < 0)
                fprintf(stderr,
                        "kboxd: nfs: read-only remount of %s failed: %s\n",
                        b->guest_path, kbox_err_text(ret));
        }
        fprintf(stderr, "kboxd: nfs: %s -> %s%s\n", src, b->guest_path,
                b->readonly ? " (ro)" : "");
    }
    return 0;
}

void kbox_daemon_nfs_unbind_container(const struct kbox_sysnrs *s,
                                      const char *rootfs,
                                      const struct kbox_host_bind *binds,
                                      size_t bind_count)
{
    if (!s || !rootfs || !binds)
        return;
    for (size_t i = 0; i < bind_count; i++) {
        char dst[KBOX_MAX_PATH];

        if (!binds[i].is_nfs)
            continue;
        if ((size_t) snprintf(dst, sizeof(dst), "%s%s", rootfs,
                              binds[i].guest_path) >= sizeof(dst))
            continue;
        /* Lazy detach: the container may still hold cwd or open files. */
        {
            long ur = kbox_lkl_umount2(s, dst, KBOX_MNT_DETACH);
            fprintf(stderr, "kboxd: nfs: released %s (detach=%ld %s)\n", dst,
                    ur, ur < 0 ? kbox_err_text(ur) : "ok");
        }
    }
}
