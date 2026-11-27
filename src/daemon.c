/* SPDX-License-Identifier: MIT */
/* daemon.c - Single-LKL multi-container daemon with per-container Linux
 * namespaces (NET_NS, MNT_NS, UTS_NS) and seccomp supervision.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "daemon.h"
#include "fd-table.h"
#include "kbox/daemon-json.h"
#include "kbox/elf.h"
#include "kbox/mount.h"
#include "lkl-wrap.h"
#include "net.h"
#include "seccomp.h"
#include "shadow-fd.h"

#define DAEMON_LOG_DIR "/tmp/kboxd-logs"
#define LKL_O_DIRECTORY 0x10000
#define MAX_CONTAINERS 64
#define MAX_EXECS 64
#define MAX_CMD_ARGS 64
#define MAX_ENV_VARS 128
#define MAX_ALIASES 16
#define RPC_MAX_LINE (128 * 1024)
#define COPY_BUF_LEN 65536
#define MAX_HARDLINKS 2048

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum container_state {
    CONT_FREE = 0,
    CONT_CREATED = 1,
    CONT_STARTING = 2,
    CONT_RUNNING = 3,
    CONT_EXITED = 4,
};

enum exec_state {
    EXEC_FREE = 0,
    EXEC_STARTING = 1,
    EXEC_RUNNING = 2,
    EXEC_EXITED = 3,
};

struct port_binding_spec {
    char host_ip[32];
    int host_port;
    int container_port;
};

int kbox_guest_exe_realpath(const struct kbox_supervisor_ctx *ctx,
                            const char *in,
                            char *out,
                            size_t out_size);

struct daemon_proc_env {
    const struct kbox_host_bind *binds;
    /* Container has its own procfs mounted in its rootfs, so /proc must be
     * resolved inside LKL instead of being continued to the host kernel. */
    int private_proc;
    size_t bind_count;
    const char *workdir;
    char *const *cmd;
    int cmd_count;
    char *const *env;
    int env_count;
    /* A file whose contents become the process's stdin, or NULL for /dev/null.
     * `docker exec -i` needs this: the HTTP body the caller streams is spooled
     * to a file first, because nothing on the host side can stay attached to a
     * guest descriptor once the request handler returns. */
    const char *stdin_path;
    /* The address this container is known by on the pod network. A connect
     * aimed at it must not leave the container, or it comes back in through
     * the host forwarder and deadlocks against itself. */
    const char *own_ip;
    int host_net;
    long mem_limit; /* bytes, 0 = none */
};

struct daemon_container {
    int slot;
    enum container_state state;
    char id[80];
    char name[64];
    char image_id[128];
    char hostname[64];
    char workdir[PATH_MAX];
    char ip[32];
    int host_net;
    long mem_limit; /* bytes, 0 = none */
    char host_if[16];
    char log_path[160];

    char *cmd[MAX_CMD_ARGS + 1];
    int cmd_count;
    char *env[MAX_ENV_VARS + 1];
    int env_count;
    struct kbox_host_bind binds[KBOX_HOST_BINDS_MAX];
    size_t bind_count;
    char aliases[MAX_ALIASES][KBOX_DAEMON_MAX_ALIAS];
    int alias_count;
    struct port_binding_spec ports[16];
    int port_count;

    int mnt_ns_fd;
    int net_ns_fd;
    int uts_ns_fd;
    int rootfs_dir_fd;
    int active_execs;

    pid_t child_pid;
    int exit_efd;
    int child_exit_status;
    int exit_code;
    char start_err[256];

    time_t started_at;
    time_t finished_at;

    pthread_t worker_thread;
    int worker_started;
    pthread_mutex_t lock;
    int setup_held; /* this container holds the start-up gate */
    pthread_cond_t cv;
};

struct daemon_exec {
    enum exec_state state;
    char id[80];
    char container_id[80];
    char workdir[PATH_MAX];
    char log_path[160];
    /* Spooled stdin for `docker exec -i`, empty when the caller sent none. */
    char stdin_path[160];
    char stdin_file[180];

    char *cmd[MAX_CMD_ARGS + 1];
    int cmd_count;
    char *env[MAX_ENV_VARS + 1];
    int env_count;
    struct kbox_host_bind binds[KBOX_HOST_BINDS_MAX];
    size_t bind_count;

    struct daemon_container *cont;
    pid_t child_pid;
    int exit_efd;
    int child_exit_status;
    int exit_code;
    char start_err[256];

    pthread_t thread;
    int thread_started;
    pthread_mutex_t lock;
    pthread_cond_t cv;
};

struct log_pump_ctx {
    int out_fd;
    int err_fd;
    int log_fd;
};

struct hardlink_entry {
    dev_t dev;
    ino_t ino;
    char lkl_path[PATH_MAX];
};

struct import_state {
    const struct kbox_sysnrs *sysnrs;
    struct hardlink_entry *links;
    size_t link_count;
};

static const struct kbox_sysnrs *g_sysnrs;

/* Daemon config (network + declared NFS mounts), read once at startup and
 * shared read-only with container workers. */
static struct kbox_daemon_config g_config;
static const struct kbox_host_nrs *g_host_nrs;
static int g_verbose;
static volatile int g_daemon_stop;
static int g_listen_sock = -1;
static char g_config_path[512];

void kbox_daemon_set_config_path(const char *path)
{
    if (path && *path)
        snprintf(g_config_path, sizeof(g_config_path), "%s", path);
    else
        g_config_path[0] = '\0';
}

static pthread_mutex_t g_reap_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_image_lock = PTHREAD_MUTEX_INITIALIZER;
/* Hostfs-backed image store: when storage.images=hostfs the daemon records the
 * host path of each image tree and mounts it instead of copying it into the
 * guest tmpfs, so an image occupies disk on the node and only page cache in
 * guest memory. */
#define MAX_IMAGE_RECS 64
#define MAX_IMAGE_LAYERS 48
#define IMAGE_LAYER_PATH_MAX 512

struct image_layer {
    char path[IMAGE_LAYER_PATH_MAX]; /* host directory of the unpacked layer */
    char guest[64];                  /* where it is mounted in the guest */
    int mounted;
};

struct image_record {
    char id[128];
    char src[PATH_MAX];
    int mounted;
    struct image_layer layers[MAX_IMAGE_LAYERS];
    int layer_count;
};

static struct image_record g_image_recs[MAX_IMAGE_RECS];
static size_t g_image_rec_count;
static pthread_mutex_t g_image_recs_lock = PTHREAD_MUTEX_INITIALIZER;

/* A layer directory is shared by every image that contains it, so its hostfs
 * mount must happen once per guest path, not once per image record. */
#define MAX_MOUNTED_LAYERS 256
static char g_mounted_layers[MAX_MOUNTED_LAYERS][64];
static int g_mounted_layer_count;

static int layer_guest_mounted(const char *guest)
{
    int i;

    for (i = 0; i < g_mounted_layer_count; i++)
        if (strcmp(g_mounted_layers[i], guest) == 0)
            return 1;
    return 0;
}

static void layer_guest_mark(const char *guest)
{
    if (g_mounted_layer_count < MAX_MOUNTED_LAYERS)
        snprintf(g_mounted_layers[g_mounted_layer_count++], 64, "%s", guest);
}

/* Guest mount point for one layer: /layers/<first 16 hex of the digest>. Kept
 * short because all of them end up in the overlay mount option string. */
static void image_layer_guest_path(const char *host_path, char *out, size_t cap)
{
    const char *base = strrchr(host_path, '/');

    base = base ? base + 1 : host_path;
    snprintf(out, cap, "/layers/%.16s", base);
}

static int image_record_add(const char *id,
                            const char *src,
                            char **layers,
                            int layer_count)
{
    struct image_record *rec = NULL;
    size_t i;
    int l;

    if (layer_count > MAX_IMAGE_LAYERS)
        layer_count = MAX_IMAGE_LAYERS;

    pthread_mutex_lock(&g_image_recs_lock);
    for (i = 0; i < g_image_rec_count; i++) {
        if (strcmp(g_image_recs[i].id, id) == 0) {
            rec = &g_image_recs[i];
            break;
        }
    }
    if (!rec && g_image_rec_count < MAX_IMAGE_RECS)
        rec = &g_image_recs[g_image_rec_count++];
    if (rec) {
        snprintf(rec->id, sizeof(rec->id), "%s", id);
        snprintf(rec->src, sizeof(rec->src), "%s", src ? src : "");
        rec->layer_count = 0;
        for (l = 0; l < layer_count; l++) {
            struct image_layer *ly = &rec->layers[rec->layer_count];

            if (!layers[l] || !layers[l][0])
                continue;
            if (strlen(layers[l]) >= sizeof(ly->path))
                continue;
            snprintf(ly->path, sizeof(ly->path), "%s", layers[l]);
            image_layer_guest_path(ly->path, ly->guest, sizeof(ly->guest));
            ly->mounted = 0;
            rec->layer_count++;
        }
    }
    pthread_mutex_unlock(&g_image_recs_lock);
    return rec ? 0 : -ENOSPC;
}

/* Number of layers recorded for an image (0 for a merged-tree import). */
static int image_layer_count(const char *id)
{
    size_t i;
    int n = 0;

    pthread_mutex_lock(&g_image_recs_lock);
    for (i = 0; i < g_image_rec_count; i++) {
        if (strcmp(g_image_recs[i].id, id) == 0) {
            n = g_image_recs[i].layer_count;
            break;
        }
    }
    pthread_mutex_unlock(&g_image_recs_lock);
    return n;
}

/* Fill the overlay lowerdir list from the image's layers (top first, which is
 * the order the shim sends). Returns 1 when the image has layers. */
static int image_lowerdir(const char *id, char *out, size_t cap)
{
    struct image_record *rec = NULL;
    size_t i, used = 0;
    int l, any = 0;

    out[0] = '\0';
    pthread_mutex_lock(&g_image_recs_lock);
    for (i = 0; i < g_image_rec_count; i++) {
        if (strcmp(g_image_recs[i].id, id) == 0) {
            rec = &g_image_recs[i];
            break;
        }
    }
    if (rec) {
        for (l = 0; l < rec->layer_count; l++) {
            int n, j, seen = 0;

            /* An image may list one digest twice (identical empty layers).
             * overlayfs refuses the same directory twice in lowerdir with
             * ELOOP, and the upper copy already supplies the same files. */
            for (j = 0; j < l; j++) {
                if (strcmp(rec->layers[j].guest, rec->layers[l].guest) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (seen)
                continue;
            n = snprintf(out + used, cap - used, "%s%s", used ? ":" : "",
                         rec->layers[l].guest);

            if (n < 0 || (size_t) n >= cap - used)
                break;
            used += (size_t) n;
            any = 1;
        }
    }
    pthread_mutex_unlock(&g_image_recs_lock);
    return any;
}

/* Mount /images/<id> from the image's host directory. Mount option strings are
 * copied a full page at a time by copy_mount_options(), so the buffer is larger
 * than any path we pass. */
static int image_mount_hostfs(const struct kbox_sysnrs *sysnrs, const char *id)
{
    static char opts[8192];
    char guest[160];
    struct image_record *rec = NULL;
    size_t i;
    long err = 0;

    if (!g_config.images_hostfs)
        return 0;

    pthread_mutex_lock(&g_image_recs_lock);
    for (i = 0; i < g_image_rec_count; i++) {
        if (strcmp(g_image_recs[i].id, id) == 0) {
            rec = &g_image_recs[i];
            break;
        }
    }
    if (!rec) {
        pthread_mutex_unlock(&g_image_recs_lock);
        return -ENOENT;
    }

    for (i = 0; i < (size_t) rec->layer_count; i++) {
        struct image_layer *ly = &rec->layers[i];
        struct stat hst;

        if (ly->mounted || layer_guest_mounted(ly->guest)) {
            ly->mounted = 1;
            continue;
        }
        if (stat(ly->path, &hst) < 0 || !S_ISDIR(hst.st_mode))
            continue;
        snprintf(opts, sizeof(opts), "hostfs=%s", ly->path);
        lkl_mkdir_p_daemon(sysnrs, ly->guest, 0755);
        err = kbox_lkl_mount(sysnrs, "none", ly->guest, "hostfs", 0, opts);
        if (err < 0) {
            pthread_mutex_unlock(&g_image_recs_lock);
            return err;
        }
        ly->mounted = 1;
        layer_guest_mark(ly->guest);
    }

    /* Legacy path: an image imported as a merged tree (storage.images=copy) or
     * through docker import has no layers, only src. */
    if (!rec->mounted && rec->src[0]) {
        struct stat hst;

        if (stat(rec->src, &hst) == 0 && S_ISDIR(hst.st_mode)) {
            snprintf(guest, sizeof(guest), "/images/%s", id);
            snprintf(opts, sizeof(opts), "hostfs=%s", rec->src);
            lkl_mkdir_p_daemon(sysnrs, guest, 0755);
            err = kbox_lkl_mount(sysnrs, "none", guest, "hostfs", 0, opts);
            if (err == 0)
                rec->mounted = 1;
        }
    }
    pthread_mutex_unlock(&g_image_recs_lock);
    if (err < 0 && g_verbose)
        fprintf(stderr, "kboxd: hostfs mount of image %s failed: %ld\n", id,
                err);
    return (int) err;
}
static pthread_mutex_t g_cont_table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_exec_table_lock = PTHREAD_MUTEX_INITIALIZER;
static struct daemon_container g_containers[MAX_CONTAINERS];
static struct daemon_exec g_execs[MAX_EXECS];
static int g_veth_seq;

static pthread_t g_reaper_thread;
static int g_reaper_started;

extern char **environ;

static const struct kbox_host_nrs *select_host_nrs_for_daemon(void)
{
#if defined(__x86_64__)
    return &HOST_NRS_X86_64;
#elif defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
    return &HOST_NRS_GENERIC;
#else
#error "Unsupported architecture"
#endif
}

/* Minimal, safe JSON helpers (no strcpy/strcat/sprintf/atoi/sscanf). */

/* Recursive LKL directory helpers. */

static int lkl_mkdir_p(const struct kbox_sysnrs *sysnrs,
                       const char *path,
                       unsigned int mode)
{
    return (int) lkl_mkdir_p_daemon(sysnrs, path, (int) mode);
}

int lkl_mkdir_p_daemon(const struct kbox_sysnrs *sysnrs,
                       const char *path,
                       int mode)
{
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp))
        return -ENAMETOOLONG;
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            long r = kbox_lkl_mkdir(sysnrs, tmp, mode);
            if (r < 0 && r != -EEXIST)
                return (int) r;
            *p = '/';
        }
    }
    long r = kbox_lkl_mkdir(sysnrs, tmp, mode);
    if (r < 0 && r != -EEXIST)
        return (int) r;
    return 0;
}

static const char *lookup_hardlink(struct import_state *st, dev_t d, ino_t i)
{
    for (size_t k = 0; k < st->link_count; k++) {
        if (st->links[k].dev == d && st->links[k].ino == i)
            return st->links[k].lkl_path;
    }
    return NULL;
}

static void record_hardlink(struct import_state *st,
                            dev_t d,
                            ino_t i,
                            const char *lkl_path)
{
    if (st->link_count >= MAX_HARDLINKS)
        return;
    struct hardlink_entry *e = &st->links[st->link_count++];
    e->dev = d;
    e->ino = i;
    snprintf(e->lkl_path, sizeof(e->lkl_path), "%s", lkl_path);
}

static int import_host_tree_rec(struct import_state *st,
                                const char *host_dir,
                                const char *lkl_dir,
                                char *copy_buf)
{
    DIR *dp = opendir(host_dir);
    if (!dp)
        return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char hpath[PATH_MAX];
        char lpath[PATH_MAX];
        if (snprintf(hpath, sizeof(hpath), "%s/%s", host_dir, de->d_name) >=
                (int) sizeof(hpath) ||
            snprintf(lpath, sizeof(lpath), "%s/%s", lkl_dir, de->d_name) >=
                (int) sizeof(lpath))
            continue;

        struct stat hs;
        if (lstat(hpath, &hs) < 0)
            continue;

        if (S_ISDIR(hs.st_mode)) {
            long mr = kbox_lkl_mkdir(st->sysnrs, lpath, hs.st_mode & 07777);
            if (mr < 0 && mr != -EEXIST) {
                closedir(dp);
                return (int) mr;
            }
            /* Ensure owner rwx while populating read-only directories. */
            if ((hs.st_mode & 0700) != 0700)
                kbox_lkl_fchmodat(st->sysnrs, AT_FDCWD_LINUX, lpath, 0755, 0);

            int rc = import_host_tree_rec(st, hpath, lpath, copy_buf);
            kbox_lkl_fchmodat(st->sysnrs, AT_FDCWD_LINUX, lpath,
                              hs.st_mode & 07777, 0);
            if (rc < 0) {
                closedir(dp);
                return rc;
            }
        } else if (S_ISLNK(hs.st_mode)) {
            char target[PATH_MAX];
            ssize_t rl = readlink(hpath, target, sizeof(target) - 1);
            if (rl >= 0) {
                target[rl] = '\0';
                kbox_lkl_unlinkat(st->sysnrs, AT_FDCWD_LINUX, lpath, 0);
                long sr = kbox_lkl_symlinkat(st->sysnrs, target, AT_FDCWD_LINUX,
                                             lpath);
                if (sr < 0) {
                    closedir(dp);
                    return (int) sr;
                }
            }
        } else if (S_ISREG(hs.st_mode)) {
            if (hs.st_nlink > 1) {
                const char *existing =
                    lookup_hardlink(st, hs.st_dev, hs.st_ino);
                if (existing) {
                    kbox_lkl_unlinkat(st->sysnrs, AT_FDCWD_LINUX, lpath, 0);
                    if (kbox_lkl_linkat(st->sysnrs, AT_FDCWD_LINUX, existing,
                                        AT_FDCWD_LINUX, lpath, 0) == 0)
                        continue;
                }
            }

            int hfd = open(hpath, O_RDONLY | O_CLOEXEC);
            if (hfd < 0)
                continue;

            kbox_lkl_unlinkat(st->sysnrs, AT_FDCWD_LINUX, lpath, 0);
            long lfd = kbox_lkl_openat(st->sysnrs, AT_FDCWD_LINUX, lpath,
                                       0x241 /* O_WRONLY|O_CREAT|O_TRUNC */,
                                       hs.st_mode & 07777);
            if (lfd < 0) {
                close(hfd);
                closedir(dp);
                return (int) lfd;
            }

            ssize_t nr;
            while ((nr = read(hfd, copy_buf, COPY_BUF_LEN)) > 0) {
                ssize_t off = 0;
                while (off < nr) {
                    long wr = kbox_lkl_write(st->sysnrs, lfd, copy_buf + off,
                                             nr - off);
                    if (wr <= 0) {
                        close(hfd);
                        kbox_lkl_close(st->sysnrs, lfd);
                        closedir(dp);
                        return wr < 0 ? (int) wr : -EIO;
                    }
                    off += wr;
                }
            }
            close(hfd);
            kbox_lkl_close(st->sysnrs, lfd);
            kbox_lkl_fchmodat(st->sysnrs, AT_FDCWD_LINUX, lpath,
                              hs.st_mode & 07777, 0);

            if (hs.st_nlink > 1)
                record_hardlink(st, hs.st_dev, hs.st_ino, lpath);
        }
    }
    closedir(dp);
    return 0;
}

static int import_image_rootfs(const struct kbox_sysnrs *sysnrs,
                               const char *image_id,
                               const char *host_src)
{
    char img_dir[PATH_MAX];
    char ready_marker[PATH_MAX];
    snprintf(img_dir, sizeof(img_dir), "/images/%s", image_id);
    snprintf(ready_marker, sizeof(ready_marker), "/images/%s/.kbox_ready",
             image_id);

    pthread_mutex_lock(&g_image_lock);
    struct kbox_lkl_stat st;
    if (kbox_lkl_newfstatat(sysnrs, AT_FDCWD_LINUX, ready_marker, &st, 0) ==
        0) {
        pthread_mutex_unlock(&g_image_lock);
        return 0;
    }

    int rc = lkl_mkdir_p(sysnrs, img_dir, 0755);
    if (rc < 0) {
        pthread_mutex_unlock(&g_image_lock);
        return rc;
    }

    struct import_state ist;
    memset(&ist, 0, sizeof(ist));
    ist.sysnrs = sysnrs;
    ist.links = calloc(MAX_HARDLINKS, sizeof(struct hardlink_entry));
    char *copy_buf = malloc(COPY_BUF_LEN);
    if (!ist.links || !copy_buf) {
        free(ist.links);
        free(copy_buf);
        pthread_mutex_unlock(&g_image_lock);
        return -ENOMEM;
    }

    rc = import_host_tree_rec(&ist, host_src, img_dir, copy_buf);
    free(ist.links);
    free(copy_buf);

    if (rc == 0) {
        long mfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, ready_marker,
                                   0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
        if (mfd >= 0)
            kbox_lkl_close(sysnrs, mfd);
        if (g_verbose)
            fprintf(stderr, "kboxd: imported image %s from %s\n", image_id,
                    host_src);
    }
    pthread_mutex_unlock(&g_image_lock);
    return rc;
}

/* Recursively copy inside LKL (fallback if overlay mount is unavailable). */
static int copy_lkl_tree_rec(const struct kbox_sysnrs *sysnrs,
                             const char *src_dir,
                             const char *dst_dir,
                             char *copy_buf)
{
    long dfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, src_dir,
                               O_RDONLY | LKL_O_DIRECTORY, 0);
    if (dfd < 0)
        return (int) dfd;

    uint8_t dents[8192];
    for (;;) {
        long n = kbox_lkl_getdents64(sysnrs, dfd, dents, sizeof(dents));
        if (n <= 0)
            break;
        long pos = 0;
        while (pos < n) {
            uint16_t reclen;
            memcpy(&reclen, dents + pos + 16, sizeof(reclen));
            const char *name = (const char *) (dents + pos + 19);
            pos += reclen;

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
                strcmp(name, ".kbox_ready") == 0)
                continue;

            char spath[PATH_MAX], dpath[PATH_MAX];
            if (snprintf(spath, sizeof(spath), "%s/%s", src_dir, name) >=
                    (int) sizeof(spath) ||
                snprintf(dpath, sizeof(dpath), "%s/%s", dst_dir, name) >=
                    (int) sizeof(dpath))
                continue;

            struct kbox_lkl_stat lst;
            if (kbox_lkl_newfstatat(sysnrs, AT_FDCWD_LINUX, spath, &lst,
                                    AT_SYMLINK_NOFOLLOW) < 0)
                continue;

            if (S_ISDIR(lst.st_mode)) {
                kbox_lkl_mkdir(sysnrs, dpath, 0755);
                copy_lkl_tree_rec(sysnrs, spath, dpath, copy_buf);
                kbox_lkl_fchmodat(sysnrs, AT_FDCWD_LINUX, dpath,
                                  lst.st_mode & 07777, 0);
            } else if (S_ISLNK(lst.st_mode)) {
                char target[PATH_MAX];
                long rl = kbox_lkl_readlinkat(sysnrs, AT_FDCWD_LINUX, spath,
                                              target, sizeof(target) - 1);
                if (rl >= 0) {
                    target[rl] = '\0';
                    kbox_lkl_symlinkat(sysnrs, target, AT_FDCWD_LINUX, dpath);
                }
            } else if (S_ISREG(lst.st_mode)) {
                long sfd =
                    kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, spath, O_RDONLY, 0);
                if (sfd < 0)
                    continue;
                long outfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, dpath,
                                             0x241, lst.st_mode & 07777);
                if (outfd >= 0) {
                    long r;
                    while ((r = kbox_lkl_read(sysnrs, sfd, copy_buf,
                                              COPY_BUF_LEN)) > 0) {
                        long off = 0;
                        while (off < r) {
                            long w = kbox_lkl_write(sysnrs, outfd,
                                                    copy_buf + off, r - off);
                            if (w <= 0)
                                break;
                            off += w;
                        }
                    }
                    kbox_lkl_close(sysnrs, outfd);
                }
                kbox_lkl_close(sysnrs, sfd);
            }
        }
    }
    kbox_lkl_close(sysnrs, dfd);
    return 0;
}

/* Recursively remove a directory tree in LKL tmpfs. */
static int rm_lkl_tree_rec(const struct kbox_sysnrs *sysnrs,
                           const char *dir_path)
{
    long dfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, dir_path,
                               O_RDONLY | LKL_O_DIRECTORY, 0);
    if (dfd < 0)
        return (int) dfd;

    uint8_t dents[8192];
    for (;;) {
        long n = kbox_lkl_getdents64(sysnrs, dfd, dents, sizeof(dents));
        if (n <= 0)
            break;
        long pos = 0;
        while (pos < n) {
            uint16_t reclen;
            memcpy(&reclen, dents + pos + 16, sizeof(reclen));
            const char *name = (const char *) (dents + pos + 19);
            pos += reclen;

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                continue;

            char cpath[PATH_MAX];
            if (snprintf(cpath, sizeof(cpath), "%s/%s", dir_path, name) >=
                (int) sizeof(cpath))
                continue;

            struct kbox_lkl_stat lst;
            if (kbox_lkl_newfstatat(sysnrs, AT_FDCWD_LINUX, cpath, &lst,
                                    AT_SYMLINK_NOFOLLOW) < 0)
                continue;

            if (S_ISDIR(lst.st_mode))
                rm_lkl_tree_rec(sysnrs, cpath);
            else
                kbox_lkl_unlinkat(sysnrs, AT_FDCWD_LINUX, cpath, 0);
        }
    }
    kbox_lkl_close(sysnrs, dfd);
    return (int) kbox_lkl_unlinkat(sysnrs, AT_FDCWD_LINUX, dir_path,
                                   AT_REMOVEDIR);
}

/* Container executable resolution and memfd preparation. */

static int open_container_file(const struct kbox_sysnrs *sysnrs,
                               const struct daemon_proc_env *pe,
                               const char *guest_path,
                               int *is_host_fd_out)
{
    /* Check host bind mounts first via a temporary ctx. */
    struct kbox_supervisor_ctx tmp_ctx;
    memset(&tmp_ctx, 0, sizeof(tmp_ctx));
    tmp_ctx.host_binds = pe->binds;
    tmp_ctx.host_bind_count = pe->bind_count;
    snprintf(tmp_ctx.host_cwd, sizeof(tmp_ctx.host_cwd), "%s",
             (pe->workdir && pe->workdir[0]) ? pe->workdir : "/");

    char host_path[KBOX_MAX_PATH];
    int ro = 0;
    if (kbox_resolve_host_bind_at(&tmp_ctx, AT_FDCWD_LINUX, guest_path,
                                  host_path, sizeof(host_path), &ro) == 1) {
        int hfd = open(host_path, O_RDONLY | O_CLOEXEC);
        if (hfd < 0)
            return -errno;
        *is_host_fd_out = 1;
        return hfd;
    }

    long lfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, guest_path, O_RDONLY, 0);
    if (lfd < 0)
        return (int) lfd;
    *is_host_fd_out = 0;
    return (int) lfd;
}

static int resolve_cmd_path(const struct kbox_sysnrs *sysnrs,
                            const struct daemon_proc_env *pe,
                            const char *cmd,
                            char *resolved,
                            size_t cap)
{
    if (strchr(cmd, '/')) {
        snprintf(resolved, cap, "%s", cmd);
        return 0;
    }

    const char *path_env =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
        "/usr/bin:/sbin:/bin";
    for (int i = 0; i < pe->env_count; i++) {
        if (strncmp(pe->env[i], "PATH=", 5) == 0) {
            path_env = pe->env[i] + 5;
            break;
        }
    }

    const char *p = path_env;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dlen = colon ? (size_t) (colon - p) : strlen(p);
        if (dlen > 0 && dlen < cap - 2) {
            char cand[PATH_MAX];
            snprintf(cand, sizeof(cand), "%.*s/%s", (int) dlen, p, cmd);
            int is_host = 0;
            int fd = open_container_file(sysnrs, pe, cand, &is_host);
            if (fd >= 0) {
                if (is_host)
                    close(fd);
                else
                    kbox_lkl_close(sysnrs, fd);
                snprintf(resolved, cap, "%s", cand);
                return 0;
            }
        }
        if (!colon)
            break;
        p = colon + 1;
    }
    return -ENOENT;
}

static int prepare_exec_memfds(const struct kbox_sysnrs *sysnrs,
                               const struct daemon_proc_env *pe,
                               const char *resolved_cmd,
                               char *const *in_argv,
                               int in_argc,
                               char **out_argv,
                               int max_out_argv,
                               int *exec_memfd_out,
                               int *interp_memfd_out,
                               char *err_buf,
                               size_t err_cap)
{
    int is_host = 0;
    int fd = open_container_file(sysnrs, pe, resolved_cmd, &is_host);
    if (fd < 0) {
        snprintf(err_buf, err_cap, "cannot open %s: %s", resolved_cmd,
                 strerror(-fd));
        return fd;
    }

    int memfd = is_host ? kbox_shadow_create_from_host_fd(fd)
                        : kbox_shadow_create(sysnrs, fd);
    if (is_host)
        close(fd);
    else
        kbox_lkl_close(sysnrs, fd);

    if (memfd < 0) {
        snprintf(err_buf, err_cap, "shadow memfd failed for %s: %d",
                 resolved_cmd, memfd);
        return memfd;
    }

    /* Check for #! script header. */
    char hdr[256];
    ssize_t hn = pread(memfd, hdr, sizeof(hdr) - 1, 0);
    if (hn >= 3 && hdr[0] == '#' && hdr[1] == '!') {
        hdr[hn] = '\0';
        char *nl = strchr(hdr, '\n');
        if (nl)
            *nl = '\0';
        char *cr = strchr(hdr, '\r');
        if (cr)
            *cr = '\0';

        char *p = hdr + 2;
        while (*p == ' ' || *p == '\t')
            p++;
        char *interp = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        char *opt_arg = NULL;
        if (*p) {
            *p++ = '\0';
            while (*p == ' ' || *p == '\t')
                p++;
            if (*p)
                opt_arg = p;
        }
        close(memfd);

        if (!*interp) {
            snprintf(err_buf, err_cap, "empty shebang in %s", resolved_cmd);
            return -ENOEXEC;
        }

        int i_host = 0;
        int ifd = open_container_file(sysnrs, pe, interp, &i_host);
        if (ifd < 0) {
            snprintf(err_buf, err_cap, "cannot open shebang interpreter %s",
                     interp);
            return ifd;
        }
        memfd = i_host ? kbox_shadow_create_from_host_fd(ifd)
                       : kbox_shadow_create(sysnrs, ifd);
        if (i_host)
            close(ifd);
        else
            kbox_lkl_close(sysnrs, ifd);
        if (memfd < 0)
            return memfd;

        int ai = 0;
        if (ai < max_out_argv - 1)
            out_argv[ai++] = strdup(interp);
        if (opt_arg && ai < max_out_argv - 1)
            out_argv[ai++] = strdup(opt_arg);
        if (ai < max_out_argv - 1)
            out_argv[ai++] = strdup(resolved_cmd);
        for (int k = 1; k < in_argc && ai < max_out_argv - 1; k++)
            out_argv[ai++] = strdup(in_argv[k]);
        out_argv[ai] = NULL;
    } else {
        int ai = 0;
        out_argv[ai++] = strdup(resolved_cmd);
        for (int k = 1; k < in_argc && ai < max_out_argv - 1; k++)
            out_argv[ai++] = strdup(in_argv[k]);
        out_argv[ai] = NULL;
    }

    int interp_memfd = -1;
    unsigned char *elf_buf = NULL;
    size_t elf_len = 0;
    if (kbox_read_elf_header_window_fd(memfd, &elf_buf, &elf_len) == 0) {
        char interp_path[256];
        uint64_t pt_off = 0, pt_filesz = 0;
        int ilen =
            kbox_find_elf_interp_loc(elf_buf, elf_len, interp_path,
                                     sizeof(interp_path), &pt_off, &pt_filesz);
        munmap(elf_buf, elf_len);
        if (ilen < 0) {
            close(memfd);
            snprintf(err_buf, err_cap, "malformed ELF %s", resolved_cmd);
            return -ENOEXEC;
        }
        if (ilen > 0) {
            int i_host = 0;
            int ifd = open_container_file(sysnrs, pe, interp_path, &i_host);
            if (ifd < 0) {
                close(memfd);
                snprintf(err_buf, err_cap, "missing PT_INTERP %s", interp_path);
                return ifd;
            }
            interp_memfd = i_host ? kbox_shadow_create_from_host_fd(ifd)
                                  : kbox_shadow_create(sysnrs, ifd);
            if (i_host)
                close(ifd);
            else
                kbox_lkl_close(sysnrs, ifd);
            if (interp_memfd < 0) {
                close(memfd);
                snprintf(err_buf, err_cap, "memfd failed for %s", interp_path);
                return interp_memfd;
            }
            char new_interp[64];
            int nlen = snprintf(new_interp, sizeof(new_interp),
                                "/proc/self/fd/%d", interp_memfd);
            if ((uint64_t) (nlen + 1) > pt_filesz || pt_filesz > 256) {
                close(interp_memfd);
                close(memfd);
                snprintf(err_buf, err_cap, "PT_INTERP too small");
                return -ENOEXEC;
            }
            char patch[256];
            memset(patch, 0, sizeof(patch));
            memcpy(patch, new_interp, (size_t) nlen);
            if (pwrite(memfd, patch, (size_t) pt_filesz, (off_t) pt_off) !=
                (ssize_t) pt_filesz) {
                close(interp_memfd);
                close(memfd);
                snprintf(err_buf, err_cap, "PT_INTERP pwrite failed");
                return -EIO;
            }
        }
    }

    *exec_memfd_out = memfd;
    *interp_memfd_out = interp_memfd;
    return 0;
}

/* Multiplexed Docker log writer: [stream(1=out,2=err), 0,0,0, uint32_be(n)]. */

static void write_log_frame(int log_fd,
                            uint8_t stream_id,
                            const uint8_t *data,
                            size_t len)
{
    uint8_t hdr[8] = {
        stream_id,
        0,
        0,
        0,
        (uint8_t) ((len >> 24) & 0xff),
        (uint8_t) ((len >> 16) & 0xff),
        (uint8_t) ((len >> 8) & 0xff),
        (uint8_t) (len & 0xff),
    };
    size_t off = 0;
    while (off < sizeof(hdr)) {
        ssize_t w = write(log_fd, hdr + off, sizeof(hdr) - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return;
        off += (size_t) w;
    }
    off = 0;
    while (off < len) {
        ssize_t w = write(log_fd, data + off, len - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return;
        off += (size_t) w;
    }
}

static void *log_pump_thread(void *arg)
{
    struct log_pump_ctx *lp = arg;
    uint8_t buf[16384];
    int open_out = (lp->out_fd >= 0);
    int open_err = (lp->err_fd >= 0);

    while (open_out || open_err) {
        struct pollfd pfds[2];
        int nfds = 0;
        int map[2];

        if (open_out) {
            pfds[nfds].fd = lp->out_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            map[nfds++] = 1;
        }
        if (open_err) {
            pfds[nfds].fd = lp->err_fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            map[nfds++] = 2;
        }

        int pr = poll(pfds, (nfds_t) nfds, -1);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < nfds; i++) {
            if (pfds[i].revents & (POLLIN | POLLHUP)) {
                ssize_t n = read(pfds[i].fd, buf, sizeof(buf));
                if (n > 0) {
                    if (lp->log_fd >= 0)
                        write_log_frame(lp->log_fd, (uint8_t) map[i], buf,
                                        (size_t) n);
                } else if (n == 0 ||
                           (n < 0 && errno != EINTR && errno != EAGAIN)) {
                    if (map[i] == 1)
                        open_out = 0;
                    else
                        open_err = 0;
                }
            }
        }
    }

    if (lp->out_fd >= 0)
        close(lp->out_fd);
    if (lp->err_fd >= 0)
        close(lp->err_fd);
    if (lp->log_fd >= 0)
        close(lp->log_fd);
    free(lp);
    return NULL;
}

/* Central SIGCHLD reaper thread. */

static void *sigchld_reaper_thread(void *arg)
{
    (void) arg;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    int sfd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (sfd < 0) {
        fprintf(stderr, "kboxd: signalfd failed: %s\n", strerror(errno));
        return NULL;
    }

    while (!__atomic_load_n(&g_daemon_stop, __ATOMIC_ACQUIRE)) {
        struct pollfd pfd = {.fd = sfd, .events = POLLIN, .revents = 0};
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0 || !(pfd.revents & POLLIN))
            continue;

        struct signalfd_siginfo si;
        while (read(sfd, &si, sizeof(si)) > 0) {
            /* Drain all queued signals, waitpid loop reaps all children. */
            struct pollfd d = {.fd = sfd, .events = POLLIN};
            if (poll(&d, 1, 0) <= 0)
                break;
        }

        pthread_mutex_lock(&g_reap_lock);
        for (;;) {
            int st = 0;
            pid_t pid = waitpid(-1, &st, WNOHANG);
            if (pid <= 0)
                break;

            int norm = 0;
            if (WIFEXITED(st))
                norm = WEXITSTATUS(st);
            else if (WIFSIGNALED(st))
                norm = 128 + WTERMSIG(st);

            int matched = 0;
            for (int i = 0; i < MAX_CONTAINERS; i++) {
                struct daemon_container *c = &g_containers[i];
                if (c->state != CONT_FREE && c->child_pid == pid) {
                    __atomic_store_n(&c->child_exit_status, norm,
                                     __ATOMIC_RELEASE);
                    if (c->exit_efd >= 0) {
                        uint64_t one = 1;
                        ssize_t nw = write(c->exit_efd, &one, sizeof(one));
                        (void) nw;
                    }
                    matched = 1;
                    break;
                }
            }
            if (!matched) {
                for (int i = 0; i < MAX_EXECS; i++) {
                    struct daemon_exec *e = &g_execs[i];
                    if (e->state != EXEC_FREE && e->child_pid == pid) {
                        __atomic_store_n(&e->child_exit_status, norm,
                                         __ATOMIC_RELEASE);
                        if (e->exit_efd >= 0) {
                            uint64_t one = 1;
                            ssize_t nw = write(e->exit_efd, &one, sizeof(one));
                            (void) nw;
                        }
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&g_reap_lock);
    }

    close(sfd);
    return NULL;
}

/* Container start-up gate.
 *
 * Starting a container unshares namespaces, builds an overlay mount, creates a
 * veth and spawns the process, all against the one LKL kernel. Compose starts
 * several containers at once, and when those set-ups overlapped they tripped
 * over each other: mkdir ENOENT in a directory that exists in the image
 * (nginx, maven), EEXIST creating a veth, and containers that "started" with a
 * half-built root. Only one container runs its set-up at a time; the gate is
 * released as soon as the process is running or the start has failed.
 */
static pthread_mutex_t g_setup_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_setup_cv = PTHREAD_COND_INITIALIZER;
static int g_setup_busy;

static void setup_gate_acquire(struct daemon_container *c)
{
    pthread_mutex_lock(&g_setup_mu);
    while (g_setup_busy)
        pthread_cond_wait(&g_setup_cv, &g_setup_mu);
    g_setup_busy = 1;
    c->setup_held = 1;
    pthread_mutex_unlock(&g_setup_mu);
}

static void setup_gate_release(struct daemon_container *c)
{
    pthread_mutex_lock(&g_setup_mu);
    if (c->setup_held) {
        c->setup_held = 0;
        g_setup_busy = 0;
        pthread_cond_signal(&g_setup_cv);
    }
    pthread_mutex_unlock(&g_setup_mu);
}

static void fail_container_start(struct daemon_container *c, const char *msg)
{
    setup_gate_release(c);
    pthread_mutex_lock(&c->lock);
    snprintf(c->start_err, sizeof(c->start_err), "%s", msg);
    c->state = CONT_EXITED;
    c->exit_code = 127;
    c->finished_at = time(NULL);
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->lock);
}

static void free_str_vec(char **v)
{
    for (int i = 0; v && v[i]; i++) {
        free(v[i]);
        v[i] = NULL;
    }
}

struct supervised_proc_hooks {
    void *opaque;
    pid_t *child_pid;
    int *exit_efd;
    int *exit_status;
    void (*on_running)(void *opaque);
    void (*on_failed)(void *opaque, const char *msg);
};

/* Resolve command, prepare memfds + pipes, fork tracee under g_reap_lock,
 * pump stdout/stderr to log_path, and run kbox_supervise_ctx until exit.
 */
static int launch_and_supervise_proc(const struct kbox_sysnrs *sysnrs,
                                     const struct daemon_proc_env *pe,
                                     const char *log_path,
                                     const struct supervised_proc_hooks *hooks)
{
    char err_msg[256] = {0};
    const char *raw_cmd =
        (pe->cmd_count > 0 && pe->cmd && pe->cmd[0]) ? pe->cmd[0] : "/bin/sh";
    char resolved_cmd[PATH_MAX];
    if (resolve_cmd_path(sysnrs, pe, raw_cmd, resolved_cmd,
                         sizeof(resolved_cmd)) < 0) {
        snprintf(err_msg, sizeof(err_msg), "executable not found: %s", raw_cmd);
        hooks->on_failed(hooks->opaque, err_msg);
        return -1;
    }

    char *exec_argv[MAX_CMD_ARGS + 6];
    memset(exec_argv, 0, sizeof(exec_argv));
    int exec_memfd = -1, interp_memfd = -1;
    if (prepare_exec_memfds(sysnrs, pe, resolved_cmd, pe->cmd, pe->cmd_count,
                            exec_argv, MAX_CMD_ARGS + 5, &exec_memfd,
                            &interp_memfd, err_msg, sizeof(err_msg)) < 0) {
        free_str_vec(exec_argv);
        hooks->on_failed(hooks->opaque,
                         err_msg[0] ? err_msg : "prepare exec failed");
        return -1;
    }

    char *exec_envp[MAX_ENV_VARS + 4];
    int ei = 0;
    int has_path = 0;
    for (int i = 0; i < pe->env_count && ei < MAX_ENV_VARS; i++) {
        if (strncmp(pe->env[i], "PATH=", 5) == 0)
            has_path = 1;
        exec_envp[ei++] = pe->env[i];
    }
    char default_path[] =
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    if (!has_path)
        exec_envp[ei++] = default_path;
    exec_envp[ei] = NULL;

    int sp[2] = {-1, -1};
    int out_p[2] = {-1, -1};
    int err_p[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) < 0 ||
        pipe2(out_p, O_CLOEXEC) < 0 || pipe2(err_p, O_CLOEXEC) < 0) {
        if (sp[0] >= 0) {
            close(sp[0]);
            close(sp[1]);
        }
        if (out_p[0] >= 0) {
            close(out_p[0]);
            close(out_p[1]);
        }
        if (interp_memfd >= 0)
            close(interp_memfd);
        close(exec_memfd);
        free_str_vec(exec_argv);
        hooks->on_failed(hooks->opaque, "pipe/socketpair failed");
        return -1;
    }

    int log_fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (log_fd < 0) {
        /* Without this file the container runs with its output going nowhere
         * and `docker logs` answers empty for a container that worked. Report
         * the cause instead of starting a silent black hole. */
        fprintf(stderr, "kboxd: open log %s: %s\n", log_path, strerror(errno));
        hooks->on_failed(hooks->opaque, "container log file is not writable");
        return -1;
    }
    int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    /* stdin comes from a FIFO when the caller attached one. Opened
     * NON-blocking first so a reader that arrives before the writer still gets
     * a descriptor, then switched back to blocking so reads wait for bytes
     * instead of returning EOF immediately.
     *
     * A FIFO, not a regular file: `docker exec -i` streams stdin AFTER the 101
     * handshake, so the bytes do not exist yet when the process starts. A plain
     * file would hand the guest an instant EOF and `cat > f` would write
     * nothing while still exiting 0. */
    int stdin_fd = devnull;
    if (pe->stdin_path && pe->stdin_path[0]) {
        stdin_fd = open(pe->stdin_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (stdin_fd < 0) {
            fprintf(stderr, "kboxd: open stdin %s: %s\n", pe->stdin_path,
                    strerror(errno));
            goto stdin_failed;
        }
        int fl = fcntl(stdin_fd, F_GETFL);
        if (fl >= 0)
            fcntl(stdin_fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    goto stdin_ok;

stdin_failed:
    close(log_fd);
    if (devnull >= 0)
        close(devnull);
    close(out_p[0]);
    close(out_p[1]);
    close(err_p[0]);
    close(err_p[1]);
    close(sp[0]);
    close(sp[1]);
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);
    free_str_vec(exec_argv);
    hooks->on_failed(hooks->opaque, "stdin pipe is not readable");
    return -1;

stdin_ok:

    *hooks->exit_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    __atomic_store_n(hooks->exit_status, -1, __ATOMIC_RELEASE);

    pthread_mutex_lock(&g_reap_lock);
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        if (stdin_fd >= 0)
            dup2(stdin_fd, STDIN_FILENO);
        dup2(out_p[1], STDOUT_FILENO);
        dup2(err_p[1], STDERR_FILENO);

        if (devnull > 2)
            close(devnull);
        if (stdin_fd > 2 && stdin_fd != devnull)
            close(stdin_fd);
        close(sp[0]);
        close(out_p[0]);
        close(out_p[1]);
        close(err_p[0]);
        close(err_p[1]);
        if (log_fd >= 0)
            close(log_fd);

        /* Mark every inherited daemon FD >= 3 close-on-exec so hostfs and
         * supervisor descriptors never leak across fexecve into guest
         * processes (which otherwise inherit thousands of hostfs FDs and fail
         * PostgreSQL's count_usable_fds check). sp[1], exec_memfd and
         * interp_memfd remain open until fexecve's begin_new_exec().
         * __NR_close_range is 436 on x86_64, aarch64 and riscv64. */
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
        (void) syscall(436L, 3U, ~0U, CLOSE_RANGE_CLOEXEC);

        if (kbox_supervisor_prepare_child_security() < 0)
            _exit(127);

        int lfd = kbox_install_seccomp_listener(g_host_nrs);
        if (lfd < 0)
            _exit(127);

        if (kbox_supervisor_send_fd(sp[1], lfd) < 0)
            _exit(127);
        close(sp[1]);
        close(lfd);

        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);

        fexecve(exec_memfd, exec_argv, exec_envp);
        _exit(127);
    }

    if (pid > 0)
        *hooks->child_pid = pid;
    pthread_mutex_unlock(&g_reap_lock);

    if (devnull >= 0)
        close(devnull);
    if (stdin_fd > 2 && stdin_fd != devnull)
        close(stdin_fd);
    close(sp[1]);
    close(out_p[1]);
    close(err_p[1]);
    close(exec_memfd);
    if (interp_memfd >= 0)
        close(interp_memfd);
    free_str_vec(exec_argv);

    if (pid < 0) {
        close(sp[0]);
        close(out_p[0]);
        close(err_p[0]);
        if (log_fd >= 0)
            close(log_fd);
        if (*hooks->exit_efd >= 0) {
            close(*hooks->exit_efd);
            *hooks->exit_efd = -1;
        }
        hooks->on_failed(hooks->opaque, "fork failed");
        return -1;
    }

    int listener_fd = kbox_supervisor_recv_fd(sp[0]);
    close(sp[0]);

    if (listener_fd < 0) {
        kill(-pid, SIGKILL);
        close(out_p[0]);
        close(err_p[0]);
        if (log_fd >= 0)
            close(log_fd);
        if (*hooks->exit_efd >= 0) {
            close(*hooks->exit_efd);
            *hooks->exit_efd = -1;
        }
        hooks->on_failed(hooks->opaque, "seccomp listener recv failed");
        return -1;
    }

    pthread_t log_thr;
    int has_log_thr = 0;
    struct log_pump_ctx *lp = malloc(sizeof(*lp));
    if (lp) {
        lp->out_fd = out_p[0];
        lp->err_fd = err_p[0];
        lp->log_fd = log_fd;
        if (pthread_create(&log_thr, NULL, log_pump_thread, lp) == 0)
            has_log_thr = 1;
        else {
            free(lp);
            close(out_p[0]);
            close(err_p[0]);
            if (log_fd >= 0)
                close(log_fd);
        }
    } else {
        close(out_p[0]);
        close(err_p[0]);
        if (log_fd >= 0)
            close(log_fd);
    }

    hooks->on_running(hooks->opaque);

    struct kbox_fd_table fd_table;
    struct kbox_supervisor_ctx ctx;
    kbox_fd_table_init(&fd_table);
    for (int i = 0; i < 3; i++)
        kbox_fd_table_insert_at(&fd_table, i, KBOX_LKL_FD_SHADOW_ONLY, 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.sysnrs = sysnrs;
    ctx.host_nrs = g_host_nrs;
    ctx.fd_table = &fd_table;
    ctx.listener_fd = listener_fd;
    ctx.proc_self_fd_dirfd = -1;
    ctx.proc_mem_fd = -1;
    ctx.child_pid = pid;
    ctx.verbose = g_verbose;
    ctx.root_identity = 1;
    ctx.private_proc = pe->private_proc;
    ctx.host_net = pe->host_net;
    ctx.mem_limit = pe->mem_limit;
    snprintf(ctx.own_ip, sizeof(ctx.own_ip), "%s",
             (pe->own_ip && pe->own_ip[0]) ? pe->own_ip : "");
    ctx.override_uid = (uid_t) -1;
    ctx.override_gid = (gid_t) -1;
    ctx.guest_umask = 022;
    ctx.lkl_umask_cur = 022;
    ctx.normalize = 1;
    ctx.guest_mem_ops = &kbox_process_vm_guest_mem_ops;
    ctx.host_binds = pe->binds;
    ctx.host_bind_count = pe->bind_count;
    snprintf(ctx.host_cwd, sizeof(ctx.host_cwd), "%s",
             (pe->workdir && pe->workdir[0]) ? pe->workdir : "/");
    if (kbox_guest_exe_realpath(&ctx, resolved_cmd, ctx.guest_exe,
                                sizeof(ctx.guest_exe)) != 0)
        snprintf(ctx.guest_exe, sizeof(ctx.guest_exe), "%s", resolved_cmd);
    ctx.exit_notify_fd = *hooks->exit_efd;
    ctx.exit_status_ptr = hooks->exit_status;

    int exit_code = kbox_supervise_ctx(&ctx);

    /* The container's init exiting does not end the rest of its processes, and
     * once the supervisor has returned nobody is servicing their syscalls: they
     * stay parked in the notification queue forever. postgres is the visible
     * case -- its backends keep the data directory and the SysV segment
     * attached, so the next start of the same service refused with
     * "pre-existing shared memory block ... is still in use".
     */
    kill(-pid, SIGKILL);
    for (size_t i = 0; ctx.proc_fds && i < ctx.proc_fd_count; i++) {
        if (ctx.proc_fds[i].tgid > 1)
            kill(ctx.proc_fds[i].tgid, SIGKILL);
    }
    for (int spin = 0; spin < 200; spin++) {
        if (waitpid(-pid, NULL, WNOHANG) < 0 && errno == ECHILD)
            break;
        struct timespec nap = {0, 10 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }

    kbox_dispatch_cleanup_proc_fds(&ctx);
    if (ctx.proc_mem_fd >= 0)
        close(ctx.proc_mem_fd);
    if (ctx.proc_self_fd_dirfd >= 0)
        close(ctx.proc_self_fd_dirfd);
    close(listener_fd);

    if (has_log_thr)
        pthread_join(log_thr, NULL);

    if (*hooks->exit_efd >= 0) {
        close(*hooks->exit_efd);
        *hooks->exit_efd = -1;
    }

    return (exit_code >= 0) ? exit_code : 137;
}

static void cont_on_running(void *opaque)
{
    struct daemon_container *c = opaque;
    setup_gate_release(c);
    pthread_mutex_lock(&c->lock);
    c->state = CONT_RUNNING;
    c->started_at = time(NULL);
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->lock);

    if (g_verbose)
        fprintf(stderr, "kboxd: container %s (%s) started pid=%d ip=%s\n",
                c->name, c->id, (int) c->child_pid, c->ip);
}

static void cont_on_failed(void *opaque, const char *msg)
{
    fail_container_start((struct daemon_container *) opaque, msg);
}

static void close_container_ns_fds(struct daemon_container *c,
                                   const struct kbox_sysnrs *sysnrs)
{
    if (c->rootfs_dir_fd >= 0) {
        kbox_lkl_close(sysnrs, c->rootfs_dir_fd);
        c->rootfs_dir_fd = -1;
    }
    if (c->mnt_ns_fd >= 0) {
        kbox_lkl_close(sysnrs, c->mnt_ns_fd);
        c->mnt_ns_fd = -1;
    }
    if (c->net_ns_fd >= 0) {
        kbox_lkl_close(sysnrs, c->net_ns_fd);
        c->net_ns_fd = -1;
    }
    if (c->uts_ns_fd >= 0) {
        kbox_lkl_close(sysnrs, c->uts_ns_fd);
        c->uts_ns_fd = -1;
    }
}

/* Host-side directory helpers for the ephemeral storage backend. The daemon
 * runs on the pod filesystem here, not inside LKL: these calls create and
 * remove the directories that later appear in the container through hostfs. */
static int host_mkdir_p(const char *path, mode_t mode)
{
    char buf[PATH_MAX];
    size_t i;

    if (snprintf(buf, sizeof(buf), "%s", path) >= (int) sizeof(buf))
        return -ENAMETOOLONG;
    for (i = 1; buf[i]; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, mode) < 0 && errno != EEXIST)
            return -errno;
        buf[i] = '/';
    }
    if (mkdir(buf, mode) < 0 && errno != EEXIST)
        return -errno;
    return 0;
}

static int host_rm_rf(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *de;

    if (!d)
        return (errno == ENOENT) ? 0 : -errno;
    while ((de = readdir(d)) != NULL) {
        char child[PATH_MAX];
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >=
            (int) sizeof(child))
            continue;
        if (lstat(child, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode))
            host_rm_rf(child);
        else
            unlink(child);
    }
    closedir(d);
    rmdir(path);
    return 0;
}

/* Per-container worker thread: sets up LKL namespaces (NET_NS, MNT_NS,
 * UTS_NS), overlayfs rootfs, veth pair, host bind stubs, forks tracee with
 * seccomp listener, and runs kbox_supervise_ctx until exit.
 */
static void *container_worker_thread(void *arg)
{
    struct daemon_container *c = arg;
    const struct kbox_sysnrs *sysnrs = g_sysnrs;
    char cdir[128], upper[160], work[160], rootfs[160];
    char img_dir[160];
    char err_msg[256] = {0};

    setup_gate_acquire(c);
    if (kbox_lkl_new_thread_group_leader(sysnrs) < 0) {
        fail_container_start(c, "lkl_new_thread_group_leader failed");
        return NULL;
    }

    long ur = kbox_lkl_unshare(
        sysnrs, CLONE_FS | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS);
    if (ur < 0) {
        snprintf(err_msg, sizeof(err_msg), "lkl_unshare failed: %ld", ur);
        fail_container_start(c, err_msg);
        return NULL;
    }

    long mnt_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, "/proc/self/ns/mnt",
                                  O_RDONLY, 0);
    long net_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, "/proc/self/ns/net",
                                  O_RDONLY, 0);
    long uts_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, "/proc/self/ns/uts",
                                  O_RDONLY, 0);
    if (net_fd < 0) {
        if (mnt_fd >= 0)
            kbox_lkl_close(sysnrs, mnt_fd);
        if (uts_fd >= 0)
            kbox_lkl_close(sysnrs, uts_fd);
        snprintf(err_msg, sizeof(err_msg), "open /proc/self/ns/net: %ld",
                 net_fd);
        fail_container_start(c, err_msg);
        return NULL;
    }

    snprintf(cdir, sizeof(cdir), "/containers/%s", c->id);
    snprintf(upper, sizeof(upper), "/containers/%s/upper", c->id);
    snprintf(work, sizeof(work), "/containers/%s/work", c->id);
    snprintf(rootfs, sizeof(rootfs), "/containers/%s/rootfs", c->id);
    snprintf(img_dir, sizeof(img_dir), "/images/%s", c->image_id);

    /* Ephemeral storage on the host: create <ephemeral_root>/<id>/{upper,work}
     * and mount the tree at /containers/<id> inside the container's mount
     * namespace. One mount serves both overlay directories, which overlayfs
     * requires to live on the same filesystem. */
    if (g_config.ephemeral_hostfs) {
        static char eopts[8192];
        char host_dir[PATH_MAX];
        long dr, mr;

        snprintf(host_dir, sizeof(host_dir), "%s/%s/upper",
                 g_config.ephemeral_root, c->id);
        dr = host_mkdir_p(host_dir, 0777);
        if (dr < 0) {
            snprintf(err_msg, sizeof(err_msg), "ephemeral mkdir %s: %s",
                     host_dir, strerror(-dr));
            fail_container_start(c, err_msg);
            return NULL;
        }
        snprintf(host_dir, sizeof(host_dir), "%s/%s/work",
                 g_config.ephemeral_root, c->id);
        (void) host_mkdir_p(host_dir, 0777);

        snprintf(host_dir, sizeof(host_dir), "%s/%s", g_config.ephemeral_root,
                 c->id);
        snprintf(eopts, sizeof(eopts), "hostfs=%s", host_dir);
        lkl_mkdir_p(sysnrs, cdir, 0755);
        mr = kbox_lkl_mount(sysnrs, "none", cdir, "hostfs", 0, eopts);
        if (mr < 0) {
            snprintf(err_msg, sizeof(err_msg), "hostfs mount %s: %s", cdir,
                     kbox_err_text(mr));
            fail_container_start(c, err_msg);
            return NULL;
        }
    }

    /* World-writable upper/work: a container that drops privileges writes as
     * a non-root uid, and the check that matters is against the overlay inode
     * the guest sees (1777 for /tmp), after which the real write lands in the
     * upper layer -- which is owned by root. 0755 there fails such writes with
     * EACCES even though the guest directory mode allows them. */
    lkl_mkdir_p(sysnrs, upper, 0777);
    lkl_mkdir_p(sysnrs, work, 0777);
    /* mkdir applies the supervisor's umask, so a world-writable upper layer
     * needs an explicit chmod; without it a container that drops privileges
     * cannot write through the overlay. */
    (void) kbox_lkl_fchmodat(sysnrs, AT_FDCWD_LINUX, upper, 0777, 0);
    (void) kbox_lkl_fchmodat(sysnrs, AT_FDCWD_LINUX, work, 0777, 0);
    lkl_mkdir_p(sysnrs, rootfs, 0755);

    char ovl_opts[4096];
    memset(ovl_opts, 0, sizeof(ovl_opts));
    /* Lower layers: one hostfs mount per image layer when the shim provided a
     * layer list, otherwise the merged tree. Upper layers are host-backed when
     * ephemeral_hostfs is on, which also means trusted.overlay.* is refused
     * (no CAP_SYS_ADMIN on the host), so overlay is told to use
     * user.overlay.*. Layers carry their whiteouts in that namespace too. */
    {
        char lower[2048];
        int has_layers = image_lowerdir(c->image_id, lower, sizeof(lower));

        if (!has_layers)
            snprintf(lower, sizeof(lower), "%s", img_dir);
        snprintf(ovl_opts, sizeof(ovl_opts),
                 "lowerdir=%s,upperdir=%s,workdir=%s%s", lower, upper, work,
                 (g_config.ephemeral_hostfs || has_layers) ? ",userxattr" : "");
    }
    long mr = kbox_lkl_mount(sysnrs, "overlay", rootfs, "overlay", 0, ovl_opts);
    if (mr < 0) {
        if (g_verbose)
            fprintf(stderr,
                    "kboxd: overlay mount failed (%ld), copying rootfs\n", mr);
        char *cbuf = malloc(COPY_BUF_LEN);
        if (!cbuf || copy_lkl_tree_rec(sysnrs, img_dir, rootfs, cbuf) < 0) {
            free(cbuf);
            if (mnt_fd >= 0)
                kbox_lkl_close(sysnrs, mnt_fd);
            kbox_lkl_close(sysnrs, net_fd);
            if (uts_fd >= 0)
                kbox_lkl_close(sysnrs, uts_fd);
            fail_container_start(c, "rootfs setup failed");
            return NULL;
        }
        free(cbuf);
    }

    /* A private procfs: with /proc continued to the host kernel, everything
     * a guest reads from /proc describes kboxd (uid 0 in the guest but 65534
     * in /proc/self/status, the host kernel version, kboxd's own cmdline) and
     * the magic links have to be blocked as escape paths -- which breaks the
     * official images, whose entrypoints re-exec through /proc/self/exe.
     * Mounting a real procfs inside the container's mount namespace gives
     * those links their guest meaning. */
    {
        char proc_dir[256];
        snprintf(proc_dir, sizeof(proc_dir), "%s/proc", rootfs);
        lkl_mkdir_p(sysnrs, proc_dir, 0555);
        long pr = kbox_lkl_mount(sysnrs, "proc", proc_dir, "proc", 0, NULL);
        if (pr < 0 && g_verbose)
            fprintf(stderr, "kboxd: container procfs mount failed (%ld)\n", pr);
    }

    /* kbox reports /tmp as world-writable sticky in stat(2) but the image's
     * own mode is not preserved when the layer is unpacked, so a process that
     * drops privileges -- postgres, and anything else that puts sockets or
     * scratch files in /tmp -- gets EACCES on a directory the guest is told is
     * 1777. Make the real mode match what the guest is shown. */
    {
        char tmp_p[256];
        snprintf(tmp_p, sizeof(tmp_p), "%s/tmp", rootfs);
        long cr = kbox_lkl_fchmodat(sysnrs, AT_FDCWD_LINUX, tmp_p, 01777, 0);
        if (g_verbose)
            fprintf(stderr, "kboxd: chmod %s -> %ld\n", tmp_p, cr);
        (void) cr;
        snprintf(tmp_p, sizeof(tmp_p), "%s/var/tmp", rootfs);
        (void) kbox_lkl_fchmodat(sysnrs, AT_FDCWD_LINUX, tmp_p, 01777, 0);
    }

    /* A fresh interface name for every start. A start that failed after the
     * veth was created leaves it behind, and starting the same container again
     * (compose retries one that is still "Created") asked for the same name and
     * got EEXIST, failing every container that followed. */
    snprintf(c->host_if, sizeof(c->host_if), "veth%d",
             __atomic_add_fetch(&g_veth_seq, 1, __ATOMIC_SEQ_CST));
    int vrc =
        kbox_daemon_net_create_veth(sysnrs, c->host_if, "eth0", net_fd, c->ip);
    if (vrc < 0) {
        if (mnt_fd >= 0)
            kbox_lkl_close(sysnrs, mnt_fd);
        kbox_lkl_close(sysnrs, net_fd);
        if (uts_fd >= 0)
            kbox_lkl_close(sysnrs, uts_fd);
        snprintf(err_msg, sizeof(err_msg), "veth create failed: %d", vrc);
        fail_container_start(c, err_msg);
        return NULL;
    }

    const char *gw_ip = kbox_daemon_net_gateway_ip();
    kbox_net_configure_ipv4(sysnrs, "lo", "127.0.0.1", "255.0.0.0", NULL);
    if (kbox_net_configure_ipv4(sysnrs, "eth0", c->ip, KBOX_DAEMON_HOST_MASK,
                                gw_ip) < 0) {
        if (mnt_fd >= 0)
            kbox_lkl_close(sysnrs, mnt_fd);
        kbox_lkl_close(sysnrs, net_fd);
        if (uts_fd >= 0)
            kbox_lkl_close(sysnrs, uts_fd);
        fail_container_start(c, "container eth0 config failed");
        kbox_daemon_net_delete_link(sysnrs, c->host_if, c->ip);
        return NULL;
    }

    const char *hn = c->hostname[0] ? c->hostname : c->name;
    kbox_lkl_sethostname(sysnrs, hn, (long) strlen(hn));

    char etc_dir[256], resolv_p[256], hosts_p[256];
    snprintf(etc_dir, sizeof(etc_dir), "%s/etc", rootfs);
    lkl_mkdir_p(sysnrs, etc_dir, 0755);

    snprintf(resolv_p, sizeof(resolv_p), "%s/etc/resolv.conf", rootfs);
    long rfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, resolv_p,
                               0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
    if (rfd >= 0) {
        char res[2048];
        size_t rlen = 0;
        if (c->host_net) {
            /* Host networking: the container resolves through the pod's own
             * sockets, so it needs the pod's nameservers, not the LKL
             * gateway. */
            FILE *hf = fopen("/etc/resolv.conf", "r");
            if (hf) {
                rlen = fread(res, 1, sizeof(res) - 1, hf);
                fclose(hf);
            }
        }
        if (rlen == 0)
            rlen =
                (size_t) snprintf(res, sizeof(res), "nameserver %s\n", gw_ip);
        kbox_lkl_write(sysnrs, rfd, res, (long) rlen);
        kbox_lkl_close(sysnrs, rfd);
    }

    snprintf(hosts_p, sizeof(hosts_p), "%s/etc/hosts", rootfs);
    long hfd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, hosts_p,
                               0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
    if (hfd >= 0) {
        char *hbuf = malloc(16384);
        if (hbuf) {
            size_t hlen = kbox_daemon_dns_format_hosts(hbuf, 16384);
            kbox_lkl_write(sysnrs, hfd, hbuf, (long) hlen);
            free(hbuf);
        }
        kbox_lkl_close(sysnrs, hfd);
    }

    /* NFS-backed volumes: bind the requested subtree of an already-mounted
     * export onto the container's destination. Done before chroot because the
     * export lives outside the container's rootfs; the mount namespace is
     * already private to this container.
     */
    if (g_config.nfs_count > 0 && c->bind_count > 0) {
        char nfs_err[256] = {0};
        if (kbox_daemon_nfs_bind_container(sysnrs, &g_config, rootfs, c->binds,
                                           c->bind_count, nfs_err,
                                           sizeof(nfs_err)) < 0) {
            if (mnt_fd >= 0)
                kbox_lkl_close(sysnrs, mnt_fd);
            kbox_lkl_close(sysnrs, net_fd);
            if (uts_fd >= 0)
                kbox_lkl_close(sysnrs, uts_fd);
            fail_container_start(
                c, nfs_err[0] ? nfs_err : "nfs volume bind failed");
            kbox_daemon_net_delete_link(sysnrs, c->host_if, c->ip);
            return NULL;
        }
    }

    if (kbox_lkl_chroot(sysnrs, rootfs) < 0 ||
        kbox_lkl_chdir(sysnrs, "/") < 0) {
        if (mnt_fd >= 0)
            kbox_lkl_close(sysnrs, mnt_fd);
        kbox_lkl_close(sysnrs, net_fd);
        if (uts_fd >= 0)
            kbox_lkl_close(sysnrs, uts_fd);
        fail_container_start(c, "chroot into rootfs failed");
        kbox_daemon_net_delete_link(sysnrs, c->host_if, c->ip);
        return NULL;
    }

    (void) kbox_apply_recommended_mounts(sysnrs, KBOX_MOUNT_FULL);

    long rdir_fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, "/",
                                   O_RDONLY | LKL_O_DIRECTORY, 0);

    if (c->workdir[0]) {
        lkl_mkdir_p(sysnrs, c->workdir, 0755);
        kbox_lkl_chdir(sysnrs, c->workdir);
    }

    if (c->bind_count > 0)
        kbox_ensure_lkl_bind_stubs(sysnrs, c->binds, c->bind_count);

    for (int i = 0; i < c->port_count; i++) {
        int prc = kbox_daemon_port_add(sysnrs, c->ports[i].host_ip,
                                       c->ports[i].host_port, c->ip,
                                       c->ports[i].container_port);
        if (prc < 0)
            fprintf(stderr, "kboxd: port forward %s:%d -> %s:%d failed: %s\n",
                    c->ports[i].host_ip, c->ports[i].host_port, c->ip,
                    c->ports[i].container_port, strerror(-prc));
    }

    pthread_mutex_lock(&c->lock);
    c->mnt_ns_fd = (int) mnt_fd;
    c->net_ns_fd = (int) net_fd;
    c->uts_ns_fd = (int) uts_fd;
    c->rootfs_dir_fd = (int) rdir_fd;
    pthread_mutex_unlock(&c->lock);

    struct daemon_proc_env pe = {
        .binds = c->binds,
        .bind_count = c->bind_count,
        /* 0: the container sees the host procfs, so the exec path rewrite to
         * /proc/self/fd/<n> resolves for the kernel that performs the exec.
         * With an LKL-only procfs it does not, and every exec past the first
         * failed with ENOENT -- which is what killed postgres' bootstrap. The
         * guest-meaning /proc/self/{exe,cwd,root} links are synthesised in the
         * dispatch, so they do not need a private procfs. */
        .private_proc = 0,
        .workdir = c->workdir,
        .cmd = c->cmd,
        .cmd_count = c->cmd_count,
        .env = c->env,
        .env_count = c->env_count,
        .own_ip = c->ip,
        .host_net = c->host_net,
        .mem_limit = c->mem_limit,
    };
    struct supervised_proc_hooks hooks = {
        .opaque = c,
        .child_pid = &c->child_pid,
        .exit_efd = &c->exit_efd,
        .exit_status = &c->child_exit_status,
        .on_running = cont_on_running,
        .on_failed = cont_on_failed,
    };
    int exit_code = launch_and_supervise_proc(sysnrs, &pe, c->log_path, &hooks);
    setup_gate_release(c);

    pthread_mutex_lock(&c->lock);
    c->state = CONT_EXITED;
    if (exit_code >= 0)
        c->exit_code = exit_code;
    c->finished_at = time(NULL);
    pthread_cond_broadcast(&c->cv);
    while (c->active_execs > 0)
        pthread_cond_wait(&c->cv, &c->lock);

    /* Release NFS subtree bind mounts before the namespace goes away. */
    if (g_config.nfs_count > 0 && c->bind_count > 0) {
        char unbind_root[160];
        snprintf(unbind_root, sizeof(unbind_root), "/containers/%s/rootfs",
                 c->id);
        kbox_daemon_nfs_unbind_container(sysnrs, unbind_root, c->binds,
                                         c->bind_count);
    }
    close_container_ns_fds(c, sysnrs);
    pthread_mutex_unlock(&c->lock);

    kbox_daemon_port_remove_ip(c->ip);
    kbox_daemon_net_delete_link(sysnrs, c->host_if, c->ip);

    if (g_verbose)
        fprintf(stderr, "kboxd: container %s exited (%d)\n", c->name,
                c->exit_code);
    return NULL;
}

static void fail_exec_start(struct daemon_exec *e, const char *msg)
{
    pthread_mutex_lock(&e->lock);
    snprintf(e->start_err, sizeof(e->start_err), "%s", msg);
    e->state = EXEC_EXITED;
    e->exit_code = 127;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->lock);
}

static void exec_on_running(void *opaque)
{
    struct daemon_exec *e = opaque;
    pthread_mutex_lock(&e->lock);
    e->state = EXEC_RUNNING;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->lock);
}

static void exec_on_failed(void *opaque, const char *msg)
{
    fail_exec_start((struct daemon_exec *) opaque, msg);
}

/* Per-exec worker thread: joins target container's LKL UTS/NET/MNT
 * namespaces and chroot, then executes & supervises the command.
 */
static void *exec_worker_thread(void *arg)
{
    struct daemon_exec *e = arg;
    struct daemon_container *c = e->cont;
    const struct kbox_sysnrs *sysnrs = g_sysnrs;

    long tgl = kbox_lkl_new_thread_group_leader(sysnrs);
    long ufs = (tgl >= 0) ? kbox_lkl_unshare(sysnrs, CLONE_FS) : tgl;
    if (tgl < 0 || ufs < 0) {
        char em[128];
        snprintf(em, sizeof(em), "lkl thread/fs setup failed: tgl=%ld ufs=%ld",
                 tgl, ufs);
        fail_exec_start(e, em);
        goto dec_active;
    }

    pthread_mutex_lock(&c->lock);
    if (c->state != CONT_RUNNING || c->mnt_ns_fd < 0 || c->net_ns_fd < 0 ||
        c->uts_ns_fd < 0 || c->rootfs_dir_fd < 0) {
        pthread_mutex_unlock(&c->lock);
        fail_exec_start(e, "container is not running");
        goto dec_active;
    }
    int uts_fd = c->uts_ns_fd;
    int net_fd = c->net_ns_fd;
    int mnt_fd = c->mnt_ns_fd;
    int rdir_fd = c->rootfs_dir_fd;
    pthread_mutex_unlock(&c->lock);

    long r_uts = kbox_lkl_setns(sysnrs, uts_fd, CLONE_NEWUTS);
    long r_net = kbox_lkl_setns(sysnrs, net_fd, CLONE_NEWNET);
    long r_mnt = kbox_lkl_setns(sysnrs, mnt_fd, CLONE_NEWNS);
    long r_chd = kbox_lkl_fchdir(sysnrs, rdir_fd);
    long r_chr = kbox_lkl_chroot(sysnrs, ".");
    if (r_uts < 0 || r_net < 0 || r_mnt < 0 || r_chd < 0 || r_chr < 0) {
        char em[192];
        snprintf(
            em, sizeof(em),
            "enter ns failed: uts=%ld net=%ld mnt=%ld fchdir=%ld chroot=%ld",
            r_uts, r_net, r_mnt, r_chd, r_chr);
        fail_exec_start(e, em);
        goto dec_active;
    }

    if (e->workdir[0]) {
        lkl_mkdir_p(sysnrs, e->workdir, 0755);
        kbox_lkl_chdir(sysnrs, e->workdir);
    } else {
        kbox_lkl_chdir(sysnrs, "/");
    }

    struct daemon_proc_env pe = {
        .binds = e->binds,
        .bind_count = e->bind_count,
        .workdir = e->workdir[0] ? e->workdir : "/",
        .cmd = e->cmd,
        .cmd_count = e->cmd_count,
        .env = e->env,
        .env_count = e->env_count,
        .stdin_path = e->stdin_file[0] ? e->stdin_file : NULL,
        .own_ip = c->ip,
        .host_net = c->host_net,
        .mem_limit = c->mem_limit,
    };
    struct supervised_proc_hooks hooks = {
        .opaque = e,
        .child_pid = &e->child_pid,
        .exit_efd = &e->exit_efd,
        .exit_status = &e->child_exit_status,
        .on_running = exec_on_running,
        .on_failed = exec_on_failed,
    };
    int exit_code = launch_and_supervise_proc(sysnrs, &pe, e->log_path, &hooks);

    pthread_mutex_lock(&e->lock);
    e->state = EXEC_EXITED;
    if (exit_code >= 0)
        e->exit_code = exit_code;
    pthread_cond_broadcast(&e->cv);
    pthread_mutex_unlock(&e->lock);

dec_active:
    pthread_mutex_lock(&c->lock);
    c->active_execs--;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->lock);
    return NULL;
}

/* Container lookup & lifecycle operations. */

static struct daemon_container *find_container_locked(const char *id_or_name)
{
    size_t n = strlen(id_or_name);
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        struct daemon_container *c = &g_containers[i];
        if (c->state == CONT_FREE)
            continue;
        if (strcmp(c->id, id_or_name) == 0 ||
            strcmp(c->name, id_or_name) == 0 ||
            (n >= 4 && strncmp(c->id, id_or_name, n) == 0))
            return c;
    }
    return NULL;
}

static struct daemon_exec *find_exec_locked(const char *exec_id)
{
    for (int i = 0; i < MAX_EXECS; i++) {
        if (g_execs[i].state != EXEC_FREE &&
            strcmp(g_execs[i].id, exec_id) == 0)
            return &g_execs[i];
    }
    return NULL;
}

static void free_exec_fields(struct daemon_exec *e)
{
    /* The stdin spool belongs to this exec alone: nothing else reads it after
     * the guest process is gone, and leaving it behind leaks a file per
     * `docker exec -i` under the log dir. */
    if (e->stdin_file[0])
        unlink(e->stdin_file);
    free_str_vec(e->cmd);
    e->cmd_count = 0;
    free_str_vec(e->env);
    e->env_count = 0;
}

static void free_container_fields(struct daemon_container *c)
{
    free_str_vec(c->cmd);
    c->cmd_count = 0;
    free_str_vec(c->env);
    c->env_count = 0;
}

/* RPC handlers. */

static void send_rpc_line(int fd, const char *line)
{
    size_t len = strlen(line);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, line + off, len - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return;
        off += (size_t) w;
    }
}

static void send_rpc_err(int fd, const char *msg)
{
    char buf[1024];
    size_t pos = 0;
    pos += (size_t) snprintf(buf, sizeof(buf), "{\"ok\":false,\"error\":\"");
    pos = kbox_json_escape_append(buf, sizeof(buf), pos, msg);
    snprintf(buf + pos, sizeof(buf) - pos, "\"}\n");
    send_rpc_line(fd, buf);
}

static int parse_port_num(const char *s, int *out_port)
{
    if (!s || !*s)
        return -EINVAL;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > 65535)
        return -EINVAL;
    *out_port = (int) v;
    return 0;
}

/* Parse "HP:CP" or "HOST_IP:HP:CP". Empty HOST_IP defaults to "0.0.0.0". */
static int parse_port_spec(const char *spec, struct port_binding_spec *out)
{
    if (!spec || !*spec || !out)
        return -EINVAL;
    const char *c1 = strchr(spec, ':');
    if (!c1)
        return -EINVAL;
    const char *c2 = strchr(c1 + 1, ':');

    char hp_buf[16];
    const char *cp_str = NULL;
    if (!c2) {
        size_t hlen = (size_t) (c1 - spec);
        if (hlen == 0 || hlen >= sizeof(hp_buf))
            return -EINVAL;
        memcpy(hp_buf, spec, hlen);
        hp_buf[hlen] = '\0';
        cp_str = c1 + 1;
        snprintf(out->host_ip, sizeof(out->host_ip), "0.0.0.0");
    } else {
        if (strchr(c2 + 1, ':'))
            return -EINVAL;
        size_t iplen = (size_t) (c1 - spec);
        size_t hlen = (size_t) (c2 - (c1 + 1));
        if (iplen >= sizeof(out->host_ip) || hlen == 0 ||
            hlen >= sizeof(hp_buf))
            return -EINVAL;
        if (iplen == 0) {
            snprintf(out->host_ip, sizeof(out->host_ip), "0.0.0.0");
        } else {
            memcpy(out->host_ip, spec, iplen);
            out->host_ip[iplen] = '\0';
            struct in_addr tmp;
            if (strcmp(out->host_ip, "0.0.0.0") != 0 &&
                inet_pton(AF_INET, out->host_ip, &tmp) != 1)
                return -EINVAL;
        }
        memcpy(hp_buf, c1 + 1, hlen);
        hp_buf[hlen] = '\0';
        cp_str = c2 + 1;
    }

    if (parse_port_num(hp_buf, &out->host_port) < 0 ||
        parse_port_num(cp_str, &out->container_port) < 0)
        return -EINVAL;
    return 0;
}

static void handle_rpc_line(int client_fd, const char *req)
{
    char op[64];
    if (kbox_json_get_str(req, "op", op, sizeof(op)) < 0) {
        send_rpc_err(client_fd, "missing op");
        return;
    }

    if (strcmp(op, "ping") == 0) {
        send_rpc_line(client_fd, "{\"ok\":true,\"lkl\":true}\n");
        return;
    }

    if (strcmp(op, "shutdown") == 0) {
        __atomic_store_n(&g_daemon_stop, 1, __ATOMIC_RELEASE);
        send_rpc_line(client_fd, "{\"ok\":true}\n");
        return;
    }

    if (strcmp(op, "image_import") == 0) {
        char img_id[128], src[PATH_MAX];
        if (kbox_json_get_str(req, "id", img_id, sizeof(img_id)) < 0 ||
            kbox_json_get_str(req, "src", src, sizeof(src)) < 0) {
            send_rpc_err(client_fd, "image_import requires id and src");
            return;
        }
        int rc;
        /* One slot more than the record can hold, so an image with too many
         * layers is rejected instead of silently losing its base layers. */
        char *layer_list[MAX_IMAGE_LAYERS + 1];
        int layer_count = kbox_json_get_str_array(req, "layers", layer_list,
                                                  MAX_IMAGE_LAYERS + 1);
        int li;

        if (layer_count > MAX_IMAGE_LAYERS) {
            for (li = 0; li < layer_count; li++)
                free(layer_list[li]);
            send_rpc_err(client_fd, "image has too many layers");
            return;
        }

        if (g_config.images_hostfs) {
            rc = image_record_add(img_id, src, layer_list, layer_count);
            if (rc == 0)
                rc = image_mount_hostfs(g_sysnrs, img_id);
            if (rc == 0 && g_verbose) {
                int lc = image_layer_count(img_id);

                if (lc > 0)
                    fprintf(stderr,
                            "kboxd: image %s mounted from %d layer(s)\n",
                            img_id, lc);
                else
                    fprintf(stderr, "kboxd: image %s mounted from %s\n", img_id,
                            src);
            }
        } else {
            rc = import_image_rootfs(g_sysnrs, img_id, src);
        }
        for (li = 0; li < layer_count; li++)
            free(layer_list[li]);
        if (rc < 0) {
            char msg[128];
            snprintf(msg, sizeof(msg), "import failed: %d", rc);
            send_rpc_err(client_fd, msg);
        } else {
            send_rpc_line(client_fd, "{\"ok\":true}\n");
        }
        return;
    }

    if (strcmp(op, "dns_set") == 0) {
        char name[KBOX_DAEMON_MAX_ALIAS], ip[32];
        if (kbox_json_get_str(req, "name", name, sizeof(name)) < 0 ||
            kbox_json_get_str(req, "ip", ip, sizeof(ip)) < 0) {
            send_rpc_err(client_fd, "dns_set requires name and ip");
            return;
        }
        if (kbox_daemon_dns_register(name, ip) < 0)
            send_rpc_err(client_fd, "dns register failed");
        else
            send_rpc_line(client_fd, "{\"ok\":true}\n");
        return;
    }

    if (strcmp(op, "port_add") == 0) {
        long hp = 0, cp = 0;
        char ip[32];
        char host_ip[32];
        snprintf(host_ip, sizeof(host_ip), "0.0.0.0");
        kbox_json_get_str(req, "host_ip", host_ip, sizeof(host_ip));
        if (kbox_json_get_int(req, "host_port", &hp) < 0 ||
            kbox_json_get_int(req, "container_port", &cp) < 0 ||
            kbox_json_get_str(req, "ip", ip, sizeof(ip)) < 0) {
            send_rpc_err(client_fd, "port_add invalid args");
            return;
        }
        int rc =
            kbox_daemon_port_add(g_sysnrs, host_ip, (int) hp, ip, (int) cp);
        if (rc < 0) {
            char msg[128];
            snprintf(msg, sizeof(msg), "port_add failed: %s", strerror(-rc));
            send_rpc_err(client_fd, msg);
        } else {
            send_rpc_line(client_fd, "{\"ok\":true}\n");
        }
        return;
    }

    if (strcmp(op, "container_create") == 0) {
        char cid[80], img[128], name[64];
        if (kbox_json_get_str(req, "id", cid, sizeof(cid)) < 0 ||
            kbox_json_get_str(req, "image", img, sizeof(img)) < 0) {
            send_rpc_err(client_fd, "container_create requires id and image");
            return;
        }
        if (kbox_json_get_str(req, "name", name, sizeof(name)) < 0)
            snprintf(name, sizeof(name), "%.12s", cid);

        pthread_mutex_lock(&g_cont_table_lock);
        if (find_container_locked(cid)) {
            pthread_mutex_unlock(&g_cont_table_lock);
            send_rpc_err(client_fd, "container already exists");
            return;
        }
        struct daemon_container *slot = NULL;
        int slot_idx = -1;
        for (int i = 0; i < MAX_CONTAINERS; i++) {
            if (g_containers[i].state == CONT_FREE) {
                slot = &g_containers[i];
                slot_idx = i;
                break;
            }
        }
        if (!slot) {
            pthread_mutex_unlock(&g_cont_table_lock);
            send_rpc_err(client_fd, "container table full");
            return;
        }

        memset(slot, 0, sizeof(*slot));
        slot->slot = slot_idx;
        slot->state = CONT_CREATED;
        slot->mnt_ns_fd = -1;
        slot->net_ns_fd = -1;
        slot->uts_ns_fd = -1;
        slot->rootfs_dir_fd = -1;
        slot->exit_efd = -1;
        slot->child_exit_status = -1;
        pthread_mutex_init(&slot->lock, NULL);
        /* cppcheck-suppress nullPointer */
        pthread_cond_init(&slot->cv, NULL);

        snprintf(slot->id, sizeof(slot->id), "%s", cid);
        snprintf(slot->name, sizeof(slot->name), "%s", name);
        snprintf(slot->image_id, sizeof(slot->image_id), "%s", img);
        if (kbox_json_get_str(req, "hostname", slot->hostname,
                              sizeof(slot->hostname)) < 0)
            snprintf(slot->hostname, sizeof(slot->hostname), "%.12s", cid);
        if (kbox_json_get_str(req, "workdir", slot->workdir,
                              sizeof(slot->workdir)) < 0)
            snprintf(slot->workdir, sizeof(slot->workdir), "/");

        if (kbox_json_get_str(req, "ip", slot->ip, sizeof(slot->ip)) < 0 ||
            !slot->ip[0])
            kbox_daemon_net_alloc_ip(slot->ip, sizeof(slot->ip));

        int vseq = __atomic_add_fetch(&g_veth_seq, 1, __ATOMIC_SEQ_CST);
        snprintf(slot->host_if, sizeof(slot->host_if), "veth%d", vseq);
        snprintf(slot->log_path, sizeof(slot->log_path), "%s/%s.log",
                 g_config.log_dir[0] ? g_config.log_dir : DAEMON_LOG_DIR, cid);

        slot->cmd_count =
            kbox_json_get_str_array(req, "cmd", slot->cmd, MAX_CMD_ARGS);
        slot->env_count =
            kbox_json_get_str_array(req, "env", slot->env, MAX_ENV_VARS);

        char *bind_strs[KBOX_HOST_BINDS_MAX];
        memset(bind_strs, 0, sizeof(bind_strs));
        int nb = kbox_json_get_str_array(req, "binds", bind_strs,
                                         KBOX_HOST_BINDS_MAX);
        for (int i = 0; i < nb; i++) {
            if (kbox_parse_host_volume(bind_strs[i],
                                       &slot->binds[slot->bind_count]) == 0)
                slot->bind_count++;
            free(bind_strs[i]);
        }

        char *alias_strs[MAX_ALIASES];
        memset(alias_strs, 0, sizeof(alias_strs));
        int na =
            kbox_json_get_str_array(req, "aliases", alias_strs, MAX_ALIASES);
        for (int i = 0; i < na; i++) {
            snprintf(slot->aliases[slot->alias_count++], KBOX_DAEMON_MAX_ALIAS,
                     "%s", alias_strs[i]);
            kbox_daemon_dns_register(alias_strs[i], slot->ip);
            free(alias_strs[i]);
        }
        kbox_daemon_dns_register(slot->name, slot->ip);
        char short_id[13];
        snprintf(short_id, sizeof(short_id), "%.12s", slot->id);
        kbox_daemon_dns_register(short_id, slot->ip);

        slot->host_net = kbox_json_get_bool(req, "host_net", 0);
        {
            long ml = 0;
            if (kbox_json_get_int(req, "mem_limit", &ml) == 0 && ml > 0)
                slot->mem_limit = ml;
        }
        char *port_strs[16];
        memset(port_strs, 0, sizeof(port_strs));
        int np = kbox_json_get_str_array(req, "ports", port_strs, 16);
        for (int i = 0; i < np; i++) {
            if (slot->port_count < 16 &&
                parse_port_spec(port_strs[i], &slot->ports[slot->port_count]) ==
                    0) {
                slot->port_count++;
            }
            free(port_strs[i]);
        }

        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"ok\":true,\"id\":\"%s\",\"ip\":\"%s\","
                 "\"gateway\":\"%s\",\"prefix_len\":32,\"log_path\":\"%s\"}\n",
                 slot->id, slot->ip, kbox_daemon_net_gateway_ip(),
                 slot->log_path);
        pthread_mutex_unlock(&g_cont_table_lock);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "exec_start") == 0) {
        char eid[80], cid_arg[80], wd[PATH_MAX];
        if (kbox_json_get_str(req, "exec_id", eid, sizeof(eid)) < 0 ||
            kbox_json_get_str(req, "container_id", cid_arg, sizeof(cid_arg)) <
                0) {
            send_rpc_err(client_fd,
                         "exec_start requires exec_id and container_id");
            return;
        }
        pthread_mutex_lock(&g_cont_table_lock);
        struct daemon_container *tc = find_container_locked(cid_arg);
        pthread_mutex_unlock(&g_cont_table_lock);
        if (!tc) {
            send_rpc_err(client_fd, "no such container");
            return;
        }

        pthread_mutex_lock(&tc->lock);
        if (tc->state != CONT_RUNNING || tc->mnt_ns_fd < 0 ||
            tc->net_ns_fd < 0 || tc->uts_ns_fd < 0 || tc->rootfs_dir_fd < 0) {
            pthread_mutex_unlock(&tc->lock);
            send_rpc_err(client_fd, "container is not running");
            return;
        }
        tc->active_execs++;

        pthread_mutex_lock(&g_exec_table_lock);
        struct daemon_exec *eslot = NULL;
        for (int i = 0; i < MAX_EXECS; i++) {
            if (g_execs[i].state == EXEC_FREE) {
                eslot = &g_execs[i];
                break;
            }
        }
        if (!eslot) {
            pthread_mutex_unlock(&g_exec_table_lock);
            tc->active_execs--;
            pthread_cond_broadcast(&tc->cv);
            pthread_mutex_unlock(&tc->lock);
            send_rpc_err(client_fd, "exec table full");
            return;
        }
        memset(eslot, 0, sizeof(*eslot));
        eslot->state = EXEC_STARTING;
        eslot->exit_efd = -1;
        eslot->child_exit_status = -1;
        eslot->cont = tc;
        pthread_mutex_init(&eslot->lock, NULL);
        /* cppcheck-suppress nullPointer */
        pthread_cond_init(&eslot->cv, NULL);
        snprintf(eslot->id, sizeof(eslot->id), "%s", eid);
        snprintf(eslot->container_id, sizeof(eslot->container_id), "%s",
                 tc->id);
        snprintf(eslot->log_path, sizeof(eslot->log_path), "%s/exec-%s.log",
                 g_config.log_dir[0] ? g_config.log_dir : DAEMON_LOG_DIR, eid);
        /* `docker exec -i`: the frontend spools the request body to this path
         * before starting the exec, because the guest reads its stdin from a
         * host file it can seek and re-read, not from a live socket. */
        if (kbox_json_get_str(req, "stdin_path", eslot->stdin_path,
                              sizeof(eslot->stdin_path)) == 0 &&
            eslot->stdin_path[0]) {
            snprintf(eslot->stdin_file, sizeof(eslot->stdin_file), "%s",
                     eslot->stdin_path);
        }

        if (kbox_json_get_str(req, "workdir", wd, sizeof(wd)) == 0 && wd[0])
            snprintf(eslot->workdir, sizeof(eslot->workdir), "%s", wd);
        else
            snprintf(eslot->workdir, sizeof(eslot->workdir), "%s", tc->workdir);

        eslot->cmd_count =
            kbox_json_get_str_array(req, "cmd", eslot->cmd, MAX_CMD_ARGS);
        int req_env =
            kbox_json_get_str_array(req, "env", eslot->env, MAX_ENV_VARS);
        eslot->env_count = req_env;
        /* Merge container env if not already present in exec env. */
        for (int i = 0; i < tc->env_count && eslot->env_count < MAX_ENV_VARS;
             i++) {
            const char *eq = strchr(tc->env[i], '=');
            size_t klen = eq ? (size_t) (eq - tc->env[i] + 1) : 0;
            int found = 0;
            for (int j = 0; j < req_env && klen > 0; j++) {
                if (strncmp(eslot->env[j], tc->env[i], klen) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found)
                eslot->env[eslot->env_count++] = strdup(tc->env[i]);
        }
        eslot->bind_count = tc->bind_count;
        if (eslot->bind_count > 0)
            memcpy(eslot->binds, tc->binds,
                   eslot->bind_count * sizeof(eslot->binds[0]));
        pthread_mutex_unlock(&g_exec_table_lock);
        pthread_mutex_unlock(&tc->lock);

        pthread_mutex_lock(&eslot->lock);
        if (pthread_create(&eslot->thread, NULL, exec_worker_thread, eslot) !=
            0) {
            pthread_mutex_unlock(&eslot->lock);
            pthread_mutex_lock(&tc->lock);
            tc->active_execs--;
            pthread_cond_broadcast(&tc->cv);
            pthread_mutex_unlock(&tc->lock);
            pthread_mutex_lock(&g_exec_table_lock);
            free_exec_fields(eslot);
            pthread_mutex_destroy(&eslot->lock);
            pthread_cond_destroy(&eslot->cv);
            memset(eslot, 0, sizeof(*eslot));
            eslot->state = EXEC_FREE;
            pthread_mutex_unlock(&g_exec_table_lock);
            send_rpc_err(client_fd, "pthread_create failed");
            return;
        }
        eslot->thread_started = 1;
        while (eslot->state == EXEC_STARTING)
            pthread_cond_wait(&eslot->cv, &eslot->lock);

        if (eslot->state != EXEC_RUNNING && eslot->start_err[0]) {
            char emsg[256];
            snprintf(emsg, sizeof(emsg), "%s", eslot->start_err);
            pthread_t et = eslot->thread;
            pthread_mutex_unlock(&eslot->lock);
            pthread_join(et, NULL);
            pthread_mutex_lock(&g_exec_table_lock);
            free_exec_fields(eslot);
            pthread_mutex_destroy(&eslot->lock);
            pthread_cond_destroy(&eslot->cv);
            memset(eslot, 0, sizeof(*eslot));
            eslot->state = EXEC_FREE;
            pthread_mutex_unlock(&g_exec_table_lock);
            send_rpc_err(client_fd, emsg);
            return;
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"ok\":true,\"pid\":%d,\"log_path\":\"%s\"}\n",
                 (int) eslot->child_pid, eslot->log_path);
        pthread_mutex_unlock(&eslot->lock);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "exec_wait") == 0) {
        char eid[80];
        if (kbox_json_get_str(req, "exec_id", eid, sizeof(eid)) < 0) {
            send_rpc_err(client_fd, "exec_wait requires exec_id");
            return;
        }
        pthread_mutex_lock(&g_exec_table_lock);
        struct daemon_exec *e = find_exec_locked(eid);
        pthread_mutex_unlock(&g_exec_table_lock);
        if (!e) {
            send_rpc_err(client_fd, "no such exec");
            return;
        }
        pthread_mutex_lock(&e->lock);
        while (e->state == EXEC_STARTING || e->state == EXEC_RUNNING)
            pthread_cond_wait(&e->cv, &e->lock);
        int ec = e->exit_code;
        int started = e->thread_started;
        pthread_t et = e->thread;
        e->thread_started = 0;
        pthread_mutex_unlock(&e->lock);

        if (started)
            pthread_join(et, NULL);

        pthread_mutex_lock(&g_exec_table_lock);
        free_exec_fields(e);
        pthread_mutex_destroy(&e->lock);
        pthread_cond_destroy(&e->cv);
        memset(e, 0, sizeof(*e));
        e->state = EXEC_FREE;
        pthread_mutex_unlock(&g_exec_table_lock);

        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":true,\"exit_code\":%d}\n", ec);
        send_rpc_line(client_fd, resp);
        return;
    }

    char cid[80];
    if (kbox_json_get_str(req, "id", cid, sizeof(cid)) < 0) {
        send_rpc_err(client_fd, "missing container id");
        return;
    }

    pthread_mutex_lock(&g_cont_table_lock);
    struct daemon_container *c = find_container_locked(cid);
    pthread_mutex_unlock(&g_cont_table_lock);
    if (!c) {
        send_rpc_err(client_fd, "no such container");
        return;
    }

    if (strcmp(op, "container_start") == 0) {
        pthread_mutex_lock(&c->lock);
        if (c->state == CONT_RUNNING) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"ok\":true,\"pid\":%d,\"ip\":\"%s\"}\n",
                     (int) c->child_pid, c->ip);
            pthread_mutex_unlock(&c->lock);
            send_rpc_line(client_fd, resp);
            return;
        }
        if (c->state == CONT_EXITED && c->worker_started) {
            pthread_mutex_unlock(&c->lock);
            pthread_join(c->worker_thread, NULL);
            pthread_mutex_lock(&c->lock);
            c->worker_started = 0;
        }
        c->state = CONT_STARTING;
        c->start_err[0] = '\0';
        c->child_pid = 0;
        if (pthread_create(&c->worker_thread, NULL, container_worker_thread,
                           c) != 0) {
            c->state = CONT_CREATED;
            pthread_mutex_unlock(&c->lock);
            send_rpc_err(client_fd, "pthread_create failed");
            return;
        }
        c->worker_started = 1;
        while (c->state == CONT_STARTING)
            pthread_cond_wait(&c->cv, &c->lock);

        if (c->state != CONT_RUNNING && c->start_err[0]) {
            char emsg[256];
            snprintf(emsg, sizeof(emsg), "%s", c->start_err);
            pthread_mutex_unlock(&c->lock);
            send_rpc_err(client_fd, emsg);
            return;
        }
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"ok\":true,\"pid\":%d,\"ip\":\"%s\",\"log_path\":\"%s\"}\n",
                 (int) c->child_pid, c->ip, c->log_path);
        pthread_mutex_unlock(&c->lock);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "container_stop") == 0) {
        long timeout_s = 10;
        (void) kbox_json_get_int(req, "timeout", &timeout_s);
        if (timeout_s < 1)
            timeout_s = 1;

        pthread_mutex_lock(&c->lock);
        if (c->state == CONT_RUNNING && c->child_pid > 0)
            kill(-c->child_pid, SIGTERM);

        struct timespec dl;
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += timeout_s;
        while (c->state == CONT_RUNNING || c->state == CONT_STARTING) {
            if (pthread_cond_timedwait(&c->cv, &c->lock, &dl) == ETIMEDOUT)
                break;
        }
        if (c->state == CONT_RUNNING && c->child_pid > 0) {
            kill(-c->child_pid, SIGKILL);
            while (c->state == CONT_RUNNING)
                pthread_cond_wait(&c->cv, &c->lock);
        }
        int ec = c->exit_code;
        pthread_mutex_unlock(&c->lock);

        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":true,\"exit_code\":%d}\n", ec);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "container_kill") == 0) {
        long sig = SIGKILL;
        (void) kbox_json_get_int(req, "signal", &sig);
        pthread_mutex_lock(&c->lock);
        if (c->state == CONT_RUNNING && c->child_pid > 0)
            kill(-c->child_pid, (int) sig);
        pthread_mutex_unlock(&c->lock);
        send_rpc_line(client_fd, "{\"ok\":true}\n");
        return;
    }

    if (strcmp(op, "container_wait") == 0) {
        pthread_mutex_lock(&c->lock);
        while (c->state == CONT_STARTING || c->state == CONT_RUNNING)
            pthread_cond_wait(&c->cv, &c->lock);
        int ec = c->exit_code;
        pthread_mutex_unlock(&c->lock);

        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":true,\"exit_code\":%d}\n", ec);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "container_inspect") == 0) {
        pthread_mutex_lock(&c->lock);
        const char *st_str = "created";
        if (c->state == CONT_RUNNING || c->state == CONT_STARTING)
            st_str = "running";
        else if (c->state == CONT_EXITED)
            st_str = "exited";
        char resp[512];
        snprintf(resp, sizeof(resp),
                 "{\"ok\":true,\"id\":\"%s\",\"name\":\"%s\","
                 "\"state\":\"%s\",\"pid\":%d,\"exit_code\":%d,"
                 "\"ip\":\"%s\",\"log_path\":\"%s\","
                 "\"started_at\":%ld,\"finished_at\":%ld}\n",
                 c->id, c->name, st_str, (int) c->child_pid, c->exit_code,
                 c->ip, c->log_path, (long) c->started_at,
                 (long) c->finished_at);
        pthread_mutex_unlock(&c->lock);
        send_rpc_line(client_fd, resp);
        return;
    }

    if (strcmp(op, "container_rm") == 0) {
        int force = kbox_json_get_bool(req, "force", 0);
        pthread_mutex_lock(&c->lock);
        if ((c->state == CONT_RUNNING || c->state == CONT_STARTING) && !force) {
            pthread_mutex_unlock(&c->lock);
            send_rpc_err(client_fd, "container is running");
            return;
        }
        if (c->state == CONT_RUNNING && c->child_pid > 0)
            kill(-c->child_pid, SIGKILL);
        int started = c->worker_started;
        pthread_t wt = c->worker_thread;
        c->worker_started = 0;
        pthread_mutex_unlock(&c->lock);

        /* Terminate any active exec sessions targeting this container. */
        pthread_mutex_lock(&g_exec_table_lock);
        for (int i = 0; i < MAX_EXECS; i++) {
            struct daemon_exec *e = &g_execs[i];
            if (e->state == EXEC_RUNNING && e->cont == c && e->child_pid > 0)
                kill(-e->child_pid, SIGKILL);
        }
        pthread_mutex_unlock(&g_exec_table_lock);

        if (started)
            pthread_join(wt, NULL);

        char cdir[128];
        snprintf(cdir, sizeof(cdir), "/containers/%s", c->id);
        rm_lkl_tree_rec(g_sysnrs, cdir);
        if (g_config.ephemeral_hostfs) {
            char host_dir[PATH_MAX];
            snprintf(host_dir, sizeof(host_dir), "%s/%s",
                     g_config.ephemeral_root, c->id);
            host_rm_rf(host_dir);
        }

        kbox_daemon_port_remove_ip(c->ip);
        kbox_daemon_dns_unregister_ip(c->ip);
        unlink(c->log_path);

        pthread_mutex_lock(&g_cont_table_lock);
        free_container_fields(c);
        pthread_mutex_destroy(&c->lock);
        pthread_cond_destroy(&c->cv);
        memset(c, 0, sizeof(*c));
        c->state = CONT_FREE;
        pthread_mutex_unlock(&g_cont_table_lock);

        send_rpc_line(client_fd, "{\"ok\":true}\n");
        return;
    }

    send_rpc_err(client_fd, "unknown op");
}

static void *rpc_client_thread(void *arg)
{
    int fd = (int) (intptr_t) arg;
    char *buf = malloc(RPC_MAX_LINE);
    if (!buf) {
        close(fd);
        return NULL;
    }

    size_t len = 0;
    for (;;) {
        ssize_t n = read(fd, buf + len, RPC_MAX_LINE - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        len += (size_t) n;
        buf[len] = '\0';

        char *line_start = buf;
        char *nl;
        while ((nl = strchr(line_start, '\n')) != NULL) {
            *nl = '\0';
            if (line_start[0] != '\0')
                handle_rpc_line(fd, line_start);
            line_start = nl + 1;
        }
        size_t rem = strlen(line_start);
        if (rem > 0 && line_start != buf)
            memmove(buf, line_start, rem);
        len = rem;
        if (len >= RPC_MAX_LINE - 1)
            break;
    }

    free(buf);
    close(fd);
    return NULL;
}

static void on_term_signal(int sig)
{
    (void) sig;
    __atomic_store_n(&g_daemon_stop, 1, __ATOMIC_RELEASE);
}

int kbox_daemon_stopping(void)
{
    return __atomic_load_n(&g_daemon_stop, __ATOMIC_ACQUIRE) ? 1 : 0;
}

int kbox_daemon_run(const char *sock_path, const char *cmdline, int verbose)
{
    const char *eff_sock =
        (sock_path && *sock_path) ? sock_path : KBOX_DAEMON_DEFAULT_SOCK;
    const char *eff_cmd =
        (cmdline && *cmdline) ? cmdline : "mem=4096M loglevel=4";

    g_verbose = verbose;
    g_sysnrs = detect_sysnrs();
    g_host_nrs = select_host_nrs_for_daemon();
    if (!g_sysnrs || !g_host_nrs) {
        fprintf(stderr, "kboxd: unsupported host architecture\n");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_term_signal);
    signal(SIGTERM, on_term_signal);

    sigset_t chld_mask;
    sigemptyset(&chld_mask);
    sigaddset(&chld_mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &chld_mask, NULL);

    if (kbox_net_add_device() < 0) {
        fprintf(stderr, "kboxd: kbox_net_add_device failed\n");
        return -1;
    }
    if (kbox_boot_kernel(eff_cmd) < 0) {
        kbox_net_cleanup();
        return -1;
    }

    /* Make the guest wall clock match the host before any container stamps a
     * file with "now". */
    kbox_sync_guest_realtime();

    /* Setup base LKL root filesystem hierarchy for daemon control plane. */
    lkl_mkdir_p(g_sysnrs, "/proc", 0755);
    /* Every guest file and socket is an LKL descriptor, and LKL starts with a
     * soft limit of 1024 for the whole daemon. A broker or JVM exhausts that
     * within minutes (EMFILE from open, from socket, from veth creation). Raise
     * it for this task and for init, which new tasks inherit from. */
    {
        struct {
            unsigned long long cur, max;
        } nofile = {1048576ULL, 1048576ULL};
        kbox_lkl_prlimit64(g_sysnrs, 0, 7 /* RLIMIT_NOFILE */, &nofile);
        kbox_lkl_prlimit64(g_sysnrs, 1, 7, &nofile);
    }
    kbox_lkl_mount(g_sysnrs, "proc", "/proc", "proc", 0, NULL);
    lkl_mkdir_p(g_sysnrs, "/sys", 0755);
    kbox_lkl_mount(g_sysnrs, "sysfs", "/sys", "sysfs", 0, NULL);
    lkl_mkdir_p(g_sysnrs, "/dev", 0755);
    kbox_lkl_mount(g_sysnrs, "devtmpfs", "/dev", "devtmpfs", 0, NULL);
    lkl_mkdir_p(g_sysnrs, "/etc", 0755);
    char tmpfs_opts[4096];
    memset(tmpfs_opts, 0, sizeof(tmpfs_opts));
    snprintf(tmpfs_opts, sizeof(tmpfs_opts), "mode=0777");
    lkl_mkdir_p(g_sysnrs, "/images", 0755);
    kbox_lkl_mount(g_sysnrs, "tmpfs", "/images", "tmpfs", 0, tmpfs_opts);
    lkl_mkdir_p(g_sysnrs, "/containers", 0755);
    kbox_lkl_mount(g_sysnrs, "tmpfs", "/containers", "tmpfs", 0, tmpfs_opts);

    if (kbox_net_configure(g_sysnrs) < 0) {
        fprintf(stderr, "kboxd: kbox_net_configure failed\n");
        kbox_halt_kernel();
        kbox_net_cleanup();
        return -1;
    }

    struct kbox_daemon_config cfg;
    kbox_daemon_load_config(g_config_path, &cfg);
    /* Nameservers come from the pod, never from a constant: the cluster
     * resolver address differs per cluster and is what resolves cluster names
     * (the Nexus, a sibling service) as well as the public internet. */
    if (cfg.dns_upstream_count == 0)
        kbox_daemon_read_resolvers(&cfg);
    g_config = cfg;

    /* Container logs live here; created after the config is read because the
     * directory is configurable. */
    if (mkdir(g_config.log_dir[0] ? g_config.log_dir : DAEMON_LOG_DIR, 0777) <
            0 &&
        errno != EEXIST) {
        fprintf(stderr, "kboxd: mkdir %s: %s\n",
                g_config.log_dir[0] ? g_config.log_dir : DAEMON_LOG_DIR,
                strerror(errno));
        return -1;
    }

    if (kbox_daemon_net_init(g_sysnrs, &cfg, verbose) < 0) {
        kbox_halt_kernel();
        kbox_net_cleanup();
        return -1;
    }

    /* Mount declared NFS exports before accepting any container: a service
     * that asks for a volume from a handle that never came up must not start
     * with a half-working filesystem. The wait is unbounded by design (the
     * NFS server is usually a sibling workload that starts after us) and is
     * interruptible by SIGTERM/SIGINT.
     */
    if (kbox_daemon_nfs_mount_all(g_sysnrs, &g_config, verbose) < 0) {
        fprintf(stderr, "kboxd: nfs mounts not established, shutting down\n");
        kbox_daemon_net_cleanup();
        kbox_halt_kernel();
        kbox_net_cleanup();
        return -1;
    }

    if (pthread_create(&g_reaper_thread, NULL, sigchld_reaper_thread, NULL) !=
        0) {
        fprintf(stderr, "kboxd: reaper thread failed\n");
        kbox_daemon_net_cleanup();
        kbox_halt_kernel();
        kbox_net_cleanup();
        return -1;
    }
    g_reaper_started = 1;

    unlink(eff_sock);
    g_listen_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_listen_sock < 0) {
        fprintf(stderr, "kboxd: socket(%s): %s\n", eff_sock, strerror(errno));
        goto out_cleanup;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(eff_sock) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "kboxd: socket path too long\n");
        goto out_cleanup;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", eff_sock);

    if (bind(g_listen_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(g_listen_sock, 64) < 0) {
        fprintf(stderr, "kboxd: listen(%s): %s\n", eff_sock, strerror(errno));
        goto out_cleanup;
    }

    fprintf(stderr, "kboxd: listening on %s (single LKL engine ready)\n",
            eff_sock);

    while (!__atomic_load_n(&g_daemon_stop, __ATOMIC_ACQUIRE)) {
        struct pollfd pfd = {
            .fd = g_listen_sock,
            .events = POLLIN,
            .revents = 0,
        };
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0 || !(pfd.revents & POLLIN))
            continue;

        int cfd = accept4(g_listen_sock, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0)
            continue;

        pthread_t thr;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&thr, &attr, rpc_client_thread,
                           (void *) (intptr_t) cfd) != 0)
            close(cfd);
        pthread_attr_destroy(&attr);
    }

out_cleanup:
    if (g_listen_sock >= 0) {
        close(g_listen_sock);
        g_listen_sock = -1;
    }
    unlink(eff_sock);

    /* Stop any active exec sessions and containers cleanly. */
    for (int i = 0; i < MAX_EXECS; i++) {
        struct daemon_exec *e = &g_execs[i];
        if (e->state == EXEC_RUNNING && e->child_pid > 0)
            kill(-e->child_pid, SIGKILL);
        if (e->thread_started) {
            pthread_join(e->thread, NULL);
            e->thread_started = 0;
        }
    }
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        struct daemon_container *c = &g_containers[i];
        if (c->state == CONT_RUNNING && c->child_pid > 0)
            kill(-c->child_pid, SIGKILL);
        if (c->worker_started) {
            pthread_join(c->worker_thread, NULL);
            c->worker_started = 0;
        }
    }

    if (g_reaper_started) {
        pthread_join(g_reaper_thread, NULL);
        g_reaper_started = 0;
    }

    kbox_daemon_net_cleanup();
    kbox_halt_kernel();
    kbox_net_cleanup();
    return 0;
}

/* Raise the daemon's own descriptor limit to the hard limit.
 *
 * Guest files live on the host through hostfs, and hostfs keeps one host
 * descriptor per inode (HOSTFS_I(inode)->fd) until the inode is evicted. A
 * package manager installing a distribution creates tens of thousands of
 * files, so the number of host descriptors the daemon holds tracks the number
 * of live inodes, not the number of containers. With the runtime's default
 * soft limit of 20480 the daemon hit it during `apk add mariadb-test`:
 *
 *   t=1  daemon_fds=62
 *   ...
 *   t=9  daemon_fds=19819
 *   t=11 daemon_fds=20480      <- soft RLIMIT_NOFILE
 *
 * and every later file_create() returned EMFILE, which the guest reported as
 * "No file descriptors available" from whichever call needed a file. The
 * daemon already grants 65536 to supervised children and 1 MiB to the LKL
 * tasks; it must grant itself the same room.
 */
static void raise_own_nofile_limit(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
        return;
    if (rl.rlim_cur >= rl.rlim_max)
        return;
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
        fprintf(stderr, "kboxd: cannot raise RLIMIT_NOFILE: %s\n",
                strerror(errno));
}

int kbox_daemon_main(int argc, char **argv)
{
    raise_own_nofile_limit();

    const char *sock_path = KBOX_DAEMON_DEFAULT_SOCK;
    const char *cmdline = NULL;
    const char *config_path = NULL;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--sock") == 0 || strcmp(argv[i], "-s") == 0) &&
            i + 1 < argc) {
            sock_path = argv[++i];
        } else if ((strcmp(argv[i], "--config") == 0 ||
                    strcmp(argv[i], "-c") == 0) &&
                   i + 1 < argc) {
            config_path = argv[++i];
        } else if ((strcmp(argv[i], "--cmdline") == 0 ||
                    strcmp(argv[i], "-k") == 0) &&
                   i + 1 < argc) {
            cmdline = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0 ||
                   strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            fprintf(stderr,
                    "Usage: kbox daemon [--sock PATH] [--config PATH] "
                    "[--cmdline STR] [-v]\n");
            return 0;
        } else {
            fprintf(stderr, "kbox daemon: unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    kbox_daemon_set_config_path(config_path);
    return kbox_daemon_run(sock_path, cmdline, verbose) < 0 ? 1 : 0;
}
