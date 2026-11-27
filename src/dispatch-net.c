/* SPDX-License-Identifier: MIT */

/* Network syscall handlers for the seccomp dispatch engine. */

/* The single address the LKL guest owns on its slirp interface. Kept in step
 * with GUEST_IP_STR in net-slirp.c: a connect aimed at the container's own pod
 * address is retargeted here, because that is where its listeners really live.
 */
/* unused, kept out of the way */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <stdlib.h>
#include "dispatch-internal.h"
#include "kbox/path.h"
#include "net.h"

#define KBOX_UNIX_TYPE_MAX 8192
/* Per tracee fd: socket type (low 7 bits) and a nonblocking flag (0x80) of
 * AF_UNIX sockets created through forward_socket; 0 = not one of ours. */
static uint8_t g_unix_type[KBOX_UNIX_TYPE_MAX];

/* Socket timeouts set on a path-named AF_UNIX socket before bind/connect.
 * handle_unix_bind_connect() swaps in a fresh host socket via ADDFD_AT, which
 * would otherwise lose SO_RCVTIMEO/SO_SNDTIMEO configured beforehand (breaking
 * MariaDB's main.ssl_timeout on localhost).
 */
struct kbox_unix_sock_opts {
    int has_rcvtimeo;
    struct timeval rcvtimeo;
    int has_sndtimeo;
    struct timeval sndtimeo;
};

static struct kbox_unix_sock_opts g_unix_opts[KBOX_UNIX_TYPE_MAX];

/* Guest paths of AF_UNIX sockets kbox bound or connected on the host.
 *
 * The host socket lives at a hash of the guest path (/dev/shm/kbox-unix/...),
 * and the tracee's descriptor is that host socket. getsockname() therefore
 * returned the hashed path, which CPython's socketserver stores as the
 * server address: the next connect() then asked for the hashed path, kbox
 * hashed it again, and the connection failed with ENOENT. Remember the path
 * the guest used and answer getsockname/getpeername with it.
 */
static char *g_unix_bind_path[KBOX_UNIX_TYPE_MAX];
static char *g_unix_peer_path[KBOX_UNIX_TYPE_MAX];

static void set_unix_path(char **slot, long fd, const char *path)
{
    if (fd < 0 || fd >= KBOX_UNIX_TYPE_MAX)
        return;
    free(*slot);
    *slot = strdup(path);
}

void kbox_net_forget_fd(long fd)
{
    if (fd < 0 || fd >= KBOX_UNIX_TYPE_MAX)
        return;
    g_unix_type[fd] = 0;
    memset(&g_unix_opts[fd], 0, sizeof(g_unix_opts[fd]));
    free(g_unix_bind_path[fd]);
    g_unix_bind_path[fd] = NULL;
    free(g_unix_peer_path[fd]);
    g_unix_peer_path[fd] = NULL;
}

void kbox_net_note_unix_nonblock(long fd, int nonblock)
{
    if (fd < 0 || fd >= KBOX_UNIX_TYPE_MAX || g_unix_type[fd] == 0)
        return;
    if (nonblock)
        g_unix_type[fd] |= 0x80;
    else
        g_unix_type[fd] &= 0x7f;
}

/* Answer getsockname/getpeername from the remembered guest path. */
static struct kbox_dispatch unix_path_query(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long fd,
    const char *guest_path,
    int is_bind)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);
    struct sockaddr_un addr;
    size_t path_len = strlen(guest_path);

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (path_len >= sizeof(addr.sun_path))
        path_len = sizeof(addr.sun_path) - 1;

    unsigned int addrlen;
    if (guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen)) < 0)
        return kbox_dispatch_errno(EFAULT);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, guest_path, path_len);
    unsigned int out_len =
        (unsigned int) (offsetof(struct sockaddr_un, sun_path) + path_len + 1);

    if (addrlen < out_len)
        return kbox_dispatch_errno(EINVAL);

    int wrc = guest_mem_write(ctx, pid, addr_ptr, &addr, out_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    if (ctx->verbose)
        fprintf(stderr, "kbox: unix: %s -> %s\n",
                is_bind ? "getsockname" : "getpeername", guest_path);
    return kbox_dispatch_value(0);
}

/* Shadow socket design:
 *   1. Create an LKL network socket inside LKL's network stack
 *   2. Create a host socketpair (sp[0]=supervisor, sp[1]=tracee)
 *   3. Inject sp[1] into the tracee via ADDFD
 *   4. Register sp[0]+lkl_fd with the SLIRP event loop
 *   5. The event loop pumps data between sp[0] and the LKL socket
 *
 * The tracee sees a real host FD, so poll/epoll/read/write all work natively
 * via the host kernel. Only control-plane ops (connect, getsockopt, etc.) need
 * explicit forwarding.
 *
 * INET sockets with SLIRP active get a shadow socket bridge so data flows
 * through the host kernel socketpair (bypassing BKL contention in blocking LKL
 * recv/send calls). Non-INET sockets and INET sockets without SLIRP use the
 * standard virtual FD path.
 *
 * Limitation: listen/accept on shadow sockets fail because AF_UNIX socketpair
 * doesn't support inbound connections. Server sockets must be used without
 * --net or via a future deferred-bridge approach.
 */
static int attach_shadow_socket(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long lkl_fd,
                                int base_type,
                                int sock_flags,
                                int64_t *out_fd)
{
    int sp[2];
    if (socketpair(AF_UNIX, base_type | SOCK_CLOEXEC, 0, sp) < 0)
        return -errno;

    fcntl(sp[0], F_SETFL, O_NONBLOCK);
    if (sock_flags & SOCK_NONBLOCK)
        fcntl(sp[1], F_SETFL, O_NONBLOCK);

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
    if (vfd < 0) {
        close(sp[0]);
        close(sp[1]);
        return -EMFILE;
    }

    if (kbox_net_register_socket((int) lkl_fd, sp[0], base_type) < 0) {
        close(sp[0]);
        close(sp[1]);
        if (sock_flags & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        *out_fd = (int64_t) vfd;
        return 0;
    }

    uint32_t addfd_flags = (sock_flags & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
    int host_fd = request_addfd(ctx, req, sp[1], addfd_flags);
    if (host_fd < 0) {
        (void) kbox_net_deregister_socket((int) lkl_fd);
        close(sp[1]);
        kbox_fd_table_remove(ctx->fd_table, vfd);
        return host_fd;
    }
    /* A prior bridged socket that held this low host_fd may have been closed
     * natively in the kernel (item 33). Retire it before installing the new
     * reverse mapping so lookup never returns the dead socket (item 37). */
    if (host_fd >= 0)
        kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                      host_fd, 1);
    kbox_fd_table_set_host_fd(ctx->fd_table, vfd, host_fd);

    /* The ADDFD-injected host_fd may land on a low FD number that already
     * has a SHADOW_ONLY entry (from pipe tracking or inherited FD scan).
     * Overwrite it so resolve_lkl_socket finds the LKL socket via the
     * direct lookup path instead of returning the stale SHADOW_ONLY.
     */
    if (host_fd != vfd) {
        struct kbox_fd_entry *low = fd_table_entry(ctx->fd_table, host_fd);
        if (low && low->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
            kbox_fd_table_remove(ctx->fd_table, host_fd);
    }

    struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, vfd);
    if (e) {
        e->shadow_sp = sp[1];
        e->sock_type = base_type & 0xf;
        if (host_fd >= 0)
            e->guest_id =
                kbox_guest_fd_identity(kbox_syscall_request_pid(req), host_fd);
        if (sock_flags & SOCK_CLOEXEC)
            e->cloexec = 1;
    }

    *out_fd = (int64_t) host_fd;
    return 0;
}

struct kbox_dispatch forward_socket(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long type_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long protocol = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int base_type = (int) type_raw & 0xFF;

    /* AF_UNIX: LKL has no UNIX sockets; the socket is a host passthrough fd.
     * network_mode: host does the same for INET and netlink: the container
     * shares the pod network, so localhost reaches the published ports and its
     * own listeners are pod listeners. */
    if (domain == AF_UNIX ||
        (ctx->host_net &&
         (domain == AF_INET || domain == AF_INET6 || domain == AF_NETLINK))) {
        int hfd =
            socket((int) domain, (int) type_raw | SOCK_CLOEXEC, (int) protocol);
        if (hfd < 0)
            return kbox_dispatch_errno(errno);
        uint32_t af = (type_raw & SOCK_CLOEXEC) ? O_CLOEXEC : 0;
        int tfd = request_addfd(ctx, req, hfd, af);
        close(hfd);
        if (tfd < 0)
            return kbox_dispatch_errno(-tfd);
        if (tfd >= 0)
            kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                          tfd, 1);
        track_host_passthrough_fd(ctx->fd_table, tfd);
        if (domain == AF_UNIX && tfd >= 0 && tfd < KBOX_UNIX_TYPE_MAX) {
            g_unix_type[tfd] =
                (uint8_t) ((base_type & 0x7f) |
                           ((type_raw & SOCK_NONBLOCK) ? 0x80 : 0));
            memset(&g_unix_opts[tfd], 0, sizeof(g_unix_opts[tfd]));
        }
        if (type_raw & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, tfd, 1);
        return kbox_dispatch_value(tfd);
    }

    long ret = kbox_lkl_socket(ctx->sysnrs, domain, type_raw, protocol);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long lkl_fd = ret;

    /* Virtual FD path when shadow bridge is not applicable:
     * - SLIRP/net loop not active
     * - Non-INET domain (AF_UNIX, AF_NETLINK, etc.)
     * - Non-stream/datagram type (SOCK_RAW, etc.): socketpair(AF_UNIX) only
     *   supports SOCK_STREAM and SOCK_DGRAM
     */
    if (!kbox_net_is_active() ||
        (domain != 2 /* AF_INET */ && domain != 10 /* AF_INET6 */) ||
        (base_type != SOCK_STREAM && base_type != SOCK_DGRAM)) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, lkl_fd);
            return kbox_dispatch_errno(EMFILE);
        }
        if (type_raw & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        return kbox_dispatch_value((int64_t) vfd);
    }

    int64_t out_fd = -1;
    int rc = attach_shadow_socket(req, ctx, lkl_fd, base_type, (int) type_raw,
                                  &out_fd);
    if (rc < 0) {
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(-rc);
    }
    return kbox_dispatch_value(out_fd);
}

/* AF_UNIX sockets.
 *
 * LKL is built without UNIX sockets, so a path-named AF_UNIX socket lives in
 * the host kernel as a passthrough fd. The guest's path is inside its LKL
 * rootfs, which the host cannot see, so bind and connect map it to a private
 * host path (one directory per container, one hashed name per guest path).
 * bind also leaves an empty placeholder at the guest path in LKL so stat,
 * chmod and unlink of the socket file (postgres does all three) behave.
 * Abstract names (leading NUL) need no mapping and go to the host as they are.
 */
static int unix_host_path(const struct kbox_supervisor_ctx *ctx,
                          const char *guest_path,
                          char *out,
                          size_t out_size)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a */
    char dir[96];

    for (const char *p = guest_path; *p; p++) {
        h ^= (unsigned char) *p;
        h *= 1099511628211ULL;
    }
    mkdir("/dev/shm/kbox-unix", 0777);
    /* A container's sockets are shared with its exec sessions (pg_isready
     * after docker exec), which are separate supervisors with their own
     * child pids. The container's IP is the one thing all of them agree on. */
    if (ctx->own_ip[0])
        snprintf(dir, sizeof(dir), "/dev/shm/kbox-unix/ip-%s", ctx->own_ip);
    else
        snprintf(dir, sizeof(dir), "/dev/shm/kbox-unix/%d",
                 (int) ctx->child_pid);
    mkdir(dir, 0777);
    if (snprintf(out, out_size, "%s/%016llx", dir, (unsigned long long) h) >=
        (int) out_size)
        return -ENAMETOOLONG;
    return 0;
}

/* Resolve an AF_UNIX path the way the guest would: relative names are relative
 * to the guest's current directory, not to the daemon's. A relative name that
 * reached the host unchanged was bound in the supervisor's own cwd, shared by
 * every container and never cleaned up, so the second bind of the same name
 * failed with EADDRINUSE. */
static int unix_resolve_guest_path(struct kbox_supervisor_ctx *ctx,
                                   const char *path,
                                   char *out,
                                   size_t out_size)
{
    char cwd[KBOX_MAX_PATH];
    int n;

    if (path[0] == '/') {
        n = snprintf(out, out_size, "%s", path);
        return (n < 0 || (size_t) n >= out_size) ? -ENAMETOOLONG : 0;
    }
    if (ctx->host_cwd[0] != '\0')
        n = snprintf(cwd, sizeof(cwd), "%s", ctx->host_cwd);
    else if (kbox_lkl_getcwd(ctx->sysnrs, cwd, (long) sizeof(cwd)) >= 0)
        n = (int) strlen(cwd);
    else
        return -ENOENT;
    if (n < 0 || (size_t) n >= sizeof(cwd))
        return -ENAMETOOLONG;
    if (kbox_normalize_join(cwd, path, out, out_size) < 0)
        return -ENAMETOOLONG;
    return 0;
}

/* Handle bind/connect of a passthrough socket to an AF_UNIX path. Returns 1
 * and fills *out when handled; 0 means "not an AF_UNIX path address". */
static int unix_path_call(const struct kbox_syscall_request *req,
                          struct kbox_supervisor_ctx *ctx,
                          int is_bind,
                          struct kbox_dispatch *out)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint8_t buf[sizeof(struct sockaddr_un) + 8];
    struct sockaddr_un host;
    char gpath[sizeof(host.sun_path) + 1];
    char hpath[sizeof(host.sun_path)];
    size_t plen;

    if (addr_ptr == 0 || len_raw < 3 || len_raw > (int64_t) sizeof(buf))
        return 0;
    if (guest_mem_read(ctx, pid, addr_ptr, buf, (size_t) len_raw) < 0)
        return 0;
    if (buf[0] != AF_UNIX || buf[1] != 0 || buf[2] == '\0')
        return 0; /* not AF_UNIX, or abstract */

    plen = (size_t) len_raw - 2;
    if (plen > sizeof(host.sun_path))
        plen = sizeof(host.sun_path);
    memcpy(gpath, buf + 2, plen);
    gpath[plen] = '\0'; /* sun_path need not be NUL-terminated */

    char gabs[KBOX_MAX_PATH];
    if (unix_resolve_guest_path(ctx, gpath, gabs, sizeof(gabs)) < 0)
        return 0; /* unresolvable: leave it to the host */
    memcpy(gpath, gabs, strlen(gabs) + 1);

    int rc = unix_host_path(ctx, gpath, hpath, sizeof(hpath));
    if (rc < 0) {
        *out = kbox_dispatch_errno(-rc);
        return 1;
    }
    memset(&host, 0, sizeof(host));
    host.sun_family = AF_UNIX;
    memcpy(host.sun_path, hpath, strlen(hpath));

    /* The supervisor cannot reach the tracee's socket (pidfd_getfd is blocked
     * and /proc/<pid>/fd refuses sockets), so it makes a fresh socket of the
     * same type, binds or connects that one on the host path, and swaps it in
     * at the same fd number with ADDFD_AT. */
    int utype = SOCK_STREAM;
    int unb = 0;
    if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX && g_unix_type[fd]) {
        utype = g_unix_type[fd] & 0x7f;
        unb = g_unix_type[fd] & 0x80;
    }
    int nsock =
        socket(AF_UNIX, utype | SOCK_CLOEXEC | (unb ? SOCK_NONBLOCK : 0), 0);
    if (nsock < 0) {
        *out = kbox_dispatch_errno(errno);
        return 1;
    }
    if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX) {
        if (g_unix_opts[fd].has_rcvtimeo)
            (void) setsockopt(nsock, SOL_SOCKET, SO_RCVTIMEO,
                              &g_unix_opts[fd].rcvtimeo,
                              sizeof(g_unix_opts[fd].rcvtimeo));
        if (g_unix_opts[fd].has_sndtimeo)
            (void) setsockopt(nsock, SOL_SOCKET, SO_SNDTIMEO,
                              &g_unix_opts[fd].sndtimeo,
                              sizeof(g_unix_opts[fd].sndtimeo));
    }

    if (is_bind) {
        struct kbox_lkl_stat kst;
        memset(&kst, 0, sizeof(kst));
        if (kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, gpath, &kst, 0) >=
            0) {
            close(nsock);
            *out = kbox_dispatch_errno(EADDRINUSE); /* guest file exists */
            return 1;
        }
        unlink(hpath); /* stale socket of an earlier run */
        if (bind(nsock, (struct sockaddr *) &host, sizeof(host)) < 0) {
            int e = errno;
            close(nsock);
            *out = kbox_dispatch_errno(e);
            return 1;
        }
    } else if (connect(nsock, (struct sockaddr *) &host, sizeof(host)) < 0) {
        int e = errno;
        close(nsock);
        if (ctx->verbose)
            fprintf(stderr, "kbox: unix: connect %s -> %s: %s\n", gpath, hpath,
                    strerror(e));
        *out = kbox_dispatch_errno(e);
        return 1;
    }

    uint32_t af = kbox_fd_table_get_cloexec(ctx->fd_table, fd) ? O_CLOEXEC : 0;
    int swapped = request_addfd_at(ctx, req, nsock, (int) fd, af);
    close(nsock);
    if (swapped < 0) {
        *out = kbox_dispatch_errno(-swapped);
        return 1;
    }
    if (is_bind) {
        /* Give the guest path a socket inode, as a real bind(2) leaves behind.
         * A regular file placeholder made stat() report S_IFREG, so
         * Path.is_socket() and socket-aware tooling saw a plain file where the
         * guest had just bound a socket. mknod(2) accepts S_IFSOCK on Linux,
         * and open(2) on the result fails with ENXIO exactly as it does for a
         * socket file.
         */
        (void) kbox_lkl_mknodat(ctx->sysnrs, AT_FDCWD_LINUX, gpath,
                                S_IFSOCK | 0777, 0);
        /* The placeholder above lives in the LKL rootfs. When the guest path is
         * on a bind mount the host answers stat() for that path, and the host
         * still had no file there: lstat() reported ENOENT for a socket the
         * guest had just bound (test_stat.test_socket). An unprivileged process
         * may create a socket inode with mknod, so leave the same placeholder
         * on the host path. EEXIST only means a stale node is already there. */
        if (kbox_is_lkl_virtual_path(gpath) == false &&
            strncmp(gpath, "/proc", 5) != 0 && strncmp(gpath, "/dev", 4) != 0 &&
            strncmp(gpath, "/sys", 4) != 0)
            (void) mknod(gpath, S_IFSOCK | 0777, 0);
        set_unix_path(&g_unix_bind_path[fd], fd, gpath);
    } else {
        set_unix_path(&g_unix_peer_path[fd], fd, gpath);
    }
    if (ctx->verbose)
        fprintf(stderr, "kbox: unix: %s %s -> %s\n",
                is_bind ? "bind" : "connect", gpath, hpath);
    *out = kbox_dispatch_value(0);
    return 1;
}

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd);
/* Defined beside forward_getpeername: the peer of a bridged connection. */
static void record_sock_peer(struct kbox_fd_entry *entry,
                             const uint8_t *addr,
                             size_t len);

struct kbox_dispatch forward_bind(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        struct kbox_dispatch ud;
        if (unix_path_call(req, ctx, 1, &ud))
            return ud;
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    if (ret == -EADDRINUSE && kbox_net_is_active()) {
        /* A previous listener may have closed its low descriptor natively in
         * the kernel without reusing the fd number yet. Sweep stale bridged
         * sockets so the dead LKL socket releases the port, then retry once. */
        kbox_sweep_stale_bridged_sockets(ctx, pid);
        ret = kbox_lkl_bind(ctx->sysnrs, lkl_fd, buf, (long) len);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* Is this entry only the inherited-FD placeholder? */
static int heuristic_shadow_entry(const struct kbox_fd_entry *e)
{
    return e == NULL || e->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY;
}

/* Resolve LKL FD and optional FD-table entry from a tracee FD.
 *
 * A bridged socket is handed to the guest as a host FD injected with ADDFD, so
 * the LKL twin lives in the virtual entry that records that host FD -- not
 * necessarily at the same number. The same number can hold a stale entry: the
 * one-time inherited-FD scan registers every low FD as SHADOW_ONLY, and sockets
 * later injected land elsewhere. Looking the number up first therefore answered
 * "host passthrough" for a socket that is really bridged, and every control
 * call on it (sendmsg with a destination, recvmsg, connect) was left to the
 * host socketpair, which rejected the guest's AF_INET address with EINVAL. The
 * host mapping wins when it carries a real LKL socket.
 */
static long resolve_lkl_socket_entry(struct kbox_supervisor_ctx *ctx,
                                     long fd,
                                     struct kbox_fd_entry **entry_out)
{
    if (entry_out)
        *entry_out = NULL;

    struct kbox_fd_entry *direct = fd_table_entry(ctx->fd_table, fd);
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);

    /* Only when the number itself cannot answer: an entry that is absent or the
     * placeholder the inherited-FD scan installed. A live entry at the number
     * may belong to a different object now (FD numbers are reused, and entries
     * of bridged sockets outlive the child that closed them), and treating a
     * fresh AF_UNIX or TCP socket as somebody else's LKL socket made it return
     * another socket's source address and ancillary data. */
    if (vfd >= 0 && vfd != fd && heuristic_shadow_entry(direct)) {
        struct kbox_fd_entry *he = fd_table_entry(ctx->fd_table, vfd);

        if (he && he->lkl_fd >= 0 && he->shadow_sp >= 0) {
            if (entry_out)
                *entry_out = he;
            return he->lkl_fd;
        }
    }

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0) {
        if (entry_out)
            *entry_out = fd_table_entry(ctx->fd_table, fd);
        return lkl_fd;
    }
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
        return lkl_fd;

    if (vfd >= 0) {
        struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, vfd);
        if (entry_out)
            *entry_out = e;
        return e ? e->lkl_fd : -1;
    }

    return -1;
}

static long resolve_lkl_socket(struct kbox_supervisor_ctx *ctx, long fd)
{
    return resolve_lkl_socket_entry(ctx, fd, NULL);
}

struct kbox_dispatch forward_listen(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long backlog = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long ret = kbox_lkl_listen(ctx->sysnrs, lkl_fd, backlog);
    if (ret == 0 && entry)
        entry->sock_connected = 0;
    if (ret == 0 && entry && entry->shadow_sp >= 0 && kbox_net_is_active())
        kbox_net_set_listening((int) lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch complete_accept_result(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long listen_lkl_fd,
    uint64_t addr_ptr,
    uint64_t len_ptr,
    unsigned int in_len,
    unsigned int out_len,
    const uint8_t *addr,
    long client_lkl,
    int flags)
{
    /* Drain any listening readiness token from the host socketpair and re-arm
     * notification in case additional backlog connections remain.
     */
    if (entry && entry->shadow_sp >= 0 && kbox_net_is_active()) {
        char drain[16];
        while (recv(entry->shadow_sp, drain, sizeof(drain), MSG_DONTWAIT) > 0)
            ;
        kbox_net_clear_listening_notify((int) listen_lkl_fd);
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: accept done lkl=%ld -> cleared notify\n",
                    listen_lkl_fd);
    }

    if (client_lkl < 0) {
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: accept incomplete rc=%ld\n",
                    client_lkl);
        return kbox_dispatch_from_lkl(client_lkl);
    }

    pid_t pid = kbox_syscall_request_pid(req);
    if (addr_ptr != 0) {
        unsigned int write_len = out_len < in_len ? out_len : in_len;
        if (write_len > 0) {
            int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
            if (wrc < 0) {
                lkl_close_and_invalidate(ctx, client_lkl);
                return kbox_dispatch_errno(-wrc);
            }
        }
        int wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
        if (wrc < 0) {
            lkl_close_and_invalidate(ctx, client_lkl);
            return kbox_dispatch_errno(-wrc);
        }
    }

    /* The accepted connection keeps its shadow: the shadow is what tells the
     * tracee its socket became readable, and dropping it makes the very first
     * read block forever. Whatever strands the answer on the second
     * self-connection, it is not the shadow's existence.
     */
    if (!entry || entry->shadow_sp < 0 || !kbox_net_is_active()) {
        long vfd = kbox_fd_table_insert(ctx->fd_table, client_lkl, 0);
        if (vfd < 0) {
            lkl_close_and_invalidate(ctx, client_lkl);
            return kbox_dispatch_errno(EMFILE);
        }
        if (flags & SOCK_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
        return kbox_dispatch_value((int64_t) vfd);
    }

    int64_t out_fd = -1;
    int rc =
        attach_shadow_socket(req, ctx, client_lkl, SOCK_STREAM, flags, &out_fd);
    if (rc < 0) {
        lkl_close_and_invalidate(ctx, client_lkl);
        return kbox_dispatch_errno(-rc);
    }
    {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, out_fd);
        struct kbox_fd_entry *ne =
            vfd >= 0 ? fd_table_entry(ctx->fd_table, vfd) : NULL;
        if (ne)
            ne->sock_connected = 1;
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: net: accepted lkl=%ld vfd=%lld\n", client_lkl,
                (long long) out_fd);
    return kbox_dispatch_value(out_fd);
}

static struct kbox_dispatch defer_pending_accept(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long listen_fd,
    int flags,
    uint64_t addr_ptr,
    uint64_t len_ptr,
    unsigned int in_len)
{
    for (size_t i = 0; i < KBOX_PENDING_ACCEPTS_MAX; i++) {
        if (!ctx->pending_accepts[i].active) {
            if (getenv("KBOX_NET_TRACE"))
                fprintf(stderr,
                        "kbox: net: accept deferred slot=%zu listen=%ld "
                        "count=%zu\n",
                        i, listen_fd, ctx->pending_accept_count + 1);
            ctx->pending_accepts[i].active = 1;
            ctx->pending_accepts[i].req = *req;
            ctx->pending_accepts[i].listen_fd = listen_fd;
            ctx->pending_accepts[i].flags = flags;
            ctx->pending_accepts[i].addr_ptr = addr_ptr;
            ctx->pending_accepts[i].len_ptr = len_ptr;
            ctx->pending_accepts[i].in_len = in_len;
            ctx->pending_accept_count++;
            return (struct kbox_dispatch) {.kind = KBOX_DISPATCH_DEFERRED};
        }
    }
    return kbox_dispatch_errno(EAGAIN);
}

/* A stream shadow socket with no peer cannot read or write.
 *
 * The tracee's stream data path is the AF_UNIX socketpair that shadows the LKL
 * socket, and that pair is always connected; a recv() on it therefore waits
 * for bytes instead of failing. Linux answers ENOTCONN for recv/send on an
 * unconnected or listening TCP socket, and CPython's ssl module depends on it:
 * wrap_socket() probes an unconnected socket with recv(1) and treats anything
 * other than ENOTCONN/EINVAL as fatal. Datagram sockets are usable before
 * connect() and must keep working, so the check is by socket type.
 */
static int stream_socket_unconnected(const struct kbox_fd_entry *e)
{
    return e && e->shadow_sp >= 0 && e->sock_type == SOCK_STREAM &&
           !e->sock_connected;
}


static long try_accept4_nonblock(const struct kbox_sysnrs *sysnrs,
                                 long lkl_fd,
                                 int *was_nonblock_out,
                                 void *addr,
                                 unsigned int *out_len,
                                 int flags,
                                 int verbose)
{
    long lfl = kbox_lkl_fcntl(sysnrs, lkl_fd, F_GETFL, 0);
    int nonblock = (lfl >= 0 && (lfl & O_NONBLOCK)) ? 1 : 0;
    long setfl = 0;

    if (was_nonblock_out)
        *was_nonblock_out = nonblock;

    if (!nonblock && lfl >= 0)
        setfl = kbox_lkl_fcntl(sysnrs, lkl_fd, F_SETFL, lfl | O_NONBLOCK);
    long client_lkl = kbox_lkl_accept4(sysnrs, lkl_fd, addr, out_len, flags);
    if (verbose)
        fprintf(stderr,
                "kbox: accept probe lkl=%ld getfl=%ld (%s) setfl=%ld -> %ld\n",
                lkl_fd, lfl, nonblock ? "nonblock" : "blocking", setfl,
                client_lkl);
    if (!nonblock && lfl >= 0)
        kbox_lkl_fcntl(sysnrs, lkl_fd, F_SETFL, lfl);
    return client_lkl;
}

static long shadow_or_lkl_recvfrom(struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_fd_entry *entry,
                                   long lkl_fd,
                                   void *buf,
                                   size_t cap,
                                   long flags,
                                   void *addr_out,
                                   unsigned int *addrlen_io,
                                   void *ctl_out,
                                   size_t *ctllen_io,
                                   size_t ctl_cap,
                                   int *msg_flags_out);
static struct kbox_dispatch finish_recvfrom(
    const struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t buf_ptr,
    uint64_t src_ptr,
    uint64_t addrlen_ptr,
    unsigned int addrlen,
    const void *buf,
    long ret,
    const void *addr,
    unsigned int out_addrlen);

static void poll_pending_recvmsgs(struct kbox_supervisor_ctx *ctx);

/* Complete a parked blocking recvfrom once its datagram has arrived. */
static void poll_pending_recvs(struct kbox_supervisor_ctx *ctx)
{
    for (size_t i = 0; i < KBOX_PENDING_RECVS_MAX; i++) {
        struct kbox_pending_recv *pr = &ctx->pending_recvs[i];
        struct kbox_syscall_request saved;
        struct kbox_fd_entry *entry = NULL;
        long lkl_fd;
        uint64_t id;
        uint8_t *buf;
        uint8_t addr[128];
        unsigned int out_addrlen;
        long ret;
        struct kbox_dispatch d;

        if (!pr->active)
            continue;

        saved = pr->req;
        id = kbox_syscall_request_cookie(&saved);
        if (ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
            0) {
            pr->active = 0;
            ctx->pending_recv_count--;
            continue;
        }

        kbox_dispatch_prepare_request_ctx(ctx, &saved);

        lkl_fd = resolve_lkl_socket_entry(ctx, pr->fd, &entry);
        if (lkl_fd < 0) {
            pr->active = 0;
            ctx->pending_recv_count--;
            d = kbox_dispatch_errno(EBADF);
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        buf = malloc(pr->len ? pr->len : 1);
        if (!buf) {
            pr->active = 0;
            ctx->pending_recv_count--;
            d = kbox_dispatch_errno(ENOMEM);
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        out_addrlen = pr->addrlen;
        ret = shadow_or_lkl_recvfrom(ctx, entry, lkl_fd, buf, pr->len,
                                     pr->flags | 0x40 /* MSG_DONTWAIT */, addr,
                                     &out_addrlen, NULL, NULL, 0, NULL);
        if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            free(buf);
            if (pr->deadline_ms >= 0) {
                struct timespec now;
                long now_ms;

                clock_gettime(CLOCK_MONOTONIC, &now);
                now_ms = now.tv_sec * 1000L + now.tv_nsec / 1000000L;
                if (now_ms >= pr->deadline_ms) {
                    pr->active = 0;
                    ctx->pending_recv_count--;
                    d = kbox_dispatch_errno(EAGAIN);
                    kbox_notify_respond(ctx->listener_fd, id, &d);
                }
            }
            continue;
        }

        pr->active = 0;
        ctx->pending_recv_count--;

        if (ret < 0) {
            free(buf);
            d = kbox_dispatch_from_lkl(ret);
        } else {
            d = finish_recvfrom(ctx, kbox_syscall_request_pid(&saved),
                                pr->buf_ptr, pr->src_ptr, pr->addrlen_ptr,
                                pr->addrlen, buf, ret, addr, out_addrlen);
            free(buf);
        }
        kbox_notify_respond(ctx->listener_fd, id, &d);
    }
}

static uint64_t connect_poll_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

/* Probe an in-flight non-blocking LKL connect() without consuming SO_ERROR.
 *
 * Returns:
 *   1  handshake established (getpeername succeeded)
 *  -1  handshake failed (LKL ppoll reported POLLERR/POLLHUP/POLLNVAL;
 *      SO_ERROR remains intact for the guest's next getsockopt call)
 *   0  still connecting
 */
static int probe_connecting_lkl_socket(struct kbox_supervisor_ctx *ctx,
                                       long lkl_fd,
                                       short *out_revents)
{
    struct sockaddr_storage peer;
    socklen_t plen = sizeof(peer);
    struct pollfd lpfd = {
        .fd = (int) lkl_fd,
        .events = POLLOUT | POLLERR | POLLHUP,
        .revents = 0,
    };
    struct timespec zero_ts = {0, 0};
    long pr;

    if (out_revents)
        *out_revents = 0;
    if (kbox_net_peek_lkl_error((int) lkl_fd) > 0) {
        if (out_revents)
            *out_revents = POLLOUT | POLLERR | POLLHUP;
        return -1;
    }
    if (kbox_lkl_getpeername(ctx->sysnrs, lkl_fd, &peer, &plen) == 0)
        return 1;
    pr = kbox_lkl_ppoll(ctx->sysnrs, &lpfd, 1, &zero_ts, NULL, 0);
    if (pr > 0 && (lpfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        if (out_revents)
            *out_revents = lpfd.revents;
        return -1;
    }
    return 0;
}

static int write_pollfd_revents(struct kbox_supervisor_ctx *ctx,
                                pid_t pid,
                                uint64_t fds_ptr,
                                short revents)
{
    return guest_mem_write(ctx, pid, fds_ptr + offsetof(struct pollfd, revents),
                           &revents, sizeof(revents));
}

int kbox_try_defer_connect_poll(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                struct kbox_dispatch *out)
{
    int is_ppoll;
    int is_poll;
    uint64_t fds_ptr;
    long nfds;
    pid_t pid;
    struct pollfd pfd;
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd;
    short lkl_rev = 0;
    int st;
    int has_deadline = 0;
    uint64_t deadline_ns = 0;

    if (!req || !ctx || !ctx->host_nrs || !out)
        return 0;
    is_ppoll =
        (ctx->host_nrs->ppoll >= 0 && (long) req->nr == ctx->host_nrs->ppoll);
    is_poll =
        (ctx->host_nrs->poll >= 0 && (long) req->nr == ctx->host_nrs->poll);
    if (!is_ppoll && !is_poll)
        return 0;

    fds_ptr = kbox_syscall_request_arg(req, 0);
    nfds = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (fds_ptr == 0 || nfds != 1)
        return 0;

    pid = kbox_syscall_request_pid(req);
    if (guest_mem_read(ctx, pid, fds_ptr, &pfd, sizeof(pfd)) < 0)
        return 0;
    if (pfd.fd < 0 || !(pfd.events & (POLLOUT | POLLWRNORM | POLLWRBAND)))
        return 0;

    lkl_fd = resolve_lkl_socket_entry(ctx, pfd.fd, &entry);
    if (lkl_fd < 0 || !entry || entry->shadow_sp < 0 ||
        !entry->sock_connected || entry->sock_established)
        return 0;

    st = probe_connecting_lkl_socket(ctx, lkl_fd, &lkl_rev);
    if (st > 0) {
        entry->sock_established = 1;
        return 0;
    }
    if (st < 0) {
        short rev =
            (short) ((pfd.events & (POLLOUT | POLLWRNORM | POLLWRBAND)) |
                     (lkl_rev & (POLLERR | POLLHUP | POLLNVAL)));

        entry->sock_connected = 0;
        entry->sock_established = 0;
        if (write_pollfd_revents(ctx, pid, fds_ptr, rev) < 0) {
            *out = kbox_dispatch_errno(EFAULT);
            return 1;
        }
        *out = kbox_dispatch_value(1);
        return 1;
    }

    if (is_ppoll) {
        uint64_t tmo_ptr = kbox_syscall_request_arg(req, 2);

        if (tmo_ptr != 0) {
            struct timespec ts;

            if (guest_mem_read(ctx, pid, tmo_ptr, &ts, sizeof(ts)) < 0) {
                *out = kbox_dispatch_errno(EFAULT);
                return 1;
            }
            if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L) {
                *out = kbox_dispatch_errno(EINVAL);
                return 1;
            }
            if (ts.tv_sec == 0 && ts.tv_nsec == 0) {
                if (write_pollfd_revents(ctx, pid, fds_ptr, 0) < 0) {
                    *out = kbox_dispatch_errno(EFAULT);
                    return 1;
                }
                *out = kbox_dispatch_value(0);
                return 1;
            }
            uint64_t sec = (uint64_t) (ts.tv_sec > 3600 ? 3600 : ts.tv_sec);
            deadline_ns = connect_poll_now_ns() + sec * 1000000000ULL +
                          (uint64_t) ts.tv_nsec;
            has_deadline = 1;
        }
    } else {
        int tmo_ms = (int) to_c_long_arg(kbox_syscall_request_arg(req, 2));

        if (tmo_ms == 0) {
            if (write_pollfd_revents(ctx, pid, fds_ptr, 0) < 0) {
                *out = kbox_dispatch_errno(EFAULT);
                return 1;
            }
            *out = kbox_dispatch_value(0);
            return 1;
        }
        if (tmo_ms > 0) {
            uint64_t ms = (uint64_t) (tmo_ms > 3600000 ? 3600000 : tmo_ms);

            deadline_ns = connect_poll_now_ns() + ms * 1000000ULL;
            has_deadline = 1;
        }
    }

    for (size_t i = 0; i < KBOX_PENDING_CONNECT_POLLS_MAX; i++) {
        struct kbox_pending_connect_poll *pc = &ctx->pending_connect_polls[i];

        if (pc->active)
            continue;
        pc->active = 1;
        pc->req = *req;
        pc->guest_fd = pfd.fd;
        pc->fds_ptr = fds_ptr;
        pc->events = pfd.events;
        pc->has_deadline = has_deadline;
        pc->deadline_ns = deadline_ns;
        ctx->pending_connect_poll_count++;
        *out = (struct kbox_dispatch) {.kind = KBOX_DISPATCH_DEFERRED};
        return 1;
    }
    return 0;
}

void kbox_poll_pending_connect_polls(struct kbox_supervisor_ctx *ctx)
{
    uint64_t now_ns;

    if (!ctx || ctx->pending_connect_poll_count == 0)
        return;

    now_ns = connect_poll_now_ns();
    for (size_t i = 0; i < KBOX_PENDING_CONNECT_POLLS_MAX; i++) {
        struct kbox_pending_connect_poll *pc = &ctx->pending_connect_polls[i];
        uint64_t id;
        struct kbox_syscall_request saved_req;
        struct kbox_fd_entry *entry = NULL;
        long lkl_fd;
        short lkl_rev = 0;
        int st;
        pid_t pid;

        if (!pc->active)
            continue;
        id = kbox_syscall_request_cookie(&pc->req);
        if (ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
            0) {
            pc->active = 0;
            ctx->pending_connect_poll_count--;
            continue;
        }

        saved_req = pc->req;
        pid = kbox_syscall_request_pid(&saved_req);
        kbox_dispatch_prepare_request_ctx(ctx, &saved_req);

        lkl_fd = resolve_lkl_socket_entry(ctx, pc->guest_fd, &entry);
        if (lkl_fd < 0 || !entry) {
            struct kbox_dispatch d;

            if (write_pollfd_revents(ctx, pid, pc->fds_ptr, POLLNVAL) < 0)
                d = kbox_dispatch_errno(EFAULT);
            else
                d = kbox_dispatch_value(1);
            pc->active = 0;
            ctx->pending_connect_poll_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        st = probe_connecting_lkl_socket(ctx, lkl_fd, &lkl_rev);
        if (st > 0) {
            struct kbox_dispatch d = kbox_dispatch_continue();

            entry->sock_established = 1;
            pc->active = 0;
            ctx->pending_connect_poll_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }
        if (st < 0) {
            short rev =
                (short) ((pc->events & (POLLOUT | POLLWRNORM | POLLWRBAND)) |
                         (lkl_rev & (POLLERR | POLLHUP | POLLNVAL)));
            struct kbox_dispatch d;

            entry->sock_connected = 0;
            entry->sock_established = 0;
            if (write_pollfd_revents(ctx, pid, pc->fds_ptr, rev) < 0)
                d = kbox_dispatch_errno(EFAULT);
            else
                d = kbox_dispatch_value(1);
            pc->active = 0;
            ctx->pending_connect_poll_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }
        if (pc->has_deadline && now_ns >= pc->deadline_ns) {
            struct kbox_dispatch d;

            if (write_pollfd_revents(ctx, pid, pc->fds_ptr, 0) < 0)
                d = kbox_dispatch_errno(EFAULT);
            else
                d = kbox_dispatch_value(0);
            pc->active = 0;
            ctx->pending_connect_poll_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
        }
    }
}

void kbox_dispatch_poll_pending(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || ctx->listener_fd < 0)
        return;
    poll_pending_recvs(ctx);
    poll_pending_recvmsgs(ctx);
    kbox_poll_pending_fifo_opens(ctx);
    kbox_poll_pending_connect_polls(ctx);
    if (ctx->pending_accept_count == 0)
        return;

    struct pollfd pfds[KBOX_PENDING_ACCEPTS_MAX];
    size_t slots[KBOX_PENDING_ACCEPTS_MAX];
    long lkl_fds[KBOX_PENDING_ACCEPTS_MAX];
    size_t npoll = 0;

    for (size_t i = 0; i < KBOX_PENDING_ACCEPTS_MAX; i++) {
        struct kbox_pending_accept *pa = &ctx->pending_accepts[i];
        if (!pa->active)
            continue;

        uint64_t id = kbox_syscall_request_cookie(&pa->req);
        if (ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
            0) {
            pa->active = 0;
            ctx->pending_accept_count--;
            continue;
        }

        struct kbox_syscall_request saved_req = pa->req;
        kbox_dispatch_prepare_request_ctx(ctx, &saved_req);

        struct kbox_fd_entry *entry = NULL;
        long lkl_fd = resolve_lkl_socket_entry(ctx, pa->listen_fd, &entry);
        if (lkl_fd < 0) {
            struct kbox_dispatch d = kbox_dispatch_errno(EBADF);
            pa->active = 0;
            ctx->pending_accept_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        pfds[npoll].fd = (int) lkl_fd;
        pfds[npoll].events = POLLIN;
        pfds[npoll].revents = 0;
        slots[npoll] = i;
        lkl_fds[npoll] = lkl_fd;
        npoll++;
    }

    if (npoll == 0)
        return;

    /* Check readiness across all waiting listeners in a single LKL ppoll call
     * so idle listening sockets don't burn BKL time with accept4 retries.
     */
    struct timespec zero_ts = {0, 0};
    long pr = kbox_lkl_ppoll(ctx->sysnrs, pfds, (unsigned long) npoll, &zero_ts,
                             NULL, 0);
    if (pr == 0)
        return;
    int filter_ready = (pr > 0);

    for (size_t k = 0; k < npoll; k++) {
        if (filter_ready &&
            !(pfds[k].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)))
            continue;

        struct kbox_pending_accept *pa = &ctx->pending_accepts[slots[k]];
        if (!pa->active)
            continue;

        uint64_t id = kbox_syscall_request_cookie(&pa->req);
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: accept retry slot=%zu listen=%ld count=%zu\n",
                    slots[k], pa->listen_fd, ctx->pending_accept_count);

        struct kbox_syscall_request saved_req = pa->req;
        kbox_dispatch_prepare_request_ctx(ctx, &saved_req);

        struct kbox_fd_entry *entry = NULL;
        long lkl_fd = resolve_lkl_socket_entry(ctx, pa->listen_fd, &entry);
        if (lkl_fd < 0) {
            struct kbox_dispatch d = kbox_dispatch_errno(EBADF);
            pa->active = 0;
            ctx->pending_accept_count--;
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }
        (void) lkl_fds[k];

        uint8_t addr[4096] = {0};
        unsigned int out_len = pa->addr_ptr != 0 ? pa->in_len : 0;
        long client_lkl = try_accept4_nonblock(
            ctx->sysnrs, lkl_fd, NULL, pa->addr_ptr ? addr : NULL,
            pa->addr_ptr ? &out_len : NULL, pa->flags, ctx->verbose ? 1 : 0);
        if (client_lkl == -EAGAIN || client_lkl == -EWOULDBLOCK)
            continue;

        uint64_t addr_ptr = pa->addr_ptr;
        uint64_t len_ptr = pa->len_ptr;
        unsigned int in_len = pa->in_len;
        int flags = pa->flags;

        pa->active = 0;
        ctx->pending_accept_count--;

        struct kbox_dispatch d = complete_accept_result(
            &saved_req, ctx, entry, lkl_fd, addr_ptr, len_ptr, in_len, out_len,
            addr, client_lkl, flags);
        kbox_notify_respond(ctx->listener_fd, id, &d);
    }
}

static struct kbox_dispatch dispatch_accept_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int flags)
{
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);

    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: accept cont fd=%ld lkl=%ld so=%d\n", fd,
                    lkl_fd, lkl_fd == KBOX_LKL_FD_SHADOW_ONLY);
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);
    unsigned int in_len = 0;

    if (addr_ptr != 0) {
        if (len_ptr == 0)
            return kbox_dispatch_errno(EFAULT);
        int rrc = guest_mem_read(ctx, pid, len_ptr, &in_len, sizeof(in_len));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
        if ((int) in_len < 0)
            return kbox_dispatch_errno(EINVAL);
        if (in_len > 4096)
            in_len = 4096;
    }

    uint8_t addr[4096] = {0};
    unsigned int out_len = 0;
    int nonblock = 0;
    long client_lkl = -EAGAIN;

    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr,
                "kbox: net: accept enter lkl=%ld listener_fd=%d src=%d\n",
                lkl_fd, ctx->listener_fd, (int) req->source);
    for (;;) {
        out_len = addr_ptr != 0 ? in_len : 0;
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            ctx->listener_fd >= 0) {
            client_lkl = try_accept4_nonblock(
                ctx->sysnrs, lkl_fd, &nonblock, addr_ptr ? addr : NULL,
                addr_ptr ? &out_len : NULL, flags, ctx->verbose ? 1 : 0);
        } else {
            long lfl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
            nonblock = (lfl >= 0 && (lfl & O_NONBLOCK)) ? 1 : 0;
            client_lkl =
                kbox_lkl_accept4(ctx->sysnrs, lkl_fd, addr_ptr ? addr : NULL,
                                 addr_ptr ? &out_len : NULL, flags);
        }
        if (client_lkl != -EAGAIN && client_lkl != -EWOULDBLOCK)
            break;
        if (nonblock)
            break;
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            ctx->listener_fd >= 0) {
            return defer_pending_accept(req, ctx, fd, flags, addr_ptr, len_ptr,
                                        in_len);
        }
        struct pollfd lpfd = {
            .fd = (int) lkl_fd,
            .events = POLLIN,
            .revents = 0,
        };
        struct timespec ts = {0, 50 * 1000 * 1000};
        long pr = kbox_lkl_ppoll(ctx->sysnrs, &lpfd, 1, &ts, NULL, 0);
        if (pr < 0 && pr != -EINTR) {
            client_lkl = pr;
            break;
        }
    }

    return complete_accept_result(req, ctx, entry, lkl_fd, addr_ptr, len_ptr,
                                  in_len, out_len, addr, client_lkl, flags);
}

struct kbox_dispatch forward_accept(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    return dispatch_accept_common(req, ctx, 0);
}

struct kbox_dispatch forward_accept4(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return dispatch_accept_common(req, ctx, flags);
}

struct kbox_dispatch forward_connect(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        struct kbox_dispatch ud;
        if (unix_path_call(req, ctx, 0, &ud))
            return ud;
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;

    if (addr_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    if (len > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t buf[4096];
    int rrc = guest_mem_read(ctx, pid, addr_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (ctx->verbose && len >= sizeof(struct sockaddr_in) &&
        ((struct sockaddr_in *) buf)->sin_family == AF_INET) {
        struct sockaddr_in *d = (struct sockaddr_in *) buf;
        char dstr[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &d->sin_addr, dstr, sizeof(dstr));
        fprintf(stderr,
                "kbox: net: connect fd=%ld lkl_fd=%ld -> %s:%u own=%s\n", fd,
                lkl_fd, dstr, (unsigned) ntohs(d->sin_port),
                ctx->own_ip[0] ? ctx->own_ip : "-");
    }

    /* A connect aimed at the container's own address is left alone: the LKL
     * interface owns that address, so the listener is reached locally without
     * leaving the container. Retargeting it to slirp's fixed guest address was
     * wrong -- that address carries no listener, and the connect came back
     * refused instead of being served. Keep the trace until the own-address
     * path is proven on every image we run.
     */
    if (kbox_net_is_active())
        kbox_sweep_stale_bridged_sockets(ctx, pid);
    long ret = kbox_lkl_connect(ctx->sysnrs, lkl_fd, buf, (long) len);

    /* A loopback connect often comes back EINPROGRESS even though both ends are
     * inside this kernel. The tracee then waits for POLLOUT on the socketpair,
     * which is a host fd and does not know about LKL's handshake, so the
     * guest's poll+SO_ERROR loop can miss it and the connect looks hung. For a
     * blocking socket, finish the handshake here instead of handing it back.
     */
    if (ret == -EINPROGRESS) {
        long fl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
        int blocking = !(fl >= 0 && (fl & O_NONBLOCK));
        if (blocking) {
            /* A blocking connect must not report "in progress": Linux waits for
             * the handshake and returns success or the real error. POLLOUT on
             * the descriptor the guest polls is not proof of completion -- that
             * descriptor is a host socketpair, and it reports POLLOUT as soon
             * as the peer exists. Calling the connect complete there made the
             * next read answer EINPROGRESS, which MariaDB's client reports as
             * "Lost connection to server at 'handshake: reading initial
             * communication packet', system error: 115" and the chained-SSL
             * test as a result mismatch. SO_ERROR carries LKL's own state, so
             * wait on that instead.
             */
            for (int attempt = 0; attempt < 1200; attempt++) {
                struct pollfd wp = {
                    .fd = (int) lkl_fd,
                    .events = POLLOUT,
                    .revents = 0,
                };
                struct timespec wts = {0, 10 * 1000 * 1000};
                struct sockaddr_storage peer;
                socklen_t plen = sizeof(peer);
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                long gr;

                /* SO_ERROR carries no error while the handshake is still in
                 * flight, so a zero there is not proof that the connection is
                 * up. getpeername() is: it answers ENOTCONN until the peer is
                 * known. Measured on a loopback connect that returned
                 * EINPROGRESS: the old loop read SO_ERROR == 0 and answered a
                 * blocking connect() with success before the connection
                 * existed, and the mariadb client reported "Lost connection to
                 * server at 'handshake: reading initial communication
                 * packet', system error: 115" for 74 to 108 of 200 attempts,
                 * while plain Docker completed all 200.
                 */
                if (kbox_lkl_getpeername(ctx->sysnrs, lkl_fd, &peer, &plen) ==
                    0) {
                    ret = 0;
                    break;
                }
                int pumped_err = kbox_net_take_lkl_error((int) lkl_fd);
                if (pumped_err > 0) {
                    ret = -(long) pumped_err;
                    break;
                }
                gr = kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, SOL_SOCKET,
                                         SO_ERROR, &soerr, &slen);
                if (gr == 0 && soerr != 0 && soerr != EINPROGRESS &&
                    soerr != EALREADY && soerr != EAGAIN) {
                    ret = -(long) soerr;
                    break;
                }
                /* A connecting descriptor reports writable long before the
                 * handshake finishes, so ppoll returns at once and a loop that
                 * only re-reads the error state runs all 1200 passes in
                 * microseconds. Waiting has to be on the clock, not on
                 * readiness. */
                (void) kbox_lkl_ppoll(ctx->sysnrs, &wp, 1, &wts, NULL, 0);
            }
            if (ret == -EINPROGRESS)
                ret = -ETIMEDOUT;
        }
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: net: connect ret lkl_fd=%ld -> %ld\n", lkl_fd,
                ret);

    /* Remember that the socket has a peer. recv/send on a stream socket
     * without one must fail with ENOTCONN instead of waiting on the shadow
     * socketpair, which is always connected and therefore never reports it. */
    if (entry && (ret == 0 || ret == -EINPROGRESS)) {
        entry->sock_connected = 1;
        entry->sock_established = (ret == 0);
        record_sock_peer(entry, buf, len);
        /* The listener on the other side can accept right away; wake it before
         * this syscall returns. */
        kbox_net_notify_listeners();
    }

    /* Propagate -EINPROGRESS directly for nonblocking sockets. The tracee's
     * poll(POLLOUT) on the AF_UNIX socketpair returns immediately (spurious
     * wakeup), but getsockopt(SO_ERROR) is forwarded to the LKL socket and
     * returns the real handshake status. The tracee retries poll+getsockopt
     * until SO_ERROR clears; standard nonblocking connect flow.
     */
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_getsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        /* SO_PEERCRED on a host-passthrough socket (every AF_UNIX one is: LKL
         * has no unix sockets) is answered by the HOST kernel, which reports
         * the host owner of the peer -- the role user, uid 1000 -- while the
         * guest believes it is uid 0. A guest-side peer check then sees a
         * stranger: hermes refuses its own gateway with "unsafe_control_peer"
         * and every agent run dies before its first model call.
         *
         * Report the identity the guest would present. The opposite rewrite
         * already exists in sendmsg, which turns SCM_CREDENTIALS into host
         * credentials so the host kernel accepts them. */
        if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
            long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
            uint64_t optlen_ptr = kbox_syscall_request_arg(req, 4);

            if (level == SOL_SOCKET && optname == SO_PEERCRED &&
                optval_ptr != 0 && optlen_ptr != 0) {
                pid_t pid = kbox_syscall_request_pid(req);
                unsigned int optlen = 0;
                if (guest_mem_read(ctx, pid, optlen_ptr, &optlen,
                                   sizeof(optlen)) >= 0 &&
                    optlen >= sizeof(struct ucred)) {
                    struct ucred uc;
                    memset(&uc, 0, sizeof(uc));
                    uc.uid = ctx->root_identity ? 0 : (uint32_t) getuid();
                    uc.gid = ctx->root_identity ? 0 : (uint32_t) getgid();
                    if (guest_mem_write(ctx, pid, optval_ptr, &uc,
                                        sizeof(uc)) >= 0) {
                        unsigned int out_len = sizeof(uc);
                        (void) guest_mem_write(ctx, pid, optlen_ptr, &out_len,
                                               sizeof(out_len));
                        return kbox_dispatch_value(0);
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    uint64_t optlen_ptr = kbox_syscall_request_arg(req, 4);

    if (optval_ptr == 0 || optlen_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Read the optlen from tracee. */
    unsigned int optlen;
    int rrc = guest_mem_read(ctx, pid, optlen_ptr, &optlen, sizeof(optlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096];
    unsigned int out_len = optlen;

    long ret = kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, level, optname, optval,
                                   &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    /* A connect() that completed in the background reports its outcome once,
     * here: 0 means the connection is up, an error means it never was. Track
     * that so getpeername() (and with it ssl.SSLSocket._create) agrees with
     * what the guest was told. */
    if (level == SOL_SOCKET && optname == SO_ERROR && out_len >= sizeof(int)) {
        struct kbox_fd_entry *entry = NULL;
        int so_error;

        (void) resolve_lkl_socket_entry(ctx, fd, &entry);
        memcpy(&so_error, optval, sizeof(so_error));
        if (getenv("KBOX_SOERR_TRACE"))
            fprintf(stderr,
                    "kbox: soerr fd=%ld lkl=%ld entry=%p shadow=%d err=%d "
                    "conn=%d est=%d\n",
                    fd, lkl_fd, (void *) entry,
                    entry ? (int) entry->shadow_sp : -1, so_error,
                    entry ? (int) entry->sock_connected : -1,
                    entry ? (int) entry->sock_established : -1);
        if (so_error == 0) {
            int pumped_err = kbox_net_take_lkl_error((int) lkl_fd);

            if (pumped_err > 0) {
                so_error = pumped_err;
                memcpy(optval, &so_error, sizeof(so_error));
            }
        } else {
            (void) kbox_net_take_lkl_error((int) lkl_fd);
        }
        if (entry && entry->shadow_sp >= 0) {
            /* SO_ERROR must answer for the state the guest is asking about, and
             * "in flight" is a state, not an outcome. The guest that drives a
             * connect through epoll -- asyncio, anyio, httpx, so every hermes
             * model call -- reads SO_ERROR once, after writability, and takes
             * ANY non-zero value as the connect failure. A single failed
             * getpeername() here used to answer EINPROGRESS and tear the entry
             * down, so that guest saw "[Errno 115] Operation now in progress"
             * and could never reach the model, while a blocking connect (which
             * the connect path finishes itself) worked.
             *
             * Finish the handshake here instead, waiting the same bounded way
             * the blocking path does: 0 or the real error, never a spurious
             * EINPROGRESS. */
            if (so_error == 0 && entry->sock_connected &&
                !entry->sock_established) {
                struct sockaddr_storage peer;
                socklen_t plen = sizeof(peer);
                int done = 0;

                for (int attempt = 0; attempt < 1200; attempt++) {
                    int pumped_err;

                    plen = sizeof(peer);
                    if (kbox_lkl_getpeername(ctx->sysnrs, lkl_fd, &peer,
                                             &plen) == 0) {
                        entry->sock_established = 1;
                        done = 1;
                        break;
                    }
                    pumped_err = kbox_net_take_lkl_error((int) lkl_fd);
                    if (pumped_err > 0 && pumped_err != EINPROGRESS &&
                        pumped_err != EALREADY && pumped_err != EAGAIN) {
                        so_error = pumped_err;
                        entry->sock_connected = 0;
                        entry->sock_established = 0;
                        entry->sock_peer_family = 0;
                        done = 1;
                        break;
                    }
                    {
                        struct pollfd wp = {
                            .fd = (int) lkl_fd,
                            .events = POLLOUT,
                            .revents = 0,
                        };
                        struct timespec wts = {0, 2 * 1000 * 1000};

                        (void) kbox_lkl_ppoll(ctx->sysnrs, &wp, 1, &wts, NULL,
                                              0);
                    }
                }
                if (!done)
                    so_error = EINPROGRESS;
                memcpy(optval, &so_error, sizeof(so_error));
            } else if (so_error != 0 && so_error != EINPROGRESS &&
                       so_error != EALREADY) {
                entry->sock_connected = 0;
                entry->sock_established = 0;
                entry->sock_peer_family = 0;
            } else if (so_error == 0) {
                entry->sock_established = 1;
            }
        }
    }

    /* Write min(out_len, optlen) to avoid leaking stack data. */
    unsigned int write_len = out_len < optlen ? out_len : optlen;
    int wrc = guest_mem_write(ctx, pid, optval_ptr, optval, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, optlen_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_setsockopt(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))) {
        if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX && g_unix_type[fd] != 0) {
            long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
            long optlen = to_c_long_arg(kbox_syscall_request_arg(req, 4));

            if (level == SOL_SOCKET && optval_ptr != 0 &&
                optlen == (long) sizeof(struct timeval) &&
                (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
                struct timeval tv;

                if (guest_mem_read(ctx, kbox_syscall_request_pid(req),
                                   optval_ptr, &tv, sizeof(tv)) == 0) {
                    if (optname == SO_RCVTIMEO) {
                        g_unix_opts[fd].has_rcvtimeo = 1;
                        g_unix_opts[fd].rcvtimeo = tv;
                    } else {
                        g_unix_opts[fd].has_sndtimeo = 1;
                        g_unix_opts[fd].sndtimeo = tv;
                    }
                }
            }
        }
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    long level = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long optname = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t optval_ptr = kbox_syscall_request_arg(req, 3);
    long optlen = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    if (optlen < 0 || optlen > 4096)
        return kbox_dispatch_errno(EINVAL);

    uint8_t optval[4096] = {0};
    if (optval_ptr != 0 && optlen > 0) {
        int rrc = guest_mem_read(ctx, pid, optval_ptr, optval, (size_t) optlen);
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }

    long ret = kbox_lkl_setsockopt(ctx->sysnrs, lkl_fd, level, optname,
                                   optval_ptr ? optval : NULL, optlen);
    /* Mirror SO_RCVTIMEO and SO_SNDTIMEO onto the host socketpair that backs
     * read(2)/write(2)/readv(2)/writev(2) on bridged TCP sockets.
     */
    if (ret == 0 && entry && entry->shadow_sp >= 0 && level == SOL_SOCKET &&
        optval_ptr != 0 && optlen > 0 &&
        (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
        (void) setsockopt(entry->shadow_sp, SOL_SOCKET, (int) optname, optval,
                          (socklen_t) optlen);
    }
    return kbox_dispatch_from_lkl(ret);
}

typedef long (*sockaddr_query_fn)(const struct kbox_sysnrs *s,
                                  long fd,
                                  void *addr,
                                  void *addrlen);

static struct kbox_dispatch forward_sockaddr_query(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    sockaddr_query_fn query)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);

    if (addr_ptr == 0 || len_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    unsigned int addrlen;
    int rrc = guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    if (addrlen > 4096)
        addrlen = 4096;

    uint8_t addr[4096] = {0};
    unsigned int out_len = addrlen;

    long ret = query(ctx->sysnrs, lkl_fd, addr, &out_len);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    unsigned int write_len = out_len < addrlen ? out_len : addrlen;
    int wrc = guest_mem_write(ctx, pid, addr_ptr, addr, write_len);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    wrc = guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getsockname(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX && g_unix_bind_path[fd])
        return unix_path_query(req, ctx, fd, g_unix_bind_path[fd], 1);
    return forward_sockaddr_query(req, ctx, kbox_lkl_getsockname);
}

/* Remember the peer address of a connected bridged socket.
 *
 * The guest's descriptor is a socketpair end, so neither the host nor the LKL
 * twin is a reliable source for this: the host would name the socketpair, and
 * the LKL twin can be retired and its number reused while the guest's end is
 * still live. The connection's peer is the sockaddr the guest connected to,
 * which is known here and never changes.
 */
static void record_sock_peer(struct kbox_fd_entry *entry,
                             const uint8_t *addr,
                             size_t len)
{
    if (!entry || !addr)
        return;

    memset(&entry->sock_peer, 0, sizeof(entry->sock_peer));
    entry->sock_peer_family = 0;
    if (len >= sizeof(struct sockaddr_in) &&
        ((const struct sockaddr_in *) addr)->sin_family == AF_INET) {
        memcpy(&entry->sock_peer.in, addr, sizeof(struct sockaddr_in));
        entry->sock_peer_family = AF_INET;
    } else if (len >= sizeof(struct sockaddr_in6) &&
               ((const struct sockaddr_in6 *) addr)->sin6_family == AF_INET6) {
        memcpy(&entry->sock_peer.in6, addr, sizeof(struct sockaddr_in6));
        entry->sock_peer_family = AF_INET6;
    }
}

/* Answer getpeername() from the recorded peer.
 *
 * ssl.SSLSocket._create() asks getpeername() to decide whether the socket it
 * wraps is connected, and treats ENOTCONN as "not connected" -- it then skips
 * the handshake entirely and the caller fails later with a bare ENOTCONN
 * (test_ssl.SimpleBackgroundTests.test_get_server_certificate_timeout). A
 * socket whose connect() the guest already saw succeed is connected, whatever
 * state the LKL twin is in at that instant.
 *
 * Returns 1 when the call was answered, 0 when the caller must ask LKL (no
 * recorded peer: an accepted socket the guest asked no address for, or one
 * that is not connected at all).
 */
static int answer_peer_from_entry(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx,
                                  const struct kbox_fd_entry *entry,
                                  struct kbox_dispatch *out)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 1);
    uint64_t len_ptr = kbox_syscall_request_arg(req, 2);
    unsigned int addrlen;

    if (!entry || !entry->sock_connected || entry->sock_peer_family == 0)
        return 0;
    if (addr_ptr == 0 || len_ptr == 0)
        return 0;
    if (guest_mem_read(ctx, pid, len_ptr, &addrlen, sizeof(addrlen)) < 0)
        return 0;

    if (entry->sock_peer_family == AF_INET) {
        unsigned int out_len = (unsigned int) sizeof(struct sockaddr_in);

        if (guest_mem_write(ctx, pid, addr_ptr, &entry->sock_peer.in, out_len) <
                0 ||
            guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len)) < 0)
            return 0;
        *out = kbox_dispatch_value(0);
        return 1;
    }
    {
        unsigned int out_len = (unsigned int) sizeof(struct sockaddr_in6);

        if (guest_mem_write(ctx, pid, addr_ptr, &entry->sock_peer.in6,
                            out_len) < 0 ||
            guest_mem_write(ctx, pid, len_ptr, &out_len, sizeof(out_len)) < 0)
            return 0;
        *out = kbox_dispatch_value(0);
        return 1;
    }
}

struct kbox_dispatch forward_getpeername(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    struct kbox_dispatch d;

    if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX && g_unix_peer_path[fd])
        return unix_path_query(req, ctx, fd, g_unix_peer_path[fd], 0);

    (void) resolve_lkl_socket_entry(ctx, fd, &entry);

    /* LKL answers first: a connection that really ended (a reset, or a peer
     * that never completed the handshake) must keep answering ENOTCONN. That
     * is what ssl.SSLSocket._create() relies on to detect a socket closed
     * before the handshake, and test_ssl.test_preauth_data_to_tls_client
     * checks it for a peer that resets a connection carrying data.
     */
    d = forward_sockaddr_query(req, ctx, kbox_lkl_getpeername);
    if (d.kind == KBOX_DISPATCH_RETURN && d.error == 0) {
        if (entry && entry->shadow_sp >= 0)
            entry->sock_established = 1;
        return d;
    }
    if (d.kind == KBOX_DISPATCH_RETURN && d.error == ENOTCONN && entry &&
        !entry->sock_established) {
        struct kbox_dispatch recorded;

        /* The connection is still coming up. The guest's connect() has already
         * returned, its descriptor is a socketpair the host reports as
         * connected, and LKL has simply not finished the handshake yet: answer
         * the peer the guest connected to instead of "not connected". */
        if (answer_peer_from_entry(req, ctx, entry, &recorded))
            return recorded;
    }
    return d;
}

struct kbox_dispatch forward_shutdown(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long how = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (how == SHUT_WR || how == SHUT_RDWR)
        kbox_net_flush_socket((int) lkl_fd);
    long ret = kbox_lkl_shutdown(ctx->sysnrs, lkl_fd, how);
    return kbox_dispatch_from_lkl(ret);
}

/* For shadow sockets with a destination address, forward the data + address
 * directly to the LKL socket. This is needed for unconnected UDP (DNS resolver
 * uses sendto with sockaddr_in without prior connect).
 *
 * sendto(fd, buf, len, flags, dest_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=dest_addr, args[5]=addrlen
 */
/* Deliver out-of-band data the way the guest asked for.
 *
 * Stream data from the tracee goes into a socketpair and the net pump forwards
 * it to the LKL socket with MSG_DONTWAIT, so the urgent flag never survives the
 * trip: AF_UNIX socketpairs reject MSG_OOB, and the pump has no per-chunk flags
 * to carry. ftplib.abort() sends "ABOR" with MSG_OOB, the server's SO_OOBINLINE
 * socket never saw it, and the client waited for a reply that could not come.
 *
 * Send the urgent bytes on the LKL socket directly, after draining whatever the
 * pump still holds, so the byte keeps its place in the stream.
 */
static struct kbox_dispatch shadow_send_oob(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long lkl_fd,
    uint64_t buf_ptr,
    size_t len)
{
    uint8_t buf[4096];
    long ret;

    if (len == 0)
        return kbox_dispatch_value(0);
    if (len > sizeof(buf))
        len = sizeof(buf);
    if (guest_mem_read(ctx, kbox_syscall_request_pid(req), buf_ptr, buf, len) <
        0)
        return kbox_dispatch_errno(EFAULT);

    kbox_net_flush_socket((int) lkl_fd);
    ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len,
                          MSG_OOB | MSG_DONTWAIT, NULL, 0);
    return kbox_dispatch_from_lkl(ret);
}

/* Same, for sendmsg: gather the iovecs into one buffer, then send it urgent. */
static struct kbox_dispatch shadow_sendmsg_oob(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long lkl_fd)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
    struct {
        uint64_t msg_name;
        uint32_t msg_namelen;
        uint32_t __pad0;
        uint64_t msg_iov;
        uint64_t msg_iovlen;
        uint64_t msg_control;
        uint64_t msg_controllen;
        int msg_flags;
    } mh;
    struct {
        uint64_t iov_base;
        uint64_t iov_len;
    } iovs[64];
    uint8_t buf[4096];
    size_t total = 0;
    size_t niov;
    long ret;

    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh)) < 0)
        return kbox_dispatch_errno(EFAULT);

    niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;
    if (niov > 0 &&
        guest_mem_read(ctx, pid, mh.msg_iov, iovs, niov * sizeof(iovs[0])) < 0)
        return kbox_dispatch_errno(EFAULT);

    for (size_t v = 0; v < niov && total < sizeof(buf); v++) {
        size_t take = (size_t) iovs[v].iov_len;

        if (take > sizeof(buf) - total)
            take = sizeof(buf) - total;
        if (take == 0)
            continue;
        if (guest_mem_read(ctx, pid, iovs[v].iov_base, buf + total, take) < 0)
            return kbox_dispatch_errno(EFAULT);
        total += take;
    }
    if (total == 0)
        return kbox_dispatch_value(0);

    kbox_net_flush_socket((int) lkl_fd);
    ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) total,
                          MSG_OOB | MSG_DONTWAIT, NULL, 0);
    return kbox_dispatch_from_lkl(ret);
}

/* sendto(2) to an AF_UNIX path address.
 *
 * A datagram socket bound to a guest path lives in the host namespace (see
 * unix_path_call): the path the guest sees is only an inode LKL keeps for stat.
 * The host-fd shortcut below would hand the call to the kernel with the guest
 * path, which the host cannot resolve, and LKL's sendto finds no bound socket
 * there either -- test_logging's UnixDatagramHandler failed with ENOENT and
 * left the module waiting for a datagram that never arrived.
 *
 * The supervisor can address the hashed host path directly, so it sends the
 * datagram from its own unbound socket. A sender that is itself bound to a
 * guest path is left alone: its datagrams must carry its own address, and only
 * its own socket can provide that.
 *
 * Returns 1 when handled and fills *ret (a byte count or a negative errno);
 * returns 0 to let the caller continue with the normal path.
 */
static int unix_path_sendto(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long fd,
                            long *ret)
{
    struct sockaddr_un host;
    char gpath[sizeof(host.sun_path) + 1];
    char gabs[KBOX_MAX_PATH];
    char hpath[sizeof(host.sun_path)];
    uint8_t addr[128];
    uint8_t data[65536];
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr_ptr = kbox_syscall_request_arg(req, 4);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    int64_t addrlen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 5));
    size_t len, addrlen, plen;
    int sock;
    ssize_t n;

    if (addr_ptr == 0 || addrlen_raw < 3 ||
        addrlen_raw > (int64_t) sizeof(addr))
        return 0;
    addrlen = (size_t) addrlen_raw;
    if (guest_mem_read(ctx, pid, addr_ptr, addr, addrlen) < 0)
        return 0;
    if (addr[0] != AF_UNIX || addr[1] != 0 || addr[2] == '\0')
        return 0; /* not AF_UNIX, or abstract */
    if (fd >= 0 && fd < KBOX_UNIX_TYPE_MAX && g_unix_bind_path[fd])
        return 0;

    if (len_raw < 0)
        return 0;
    len = (size_t) len_raw;
    if (len > sizeof(data))
        return 0;
    if (len > 0 && guest_mem_read(ctx, pid, buf_ptr, data, len) < 0)
        return 0;

    plen = addrlen - 2;
    if (plen > sizeof(host.sun_path))
        plen = sizeof(host.sun_path);
    memcpy(gpath, addr + 2, plen);
    gpath[plen] = '\0';

    if (unix_resolve_guest_path(ctx, gpath, gabs, sizeof(gabs)) < 0)
        return 0;
    if (unix_host_path(ctx, gabs, hpath, sizeof(hpath)) < 0) {
        *ret = -ENAMETOOLONG;
        return 1;
    }

    sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        *ret = -errno;
        return 1;
    }
    memset(&host, 0, sizeof(host));
    host.sun_family = AF_UNIX;
    memcpy(host.sun_path, hpath, strlen(hpath));
    n = sendto(sock, data, len, (int) flags, (struct sockaddr *) &host,
               (socklen_t) sizeof(host));
    if (n < 0 && (errno == ENOENT || errno == ECONNREFUSED)) {
        /* No kbox-bound socket at that path: the normal path knows best. */
        close(sock);
        return 0;
    }
    *ret = n < 0 ? -errno : (long) n;
    close(sock);
    return 1;
}

/* A send to a connected stream socket that carries an address.
 *
 * POSIX says the address is ignored then, and the guest's descriptor is a
 * socketpair that is itself connected: handing the AF_INET address to the host
 * answered EISCONN, and handing it to LKL put a blocking send inside the
 * dispatcher, where a signal could not interrupt it
 * (test_socket.InterruptedSendTimeoutTest.testInterruptedSendtoTimeout).
 * So the address is dropped here and the bytes go to the descriptor the tracee
 * actually wrote to.
 */
static long send_ignoring_addr(struct kbox_supervisor_ctx *ctx,
                               struct kbox_fd_entry *entry,
                               long lkl_fd,
                               pid_t pid,
                               uint64_t buf_ptr,
                               size_t len,
                               long flags)
{
    uint8_t buf[65536];
    int writes = 0;

    if (len > sizeof(buf))
        len = sizeof(buf);
    if (guest_mem_read(ctx, pid, buf_ptr, buf, len) < 0)
        return -EFAULT;

    if (entry && entry->shadow_sp >= 0) {
        for (int step = 0; step < 4; step++) {
            ssize_t n =
                send(entry->shadow_sp, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);

            if (n >= 0)
                return (long) n;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                return -errno;
            struct pollfd p = {
                .fd = entry->shadow_sp,
                .events = POLLOUT,
                .revents = 0,
            };
            if (poll(&p, 1, 25) <= 0)
                return -EAGAIN;
        }
        return -EAGAIN;
    }

    for (writes = 0; writes < 4; writes++) {
        long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len,
                                   flags | 0x40 /* MSG_DONTWAIT */, NULL, 0);

        if (ret >= 0 || (ret != -EAGAIN && ret != -EWOULDBLOCK))
            return ret;
        struct pollfd p = {
            .fd = (int) lkl_fd,
            .events = POLLOUT,
            .revents = 0,
        };
        struct timespec ts = {0, 25 * 1000 * 1000};

        if (kbox_lkl_ppoll(ctx->sysnrs, &p, 1, &ts, NULL, 0) <= 0)
            return -EAGAIN;
    }
    return -EAGAIN;
}

struct kbox_dispatch forward_sendto(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long unix_ret;

    /* An AF_UNIX path datagram has to be decided before the host-fd shortcut
     * below, which would otherwise hand the guest path to the host kernel. */
    if (unix_path_sendto(req, ctx, fd, &unix_ret))
        return kbox_dispatch_from_lkl(unix_ret);

    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t dest_ptr = kbox_syscall_request_arg(req, 4);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (dest_ptr == 0 && stream_socket_unconnected(entry))
        return kbox_dispatch_errno(ENOTCONN);
    if (dest_ptr == 0) {
        if ((flags & MSG_OOB) && lkl_fd >= 0 && len_raw > 0)
            return shadow_send_oob(ctx, req, lkl_fd, buf_ptr, (size_t) len_raw);
        if (!entry || entry->shadow_sp >= 0) {
            /* Bridged: the host kernel writes into the socketpair. Record that
             * the bridge owes delivery, so a readiness call that follows does
             * not measure the socket before the peer has the bytes. */
            kbox_net_mark_guest_write();
            return kbox_dispatch_continue();
        }

        /* A socket that lives only inside LKL has no host descriptor to write
         * to: send(2) is sendto(2) without a destination, and the bytes must
         * go through LKL just like an addressed send. */
        if (len_raw < 0)
            return kbox_dispatch_errno(EINVAL);

        pid_t lpid = kbox_syscall_request_pid(req);
        size_t llen = (size_t) len_raw;

        if (llen > 65536)
            llen = 65536;
        uint8_t lbuf[65536];

        {
            int lrc = guest_mem_read(ctx, lpid, buf_ptr, lbuf, llen);

            if (lrc < 0)
                return kbox_dispatch_errno(-lrc);
        }
        return kbox_dispatch_from_lkl(kbox_lkl_sendto(
            ctx->sysnrs, lkl_fd, lbuf, (long) llen, flags, NULL, 0));
    }

    /* Has a destination address: forward via LKL sendto. */
    pid_t pid = kbox_syscall_request_pid(req);
    int64_t addrlen_raw = to_c_long_arg(kbox_syscall_request_arg(req, 5));

    if (len_raw < 0 || addrlen_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    size_t addrlen = (size_t) addrlen_raw;

    if (len > 65536)
        len = 65536;
    if (addrlen > 128)
        return kbox_dispatch_errno(EINVAL);

    if (entry && entry->sock_connected && entry->sock_type == SOCK_STREAM)
        return kbox_dispatch_from_lkl(
            send_ignoring_addr(ctx, entry, lkl_fd, pid, buf_ptr, len, flags));

    uint8_t buf[65536];
    uint8_t addr[128];

    int rrc = guest_mem_read(ctx, pid, buf_ptr, buf, len);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    rrc = guest_mem_read(ctx, pid, dest_ptr, addr, addrlen);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long ret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) len, flags,
                               addr, (long) addrlen);
    return kbox_dispatch_from_lkl(ret);
}

/* Forward sendmmsg(fd, msgvec, vlen, flags) via LKL sendto for addressed
 * messages (e.g. unconnected UDP sockets such as glibc DNS retries). Connected
 * sockets without msg_name fall through to the host socketpair via CONTINUE.
 */
struct kbox_dispatch forward_sendmmsg(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = resolve_lkl_socket(ctx, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t msgvec_ptr = kbox_syscall_request_arg(req, 1);
    unsigned int vlen = (unsigned int) kbox_syscall_request_arg(req, 2);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    if (vlen == 0)
        return kbox_dispatch_value(0);
    if (msgvec_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    if (vlen > 1024)
        vlen = 1024;

    struct {
        struct {
            uint64_t msg_name;
            uint32_t msg_namelen;
            uint32_t __pad0;
            uint64_t msg_iov;
            uint64_t msg_iovlen;
            uint64_t msg_control;
            uint64_t msg_controllen;
            int msg_flags;
            int __pad1;
        } msg_hdr;
        unsigned int msg_len;
        unsigned int __pad2;
    } mm;
    _Static_assert(sizeof(mm) == 64, "64-bit mmsghdr ABI size mismatch");

    pid_t pid = kbox_syscall_request_pid(req);
    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int sent_msgs = 0;

    for (unsigned int m = 0; m < vlen; m++) {
        uint64_t entry_ptr = msgvec_ptr + (uint64_t) m * sizeof(mm);
        int rrc = guest_mem_read(ctx, pid, entry_ptr, &mm, sizeof(mm));
        if (rrc < 0)
            return sent_msgs > 0 ? kbox_dispatch_value((int64_t) sent_msgs)
                                 : kbox_dispatch_errno(-rrc);

        if (mm.msg_hdr.msg_name == 0 || mm.msg_hdr.msg_namelen == 0) {
            if (sent_msgs == 0)
                return kbox_dispatch_continue();
            break;
        }
        if (mm.msg_hdr.msg_namelen > sizeof(addr))
            return sent_msgs > 0 ? kbox_dispatch_value((int64_t) sent_msgs)
                                 : kbox_dispatch_errno(EINVAL);

        rrc = guest_mem_read(ctx, pid, mm.msg_hdr.msg_name, addr,
                             mm.msg_hdr.msg_namelen);
        if (rrc < 0)
            return sent_msgs > 0 ? kbox_dispatch_value((int64_t) sent_msgs)
                                 : kbox_dispatch_errno(-rrc);

        size_t total_len = 0;
        if (mm.msg_hdr.msg_iovlen > 0) {
            size_t niov = (size_t) mm.msg_hdr.msg_iovlen;
            if (niov > 64)
                niov = 64;
            struct {
                uint64_t iov_base;
                uint64_t iov_len;
            } iovs[64];
            rrc = guest_mem_read(ctx, pid, mm.msg_hdr.msg_iov, iovs,
                                 niov * sizeof(iovs[0]));
            if (rrc < 0)
                return sent_msgs > 0 ? kbox_dispatch_value((int64_t) sent_msgs)
                                     : kbox_dispatch_errno(-rrc);

            for (size_t v = 0; v < niov && total_len < sizeof(buf); v++) {
                size_t chunk = (size_t) iovs[v].iov_len;
                if (chunk > sizeof(buf) - total_len)
                    chunk = sizeof(buf) - total_len;
                if (chunk == 0)
                    continue;
                rrc = guest_mem_read(ctx, pid, iovs[v].iov_base,
                                     buf + total_len, chunk);
                if (rrc < 0)
                    return sent_msgs > 0
                               ? kbox_dispatch_value((int64_t) sent_msgs)
                               : kbox_dispatch_errno(-rrc);
                total_len += chunk;
            }
        }

        long sret = kbox_lkl_sendto(ctx->sysnrs, lkl_fd, buf, (long) total_len,
                                    flags, addr, (long) mm.msg_hdr.msg_namelen);
        if (sret < 0) {
            if (sent_msgs > 0)
                break;
            return kbox_dispatch_from_lkl(sret);
        }

        unsigned int msg_len = (unsigned int) sret;
        (void) guest_mem_write(ctx, pid, entry_ptr + 56, &msg_len,
                               sizeof(msg_len));
        sent_msgs++;
    }

    return kbox_dispatch_value((int64_t) sent_msgs);
}

/* Receive from a shadow socket (draining any datagram/packet already pumped
 * into the supervisor socketpair first so pump_shadow_lkl_read cannot starve
 * recvfrom/recvmsg), preserving the real peer address.
 */
static long shadow_or_lkl_recvfrom(struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_fd_entry *entry,
                                   long lkl_fd,
                                   void *buf,
                                   size_t cap,
                                   long flags,
                                   void *addr_out,
                                   unsigned int *addrlen_io,
                                   void *ctl_out,
                                   size_t *ctllen_io,
                                   size_t ctl_cap,
                                   int *msg_flags_out)
{
    int sp_fd = (entry && entry->shadow_sp >= 0 && kbox_net_is_active())
                    ? entry->shadow_sp
                    : -1;
    if (sp_fd < 0) {
        if (ctl_out && ctllen_io) {
            /* Ask LKL for the ancillary data in the same call. */
            struct iovec iov = {.iov_base = buf, .iov_len = cap};
            struct msghdr mh;
            long lr;

            memset(&mh, 0, sizeof(mh));
            mh.msg_name = addr_out;
            mh.msg_namelen = addrlen_io ? *addrlen_io : 0;
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            mh.msg_control = ctl_out;
            mh.msg_controllen = *ctllen_io < ctl_cap ? *ctllen_io : ctl_cap;

            lr = lkl_syscall6(ctx->sysnrs->recvmsg, lkl_fd, (long) &mh, flags,
                              0, 0, 0);
            if (lr >= 0) {
                if (addrlen_io)
                    *addrlen_io = mh.msg_namelen;
                *ctllen_io = mh.msg_controllen;
            }
            return lr;
        }
        return kbox_lkl_recvfrom(ctx->sysnrs, lkl_fd, buf, (long) cap, flags,
                                 addr_out, addrlen_io);
    }

    int peek = (flags & MSG_PEEK) ? MSG_PEEK : 0;
    int fl = fcntl(sp_fd, F_GETFL);
    int is_nb = ((flags & MSG_DONTWAIT) != 0) || (fl >= 0 && (fl & O_NONBLOCK));

    int stype = 0;
    socklen_t slen = sizeof(stype);
    if (getsockopt(sp_fd, SOL_SOCKET, SO_TYPE, &stype, &slen) < 0)
        stype = 0;

    long deadline_ms = -1;
    if (!is_nb) {
        struct timeval rtv = {0, 0};
        unsigned int rtvlen = sizeof(rtv);
        if (kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, SOL_SOCKET, SO_RCVTIMEO,
                                &rtv, &rtvlen) == 0 &&
            (rtv.tv_sec > 0 || rtv.tv_usec > 0)) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline_ms = (now.tv_sec + rtv.tv_sec) * 1000L +
                          (now.tv_nsec / 1000000L) +
                          ((rtv.tv_usec + 999L) / 1000L);
        }
    }

    for (;;) {
        /* A datagram larger than the tracee's buffer is delivered truncated,
         * but the caller must still learn MSG_TRUNC and receive only the bytes
         * that fit. MSG_TRUNC makes the host report the full datagram size
         * instead of the copied size. */
        int recv_flags = MSG_DONTWAIT | peek;
        ssize_t sp_n;

        if (stype == SOCK_DGRAM)
            recv_flags |= MSG_TRUNC;
        sp_n = recv(sp_fd, buf, cap, recv_flags);
        if (sp_n > 0 && (size_t) sp_n > cap) {
            if (msg_flags_out)
                *msg_flags_out |= MSG_TRUNC;
            sp_n = (ssize_t) cap;
        }
        if (sp_n >= 0) {
            unsigned int alen = 128;
            if (stype == SOCK_DGRAM &&
                kbox_net_pop_dgram_meta((int) lkl_fd, addr_out, &alen, ctl_out,
                                        ctllen_io, ctl_cap, peek != 0)) {
                *addrlen_io = alen;
            } else {
                alen = 128;
                if (kbox_lkl_getpeername(ctx->sysnrs, lkl_fd, addr_out,
                                         &alen) == 0)
                    *addrlen_io = alen;
                else
                    *addrlen_io = 0;
            }
            return (long) sp_n;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -errno;

        /* The LKL socket belongs to the pump: it is the only reader that may
         * take bytes from it, and it is the writer of this socketpair. Reading
         * it here too split one line between two readers, and worse, let this
         * path answer end of file while the pump still held the line in its
         * guest-bound buffer -- the guest received an empty result for data
         * that was already here (test_socket's stream recvmsg cases failed that
         * way in the pod). With this socketpair empty there is nothing to
         * report yet, and the caller parks or retries.
         */
        /* The bridge may be holding an ICMP-derived error for this socket
         * (a port-unreachable on a datagram socket, for instance). Linux
         * reports it once on the next receive. */
        long pending_err = kbox_net_pop_recv_error((int) lkl_fd);
        if (pending_err < 0)
            return pending_err;

        if (is_nb)
            return -EAGAIN;

        int wait_ms = 5;
        if (deadline_ms >= 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long now_ms = now.tv_sec * 1000L + now.tv_nsec / 1000000L;
            if (now_ms >= deadline_ms)
                return -EAGAIN;
            if (deadline_ms - now_ms < wait_ms)
                wait_ms = (int) (deadline_ms - now_ms);
        }
        struct pollfd pfd = {.fd = sp_fd, .events = POLLIN, .revents = 0};
        poll(&pfd, 1, wait_ms);
    }
}

/* For shadow sockets, receive data + source address from the LKL socket and
 * write them back to the tracee.
 *
 * recvfrom(fd, buf, len, flags, src_addr, addrlen)
 *   args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
 *   args[4]=src_addr, args[5]=addrlen
 */
/* Write a completed receive back into the tracee. Shared by the immediate
 * path and by the deferred one, so both produce identical results.
 */
static struct kbox_dispatch finish_recvfrom(
    const struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t buf_ptr,
    uint64_t src_ptr,
    uint64_t addrlen_ptr,
    unsigned int addrlen,
    const void *buf,
    long ret,
    const void *addr,
    unsigned int out_addrlen)
{
    int wrc = guest_mem_write(ctx, pid, buf_ptr, buf, (size_t) ret);

    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    if (src_ptr != 0 && out_addrlen > 0) {
        unsigned int write_len = out_addrlen < addrlen ? out_addrlen : addrlen;

        wrc = guest_mem_write(ctx, pid, src_ptr, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    if (addrlen_ptr != 0) {
        wrc = guest_mem_write(ctx, pid, addrlen_ptr, &out_addrlen,
                              sizeof(out_addrlen));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(ret);
}

/* Park a blocking recvfrom until a datagram arrives.
 *
 * The dispatcher is the only thread that answers seccomp notifications, so a
 * blocking receive on a shadow socket must not wait inside it: the guest's
 * other threads (and, in the asyncio tests, the same thread's next syscall)
 * would never be served. The notification stays unanswered, which keeps the
 * tracee blocked exactly as a blocking recvfrom should, and
 * kbox_dispatch_poll_pending completes it.
 */
static struct kbox_dispatch defer_pending_recv(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long fd,
    uint64_t buf_ptr,
    uint64_t src_ptr,
    uint64_t addrlen_ptr,
    size_t len,
    long flags,
    unsigned int addrlen,
    long lkl_fd)
{
    long deadline_ms = -1;

    /* A receive timeout is the one case where the wait must end by itself. */
    if (lkl_fd >= 0) {
        struct timeval rtv = {0, 0};
        unsigned int rtvlen = sizeof(rtv);

        if (kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, SOL_SOCKET, SO_RCVTIMEO,
                                &rtv, &rtvlen) == 0 &&
            (rtv.tv_sec > 0 || rtv.tv_usec > 0)) {
            struct timespec now;

            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline_ms = (now.tv_sec + rtv.tv_sec) * 1000L +
                          (now.tv_nsec / 1000000L) +
                          ((rtv.tv_usec + 999L) / 1000L);
        }
    }

    for (size_t i = 0; i < KBOX_PENDING_RECVS_MAX; i++) {
        struct kbox_pending_recv *pr = &ctx->pending_recvs[i];

        if (pr->active)
            continue;
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: recvfrom deferred slot=%zu fd=%ld len=%zu\n", i,
                    fd, len);
        pr->active = 1;
        pr->req = *req;
        pr->fd = fd;
        pr->buf_ptr = buf_ptr;
        pr->src_ptr = src_ptr;
        pr->addrlen_ptr = addrlen_ptr;
        pr->len = len;
        pr->flags = flags;
        pr->addrlen = addrlen;
        pr->deadline_ms = deadline_ms;
        ctx->pending_recv_count++;
        return (struct kbox_dispatch) {.kind = KBOX_DISPATCH_DEFERRED};
    }
    return kbox_dispatch_errno(EAGAIN);
}

struct kbox_dispatch forward_recvfrom(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t src_ptr = kbox_syscall_request_arg(req, 4);
    int host_shadow = entry && entry->shadow_sp >= 0;

    /* An unconnected stream socket cannot receive anything, in either form of
     * the call: Linux answers ENOTCONN at once. Deferring the receive instead
     * parked it forever because the peer that would deliver data does not
     * exist -- test_ssl's wrapped unconnected socket hung its whole module in
     * recvfrom() that way (ssl.SSLSocket.recvfrom on a socket that was never
     * connected).
     */
    if (stream_socket_unconnected(entry))
        return kbox_dispatch_errno(ENOTCONN);

    /* No address buffer: this is what recv(2) is on every Linux ABI, and what
     * a stream receiver always passes. A socket that exists only inside LKL --
     * AF_NETLINK, or any family the bridge does not model -- has no host
     * descriptor, and continuing answered EBADF: glibc's if_nameindex() reads
     * its netlink dump through exactly this path, so socket.if_nameindex()
     * failed with a host errno that has nothing to do with the guest.
     *
     * A bridged socket must NOT be continued here. Its descriptor is a host
     * socketpair that carries no receive timeout of its own -- SO_RCVTIMEO
     * lives on the LKL socket -- so the host kernel would block the guest
     * forever and ignore the timeout the guest asked for
     * (test_socket.NetworkConnectionBehaviourTest.testOutsideTimeout, and every
     * SO_RCVTIMEO case). Both forms take the same path below: try once, then
     * park with the timeout applied.
     */
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t buf_ptr = kbox_syscall_request_arg(req, 1);
    int64_t len_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t addrlen_ptr = kbox_syscall_request_arg(req, 5);

    if (len_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t len = (size_t) len_raw;
    if (len > 65536)
        len = 65536;

    unsigned int addrlen = 0;
    if (addrlen_ptr != 0) {
        int rrc =
            guest_mem_read(ctx, pid, addrlen_ptr, &addrlen, sizeof(addrlen));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
    }
    if (addrlen > 128)
        addrlen = 128;

    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int out_addrlen = addrlen;

    {
        int fl = host_shadow ? fcntl(entry->shadow_sp, F_GETFL) : -1;
        int is_nb =
            (flags & MSG_DONTWAIT) != 0 || (fl >= 0 && (fl & O_NONBLOCK) != 0);

        if (!host_shadow) {
            long lfl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);

            if (lfl >= 0 && (lfl & O_NONBLOCK))
                is_nb = 1;
        }

        if (!is_nb && (host_shadow ? kbox_net_is_active() : 1)) {
            long now_ret = shadow_or_lkl_recvfrom(
                ctx, entry, lkl_fd, buf, len, flags | 0x40 /* MSG_DONTWAIT */,
                addr, &out_addrlen, NULL, NULL, 0, NULL);

            if (now_ret != -EAGAIN && now_ret != -EWOULDBLOCK) {
                if (now_ret < 0)
                    return kbox_dispatch_from_lkl(now_ret);
                return finish_recvfrom(ctx, pid, buf_ptr, src_ptr, addrlen_ptr,
                                       addrlen, buf, now_ret, addr,
                                       out_addrlen);
            }
            return defer_pending_recv(req, ctx, fd, buf_ptr, src_ptr,
                                      addrlen_ptr, len, flags, addrlen, lkl_fd);
        }
    }

    long ret = shadow_or_lkl_recvfrom(ctx, entry, lkl_fd, buf, len, flags, addr,
                                      &out_addrlen, NULL, NULL, 0, NULL);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);

    return finish_recvfrom(ctx, pid, buf_ptr, src_ptr, addrlen_ptr, addrlen,
                           buf, ret, addr, out_addrlen);
}

/* sendmsg on a bridged socket that carries an explicit destination address.
 *
 * The guest's descriptor is the AF_UNIX socketpair that stands in for the LKL
 * socket, and that pair is already connected. A sendmsg carrying the guest's
 * AF_INET sockaddr therefore fails with EINVAL and nothing is sent, which is
 * how test_socket's sendmsg clients failed while their servers waited for a
 * datagram that never left. The payload and the control data go into the LKL
 * socket instead, where the address means what the guest meant.
 */
static struct kbox_dispatch sendmsg_bridged(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long lkl_fd,
    const struct msghdr *smh)
{
    pid_t pid = kbox_syscall_request_pid(req);
    struct iovec iovs[64];
    struct iovec local[64];
    uint8_t buf[65536];
    uint8_t ctl[512];
    uint8_t addr[128];
    size_t niov = smh->msg_iovlen;
    size_t total = 0;
    struct msghdr out;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret;

    if (smh->msg_name == NULL || smh->msg_namelen == 0 ||
        smh->msg_namelen > sizeof(addr) || niov > 64)
        return kbox_dispatch_continue();
    if (guest_mem_read(ctx, pid, (uint64_t) (uintptr_t) smh->msg_iov, iovs,
                       niov * sizeof(iovs[0])) != 0)
        return kbox_dispatch_continue();
    if (guest_mem_read(ctx, pid, (uint64_t) (uintptr_t) smh->msg_name, addr,
                       smh->msg_namelen) != 0)
        return kbox_dispatch_continue();

    for (size_t v = 0; v < niov && total < sizeof(buf); v++) {
        size_t chunk = (size_t) iovs[v].iov_len;

        if (chunk > sizeof(buf) - total)
            chunk = sizeof(buf) - total;
        if (chunk > 0 && iovs[v].iov_base != NULL &&
            guest_mem_read(ctx, pid, (uint64_t) (uintptr_t) iovs[v].iov_base,
                           buf + total, chunk) != 0)
            return kbox_dispatch_continue();
        local[v].iov_base = buf + total;
        local[v].iov_len = chunk;
        total += chunk;
    }

    memset(&out, 0, sizeof(out));
    out.msg_name = addr;
    out.msg_namelen = smh->msg_namelen;
    out.msg_iov = local;
    out.msg_iovlen = niov;
    if (smh->msg_control && smh->msg_controllen > 0 &&
        smh->msg_controllen <= sizeof(ctl) &&
        guest_mem_read(ctx, pid, (uint64_t) (uintptr_t) smh->msg_control, ctl,
                       smh->msg_controllen) == 0) {
        out.msg_control = ctl;
        out.msg_controllen = smh->msg_controllen;
    }

    ret =
        lkl_syscall6(ctx->sysnrs->sendmsg, lkl_fd, (long) &out, flags, 0, 0, 0);
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr,
                "kbox: net: sendmsg bridged lkl=%ld iov=%zu total=%zu "
                "addrlen=%u ctl=%zu -> %ld\n",
                lkl_fd, niov, total, smh->msg_namelen, out.msg_controllen, ret);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    return kbox_dispatch_value(ret);
}

/* sendmsg: the guest sees uid/gid from LKL (root), while the process the host
 * kernel sees runs as an unprivileged user. An SCM_CREDENTIALS ucred built from
 * getuid()/getgid() is therefore refused with EPERM, which broke Chromium's
 * zygote hello and so every Chromium child process. Rewrite uid/gid to the
 * real ones in place and let the host kernel send. Only the process's own
 * credentials are written, so nothing can be forged through this.
 *
 * sendmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
struct kbox_dispatch forward_sendmsg(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);

    {
        long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
        struct kbox_fd_entry *entry = NULL;

        (void) resolve_lkl_socket_entry(ctx, fd, &entry);
        if (stream_socket_unconnected(entry))
            return kbox_dispatch_errno(ENOTCONN);

        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: sendmsg entry fd=%ld entry=%p sp=%d type=%d\n",
                    fd, (void *) entry, entry ? (int) entry->shadow_sp : -99,
                    entry ? entry->sock_type : -99);
        if (entry && entry->shadow_sp >= 0 && entry->sock_type == SOCK_DGRAM) {
            long lkl_fd = resolve_lkl_socket(ctx, fd);
            uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
            struct msghdr smh;

            if (lkl_fd >= 0 && msg_ptr != 0 &&
                guest_mem_read(ctx, pid, msg_ptr, &smh, sizeof(smh)) == 0) {
                if (smh.msg_name == NULL && !entry->sock_connected) {
                    /* Linux answers EDESTADDRREQ: an unconnected datagram
                     * socket with no destination has nowhere to send. The
                     * socketpair that stands in for it is always connected, so
                     * the host would happily accept the message. */
                    return kbox_dispatch_errno(EDESTADDRREQ);
                }
                if (smh.msg_name != NULL && smh.msg_namelen > 0) {
                    struct kbox_dispatch d =
                        sendmsg_bridged(req, ctx, lkl_fd, &smh);

                    if (d.kind != KBOX_DISPATCH_CONTINUE)
                        return d;
                }
            }
        }
    }
    {
        long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
        long lkl_fd = resolve_lkl_socket(ctx, fd);
        long sflags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
        if ((sflags & MSG_OOB) && lkl_fd >= 0)
            return shadow_sendmsg_oob(req, ctx, lkl_fd);
    }
    uint64_t msg_addr = kbox_syscall_request_arg(req, 1);
    struct msghdr mh;
    char ctl[512];

    if (guest_mem_read(ctx, pid, msg_addr, &mh, sizeof(mh)) != 0)
        return kbox_dispatch_continue();
    if (!mh.msg_control || mh.msg_controllen < sizeof(struct cmsghdr) ||
        mh.msg_controllen > sizeof(ctl))
        return kbox_dispatch_continue();
    if (guest_mem_read(ctx, pid, (uint64_t) (uintptr_t) mh.msg_control, ctl,
                       mh.msg_controllen) != 0)
        return kbox_dispatch_continue();

    /* Walk the control buffer as a copy: CMSG_NXTHDR on the guest's pointers
     * would dereference tracee memory. */
    size_t off = 0;
    while (off + sizeof(struct cmsghdr) <= mh.msg_controllen) {
        struct cmsghdr *c = (struct cmsghdr *) (ctl + off);
        if (c->cmsg_len < sizeof(struct cmsghdr) ||
            off + c->cmsg_len > mh.msg_controllen)
            break;
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS &&
            c->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
            struct ucred cred;
            memcpy(&cred, CMSG_DATA(c), sizeof(cred));
            cred.uid = geteuid();
            cred.gid = getegid();
            uint64_t dst = (uint64_t) (uintptr_t) mh.msg_control + off +
                           (uint64_t) ((char *) CMSG_DATA(c) - (char *) c);
            if (guest_mem_write(ctx, pid, dst, &cred, sizeof(cred)) != 0 &&
                ctx->verbose)
                fprintf(stderr, "kbox: sendmsg: ucred rewrite failed\n");
        }
        off += CMSG_ALIGN(c->cmsg_len);
    }
    return kbox_dispatch_continue();
}

/* Intercept for shadow sockets so that msg_name (source
 * address) is populated from the LKL socket, not the AF_UNIX socketpair.
 *
 * recvmsg(fd, msg, flags)
 *   args[0]=fd, args[1]=msg_ptr, args[2]=flags
 */
/* Guest-side msghdr, as the kernel lays it out for a 64-bit process. */
struct kbox_guest_msghdr {
    uint64_t msg_name;
    uint32_t msg_namelen;
    uint32_t __pad0;
    uint64_t msg_iov;
    uint64_t msg_iovlen;
    uint64_t msg_control;
    uint64_t msg_controllen;
    int msg_flags;
};

struct kbox_guest_iovec {
    uint64_t iov_base;
    uint64_t iov_len;
};

/* Copy the LKL control message into the tracee's msg_control buffer.
 *
 * This mirrors the kernel's put_cmsg(): a buffer too small for a cmsghdr gets
 * nothing and sets MSG_CTRUNC, a buffer smaller than the whole cmsg gets the
 * part that fits and sets MSG_CTRUNC, and the reported msg_controllen is the
 * distance the write cursor advanced -- that is what
 * test_socket's truncation cases compare against.
 */
static size_t put_cmsg_guest(struct kbox_supervisor_ctx *ctx,
                             pid_t pid,
                             uint64_t ctl_ptr,
                             size_t cap,
                             const uint8_t *ctl,
                             size_t ctllen,
                             int *trunc_out)
{
    size_t used = 0;
    size_t off = 0;

    if (trunc_out)
        *trunc_out = 0;

    /* Copy one cmsg at a time, with the kernel's own rules (put_cmsg() in
     * net/core/scm.c): a buffer without room for a whole cmsghdr gets nothing
     * and MSG_CTRUNC; a buffer with less room than the cmsg gets the part that
     * fits, written with a cmsg_len equal to that part, and MSG_CTRUNC. Both
     * the length in the header and the advance of the cursor must agree with
     * what was actually written, or the tracee's parser reports malformed
     * ancillary data.
     */
    while (off + sizeof(struct cmsghdr) <= ctllen) {
        const struct cmsghdr *c = (const struct cmsghdr *) (ctl + off);
        struct cmsghdr out;
        size_t payload;
        size_t cmlen;
        size_t adv;

        if (c->cmsg_len < sizeof(struct cmsghdr) || off + c->cmsg_len > ctllen)
            break;

        payload = (size_t) c->cmsg_len - sizeof(struct cmsghdr);
        cmlen = CMSG_LEN(payload);
        adv = CMSG_SPACE(payload);

        if (ctl_ptr == 0 || cap - used < sizeof(struct cmsghdr)) {
            if (trunc_out)
                *trunc_out = MSG_CTRUNC;
            break;
        }
        if (cap - used < cmlen) {
            if (trunc_out)
                *trunc_out = MSG_CTRUNC;
            cmlen = cap - used;
        }
        if (adv > cap - used)
            adv = cap - used;

        out.cmsg_len = cmlen;
        out.cmsg_level = c->cmsg_level;
        out.cmsg_type = c->cmsg_type;

        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: net: cmsg to guest level=%d type=%d payload=%zu "
                    "cap=%zu used=%zu len=%zu\n",
                    c->cmsg_level, c->cmsg_type, payload, cap, used, cmlen);
        if (guest_mem_write(ctx, pid, ctl_ptr + used, &out, sizeof(out)) < 0)
            break;
        if (cmlen > sizeof(out) &&
            guest_mem_write(ctx, pid, ctl_ptr + used + sizeof(out),
                            ctl + off + sizeof(out), cmlen - sizeof(out)) < 0)
            break;

        used += adv;
        off += CMSG_ALIGN(c->cmsg_len);
        if (cmlen < CMSG_LEN(payload))
            break;
    }
    return used;
}

/* Scatter a received datagram into the tracee and finish its msghdr. */
static struct kbox_dispatch finish_recvmsg(struct kbox_supervisor_ctx *ctx,
                                           pid_t pid,
                                           uint64_t msg_ptr,
                                           const struct kbox_guest_msghdr *mh,
                                           const struct kbox_guest_iovec *iovs,
                                           size_t niov,
                                           const uint8_t *buf,
                                           long ret,
                                           const uint8_t *addr,
                                           unsigned int out_addrlen,
                                           const uint8_t *ctl,
                                           size_t ctllen,
                                           int recv_flags)
{
    size_t written = 0;
    size_t ctl_used;
    uint64_t zero8 = 0;
    int msg_flags = recv_flags;
    int wrc;

    for (size_t v = 0; v < niov && written < (size_t) ret; v++) {
        size_t chunk = (size_t) ret - written;

        if (chunk > (size_t) iovs[v].iov_len)
            chunk = (size_t) iovs[v].iov_len;
        if (chunk > 0 && iovs[v].iov_base != 0) {
            wrc = guest_mem_write(ctx, pid, iovs[v].iov_base, buf + written,
                                  chunk);
            if (wrc < 0)
                return kbox_dispatch_errno(-wrc);
            written += chunk;
        }
    }

    /* Source address, then its length inside the msghdr. */
    if (out_addrlen > 0 && mh->msg_name != 0) {
        unsigned int write_len =
            out_addrlen < mh->msg_namelen ? out_addrlen : mh->msg_namelen;

        wrc = guest_mem_write(ctx, pid, mh->msg_name, addr, write_len);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    wrc = guest_mem_write(ctx, pid, msg_ptr + 8 /* msg_namelen */, &out_addrlen,
                          sizeof(out_addrlen));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    /* Ancillary data (IPV6_TCLASS, IPV6_HOPLIMIT, IP_TOS ...), with the
     * kernel's truncation rules. msg_controllen reports how far the cursor
     * advanced, and MSG_CTRUNC marks a buffer that could not hold it all.
     */
    ctl_used = 0;
    if (ctl && ctllen > 0) {
        ctl_used = put_cmsg_guest(ctx, pid, mh->msg_control,
                                  (size_t) mh->msg_controllen, ctl, ctllen,
                                  &msg_flags);
    } else if (mh->msg_control != 0 && mh->msg_controllen > 0) {
        /* Nothing to report: CMSG_FIRSTHDR() in the tracee must not parse
         * uninitialized bytes of its control buffer. */
        ctl_used = 0;
    }
    {
        uint64_t ctl_written = ctl_used;

        wrc = guest_mem_write(ctx, pid, msg_ptr + 40 /* msg_controllen */,
                              &ctl_written, sizeof(ctl_written));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    wrc = guest_mem_write(ctx, pid, msg_ptr + 48 /* msg_flags */, &msg_flags,
                          sizeof(msg_flags));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    (void) zero8;
    return kbox_dispatch_value(ret);
}

/* One attempt at a datagram recvmsg.
 *
 * The attempt never waits. Only the dispatch thread answers notifications for
 * this container, so a blocking wait here stops the guest's other threads --
 * including the thread that is about to send the datagram being waited for.
 * A blocking socket parks the notification instead (defer_pending_recvmsg) and
 * kbox_dispatch_poll_pending retries the receive.
 */
static struct kbox_dispatch recvmsg_attempt(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    struct kbox_fd_entry *entry,
    long lkl_fd,
    uint64_t msg_ptr,
    long flags)
{
    pid_t pid = kbox_syscall_request_pid(req);
    struct kbox_guest_msghdr mh;
    struct kbox_guest_iovec iovs[64];
    size_t niov;
    size_t total_cap = 0;
    uint8_t buf[65536];
    uint8_t addr[128];
    unsigned int addrlen;
    unsigned int out_addrlen;
    long ret;
    int rrc;

    rrc = guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    if (mh.msg_iovlen == 0)
        return kbox_dispatch_value(0);

    niov = (size_t) mh.msg_iovlen;
    if (niov > 64)
        niov = 64;
    rrc = guest_mem_read(ctx, pid, mh.msg_iov, iovs, niov * sizeof(iovs[0]));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);
    for (size_t v = 0; v < niov; v++) {
        if (iovs[v].iov_len > 65536 - total_cap)
            total_cap = 65536;
        else
            total_cap += (size_t) iovs[v].iov_len;
    }

    addrlen = mh.msg_namelen < sizeof(addr) ? mh.msg_namelen
                                            : (unsigned int) sizeof(addr);
    out_addrlen = addrlen;

    /* Capture the ancillary data LKL produced. The guest's buffer can be
     * larger than this; IP cmsgs are a few bytes each, and msg_controllen is
     * still honoured from the guest's own capacity. */
    int recv_flags = 0;

    /* Ancillary data is only produced for datagram sockets here: the bridge
     * carries it in the per-datagram metadata queue, and a stream socket has no
     * such record. Asking LKL for control data on a stream socket returned
     * unrelated options and put a cmsg in a recvmsg that expects none. */
    if (mh.msg_control != 0 && mh.msg_controllen > 0 && entry &&
        entry->sock_type == SOCK_DGRAM) {
        uint8_t ctl[256];
        size_t ctllen = mh.msg_controllen < sizeof(ctl)
                            ? (size_t) mh.msg_controllen
                            : sizeof(ctl);

        ret = shadow_or_lkl_recvfrom(
            ctx, entry, lkl_fd, buf, total_cap, flags | 0x40 /* MSG_DONTWAIT */,
            addr, &out_addrlen, ctl, &ctllen, sizeof(ctl), &recv_flags);
        if (ret < 0)
            return kbox_dispatch_from_lkl(ret);
        return finish_recvmsg(ctx, pid, msg_ptr, &mh, iovs, niov, buf, ret,
                              addr, out_addrlen, ctl, ctllen, recv_flags);
    }

    ret = shadow_or_lkl_recvfrom(ctx, entry, lkl_fd, buf, total_cap,
                                 flags | 0x40 /* MSG_DONTWAIT */, addr,
                                 &out_addrlen, NULL, NULL, 0, &recv_flags);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    return finish_recvmsg(ctx, pid, msg_ptr, &mh, iovs, niov, buf, ret, addr,
                          out_addrlen, NULL, 0, recv_flags);
}

/* Park a blocking recvmsg until its datagram arrives. */
static struct kbox_dispatch defer_pending_recvmsg(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long fd,
    uint64_t msg_ptr,
    long flags,
    long lkl_fd)
{
    long deadline_ms = -1;

    if (lkl_fd >= 0) {
        struct timeval rtv = {0, 0};
        unsigned int rtvlen = sizeof(rtv);

        if (kbox_lkl_getsockopt(ctx->sysnrs, lkl_fd, SOL_SOCKET, SO_RCVTIMEO,
                                &rtv, &rtvlen) == 0 &&
            (rtv.tv_sec > 0 || rtv.tv_usec > 0)) {
            struct timespec now;

            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline_ms = (now.tv_sec + rtv.tv_sec) * 1000L +
                          (now.tv_nsec / 1000000L) +
                          ((rtv.tv_usec + 999L) / 1000L);
        }
    }

    for (size_t i = 0; i < KBOX_PENDING_RECVMSGS_MAX; i++) {
        struct kbox_pending_recvmsg *pm = &ctx->pending_recvmsgs[i];

        if (pm->active)
            continue;
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr, "kbox: net: recvmsg deferred slot=%zu fd=%ld\n", i,
                    fd);
        pm->active = 1;
        pm->req = *req;
        pm->fd = fd;
        pm->msg_ptr = msg_ptr;
        pm->flags = flags;
        pm->deadline_ms = deadline_ms;
        ctx->pending_recvmsg_count++;
        return (struct kbox_dispatch) {.kind = KBOX_DISPATCH_DEFERRED};
    }
    return kbox_dispatch_errno(EAGAIN);
}

/* Complete parked recvmsg calls once their datagrams have arrived. */
static void poll_pending_recvmsgs(struct kbox_supervisor_ctx *ctx)
{
    for (size_t i = 0; i < KBOX_PENDING_RECVMSGS_MAX; i++) {
        struct kbox_pending_recvmsg *pm = &ctx->pending_recvmsgs[i];
        struct kbox_syscall_request saved;
        struct kbox_fd_entry *entry = NULL;
        struct kbox_dispatch d;
        long lkl_fd;
        uint64_t id;

        if (!pm->active)
            continue;

        saved = pm->req;
        id = kbox_syscall_request_cookie(&saved);
        if (ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
            0) {
            pm->active = 0;
            ctx->pending_recvmsg_count--;
            continue;
        }

        kbox_dispatch_prepare_request_ctx(ctx, &saved);

        lkl_fd = resolve_lkl_socket_entry(ctx, pm->fd, &entry);
        if (lkl_fd < 0) {
            pm->active = 0;
            ctx->pending_recvmsg_count--;
            d = kbox_dispatch_errno(EBADF);
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        d = recvmsg_attempt(ctx, &saved, entry, lkl_fd, pm->msg_ptr, pm->flags);
        if (d.kind == KBOX_DISPATCH_RETURN && d.error == EAGAIN) {
            if (pm->deadline_ms >= 0) {
                struct timespec now;
                long now_ms;

                clock_gettime(CLOCK_MONOTONIC, &now);
                now_ms = now.tv_sec * 1000L + now.tv_nsec / 1000000L;
                if (now_ms >= pm->deadline_ms) {
                    pm->active = 0;
                    ctx->pending_recvmsg_count--;
                    d = kbox_dispatch_errno(EAGAIN);
                    kbox_notify_respond(ctx->listener_fd, id, &d);
                }
            }
            continue;
        }

        pm->active = 0;
        ctx->pending_recvmsg_count--;
        kbox_notify_respond(ctx->listener_fd, id, &d);
    }
}

struct kbox_dispatch forward_recvmsg(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    struct kbox_fd_entry *entry = NULL;
    long lkl_fd = resolve_lkl_socket_entry(ctx, fd, &entry);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t msg_ptr = kbox_syscall_request_arg(req, 1);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (stream_socket_unconnected(entry))
        return kbox_dispatch_errno(ENOTCONN);
    if (msg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);

    struct kbox_guest_msghdr mh;
    int rrc = guest_mem_read(ctx, pid, msg_ptr, &mh, sizeof(mh));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    /* No msg_name: for connected stream sockets, CONTINUE via socketpair. */
    if (mh.msg_name == 0 || mh.msg_namelen == 0)
        return kbox_dispatch_continue();

    int fl = (entry && entry->shadow_sp >= 0) ? fcntl(entry->shadow_sp, F_GETFL)
                                              : -1;
    int is_nb =
        (flags & MSG_DONTWAIT) != 0 || (fl >= 0 && (fl & O_NONBLOCK) != 0);

    struct kbox_dispatch d =
        recvmsg_attempt(ctx, req, entry, lkl_fd, msg_ptr, flags);
    if (d.kind == KBOX_DISPATCH_RETURN && d.error == EAGAIN && !is_nb)
        return defer_pending_recvmsg(req, ctx, fd, msg_ptr, flags, lkl_fd);
    return d;
}
