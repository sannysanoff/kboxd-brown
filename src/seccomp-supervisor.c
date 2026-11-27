/* SPDX-License-Identifier: MIT */
/* seccomp-supervisor.c - Fork, install seccomp, exec, supervise.
 *
 * The supervisor creates a socketpair, forks a child process, installs
 * a seccomp-unotify BPF filter in the child, sends the listener FD
 * back over the socketpair, and then execs the target command.  The
 * parent sits in a poll loop receiving intercepted syscalls, forwarding
 * them to LKL, and sending responses back.
 *
 */

#include <dirent.h>
#include <errno.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "fd-table.h"
#include "lkl-wrap.h"
#include "net.h"
#include "seccomp.h"
#include "syscall-nr.h"
#ifdef KBOX_HAS_WEB
#include "web.h"
#endif

/* Notification types (kbox_seccomp_notif etc.) are provided by
 * seccomp-defs.h via seccomp.h.
 */

/* SCM_RIGHTS helpers. */

/* Create a UNIX socketpair.
 * On success fds[0] and fds[1] are filled; returns 0.
 * On failure returns -1 with a message on stderr.
 */
static int socketpair_create(int fds[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* Send a single file descriptor over a UNIX socket using SCM_RIGHTS.
 */
int kbox_supervisor_send_fd(int sock, int fd)
{
    char buf = 0;
    struct iovec iov = {
        .iov_base = &buf,
        .iov_len = 1,
    };

    /* Ancillary data buffer.  CMSG_SPACE gives the padded size
     * needed to carry one int.
     */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg;
    struct cmsghdr *cmsg;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    {
        ssize_t sret;
        do {
            sret = sendmsg(sock, &msg, (int) KBOX_SENDMSG_HANDSHAKE_FLAG);
        } while (sret < 0 && errno == EINTR);
        if (sret < 0) {
            fprintf(stderr, "sendmsg(SCM_RIGHTS): %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

/* Receive a single file descriptor from a UNIX socket via SCM_RIGHTS.
 * Returns the received FD on success, -1 on error.
 */
int kbox_supervisor_recv_fd(int sock)
{
    char buf;
    struct iovec iov = {
        .iov_base = &buf,
        .iov_len = 1,
    };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    struct msghdr msg;
    struct cmsghdr *cmsg;
    ssize_t n;
    int fd;

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    do {
        n = recvmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        fprintf(stderr, "recvmsg(SCM_RIGHTS): %s\n", strerror(errno));
        return -1;
    }
    if (n == 0) {
        fprintf(stderr, "recvmsg: peer closed socket before sending fd\n");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) {
        fprintf(stderr, "recvmsg: missing cmsg header\n");
        return -1;
    }
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "recvmsg: unexpected cmsg type\n");
        return -1;
    }
    if (cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        fprintf(stderr, "recvmsg: short cmsg payload\n");
        return -1;
    }

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/* Build a seccomp_notif_resp from a dispatch result. */

/* KBOX_NOTIF_FLAG_CONTINUE from seccomp-defs.h */

static void build_response(struct kbox_seccomp_notif_resp *resp,
                           uint64_t id,
                           const struct kbox_dispatch *d)
{
    memset(resp, 0, sizeof(*resp));
    resp->id = id;

    switch (d->kind) {
    case KBOX_DISPATCH_CONTINUE:
        resp->flags = KBOX_NOTIF_FLAG_CONTINUE;
        resp->val = 0;
        resp->error = 0;
        break;
    case KBOX_DISPATCH_RETURN:
        resp->flags = 0;
        resp->val = d->val;
        /* seccomp_notif_resp.error is a negative errno value.
         * The kernel negates it to produce the tracee's errno:
         *   error = -ENOENT (-2)  =>  tracee errno = 2 (ENOENT)
         * kbox_dispatch_errno stores positive values, so negate here.
         */
        resp->error = d->error ? -d->error : 0;
        break;
    case KBOX_DISPATCH_DEFERRED:
        break;
    }
}

/* Child wait helper. */

/* Check child status via non-blocking waitpid.
 * Returns:
 *   1  if child exited; *exit_code is filled with the exit status.
 *   0  if child is still running.
 *  -1  on waitpid failure.
 */
static int check_child(pid_t pid, int *exit_code)
{
    int status = 0;
    pid_t w;

    w = waitpid(pid, &status, WNOHANG);
    if (w < 0)
        return -1;
    if (w == 0)
        return 0;

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
        return 1;
    }
    if (WIFSIGNALED(status)) {
        *exit_code = 128 + WTERMSIG(status);
        return 1;
    }
    return 0;
}

static int check_ctx_child(struct kbox_supervisor_ctx *ctx, int *exit_code)
{
    if (ctx->exit_notify_fd >= 0 && ctx->exit_status_ptr) {
        int st = __atomic_load_n(ctx->exit_status_ptr, __ATOMIC_ACQUIRE);
        if (st >= 0) {
            *exit_code = st;
            return 1;
        }
        return 0;
    }
    return check_child(ctx->child_pid, exit_code);
}

/* Supervisor loop. */

/* Sit in a poll loop on two FDs:
 *   - listener_fd: seccomp notifications from the child.
 *   - wait_fd:     signalfd for SIGCHLD, or caller-provided exit_notify_fd.
 *
 * On SIGCHLD/exit_notify_fd or POLLHUP, recheck child exit status.
 * On POLLIN for the listener, receive notification, dispatch, respond.
 *
 * When exit_notify_fd < 0, SIGCHLD must already be blocked by the caller
 * before fork() so the signal cannot be lost between fork and signalfd.
 *
 * Returns the child exit code, or -1 on fatal error.
 */
/* Defined below the loop: see "Stuck-syscall reporter". */
struct kbox_slow_slot;
static struct kbox_slow_slot *slow_begin(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req);
static void slow_end(struct kbox_slow_slot *slot);
static void kbox_dump_handler(int sig);

static int supervise_loop(struct kbox_supervisor_ctx *ctx)
{
    struct kbox_seccomp_notif notif;
    struct kbox_seccomp_notif_resp resp;

    signal(SIGUSR1, kbox_dump_handler);
    struct kbox_syscall_request req;
    struct kbox_dispatch d;
    struct pollfd pfds[2];
    int exit_code = -1;
    int ret;
    int sigchld_fd = -1;
    int wait_fd;
    int poll_timeout;

    if (ctx->exit_notify_fd >= 0) {
        wait_fd = ctx->exit_notify_fd;
    } else {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigchld_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (sigchld_fd < 0) {
            fprintf(stderr, "signalfd: %s\n", strerror(errno));
            return -1;
        }
        wait_fd = sigchld_fd;
    }

    for (;;) {
        if (ctx->pending_accept_count > 0 || ctx->pending_recv_count > 0 ||
            ctx->pending_recvmsg_count > 0 ||
            ctx->pending_fifo_open_count > 0 ||
            ctx->pending_connect_poll_count > 0)
            kbox_dispatch_poll_pending(ctx);
        kbox_sweep_stale_bridged_sockets_periodic(ctx, ctx->child_pid);

        poll_timeout =
            ctx->pending_connect_poll_count > 0
                ? 5
                : ((ctx->pending_accept_count > 0 ||
                    ctx->pending_recv_count > 0 ||
                    ctx->pending_recvmsg_count > 0 ||
                    ctx->pending_fifo_open_count > 0)
                       ? 10
                       : (kbox_has_active_bridged_sockets(ctx) ? 15 : -1));
#ifdef KBOX_HAS_WEB
        if (ctx->web && (poll_timeout < 0 || poll_timeout > 100))
            poll_timeout = 100;
#endif

        /* Poll for seccomp notifications and child exit simultaneously.
         * In the normal non-web steady state we block here instead of
         * doing a non-blocking waitpid() on every iteration; that extra
         * wait syscall shows up directly in the seccomp fast path on
         * syscall-heavy workloads.
         */
        pfds[0].fd = ctx->listener_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = wait_fd;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        ret = poll(pfds, 2, poll_timeout);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "poll(listener): %s\n", strerror(errno));
            goto out;
        }
        if (ret == 0) {
#ifdef KBOX_HAS_WEB
            /* Timer-driven telemetry sampling on poll timeout. */
            if (ctx->web) {
                kbox_web_set_fd_used(ctx->web,
                                     kbox_fd_table_count(ctx->fd_table));
                kbox_web_tick(ctx->web);
            }
#endif
            continue;
        }

        /* Child exit wakeup: drain wait_fd and check child status. */
        if (pfds[1].revents & POLLIN) {
            if (sigchld_fd >= 0) {
                struct signalfd_siginfo si;
                while (read(sigchld_fd, &si, sizeof(si)) > 0)
                    ;
            } else {
                uint64_t val;
                while (read(wait_fd, &val, sizeof(val)) > 0)
                    ;
            }
            ret = check_ctx_child(ctx, &exit_code);
            if (ret < 0) {
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
                goto out;
            }
            if (ret == 1)
                goto out;
        }

        /* POLLHUP / POLLERR on listener => recheck child. */
        if (pfds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            ret = check_ctx_child(ctx, &exit_code);
            if (ret < 0) {
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
                goto out;
            }
            if (ret == 1)
                goto out;
            continue;
        }

        /* No data on listener FD. */
        if (!(pfds[0].revents & POLLIN))
            continue;

        /* Receive notification. */
        ret = kbox_notify_recv(ctx->listener_fd, &notif);
        if (ret < 0) {
            int e = -ret;
            if (e == EINTR || e == EAGAIN || e == ENOENT) {
#ifdef KBOX_HAS_WEB
                if (e == ENOENT && ctx->web)
                    kbox_web_counters(ctx->web)->recv_enoent++;
#endif
                if (e == ENOENT) {
                    ret = check_ctx_child(ctx, &exit_code);
                    if (ret < 0) {
                        fprintf(stderr, "waitpid: %s\n", strerror(errno));
                        goto out;
                    }
                    if (ret == 1)
                        goto out;
                }
                continue;
            }
            fprintf(stderr, "kbox_notify_recv: %s\n", strerror(e));
            goto out;
        }

        /* Dispatch to LKL (with optional latency measurement). */
#ifdef KBOX_HAS_WEB
        uint64_t t_dispatch_start = 0;
        if (ctx->web)
            t_dispatch_start = kbox_clock_ns();
#endif
        if (kbox_syscall_request_from_notif(&notif, &req) < 0) {
            fprintf(stderr, "kbox: failed to decode seccomp notification\n");
            goto out;
        }

        /* One-time scan: register every FD the child inherited from the
         * parent environment as SHADOW_ONLY.  Without this, FDs beyond
         * stdio (e.g. fd 3 from a logging daemon, fd 255 from bash)
         * would hit the EBADF policy.  Runs while the tracee is blocked
         * in USER_NOTIF so no race with the child's own FD operations.
         */
        if (!ctx->inherited_fds_tracked) {
            char fd_dir_path[64];
            DIR *fd_dir;
            struct dirent *de;

            snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd",
                     (int) ctx->child_pid);
            fd_dir = opendir(fd_dir_path);
            if (fd_dir) {
                while ((de = readdir(fd_dir)) != NULL) {
                    char *endp;
                    long ifd;

                    if (de->d_name[0] == '.')
                        continue;
                    errno = 0;
                    ifd = strtol(de->d_name, &endp, 10);
                    if (errno || *endp != '\0' || ifd < 0)
                        continue;
                    if (kbox_fd_table_get_lkl(ctx->fd_table, ifd) != -1)
                        continue;
                    kbox_fd_table_insert_at(ctx->fd_table, ifd,
                                            KBOX_LKL_FD_SHADOW_ONLY, 0);
                }
                closedir(fd_dir);
            }
            ctx->inherited_fds_tracked = 1;
        }

        struct kbox_slow_slot *slow = slow_begin(ctx, &req);
        d = kbox_dispatch_request(ctx, &req);
        slow_end(slow);

        if (d.kind == KBOX_DISPATCH_DEFERRED)
            continue;

        /* Build and send response. */
        build_response(&resp, notif.id, &d);
        ret = kbox_notify_send(ctx->listener_fd, &resp);

#ifdef KBOX_HAS_WEB
        /* Record telemetry after send (includes full round-trip). */
        if (ctx->web) {
            uint64_t latency = kbox_clock_ns() - t_dispatch_start;

            enum kbox_disposition disp;
            if (d.kind == KBOX_DISPATCH_CONTINUE)
                disp = KBOX_DISP_CONTINUE;
            else if (d.error == ENOSYS)
                disp = KBOX_DISP_ENOSYS;
            else
                disp = KBOX_DISP_RETURN;

            const char *sname = syscall_name_from_nr(ctx->host_nrs, req.nr);

            kbox_web_record_syscall(ctx->web, (uint32_t) req.pid, req.nr, sname,
                                    req.args, disp, d.val, d.error, latency);
        }
#endif

        if (ret < 0) {
            int e = -ret;
            /* ENOENT: tracee died between recv and send.
             * EBADF: notification ID invalidated (thread exit
             *        in a multi-threaded guest).
             * Both are harmless; loop around, waitpid picks
             * up the exit.
             */
            if (e == ENOENT || e == EBADF) {
                static int reported;
                if (reported < 20) {
                    reported++;
                    const char *sname =
                        syscall_name_from_nr(ctx->host_nrs, req.nr);
                    fprintf(stderr, "kbox: answer lost pid=%u nr=%d (%s): %s\n",
                            (unsigned int) req.pid, (int) req.nr,
                            sname ? sname : "unknown", strerror(e));
                }
#ifdef KBOX_HAS_WEB
                if (e == ENOENT && ctx->web)
                    kbox_web_counters(ctx->web)->send_enoent++;
#endif
                ret = check_ctx_child(ctx, &exit_code);
                if (ret < 0) {
                    fprintf(stderr, "waitpid: %s\n", strerror(errno));
                    goto out;
                }
                if (ret == 1)
                    goto out;
                continue;
            }
            fprintf(stderr, "kbox_notify_send: %s\n", strerror(e));
            goto out;
        }
    }

out:
    /* Cancel any helper thread still blocked in a FIFO open before removing
     * the container's FIFO twin directory. */
    kbox_cancel_pending_fifo_opens(ctx);
    /* The container's init has exited, so no guest can open a FIFO of this
     * container again. Removing its twin directory keeps the supervisor's
     * tmpfs bounded across container lifetimes. */
    fifo_twin_cleanup(ctx->child_pid);
    if (sigchld_fd >= 0)
        close(sigchld_fd);
    return exit_code;
}

/* Stuck-syscall reporter.
 *
 * A guest that never advances looks the same whether its own syscall blocks or
 * the supervisor is stuck inside an LKL call that never returns; from outside
 * the process both show up as a thread in futex_wait. When the pod run of
 * test_ssl froze, the stack of the guest named bind(), the supervisor showed no
 * spinning thread, and nothing said which LKL call the supervisor had entered.
 *
 * Each supervised dispatch marks its request here. A reporter thread names any
 * request that has been running for longer than a few seconds, and names it
 * again when it finally returns, so a stuck engine is visible without turning
 * on per-syscall verbose output.
 */
#define KBOX_SLOW_SLOTS 16
#define KBOX_SLOW_SECONDS 5

struct kbox_slow_slot {
    int busy;
    long nr;
    const char *name;
    pid_t pid;
    uint64_t start_ns;
    int reported;
};

static pthread_mutex_t g_slow_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_slow_cond = PTHREAD_COND_INITIALIZER;
static struct kbox_slow_slot g_slow[KBOX_SLOW_SLOTS];
static int g_slow_started;

/* A guest that waits for a socket that never becomes readable leaves the pump
 * ticking and nothing in the log. SIGUSR1 asks for the bridge state, printed by
 * the reporter thread so no LKL call happens inside a signal handler.
 */
static volatile sig_atomic_t g_dump_requested;

static void kbox_dump_handler(int sig)
{
    (void) sig;
    g_dump_requested = 1;
}

static uint64_t slow_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static void *kbox_slow_main(void *arg)
{
    (void) arg;
    int pump_reported = 0;

    for (;;) {
        struct timespec wake;

        clock_gettime(CLOCK_REALTIME, &wake);
        wake.tv_sec += 1;

        pthread_mutex_lock(&g_slow_lock);
        (void) pthread_cond_timedwait(&g_slow_cond, &g_slow_lock, &wake);

        uint64_t now = slow_now_ns();
        for (int i = 0; i < KBOX_SLOW_SLOTS; i++) {
            struct kbox_slow_slot *slot = &g_slow[i];

            if (!slot->busy || slot->reported)
                continue;
            if (now - slot->start_ns <
                (uint64_t) KBOX_SLOW_SECONDS * 1000000000ull)
                continue;
            slot->reported = 1;
            /* format-ok: a literal, split only because the call
             * does not fit on one line. */
            fprintf(/* format-ok */
                    stderr,
                    "kbox: syscall pid=%d nr=%ld (%s) not returned "
                    "after %llus; the guest waits\n",
                    (int) slot->pid, slot->nr,
                    slot->name ? slot->name : "unknown",
                    (unsigned long long) ((now - slot->start_ns) /
                                          1000000000ull));
        }
        pthread_mutex_unlock(&g_slow_lock);

        /* A guest that spins on a poll that keeps reporting ready looks exactly
         * like a busy program. The pump behind those descriptors is a single
         * thread holding the bridge lock; when it stops, every container's
         * sockets stop with it and nothing else in the log says so. Report the
         * step it is stuck in, once per stall: the flag clears as soon as the
         * pump moves again.
         */
        {
            int stage = 0;
            int pslot = -1;
            uint64_t age_ms = kbox_net_pump_stage_age_ms(&stage, &pslot);

            if (age_ms >= 2000) {
                if (!pump_reported) {
                    pump_reported = 1;
                    fprintf(stderr,
                            "kbox: net: pump stuck in stage=%d slot=%d for "
                            "%llums\n",
                            stage, pslot, (unsigned long long) age_ms);
                }
            } else if (age_ms == 0 && pump_reported) {
                pump_reported = 0;
            }
        }

        /* LKL runs every Linux syscall under one CPU lock. A single call that
         * never returns freezes all file and socket work, for every container,
         * and the guest's only symptom is a syscall without an answer. */
        kbox_lkl_report_stalls(2000);

        if (g_dump_requested) {
            g_dump_requested = 0;
            kbox_net_dump_state();
        }
    }
    return NULL;
}

static struct kbox_slow_slot *slow_begin(struct kbox_supervisor_ctx *ctx,
                                         const struct kbox_syscall_request *req)
{
    struct kbox_slow_slot *slot = NULL;

    pthread_mutex_lock(&g_slow_lock);
    if (!g_slow_started) {
        pthread_t thread;
        pthread_attr_t attr;

        if (pthread_attr_init(&attr) == 0) {
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if (pthread_create(&thread, &attr, kbox_slow_main, NULL) == 0)
                g_slow_started = 1;
            pthread_attr_destroy(&attr);
        }
    }
    for (int i = 0; i < KBOX_SLOW_SLOTS; i++) {
        if (g_slow[i].busy)
            continue;
        slot = &g_slow[i];
        slot->busy = 1;
        slot->nr = (long) req->nr;
        slot->name = syscall_name_from_nr(ctx->host_nrs, req->nr);
        slot->pid = kbox_syscall_request_pid(req);
        slot->start_ns = slow_now_ns();
        slot->reported = 0;
        break;
    }
    pthread_mutex_unlock(&g_slow_lock);
    return slot;
}

static void slow_end(struct kbox_slow_slot *slot)
{
    if (!slot)
        return;
    pthread_mutex_lock(&g_slow_lock);
    if (slot->reported) {
        uint64_t ns = slow_now_ns() - slot->start_ns;

        fprintf(stderr,
                "kbox: syscall pid=%d nr=%ld (%s) returned after %llus\n",
                (int) slot->pid, slot->nr, slot->name ? slot->name : "unknown",
                (unsigned long long) (ns / 1000000000ull));
    }
    slot->busy = 0;
    slot->reported = 0;
    pthread_mutex_unlock(&g_slow_lock);
}

int kbox_supervise_ctx(struct kbox_supervisor_ctx *ctx)
{
    return supervise_loop(ctx);
}

int kbox_supervisor_prepare_child_security(void)
{
    struct rlimit rl = {65536, 65536};
    struct rlimit rtlim = {0, 0};
    struct rlimit rclim = {0, 0};

    setrlimit(RLIMIT_NOFILE, &rl);
    setrlimit(RLIMIT_RTPRIO, &rtlim);
    /* A crashed guest would otherwise dump a core into the supervisor's
     * working directory (the host project tree); ClickHouse dumps are tens
     * of gigabytes because of its thread count and address space.
     */
    setrlimit(RLIMIT_CORE, &rclim);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS): %s\n", strerror(errno));
        return -1;
    }

    prctl(47 /* PR_CAP_AMBIENT */, 4 /* PR_CAP_AMBIENT_CLEAR_ALL */, 0, 0, 0);
    for (int cap = 0; cap <= 63; cap++)
        prctl(24 /* PR_CAPBSET_DROP */, cap, 0, 0, 0);
    return 0;
}

/* Public entry point. */

int kbox_run_supervisor_volumes(const struct kbox_sysnrs *sysnrs,
                                const char *command,
                                const char *const *args,
                                int nargs,
                                const char *host_root,
                                int exec_memfd,
                                int verbose,
                                int root_identity,
                                int normalize,
                                struct kbox_web_ctx *web,
                                const struct kbox_host_bind *host_binds,
                                size_t host_bind_count)
{
    int sp[2]; /* socketpair */
    pid_t pid;
    int listener_fd;
    int exit_code;
    int status;
    /* The FD table holds KBOX_FD_TABLE_MAX entries (8.9 MiB) and the
     * context adds 0.4 MiB. As locals they overflowed
     * the 8 MiB stack at -O2, where the caller's frame is still on the stack,
     * and the supervisor died with SIGSEGV before its first statement. They
     * live for the whole process, so they belong on the heap. */
    struct kbox_fd_table *fd_table;
    struct kbox_supervisor_ctx *ctx;
    sigset_t old_mask;

    /* Architecture-specific host syscall numbers for the BPF filter. */
#if defined(__x86_64__)
    const struct kbox_host_nrs *host_nrs = &HOST_NRS_X86_64;
#elif defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
    const struct kbox_host_nrs *host_nrs = &HOST_NRS_GENERIC;
#else
#error "Unsupported architecture"
#endif

    /* 1. Create socketpair for passing the listener FD. */
    if (socketpair_create(sp) < 0)
        return -1;

    /* Save the caller's mask so both parent and child can
     * restore it later.
     */
    {
        if (sigprocmask(SIG_SETMASK, NULL, &old_mask) < 0) {
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
            close(sp[0]);
            close(sp[1]);
            return -1;
        }
    }

    /* 2. Fork. */
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        close(sp[0]);
        close(sp[1]);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child process. */
        close(sp[0]);

        if (kbox_supervisor_prepare_child_security() < 0)
            _exit(127);

        /* 3b. Install BPF filter, get listener FD. */
        listener_fd = kbox_install_seccomp_listener(host_nrs);
        if (listener_fd < 0) {
            fprintf(stderr, "kbox_install_seccomp_listener failed\n");
            _exit(127);
        }

        /* 3c. Send listener FD to parent via SCM_RIGHTS.
         * sendmsg is in the BPF allow list so this bypasses seccomp. */
        if (kbox_supervisor_send_fd(sp[1], listener_fd) < 0)
            _exit(127);

        /* 3d. Close socket and listener; parent owns them now. */
        close(sp[1]);
        close(listener_fd);

        /* 3e. Restore the inherited signal mask before exec, minus SIGCHLD.
         *
         * LKL blocks SIGCHLD for the whole process before booting its kernel
         * threads, so old_mask already has it blocked. Restoring that mask
         * verbatim gives the guest a SIGCHLD it can never receive: every child
         * it reaps leaves SIGCHLD pending forever, and signal.sigpending()
         * reports a signal that no guest code ever raised. The child has not
         * inherited any LKL kernel threads, so it has no reason to block it.
         */
        {
            sigset_t exec_mask = old_mask;
            sigdelset(&exec_mask, SIGCHLD);
            if (sigprocmask(SIG_SETMASK, &exec_mask, NULL) < 0) {
                fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n",
                        strerror(errno));
                _exit(127);
            }
        }

        /* 3f. Build argv and exec.
         *
         * argv[0] = command, then args[0..nargs], then NULL.
         *
         * If exec_memfd >= 0 (image mode), use fexecve to exec
         * the memfd directly.  This allows running binaries from
         * the LKL filesystem without them existing on the host.
         */
        {
            const char **argv;
            int i;

            argv = malloc((size_t) (nargs + 2) * sizeof(char *));
            if (!argv)
                _exit(127);

            argv[0] = command;
            for (i = 0; i < nargs; i++)
                argv[i + 1] = args[i];
            argv[nargs + 1] = NULL;

            if (exec_memfd >= 0)
                fexecve(exec_memfd, (char *const *) argv, environ);
            else
                execv(command, (char *const *) argv);

            /* exec only returns on failure. */
            fprintf(stderr, "exec(%s): %s\n", command, strerror(errno));
            free(argv);
        }
        _exit(127);
    }

    /* Parent process. */
    close(sp[1]);

    /* 4a. Receive listener FD from child. */
    listener_fd = kbox_supervisor_recv_fd(sp[0]);
    close(sp[0]);

    if (listener_fd < 0) {
        /* Child probably died.  Reap and report. */
        pid_t w;
        status = 0;
        w = waitpid(pid, &status, WNOHANG);
        if (w == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
        fprintf(stderr, "failed to receive seccomp listener fd\n");
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
            fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));
        return -1;
    }

    fd_table = calloc(1, sizeof(*fd_table));
    ctx = calloc(1, sizeof(*ctx));
    if (!fd_table || !ctx) {
        fprintf(stderr, "kbox: supervisor: out of memory\n");
        free(fd_table);
        free(ctx);
        return -1;
    }

    /* 4b. Set up supervisor context. */
    kbox_fd_table_init(fd_table);

    /* Register stdio (0, 1, 2) as host-passthrough FDs so the EBADF policy
     * for untracked FDs does not block inherited terminal/pipe I/O.
     */
    for (int i = 0; i < 3; i++)
        kbox_fd_table_insert_at(fd_table, i, KBOX_LKL_FD_SHADOW_ONLY, 0);

    /* calloc() already cleared both. */
    ctx->sysnrs = sysnrs;
    ctx->host_nrs = host_nrs;
    ctx->fd_table = fd_table;
    ctx->listener_fd = listener_fd;
    ctx->proc_self_fd_dirfd = -1;
    ctx->close_inotify_fd = -1;
    ctx->proc_mem_fd = -1;
    ctx->child_pid = pid;
    ctx->host_root = host_root;
    ctx->verbose = verbose;
    ctx->root_identity = root_identity;
    ctx->override_uid = (uid_t) -1;
    ctx->override_gid = (gid_t) -1;
    ctx->guest_umask = 022;
    ctx->lkl_umask_cur = 022;
    ctx->normalize = normalize;
    ctx->guest_mem_ops = &kbox_process_vm_guest_mem_ops;
    ctx->fd_inject_ops = NULL;
    ctx->web = web;
    ctx->host_binds = host_binds;
    ctx->host_bind_count = host_bind_count;
    ctx->exit_notify_fd = -1;
    ctx->exit_status_ptr = NULL;

    /* 4c. Enter supervisor loop. */
    exit_code = supervise_loop(ctx);
    kbox_dispatch_cleanup_proc_fds(ctx);

    /* Restore the caller's signal mask now that the signalfd is closed. */
    if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
        fprintf(stderr, "sigprocmask(SIG_SETMASK): %s\n", strerror(errno));

    if (ctx->proc_mem_fd >= 0)
        close(ctx->proc_mem_fd);
    if (ctx->proc_self_fd_dirfd >= 0)
        close(ctx->proc_self_fd_dirfd);
    if (ctx->close_inotify_fd >= 0)
        close(ctx->close_inotify_fd);
    free(ctx->close_watches);
    ctx->close_watches = NULL;
    ctx->close_watch_count = 0;
    ctx->close_watch_cap = 0;
    close(listener_fd);

    if (exit_code < 0) {
        if (kill(pid, SIGKILL) < 0 && errno != ESRCH)
            fprintf(stderr, "kill(%d): %s\n", (int) pid, strerror(errno));
        while (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            if (errno != ECHILD)
                fprintf(stderr, "waitpid: %s\n", strerror(errno));
            break;
        }
        free(fd_table);
        free(ctx);
        return -1;
    }
    if (exit_code != 0) {
        fprintf(stderr, "child exited with status %d\n", exit_code);
        free(fd_table);
        free(ctx);
        return -1;
    }
    free(fd_table);
    free(ctx);
    return 0;
}

int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web)
{
    return kbox_run_supervisor_volumes(sysnrs, command, args, nargs, host_root,
                                       exec_memfd, verbose, root_identity,
                                       normalize, web, NULL, 0);
}
