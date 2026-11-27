/* SPDX-License-Identifier: MIT */

/* Miscellaneous syscall handlers for the seccomp dispatch engine.
 *
 * Time queries, pipe creation, uname, getrandom, prctl, extended I/O
 * (pwrite, writev, readv), truncation, sync, links, and ioctl.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "kbox/path.h"
#include "vcred.h"

struct kbox_dispatch forward_clock_gettime(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    /* A CPU clock id that names a thread or a process encodes that id and is
     * negative. Linux answers such a clock only in the process that owns the
     * thread, and the supervisor is a different process: its own call answered
     * EINVAL for the guest's time.pthread_getcpuclockid()
     * (test_time.test_pthread_getcpuclockid). The tracee owns the thread, so
     * let its own kernel call answer. */
    if (clockid < 0)
        return kbox_dispatch_continue();

    if (remote_ts == 0)
        return kbox_dispatch_errno(EFAULT);

    struct timespec ts;
    if (clock_gettime(clockid, &ts) < 0)
        return kbox_dispatch_errno(errno);

    int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_clock_getres(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_ts = kbox_syscall_request_arg(req, 1);

    /* Same reason as in forward_clock_gettime: an encoded CPU clock belongs to
     * the tracee's process, not to the supervisor's. */
    if (clockid < 0)
        return kbox_dispatch_continue();

    struct timespec ts;
    if (clock_getres(clockid, remote_ts ? &ts : NULL) < 0)
        return kbox_dispatch_errno(errno);

    if (remote_ts != 0) {
        int wrc = guest_mem_write(ctx, pid, remote_ts, &ts, sizeof(ts));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_gettimeofday(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_tv = kbox_syscall_request_arg(req, 0);
    uint64_t remote_tz = kbox_syscall_request_arg(req, 1);

    /* Use clock_gettime(CLOCK_REALTIME) as the underlying source, which works
     * on both x86_64 and aarch64.
     */
    if (remote_tv != 0) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
            return kbox_dispatch_errno(errno);

        struct {
            long tv_sec;
            long tv_usec;
        } tv;
        tv.tv_sec = ts.tv_sec;
        tv.tv_usec = ts.tv_nsec / 1000;

        int wrc = guest_mem_write(ctx, pid, remote_tv, &tv, sizeof(tv));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    if (remote_tz != 0) {
        /* Return zeroed timezone (UTC). */
        struct {
            int tz_minuteswest;
            int tz_dsttime;
        } tz = {0, 0};

        int wrc = guest_mem_write(ctx, pid, remote_tz, &tz, sizeof(tz));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }

    return kbox_dispatch_value(0);
}

/* /proc inside a container is the host's procfs (paths under it are
 * continued to the host kernel), so the magic links of the guest's own
 * process describe kboxd rather than the guest, and kbox blocks them as
 * escape paths. Official images depend on them -- gosu re-execs through
 * /proc/self/exe, su-exec and tini do the same -- so synthesize the three
 * that name guest state from state kbox already tracks.
 *
 * Returns the number of bytes to report, or 0 if the path is not one of
 * ours. */
static int synthesize_proc_magic_link(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      char *out,
                                      size_t out_size)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char path[KBOX_MAX_PATH];
    int rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                                   path, sizeof(path));
    if (rc < 0)
        return 0;

    const char *tail = NULL;
    if (strncmp(path, "/proc/self/", 11) == 0)
        tail = path + 11;
    else if (strncmp(path, "/proc/thread-self/", 18) == 0)
        tail = path + 18;
    else if (strncmp(path, "/dev/", 5) == 0)
        tail = path + 5;
    if (!tail)
        return 0;

    /* /proc/self/fd/N: the tracee's own descriptor table is the host's, so the
     * supervisor can read the link from /proc/<pid>/fd/N. ttyname() and pty
     * setup answer through this link; without it openpty() created a pty and
     * then failed to name or open the slave.
     */
    if (strncmp(tail, "fd/", 3) == 0 && tail[3] != '\0') {
        char *end = NULL;
        long vfd = strtol(tail + 3, &end, 10);
        if (end && (*end == '\0' || *end == '/')) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, vfd);
            if (entry && entry->lkl_fd >= 0) {
                char link[64];
                snprintf(link, sizeof(link), "/proc/self/fd/%ld",
                         entry->lkl_fd);
                long n = kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, link,
                                             out, out_size);
                if (n > 0)
                    return (int) n;
            }
        }
        char link[64];
        ssize_t n;
        snprintf(link, sizeof(link), "/proc/%d/fd/%s", (int) pid, tail + 3);
        n = readlink(link, out, out_size);
        if (n <= 0)
            return 0;
        return (int) n;
    }

    const char *target = NULL;
    if (strcmp(tail, "exe") == 0) {
        const char *exe = kbox_guest_exe_for(ctx, pid);
        if (exe[0])
            target = exe;
    } else if (strcmp(tail, "cwd") == 0) {
        target = ctx->host_cwd;
    } else if (strcmp(tail, "root") == 0) {
        target = "/";
    }
    if (!target)
        return 0;

    size_t n = strlen(target);
    if (n > out_size)
        n = out_size;
    memcpy(out, target, n);
    return (int) n;
}

struct kbox_dispatch forward_readlinkat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 2);
    int64_t bufsiz_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    if (bufsiz_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t bufsiz = (size_t) bufsiz_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    if (bufsiz > KBOX_MAX_PATH)
        bufsiz = KBOX_MAX_PATH;

    /* Magic links of the guest's own process, before any path translation:
     * kbox blocks them as host escape paths and they are not host paths. */
    {
        char magic[KBOX_MAX_PATH];
        int mrc = synthesize_proc_magic_link(req, ctx, magic, sizeof(magic));
        if (mrc > 0) {
            size_t n = (size_t) mrc;
            if (n > bufsiz)
                n = bufsiz;
            int wrc = guest_mem_write(ctx, pid, remote_buf, magic, n);
            if (wrc < 0)
                return kbox_dispatch_errno(-wrc);
            return kbox_dispatch_value((int64_t) n);
        }
    }

    /* Host dirfd: call host readlinkat with a supervisor-owned copy. */
    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                               &sv_dirfd, &close_sv);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        char linkbuf[KBOX_MAX_PATH + 1];
        char guest_target[KBOX_MAX_PATH];
        ssize_t n = readlinkat(sv_dirfd, translated, linkbuf, bufsiz);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (n < 0)
            return kbox_dispatch_errno(saved);

        /* A link on a mounted volume stores an absolute target in its host
         * form (see forward_symlinkat); the guest must read its own path. */
        const char *out_buf = linkbuf;
        linkbuf[n] = '\0';
        if (n > 0 && linkbuf[0] == '/') {
            if (kbox_bind_host_to_guest(ctx->host_binds, ctx->host_bind_count,
                                        linkbuf, guest_target,
                                        sizeof(guest_target)) == 1) {
                out_buf = guest_target;
                n = (ssize_t) strlen(guest_target);
            }
        }
        size_t wlen = (size_t) n;
        if (wlen > bufsiz)
            wlen = bufsiz;
        int wrc = guest_mem_write(ctx, pid, remote_buf, out_buf, wlen);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value((int64_t) wlen);
    }

    char linkbuf[KBOX_MAX_PATH];
    long ret = kbox_lkl_readlinkat(ctx->sysnrs, lkl_dirfd, translated, linkbuf,
                                   (long) bufsiz);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, linkbuf, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

static struct kbox_dispatch inject_host_fd_pair(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int host_fds[2],
    uint64_t remote_fds,
    uint32_t cloexec_flag)
{
    pid_t pid = kbox_syscall_request_pid(req);
    /* Pipes go into the host-passthrough band so the kernel closes them
     * itself: a close answered by the supervisor can be aborted by a signal
     * while the tracee waits, and the descriptor then stays open (item 30 in
     * three-suites-report.md). */
    int tracee_fd0 =
        request_addfd_passthrough(ctx, req, host_fds[0], cloexec_flag);
    if (tracee_fd0 < 0) {
        close(host_fds[0]);
        close(host_fds[1]);
        return kbox_dispatch_errno(-tracee_fd0);
    }

    int tracee_fd1 =
        request_addfd_passthrough(ctx, req, host_fds[1], cloexec_flag);
    close(host_fds[0]);
    close(host_fds[1]);
    if (tracee_fd1 < 0)
        return kbox_dispatch_errno(-tracee_fd1);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd0);
    track_host_passthrough_fd(ctx->fd_table, tracee_fd1);

    int guest_fds[2] = {tracee_fd0, tracee_fd1};
    int wrc =
        guest_mem_write(ctx, pid, remote_fds, guest_fds, sizeof(guest_fds));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr, "kbofdt: pair pid=%d host=%d,%d tracee=%d,%d\n",
                (int) pid, host_fds[0], host_fds[1], tracee_fd0, tracee_fd1);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_pipe2(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    uint64_t remote_pipefd = kbox_syscall_request_arg(req, 0);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_pipefd == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Create a real host pipe and inject both ends into the tracee via
     * SECCOMP_IOCTL_NOTIF_ADDFD.  This makes pipes fully native:
     *   - dup2/close/read/write on pipe FDs -> CONTINUE (host kernel)
     *   - Proper fork semantics: both parent and child share the real
     *     pipe, no virtual FD table conflicts.
     *   - No LKL overhead for IPC data transfer.
     */
    int host_pipefd[2];
    /* pipe() has no interruptible step in the kernel, so the guest never
     * expects EINTR from it. The supervisor does get signals, and its own
     * pipe2() call can be interrupted: a shell then reports "can't create
     * pipe: Interrupted system call" and a script dies for no reason the
     * guest can see. Retry, since nothing was created.
     */
    while (pipe2(host_pipefd, (int) flags) < 0) {
        if (errno != EINTR)
            return kbox_dispatch_errno(errno);
    }

    return inject_host_fd_pair(req, ctx, host_pipefd, remote_pipefd,
                               (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
}

struct kbox_dispatch forward_socketpair(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long domain = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long type_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long protocol = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    uint64_t remote_sv = kbox_syscall_request_arg(req, 3);

    if (remote_sv == 0)
        return kbox_dispatch_errno(EFAULT);
    if (domain != AF_UNIX)
        return kbox_dispatch_errno(EAFNOSUPPORT);

    int host_sv[2];
    /* Same reason as pipe2: socketpair() never returns EINTR to a guest, so a
     * signal that reaches the supervisor must not manufacture one. */
    while (socketpair((int) domain, (int) type_raw, (int) protocol, host_sv) <
           0) {
        if (errno != EINTR)
            return kbox_dispatch_errno(errno);
    }

    return inject_host_fd_pair(req, ctx, host_sv, remote_sv,
                               (type_raw & SOCK_CLOEXEC) ? O_CLOEXEC : 0);
}

struct kbox_dispatch forward_xattr_nodata(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    (void) req;
    (void) ctx;
    return kbox_dispatch_errno(ENODATA);
}

struct kbox_dispatch forward_uname(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    snprintf(uts.sysname, sizeof(uts.sysname), "Linux");
    snprintf(uts.nodename, sizeof(uts.nodename), "kbox");
    if (ctx->exit_notify_fd >= 0 && ctx->sysnrs && ctx->sysnrs->uname > 0) {
        struct utsname lkl_uts;
        memset(&lkl_uts, 0, sizeof(lkl_uts));
        if (lkl_syscall6(ctx->sysnrs->uname, (long) &lkl_uts, 0, 0, 0, 0, 0) ==
                0 &&
            lkl_uts.nodename[0] && strcmp(lkl_uts.nodename, "(none)") != 0)
            snprintf(uts.nodename, sizeof(uts.nodename), "%s",
                     lkl_uts.nodename);
    }
    snprintf(uts.release, sizeof(uts.release), "6.8.0-kbox");
    snprintf(uts.version, sizeof(uts.version), "#1 SMP");
#if defined(__x86_64__)
    snprintf(uts.machine, sizeof(uts.machine), "x86_64");
#elif defined(__aarch64__)
    snprintf(uts.machine, sizeof(uts.machine), "aarch64");
#elif (defined(__riscv) && __riscv_xlen == 64)
    snprintf(uts.machine, sizeof(uts.machine), "riscv64");
#else
    snprintf(uts.machine, sizeof(uts.machine), "unknown");
#endif

    int wrc = guest_mem_write(ctx, pid, remote_buf, &uts, sizeof(uts));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_getrandom(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    /* Serve getrandom(2) directly from the host Linux kernel's CSPRNG.
     *
     * Forwarding getrandom() to LKL's /dev/urandom acquired LKL's global CPU
     * lock while LKL had no hardware RNG, stalling the entire engine and
     * network pump (stage=4) for 3-6 seconds right after boot and silently
     * capping reads at 256 bytes while ignoring GRND_NONBLOCK/GRND_RANDOM.
     * getrandom() touches only the caller's user buffer and no guest path or
     * descriptor, so host execution gives exact Linux semantics with zero LKL
     * contention.
     */
    (void) req;
    (void) ctx;
    return kbox_dispatch_continue();
}

/* syslog(type, buf, len): forward to LKL so dmesg shows the LKL kernel's ring
 * buffer, not the host's.
 *
 * Types that read into buf (2=READ, 3=READ_ALL, 4=READ_CLEAR): call LKL with
 * a scratch buffer, then copy to tracee.
 * Types that just return a value (0,1,5-10): forward type+len, return the
 * result directly.
 */
#define SYSLOG_ACTION_READ 2
#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_READ_CLEAR 4
#define SYSLOG_ACTION_SIZE_BUFFER 10

struct kbox_dispatch forward_syslog(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long type = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    int needs_buf =
        (type == SYSLOG_ACTION_READ || type == SYSLOG_ACTION_READ_ALL ||
         type == SYSLOG_ACTION_READ_CLEAR);

    if (!needs_buf) {
        /* No buffer transfer: SIZE_BUFFER, CONSOLE_ON/OFF, etc. */
        long ret = lkl_syscall6(ctx->sysnrs->syslog, type, 0, len, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    if (len <= 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Static buffer; safe because the supervisor is single-threaded.
     * Clamp to the actual LKL ring buffer size so READ_CLEAR never discards
     * data beyond what we can copy out. The ring buffer size is fixed at boot,
     * so cache it after the first query. Hard-cap at 1MB (the static buffer
     * size) as a safety ceiling.
     */
    static uint8_t scratch[1024 * 1024];
    static long cached_ring_sz;
    static pthread_mutex_t syslog_lock = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&syslog_lock);
    if (!cached_ring_sz) {
        long sz = lkl_syscall6(ctx->sysnrs->syslog, SYSLOG_ACTION_SIZE_BUFFER,
                               0, 0, 0, 0, 0);
        cached_ring_sz = (sz > 0) ? sz : -1;
    }
    if (cached_ring_sz > 0 && len > cached_ring_sz)
        len = cached_ring_sz;
    if (len > (long) sizeof(scratch))
        len = (long) sizeof(scratch);

    long ret =
        lkl_syscall6(ctx->sysnrs->syslog, type, (long) scratch, len, 0, 0, 0);
    if (ret < 0) {
        pthread_mutex_unlock(&syslog_lock);
        return kbox_dispatch_errno((int) (-ret));
    }

    size_t n = (size_t) ret;
    int wrc = guest_mem_write(ctx, pid, remote_buf, scratch, n);
    pthread_mutex_unlock(&syslog_lock);

    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_GET_NAME
#define PR_GET_NAME 16
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

struct kbox_dispatch forward_prctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long option = to_c_long_arg(kbox_syscall_request_arg(req, 0));

    /* Block PR_SET_DUMPABLE(0): clearing dumpability makes process_vm_readv
     * fail, which would bypass clone3 namespace-flag sanitization (supervisor
     * can't read clone_args.flags from a non-dumpable process). Return success
     * without actually clearing; the tracee thinks it worked, but supervisor
     * retains read access.
     */
    if (option == PR_SET_DUMPABLE &&
        to_c_long_arg(kbox_syscall_request_arg(req, 1)) == 0)
        return kbox_dispatch_value(0);
    /* Match: report dumpable even if guest tried to clear it. */
    if (option == PR_GET_DUMPABLE)
        return kbox_dispatch_value(1);

    /* Only forward PR_SET_NAME and PR_GET_NAME to LKL. Everything else passes
     * through to the host kernel.
     *
     * PR_SET_NAME/PR_GET_NAME use a 16-byte name buffer. The tracee passes a
     * pointer in arg2 which is in the tracee's address space, not ours. We must
     * copy through kbox_vm_read/kbox_vm_write.
     */
    if (option != PR_SET_NAME && option != PR_GET_NAME)
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_name = kbox_syscall_request_arg(req, 1);
    if (remote_name == 0)
        return kbox_dispatch_errno(EFAULT);

    /* PR_SET_NAME: read 16-byte name from tracee, pass local copy to LKL. */
    if (option == PR_SET_NAME) {
        char name[16];
        int rrc = guest_mem_read(ctx, pid, remote_name, name, sizeof(name));
        if (rrc < 0)
            return kbox_dispatch_errno(-rrc);
        name[15] = '\0'; /* ensure NUL termination */
        long ret =
            lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
        return kbox_dispatch_from_lkl(ret);
    }

    /* PR_GET_NAME: get name from LKL into local buffer, write to tracee. */
    char name[16] = {0};
    long ret =
        lkl_syscall6(ctx->sysnrs->prctl, option, (long) name, 0, 0, 0, 0);
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    int wrc = guest_mem_write(ctx, pid, remote_name, name, sizeof(name));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

#define KBOX_CAP_VERSION_1 0x19980330U
#define KBOX_CAP_VERSION_2 0x20071026U
#define KBOX_CAP_VERSION_3 0x20080522U

struct kbox_cap_header {
    uint32_t version;
    int32_t pid;
};

struct kbox_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static int cap_u32s_for_version(uint32_t version)
{
    if (version == KBOX_CAP_VERSION_1)
        return 1;
    if (version == KBOX_CAP_VERSION_2 || version == KBOX_CAP_VERSION_3)
        return 2;
    return 0;
}

/* Read and validate a Linux capability header from the tracee.
 * On unsupported version, kernel capget/capset rewrites hdr->version to v3 and
 * returns EINVAL (or 0 for capget with datap == NULL). Returns u32s (>0) when
 * valid, 0 if capget(hdrp, NULL) succeeded after version rewrite, or -errno.
 */
static int cap_validate_header(struct kbox_supervisor_ctx *ctx,
                               pid_t pid,
                               uint64_t remote_hdr,
                               int allow_null_data,
                               uint64_t remote_data)
{
    if (remote_hdr == 0)
        return -EFAULT;

    struct kbox_cap_header hdr;
    int rrc = guest_mem_read(ctx, pid, remote_hdr, &hdr, sizeof(hdr));
    if (rrc < 0)
        return rrc;

    int u32s = cap_u32s_for_version(hdr.version);
    if (u32s == 0) {
        hdr.version = KBOX_CAP_VERSION_3;
        int wrc = guest_mem_write(ctx, pid, remote_hdr, &hdr, sizeof(hdr));
        if (wrc < 0)
            return wrc;
        if (allow_null_data && remote_data == 0)
            return 0;
        return -EINVAL;
    }

    return u32s;
}

struct kbox_dispatch forward_capget(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_hdr = kbox_syscall_request_arg(req, 0);
    uint64_t remote_data = kbox_syscall_request_arg(req, 1);

    int u32s = cap_validate_header(ctx, pid, remote_hdr, 1, remote_data);
    if (u32s < 0)
        return kbox_dispatch_errno(-u32s);
    if (u32s == 0 || remote_data == 0)
        return kbox_dispatch_value(0);

    /* Supervisor runs with NO_NEW_PRIVS and ambient/bounding caps cleared;
     * report an empty capability mask consistently for any virtual PID.
     */
    struct kbox_cap_data data[2] = {0};
    int wrc = guest_mem_write(ctx, pid, remote_data, data,
                              (size_t) u32s * sizeof(data[0]));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_capset(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_hdr = kbox_syscall_request_arg(req, 0);
    uint64_t remote_data = kbox_syscall_request_arg(req, 1);

    int u32s = cap_validate_header(ctx, pid, remote_hdr, 0, remote_data);
    if (u32s < 0)
        return kbox_dispatch_errno(-u32s);
    if (remote_data == 0)
        return kbox_dispatch_errno(EFAULT);

    struct kbox_cap_data data[2] = {0};
    int rrc = guest_mem_read(ctx, pid, remote_data, data,
                             (size_t) u32s * sizeof(data[0]));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    for (int i = 0; i < u32s; i++) {
        if (data[i].effective || data[i].permitted || data[i].inheritable)
            return kbox_dispatch_errno(EPERM);
    }
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_pwrite64(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW) {
        if (getenv("KBOX_FD_TRACE"))
            fprintf(stderr, "kbofdt: pwrite64 continue fd=%ld lkl=%ld\n", fd,
                    lkl_fd);
        return kbox_dispatch_continue();
    }
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr, "kbofdt: pwrite64 lkl fd=%ld lkl=%ld host_fd=%ld\n", fd,
                lkl_fd, entry ? entry->host_fd : -99L);

    invalidate_stat_cache_fd(ctx, lkl_fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    size_t max_count = 1024 * 1024;
    if (count > max_count)
        count = max_count;

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        int rrc = guest_mem_read(ctx, pid, remote, scratch, chunk_len);
        if (rrc < 0) {
            if (total == 0)
                return kbox_dispatch_errno(-rrc);
            break;
        }

        long pwrite_off;
        if (__builtin_add_overflow(offset, (long) total, &pwrite_off)) {
            if (total == 0)
                return kbox_dispatch_errno(EOVERFLOW);
            break;
        }
        long ret = kbox_lkl_pwrite64(ctx->sysnrs, lkl_fd, scratch,
                                     (long) chunk_len, pwrite_off);
        if (ret < 0) {
            if (total == 0)
                return kbox_dispatch_errno((int) (-ret));
            break;
        }

        size_t n = (size_t) ret;
        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value((int64_t) total);
}

/* iovec layout matches the kernel's: { void *iov_base; size_t iov_len; }
 * On 64-bit: 16 bytes per entry.
 */
#define IOV_ENTRY_SIZE 16
/* Match the kernel's UIO_MAXIOV.  The iov_buf is static (not stack-allocated)
 * because in trap/rewrite mode dispatch runs in signal handler context where
 * 16 KB on the stack risks overflow on threads with small stacks. Dispatcher is
 * single-threaded (documented invariant), so a static buffer is safe.
 */
#define IOV_MAX_COUNT 1024
static __thread uint8_t iov_scratch[IOV_MAX_COUNT * IOV_ENTRY_SIZE];

/* Shared iov scatter/gather dispatcher for writev and readv.
 *
 * is_write selects the direction: 1 = guest->LKL (writev), 0 = LKL->guest
 * (readv). The chunked loop, iov parsing, and error handling are identical in
 * both directions.
 */
static struct kbox_dispatch dispatch_iov_transfer(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_write,
    int have_offset,
    int64_t start_offset)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    /* A read-only file promoted to a local-only shadow is served from that
     * shadow by read(2) and pread64(2). Reads through readv(2) and preadv(2)
     * must use the same shadow. Otherwise the two paths disagree: a readv
     * advances LKL's offset and leaves the shadow's where it was, so the next
     * read(2) hands back bytes the caller has already consumed. musl's stdio
     * mixes read and readv on one FILE, and BFD reads ELF section headers that
     * way, which is why ld and objdump rejected object files that live on the
     * internal filesystem while accepting the same bytes from a mounted
     * volume. */
    int shadow_read = 0;
    if (!is_write && entry && entry->shadow_sp >= 0 &&
        entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
        shadow_read = 1;

    if (is_write && ctx->verbose) {
        long cur = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);
        fprintf(stderr, "kbox: writev fd=%ld lkl=%ld host_fd=%ld cur_off=%ld\n",
                fd, lkl_fd, entry ? entry->host_fd : -99, cur);
    }

    if (is_write)
        invalidate_stat_cache_fd(ctx, lkl_fd);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_iov = kbox_syscall_request_arg(req, 1);
    int64_t iovcnt_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (iovcnt_raw < 0 || iovcnt_raw > IOV_MAX_COUNT)
        return kbox_dispatch_errno(EINVAL);
    if (iovcnt_raw == 0)
        return kbox_dispatch_value(0);
    if (remote_iov == 0)
        return kbox_dispatch_errno(EFAULT);

    int iovcnt = (int) iovcnt_raw;
    size_t iov_bytes = (size_t) iovcnt * IOV_ENTRY_SIZE;

    int rrc = guest_mem_read(ctx, pid, remote_iov, iov_scratch, iov_bytes);
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    int mirror_host =
        is_write ? kbox_fd_table_mirror_tty(ctx->fd_table, fd) : 0;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    int err = 0;

    int i;
    for (i = 0; i < iovcnt; i++) {
        uint64_t base;
        uint64_t len;
        memcpy(&base, &iov_scratch[i * IOV_ENTRY_SIZE], 8);
        memcpy(&len, &iov_scratch[i * IOV_ENTRY_SIZE + 8], 8);

        if (base == 0 || len == 0)
            continue;

        size_t seg_total = 0;
        while (seg_total < len) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            if (chunk > len - seg_total)
                chunk = len - seg_total;

            uint64_t remote;
            if (__builtin_add_overflow(base, seg_total, &remote)) {
                err = EFAULT;
                goto done;
            }

            if (is_write) {
                rrc = guest_mem_read(ctx, pid, remote, scratch, chunk);
                if (rrc < 0) {
                    err = -rrc;
                    goto done;
                }
            }

            int64_t at = start_offset + (int64_t) total;
            long ret;
            if (shadow_read) {
                ssize_t sr;

                if (have_offset)
                    sr = pread(entry->shadow_sp, scratch, chunk, (off_t) at);
                else
                    sr = read(entry->shadow_sp, scratch, chunk);
                ret = sr < 0 ? -(long) errno : (long) sr;
            } else if (have_offset)
                ret = is_write ? kbox_lkl_pwrite64(ctx->sysnrs, lkl_fd, scratch,
                                                   (long) chunk, (long) at)
                               : kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                                  (long) chunk, (long) at);
            else
                ret = is_write ? kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch,
                                                (long) chunk)
                               : kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch,
                                               (long) chunk);
            if (ret < 0) {
                err = (int) (-ret);
                goto done;
            }

            size_t n = (size_t) ret;
            if (n == 0)
                goto done;

            if (is_write) {
                if (mirror_host) {
                    ssize_t written = write(STDOUT_FILENO, scratch, n);
                    (void) written;
                }
            } else {
                int wrc = guest_mem_write(ctx, pid, remote, scratch, n);
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
            }

            seg_total += n;
            total += n;
            if (n < chunk)
                goto done;
        }
    }

done:
    if (is_write && total > 0)
        invalidate_path_shadow_cache(ctx);
    /* The shadow is the authoritative position for these reads, so carry it
     * back to LKL. read(2) on the same descriptor does the same, which keeps a
     * caller that mixes the two calls on one descriptor consistent. */
    if (shadow_read && !have_offset) {
        off_t cur = lseek(entry->shadow_sp, 0, SEEK_CUR);

        if (cur >= 0)
            (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) cur, SEEK_SET);
    }
    if (getenv("KBOX_FD_TRACE") && fd >= 0)
        fprintf(stderr,
                "kbofdt: iov done fd=%ld lkl=%ld write=%d total=%zu err=%d\n",
                fd, lkl_fd, is_write, total, err);
    if (total == 0 && err)
        return kbox_dispatch_errno(err);
    return kbox_dispatch_value((int64_t) total);
}

struct kbox_dispatch forward_writev(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_transfer(req, ctx, 1, 0, 0);
}

struct kbox_dispatch forward_readv(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_transfer(req, ctx, 0, 0, 0);
}

/* Vector I/O at an explicit offset. postgres writes its WAL and its relation
 * pages this way; without it the syscall fell through to the unknown-syscall
 * denial and bootstrap died on "could not write to file ... Function not
 * implemented".
 */
static struct kbox_dispatch dispatch_iov_at_offset(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_write,
    int has_flags)
{
    if (has_flags) {
        /* RWF_HIPRI, RWF_NOWAIT and friends are advisory: Linux completes the
         * transfer and ignores them for a file that does not support them.
         * Answering ENOSYS made os.preadv(fd, buf, n, RWF_HIPRI) fail
         * (test_posix.test_preadv_flags). The flags are not forwarded because
         * LKL's preadv2 support depends on the backing file system; the data
         * transfer is the part the caller depends on.
         */
        (void) to_c_long_arg(kbox_syscall_request_arg(req, 4));
    }
    int64_t offset = (int64_t) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return dispatch_iov_transfer(req, ctx, is_write, 1, offset);
}

struct kbox_dispatch forward_pwritev(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_at_offset(req, ctx, 1, 0);
}

struct kbox_dispatch forward_preadv(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_at_offset(req, ctx, 0, 0);
}

struct kbox_dispatch forward_pwritev2(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_at_offset(req, ctx, 1, 1);
}

struct kbox_dispatch forward_preadv2(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    return dispatch_iov_at_offset(req, ctx, 0, 1);
}

struct kbox_dispatch forward_ftruncate(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    long length = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_ftruncate_safe(ctx->sysnrs, lkl_fd, length);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fallocate(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
        return kbox_dispatch_continue();

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long offset = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long len = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    long ret = kbox_lkl_fallocate(ctx->sysnrs, lkl_fd, mode, offset, len);
    if (ret == -ENOSYS)
        return kbox_dispatch_errno(ENOSYS);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_flock(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long operation = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_flock(ctx->sysnrs, lkl_fd, operation);
    if (ret == -ENOSYS) {
        if ((operation & (LOCK_SH | LOCK_EX | LOCK_UN)) == 0)
            return kbox_dispatch_errno(EINVAL);
        return kbox_dispatch_value(0);
    }
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fchmod(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_fchmod(ctx->sysnrs, lkl_fd, mode);
    if (ret >= 0) {
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* fchown: LKL files go to LKL; host descriptors cannot be chowned by an
 * unprivileged supervisor, so a virtual-root guest's request lands in the
 * ownership overlay (see vcred.h). */
struct kbox_dispatch forward_fchown(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long owner = (int32_t) kbox_syscall_request_arg(req, 1);
    long group = (int32_t) kbox_syscall_request_arg(req, 2);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd >= 0) {
        long ret = kbox_lkl_fchownat(ctx->sysnrs, lkl_fd, "", owner, group,
                                     0x1000 /* AT_EMPTY_PATH */);
        /* LKL performs this call with the supervisor's credentials, which are
         * the unprivileged container's, so chown_common refuses with EPERM
         * before hostfs is reached and the guest file's owner never changes.
         * A virtual-root guest is entitled to the change (that is the whole
         * point of running as root inside its own kernel), and chown(path)
         * already records it in the ownership overlay through
         * host_chown_virtual. Record it here too, keyed by the guest file's
         * (device, inode) so stat reports it and a later rename keeps it.
         * apk sets the owner on every file it extracts, so without this every
         * transaction fails with "Failed to set ownership: Permission denied".
         */
        if ((ret == 0 || ret == -EPERM || ret == -EACCES) &&
            ctx->root_identity && (owner != -1 || group != -1)) {
            struct kbox_lkl_stat kst;

            if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst) >= 0) {
                struct stat eff;
                int64_t eff_uid = owner;
                int64_t eff_gid = group;

                if (eff_uid == -1 || eff_gid == -1) {
                    kbox_lkl_stat_to_host(&kst, &eff);
                    (void) kbox_owner_apply_overlay(&eff);
                    if (eff_uid == -1)
                        eff_uid = (int64_t) eff.st_uid;
                    if (eff_gid == -1)
                        eff_gid = (int64_t) eff.st_gid;
                }
                kbox_owner_set((dev_t) kst.st_dev, (ino_t) kst.st_ino, eff_uid,
                               eff_gid);
                invalidate_path_shadow_cache(ctx);
                invalidate_stat_cache_fd(ctx, lkl_fd);
                if (getenv("KBOX_TRACE"))
                    fprintf(stderr,
                            "kbox: fchown fd=%ld (virtual root) owner=%lld "
                            "group=%lld\n",
                            fd, (long long) eff_uid, (long long) eff_gid);
                return kbox_dispatch_value(0);
            }
        }
        if (ret >= 0) {
            invalidate_path_shadow_cache(ctx);
            invalidate_stat_cache_fd(ctx, lkl_fd);
        }
        return kbox_dispatch_from_lkl(ret);
    }
    if (!(ctx->root_identity))
        return kbox_dispatch_continue();

    pid_t pid = kbox_syscall_request_pid(req);
    struct kbox_vcred c;
    struct stat st;
    char link[64];

    kbox_vcred_get(pid, &c);
    if (c.euid != 0)
        return kbox_dispatch_errno(EPERM);
    snprintf(link, sizeof(link), "/proc/%d/fd/%ld", (int) pid, fd);
    if (stat(link, &st) < 0)
        return kbox_dispatch_errno(errno);
    kbox_owner_record_host(pid, AT_FDCWD, link, 0, &st, owner, group);
    if (getenv("KBOX_TRACE"))
        fprintf(stderr,
                "kbox: fchown fd=%ld -> owner=%ld group=%ld (virtual)\n", fd,
                owner, group);
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_fadvise64(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    return kbox_dispatch_value(0);
}

struct kbox_dispatch forward_fsync(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fsync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_fdatasync(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_fdatasync(ctx->sysnrs, lkl_fd);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_sync(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    (void) req;
    long ret = kbox_lkl_sync(ctx->sysnrs);
    return kbox_dispatch_from_lkl(ret);
}

/* sync_file_range(fd, offset, nbytes, flags).
 *
 * This call only starts writeback of a range; it does not promise durability,
 * and a program that needs durability still calls fsync. Redis uses it to pace
 * RDB writing (rdb-save-incremental-fsync) and treats any error as a fatal
 * write failure: with this syscall unknown, kbox answered ENOSYS and every
 * save of a database large enough to need more than one range failed with
 * "Write error while saving DB to the disk(rdbSaveRio): Function not
 * implemented", which aborted redis' own test client.
 *
 * It is forwarded to LKL so a real filesystem can schedule the writeback. When
 * the filesystem behind the guest file has no implementation, the answer is
 * success rather than ENOSYS: the hint was accepted, and the caller's own
 * fsync is what makes the data durable. An unknown descriptor is still EBADF.
 */
struct kbox_dispatch forward_sync_file_range(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    /* A writeback shadow holds the bytes in the supervisor's memfd, so the
     * same flush fsync performs is what this call has to ask for. */
    if (entry && entry->shadow_writeback) {
        int rc = sync_shadow_writeback(ctx, entry);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_sync_file_range(
        ctx->sysnrs, lkl_fd, to_c_long_arg(kbox_syscall_request_arg(req, 1)),
        to_c_long_arg(kbox_syscall_request_arg(req, 2)),
        to_c_long_arg(kbox_syscall_request_arg(req, 3)));
    if (ret == -ENOSYS)
        return kbox_dispatch_value(0);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_symlinkat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char targetbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               targetbuf, sizeof(targetbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char linktrans[KBOX_MAX_PATH];
    long newdirfd;
    rc = translate_request_at_path(req, ctx, 1, 2, linktrans, sizeof(linktrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* A link stored on a mounted volume is resolved by the host kernel, which
     * knows only host paths. An absolute target that names a guest path inside
     * such a volume is stored in its host form, and forward_readlinkat() shows
     * it back in its guest form. Without this an absolute link inside the
     * volume dangles: MariaDB's symlink tests could create the link but neither
     * the server nor the shell could open it.
     */
    char stored_target[KBOX_MAX_PATH];
    const char *target_to_store = targetbuf;
    if (targetbuf[0] == '/' && should_continue_for_dirfd(newdirfd)) {
        char mapped[KBOX_MAX_PATH];
        if (kbox_bind_guest_to_host(ctx->host_binds, ctx->host_bind_count,
                                    targetbuf, mapped, sizeof(mapped)) == 1) {
            snprintf(stored_target, sizeof(stored_target), "%s", mapped);
            target_to_store = stored_target;
        }
    }

    /* Host dirfd: call host symlinkat with a supervisor-owned copy. */
    if (should_continue_for_dirfd(newdirfd)) {
        long raw = to_dirfd_arg(kbox_syscall_request_arg(req, 1));
        if (host_bind_is_readonly(ctx, pid, raw, newdirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw, newdirfd, &sv_dirfd,
                                               &close_sv);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        int host_rc = symlinkat(target_to_store, sv_dirfd, linktrans);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    /* Target is stored as-is (not translated). */
    long ret = kbox_lkl_symlinkat(ctx->sysnrs, targetbuf, newdirfd, linktrans);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

struct kbox_dispatch forward_linkat(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    int rc;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    char oldtrans[KBOX_MAX_PATH];
    long olddirfd;
    rc = translate_request_at_path(req, ctx, 0, 1, oldtrans, sizeof(oldtrans),
                                   &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char newtrans[KBOX_MAX_PATH];
    long newdirfd;
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* linkat("/proc/self/fd/N", path): apk writes its database with O_TMPFILE
     * and materializes it by linking the magic link, which is the documented
     * way to give a temporary anonymous file its name. N is one of kbox's
     * descriptors, so the host's /proc/<pid>/fd/N does not exist; resolve it
     * to the guest file kbox holds and link that file directly with
     * AT_EMPTY_PATH. Without this branch the old path looked like a host path
     * and every apk transaction failed with "failed to write database:
     * Cross-device link".
     */
    {
        long vfd = -1;

        if (!should_continue_for_dirfd(newdirfd) &&
            fd_magic_link_fd(oldtrans, &vfd) && vfd >= 0) {
            struct kbox_fd_entry *src = fd_table_entry(ctx->fd_table, vfd);

            if (src && src->lkl_fd >= 0) {
                if (src->shadow_writeback)
                    (void) sync_shadow_writeback(ctx, src);
                long ret =
                    kbox_lkl_linkat(ctx->sysnrs, src->lkl_fd, "", newdirfd,
                                    newtrans, 0x1000 /* AT_EMPTY_PATH */);
                if (ret >= 0)
                    invalidate_path_shadow_cache(ctx);
                return kbox_dispatch_from_lkl(ret);
            }
        }
    }

    /* A path that belongs to the host -- an absolute /dev, /proc or /sys path
     * -- has to be linked on the host, exactly as openat handles it. musl's
     * sem_open creates /dev/shm/tmp-<random>, fills it, and linkat()s it to
     * the final /dev/shm/<name>; sending that link to LKL answered ENOENT, so
     * every multiprocessing Lock, Queue and ProcessPoolExecutor failed with
     * FileNotFoundError (test_compileall.test_workers,
     * test_concurrent_futures, test_importlib's pool test, test_regrtest).
     */
    if (kbox_path_is_host_passthrough(ctx, req, 1, oldtrans) ||
        kbox_path_is_host_passthrough(ctx, req, 3, newtrans)) {
        if (!kbox_path_is_host_passthrough(ctx, req, 1, oldtrans) ||
            !kbox_path_is_host_passthrough(ctx, req, 3, newtrans)) {
            if (getenv("KBOX_TRACE"))
                fprintf(stderr,
                        "kbox: link EXDEV old=%s oldpassthrough=%d new=%s "
                        "newpassthrough=%d\n",
                        oldtrans,
                        kbox_path_is_host_passthrough(ctx, req, 1, oldtrans),
                        newtrans,
                        kbox_path_is_host_passthrough(ctx, req, 3, newtrans));
            return kbox_dispatch_errno(EXDEV);
        }
        int host_rc =
            linkat(AT_FDCWD, oldtrans, AT_FDCWD, newtrans, (int) flags);
        int saved = errno;
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    /* Host dirfd on either side: call host linkat with supervisor copies. */
    if (should_continue_for_dirfd(olddirfd) ||
        should_continue_for_dirfd(newdirfd)) {
        if (!should_continue_for_dirfd(olddirfd) ||
            !should_continue_for_dirfd(newdirfd)) {
            if (getenv("KBOX_TRACE"))
                fprintf(stderr,
                        "kbox: link EXDEV dirfd old=%s(%ld) new=%s(%ld)\n",
                        oldtrans, olddirfd, newtrans, newdirfd);
            return kbox_dispatch_errno(EXDEV);
        }
        long raw_old = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        long raw_new = to_dirfd_arg(kbox_syscall_request_arg(req, 2));
        if (host_bind_is_readonly(ctx, pid, raw_old, olddirfd) ||
            host_bind_is_readonly(ctx, pid, raw_new, newdirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_old = AT_FDCWD;
        int sv_new = AT_FDCWD;
        int close_old = 0;
        int close_new = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw_old, olddirfd, &sv_old,
                                               &close_old);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        drc = open_host_dirfd_for_dispatch(pid, raw_new, newdirfd, &sv_new,
                                           &close_new);
        if (drc < 0) {
            if (close_old)
                close(sv_old);
            return kbox_dispatch_errno(-drc);
        }
        int host_rc = linkat(sv_old, oldtrans, sv_new, newtrans, (int) flags);
        int saved = errno;
        if (close_old)
            close(sv_old);
        if (close_new)
            close(sv_new);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_linkat(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                               newtrans, flags);
    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

/* struct timespec is 16 bytes on 64-bit: tv_sec(8) + tv_nsec(8). */
#define TIMESPEC_SIZE 16

struct kbox_dispatch forward_utimensat(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long dirfd_raw = to_dirfd_arg(kbox_syscall_request_arg(req, 0));

    /* pathname can be NULL for utimensat (operates on dirfd itself). In that
     * case args[1] == 0.
     */
    const char *translated_path = NULL;
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc;
    int need_host_emulation = 0;

    if (kbox_syscall_request_arg(req, 1) != 0) {
        rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        translated_path = translated;
        if (should_continue_for_dirfd(lkl_dirfd))
            need_host_emulation = 1;
    } else {
        translated_path = NULL;
        /* dirfd must be a virtual FD when path is NULL. */
        lkl_dirfd = kbox_fd_table_get_lkl(ctx->fd_table, dirfd_raw);
        if (lkl_dirfd < 0)
            need_host_emulation = 1;
    }

    /* Read the times array (2 x struct timespec) if provided. */
    uint8_t times_buf[TIMESPEC_SIZE * 2];
    const void *times = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read(ctx, pid, kbox_syscall_request_arg(req, 2),
                            times_buf, sizeof(times_buf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        times = times_buf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    /* Host dirfd (or host-passthrough FD with NULL path): call host utimensat
     * with a supervisor-owned copy of the tracee's dirfd.
     */
    if (need_host_emulation) {
        if (host_bind_is_readonly(ctx, pid, dirfd_raw, lkl_dirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        int drc = open_host_dirfd_for_dispatch(pid, dirfd_raw, lkl_dirfd,
                                               &sv_dirfd, &close_sv);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        int host_rc;
        if (translated_path) {
            host_rc = utimensat(sv_dirfd, translated_path,
                                (const struct timespec *) times, (int) flags);
        } else if (flags == 0) {
            host_rc = futimens(sv_dirfd, (const struct timespec *) times);
        } else {
            errno = EINVAL;
            host_rc = -1;
        }
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    if (ctx->verbose && times) {
        const long *t = (const long *) times;
        fprintf(stderr,
                "kbox: utimensat lkl path=%s dirfd=%ld flags=%ld "
                "times=%ld.%09ld/%ld.%09ld\n",
                translated_path ? translated_path : "(fd)", lkl_dirfd, flags,
                t[0], t[1], t[2], t[3]);
    }
    long ret = kbox_lkl_utimensat(ctx->sysnrs, lkl_dirfd, translated_path,
                                  times, flags);
    if (ret >= 0) {
        if (!translated_path) {
            struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, dirfd_raw);
            if (e && e->shadow_sp >= 0)
                (void) futimens(e->shadow_sp, (const struct timespec *) times);
        }
        invalidate_path_shadow_cache(ctx);
        invalidate_stat_cache_fd(ctx, lkl_dirfd);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* Terminal ioctl constants. */
#ifndef TCGETS
#define TCGETS 0x5401
#endif
#ifndef TCSETS
#define TCSETS 0x5402
#endif
#ifndef TIOCGWINSZ
#define TIOCGWINSZ 0x5413
#endif
#ifndef TIOCSWINSZ
#define TIOCSWINSZ 0x5414
#endif
#ifndef TIOCGPGRP
#define TIOCGPGRP 0x540F
#endif
#ifndef TIOCSPGRP
#define TIOCSPGRP 0x5410
#endif
#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif

/* Resolve a tracee FD to the LKL socket behind it.
 *
 * Shadow sockets give the tracee a host socketpair end; the socket itself
 * lives in LKL. FIONBIO and the other socket ioctls therefore have to reach
 * the LKL file, not the socketpair end: LKL's accept()/connect() read the
 * non-blocking bit from the LKL file flags, so a flag set only on the host
 * shadow leaves accept() blocking forever (CPython's setblocking() and
 * settimeout() use ioctl(FIONBIO), not fcntl(F_SETFL)).
 *
 * Returns the LKL FD and, through entry_out, the FD-table entry that owns the
 * host shadow, or -1 when the FD is not a shadow socket.
 */
static long resolve_shadow_socket_lkl(struct kbox_supervisor_ctx *ctx,
                                      long fd,
                                      struct kbox_fd_entry **entry_out)
{
    long lkl_fd;
    struct kbox_fd_entry *entry = NULL;

    if (entry_out)
        *entry_out = NULL;

    lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd >= 0) {
        entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->shadow_sp >= 0) {
            if (entry_out)
                *entry_out = entry;
            return lkl_fd;
        }
        return -1;
    }

    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd < 0)
        return -1;
    entry = fd_table_entry(ctx->fd_table, vfd);
    if (!entry || entry->lkl_fd < 0 || entry->shadow_sp < 0)
        return -1;
    if (entry_out)
        *entry_out = entry;
    return entry->lkl_fd;
}

/* ioctl(FIONBIO) on a guest socket: apply the blocking flag to the LKL file
 * and to the host shadow, and answer 0. Both copies must agree, because the
 * guest's own F_GETFL goes to the host shadow while LKL makes its blocking
 * decisions from its own file flags.
 */
static struct kbox_dispatch ioctl_fionbio(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long lkl_fd,
    struct kbox_fd_entry *entry,
    uint64_t arg_ptr)
{
    int on = 0;
    int rrc;

    if (arg_ptr == 0)
        return kbox_dispatch_errno(EFAULT);
    rrc = guest_mem_read(ctx, kbox_syscall_request_pid(req), arg_ptr, &on,
                         sizeof(on));
    if (rrc < 0)
        return kbox_dispatch_errno(-rrc);

    long lfl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
    if (lfl < 0)
        return kbox_dispatch_from_lkl(lfl);

    long nfl = on ? (lfl | O_NONBLOCK) : (lfl & ~O_NONBLOCK);
    if (nfl != lfl) {
        long fr = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_SETFL, nfl);
        if (fr < 0)
            return kbox_dispatch_from_lkl(fr);
    }
    if (entry && entry->shadow_sp >= 0) {
        int hfl = fcntl(entry->shadow_sp, F_GETFL);
        if (hfl >= 0) {
            int hnfl = on ? (hfl | O_NONBLOCK) : (hfl & ~O_NONBLOCK);
            if (hnfl != hfl)
                (void) fcntl(entry->shadow_sp, F_SETFL, hnfl);
        }
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: ioctl FIONBIO fd-lkl=%ld on=%d -> 0\n", lkl_fd,
                on);
    return kbox_dispatch_value(0);
}

#ifndef SIOCGIFINDEX
#define SIOCGIFINDEX 0x8933
#endif
#ifndef SIOCGIFNAME
#define SIOCGIFNAME 0x8910
#endif

struct kbox_dispatch forward_ioctl(const struct kbox_syscall_request *req,
                                   struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (cmd == FIONBIO) {
        struct kbox_fd_entry *entry = NULL;
        long sock_lkl = resolve_shadow_socket_lkl(ctx, fd, &entry);
        if (sock_lkl < 0)
            sock_lkl = lkl_fd; /* vfd-backed LKL socket, no host shadow */
        if (sock_lkl >= 0)
            return ioctl_fionbio(req, ctx, sock_lkl, entry,
                                 kbox_syscall_request_arg(req, 2));
        /* A host-passthrough socket: an accepted AF_UNIX connection, or one
         * inherited from the runtime. The host owns its blocking flag, and the
         * accepted socket's FD is never in the table. asyncio calls
         * setblocking(False) on every accepted connection, and answering EBADF
         * there dropped the connection before the first byte.
         */
        if (tracee_fd_is_open(kbox_syscall_request_pid(req), fd))
            return kbox_dispatch_continue();
        return kbox_dispatch_errno(EBADF);
    }

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Interface lookups are answered by LKL, not by the host, even when the
         * descriptor is a host one. musl opens an AF_UNIX socket for
         * if_nametoindex()/if_indextoname(), and an AF_UNIX socket is a host
         * passthrough here; the host answered SIOCGIFINDEX about *its* network,
         * so every interface LKL has and the pod has not -- the sit0 tunnel is
         * one -- looked missing (test_socket's testInterfaceNameIndex compared
         * the netlink dump against that answer).
         */
        if (cmd == SIOCGIFINDEX || cmd == SIOCGIFNAME) {
            long lkl_sock = kbox_lkl_socket(ctx->sysnrs, 2 /* AF_INET */,
                                            2 /* SOCK_DGRAM */, 0);
            uint8_t ifr[40];
            pid_t pid = kbox_syscall_request_pid(req);
            uint64_t arg_ptr = kbox_syscall_request_arg(req, 2);

            if (lkl_sock < 0)
                return kbox_dispatch_errno((int) (-lkl_sock));
            if (arg_ptr == 0 ||
                guest_mem_read(ctx, pid, arg_ptr, ifr, sizeof(ifr)) < 0) {
                kbox_lkl_close(ctx->sysnrs, lkl_sock);
                return kbox_dispatch_errno(EFAULT);
            }
            long iret = kbox_lkl_ioctl(ctx->sysnrs, lkl_sock, cmd, (long) ifr);

            if (iret == 0 &&
                guest_mem_write(ctx, pid, arg_ptr, ifr, sizeof(ifr)) < 0)
                iret = -EFAULT;
            kbox_lkl_close(ctx->sysnrs, lkl_sock);
            return kbox_dispatch_from_lkl(iret);
        }

        /* Host-passthrough FD (stdin/stdout/stderr, pipe, eventfd, a pty from
         * the container's own /dev, etc.). The host kernel owns it and can
         * answer every ioctl itself, including the job-control ones. Answering
         * ENOTTY for TIOCSCTTY here broke pty.fork(): musl's login_tty() runs
         * setsid() and then TIOCSCTTY on the slave, and the tracee already is a
         * session leader at that point, so the kernel accepts it.
         */
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0) {
        if (!io_should_deny_fd(ctx, req, fd, lkl_fd))
            return kbox_dispatch_continue();
        return kbox_dispatch_errno(EBADF);
    }

    /* LKL-backed FD: the file lives in the guest kernel, so the ioctl must run
     * there. Returning ENOTTY for everything made pty.fork() fail: musl's
     * login_tty() issues TIOCSCTTY on the slave descriptor, got ENOTTY, and the
     * child exited before it could run any test code -- which showed up as
     * test_builtin's PtyTests and test_pty hanging forever on the result pipe.
     * A regular file still answers ENOTTY; that answer now comes from LKL.
     *
     * TIOCSCTTY is the one exception. It makes the calling *host* process the
     * leader of a session with this terminal, state that lives in the tracee's
     * task_struct and that no LKL syscall can reach. LKL would apply it to its
     * own worker thread instead. Answer success when LKL confirms the FD is a
     * terminal, so the guest can finish login_tty(); everything the guest then
     * does with the terminal (termios, window size, read, write) is real LKL
     * state.
     */
    if (cmd == TIOCSCTTY) {
        unsigned char tio[128];
        if (kbox_lkl_ioctl(ctx->sysnrs, lkl_fd, TCGETS, (long) tio) < 0)
            return kbox_dispatch_errno(ENOTTY);
        return kbox_dispatch_value(0);
    }
    if (cmd == TIOCGPGRP || cmd == TIOCSPGRP) {
        /* The process group of the tracee is host state; LKL only knows its own
         * worker threads. Report the tracee's own group, which is what a guest
         * expects to read back, and accept any value on write. */
        if (cmd == TIOCGPGRP) {
            pid_t pgrp = getpgid(kbox_syscall_request_pid(req));
            uint64_t remote = kbox_syscall_request_arg(req, 2);
            if (remote == 0)
                return kbox_dispatch_errno(EFAULT);
            if (pgrp < 0)
                pgrp = kbox_syscall_request_pid(req);
            if (guest_mem_write(ctx, kbox_syscall_request_pid(req), remote,
                                &pgrp, sizeof(pgrp)) < 0)
                return kbox_dispatch_errno(EFAULT);
            return kbox_dispatch_value(0);
        }
        return kbox_dispatch_value(0);
    }

    long ret = kbox_lkl_ioctl(ctx->sysnrs, lkl_fd, cmd,
                              (long) kbox_syscall_request_arg(req, 2));
    return kbox_dispatch_from_lkl(ret);
}

/* Intercepted FD-creating syscalls: eventfd, timerfd_create, epoll_create1.
 *
 * Previously these went through CONTINUE, leaving their FDs untracked. That
 * allowed read/write on leaked host FDs to also CONTINUE. Now we create the
 * FD in the supervisor, inject it via ADDFD, and track it as host-passthrough
 * so the EBADF policy for untracked FDs does not break legitimate I/O.
 */

struct kbox_dispatch forward_eventfd(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx)
{
    unsigned int initval = (unsigned int) kbox_syscall_request_arg(req, 0);
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 1));

    int host_fd = eventfd(initval, flags & ~EFD_CLOEXEC);
    if (host_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: eventfd2(%u, 0x%x): host errno %d\n",
                    initval, (unsigned) flags, errno);
        return kbox_dispatch_errno(errno);
    }

    uint32_t addfd_flags = (flags & EFD_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: eventfd2: addfd failed: %d\n", tracee_fd);
        return kbox_dispatch_errno(-tracee_fd);
    }

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & EFD_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

/* memfd_create: an anonymous host file with no path. Chromium makes its
 * shared-memory regions with it. The fd has to be injected and tracked like
 * eventfd, because a plain CONTINUE leaves it unknown to the fd table and the
 * very next ftruncate/mmap/fstat on it then fails with EBADF. */
struct kbox_dispatch forward_memfd_create(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char name[256];
    unsigned int flags =
        (unsigned int) to_c_long_arg(kbox_syscall_request_arg(req, 1));
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                                   name, sizeof(name));
    if (rc < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: memfd_create: name read failed: %d\n", rc);
        return kbox_dispatch_errno(-rc);
    }

    int host_fd = (int) syscall(SYS_memfd_create, name, flags & ~1U);
    if (host_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: memfd_create(\"%s\", 0x%x): host errno %d\n",
                    name, flags, errno);
        return kbox_dispatch_errno(errno);
    }

    uint32_t addfd_flags = (flags & 1U) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: memfd_create(\"%s\"): addfd failed: %d\n",
                    name, tracee_fd);
        return kbox_dispatch_errno(-tracee_fd);
    }

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & 1U)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

/* signalfd: the descriptor has to live in the host, like eventfd and
 * timerfd, because the signals it reports are delivered to the host process.
 * Without this the syscall never reached anyone -- kbox denies syscalls it does
 * not know with ENOSYS -- and postgres' postmaster died on it at startup. */
struct kbox_dispatch forward_signalfd4(const struct kbox_syscall_request *req,
                                       struct kbox_supervisor_ctx *ctx)
{
    int ufd = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t mask_addr = kbox_syscall_request_arg(req, 1);
    size_t sizemask = (size_t) to_c_long_arg(kbox_syscall_request_arg(req, 2));
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    pid_t pid = kbox_syscall_request_pid(req);

    if (sizemask > sizeof(sigset_t))
        sizemask = sizeof(sigset_t);

    sigset_t mask;
    memset(&mask, 0, sizeof(mask));
    if (sizemask > 0 &&
        guest_mem_read(ctx, pid, mask_addr, &mask, sizemask) != 0)
        return kbox_dispatch_errno(EFAULT);

    int host_fd = signalfd(ufd, &mask, flags & ~SFD_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & SFD_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & SFD_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

struct kbox_dispatch forward_timerfd_create(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    int clockid = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 1));

    int host_fd = timerfd_create(clockid, flags & ~TFD_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & TFD_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & TFD_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}

struct kbox_dispatch forward_epoll_create1(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));

    int host_fd = epoll_create1(flags & ~EPOLL_CLOEXEC);
    if (host_fd < 0)
        return kbox_dispatch_errno(errno);

    uint32_t addfd_flags = (flags & EPOLL_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, addfd_flags);
    close(host_fd);
    if (tracee_fd < 0)
        return kbox_dispatch_errno(-tracee_fd);

    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (flags & EPOLL_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);

    return kbox_dispatch_value(tracee_fd);
}
