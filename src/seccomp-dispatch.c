/* SPDX-License-Identifier: MIT */

/* Syscall dispatch engine for the seccomp supervisor.
 *
 * Each intercepted syscall notification is dispatched to a handler that either
 * forwards it through LKL (RETURN) or lets host kernel handle it (CONTINUE).
 * This is the beating heart of kbox: every file open, read, write, stat, and
 * directory operation the tracee makes gets routed through here.
 *
 * Single-threaded dispatch contract
 * ----------------------------------
 * All notification processing runs on a single thread (supervisor loop in
 * seccomp mode, SIGSYS handler in trap/rewrite mode). The following state is
 * protected only by this single-threaded invariant:
 *
 *   dispatch_scratch[]     Static I/O buffer (this file).
 *   kbox_fd_table entries  FD table (fd-table.c).
 *   Path scratch buffers   Translation/literal caches (path.c).
 *   shadow_sockets[]       SLIRP socket array (net-slirp.c).
 *   saved_guest_segv/bus   Fault handler saved actions (procmem.c).
 *   fault_armed            Thread-local; single-threaded guest means
 *                          only one thread ever arms it.
 *
 * If parallel dispatch or multi-threaded guest support is introduced,
 * every item above needs locking or per-thread allocation.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
/* seccomp types via seccomp.h -> seccomp-defs.h */
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>

union kbox_semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/* pidfd_getfd is used to obtain a supervisor copy of a tracee FD that shares
 * the same file description (needed for emulating dup on host-passthrough FDs).
 * Available since Linux 5.6; kbox requires 5.13+ for seccomp USER_NOTIF.
 */
#ifndef __NR_pidfd_open
#if defined(__x86_64__)
#define __NR_pidfd_open 434
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_pidfd_open 434
#endif
#endif
#ifndef __NR_pidfd_getfd
#if defined(__x86_64__)
#define __NR_pidfd_getfd 438
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_pidfd_getfd 438
#endif
#endif
#ifndef __NR_faccessat2
#if defined(__x86_64__)
#define __NR_faccessat2 439
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_faccessat2 439
#endif
#endif
#ifndef __NR_statx
#if defined(__x86_64__)
#define __NR_statx 332
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_statx 291
#endif
#endif

#ifndef __NR_truncate
#if defined(__x86_64__)
#define __NR_truncate 76
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_truncate 45
#endif
#endif
#ifndef __NR_sched_rr_get_interval
#define __NR_sched_rr_get_interval 127
#endif
#ifndef __NR_preadv2
#if defined(__x86_64__)
#define __NR_preadv2 287
#define __NR_pwritev2 328
#elif defined(__aarch64__) || (defined(__riscv) && (__riscv_xlen == 64))
#define __NR_preadv2 287
#define __NR_pwritev2 288
#endif
#endif

#include "dispatch-internal.h"
#include "fd-table.h"
#include "kbox/elf.h"
#include "kbox/identity.h"
#include "kbox/path.h"
#include "lkl-wrap.h"
#include "net.h"
#include "procmem.h"
#include "seccomp.h"

/* Diagnostic helpers, enabled with KBOX_FD_TRACE=1. */
static int fd_trace_enabled(void);
static void fd_trace_table(const char *tag,
                           const struct kbox_fd_table *t,
                           pid_t tgid);

#include "shadow-fd.h"
#include "syscall-nr.h"
#include "vcred.h"

/* Per-thread scratch buffer for I/O dispatch. Each supervisor thread is
 * non-reentrant: only one syscall is dispatched per thread at a time. Using TLS
 * avoids heap allocation from the SIGSYS handler in trap / rewrite mode, where
 * the guest may hold glibc heap locks, while supporting concurrent daemon
 * container threads.
 */
__thread uint8_t dispatch_scratch[KBOX_IO_CHUNK_LEN];


struct kbox_fd_inject_ops {
    int (*addfd)(const struct kbox_supervisor_ctx *ctx,
                 uint64_t cookie,
                 int srcfd,
                 uint32_t newfd_flags);
    int (*addfd_at)(const struct kbox_supervisor_ctx *ctx,
                    uint64_t cookie,
                    int srcfd,
                    int target_fd,
                    uint32_t newfd_flags);
};

static int seccomp_request_addfd(const struct kbox_supervisor_ctx *ctx,
                                 uint64_t cookie,
                                 int srcfd,
                                 uint32_t newfd_flags)
{
    return kbox_notify_addfd(ctx->listener_fd, cookie, srcfd, newfd_flags);
}

static int seccomp_request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                                    uint64_t cookie,
                                    int srcfd,
                                    int target_fd,
                                    uint32_t newfd_flags)
{
    return kbox_notify_addfd_at(ctx->listener_fd, cookie, srcfd, target_fd,
                                newfd_flags);
}

static const struct kbox_fd_inject_ops seccomp_fd_inject_ops = {
    .addfd = seccomp_request_addfd,
    .addfd_at = seccomp_request_addfd_at,
};

static int find_available_tracee_fd(const struct kbox_supervisor_ctx *ctx,
                                    pid_t pid,
                                    int minfd);

/* True when a redirect onto stdin/stdout/stderr lives only in kbox's table. */
static int virtual_stdio_redirect_active(const struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->fd_table)
        return 0;
    for (long fd = 0; fd < 3; fd++) {
        if (kbox_fd_table_get_lkl(ctx->fd_table, fd) >= 0)
            return 1;
    }
    return 0;
}

int request_addfd(const struct kbox_supervisor_ctx *ctx,
                  const struct kbox_syscall_request *req,
                  int srcfd,
                  uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd || !req)
        return -EINVAL;

    /* The kernel hands out the lowest free number. A shell redirect onto fd
     * 0-2 is purely virtual here -- dash closes the real descriptor first --
     * so that number looks free to the kernel and the injected descriptor
     * (the dynamic loader's memfd at exec) landed on it. Its later close then
     * erased the redirect, and the program's output failed with EBADF
     * (ls, id, stat, cp -v >> file). Pick a number the table is not using.
     */
    if (virtual_stdio_redirect_active(ctx) && ctx->fd_inject_ops->addfd_at) {
        int target =
            find_available_tracee_fd(ctx, kbox_syscall_request_pid(req), 0);
        if (target >= 0) {
            int r = ctx->fd_inject_ops->addfd_at(
                ctx, kbox_syscall_request_cookie(req), srcfd, target,
                newfd_flags);
            if (getenv("KBOX_FD_TRACE") && r >= 0)
                fprintf(stderr,
                        "kbofdt: addfd-at pid=%u src=%d fd=%d flags=%#x\n",
                        (unsigned) kbox_syscall_request_pid(req), srcfd, r,
                        newfd_flags);
            return r;
        }
    }
    {
        int r = ctx->fd_inject_ops->addfd(ctx, kbox_syscall_request_cookie(req),
                                          srcfd, newfd_flags);
        if (getenv("KBOX_FD_TRACE") && r >= 0)
            fprintf(stderr, "kbofdt: addfd pid=%u src=%d fd=%d flags=%#x\n",
                    (unsigned) kbox_syscall_request_pid(req), srcfd, r,
                    newfd_flags);
        return r;
    }
}

int request_addfd_at(const struct kbox_supervisor_ctx *ctx,
                     const struct kbox_syscall_request *req,
                     int srcfd,
                     int target_fd,
                     uint32_t newfd_flags)
{
    if (!ctx || !ctx->fd_inject_ops || !ctx->fd_inject_ops->addfd_at || !req)
        return -EINVAL;
    return ctx->fd_inject_ops->addfd_at(ctx, kbox_syscall_request_cookie(req),
                                        srcfd, target_fd, newfd_flags);
}

int request_addfd_passthrough(const struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              int srcfd,
                              uint32_t newfd_flags)
{
    if (!ctx || !req)
        return -EINVAL;

    /* Every fd call is notified and this side decides ownership from its own
     * table, so a passthrough descriptor needs no reserved band: it takes the
     * lowest free number like any other descriptor. */
    return request_addfd(ctx, req, srcfd, newfd_flags);
}

static unsigned ctx_lkl_fd_ref_count(const struct kbox_supervisor_ctx *ctx,
                                     long lkl_fd)
{
    if (!ctx || lkl_fd < 0)
        return 0;
    unsigned total = 0;
    if (ctx->proc_fds && ctx->proc_fd_count > 0) {
        for (size_t i = 0; i < ctx->proc_fd_count; i++) {
            if (ctx->proc_fds[i].table)
                total +=
                    kbox_fd_table_lkl_ref_count(ctx->proc_fds[i].table, lkl_fd);
        }
    } else if (ctx->fd_table) {
        total += kbox_fd_table_lkl_ref_count(ctx->fd_table, lkl_fd);
    }
    if (ctx->pending_forks) {
        for (size_t i = 0; i < ctx->pending_fork_count; i++) {
            if (ctx->pending_forks[i].table)
                total += kbox_fd_table_lkl_ref_count(
                    ctx->pending_forks[i].table, lkl_fd);
        }
    }
    return total;
}

static long ctx_close_lkl_if_unreferenced(struct kbox_supervisor_ctx *ctx,
                                          long lkl_fd,
                                          int maybe_net_socket)
{
    if (lkl_fd < 0)
        return 0;
    unsigned refs = ctx_lkl_fd_ref_count(ctx, lkl_fd);
    if (refs != 0) {
        if (fd_trace_enabled() && refs > 0)
            fprintf(stderr,
                    "kbofdt: lkl_keep fd=%ld refs=%u procs=%zu forks=%zu\n",
                    lkl_fd, refs, ctx->proc_fd_count, ctx->pending_fork_count);
        return 0;
    }
    if (maybe_net_socket && kbox_net_deregister_socket((int) lkl_fd)) {
        /* The bridge closes it once its last bytes are out. The descriptor is
         * gone from the tracee, so no cached metadata may survive it. */
        invalidate_stat_cache_fd(ctx, lkl_fd);
        return 0;
    }
    return lkl_close_and_invalidate(ctx, lkl_fd);
}

/* Identity of the descriptor the tracee holds at a low number.
 *
 * A guest close of a low descriptor runs in the kernel, so kbox does not see
 * it; the number can then be handed to a native pipe or memfd while a routing
 * entry for the closed file is still in the table. Each such entry records the
 * kernel (st_dev, st_ino) behind /proc/<pid>/fd/<n>, which distinguishes even
 * two memfds with the same name ("/memfd:kbox-shadow (deleted)").
 */
uint64_t kbox_guest_fd_identity(pid_t pid, long fd)
{
    char path[64];
    struct stat st;

    if (fd < 0 || fd >= KBOX_FD_TABLE_CAPACITY) {
        errno = EINVAL;
        return 0;
    }
    if (snprintf(path, sizeof(path), "/proc/%d/fd/%ld", (int) pid, fd) >=
        (int) sizeof(path)) {
        errno = ENAMETOOLONG;
        return 0;
    }
    if (stat(path, &st) < 0)
        return 0;
    return kbox_fd_stat_identity((uint64_t) st.st_dev, (uint64_t) st.st_ino);
}

/* Record the descriptor's identity on a low-fd entry that carries LKL state. */
static void note_low_fd_identity(struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 long fd)
{
    struct kbox_fd_entry *entry;

    if (!ctx || !ctx->fd_table || fd < 0 || fd >= KBOX_FD_TABLE_CAPACITY)
        return;
    entry = fd_table_entry(ctx->fd_table, fd);
    if (!entry || entry->lkl_fd < 0)
        return;
    entry->guest_id = kbox_guest_fd_identity(pid, fd);
}

/* Drop the entry of a descriptor that was closed and whose number was reused.
 */
static long remove_fd_table_entry_with_writeback(
    struct kbox_supervisor_ctx *ctx,
    long fd);

static void retire_host_fd_vfd_in_table(struct kbox_supervisor_ctx *ctx,
                                        struct kbox_fd_table *table,
                                        long vfd,
                                        long host_fd)
{
    struct kbox_fd_entry *e = fd_table_entry(table, vfd);
    long lkl_fd;

    if (!e)
        return;
    lkl_fd = e->lkl_fd;
    if (e->shadow_writeback)
        (void) sync_shadow_writeback(ctx, e);
    note_shadow_writeback_close(ctx, e);
    if (lkl_fd >= 0)
        invalidate_stat_cache_fd(ctx, lkl_fd);
    kbox_fd_table_remove(table, vfd);
    kbox_net_forget_fd(host_fd);
    if (lkl_fd >= 0)
        ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 1);
}

void kbox_retire_stale_host_fd_vfd(struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   long host_fd,
                                   int force)
{
    if (!ctx || !ctx->fd_table || host_fd < 0 ||
        host_fd >= KBOX_FD_TABLE_CAPACITY)
        return;

    /* A descriptor's close can run in the kernel without the table hearing
     * about it, so a bridged entry that claims this host_fd stays behind.
     * Retire it, or a new socket, pipe or file on that number is routed to the
     * old LKL object. */
    for (int guard = 0; guard < 16; guard++) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, host_fd);
        struct kbox_fd_entry *e;

        if (vfd < 0)
            break;
        e = fd_table_entry(ctx->fd_table, vfd);
        if (!e || e->lkl_fd < 0)
            break;
        if (!force) {
            if (e->guest_id == 0)
                break;
            uint64_t now = kbox_guest_fd_identity(pid, host_fd);

            if (!kbox_fd_identity_stale(e->guest_id, now, errno))
                break;
        }
        retire_host_fd_vfd_in_table(ctx, ctx->fd_table, vfd, host_fd);
    }
}

static void sweep_bridged_table(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_table *table,
                                pid_t owner_pid)
{
    if (!table || owner_pid <= 0 || table->low_host_count == 0)
        return;
    for (size_t w = 0; w < KBOX_FD_TABLE_MAX / 64; w++) {
        uint64_t bits = table->low_host_bitmap[w];

        while (bits) {
            unsigned b = (unsigned) __builtin_ctzll(bits);
            long i = (long) (w * 64 + b);
            struct kbox_fd_entry *e = &table->slots[i];

            bits &= bits - 1;
            if (e->lkl_fd < 0 || e->shadow_sp < 0 || e->host_fd < 0 ||
                e->host_fd == i || e->guest_id == 0)
                continue;
            uint64_t now = kbox_guest_fd_identity(owner_pid, e->host_fd);

            if (kbox_fd_identity_stale(e->guest_id, now, errno))
                retire_host_fd_vfd_in_table(ctx, table, i, e->host_fd);
        }
    }
}

int kbox_has_active_bridged_sockets(const struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !kbox_net_is_active())
        return 0;
    if (ctx->fd_table && ctx->fd_table->low_host_count > 0)
        return 1;
    for (size_t i = 0; i < ctx->proc_fd_count; i++) {
        if (ctx->proc_fds[i].table &&
            ctx->proc_fds[i].table->low_host_count > 0)
            return 1;
    }
    return 0;
}

void kbox_sweep_stale_bridged_sockets_periodic(struct kbox_supervisor_ctx *ctx,
                                               pid_t fallback_pid)
{
    struct timespec ts;
    uint64_t now_ns;

    if (!kbox_has_active_bridged_sockets(ctx))
        return;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return;
    now_ns = (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
    if (ctx->last_bridged_sweep_ns != 0 &&
        now_ns - ctx->last_bridged_sweep_ns < 10000000ULL)
        return;
    ctx->last_bridged_sweep_ns = now_ns;
    kbox_sweep_stale_bridged_sockets(ctx, fallback_pid);
}

void kbox_sweep_stale_bridged_sockets(struct kbox_supervisor_ctx *ctx,
                                      pid_t fallback_pid)
{
    int swept_active = 0;

    if (!ctx)
        return;
    for (size_t i = 0; i < ctx->proc_fd_count; i++) {
        struct kbox_proc_fd_entry *p = &ctx->proc_fds[i];

        if (!p->table || p->tgid <= 0)
            continue;
        if (p->table == ctx->fd_table)
            swept_active = 1;
        sweep_bridged_table(ctx, p->table, p->tgid);
    }
    if (!swept_active && ctx->fd_table && fallback_pid > 0)
        sweep_bridged_table(ctx, ctx->fd_table, fallback_pid);
}

static void drop_reused_low_fd_entry(struct kbox_supervisor_ctx *ctx,
                                     pid_t pid,
                                     long fd)
{
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    long lkl_fd;

    if (!entry)
        return;
    lkl_fd = entry->lkl_fd;
    if (getenv("KBOX_TRACE"))
        fprintf(stderr,
                "kbox: low fd %ld reused (lkl=%ld); dropping the stale entry\n",
                fd, lkl_fd);
    if (lkl_fd >= 0) {
        struct kbox_lkl_stat st;

        if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &st) == 0)
            kbox_lock_release_file(&ctx->locks, pid, (int) lkl_fd, st.st_dev,
                                   st.st_ino);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }
    /* What forward_close would have done for this descriptor. The close ran in
     * the kernel, so a pending writeback lives until here; its bytes still win
     * over the LKL inode for any reader that asks through kbox, but the flush
     * must happen before the shadow is released. */
    (void) remove_fd_table_entry_with_writeback(ctx, fd);
    kbox_net_forget_fd(fd);
    if (lkl_fd >= 0)
        ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 0);
}

static void sweep_stale_low_fds(struct kbox_supervisor_ctx *ctx,
                                pid_t pid,
                                long max_fd)
{
    long limit;
    long fd;

    if (!ctx || !ctx->fd_table || pid <= 0)
        return;
    limit = max_fd < KBOX_FD_TABLE_CAPACITY ? max_fd : KBOX_FD_TABLE_CAPACITY;

    for (fd = 0; fd < limit; fd++) {
        struct kbox_fd_entry *entry = &ctx->fd_table->slots[fd];
        char path[64];
        struct stat st;

        if (entry->lkl_fd == -1)
            continue;
        if (snprintf(path, sizeof(path), "/proc/%d/fd/%ld", (int) pid, fd) >=
            (int) sizeof(path))
            continue;
        if (lstat(path, &st) < 0) {
            if (errno == ENOENT) {
                if (entry->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                    kbox_fd_table_remove(ctx->fd_table, fd);
                else
                    drop_reused_low_fd_entry(ctx, pid, fd);
            }
        } else if (entry->guest_id != 0) {
            uint64_t now = kbox_guest_fd_identity(pid, fd);

            if (kbox_fd_identity_stale(entry->guest_id, now, errno))
                drop_reused_low_fd_entry(ctx, pid, fd);
        }
    }
}

/* Validate the low descriptors a syscall routes through the table.
 *
 * Native pipes and native closes are what make pipe() and close() immune to
 * the interrupted-notification defect (item 33): the kernel creates and closes
 * those descriptors itself. The cost is that a close is no longer observed, so
 * before any data is routed through a low-fd entry, confirm that the tracee
 * still holds the object the entry was made for. A mismatch means the number
 * was closed and reused; the entry is dropped and the call runs against the
 * descriptor the tracee really has.
 */
static void validate_low_fd_routing(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h;
    long nr;
    long fds[2] = {-1, -1};
    pid_t pid;
    int i;

    if (!ctx || !ctx->fd_table || !req || !ctx->host_nrs)
        return;
    if (req->source != KBOX_SYSCALL_SOURCE_SECCOMP)
        return;
    h = ctx->host_nrs;
    nr = (long) req->nr;
    pid = kbox_syscall_request_pid(req);

    if (kbox_nr_is_fd_file_io(nr, h) || nr == (long) h->preadv2 ||
        nr == (long) h->pwritev2 || nr == (long) h->lseek ||
        nr == (long) h->fstat || nr == (long) h->fstatfs ||
        nr == (long) h->fcntl || nr == (long) h->dup ||
        nr == (long) h->ftruncate || nr == (long) h->fallocate ||
        nr == (long) h->fsync || nr == (long) h->fdatasync ||
        nr == (long) h->sync_file_range || nr == (long) h->fadvise64 ||
        nr == (long) h->flock || nr == (long) h->ioctl ||
        nr == (long) h->getdents64 || nr == (long) h->getdents ||
        nr == (long) h->fchdir || nr == (long) h->fchmod ||
        nr == (long) h->fchown || nr == (long) h->epoll_ctl ||
        nr == (long) h->execveat || nr == (long) h->connect ||
        nr == (long) h->bind || nr == (long) h->listen ||
        nr == (long) h->accept || nr == (long) h->accept4 ||
        nr == (long) h->sendto || nr == (long) h->sendmmsg ||
        nr == (long) h->recvfrom || nr == (long) h->recvmsg ||
        nr == (long) h->sendmsg || nr == (long) h->getsockopt ||
        nr == (long) h->setsockopt || nr == (long) h->getsockname ||
        nr == (long) h->getpeername || nr == (long) h->shutdown) {
        fds[0] = (long) req->args[0];
    } else if (nr == (long) h->dup2 || nr == (long) h->dup3) {
        fds[0] = (long) req->args[0];
        fds[1] = (long) req->args[1];
    } else if (nr == (long) h->openat || nr == (long) h->openat2 ||
               nr == (long) h->newfstatat || nr == (long) h->statx ||
               nr == (long) h->faccessat || nr == (long) h->faccessat2 ||
               nr == (long) h->fchmodat || nr == (long) h->fchmodat2 ||
               nr == (long) h->fchownat || nr == (long) h->utimensat ||
               nr == (long) h->readlinkat || nr == (long) h->mkdirat ||
               nr == (long) h->mknodat || nr == (long) h->unlinkat) {
        /* A stale directory entry would move the call into a directory the
         * guest can no longer name, so the dirfd is checked too. */
        fds[0] = (long) req->args[0];
    } else if (nr == (long) h->renameat || nr == (long) h->renameat2 ||
               nr == (long) h->linkat) {
        fds[0] = (long) req->args[0];
        fds[1] = (long) req->args[2];
    } else if (nr == (long) h->symlinkat) {
        fds[0] = (long) req->args[1];
    } else if (nr == (long) h->sendfile || nr == (long) h->copy_file_range) {
        fds[0] = (long) req->args[0];
        fds[1] = (long) req->args[1];
    } else if (nr == (long) h->mmap) {
        fds[0] = (long) req->args[4];
    }

    for (i = 0; i < 2; i++) {
        struct kbox_fd_entry *entry;
        long fd = fds[i];

        if (fd < 0 || fd >= KBOX_FD_TABLE_CAPACITY)
            continue;
        kbox_retire_stale_host_fd_vfd(ctx, pid, fd, 0);
        entry = fd_table_entry(ctx->fd_table, fd);
        if (!entry || entry->lkl_fd < 0 || entry->guest_id == 0)
            continue;
        uint64_t now = kbox_guest_fd_identity(pid, fd);
        if (!kbox_fd_identity_stale(entry->guest_id, now, errno))
            continue;
        drop_reused_low_fd_entry(ctx, pid, fd);
    }
}

static int read_proc_tgid_ppid(pid_t pid,
                               pid_t *tgid_out,
                               pid_t *ppid_out,
                               char *state_out)
{
    char path[64];
    char buf[1024];
    int fd;
    ssize_t n;
    pid_t tgid = -1;
    pid_t ppid = -1;
    char state = '\0';

    snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -ENOENT;
    buf[n] = '\0';

    for (char *p = buf; *p;) {
        if (strncmp(p, "State:", 6) == 0) {
            char *q = p + 6;
            while (*q == ' ' || *q == '\t')
                q++;
            state = *q;
        } else if (strncmp(p, "Tgid:", 5) == 0) {
            tgid = (pid_t) strtol(p + 5, NULL, 10);
        } else if (strncmp(p, "PPid:", 5) == 0) {
            ppid = (pid_t) strtol(p + 5, NULL, 10);
        }
        if (state && tgid > 0 && ppid >= 0)
            break;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        p = nl + 1;
    }
    if (tgid <= 0)
        return -ENOENT;
    if (tgid_out)
        *tgid_out = tgid;
    if (ppid_out)
        *ppid_out = ppid;
    if (state_out)
        *state_out = state;
    return 0;
}

static struct kbox_proc_fd_entry *find_proc_fd_entry(
    struct kbox_supervisor_ctx *ctx,
    pid_t tgid)
{
    if (!ctx || !ctx->proc_fds)
        return NULL;
    for (size_t i = 0; i < ctx->proc_fd_count; i++) {
        if (ctx->proc_fds[i].tgid == tgid)
            return &ctx->proc_fds[i];
    }
    return NULL;
}

static void set_active_host_cwd(struct kbox_supervisor_ctx *ctx,
                                const char *cwd)
{
    if (!ctx)
        return;
    if (!cwd || cwd[0] == '\0') {
        ctx->host_cwd[0] = '\0';
        if (ctx->active_proc)
            ctx->active_proc->host_cwd[0] = '\0';
        return;
    }
    snprintf(ctx->host_cwd, sizeof(ctx->host_cwd), "%s", cwd);
    if (ctx->active_proc)
        snprintf(ctx->active_proc->host_cwd, sizeof(ctx->active_proc->host_cwd),
                 "%s", cwd);
}

static void sync_ctx_host_cwd(struct kbox_supervisor_ctx *ctx,
                              struct kbox_proc_fd_entry *e)
{
    const char *src = e ? e->host_cwd : "";
    if (strcmp(ctx->host_cwd, src) != 0)
        invalidate_translated_path_cache(ctx);
    if (src[0] == '\0')
        ctx->host_cwd[0] = '\0';
    else
        snprintf(ctx->host_cwd, sizeof(ctx->host_cwd), "%s", src);
    ctx->active_proc = e;
}

static void release_table_entries_close_lkl(struct kbox_supervisor_ctx *ctx,
                                            struct kbox_fd_table *t)
{
    if (!t)
        return;

    for (long fd = 0; fd < KBOX_FD_TABLE_CAPACITY; fd++) {
        long lkl = t->slots[fd].lkl_fd;
        if (lkl == -1)
            continue;
        if (t->slots[fd].shadow_writeback)
            note_shadow_writeback_close(ctx, &t->slots[fd]);
        kbox_fd_table_remove(t, fd);
        if (lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
    }
}

static void dup_table_supervisor_fds(struct kbox_supervisor_ctx *ctx,
                                     struct kbox_fd_table *t)
{
    for (long fd = 0; fd < KBOX_FD_TABLE_CAPACITY; fd++) {
        struct kbox_fd_entry *e = &t->slots[fd];
        if (e->lkl_fd == -1)
            continue;
        if (e->shadow_sp >= 0) {
            int dup_sp = fcntl(e->shadow_sp, F_DUPFD_CLOEXEC, 3);
            e->shadow_sp = dup_sp >= 0 ? dup_sp : -1;
            if (e->shadow_writeback) {
                if (dup_sp >= 0 && ctx)
                    ctx->active_writeback_shadows++;
                else
                    e->shadow_writeback = 0;
            }
        } else {
            e->shadow_writeback = 0;
            if (e->host_fd >= 0) {
                int dup_h = fcntl((int) e->host_fd, F_DUPFD_CLOEXEC, 3);
                e->host_fd = dup_h >= 0 ? dup_h : -1;
            }
        }
        if (e->host_sv_fd >= 0) {
            int dup_sv = fcntl(e->host_sv_fd, F_DUPFD_CLOEXEC, 3);
            e->host_sv_fd = dup_sv >= 0 ? dup_sv : -1;
        }
    }
}

static void sync_table_writebacks(struct kbox_supervisor_ctx *ctx,
                                  struct kbox_fd_table *t,
                                  int deregister);

static void reap_dead_proc_fds(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->proc_fds)
        return;

    for (size_t i = 0; i < ctx->proc_fd_count;) {
        if (!ctx->proc_fds[i].owned) {
            i++;
            continue;
        }
        pid_t tgid = ctx->proc_fds[i].tgid;
        char state = '\0';
        int rc = read_proc_tgid_ppid(tgid, NULL, NULL, &state);
        int alive;

        /* A failed /proc read is not proof of death. Freeing the FD table of a
         * live process hands its next syscall a dangling table, which surfaces
         * as arbitrary memory corruption (CPython crashed inside the pickle
         * module while a multiprocessing pool churned through workers). Only a
         * definite zombie, or a tgid the kernel rejects, counts as dead.
         */
        if (rc < 0)
            alive = kill(tgid, 0) == 0 || errno == EPERM;
        else
            alive = state != 'Z' && state != 'X';
        if (alive) {
            i++;
            continue;
        }

        struct kbox_fd_table *dead_tab = ctx->proc_fds[i].table;
        fd_trace_table("reap", dead_tab, tgid);
        /* A process killed by a signal never reaches exit_group. */
        sync_table_writebacks(ctx, dead_tab, 0);
        if (ctx->fd_table == dead_tab)
            ctx->fd_table = ctx->root_fd_table;
        ctx->active_proc = NULL;
        ctx->proc_fds[i] = ctx->proc_fds[ctx->proc_fd_count - 1];
        ctx->proc_fd_count--;

        for (size_t c = 0; c < KBOX_PID_TGID_CACHE_MAX; c++) {
            if (ctx->pid_tgid_cache[c].tgid == tgid) {
                ctx->pid_tgid_cache[c].pid = 0;
                ctx->pid_tgid_cache[c].tgid = 0;
            }
        }
        /* A process killed by a signal never reaches exit_group, so nothing
         * flushed the writable shadows of its own descriptor table. Reaping it
         * is the last moment those memfds can be copied back; after free() the
         * data is gone. faulthandler's crash tests write the traceback from the
         * dying child and the parent reads it once waitpid returns.
         */
        sync_table_writebacks(ctx, dead_tab, 1);
        release_table_entries_close_lkl(ctx, dead_tab);
        free(dead_tab);
    }
}

static void release_pending_fork_slot(struct kbox_supervisor_ctx *ctx,
                                      size_t idx)
{
    if (!ctx || !ctx->pending_forks || idx >= ctx->pending_fork_count)
        return;

    struct kbox_fd_table *snap = ctx->pending_forks[idx].table;
    for (size_t i = idx; i + 1 < ctx->pending_fork_count; i++)
        ctx->pending_forks[i] = ctx->pending_forks[i + 1];
    ctx->pending_fork_count--;
    memset(&ctx->pending_forks[ctx->pending_fork_count], 0,
           sizeof(ctx->pending_forks[0]));

    if (snap) {
        release_table_entries_close_lkl(ctx, snap);
        free(snap);
    }
}

static void reap_dead_pending_forks(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->pending_forks)
        return;

    for (size_t i = 0; i < ctx->pending_fork_count;) {
        char state = '\0';
        int rc = read_proc_tgid_ppid(ctx->pending_forks[i].parent_tgid, NULL,
                                     NULL, &state);
        if (rc < 0 || state == 'Z' || state == 'X') {
            release_pending_fork_slot(ctx, i);
            continue;
        }
        i++;
    }
}

/* Snapshot the parent's FD table when clone/clone3/fork/vfork creates a child
 * with a private file descriptor table (!(flags & (CLONE_THREAD|CLONE_FILES))).
 * This closes the race where the parent closes an inherited FD before the
 * child makes its first seccomp-trapped syscall.
 */
void kbox_dispatch_snapshot_fork(struct kbox_supervisor_ctx *ctx,
                                 pid_t caller_pid)
{
    if (!ctx || !ctx->fd_table || caller_pid <= 0)
        return;

    pid_t parent_tgid = 0;
    const char *cwd = ctx->host_cwd;
    if (ctx->active_proc && ctx->active_proc->tgid > 0) {
        parent_tgid = ctx->active_proc->tgid;
        cwd = ctx->active_proc->host_cwd;
    } else if (read_proc_tgid_ppid(caller_pid, &parent_tgid, NULL, NULL) < 0 ||
               parent_tgid <= 0) {
        return;
    }

    if (!ctx->pending_forks) {
        ctx->pending_forks =
            calloc(KBOX_PENDING_FORKS_MAX, sizeof(*ctx->pending_forks));
        if (!ctx->pending_forks)
            return;
    }

    if (ctx->pending_fork_count >= KBOX_PENDING_FORKS_MAX)
        reap_dead_pending_forks(ctx);
    if (ctx->pending_fork_count >= KBOX_PENDING_FORKS_MAX)
        release_pending_fork_slot(ctx, 0);

    struct kbox_fd_table *snap_tab = calloc(1, sizeof(*snap_tab));
    if (!snap_tab)
        return;
    memcpy(snap_tab, ctx->fd_table, sizeof(*snap_tab));
    dup_table_supervisor_fds(ctx, snap_tab);

    struct kbox_pending_fork *pf =
        &ctx->pending_forks[ctx->pending_fork_count++];
    pf->parent_tgid = parent_tgid;
    pf->table = snap_tab;
    snprintf(pf->host_cwd, sizeof(pf->host_cwd), "%s", cwd ? cwd : "/");
    snprintf(pf->lkl_cwd, sizeof(pf->lkl_cwd), "%s",
             (ctx->active_proc && ctx->active_proc->lkl_cwd[0])
                 ? ctx->active_proc->lkl_cwd
                 : ctx->lkl_cwd_cur);
    pf->umask = ctx->active_proc ? ctx->active_proc->umask : ctx->guest_umask;
    pf->rlimit_nofile_cur =
        ctx->active_proc ? ctx->active_proc->rlimit_nofile_cur : 65536;
    pf->rlimit_nofile_max =
        ctx->active_proc ? ctx->active_proc->rlimit_nofile_max : 1048576;
}

static int take_pending_fork_table(struct kbox_supervisor_ctx *ctx,
                                   pid_t parent_tgid,
                                   struct kbox_fd_table **out_tab,
                                   char *out_cwd,
                                   size_t cwd_len,
                                   char *out_lkl_cwd,
                                   size_t lkl_cwd_len,
                                   unsigned *out_umask,
                                   uint64_t *out_rlim_cur,
                                   uint64_t *out_rlim_max)
{
    if (!ctx || !ctx->pending_forks || parent_tgid <= 0)
        return 0;

    for (size_t i = 0; i < ctx->pending_fork_count; i++) {
        if (ctx->pending_forks[i].parent_tgid != parent_tgid)
            continue;
        *out_tab = ctx->pending_forks[i].table;
        snprintf(out_cwd, cwd_len, "%s", ctx->pending_forks[i].host_cwd);
        snprintf(out_lkl_cwd, lkl_cwd_len, "%s", ctx->pending_forks[i].lkl_cwd);
        if (out_umask)
            *out_umask = ctx->pending_forks[i].umask;
        if (out_rlim_cur)
            *out_rlim_cur = ctx->pending_forks[i].rlimit_nofile_cur;
        if (out_rlim_max)
            *out_rlim_max = ctx->pending_forks[i].rlimit_nofile_max;
        for (size_t j = i; j + 1 < ctx->pending_fork_count; j++)
            ctx->pending_forks[j] = ctx->pending_forks[j + 1];
        ctx->pending_fork_count--;
        memset(&ctx->pending_forks[ctx->pending_fork_count], 0,
               sizeof(ctx->pending_forks[0]));
        return 1;
    }
    return 0;
}

static void select_proc_fd_table_impl(struct kbox_supervisor_ctx *ctx,
                                      pid_t pid)
{
    if (!ctx || !ctx->fd_table || ctx->child_pid <= 0 || pid <= 0)
        return;

    if (!ctx->proc_fds) {
        ctx->root_fd_table = ctx->fd_table;
        ctx->proc_fds = calloc(KBOX_PROC_FD_TABLES_MAX, sizeof(*ctx->proc_fds));
        if (!ctx->proc_fds)
            return;
        ctx->proc_fds[0].tgid = ctx->child_pid;
        ctx->proc_fds[0].owned = 0;
        ctx->proc_fds[0].table = ctx->root_fd_table;
        snprintf(ctx->proc_fds[0].host_cwd, sizeof(ctx->proc_fds[0].host_cwd),
                 "%s", ctx->host_cwd);
        if (ctx->lkl_cwd_cur[0] == '\0' &&
            kbox_lkl_getcwd(ctx->sysnrs, ctx->lkl_cwd_cur,
                            (long) sizeof(ctx->lkl_cwd_cur)) < 0)
            ctx->lkl_cwd_cur[0] = '\0';
        snprintf(ctx->proc_fds[0].lkl_cwd, sizeof(ctx->proc_fds[0].lkl_cwd),
                 "%s", ctx->lkl_cwd_cur);
        ctx->proc_fds[0].umask = ctx->guest_umask;
        ctx->proc_fds[0].rlimit_nofile_cur = 65536;
        ctx->proc_fds[0].rlimit_nofile_max = 1048576;
        ctx->proc_fd_count = 1;
        ctx->active_proc = &ctx->proc_fds[0];
    }

    if (fd_trace_enabled() && pid != ctx->child_pid)
        fprintf(stderr, "kbofdt: select child pid=%d count=%zu\n", (int) pid,
                ctx->proc_fd_count);
    size_t slot = (size_t) pid % KBOX_PID_TGID_CACHE_MAX;
    pid_t tgid = 0;
    pid_t ppid = -1;
    if (ctx->pid_tgid_cache[slot].pid == pid &&
        ctx->pid_tgid_cache[slot].tgid > 0) {
        tgid = ctx->pid_tgid_cache[slot].tgid;
    } else {
        if (read_proc_tgid_ppid(pid, &tgid, &ppid, NULL) < 0) {
            if (fd_trace_enabled())
                fprintf(stderr, "kbofdt: select pid=%d no /proc entry\n",
                        (int) pid);
            return;
        }
        ctx->pid_tgid_cache[slot].pid = pid;
        ctx->pid_tgid_cache[slot].tgid = tgid;
    }

    struct kbox_proc_fd_entry *existing = find_proc_fd_entry(ctx, tgid);
    if (existing) {
        ctx->fd_table = existing->table;
        sync_ctx_host_cwd(ctx, existing);
        return;
    }

    if (ppid < 0 && read_proc_tgid_ppid(pid, &tgid, &ppid, NULL) < 0)
        return;

    if (ctx->proc_fd_count >= KBOX_PROC_FD_TABLES_MAX - 1 ||
        ctx->proc_fd_count >= 16)
        reap_dead_proc_fds(ctx);
    if (ctx->pending_fork_count >= 16)
        reap_dead_pending_forks(ctx);
    if (ctx->proc_fd_count >= KBOX_PROC_FD_TABLES_MAX) {
        ctx->fd_table = ctx->root_fd_table;
        sync_ctx_host_cwd(ctx, &ctx->proc_fds[0]);
        return;
    }

    struct kbox_proc_fd_entry *parent_entry = NULL;
    struct kbox_fd_table *child_tab = NULL;
    char child_cwd[KBOX_MAX_PATH];
    char child_lkl_cwd[KBOX_MAX_PATH];
    unsigned child_umask = ctx->guest_umask;
    uint64_t child_rlim_cur = 65536;
    uint64_t child_rlim_max = 1048576;
    child_cwd[0] = '\0';
    child_lkl_cwd[0] = '\0';

    pid_t walk = ppid;
    for (int hop = 0; hop < 4 && walk > 1 && !parent_entry; hop++) {
        pid_t w_tgid = 0;
        pid_t w_ppid = -1;
        if (read_proc_tgid_ppid(walk, &w_tgid, &w_ppid, NULL) < 0)
            break;
        if (take_pending_fork_table(ctx, w_tgid, &child_tab, child_cwd,
                                    sizeof(child_cwd), child_lkl_cwd,
                                    sizeof(child_lkl_cwd), &child_umask,
                                    &child_rlim_cur, &child_rlim_max))
            break;
        parent_entry = find_proc_fd_entry(ctx, w_tgid);
        walk = w_ppid;
    }

    if (!child_tab) {
        if (!parent_entry)
            parent_entry = &ctx->proc_fds[0];
        struct kbox_fd_table *parent_tab =
            parent_entry->table ? parent_entry->table : ctx->root_fd_table;

        child_tab = calloc(1, sizeof(*child_tab));
        if (!child_tab) {
            ctx->fd_table = ctx->root_fd_table;
            sync_ctx_host_cwd(ctx, &ctx->proc_fds[0]);
            return;
        }
        memcpy(child_tab, parent_tab, sizeof(*child_tab));
        dup_table_supervisor_fds(ctx, child_tab);
        snprintf(child_cwd, sizeof(child_cwd), "%s", parent_entry->host_cwd);
        snprintf(child_lkl_cwd, sizeof(child_lkl_cwd), "%s",
                 parent_entry->lkl_cwd);
        child_umask = parent_entry->umask;
        child_rlim_cur = parent_entry->rlimit_nofile_cur;
        child_rlim_max = parent_entry->rlimit_nofile_max;
    }

    fd_trace_table(parent_entry && child_tab == parent_entry->table
                       ? "shared"
                       : "new-child",
                   child_tab, tgid);
    struct kbox_proc_fd_entry *ce = &ctx->proc_fds[ctx->proc_fd_count];
    ce->tgid = tgid;
    ce->owned = 1;
    ce->table = child_tab;
    snprintf(ce->host_cwd, sizeof(ce->host_cwd), "%s", child_cwd);
    snprintf(ce->lkl_cwd, sizeof(ce->lkl_cwd), "%s", child_lkl_cwd);
    ce->umask = child_umask;
    ce->rlimit_nofile_cur = child_rlim_cur;
    ce->rlimit_nofile_max = child_rlim_max;
    ctx->proc_fd_count++;
    ctx->fd_table = child_tab;
    sync_ctx_host_cwd(ctx, ce);
}

/* Point LKL's (single, container-wide) cwd at the calling process's own. */
static void sync_lkl_cwd(struct kbox_supervisor_ctx *ctx)
{
    struct kbox_proc_fd_entry *e;

    if (!ctx)
        return;
    e = ctx->active_proc;

    if (!e || e->lkl_cwd[0] == '\0' ||
        strcmp(e->lkl_cwd, ctx->lkl_cwd_cur) == 0)
        return;
    if (kbox_lkl_chdir(ctx->sysnrs, e->lkl_cwd) >= 0) {
        snprintf(ctx->lkl_cwd_cur, sizeof(ctx->lkl_cwd_cur), "%s", e->lkl_cwd);
        invalidate_translated_path_cache(ctx);
    }
}

/* Point LKL's (single, container-wide) umask at the calling process's own. */
static void sync_lkl_umask(struct kbox_supervisor_ctx *ctx)
{
    unsigned want;

    if (!ctx)
        return;
    want = ctx->active_proc ? ctx->active_proc->umask : ctx->guest_umask;
    ctx->guest_umask = want;
    if (want != ctx->lkl_umask_cur) {
        if (kbox_lkl_umask(ctx->sysnrs, (long) want) >= 0)
            ctx->lkl_umask_cur = want;
    }
}

static void select_proc_fd_table(struct kbox_supervisor_ctx *ctx, pid_t pid)
{
    struct kbox_fd_table *prev = ctx ? ctx->fd_table : NULL;
    pid_t prev_tgid = ctx && ctx->active_proc ? ctx->active_proc->tgid : 0;

    select_proc_fd_table_impl(ctx, pid);
    if (fd_trace_enabled() && ctx && ctx->fd_table != prev)
        fprintf(stderr,
                "kbofdt: switch pid=%d table %p(tgid=%d) -> %p(tgid=%d)\n",
                (int) pid, (const void *) prev, (int) prev_tgid,
                (const void *) ctx->fd_table,
                ctx->active_proc ? (int) ctx->active_proc->tgid : -1);
    sync_lkl_cwd(ctx);
    sync_lkl_umask(ctx);
}

/* After a successful LKL chdir/fchdir: remember the new cwd for the caller. */
static void record_lkl_cwd(struct kbox_supervisor_ctx *ctx)
{
    char cwd[KBOX_MAX_PATH];

    if (kbox_lkl_getcwd(ctx->sysnrs, cwd, (long) sizeof(cwd)) < 0)
        return;
    snprintf(ctx->lkl_cwd_cur, sizeof(ctx->lkl_cwd_cur), "%s", cwd);
    if (ctx->active_proc)
        snprintf(ctx->active_proc->lkl_cwd, sizeof(ctx->active_proc->lkl_cwd),
                 "%s", cwd);
}

void kbox_dispatch_cleanup_proc_fds(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->pending_forks) {
        while (ctx->pending_fork_count > 0)
            release_pending_fork_slot(ctx, ctx->pending_fork_count - 1);
        free(ctx->pending_forks);
        ctx->pending_forks = NULL;
    }
    if (ctx->root_fd_table)
        ctx->fd_table = ctx->root_fd_table;
    if (ctx->proc_fds) {
        for (size_t i = 0; i < ctx->proc_fd_count; i++) {
            if (ctx->proc_fds[i].owned && ctx->proc_fds[i].table) {
                release_table_entries_close_lkl(ctx, ctx->proc_fds[i].table);
                free(ctx->proc_fds[i].table);
                ctx->proc_fds[i].table = NULL;
            }
        }
        free(ctx->proc_fds);
        ctx->proc_fds = NULL;
        ctx->proc_fd_count = 0;
    }
    if (ctx->fd_table)
        release_table_entries_close_lkl(ctx, ctx->fd_table);
}

void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req)
{
    if (!ctx || !req)
        return;

    ctx->active_guest_mem = req->guest_mem;
    if (!ctx->active_guest_mem.ops) {
        ctx->active_guest_mem.ops = &kbox_process_vm_guest_mem_ops;
        ctx->active_guest_mem.opaque = (uintptr_t) req->pid;
    }
    ctx->guest_mem_ops = ctx->active_guest_mem.ops;
    if (!ctx->fd_inject_ops)
        ctx->fd_inject_ops = &seccomp_fd_inject_ops;
    if (ctx->pending_reap) {
        ctx->pending_reap = 0;
        reap_dead_proc_fds(ctx);
    }
    if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
        select_proc_fd_table(ctx, req->pid);
}

/* The pid argument is not decoration.
 *
 * The active guest memory is the process whose notification is being handled.
 * Some callers write to a different process: a parked recvfrom completes on a
 * poll before the next notification is dispatched, and its payload belongs to
 * the process that issued the recvfrom, not to whoever is asking now. Writing
 * through the active guest put those bytes into the requesting process's
 * address space, at an address that means something else there -- arbitrary
 * corruption in an unrelated guest that happens to be running, visible only
 * when two processes overlap in time.
 */
static struct kbox_guest_mem active_guest_for(
    const struct kbox_supervisor_ctx *ctx,
    pid_t pid)
{
    struct kbox_guest_mem gm = ctx->active_guest_mem;

    if (gm.ops == &kbox_process_vm_guest_mem_ops && pid != 0)
        gm.opaque = (uintptr_t) pid;
    return gm;
}

/* Say it out loud when a call reaches a process other than the requester. */
static void trace_guest_pid_mismatch(const struct kbox_supervisor_ctx *ctx,
                                     pid_t pid,
                                     const char *what,
                                     uint64_t addr,
                                     size_t len)
{
    if (!getenv("KBOX_TRACE"))
        return;
    if (ctx->active_guest_mem.ops != &kbox_process_vm_guest_mem_ops)
        return;
    if ((uintptr_t) pid == ctx->active_guest_mem.opaque)
        return;
    fprintf(stderr,
            "kbox: %s pid=%d while request pid=%llu addr=0x%llx len=%zu\n",
            what, (int) pid, (unsigned long long) ctx->active_guest_mem.opaque,
            (unsigned long long) addr, len);
}

int guest_mem_read(const struct kbox_supervisor_ctx *ctx,
                   pid_t pid,
                   uint64_t remote_addr,
                   void *out,
                   size_t len)
{
    struct kbox_guest_mem gm = active_guest_for(ctx, pid);

    trace_guest_pid_mismatch(ctx, pid, "read", remote_addr, len);
    return kbox_guest_mem_read(&gm, remote_addr, out, len);
}

int guest_mem_write(const struct kbox_supervisor_ctx *ctx,
                    pid_t pid,
                    uint64_t remote_addr,
                    const void *in,
                    size_t len)
{
    struct kbox_guest_mem gm = active_guest_for(ctx, pid);

    trace_guest_pid_mismatch(ctx, pid, "write", remote_addr, len);
    return kbox_guest_mem_write(&gm, remote_addr, in, len);
}

int guest_mem_write_force(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          const void *in,
                          size_t len)
{
    struct kbox_guest_mem gm = active_guest_for(ctx, pid);

    trace_guest_pid_mismatch(ctx, pid, "write-force", remote_addr, len);
    return kbox_guest_mem_write_force(&gm, remote_addr, in, len);
}

int guest_mem_read_string(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          uint64_t remote_addr,
                          char *buf,
                          size_t max_len)
{
    struct kbox_guest_mem gm = active_guest_for(ctx, pid);

    trace_guest_pid_mismatch(ctx, pid, "read-string", remote_addr, max_len);
    return kbox_guest_mem_read_string(&gm, remote_addr, buf, max_len);
}

int guest_mem_read_open_how(const struct kbox_supervisor_ctx *ctx,
                            pid_t pid,
                            uint64_t remote_addr,
                            uint64_t size,
                            struct kbox_open_how *out)
{
    struct kbox_guest_mem gm = active_guest_for(ctx, pid);

    trace_guest_pid_mismatch(ctx, pid, "read-open-how", remote_addr,
                             (size_t) size);
    return kbox_guest_mem_read_open_how(&gm, remote_addr, size, out);
}

/* Stat ABI conversion. */

/* Convert LKL's generic-arch stat layout to the host's struct stat.
 *
 * LKL always fills stat buffers using the asm-generic layout regardless of the
 * host architecture. On x86_64 the two layouts differ:
 *   generic: st_mode (u32) at offset 16, st_nlink (u32) at offset 20
 *   x86_64:  st_nlink (u64) at offset 16, st_mode (u32) at offset 24
 *
 * On aarch64 the kernel uses the generic layout, but C library's struct stat
 * may still have different padding, so convert explicitly on all arch.
 */
void kbox_lkl_stat_to_host(const struct kbox_lkl_stat *src, struct stat *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->st_dev = (dev_t) src->st_dev;
    dst->st_ino = (ino_t) src->st_ino;
    dst->st_mode = (mode_t) src->st_mode;
    dst->st_nlink = (nlink_t) src->st_nlink;
    dst->st_uid = (uid_t) src->st_uid;
    dst->st_gid = (gid_t) src->st_gid;
    dst->st_rdev = (dev_t) src->st_rdev;
    dst->st_size = (off_t) src->st_size;
    dst->st_blksize = (blksize_t) src->st_blksize;
    dst->st_blocks = (blkcnt_t) src->st_blocks;
    dst->st_atim.tv_sec = (time_t) src->st_atime_sec;
    dst->st_atim.tv_nsec = (long) src->st_atime_nsec;
    dst->st_mtim.tv_sec = (time_t) src->st_mtime_sec;
    dst->st_mtim.tv_nsec = (long) src->st_mtime_nsec;
    dst->st_ctim.tv_sec = (time_t) src->st_ctime_sec;
    dst->st_ctim.tv_nsec = (long) src->st_ctime_nsec;
}

/* Dispatch result constructors. */

struct kbox_dispatch kbox_dispatch_continue(void)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_CONTINUE,
        .val = 0,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_errno(int err)
{
    if (err <= 0)
        err = EIO;
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = 0,
        .error = err,
    };
}

struct kbox_dispatch kbox_dispatch_value(int64_t val)
{
    return (struct kbox_dispatch) {
        .kind = KBOX_DISPATCH_RETURN,
        .val = val,
        .error = 0,
    };
}

struct kbox_dispatch kbox_dispatch_from_lkl(long ret)
{
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    return kbox_dispatch_value((int64_t) ret);
}

/* Path and FD helper functions. */

/* Check if the original guest path at a given arg index starts with '/'.
 * Used to gate virtual-path CONTINUE on originally-absolute paths: relative
 * paths like "./proc" normalize to "/proc" but should go through LKL, while
 * absolute "/proc/self/status" should CONTINUE to the host kernel.
 */
static bool guest_path_is_absolute(const struct kbox_supervisor_ctx *ctx,
                                   const struct kbox_syscall_request *req,
                                   size_t arg_idx)
{
    uint8_t first = 0;
    if (guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, arg_idx), &first, 1) == 0)
        return first == '/';
    return false;
}

static bool should_continue_virtual_path(const struct kbox_supervisor_ctx *ctx,
                                         const struct kbox_syscall_request *req,
                                         size_t path_idx,
                                         const char *translated)
{
    /* fd magic links belong to the host: the descriptors a guest process sees
     * are kbox-injected host fds (exec memfds, pipes, sockets), which a guest
     * procfs knows nothing about, while execve through /proc/self/fd/N is how
     * kbox hands executables to the kernel. */
    {
        const char *tail = NULL;
        if (!strncmp(translated, "/proc/self/fd", 13))
            tail = translated + 13;
        else if (!strncmp(translated, "/proc/thread-self/fd", 20))
            tail = translated + 20;
        else if (!strncmp(translated, "/proc/", 6) && translated[6] >= '0' &&
                 translated[6] <= '9') {
            const char *p2 = translated + 6;
            while (*p2 >= '0' && *p2 <= '9')
                p2++;
            if (!strncmp(p2, "/fd", 3))
                tail = p2 + 3;
        }
        if (tail && (tail[0] == '\0' || tail[0] == '/'))
            return true;
    }

    /* A container with its own procfs resolves /proc inside LKL; continuing
     * it would read the host's, and the magic links there are blocked. */
    if (ctx->private_proc && !strncmp(translated, "/proc", 5) &&
        (translated[5] == '\0' || translated[5] == '/'))
        return false;
    return kbox_is_lkl_virtual_path(translated) &&
           guest_path_is_absolute(ctx, req, path_idx);
}

/* Public wrapper: other dispatch units need the same host/LKL decision that
 * openat makes, so that linkat, renameat and friends stay on the backing the
 * path belongs to. */
int kbox_path_is_host_passthrough(const struct kbox_supervisor_ctx *ctx,
                                  const struct kbox_syscall_request *req,
                                  size_t path_idx,
                                  const char *translated)
{
    return should_continue_virtual_path(ctx, req, path_idx, translated) ? 1 : 0;
}

/* Resolve dirfd for *at() syscalls.
 *
 * If the path is absolute, AT_FDCWD is fine regardless of dirfd. If dirfd is
 * AT_FDCWD, pass it through. Otherwise look up the virtual FD in the table to
 * get the LKL fd.  Returns -1 if the fd is not in the table (caller should
 * CONTINUE).
 */
long resolve_open_dirfd(const char *path,
                        long dirfd,
                        const struct kbox_fd_table *table)
{
    if (path[0] == '/')
        return AT_FDCWD_LINUX;
    if (dirfd == AT_FDCWD_LINUX)
        return AT_FDCWD_LINUX;
    return kbox_fd_table_get_lkl(table, dirfd);
}

int read_guest_string(const struct kbox_supervisor_ctx *ctx,
                      pid_t pid,
                      uint64_t addr,
                      char *buf,
                      size_t size)
{
    return guest_mem_read_string(ctx, pid, addr, buf, size);
}

static struct kbox_translated_path_cache_entry *find_translated_path_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *guest_path)
{
    size_t i;

    if (!ctx || !guest_path)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        struct kbox_translated_path_cache_entry *entry =
            &ctx->translated_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            strcmp(entry->guest_path, guest_path) == 0) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_translated_path_cache_entry *reserve_translated_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++) {
        if (!ctx->translated_path_cache[i].valid)
            return &ctx->translated_path_cache[i];
    }
    return &ctx->translated_path_cache[0];
}

static struct kbox_literal_path_cache_entry *find_literal_path_cache(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    uint64_t guest_addr)
{
    size_t i;

    if (!ctx || guest_addr == 0)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        struct kbox_literal_path_cache_entry *entry =
            &ctx->literal_path_cache[i];
        if (entry->valid &&
            entry->generation == ctx->path_translation_generation &&
            entry->pid == pid && entry->guest_addr == guest_addr) {
            return entry;
        }
    }
    return NULL;
}

static struct kbox_literal_path_cache_entry *reserve_literal_path_cache(
    struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return NULL;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++) {
        if (!ctx->literal_path_cache[i].valid)
            return &ctx->literal_path_cache[i];
    }
    return &ctx->literal_path_cache[0];
}

int guest_addr_is_writable(pid_t pid, uint64_t addr)
{
    char maps_path[64];
    FILE *fp;
    char line[256];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return 1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8];

        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (addr < start || addr >= end)
            continue;
        fclose(fp);
        return strchr(perms, 'w') != NULL;
    }

    fclose(fp);
    return 1;
}

struct guest_file_backing_interval {
    uint64_t file_start;
    uint64_t file_end;
    unsigned long long inode;
    char dev[32];
};

int guest_range_has_shared_file_write_mapping(pid_t pid,
                                              uint64_t addr,
                                              uint64_t len)
{
    char maps_path[64];
    FILE *fp;
    char line[512];
    uint64_t end_addr;
    struct guest_file_backing_interval *targets = NULL;
    size_t target_count = 0;
    size_t target_cap = 0;
    int rc = 0;

    if (len == 0)
        return 0;
    if (__builtin_add_overflow(addr, len, &end_addr))
        end_addr = UINT64_MAX;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int) pid);
    fp = fopen(maps_path, "re");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, inode;
        unsigned long long offset;
        char perms[8];
        char dev[32];
        uint64_t overlap_start;
        uint64_t overlap_end;
        struct guest_file_backing_interval *new_targets;

        if (sscanf(line, "%llx-%llx %7s %llx %31s %llu", &start, &end, perms,
                   &offset, dev, &inode) != 6)
            continue;
        if (inode == 0)
            continue;
        if (end <= addr || start >= end_addr)
            continue;
        if (strchr(perms, 's') == NULL)
            continue;
        overlap_start = addr > start ? addr : (uint64_t) start;
        overlap_end = end_addr < end ? end_addr : (uint64_t) end;
        if (overlap_start >= overlap_end)
            continue;
        if (target_count == target_cap) {
            size_t new_cap = target_cap == 0 ? 4 : target_cap * 2;

            new_targets = realloc(targets, new_cap * sizeof(*targets));
            if (!new_targets) {
                rc = -1;
                goto out;
            }
            targets = new_targets;
            target_cap = new_cap;
        }
        if (__builtin_add_overflow((uint64_t) offset,
                                   overlap_start - (uint64_t) start,
                                   &targets[target_count].file_start)) {
            rc = -1;
            goto out;
        }
        if (__builtin_add_overflow(targets[target_count].file_start,
                                   overlap_end - overlap_start,
                                   &targets[target_count].file_end)) {
            rc = -1;
            goto out;
        }
        targets[target_count].inode = inode;
        memcpy(targets[target_count].dev, dev,
               sizeof(targets[target_count].dev));
        targets[target_count].dev[sizeof(targets[target_count].dev) - 1] = '\0';
        target_count++;
    }

    fclose(fp);
    fp = NULL;

    if (target_count == 0)
        goto out;

    fp = fopen(maps_path, "re");
    if (!fp) {
        rc = -1;
        goto out;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end, inode;
        unsigned long long offset;
        char perms[8];
        char dev[32];
        uint64_t map_file_start;
        uint64_t map_file_end;
        size_t i;

        if (sscanf(line, "%llx-%llx %7s %llx %31s %llu", &start, &end, perms,
                   &offset, dev, &inode) != 6)
            continue;
        if (inode == 0)
            continue;
        if (strchr(perms, 's') == NULL || strchr(perms, 'w') == NULL)
            continue;
        map_file_start = (uint64_t) offset;
        if (__builtin_add_overflow(map_file_start,
                                   (uint64_t) end - (uint64_t) start,
                                   &map_file_end)) {
            rc = -1;
            goto out;
        }
        for (i = 0; i < target_count; i++) {
            if (targets[i].inode != inode)
                continue;
            if (strcmp(targets[i].dev, dev) != 0)
                continue;
            if (map_file_end <= targets[i].file_start ||
                map_file_start >= targets[i].file_end) {
                continue;
            }
            rc = 1;
            goto out;
        }
    }

out:
    if (fp)
        fclose(fp);
    free(targets);
    return rc;
}

void invalidate_translated_path_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    ctx->path_translation_generation++;
    for (i = 0; i < KBOX_TRANSLATED_PATH_CACHE_MAX; i++)
        ctx->translated_path_cache[i].valid = 0;
    for (i = 0; i < KBOX_LITERAL_PATH_CACHE_MAX; i++)
        ctx->literal_path_cache[i].valid = 0;
}

int translate_guest_path(const struct kbox_supervisor_ctx *ctx,
                         pid_t pid,
                         uint64_t addr,
                         const char *host_root,
                         char *translated,
                         size_t size)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    char pathbuf[KBOX_MAX_PATH];
    struct kbox_literal_path_cache_entry *literal_entry;
    struct kbox_translated_path_cache_entry *entry;

    literal_entry = find_literal_path_cache(mutable_ctx, pid, addr);
    if (literal_entry) {
        size_t len = strlen(literal_entry->translated);

        if (len >= size)
            return -ENAMETOOLONG;
        memcpy(translated, literal_entry->translated, len + 1);
        return 0;
    }

    int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return rc;

    /* A relative path resolves against the guest's working directory, so its
     * translation changes with chdir. The cache is keyed by the path string
     * alone and is shared by every process the daemon serves, so a relative
     * path must not be cached: another process with another cwd would get the
     * first process's answer.
     */
    bool cacheable = pathbuf[0] == '/';

    if (cacheable) {
        entry = find_translated_path_cache(mutable_ctx, pathbuf);
        if (entry) {
            if (strlen(entry->translated) >= size)
                return -ENAMETOOLONG;
            memcpy(translated, entry->translated,
                   strlen(entry->translated) + 1);
            return 0;
        }
    }

    rc = kbox_translate_path_for_lkl(pid, pathbuf, host_root, translated, size);
    if (rc < 0)
        return rc;

    /* A relative name that only looks like a virtual path belongs to the
     * working directory, not to the root. kbox_translate_path_for_lkl rewrites
     * "sys" to "/sys" so that a guest with cwd / sees the same directory, but
     * with any other cwd "sys" means <cwd>/sys: MariaDB creates the sys schema
     * with mkdir("./sys") and open("./sys/db.opt"), and the rewrite sent both
     * into the read-only sysfs mount, which answered EACCES and left the
     * server unable to install its system database.
     */
    if (kbox_keep_relative_virtual(pathbuf, translated, ctx->lkl_cwd_cur)) {
        if (strlen(pathbuf) >= size)
            return -ENAMETOOLONG;
        memcpy(translated, pathbuf, strlen(pathbuf) + 1);
    }

    if (cacheable) {
        entry = reserve_translated_path_cache(mutable_ctx);
        if (entry) {
            entry->valid = 1;
            entry->generation = mutable_ctx->path_translation_generation;
            strncpy(entry->guest_path, pathbuf, sizeof(entry->guest_path) - 1);
            entry->guest_path[sizeof(entry->guest_path) - 1] = '\0';
            strncpy(entry->translated, translated,
                    sizeof(entry->translated) - 1);
            entry->translated[sizeof(entry->translated) - 1] = '\0';
        }
    }

    if (!guest_addr_is_writable(pid, addr)) {
        literal_entry = reserve_literal_path_cache(mutable_ctx);
        if (literal_entry) {
            literal_entry->valid = 1;
            literal_entry->generation =
                mutable_ctx->path_translation_generation;
            literal_entry->pid = pid;
            literal_entry->guest_addr = addr;
            strncpy(literal_entry->translated, translated,
                    sizeof(literal_entry->translated) - 1);
            literal_entry->translated[sizeof(literal_entry->translated) - 1] =
                '\0';
        }
    }
    return 0;
}

int translate_request_path(const struct kbox_syscall_request *req,
                           const struct kbox_supervisor_ctx *ctx,
                           size_t path_idx,
                           const char *host_root,
                           char *translated,
                           size_t size)
{
    return translate_guest_path(ctx, kbox_syscall_request_pid(req),
                                kbox_syscall_request_arg(req, path_idx),
                                host_root, translated, size);
}

static int read_tracee_fd_link(pid_t pid, long fd, char *out, size_t out_size)
{
    char link_path[64];
    ssize_t n;

    if (pid <= 0 || fd < 0 || !out || out_size == 0)
        return -1;
    snprintf(link_path, sizeof(link_path), /* format-ok */
             "/proc/%d/fd/%ld", (int) pid, fd);
    n = readlink(link_path, out, out_size - 1);
    if (n < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

static bool host_dirfd_targets_proc(pid_t pid, long fd)
{
    char target[KBOX_MAX_PATH];

    if (pid <= 0 || read_tracee_fd_link(pid, fd, target, sizeof(target)) < 0)
        return false;

    if (strcmp(target, "/proc") == 0)
        return true;
    return strncmp(target, "/proc/", 6) == 0;
}

static bool path_has_prefix_dir(const char *path,
                                const char *prefix,
                                size_t prefix_len)
{
    if (prefix_len == 1 && prefix[0] == '/')
        return path[0] == '/';
    if (strncmp(path, prefix, prefix_len) != 0)
        return false;
    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

static int resolve_host_fd_guest_bind(const struct kbox_supervisor_ctx *ctx,
                                      pid_t pid,
                                      long fd,
                                      char *guest_out,
                                      size_t guest_out_size,
                                      int *ro_out)
{
    char target[KBOX_MAX_PATH];
    const struct kbox_host_bind *best = NULL;
    size_t best_hlen = 0;

    if (!ctx || ctx->host_bind_count == 0 || fd < 0)
        return 0;
    if (read_tracee_fd_link(pid, fd, target, sizeof(target)) < 0)
        return 0;

    for (size_t i = 0; i < ctx->host_bind_count; i++) {
        const struct kbox_host_bind *b = &ctx->host_binds[i];
        size_t hlen = strlen(b->host_path);
        if (path_has_prefix_dir(target, b->host_path, hlen) &&
            hlen >= best_hlen) {
            best = b;
            best_hlen = hlen;
        }
    }
    if (!best)
        return 0;

    if (ro_out)
        *ro_out = best->readonly;
    if (guest_out && guest_out_size > 0) {
        const char *tail = (best_hlen == 1 && best->host_path[0] == '/')
                               ? target
                               : target + best_hlen;
        int wn;
        if (tail[0] == '\0')
            wn = snprintf(guest_out, guest_out_size, "%s", best->guest_path);
        else if (best->guest_len == 1 && best->guest_path[0] == '/')
            wn = snprintf(guest_out, guest_out_size, "%s", tail);
        else
            wn = snprintf(guest_out, guest_out_size, "%s%s", best->guest_path,
                          tail);
        if (wn < 0 || (size_t) wn >= guest_out_size)
            return -ENAMETOOLONG;
    }
    return 1;
}

static int resolve_guest_cwd(const struct kbox_supervisor_ctx *ctx,
                             char *cwd_out,
                             size_t cwd_size)
{
    if (!ctx || !cwd_out || cwd_size == 0)
        return -EINVAL;
    if (ctx->host_cwd[0] != '\0') {
        int n = snprintf(cwd_out, cwd_size, "%s", ctx->host_cwd);
        return (n < 0 || (size_t) n >= cwd_size) ? -ENAMETOOLONG : 0;
    }
    long ret = kbox_lkl_getcwd(ctx->sysnrs, cwd_out, (long) cwd_size);
    if (ret < 0)
        return (int) ret;
    return 0;
}

int kbox_parse_host_volume(const char *spec, struct kbox_host_bind *out)
{
    char raw_host[KBOX_MAX_PATH];
    char raw_dst[KBOX_MAX_PATH];
    char resolved_host[KBOX_MAX_PATH];
    const char *c1;
    const char *c2;
    size_t hlen, dlen;

    if (!spec || !out || spec[0] == '\0')
        return -1;
    memset(out, 0, sizeof(*out));

    /* "nfs://<name>[/subdir]:<dest>[:ro]" — the scheme name is hard-coded and
     * is not a host path, so the first colon cannot be the separator. The
     * reference part is kept verbatim and resolved by the daemon against the
     * "mounts:" section of the config.
     */
    if (strncmp(spec, "nfs://", 6) == 0) {
        const char *sep = strchr(spec + 6, ':');
        if (!sep || sep == spec + 6)
            return -1;
        hlen = (size_t) (sep - spec);
        if (hlen >= sizeof(raw_host))
            return -1;
        memcpy(raw_host, spec, hlen);
        raw_host[hlen] = '\0';

        c1 = sep; /* destination starts here, parsed by the common path below */
        out->is_nfs = 1;
        snprintf(out->host_path, sizeof(out->host_path), "%s", raw_host);
    } else {
        c1 = strchr(spec, ':');
        if (!c1 || c1 == spec)
            return -1;
        hlen = (size_t) (c1 - spec);
        if (hlen >= sizeof(raw_host))
            return -1;
        memcpy(raw_host, spec, hlen);
        raw_host[hlen] = '\0';
    }

    const char *dst_start = c1 + 1;
    c2 = strchr(dst_start, ':');
    dlen = c2 ? (size_t) (c2 - dst_start) : strlen(dst_start);
    if (dlen == 0 || dlen >= sizeof(raw_dst) || dst_start[0] != '/')
        return -1;
    memcpy(raw_dst, dst_start, dlen);
    raw_dst[dlen] = '\0';

    if (kbox_normalize_join("/", raw_dst, out->guest_path,
                            sizeof(out->guest_path)) < 0)
        return -1;

    if (out->is_nfs) {
        out->guest_len = strlen(out->guest_path);
        goto parse_mode;
    }

    if (realpath(raw_host, resolved_host) != NULL) {
        snprintf(out->host_path, sizeof(out->host_path), "%s", resolved_host);
    } else if (raw_host[0] == '/') {
        if (kbox_normalize_join("/", raw_host, out->host_path,
                                sizeof(out->host_path)) < 0)
            return -1;
    } else {
        char cwd[KBOX_MAX_PATH];
        if (!getcwd(cwd, sizeof(cwd)))
            return -1;
        if (kbox_normalize_join(cwd, raw_host, out->host_path,
                                sizeof(out->host_path)) < 0)
            return -1;
    }

    size_t host_len = strlen(out->host_path);
    while (host_len > 1 && out->host_path[host_len - 1] == '/') {
        out->host_path[--host_len] = '\0';
    }
    out->guest_len = strlen(out->guest_path);

parse_mode:
    if (c2 && c2[1] != '\0') {
        const char *p = c2 + 1;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t tok_len = comma ? (size_t) (comma - p) : strlen(p);
            if (tok_len == 2 && strncmp(p, "ro", 2) == 0)
                out->readonly = 1;
            else if (tok_len == 2 && strncmp(p, "rw", 2) == 0)
                out->readonly = 0;
            if (!comma)
                break;
            p = comma + 1;
        }
    }
    return 0;
}

static int resolve_host_bind_canonical(const struct kbox_supervisor_ctx *ctx,
                                       long raw_dirfd,
                                       const char *guest_path,
                                       char *norm_out,
                                       size_t norm_size,
                                       char *host_out,
                                       size_t host_out_size,
                                       int *ro_out)
{
    char norm_buf[KBOX_MAX_PATH];
    const struct kbox_host_bind *best = NULL;

    if (!norm_out) {
        norm_out = norm_buf;
        norm_size = sizeof(norm_buf);
    }
    if (!ctx || !guest_path || guest_path[0] == '\0')
        return 0;

    if (guest_path[0] == '/') {
        if (kbox_normalize_join("/", guest_path, norm_out, norm_size) < 0)
            return -ENAMETOOLONG;
    } else if (raw_dirfd == AT_FDCWD_LINUX) {
        char cwd[KBOX_MAX_PATH];
        int crc = resolve_guest_cwd(ctx, cwd, sizeof(cwd));
        if (crc < 0)
            return 0;
        if (kbox_normalize_join(cwd, guest_path, norm_out, norm_size) < 0)
            return -ENAMETOOLONG;
    } else {
        return 0;
    }

    if (ctx->host_bind_count == 0)
        return 0;

    for (size_t i = 0; i < ctx->host_bind_count; i++) {
        const struct kbox_host_bind *b = &ctx->host_binds[i];
        /* NFS volumes are real mounts inside the guest kernel, not paths to
         * redirect at dispatch time. */
        if (b->is_nfs)
            continue;
        if (path_has_prefix_dir(norm_out, b->guest_path, b->guest_len)) {
            if (!best || b->guest_len >= best->guest_len)
                best = b;
        }
    }
    if (!best)
        return 0;

    const char *tail = (best->guest_len == 1 && best->guest_path[0] == '/')
                           ? norm_out
                           : norm_out + best->guest_len;
    int wn;
    if (tail[0] == '\0')
        wn = snprintf(host_out, host_out_size, "%s", best->host_path);
    else if (strcmp(best->host_path, "/") == 0)
        wn = snprintf(host_out, host_out_size, "%s", tail);
    else
        wn = snprintf(host_out, host_out_size, "%s%s", best->host_path, tail);
    if (wn < 0 || (size_t) wn >= host_out_size)
        return -ENAMETOOLONG;

    if (ro_out)
        *ro_out = best->readonly;
    return 1;
}

static void lkl_mkdir_p_best_effort(const struct kbox_sysnrs *sysnrs,
                                    const char *path)
{
    char buf[KBOX_MAX_PATH];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof(buf))
        return;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            kbox_lkl_mkdir(sysnrs, buf, 0755);
            *p = '/';
        }
    }
    kbox_lkl_mkdir(sysnrs, buf, 0755);
}

int kbox_ensure_lkl_bind_stubs(const struct kbox_sysnrs *sysnrs,
                               const struct kbox_host_bind *binds,
                               size_t count)
{
    if (!sysnrs || !binds)
        return 0;
    for (size_t i = 0; i < count; i++) {
        const struct kbox_host_bind *b = &binds[i];
        struct stat st;
        int is_dir = 1;

        /* NFS volumes are bind-mounted by the daemon, not stubbed here. */
        if (b->is_nfs)
            continue;
        if (stat(b->host_path, &st) == 0 && !S_ISDIR(st.st_mode))
            is_dir = 0;
        if (is_dir) {
            lkl_mkdir_p_best_effort(sysnrs, b->guest_path);
        } else {
            const char *slash = strrchr(b->guest_path, '/');
            if (slash && slash > b->guest_path) {
                char parent[KBOX_MAX_PATH];
                size_t plen = (size_t) (slash - b->guest_path);
                if (plen < sizeof(parent)) {
                    memcpy(parent, b->guest_path, plen);
                    parent[plen] = '\0';
                    lkl_mkdir_p_best_effort(sysnrs, parent);
                }
            }
            long fd = kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, b->guest_path,
                                      O_CREAT | O_WRONLY, 0644);
            if (fd >= 0)
                kbox_lkl_close(sysnrs, fd);
        }
    }
    return 0;
}

int kbox_resolve_host_bind_at(const struct kbox_supervisor_ctx *ctx,
                              long raw_dirfd,
                              const char *guest_path,
                              char *host_out,
                              size_t host_out_size,
                              int *ro_out)
{
    return resolve_host_bind_canonical(ctx, raw_dirfd, guest_path, NULL, 0,
                                       host_out, host_out_size, ro_out);
}

int open_host_dirfd_for_dispatch(pid_t pid,
                                 long raw_dirfd,
                                 long lkl_dirfd,
                                 int *sv_dirfd_out,
                                 int *close_out)
{
    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND ||
        lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO) {
        *sv_dirfd_out = AT_FDCWD;
        *close_out = 0;
        return 0;
    }
    int fd = dup_tracee_fd(pid, (int) raw_dirfd);
    if (fd < 0)
        return fd;
    *sv_dirfd_out = fd;
    *close_out = 1;
    return 0;
}

int host_bind_is_readonly(const struct kbox_supervisor_ctx *ctx,
                          pid_t pid,
                          long raw_dirfd,
                          long lkl_dirfd)
{
    int ro = 0;

    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO)
        return 1;
    if (lkl_dirfd == -1 && raw_dirfd >= 0) {
        if (resolve_host_fd_guest_bind(ctx, pid, raw_dirfd, NULL, 0, &ro) > 0)
            return ro;
    }
    return 0;
}

static int translate_request_path_or_bind(
    const struct kbox_syscall_request *req,
    const struct kbox_supervisor_ctx *ctx,
    size_t path_idx,
    char *translated,
    size_t size,
    long *lkl_dirfd_out)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t addr = kbox_syscall_request_arg(req, path_idx);

    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        int brc =
            resolve_host_bind_canonical(ctx, AT_FDCWD_LINUX, pathbuf, norm,
                                        sizeof(norm), translated, size, &ro);
        if (brc < 0)
            return brc;
        if (brc > 0) {
            *lkl_dirfd_out =
                ro ? KBOX_LKL_DIRFD_HOST_BIND_RO : KBOX_LKL_DIRFD_HOST_BIND;
            return 0;
        }
        if (ctx->host_cwd[0] != '\0' && pathbuf[0] != '/') {
            int n = snprintf(translated, size, "%s", norm);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            *lkl_dirfd_out = AT_FDCWD_LINUX;
            return 0;
        }
    }

    *lkl_dirfd_out = AT_FDCWD_LINUX;
    return translate_request_path(req, ctx, path_idx, ctx->host_root,
                                  translated, size);
}

int translate_request_at_path(const struct kbox_syscall_request *req,
                              struct kbox_supervisor_ctx *ctx,
                              size_t dirfd_idx,
                              size_t path_idx,
                              char *translated,
                              size_t size,
                              long *lkl_dirfd)
{
    long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, dirfd_idx));

    /* If dirfd is not AT_FDCWD and not tracked in our FD table, this is a
     * host-kernel FD (e.g., from a CONTINUE'd openat on /proc or /sys).
     * For relative or empty paths the host kernel must resolve them against
     * that dirfd, so signal CONTINUE by setting *lkl_dirfd = -1.
     *
     * Reject unsafe relative lookups instead of translating them through LKL:
     * translating "../../etc/passwd" against the guest cwd would silently
     * change syscall semantics, and continuing it against the host dirfd could
     * escape the virtual namespace.
     *
     * For absolute paths dirfd is irrelevant and normal translation proceeds.
     */
    if (raw_dirfd != AT_FDCWD_LINUX && raw_dirfd >= 0 &&
        kbox_fd_table_get_lkl(ctx->fd_table, raw_dirfd) < 0) {
        char pathbuf[KBOX_MAX_PATH];
        pid_t req_pid = kbox_syscall_request_pid(req);
        bool proc_dirfd = host_dirfd_targets_proc(req_pid, raw_dirfd);
        int rc = read_guest_string(ctx, req_pid,
                                   kbox_syscall_request_arg(req, path_idx),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        if (pathbuf[0] != '/') {
            if (kbox_relative_path_has_dotdot(pathbuf) ||
                (proc_dirfd && kbox_relative_proc_escape_path(pathbuf))) {
                return -EPERM;
            }
            *lkl_dirfd = -1;
            int n = snprintf(translated, size, "%s", pathbuf);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            return 0;
        }
        /* Absolute path: dirfd is ignored, so normal translation is safe. */
    }

    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, kbox_syscall_request_pid(req),
                                   kbox_syscall_request_arg(req, path_idx),
                                   pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return rc;
        int brc = resolve_host_bind_canonical(
            ctx, raw_dirfd, pathbuf, norm, sizeof(norm), translated, size, &ro);
        if (brc < 0)
            return brc;
        if (brc > 0) {
            *lkl_dirfd =
                ro ? KBOX_LKL_DIRFD_HOST_BIND_RO : KBOX_LKL_DIRFD_HOST_BIND;
            return 0;
        }
        if (ctx->host_cwd[0] != '\0' && raw_dirfd == AT_FDCWD_LINUX &&
            pathbuf[0] != '/') {
            int n = snprintf(translated, size, "%s", norm);
            if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
            *lkl_dirfd = AT_FDCWD_LINUX;
            return 0;
        }
    }

    int rc = translate_request_path(req, ctx, path_idx, ctx->host_root,
                                    translated, size);
    if (rc < 0)
        return rc;

    *lkl_dirfd = resolve_open_dirfd(translated, raw_dirfd, ctx->fd_table);
    return 0;
}

int should_continue_for_dirfd(long lkl_dirfd)
{
    if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND ||
        lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO)
        return 1;
    return lkl_dirfd < 0 && lkl_dirfd != AT_FDCWD_LINUX;
}

static int pid_fd_is_open(pid_t pid, long fd)
{
    char link_path[64];
    char target[1];

    if (pid <= 0 || fd < 0)
        return 0;
    snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%ld", (int) pid, fd);
    if (readlink(link_path, target, sizeof(target)) >= 0)
        return 1;
    return errno != ENOENT;
}

int child_fd_is_open(const struct kbox_supervisor_ctx *ctx, long fd)
{
    pid_t pid = ctx ? ctx->child_pid : 0;

    if (ctx && ctx->active_proc && ctx->active_proc->tgid > 0)
        pid = ctx->active_proc->tgid;
    return pid_fd_is_open(pid, fd);
}

/* Diagnostic dump of a descriptor table, enabled with KBOX_FD_TRACE=1. */
static int fd_trace_enabled(void)
{
    return getenv("KBOX_FD_TRACE") != NULL;
}

static void fd_trace_dump(const struct kbox_fd_table *t, const char *why)
{
    struct shape {
        long lkl_fd;
        long host_fd;
        int shadow_sp;
        int shadow_writeback;
        int mirror_tty;
        long count;
        long first_fd;
    } shapes[16];
    int nshapes = 0;
    long occupied = 0;

    if (!fd_trace_enabled() || !t)
        return;
    fprintf(stderr, "kbofdt: dump %s\n", why);
    for (long fd = 0; fd < KBOX_FD_TABLE_CAPACITY; fd++) {
        const struct kbox_fd_entry *e = &t->slots[fd];
        int found = 0;

        if (e->lkl_fd == -1)
            continue;
        occupied++;
        for (int i = 0; i < nshapes; i++) {
            if (shapes[i].lkl_fd == (e->lkl_fd >= 0 ? 0 : e->lkl_fd) &&
                shapes[i].host_fd == (e->host_fd >= 0 ? 0 : e->host_fd) &&
                shapes[i].shadow_sp == (e->shadow_sp >= 0 ? 1 : e->shadow_sp) &&
                shapes[i].shadow_writeback == e->shadow_writeback &&
                shapes[i].mirror_tty == e->mirror_tty) {
                shapes[i].count++;
                found = 1;
                break;
            }
        }
        if (!found && nshapes < 16) {
            shapes[nshapes].lkl_fd = e->lkl_fd >= 0 ? 0 : e->lkl_fd;
            shapes[nshapes].host_fd = e->host_fd >= 0 ? 0 : e->host_fd;
            shapes[nshapes].shadow_sp = e->shadow_sp >= 0 ? 1 : e->shadow_sp;
            shapes[nshapes].shadow_writeback = e->shadow_writeback;
            shapes[nshapes].mirror_tty = e->mirror_tty;
            shapes[nshapes].count = 1;
            shapes[nshapes].first_fd = fd;
            nshapes++;
        }
    }
    for (int i = 0; i < nshapes; i++)
        fprintf(stderr,
                "kbofdt:   shape first_fd=%ld lkl>=0:%d host_fd=%ld sp>=0:%d "
                "wb=%d mirror=%d count=%ld\n",
                shapes[i].first_fd, shapes[i].lkl_fd == 0, shapes[i].host_fd,
                shapes[i].shadow_sp == 1, shapes[i].shadow_writeback,
                shapes[i].mirror_tty, shapes[i].count);
    fprintf(stderr, "kbofdt: dump %s: %ld occupied\n", why, occupied);
}

static void fd_trace_table(const char *tag,
                           const struct kbox_fd_table *t,
                           pid_t tgid)
{
    if (!fd_trace_enabled() || !t)
        return;
    fprintf(stderr, "kbofdt: table %s tgid=%d ptr=%p total=%u\n", tag,
            (int) tgid, (const void *) t, kbox_fd_table_count(t));
}

/* Lowest descriptor whose slot is free and which the
 * tracee does not already hold. Ownership comes from the table, never from the
 * number. */
static long allocate_shadow_fd_from(struct kbox_supervisor_ctx *ctx,
                                    long min_fd)
{
    long end_fd = KBOX_FD_TABLE_CAPACITY;
    long fd;

    if (!ctx || !ctx->fd_table)
        return -1;
    if (min_fd < 0)
        min_fd = 0;

    for (fd = min_fd; fd < end_fd; fd++) {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

        if (entry && entry->lkl_fd == -1 && !child_fd_is_open(ctx, fd))
            return fd;
    }
    return -1;
}

static long allocate_writable_shadow_fd(struct kbox_supervisor_ctx *ctx)
{
    return allocate_shadow_fd_from(ctx, KBOX_NATIVE_CLOSE_MAX);
}

/* Install a real host placeholder descriptor at a low virtual FD
 * (< KBOX_NATIVE_CLOSE_MAX) that has no same-fd shadow. Because close(fd)
 * below KBOX_NATIVE_CLOSE_MAX runs natively in the host kernel, the tracee
 * must hold a real descriptor at that number so close() returns 0 instead of
 * EBADF (e.g. dup2/F_DUPFD of a directory or writable LKL file). A zero-byte
 * memfd gives each placeholder a unique (st_dev, st_ino) so
 * validate_low_fd_routing() detects close or reuse immediately.
 */
static int close_watch_register(struct kbox_supervisor_ctx *ctx,
                                int memfd,
                                long lkl_fd,
                                int shadow_sp,
                                const struct kbox_fd_entry *src);

static void install_low_vfd_placeholder(struct kbox_supervisor_ctx *ctx,
                                        const struct kbox_syscall_request *req,
                                        long fd,
                                        int cloexec)
{
    struct kbox_fd_entry *entry;
    long lkl_fd = -1;
    int wd = -1;
    int pfd;

    if (!ctx || !req || fd < 0 || fd >= KBOX_FD_TABLE_CAPACITY)
        return;
    entry = fd_table_entry(ctx->fd_table, fd);
    if (entry)
        lkl_fd = entry->lkl_fd;
    pfd = memfd_create("kbox-vfd", MFD_CLOEXEC);
    if (pfd < 0)
        return;
    /* Registered before the descriptor reaches the guest, so the close that
     * follows immediately is never missed. */
    wd = close_watch_register(ctx, pfd, lkl_fd, -1, entry);
    (void) request_addfd_at(ctx, req, pfd, (int) fd, cloexec ? O_CLOEXEC : 0);
    close(pfd);
    if (wd >= 0 && entry)
        entry->watch_wd = wd;
    note_low_fd_identity(ctx, kbox_syscall_request_pid(req), fd);
}

static long allocate_dup_shadow_fd_from(struct kbox_supervisor_ctx *ctx,
                                        pid_t pid,
                                        long min_fd)
{
    long fd;
    long max_fd = KBOX_FD_TABLE_CAPACITY;

    if (!ctx || !ctx->fd_table)
        return -1;
    if (min_fd < 0)
        min_fd = 0;
    if (ctx->active_proc &&
        (uint64_t) min_fd >= ctx->active_proc->rlimit_nofile_cur)
        return -1;
    if (ctx->active_proc &&
        (uint64_t) max_fd > ctx->active_proc->rlimit_nofile_cur)
        max_fd = (long) ctx->active_proc->rlimit_nofile_cur;

    for (fd = min_fd; fd < max_fd; fd++) {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

        if (entry && entry->lkl_fd == -1 && !pid_fd_is_open(pid, fd))
            return fd;
    }
    return -1;
}

int ensure_proc_self_fd_dir(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx)
        return -1;
    if (ctx->proc_self_fd_dirfd >= 0)
        return ctx->proc_self_fd_dirfd;

    ctx->proc_self_fd_dirfd =
        open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return ctx->proc_self_fd_dirfd;
}

int ensure_proc_mem_fd(struct kbox_supervisor_ctx *ctx)
{
    char path[64];

    if (!ctx || ctx->child_pid <= 0)
        return -1;
    if (ctx->proc_mem_fd >= 0)
        return ctx->proc_mem_fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", (int) ctx->child_pid);
    ctx->proc_mem_fd = open(path, O_RDWR | O_CLOEXEC);
    return ctx->proc_mem_fd;
}

int guest_mem_write_small_metadata(const struct kbox_supervisor_ctx *ctx,
                                   pid_t pid,
                                   uint64_t remote_addr,
                                   const void *in,
                                   size_t len)
{
    struct kbox_supervisor_ctx *mutable_ctx =
        (struct kbox_supervisor_ctx *) ctx;
    ssize_t n;
    int fd;

    if (!ctx || !in)
        return -EFAULT;
    if (len == 0)
        return 0;
    if (remote_addr == 0)
        return -EFAULT;
    if (pid != ctx->child_pid ||
        ctx->active_guest_mem.ops != &kbox_process_vm_guest_mem_ops)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    fd = ensure_proc_mem_fd(mutable_ctx);
    if (fd < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);

    n = pwrite(fd, in, len, (off_t) remote_addr);
    if (n < 0)
        return guest_mem_write(ctx, pid, remote_addr, in, len);
    if ((size_t) n != len)
        return -EIO;
    return 0;
}

/* Build the host-side path for a guest-relative (translated) path.
 * Only valid when host_root is set (host-directory rootfs mode): translated is
 * relative to host_root (stripped by kbox_translate_path_for_lkl). When
 * host_root is NULL (image / daemon LKL-rootfs modes), there is no host rootfs
 * directory and files must be served from LKL, never the supervisor's own `/`.
 */
static int build_host_open_path(const struct kbox_supervisor_ctx *ctx,
                                const char *translated,
                                char *out,
                                size_t out_size)
{
    int n;

    if (!ctx || !ctx->host_root)
        return -1;

    /* translated is absolute (starts with '/'), skip the leading '/' when
     * joining to avoid double-slash.
     */
    const char *tail = translated;
    if (*tail == '/')
        tail++;
    n = snprintf(out, out_size, "%s/%s", ctx->host_root, tail);
    return (n >= 0 && (size_t) n < out_size) ? 0 : -1;
}

int reopen_cached_shadow_fd(struct kbox_supervisor_ctx *ctx,
                            const struct kbox_path_shadow_cache_entry *entry)
{
    char fd_name[32];
    int dirfd;
    int fd;

    if (!entry)
        return -1;
    if (entry->path[0] != '\0') {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, entry->path, host_path,
                                 sizeof(host_path)) == 0) {
            fd = open(host_path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0)
                return fd;
        }
    }
    fd = entry->memfd;
    if (fd < 0)
        return -1;
    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return -1;
    snprintf(fd_name, sizeof(fd_name), "%d", fd);
    return openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
}

static int find_writeback_sp_in_range(const struct kbox_supervisor_ctx *ctx,
                                      const struct kbox_fd_entry *entries,
                                      long count,
                                      long target_lkl_fd,
                                      const struct kbox_lkl_stat *target_st)
{
    for (long i = 0; i < count; i++) {
        const struct kbox_fd_entry *cand = &entries[i];
        struct kbox_lkl_stat cand_st;

        if (cand->lkl_fd < 0 || !cand->shadow_writeback || cand->shadow_sp < 0)
            continue;
        if (cand->lkl_fd == target_lkl_fd) {
            if (getenv("KBOX_FD_TRACE"))
                fprintf(stderr,
                        "kbofdt: shadow match by fd lkl=%ld sp=%d "
                        "target_dev=%llu target_ino=%llu\n",
                        target_lkl_fd, cand->shadow_sp,
                        (unsigned long long) target_st->st_dev,
                        (unsigned long long) target_st->st_ino);
            return cand->shadow_sp;
        }
        memset(&cand_st, 0, sizeof(cand_st));
        if (getenv("KBOX_FD_TRACE"))
            fprintf(stderr,
                    "kbofdt: shadow candidate lkl=%ld sp=%d (target lkl=%ld)\n",
                    cand->lkl_fd, cand->shadow_sp, target_lkl_fd);
        if (kbox_lkl_fstat(ctx->sysnrs, cand->lkl_fd, &cand_st) == 0 &&
            cand_st.st_dev == target_st->st_dev &&
            cand_st.st_ino == target_st->st_ino) {
            return cand->shadow_sp;
        }
    }
    return -1;
}

static int find_writeback_sp_in_table(const struct kbox_supervisor_ctx *ctx,
                                      const struct kbox_fd_table *table,
                                      long target_lkl_fd,
                                      const struct kbox_lkl_stat *target_st)
{
    if (!table)
        return -1;
    return find_writeback_sp_in_range(ctx, table->slots, KBOX_FD_TABLE_CAPACITY,
                                      target_lkl_fd, target_st);
}

/* Search every live process's descriptor table in this container for an active
 * writeback shadow matching (target_lkl_fd, target_st). Checking only the
 * calling process's ctx->fd_table hid uncommitted writes from any sibling or
 * child forked before the open, so stat(), open(O_RDONLY), open(O_APPEND) and
 * truncate() from another process saw stale LKL bytes or clobbered each other.
 */
static int find_writeback_sp_across_procs(const struct kbox_supervisor_ctx *ctx,
                                          long target_lkl_fd,
                                          const struct kbox_lkl_stat *target_st)
{
    int sp;

    if (!ctx || ctx->active_writeback_shadows == 0 || !target_st)
        return -1;

    sp = find_writeback_sp_in_table(ctx, ctx->fd_table, target_lkl_fd,
                                    target_st);
    if (sp >= 0)
        return sp;

    if (ctx->proc_fds) {
        for (size_t i = 0; i < ctx->proc_fd_count; i++) {
            const struct kbox_fd_table *tab = ctx->proc_fds[i].table;

            if (!tab || tab == ctx->fd_table)
                continue;
            sp = find_writeback_sp_in_table(ctx, tab, target_lkl_fd, target_st);
            if (sp >= 0)
                return sp;
        }
    }
    return -1;
}

/* Find the writable shadow of the file a path stat just described.
 *
 * A writable open copies the file into a supervisor memfd and copies it back
 * only when the descriptor is closed, so until then the LKL inode still carries
 * the old size and timestamps. Reporting those made stat() lie about a file the
 * guest was writing: gdbm's test_reorganize compares getsize() before and after
 * a write and saw no change. Matching by device and inode is how the read path
 * already finds the live copy.
 */
static int find_writeback_shadow_for_stat(const struct kbox_supervisor_ctx *ctx,
                                          const struct kbox_lkl_stat *target_st)
{
    return find_writeback_sp_across_procs(ctx, -1, target_st);
}

/* Overlay the live shadow's size and timestamps on a path stat. */
static void apply_writeback_shadow_stat(struct kbox_supervisor_ctx *ctx,
                                        const struct kbox_lkl_stat *kst,
                                        struct stat *host_stat)
{
    struct stat sst;
    int sp = find_writeback_shadow_for_stat(ctx, kst);

    if (sp < 0 || fstat(sp, &sst) < 0)
        return;
    host_stat->st_size = sst.st_size;
    host_stat->st_blocks = sst.st_blocks;
    host_stat->st_atim = sst.st_atim;
    host_stat->st_mtim = sst.st_mtim;
    host_stat->st_ctim = sst.st_ctim;
}

int kbox_find_active_writeback_shadow_sp(struct kbox_supervisor_ctx *ctx,
                                         long lkl_fd)
{
    struct kbox_lkl_stat target_st;

    if (!ctx || !ctx->fd_table || ctx->active_writeback_shadows == 0 ||
        lkl_fd < 0)
        return -1;

    memset(&target_st, 0, sizeof(target_st));
    if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &target_st) < 0)
        return -1;

    return find_writeback_sp_across_procs(ctx, lkl_fd, &target_st);
}

int kbox_reopen_writeback_shadow_ro(struct kbox_supervisor_ctx *ctx,
                                    long lkl_fd,
                                    int *out_memfd)
{
    int sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);
    int dirfd;
    char fd_name[32];
    int ro_fd;

    if (sp < 0 || !out_memfd)
        return 0;

    dirfd = ensure_proc_self_fd_dir(ctx);
    if (dirfd < 0)
        return 0;

    snprintf(fd_name, sizeof(fd_name), "%d", sp);
    ro_fd = openat(dirfd, fd_name, O_RDONLY | O_CLOEXEC);
    if (ro_fd < 0)
        return 0;

    *out_memfd = ro_fd;
    return 1;
}

/* Promote a read-only regular LKL FD to a host-visible shadow at the same guest
 * FD number on first eligible read-only access. This avoids paying memfd copy
 * cost at open time while still letting later read/lseek/fstat/mmap operations
 * run on a real host FD.
 *
 * Returns:
 *   1  shadow is available (same-fd injected for seccomp, local-only for
 *      trap/rewrite)
 *   0  shadow promotion not applicable
 *  -1  promotion attempted but failed
 */
/* Largest file kbox copies into a shadow memfd.
 *
 * A writable open makes a private copy of the file, and a read open does the
 * same lazily, so that one descriptor's writes and another descriptor's reads
 * agree while both are open. That copy is linear in file size, and the copy
 * back at close materializes every hole. A sparse 2 GiB file (test_largefile)
 * therefore turned into 2 GiB of RAM and 2 GiB of real blocks in the guest --
 * which the guest filesystem cannot hold, so the copy back failed with ENOSPC
 * and the last bytes of the file were silently lost.
 *
 * Above the cap the file stays a plain LKL file: reads, writes and seeks go
 * through the guest kernel, which is exactly the semantics a syscall shim
 * should give. The cap is far above anything the coherency fix was for (small
 * config, database and log files written by several descriptors).
 */
#define KBOX_SHADOW_MAX_BYTES (16LL * 1024 * 1024)

/* 1 when the file is small enough to shadow. */
static int shadow_size_ok(struct kbox_supervisor_ctx *ctx, long lkl_fd)
{
    struct kbox_lkl_stat st;

    memset(&st, 0, sizeof(st));
    if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &st) < 0)
        return 0;
    return st.st_size <= KBOX_SHADOW_MAX_BYTES;
}

int ensure_same_fd_shadow(struct kbox_supervisor_ctx *ctx,
                          const struct kbox_syscall_request *req,
                          long fd,
                          long lkl_fd)
{
    struct kbox_fd_entry *entry;
    long flags;
    int memfd;

    off_t cur_off;

    if (!ctx || !req || !ctx->fd_table || fd < 0 || lkl_fd < 0)
        return 0;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (!entry)
        return 0;
    if (entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
        entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
        return 1;
    }
    if (entry->host_fd >= 0)
        return 0;

    flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (!shadow_size_ok(ctx, lkl_fd))
        return 0;

    if (!kbox_reopen_writeback_shadow_ro(ctx, lkl_fd, &memfd)) {
        memfd = kbox_shadow_create_resilient(ctx, lkl_fd);
        if (memfd < 0)
            return -1;
        kbox_shadow_seal(memfd);
    }

    cur_off = (off_t) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);
    if (cur_off >= 0 && lseek(memfd, cur_off, SEEK_SET) < 0) {
        close(memfd);
        return -1;
    }

    /* Keep lazy read shadows local to the supervisor in all modes.
     * Injecting them at the guest FD number lets read(2)/lseek(2) CONTINUE,
     * but it reintroduces a close/open reuse race under concurrent seccomp
     * notifications. The local-shadow handlers already cover read/lseek/fstat
     * safely, so prefer them over same-fd injection here.
     */
    entry->host_fd = KBOX_FD_LOCAL_ONLY_SHADOW;
    entry->shadow_sp = memfd;
    entry->shadow_writeback = 0;

    if (ctx->verbose) {
        fprintf(stderr, "kbox: lazy shadow promote fd=%ld lkl_fd=%ld mode=%s\n",
                fd, lkl_fd,
                entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ? "same-fd"
                                                              : "local-only");
    }
    if (getenv("KBOX_FD_TRACE")) {
        struct stat sst;

        memset(&sst, 0, sizeof(sst));
        (void) fstat(memfd, &sst);
        fprintf(stderr, "kbofdt: ro_shadow fd=%ld lkl=%ld sp=%d copied=%lld\n",
                fd, lkl_fd, memfd, (long long) sst.st_size);
    }
    return 1;
}

static struct kbox_dispatch forward_local_shadow_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd,
    int is_pread)
{
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count;
    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;
    pid_t pid = kbox_syscall_request_pid(req);

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (count > KBOX_READ_MAX)
        count = KBOX_READ_MAX;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        ssize_t nr;

        if (chunk_len > count - total)
            chunk_len = count - total;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            long pread_off;
            if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                if (total == 0)
                    return kbox_dispatch_errno(EOVERFLOW);
                break;
            }
            nr = pread(entry->shadow_sp, scratch, chunk_len, (off_t) pread_off);
        } else {
            nr = read(entry->shadow_sp, scratch, chunk_len);
        }
        if (nr < 0) {
            if (total == 0)
                return kbox_dispatch_errno(errno);
            break;
        }
        if (nr == 0)
            break;
        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        if (guest_mem_write(ctx, pid, remote, scratch, (size_t) nr) < 0) {
            return kbox_dispatch_errno(EFAULT);
        }
        if (ctx->verbose) {
            off_t pos = lseek(entry->shadow_sp, 0, SEEK_CUR);

            fprintf(stderr,
                    "kbox: shadow read fd=%ld lkl=%ld sp=%d pread=%d count=%zu "
                    "ret=%zd pos_after=%lld\n",
                    to_c_long_arg(kbox_syscall_request_arg(req, 0)), lkl_fd,
                    entry->shadow_sp, is_pread, chunk_len, nr, (long long) pos);
        }
        total += (size_t) nr;
        if ((size_t) nr < chunk_len)
            break;
    }

    if (!is_pread) {
        off_t cur_off = lseek(entry->shadow_sp, 0, SEEK_CUR);
        if (cur_off >= 0)
            (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) cur_off,
                                  SEEK_SET);
    }

    return kbox_dispatch_value((int64_t) total);
}

static struct kbox_dispatch forward_local_shadow_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *entry,
    long lkl_fd)
{
    long off;
    long whence;
    off_t ret;

    if (!entry || entry->shadow_sp < 0)
        return kbox_dispatch_continue();

    off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    ret = lseek(entry->shadow_sp, (off_t) off, (int) whence);
    if (ctx->verbose)
        fprintf(stderr,
                "kbox: shadow lseek fd=%ld lkl=%ld sp=%d off=%ld whence=%ld "
                "ret=%lld\n",
                to_c_long_arg(kbox_syscall_request_arg(req, 0)), lkl_fd,
                entry->shadow_sp, off, whence, (long long) ret);
    if (ret < 0)
        return kbox_dispatch_errno(errno);

    (void) kbox_lkl_lseek(ctx->sysnrs, lkl_fd, (long) ret, SEEK_SET);
    return kbox_dispatch_value((int64_t) ret);
}

/* statx struct field offsets (standard on x86_64 and aarch64). */
#define STATX_UID_OFFSET 0x14
#define STATX_GID_OFFSET 0x18
#define STATX_MODE_OFFSET 0x1c
#define STATX_INO_OFFSET 0x20
#define STATX_DEV_MAJOR_OFFSET 0x88
#define STATX_DEV_MINOR_OFFSET 0x8c
#define STATX_BUF_SIZE 0x100

static unsigned long g_fd_trace_serial;

static void fd_trace_periodic(struct kbox_supervisor_ctx *ctx, const char *why)
{
    if (!fd_trace_enabled())
        return;
    if (++g_fd_trace_serial % 512 != 0)
        return;
    fd_trace_table(why, ctx->fd_table,
                   ctx->active_proc ? ctx->active_proc->tgid : 0);
}

static struct kbox_dispatch finish_open_dispatch(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long lkl_fd,
    long flags,
    const char *translated)
{
    struct kbox_dispatch shadow_dispatch;

    /* Honor POSIX lowest-fd semantics when a stdio descriptor (0/1/2) is
     * closed (e.g. close(1); open("/tmp/out", ...)). Stay on direct LKL I/O
     * (skip writeback shadow) and install a placeholder fd so native close()
     * succeeds with 0 and writes are immediately durable. */
    if (req && req->source == KBOX_SYSCALL_SOURCE_SECCOMP) {
        pid_t pid = kbox_syscall_request_pid(req);
        long stdio_fd;

        for (stdio_fd = 0; stdio_fd <= 2; stdio_fd++) {
            if (!pid_fd_is_open(pid, stdio_fd)) {
                sweep_stale_low_fds(ctx, pid, 3);
                if (kbox_fd_table_get_lkl(ctx->fd_table, stdio_fd) == -1 &&
                    kbox_fd_table_insert_at(
                        ctx->fd_table, stdio_fd, lkl_fd,
                        kbox_is_tty_like_path(translated)) == 0) {
                    if (flags & O_CLOEXEC)
                        kbox_fd_table_set_cloexec(ctx->fd_table, stdio_fd, 1);
                    install_low_vfd_placeholder(ctx, req, stdio_fd,
                                                (flags & O_CLOEXEC) != 0);
                    return kbox_dispatch_value((int64_t) stdio_fd);
                }
                break;
            }
        }
    }

    if (req && try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                               &shadow_dispatch)) {
        return shadow_dispatch;
    }

    if (req && try_writeback_shadow_open(ctx, req, lkl_fd, flags, translated,
                                         &shadow_dispatch)) {
        return shadow_dispatch;
    }

    long vfd = kbox_fd_table_insert(ctx->fd_table, lkl_fd,
                                    kbox_is_tty_like_path(translated));
    if (vfd < 0) {
        if (fd_trace_enabled()) {
            char proc[64];
            int proc_ok;

            snprintf(proc, sizeof(proc), "/proc/%d", (int) ctx->child_pid);
            proc_ok = access(proc, F_OK) == 0;
            fd_trace_table("insert-failed", ctx->fd_table,
                           ctx->active_proc ? ctx->active_proc->tgid : 0);
            fd_trace_dump(ctx->fd_table, translated ? translated : "?");
            fprintf(stderr,
                    "kbofdt: insert-failed path=%s child_pid=%d alive=%d "
                    "next_fd=%ld\n",
                    translated ? translated : "?", (int) ctx->child_pid,
                    proc_ok, ctx->fd_table->next_fd);
        }
        lkl_close_and_invalidate(ctx, lkl_fd);
        return kbox_dispatch_errno(EMFILE);
    }
    if (ctx->verbose)
        fprintf(stderr, "kbox: open %s -> vfd=%ld lkl=%ld\n",
                translated ? translated : "?", vfd, lkl_fd);
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr,
                "kbofdt: guest_open path=%s vfd=%ld lkl=%ld "
                "flags=%#lx\n",
                translated ? translated : "?", vfd, lkl_fd,
                (unsigned long) flags);
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, vfd, 1);
    fd_trace_periodic(ctx, "periodic-plain");
    return kbox_dispatch_value((int64_t) vfd);
}

/* Make a host stat result reflect the guest's virtual identity (see vcred.h):
 * chown overlay first, otherwise "owned by the supervisor" becomes "owned by
 * the calling process". Only for root_identity containers. */
static void apply_virtual_owner(struct kbox_supervisor_ctx *ctx,
                                pid_t pid,
                                struct stat *host_stat,
                                int dirfd,
                                const char *host_path,
                                int nofollow)
{
    int64_t uid, gid;

    /* A host file behind a bind mount keeps the guest's identity in
     * user.kbox.owner -- the same xattr the LKL hostfs driver reads -- so the
     * owner survives a container restart and is shared by every container that
     * sees the file. It wins over the in-memory overlay, which only lives as
     * long as this supervisor process. */
    if (host_path &&
        kbox_owner_xattr_get(dirfd, host_path, nofollow, &uid, &gid) == 1) {
        host_stat->st_uid = (uid_t) uid;
        host_stat->st_gid = (gid_t) gid;
        return;
    }
    if (ctx->root_identity)
        kbox_owner_apply(pid, host_stat);
}

static void apply_virtual_owner_statx(struct kbox_supervisor_ctx *ctx,
                                      pid_t pid,
                                      uint8_t *statx_buf)
{
    struct stat st;
    uint32_t major, minor;
    uint64_t ino;

    if (!(ctx->root_identity))
        return;
    memset(&st, 0, sizeof(st));
    memcpy(&ino, &statx_buf[STATX_INO_OFFSET], 8);
    memcpy(&major, &statx_buf[STATX_DEV_MAJOR_OFFSET], 4);
    memcpy(&minor, &statx_buf[STATX_DEV_MINOR_OFFSET], 4);
    memcpy(&st.st_uid, &statx_buf[STATX_UID_OFFSET], 4);
    memcpy(&st.st_gid, &statx_buf[STATX_GID_OFFSET], 4);
    st.st_ino = (ino_t) ino;
    st.st_dev = makedev(major, minor);
    kbox_owner_apply(pid, &st);
    memcpy(&statx_buf[STATX_UID_OFFSET], &st.st_uid, 4);
    memcpy(&statx_buf[STATX_GID_OFFSET], &st.st_gid, 4);
}

static void apply_lkl_owner_overlay_statx(struct kbox_supervisor_ctx *ctx,
                                          uint8_t *statx_buf)
{
    struct stat st;
    uint32_t major, minor;
    uint64_t ino;

    if (!(ctx->root_identity))
        return;
    memset(&st, 0, sizeof(st));
    memcpy(&ino, &statx_buf[STATX_INO_OFFSET], 8);
    memcpy(&major, &statx_buf[STATX_DEV_MAJOR_OFFSET], 4);
    memcpy(&minor, &statx_buf[STATX_DEV_MINOR_OFFSET], 4);
    memcpy(&st.st_uid, &statx_buf[STATX_UID_OFFSET], 4);
    memcpy(&st.st_gid, &statx_buf[STATX_GID_OFFSET], 4);
    st.st_ino = (ino_t) ino;
    st.st_dev = makedev(major, minor);
    if (kbox_owner_apply_overlay(&st)) {
        memcpy(&statx_buf[STATX_UID_OFFSET], &st.st_uid, 4);
        memcpy(&statx_buf[STATX_GID_OFFSET], &st.st_gid, 4);
    }
}

void normalize_host_stat_if_needed(struct kbox_supervisor_ctx *ctx,
                                   const char *path,
                                   struct stat *host_stat)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    host_stat->st_mode = (host_stat->st_mode & S_IFMT) | (n_mode & ~S_IFMT);
    host_stat->st_uid = n_uid;
    host_stat->st_gid = n_gid;
}

void normalize_statx_if_needed(struct kbox_supervisor_ctx *ctx,
                               const char *path,
                               uint8_t *statx_buf)
{
    if (!ctx->normalize)
        return;

    uint32_t n_mode, n_uid, n_gid;
    if (!kbox_normalized_permissions(path, &n_mode, &n_uid, &n_gid))
        return;

    /* Keep the file-type bits: statx reports them in the same field, and
     * glibc's ls/stat and the JDK (Files.isDirectory) read the type from it. */
    uint16_t old_mode;
    memcpy(&old_mode, &statx_buf[STATX_MODE_OFFSET], 2);
    uint16_t mode_le = (uint16_t) ((old_mode & S_IFMT) | (n_mode & ~S_IFMT));
    memcpy(&statx_buf[STATX_MODE_OFFSET], &mode_le, 2);
    memcpy(&statx_buf[STATX_UID_OFFSET], &n_uid, 4);
    memcpy(&statx_buf[STATX_GID_OFFSET], &n_gid, 4);
}

void invalidate_path_shadow_cache(struct kbox_supervisor_ctx *ctx)
{
    size_t i;

    if (!ctx)
        return;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        if (ctx->path_shadow_cache[i].valid &&
            ctx->path_shadow_cache[i].memfd >= 0) {
            close(ctx->path_shadow_cache[i].memfd);
        }
        memset(&ctx->path_shadow_cache[i], 0,
               sizeof(ctx->path_shadow_cache[i]));
        ctx->path_shadow_cache[i].memfd = -1;
    }
    invalidate_translated_path_cache(ctx);
}

static struct kbox_path_shadow_cache_entry *find_path_shadow_cache(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;

    if (!ctx || !translated)
        return NULL;
    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        struct kbox_path_shadow_cache_entry *entry = &ctx->path_shadow_cache[i];
        if (entry->valid && strcmp(entry->path, translated) == 0)
            return entry;
    }
    return NULL;
}

static struct kbox_path_shadow_cache_entry *reserve_path_shadow_cache_slot(
    struct kbox_supervisor_ctx *ctx,
    const char *translated)
{
    size_t i;
    struct kbox_path_shadow_cache_entry *entry;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return entry;

    for (i = 0; i < KBOX_PATH_SHADOW_CACHE_MAX; i++) {
        entry = &ctx->path_shadow_cache[i];
        if (!entry->valid)
            return entry;
    }

    entry = &ctx->path_shadow_cache[0];
    if (entry->memfd >= 0)
        close(entry->memfd);
    memset(entry, 0, sizeof(*entry));
    entry->memfd = -1;
    return entry;
}

int ensure_path_shadow_cache(struct kbox_supervisor_ctx *ctx,
                             const char *translated)
{
    struct kbox_path_shadow_cache_entry *entry;
    struct stat host_stat;
    int host_fd;

    if (!ctx || !translated || translated[0] == '\0' ||
        ctx->active_writeback_shadows > 0 ||
        kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (entry)
        return 1;

    {
        char host_path[KBOX_MAX_PATH];
        if (build_host_open_path(ctx, translated, host_path,
                                 sizeof(host_path)) < 0)
            return 0;
        host_fd = open(host_path, O_RDONLY | O_CLOEXEC);
    }
    if (host_fd < 0)
        return 0;

    if (fstat(host_fd, &host_stat) < 0) {
        close(host_fd);
        return 0;
    }
    if (!S_ISREG(host_stat.st_mode)) {
        close(host_fd);
        return 0;
    }
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    entry = reserve_path_shadow_cache_slot(ctx, translated);
    if (!entry) {
        close(host_fd);
        return 0;
    }

    entry->valid = 1;
    entry->memfd = host_fd;
    strncpy(entry->path, translated, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';
    entry->host_stat = host_stat;
    return 1;
}

int try_cached_shadow_open_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    long flags,
                                    const char *translated,
                                    struct kbox_dispatch *out)
{
    struct kbox_path_shadow_cache_entry *entry;
    int injected;
    int dup_fd;

    if (!ctx || !req || !translated || !out)
        return 0;
    /* Diagnostic switch: the cache injects descriptors the guest closes
     * without a close(2) of its own (the kernel-chosen numbers), and that
     * accounting is suspected of leaking table slots under package-manager
     * load. KBOX_NO_PATH_SHADOW_CACHE=1 turns it off for an A/B run. */
    if (getenv("KBOX_NO_PATH_SHADOW_CACHE"))
        return 0;
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (flags & ~(O_RDONLY | O_CLOEXEC))
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry || entry->memfd < 0)
        return 0;

    dup_fd = reopen_cached_shadow_fd(ctx, entry);
    if (dup_fd < 0)
        return 0;

    /* Let the kernel pick a fresh host-visible FD. Reusing a fixed target FD
     * races with concurrent close(2): the supervisor removes its bookkeeping
     * before the kernel replays the close, so another thread can reuse that FD
     * number and have the older close tear down the new file.
     */
    injected =
        request_addfd(ctx, req, dup_fd, (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected >= 0 &&
        kbox_fd_table_insert_at(ctx->fd_table, injected,
                                KBOX_LKL_FD_SHADOW_ONLY, 0) == 0) {
        struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, injected);

        /* Keep a supervisor copy of the bytes so a later execve through
         * /proc/self/fd/N can build an executable image from this descriptor.
         * apk runs its trigger scripts exactly that way, and an untracked
         * descriptor left the host kernel resolving the script's shebang
         * against the host root. */
        if (ne) {
            ne->host_fd = -1;
            ne->shadow_sp = fcntl(dup_fd, F_DUPFD_CLOEXEC, 3);
            if (flags & O_CLOEXEC)
                kbox_fd_table_set_cloexec(ctx->fd_table, injected, 1);
        }
    }
    close(dup_fd);
    if (injected < 0)
        return 0;

    if (getenv("KBOX_TRACE"))
        fprintf(stderr, "kbox: cached shadow open path=%s fd=%d\n", translated,
                injected);
    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

int try_cached_shadow_stat_dispatch(struct kbox_supervisor_ctx *ctx,
                                    const char *translated,
                                    uint64_t remote_stat,
                                    pid_t pid)
{
    struct kbox_path_shadow_cache_entry *entry;

    if (!ctx || !translated || remote_stat == 0)
        return 0;
    if (!ensure_path_shadow_cache(ctx, translated))
        return 0;

    entry = find_path_shadow_cache(ctx, translated);
    if (!entry)
        return 0;

    return guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                          &entry->host_stat,
                                          sizeof(entry->host_stat)) == 0;
}

void note_shadow_writeback_open(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || entry->shadow_writeback)
        return;
    entry->shadow_writeback = 1;
    ctx->active_writeback_shadows++;
    invalidate_path_shadow_cache(ctx);
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr, "kbofdt: note_open entry=%p lkl=%ld sp=%d active=%u\n",
                (void *) entry, entry->lkl_fd, entry->shadow_sp,
                (unsigned) ctx->active_writeback_shadows);
}

void note_shadow_writeback_close(struct kbox_supervisor_ctx *ctx,
                                 struct kbox_fd_entry *entry)
{
    if (!ctx || !entry || !entry->shadow_writeback)
        return;
    entry->shadow_writeback = 0;
    if (ctx->active_writeback_shadows > 0)
        ctx->active_writeback_shadows--;
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr, "kbofdt: note_close entry=%p lkl=%ld sp=%d active=%u\n",
                (void *) entry, entry->lkl_fd, entry->shadow_sp,
                (unsigned) ctx->active_writeback_shadows);
}

static void sync_cloexec_writebacks_in_range(struct kbox_supervisor_ctx *ctx,
                                             struct kbox_fd_entry *entries,
                                             long count)
{
    long i;

    if (!ctx || !entries)
        return;
    for (i = 0; i < count; i++) {
        struct kbox_fd_entry *entry = &entries[i];

        if (entry->lkl_fd != -1 && entry->cloexec) {
            if (entry->lkl_fd >= 0)
                invalidate_stat_cache_fd(ctx, entry->lkl_fd);
            if (entry->shadow_writeback) {
                (void) sync_shadow_writeback(ctx, entry);
                note_shadow_writeback_close(ctx, entry);
            }
        }
    }
}

/* Flush every pending writable shadow in one FD-table range.
 *
 * deregister == 0 keeps the entry registered, so a later close still copies
 * the data it holds. That is what a thread exit needs: the thread goes away,
 * the process and its descriptors do not.
 */

static void sync_all_writebacks_in_range(struct kbox_supervisor_ctx *ctx,
                                         struct kbox_fd_entry *entries,
                                         long count,
                                         int deregister)
{
    long i;

    if (!ctx || !entries)
        return;
    for (i = 0; i < count; i++) {
        struct kbox_fd_entry *entry = &entries[i];

        if (entry->lkl_fd >= 0 && entry->shadow_writeback) {
            (void) sync_shadow_writeback(ctx, entry);
            if (deregister)
                note_shadow_writeback_close(ctx, entry);
            invalidate_stat_cache_fd(ctx, entry->lkl_fd);
        }
    }
}

static void close_cloexec_range(struct kbox_supervisor_ctx *ctx,
                                struct kbox_fd_entry *entries,
                                long count,
                                long base_fd)
{
    for (long i = 0; i < count; i++) {
        struct kbox_fd_entry *entry = &entries[i];
        if (entry->lkl_fd == -1 || !entry->cloexec)
            continue;
        long lkl = entry->lkl_fd;
        if (lkl == KBOX_LKL_FD_SHADOW_ONLY) {
            kbox_fd_table_remove(ctx->fd_table, base_fd + i);
            continue;
        }
        kbox_fd_table_remove(ctx->fd_table, base_fd + i);
        if (lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
    }
}

void close_cloexec_with_writeback(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || !ctx->fd_table)
        return;

    sync_cloexec_writebacks_in_range(ctx, ctx->fd_table->slots,
                                     KBOX_FD_TABLE_CAPACITY);
    close_cloexec_range(ctx, ctx->fd_table->slots, KBOX_FD_TABLE_CAPACITY, 0);
}

/* Flush every writable shadow before a process leaves.
 *
 * A shadow writes into a memfd owned by the supervisor, and the memfd is only
 * copied back to the LKL file on close(2). Process exit closes descriptors
 * inside the kernel without a close syscall, so `sh -c 'tr ... > file'`
 * produced an empty file: the child wrote the data, exited, and the copy
 * stayed in the supervisor's memfd. Nothing else can observe it, and the next
 * open of that path reads the untouched LKL file. Flushing every pending
 * shadow is safe: the copy is idempotent, and a shadow that is still being
 * written is flushed again when its own owner closes it.
 */
static void sync_table_writebacks(struct kbox_supervisor_ctx *ctx,
                                  struct kbox_fd_table *t,
                                  int deregister)
{
    if (!ctx || !t)
        return;

    sync_all_writebacks_in_range(ctx, t->slots, KBOX_FD_TABLE_CAPACITY,
                                 deregister);
}

void sync_all_writeback_shadows(struct kbox_supervisor_ctx *ctx, int deregister)
{
    sync_table_writebacks(ctx, ctx->fd_table, deregister);
}

static long remove_fd_table_entry_with_writeback(
    struct kbox_supervisor_ctx *ctx,
    long fd)
{
    struct kbox_fd_entry *entry;

    if (!ctx || !ctx->fd_table)
        return -1;

    entry = fd_table_entry(ctx->fd_table, fd);
    if (entry && entry->shadow_writeback) {
        (void) sync_shadow_writeback(ctx, entry);
        note_shadow_writeback_close(ctx, entry);
    }
    return kbox_fd_table_remove(ctx->fd_table, fd);
}

int try_writeback_shadow_open(struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              long lkl_fd,
                              long flags,
                              const char *translated,
                              struct kbox_dispatch *out)
{
    struct kbox_fd_entry *entry;
    int memfd;
    long target_fd;
    int injected;

    if (!ctx || !req || !out || lkl_fd < 0 || !translated)
        return 0;
    if ((flags & O_ACCMODE) == O_RDONLY)
        return 0;
    if (!shadow_size_ok(ctx, lkl_fd))
        return 0;
    if (kbox_is_lkl_virtual_path(translated) ||
        kbox_is_tty_like_path(translated))
        return 0;

    /* A second writable open of a file that already has a writeback shadow
     * has to see the same bytes. Copying the file again would give this FD a
     * private snapshot: a writer that closes one shadow flushes to LKL, while
     * the other descriptor keeps reading the copy it made at open time, so a
     * write followed by a read through a different FD lost the data. Open a
     * new description of the existing memfd instead: same inode (one copy of
     * the data), independent file offset.
     */
    memfd = -1;
    {
        int reuse_sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);

        if (getenv("KBOX_FD_TRACE"))
            fprintf(stderr,
                    "kbofdt: wb_open lkl=%ld flags=%#lx path=%s active=%u "
                    "reuse_sp=%d\n",
                    lkl_fd, (unsigned long) flags, translated,
                    ctx->active_writeback_shadows, reuse_sp);
        if (reuse_sp >= 0) {
            int dirfd = ensure_proc_self_fd_dir(ctx);
            if (dirfd >= 0) {
                char fd_name[32];
                snprintf(fd_name, sizeof(fd_name), "%d", reuse_sp);
                memfd = openat(dirfd, fd_name, O_RDWR | O_CLOEXEC);
            }
            if (memfd >= 0 && (flags & O_TRUNC) && ftruncate(memfd, 0) < 0) {
                close(memfd);
                memfd = -1;
            }
        }
    }
    /* An O_APPEND open with no shadow to share must keep the kernel's append
     * semantics on the real file: a fresh shadow is an independent copy with
     * its own offset, so appending to it and copying back leaves holes (logs
     * written after truncation get a NUL prefix the size of the data). When a
     * shadow does exist, sharing it is the only correct answer: keeping the
     * append on the LKL file let the other shadow's writeback overwrite the
     * appended bytes, so a write through one descriptor disappeared when the
     * other was closed (test_io's threaded writers).
     *
     * Such a shadow is built from a READ-ONLY sibling of this open, because
     * filling it means pread(2) on the source and an O_WRONLY fd cannot be
     * read. Without it the descriptor stays purely virtual, which only breaks
     * once it is dup2'd onto 0/1/2: the guest then holds a number with no host
     * descriptor behind it, and a shell that forks for its command
     * substitution (dash -- /bin/sh in every role image) writes the result to
     * the wrong channel or fails with EBADF. A dispatched run's answer landed
     * in .err that way while .out, which supervisord reads, stayed empty.
     */
    if (memfd < 0 && (flags & O_APPEND)) {
        long ro_fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                     O_RDONLY, 0);

        if (ro_fd >= 0) {
            memfd = kbox_shadow_create_resilient(ctx, ro_fd);
            (void) kbox_lkl_close(ctx->sysnrs, ro_fd);
        }
        if (memfd < 0) {
            if (getenv("KBOX_FD_TRACE"))
                fprintf(stderr,
                        "kbofdt: wb_open lkl=%ld path=%s: append with no "
                        "readable sibling, staying on the LKL file\n",
                        lkl_fd, translated);
            return 0;
        }
        /* The shadow carries the file as it was; O_TRUNC on an append open is
         * legal and must still empty it. */
        if ((flags & O_TRUNC) && ftruncate(memfd, 0) < 0) {
            close(memfd);
            return 0;
        }
    }
    if (memfd < 0)
        memfd = kbox_shadow_create_resilient(ctx, lkl_fd);
    if (memfd < 0)
        return 0;
    /* Do NOT seal: this shadow is for a writable FD; the tracee needs
     * write access.  Only read-only shadows (ensure_same_fd_shadow) are
     * sealed.
     */

    /* The tracee's descriptor is this memfd, so O_APPEND has to live on it:
     * without the flag every write lands at the memfd's own offset (0 for a
     * fresh open) and `echo line >> file` overwrites the start of the file. */
    if (flags & O_APPEND) {
        int fl = fcntl(memfd, F_GETFL);
        if (fl >= 0)
            (void) fcntl(memfd, F_SETFL, fl | O_APPEND);
    }
    /* The sync back to LKL is ftruncate + pwrite64 at explicit offsets, and
     * pwrite on an O_APPEND descriptor appends regardless of the offset, so
     * the LKL side must not carry the flag: with it a 2-byte append came back
     * as "\0\0" + data. */
    if (flags & O_APPEND) {
        long lfl = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);
        if (lfl >= 0)
            (void) kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_SETFL,
                                  lfl & ~(long) O_APPEND);
    }

    target_fd = allocate_writable_shadow_fd(ctx);
    if (target_fd < 0) {
        fd_trace_table("shadow-band-full", ctx->fd_table,
                       ctx->active_proc ? ctx->active_proc->tgid : 0);
        close(memfd);
        return 0;
    }

    /* Install only in the fast-shadow band.  Host-only FDs are allowed to
     * close directly in BPF, which would bypass writeback, and kernel-picked
     * ADDFD results can also exceed the fd-table range.  Unlike the old
     * preallocation approach, the fd-table entry is published only after
     * ADDFD_AT succeeds and after child_fd_is_open() has verified that no
     * pending close still owns this tracee fd number.
     */
    injected = request_addfd_at(ctx, req, memfd, (int) target_fd,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        close(memfd);
        return 0;
    }

    /* SECCOMP_ADDFD_FLAG_SETFD guarantees injected == target_fd on success.
     * A mismatch means the kernel API contract broke; the tracee would hold
     * an untracked FD we cannot revoke.  Crash loudly instead of leaking.
     */
    if (injected != target_fd) {
        fprintf(stderr,
                "kbox: ADDFD_AT returned %d, expected %ld -- aborting\n",
                injected, target_fd);
        abort();
    }

    /* allocate_writable_shadow_fd validated target_fd is in-range and free.
     * insert_at must not fail here; if it does, the tracee holds a live FD
     * with no supervisor bookkeeping.
     */
    if (kbox_fd_table_insert_at(ctx->fd_table, injected, lkl_fd, 0) < 0) {
        fprintf(stderr,
                "kbox: fd_table_insert_at(%d) failed after ADDFD -- aborting\n",
                injected);
        abort();
    }
    note_low_fd_identity(ctx, kbox_syscall_request_pid(req), injected);

    entry = fd_table_entry(ctx->fd_table, injected);
    entry->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    entry->shadow_sp = memfd;
    {
        struct stat sst;
        if (fstat(memfd, &sst) == 0) {
            entry->shadow_mtime_sec = (long) sst.st_mtim.tv_sec;
            entry->shadow_mtime_nsec = (long) sst.st_mtim.tv_nsec;
            entry->shadow_size = (long) sst.st_size;
        }
    }
    note_shadow_writeback_open(ctx, entry);
    if (fd_trace_enabled())
        fprintf(stderr, "kbofdt: promoted fd=%d lkl=%ld table=%p path=%s\n",
                injected, lkl_fd, (const void *) ctx->fd_table, translated);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: writable shadow promote fd=%d lkl_fd=%ld path=%s\n",
                injected, lkl_fd, translated);
    }
    fd_trace_periodic(ctx, "periodic-shadow");
    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

typedef long (*kbox_getdents_fn)(const struct kbox_sysnrs *sysnrs,
                                 long fd,
                                 void *buf,
                                 long count);

static struct kbox_dispatch forward_getdents_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    kbox_getdents_fn getdents_fn)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    uint64_t remote_dirp = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    size_t count, n;
    uint8_t *buf;
    long ret;
    int wrc;

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);

    count = (size_t) count_raw;
    if (count == 0)
        return kbox_dispatch_value(0);
    if (remote_dirp == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count > KBOX_IO_CHUNK_LEN)
        count = KBOX_IO_CHUNK_LEN;

    buf = dispatch_scratch;

    ret = getdents_fn(ctx->sysnrs, lkl_fd, buf, (long) count);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    n = (size_t) ret;
    if (n > count)
        return kbox_dispatch_errno(EIO);

    wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req), remote_dirp, buf,
                          n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value((int64_t) n);
}

int dup_tracee_fd(pid_t pid, int tracee_fd);
static int dup_tracee_fd_shared(pid_t pid, int tracee_fd);

/* Gate a CONTINUE syscall that takes an FD in arg0.  Deny if the FD is
 * untracked and in a blocked range; otherwise let the host kernel handle it.
 */
/* How long a readiness call waits for the bridge pump to drain. A pass is
 * microseconds of work; the bound only keeps a wedged pump from hanging the
 * guest's poll.
 */
#define KBOX_READY_WAIT_MS 5

static struct kbox_dispatch forward_fd_gated_continue(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (io_should_deny_fd(ctx, req, fd, lkl_fd))
        return kbox_dispatch_errno(EBADF);
    /* epoll_wait/epoll_pwait: a bridged socket's peer bytes only reach the
     * guest's end of the socketpair when the pump moves them. Let the pump
     * finish, bounded, before the kernel measures readiness. */
    kbox_net_wait_until_quiet(KBOX_READY_WAIT_MS);
    return kbox_dispatch_continue();
}

/* Does this poll/ppoll ask about readability?
 *
 * Only readability justifies waiting for the bridge: the guest's socketpair end
 * becomes readable when the pump delivers, and a poll that arrives before that
 * delivery would report the fd as not readable. Writability is the socketpair's
 * own state and waiting for the bridge to drain would *change* it: a socket
 * whose peer has stopped reading looked writable for longer, and
 * test_socket.SendfileUsingSendTest.testWithTimeoutTriggeredSend then never hit
 * its ten-millisecond send timeout (it ran into the peer's close instead,
 * BrokenPipeError).
 */
static int poll_wants_read(const struct kbox_syscall_request *req,
                           struct kbox_supervisor_ctx *ctx)
{
    uint64_t fds_ptr = kbox_syscall_request_arg(req, 0);
    long nfds = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    pid_t pid = kbox_syscall_request_pid(req);
    uint8_t raw[8 * 32];

    if (!fds_ptr || nfds <= 0 || nfds > 32)
        return 1;
    if (guest_mem_read(ctx, pid, fds_ptr, raw, (size_t) nfds * 8) < 0)
        return 1;
    for (long i = 0; i < nfds; i++) {
        short events;

        /* struct pollfd { int fd; short events; short revents; } */
        memcpy(&events, raw + (size_t) i * 8 + 4, sizeof(events));
        if (events & (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND))
            return 1;
    }
    return 0;
}

/* poll/ppoll/pselect6 wait for readiness on descriptors the host kernel owns.
 *
 * A bridged socket is a socketpair end whose peer bytes arrive through the
 * bridge pump, so a poll that lands between a completed write and the pump's
 * next pass would report writability alone. An edge-triggered waiter then
 * collects a stale EPOLLOUT and loses the readable edge
 * (test_epoll.test_control_and_wait). The wait is delegated to the pump: this
 * thread holds no bridge lock and runs no LKL code, so the pump keeps making
 * progress.
 */
static struct kbox_dispatch forward_readiness_gated(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    struct kbox_dispatch deferred;

    if (kbox_try_defer_connect_poll(req, ctx, &deferred))
        return deferred;

    /* pselect6 (and a poll whose array cannot be read) waits unconditionally:
     * its readiness sets are bitmaps, and it is rare enough not to matter. */
    long style = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (style <= 0 || poll_wants_read(req, ctx))
        kbox_net_wait_until_quiet(KBOX_READY_WAIT_MS);
    return kbox_dispatch_continue();
}

/* Gate epoll_ctl: two FD args (epfd=arg0, fd=arg2). */
static struct kbox_dispatch forward_epoll_ctl_gated(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long epfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long lkl_ep = kbox_fd_table_get_lkl(ctx->fd_table, epfd);
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    /* A descriptor the table does not know about is not kbox's to refuse: the
     * call is continued to the host anyway, and the host returns EBADF by
     * itself when the descriptor really is invalid. Answering EBADF here
     * aborted postgres backends -- they register the client socket they
     * inherited from the postmaster, and kbox had no entry for that number, so
     * the backend died before it could serve a single query.
     */
    if (io_should_deny_fd(ctx, req, epfd, lkl_ep) ||
        io_should_deny_fd(ctx, req, fd, lkl_fd)) {
        if (getenv("KBOX_NET_TRACE"))
            fprintf(stderr,
                    "kbox: epoll_ctl untracked epfd=%ld lkl_ep=%ld fd=%ld "
                    "lkl_fd=%ld -> continue\n",
                    epfd, lkl_ep, fd, lkl_fd);
    }
    if (getenv("KBOX_NET_TRACE"))
        fprintf(stderr, "kbox: epoll_ctl ok epfd=%ld fd=%ld lkl_fd=%ld\n", epfd,
                fd, lkl_fd);
    return kbox_dispatch_continue();
}

/* Translate /proc/self and /proc/thread-self references to the tracee's
 * actual PID so the supervisor operates on the tracee's proc entries rather
 * than its own.
 */
static int is_decimal_fd_str(const char *s)
{
    if (!s || !*s)
        return 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
    }
    return 1;
}

void translate_proc_self(const char *path,
                         pid_t pid,
                         char *sv_path,
                         size_t sv_path_len)
{
    if (strncmp(path, "/proc/thread-self/", 18) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d/%s", (int) pid,
                 (int) pid, path + 18);
    else if (strcmp(path, "/proc/thread-self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/task/%d", (int) pid,
                 (int) pid);
    else if (strncmp(path, "/proc/self/", 11) == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/%s", (int) pid, path + 11);
    else if (strcmp(path, "/proc/self") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d", (int) pid);
    else if (strncmp(path, "/dev/fd/", 8) == 0 && is_decimal_fd_str(path + 8))
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/%s", (int) pid, path + 8);
    else if (strcmp(path, "/dev/fd") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd", (int) pid);
    else if (strcmp(path, "/dev/stdin") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/0", (int) pid);
    else if (strcmp(path, "/dev/stdout") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/1", (int) pid);
    else if (strcmp(path, "/dev/stderr") == 0)
        snprintf(sv_path, sv_path_len, "/proc/%d/fd/2", (int) pid);
    else
        snprintf(sv_path, sv_path_len, "%s", path);
}

/* Like translate_proc_self, for a path relative to a host dirfd. When the
 * dirfd is /proc itself, "self" and "thread-self" would resolve in the
 * supervisor's process (kboxd, dozens of threads), not the tracee's.
 * Chromium's zygote does fstatat(procfd, "self/task") and requires st_nlink
 * == 3 (single thread); seeing kboxd's task dir made it abort with SIGTRAP. */
static void translate_proc_self_at(int sv_dirfd,
                                   const char *path,
                                   pid_t pid,
                                   char *sv_path,
                                   size_t sv_path_len)
{
    if (sv_dirfd != AT_FDCWD && path[0] != '/') {
        int self_len = 0;
        const char *rest = NULL;
        if (!strncmp(path, "thread-self", 11) &&
            (path[11] == '\0' || path[11] == '/')) {
            self_len = 11;
            rest = path + 11;
        } else if (!strncmp(path, "self", 4) &&
                   (path[4] == '\0' || path[4] == '/')) {
            self_len = 4;
            rest = path + 4;
        }
        if (self_len) {
            char link[64], target[64];
            snprintf(link, sizeof(link), "/proc/self/fd/%d", sv_dirfd);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n == 5 && !memcmp(target, "/proc", 5)) {
                if (self_len == 11)
                    snprintf(sv_path, sv_path_len, "%d/task/%d%s", (int) pid,
                             (int) pid, rest);
                else
                    snprintf(sv_path, sv_path_len, "%d%s", (int) pid, rest);
                return;
            }
        }
    }
    translate_proc_self(path, pid, sv_path, sv_path_len);
}

/* Emulate an open that would otherwise CONTINUE to the host kernel, tracking
 * the resulting FD as host-passthrough.  The supervisor opens the file in its
 * own namespace, injects the FD into the tracee via ADDFD, and records it in
 * the FD table.  For /proc/self paths, the supervisor translates to
 * /proc/{pid} so the opened file reflects the tracee, not the supervisor.
 *
 * supervisor_dirfd: AT_FDCWD for absolute paths, or a supervisor-owned copy
 *                   of the tracee's dirfd (caller must close after return).
 */
/* Resident memory of one process, from /proc/<pid>/statm (2nd field, pages). */
static long long process_rss_bytes(pid_t pid)
{
    char path[48], buf[128];
    ssize_t n;
    int fd;
    char *p, *end;
    unsigned long long pages;

    snprintf(path, sizeof(path), "/proc/%d/statm", (int) pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    p = strchr(buf, ' ');
    if (!p)
        return 0;
    pages = strtoull(p + 1, &end, 10);
    if (end == p + 1)
        return 0;
    return (long long) (pages * (unsigned long long) sysconf(_SC_PAGESIZE));
}

/* What a per-container cgroup would report as its memory usage: the resident
 * memory of the processes this supervisor serves. */
static long long container_rss_bytes(const struct kbox_supervisor_ctx *ctx)
{
    long long total = 0;
    int root_seen = 0;

    for (size_t i = 0; i < ctx->proc_fd_count; i++) {
        pid_t tgid = ctx->proc_fds[i].tgid;
        if (tgid <= 0)
            continue;
        if (tgid == ctx->child_pid)
            root_seen = 1;
        total += process_rss_bytes(tgid);
    }
    if (!root_seen && ctx->child_pid > 0)
        total += process_rss_bytes(ctx->child_pid);
    return total;
}

/* A container reads its memory limit and usage from the cgroup files, and the
 * JVM, the JIT and ClickHouse size their heaps and caches from them. The files
 * show the whole pod, so every container believed it owned all of it (a stack
 * of JVMs grew past the pod's limit) and ClickHouse, comparing the pod's usage
 * with its own limit, refused every query. Give a container that has a limit of
 * its own (compose mem_limit, a Kubernetes resources limit) its own limit and
 * its own usage, as a real per-container cgroup would. The value is a snapshot
 * taken when the file is opened. */
static int try_cgroup_limit_open(struct kbox_supervisor_ctx *ctx,
                                 const struct kbox_syscall_request *req,
                                 const char *path,
                                 int host_flags,
                                 struct kbox_dispatch *out)
{
    char text[32];
    long long value;
    int len, memfd, tracee_fd;

    if (!ctx || ctx->mem_limit <= 0 || !path ||
        (host_flags & O_ACCMODE) != O_RDONLY)
        return 0;
    if (strcmp(path, "/sys/fs/cgroup/memory.max") == 0 ||
        strcmp(path, "/sys/fs/cgroup/memory/memory.limit_in_bytes") == 0)
        value = ctx->mem_limit;
    else if (strcmp(path, "/sys/fs/cgroup/memory.current") == 0 ||
             strcmp(path, "/sys/fs/cgroup/memory/memory.usage_in_bytes") == 0)
        value = container_rss_bytes(ctx);
    else
        return 0;

    len = snprintf(text, sizeof(text), "%lld\n", value);
    memfd = memfd_create("kbox-cgroup-file", MFD_CLOEXEC);
    if (memfd < 0)
        return 0;
    if (write(memfd, text, (size_t) len) != len) {
        close(memfd);
        return 0;
    }
    if (lseek(memfd, 0, SEEK_SET) < 0) {
        close(memfd);
        return 0;
    }
    tracee_fd = request_addfd(ctx, req, memfd,
                              (host_flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    close(memfd);
    if (tracee_fd < 0)
        return 0;
    if (tracee_fd >= 0)
        kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                      tracee_fd, 1);
    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (host_flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);
    *out = kbox_dispatch_value(tracee_fd);
    return 1;
}

/* Blocking FIFO open helper.
 *
 * A guest process opening a FIFO without O_NONBLOCK (O_RDONLY waiting for a
 * writer, or O_WRONLY waiting for a reader) must block until its peer opens
 * the other end. The container's supervisor is single-threaded, so performing
 * that openat() inline deadlocks the whole container: the peer's own openat()
 * queues behind the blocked thread and never runs. Offload the blocking open
 * onto a short-lived worker thread, park the notification, and complete it in
 * kbox_poll_pending_fifo_opens() once openat() returns.
 */
struct kbox_fifo_open_job {
    int dirfd;
    char path[KBOX_MAX_PATH];
    int open_flags;
    mode_t mode;
    int host_fd;
    int err;
    int done;
    int cancelled;
    pthread_t tid;
};

static pthread_once_t g_fifo_sig_once = PTHREAD_ONCE_INIT;

static void fifo_cancel_signal_handler(int sig)
{
    (void) sig;
}

static void install_fifo_cancel_signal(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fifo_cancel_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: pthread_kill must interrupt openat() */
    (void) sigaction(SIGUSR2, &sa, NULL);
}

static void *fifo_open_worker(void *arg)
{
    struct kbox_fifo_open_job *job = arg;
    sigset_t unblk;
    int fd;

    sigemptyset(&unblk);
    sigaddset(&unblk, SIGUSR2);
    (void) pthread_sigmask(SIG_UNBLOCK, &unblk, NULL);

    for (;;) {
        if (__atomic_load_n(&job->cancelled, __ATOMIC_ACQUIRE)) {
            fd = -1;
            job->err = EINTR;
            break;
        }
        fd = openat(job->dirfd, job->path, job->open_flags, job->mode);
        if (fd >= 0) {
            job->err = 0;
            break;
        }
        if (errno == EINTR)
            continue;
        job->err = errno;
        break;
    }
    if (job->dirfd >= 0) {
        close(job->dirfd);
        job->dirfd = -1;
    }
    job->host_fd = fd;
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static struct kbox_dispatch finish_host_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    int supervisor_dirfd,
    const char *sv_path,
    int host_flags,
    mode_t mode,
    int host_fd)
{
    uint32_t af = (host_flags & O_CLOEXEC) ? O_CLOEXEC : 0;
    int tracee_fd = request_addfd(ctx, req, host_fd, af);
    int opath_emulated = 0;

    /* The host kernel since 7.x refuses to install an O_PATH descriptor with
     * SECCOMP_IOCTL_NOTIF_ADDFD: the ioctl answers EBADF even though the
     * supervisor's own openat succeeded. Reopen without O_PATH and remember
     * the flag. The guest still gets a usable descriptor for fstat, fchmod,
     * fchdir and *at() calls; the one thing it loses is the read/write
     * refusal that O_PATH implies (Linux answers EBADF there), which nothing
     * in the Python test suite exercises. O_PATH|O_NOFOLLOW on a symlink is
     * the other difference: the reopen follows the link and fails with
     * ELOOP on a dangling one.
     */
    if (tracee_fd == -EBADF && (host_flags & O_PATH) && sv_path) {
        close(host_fd);
        int retry_flags =
            (host_flags & ~(O_PATH | O_ACCMODE)) | O_RDONLY | O_NONBLOCK;
        host_fd =
            openat(supervisor_dirfd, sv_path, retry_flags | O_CLOEXEC, mode);
        if (host_fd < 0)
            return kbox_dispatch_errno(errno);
        tracee_fd = request_addfd(ctx, req, host_fd, af);
        opath_emulated = 1;
    }

    close(host_fd);
    if (tracee_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: host openat(%s, flags=0x%x) addfd -> %d\n",
                    sv_path ? sv_path : "<fifo>", host_flags, tracee_fd);
        return kbox_dispatch_errno(-tracee_fd);
    }

    if (tracee_fd >= 0)
        kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                      tracee_fd, 1);
    track_host_passthrough_fd(ctx->fd_table, tracee_fd);
    if (opath_emulated)
        kbox_fd_table_set_opath(ctx->fd_table, tracee_fd, 1);
    if (host_flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, tracee_fd, 1);
    return kbox_dispatch_value(tracee_fd);
}

static struct kbox_dispatch defer_pending_fifo_open(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    int supervisor_dirfd,
    const char *sv_path,
    int host_flags,
    mode_t mode)
{
    struct kbox_pending_fifo_open *slot = NULL;
    struct kbox_fifo_open_job *job;

    for (size_t i = 0; i < KBOX_PENDING_FIFO_OPENS_MAX; i++) {
        if (!ctx->pending_fifo_opens[i].active) {
            slot = &ctx->pending_fifo_opens[i];
            break;
        }
    }
    if (!slot)
        return kbox_dispatch_errno(ENFILE);

    job = calloc(1, sizeof(*job));
    if (!job)
        return kbox_dispatch_errno(ENOMEM);

    if (supervisor_dirfd == AT_FDCWD) {
        job->dirfd = AT_FDCWD;
    } else {
        job->dirfd = fcntl(supervisor_dirfd, F_DUPFD_CLOEXEC, 3);
        if (job->dirfd < 0) {
            int err = errno;
            free(job);
            return kbox_dispatch_errno(err);
        }
    }
    snprintf(job->path, sizeof(job->path), "%s", sv_path);
    job->open_flags = host_flags | O_CLOEXEC;
    job->mode = mode;
    job->host_fd = -1;

    (void) pthread_once(&g_fifo_sig_once, install_fifo_cancel_signal);
    if (pthread_create(&job->tid, NULL, fifo_open_worker, job) != 0) {
        int err = errno;
        if (job->dirfd >= 0)
            close(job->dirfd);
        free(job);
        return kbox_dispatch_errno(err ? err : EAGAIN);
    }

    slot->active = 1;
    slot->cancelling = 0;
    slot->req = *req;
    slot->host_flags = host_flags;
    snprintf(slot->path, sizeof(slot->path), "%s", sv_path);
    slot->job = job;
    ctx->pending_fifo_open_count++;
    return (struct kbox_dispatch) {.kind = KBOX_DISPATCH_DEFERRED};
}

void kbox_poll_pending_fifo_opens(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || ctx->listener_fd < 0 || ctx->pending_fifo_open_count == 0)
        return;

    for (size_t i = 0; i < KBOX_PENDING_FIFO_OPENS_MAX; i++) {
        struct kbox_pending_fifo_open *pf = &ctx->pending_fifo_opens[i];
        struct kbox_fifo_open_job *job;
        uint64_t id;

        if (!pf->active)
            continue;
        job = pf->job;
        id = kbox_syscall_request_cookie(&pf->req);

        if (__atomic_load_n(&job->done, __ATOMIC_ACQUIRE)) {
            int host_fd = job->host_fd;
            int err = job->err;
            int cancelling = pf->cancelling;
            struct kbox_syscall_request saved_req = pf->req;
            int host_flags = pf->host_flags;
            char saved_path[KBOX_MAX_PATH];

            snprintf(saved_path, sizeof(saved_path), "%s", pf->path);
            (void) pthread_join(job->tid, NULL);
            free(job);
            pf->job = NULL;
            pf->active = 0;
            pf->cancelling = 0;
            ctx->pending_fifo_open_count--;

            if (cancelling) {
                if (host_fd >= 0)
                    close(host_fd);
                continue;
            }
            kbox_dispatch_prepare_request_ctx(ctx, &saved_req);
            struct kbox_dispatch d;
            if (host_fd < 0)
                d = kbox_dispatch_errno(err ? err : EIO);
            else
                d = finish_host_open_tracked(ctx, &saved_req, AT_FDCWD,
                                             saved_path, host_flags, 0,
                                             host_fd);
            kbox_notify_respond(ctx->listener_fd, id, &d);
            continue;
        }

        if (!pf->cancelling &&
            ioctl(ctx->listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ID_VALID, &id) <
                0) {
            pf->cancelling = 1;
            __atomic_store_n(&job->cancelled, 1, __ATOMIC_RELEASE);
        }
        if (pf->cancelling)
            (void) pthread_kill(job->tid, SIGUSR2);
    }
}

void kbox_cancel_pending_fifo_opens(struct kbox_supervisor_ctx *ctx)
{
    if (!ctx || ctx->pending_fifo_open_count == 0)
        return;

    for (size_t i = 0; i < KBOX_PENDING_FIFO_OPENS_MAX; i++) {
        struct kbox_pending_fifo_open *pf = &ctx->pending_fifo_opens[i];
        struct kbox_fifo_open_job *job;
        struct timespec ts = {0, 2 * 1000 * 1000};

        if (!pf->active)
            continue;
        job = pf->job;
        pf->cancelling = 1;
        __atomic_store_n(&job->cancelled, 1, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&job->done, __ATOMIC_ACQUIRE)) {
            (void) pthread_kill(job->tid, SIGUSR2);
            (void) nanosleep(&ts, NULL);
        }
        (void) pthread_join(job->tid, NULL);
        if (job->host_fd >= 0)
            close(job->host_fd);
        free(job);
        pf->job = NULL;
        pf->active = 0;
        pf->cancelling = 0;
        ctx->pending_fifo_open_count--;
    }
}

static struct kbox_dispatch emulate_host_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    int supervisor_dirfd,
    const char *path,
    int host_flags,
    mode_t mode)
{
    struct kbox_dispatch limit_dispatch;
    if (try_cgroup_limit_open(ctx, req, path, host_flags, &limit_dispatch))
        return limit_dispatch;

    char sv_path[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    translate_proc_self_at(supervisor_dirfd, path, pid, sv_path,
                           sizeof(sv_path));

    /* A blocking open of a FIFO (either a guest twin or a FIFO on a mounted
     * volume) would stall the single supervisor thread until the peer opens
     * the other end, deadlocking the whole container. */
    if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP && ctx->listener_fd >= 0 &&
        !(host_flags & (O_NONBLOCK | O_PATH | O_DIRECTORY | O_TMPFILE)) &&
        ((host_flags & O_ACCMODE) == O_RDONLY ||
         (host_flags & O_ACCMODE) == O_WRONLY)) {
        struct stat fifo_st;
        int st_flags = (host_flags & O_NOFOLLOW) ? AT_SYMLINK_NOFOLLOW : 0;

        if (fstatat(supervisor_dirfd, sv_path, &fifo_st, st_flags) == 0 &&
            S_ISFIFO(fifo_st.st_mode)) {
            if ((host_flags & O_ACCMODE) == O_WRONLY) {
                int fast_fd = openat(supervisor_dirfd, sv_path,
                                     host_flags | O_NONBLOCK | O_CLOEXEC, mode);
                if (fast_fd >= 0) {
                    int fl = fcntl(fast_fd, F_GETFL, 0);
                    if (fl >= 0)
                        (void) fcntl(fast_fd, F_SETFL, fl & ~O_NONBLOCK);
                    return finish_host_open_tracked(ctx, req, supervisor_dirfd,
                                                    sv_path, host_flags, mode,
                                                    fast_fd);
                }
                if (errno != ENXIO)
                    return kbox_dispatch_errno(errno);
            }
            return defer_pending_fifo_open(ctx, req, supervisor_dirfd, sv_path,
                                           host_flags, mode);
        }
    }

    /* A file created here is created by the supervisor's kernel, which applies
     * the supervisor's umask. The guest set its own umask, and a program that
     * asks for 0666 with umask 0 expects 0666 (test_pathlib.test_open_mode,
     * test_shutil.test_copytree_retains_permissions), so remember whether this
     * call creates the file and fix the mode afterwards.
     */
    int created_here = 0;
    if ((host_flags & O_CREAT) &&
        !(host_flags & (O_PATH | O_EXCL | O_TMPFILE))) {
        struct stat pre_st;

        if (fstatat(supervisor_dirfd, sv_path, &pre_st, AT_SYMLINK_NOFOLLOW) <
                0 &&
            errno == ENOENT)
            created_here = 1;
    }

    /* Enforce guest RLIMIT_NOFILE before opening/creating the file on disk so
     * O_CREAT|O_EXCL never leaves a file behind (and never leaks an injected
     * tracee FD) when the process is at its descriptor limit. */
    if (ctx->active_proc && ctx->active_proc->rlimit_nofile_cur < 65536) {
        int avail =
            find_available_tracee_fd(ctx, kbox_syscall_request_pid(req), 0);
        if (avail < 0 ||
            (uint64_t) avail >= ctx->active_proc->rlimit_nofile_cur)
            return kbox_dispatch_errno(EMFILE);
    }

    int host_fd =
        openat(supervisor_dirfd, sv_path, host_flags | O_CLOEXEC, mode);
    if (host_fd >= 0 && created_here) {
        unsigned umask_val = (ctx && ctx->active_proc)
                                 ? ctx->active_proc->umask
                                 : (ctx ? ctx->guest_umask : 022);
        mode_t want = (mode_t) ((unsigned) mode & ~umask_val & 07777U);

        (void) fchmod(host_fd, want);
    }
    if (host_fd < 0) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: host openat(dirfd=%d, %s, flags=0x%x mode=0%o) "
                    "-> errno %d\n",
                    supervisor_dirfd, sv_path, host_flags, (unsigned) mode,
                    errno);
        return kbox_dispatch_errno(errno);
    }

    return finish_host_open_tracked(ctx, req, supervisor_dirfd, sv_path,
                                    host_flags, mode, host_fd);
}

static int host_open_flags_write(long host_flags)
{
    return (host_flags & O_ACCMODE) != O_RDONLY ||
           (host_flags & (O_CREAT | O_TRUNC | O_APPEND));
}

static struct kbox_dispatch emulate_host_at_open_tracked(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req,
    long raw_dirfd,
    long lkl_dirfd,
    const char *translated,
    long host_flags,
    mode_t mode)
{
    pid_t pid = kbox_syscall_request_pid(req);

    if (host_open_flags_write(host_flags) &&
        host_bind_is_readonly(ctx, pid, raw_dirfd, lkl_dirfd))
        return kbox_dispatch_errno(EROFS);

    int sv_dirfd = AT_FDCWD;
    int close_sv = 0;
    int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd, &sv_dirfd,
                                           &close_sv);
    if (drc < 0)
        return kbox_dispatch_errno(-drc);

    struct kbox_dispatch d = emulate_host_open_tracked(
        ctx, req, sv_dirfd, translated, (int) host_flags, mode);
    if (close_sv)
        close(sv_dirfd);
    return d;
}

/* forward_openat. */

static int try_open_virtual_fd_link(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    const char *translated,
                                    long flags,
                                    struct kbox_dispatch *out);

/* Read a decimal sysctl through LKL itself.
 *
 * The guest's /proc can be served by kbox from the host (kbox continues
 * virtual paths to the host unless the container has a private procfs), so
 * reading these values from inside the guest describes the host kernel, not
 * the one that answered the failing call. Going through LKL answers the
 * question that matters.
 */
static long lkl_peek_number(const struct kbox_sysnrs *s, const char *path)
{
    char buf[32];
    long fd = kbox_lkl_openat(s, AT_FDCWD_LINUX, path, O_RDONLY, 0);
    long n;

    if (fd < 0)
        return fd;
    n = kbox_lkl_read(s, fd, buf, (long) sizeof(buf) - 1);
    (void) kbox_lkl_close(s, fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

/* FIFO twins.
 *
 * A FIFO the guest creates lives in the guest filesystem, which kbox serves
 * from LKL. An LKL descriptor is virtual: its number is 32768 or above and it
 * has no counterpart in the tracee's own descriptor table, so the kernel
 * cannot wait on it. select, poll and pselect therefore cannot watch a guest
 * FIFO -- and GNU make's jobserver IS a FIFO. make calls FD_SET on it, the
 * library's bounds check sees a descriptor above FD_SETSIZE, and the process
 * dies with SIGTRAP before it ever reaches pselect (item 28 in
 * three-suites-report.md).
 *
 * A FIFO on a host-backed mount does not have this problem: there kbox opens
 * the host file and injects a real descriptor. Give a guest FIFO the same
 * treatment through a twin on a tmpfs only the supervisor uses. Blocking,
 * end of file, several readers and writers, O_NONBLOCK and fstat then all come
 * from the host kernel, exactly as they do for a FIFO on a mounted volume.
 */
#define FIFO_TWIN_DIR "/dev/shm/kbox-fifos"
#define FIFO_TWIN_DIR_FALLBACK "/tmp/kbox-fifos"

static const char *fifo_twin_base(void)
{
    static const char *base;

    if (base)
        return base;
    if (mkdir(FIFO_TWIN_DIR, 0700) == 0 || errno == EEXIST)
        base = FIFO_TWIN_DIR;
    else if (mkdir(FIFO_TWIN_DIR_FALLBACK, 0700) == 0 || errno == EEXIST)
        base = FIFO_TWIN_DIR_FALLBACK;
    return base;
}

/* Name the host twin of the FIFO the guest path names.
 *
 * Returns 1 and fills out when the path is a FIFO, 0 otherwise. The twin is
 * keyed by the FIFO's inode, not by its name: a rename then keeps the same
 * twin, and a new FIFO created at an old name gets a new one. The twin is not
 * created here, so a caller that only needs the name (unlink) does not
 * recreate what it is about to remove. st_out, when given, receives the guest
 * inode's metadata, which the twin copies so fstat answers what the guest
 * expects.
 */
static int fifo_twin_name(struct kbox_supervisor_ctx *ctx,
                          long lkl_dirfd,
                          const char *guest_path,
                          char *out,
                          size_t out_size,
                          struct kbox_lkl_stat *st_out)
{
    struct kbox_lkl_stat st;
    const char *base;
    char dir[192];

    if (!ctx || !guest_path || !guest_path[0] || !out || out_size == 0)
        return 0;
    if (kbox_lkl_newfstatat(ctx->sysnrs, lkl_dirfd, guest_path, &st, 0) < 0)
        return 0;
    if ((st.st_mode & S_IFMT) != S_IFIFO)
        return 0;
    base = fifo_twin_base();
    if (!base)
        return 0;
    if (snprintf(dir, sizeof(dir), "%s/%d", base, (int) ctx->child_pid) >=
        (int) sizeof(dir))
        return 0;
    if (mkdir(dir, 0700) < 0 && errno != EEXIST)
        return 0;
    if (snprintf(out, out_size, "%s/%016llx-%016llx", dir,
                 (unsigned long long) st.st_dev,
                 (unsigned long long) st.st_ino) >= (int) out_size)
        return 0;
    if (st_out)
        *st_out = st;
    return 1;
}

/* Give the twin the metadata the guest asked for.
 *
 * The descriptor the guest receives is the twin, so fstat on it is the guest's
 * only way to ask about the FIFO it opened. A guest that created a 0640 FIFO
 * and then checks the mode of its own descriptor must not see 0600, which is
 * the mode the twin is created with. Copy the mode and the owner from the
 * guest inode on every open, so a later chmod is visible too. Device and inode
 * cannot be matched -- the twin lives on another filesystem -- and that
 * difference is measured and recorded by scripts/suites/fifo-twin.sh.
 *
 * Ownership is best effort: the supervisor opens the twin with its own
 * credentials, and the guest only reads the numbers back.
 */
static void fifo_twin_match_metadata(const char *twin,
                                     const struct kbox_lkl_stat *st)
{
    if (chmod(twin, (mode_t) (st->st_mode & 07777)) < 0 ||
        chown(twin, (uid_t) st->st_uid, (gid_t) st->st_gid) < 0)
        return;
}

/* The twin, created if this is the first open of that FIFO. */
static int fifo_host_twin(struct kbox_supervisor_ctx *ctx,
                          long lkl_dirfd,
                          const char *guest_path,
                          char *out,
                          size_t out_size)
{
    struct kbox_lkl_stat st;

    if (!fifo_twin_name(ctx, lkl_dirfd, guest_path, out, out_size, &st))
        return 0;
    if (mkfifo(out, 0600) < 0 && errno != EEXIST)
        return 0;
    fifo_twin_match_metadata(out, &st);
    return 1;
}

/* Remove the twins of a container whose supervised process has exited.
 *
 * The directory is named after the container's init process, and nothing in it
 * outlives that process. Without this call every container leaves an empty
 * directory behind, and the daemon is expected to run for months; the
 * directory is a supervisor-only tmpfs, so the leak is small but unbounded.
 */
void fifo_twin_cleanup(pid_t container_pid)
{
    const char *base = fifo_twin_base();
    char dir[192];
    DIR *d;
    struct dirent *de;

    if (!base || container_pid <= 0)
        return;
    if (snprintf(dir, sizeof(dir), "%s/%d", base, (int) container_pid) >=
        (int) sizeof(dir))
        return;
    d = opendir(dir);
    if (d) {
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] == '.')
                continue;
            (void) unlinkat(dirfd(d), de->d_name, 0);
        }
        closedir(d);
    }
    (void) rmdir(dir);
}

static struct kbox_dispatch forward_openat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = host_to_lkl_open_flags(host_flags_raw);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        return emulate_host_at_open_tracked(ctx, req, raw_dirfd, lkl_dirfd,
                                            translated, host_flags_raw,
                                            (mode_t) mode);
    }

    {
        struct kbox_dispatch fd_link_out;

        if (try_open_virtual_fd_link(ctx, req, translated, flags, &fd_link_out))
            return fd_link_out;
    }

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_raw, (mode_t) mode);

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    /* A guest FIFO is opened through its host twin, so the tracee gets a real
     * descriptor that select and pselect can watch. */
    {
        char twin[KBOX_MAX_PATH];

        if (fifo_host_twin(ctx, lkl_dirfd, translated, twin, sizeof(twin)) > 0)
            return emulate_host_open_tracked(
                ctx, req, AT_FDCWD, twin, (int) host_flags_raw, (mode_t) mode);
    }

    long ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
    if (ret == -EMFILE) {
        /* LKL starts its non-init tasks with a small descriptor limit. The
         * task that serves guest syscalls can therefore refuse an open that
         * the guest's own RLIMIT_NOFILE allows. Raise the serving task's limit
         * and retry once: the guest asked for a descriptor it is entitled to.
         *
         * Report what the serving task actually looks like: its own limit and
         * the number of descriptors its own table holds. The guest's
         * /proc/self/fd answers from the virtual table and hides both, which
         * is why the counter appeared to be at 22 while open returned EMFILE.
         */
        struct {
            unsigned long long cur, max;
        } before = {0, 0}, want = {1048576ULL, 1048576ULL};
        long prc = 0;

        (void) kbox_lkl_getrlimit(ctx->sysnrs, 0, 7, &before);
        int dir =
            (int) kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, "/proc/self/fd",
                                  O_RDONLY | O_DIRECTORY, 0);
        long dir_err = dir < 0 ? (long) dir : 0;
        long seen = -1;
        if (dir >= 0) {
            char dbuf[2048];
            long n;
            long total = 0;

            while ((n = kbox_lkl_getdents64(ctx->sysnrs, dir, dbuf,
                                            (long) sizeof(dbuf))) > 0) {
                long off = 0;

                while (off < n) {
                    unsigned short reclen;

                    memcpy(&reclen, dbuf + off + 16, sizeof(reclen));
                    if (reclen == 0)
                        break;
                    total++;
                    off += reclen;
                }
            }
            kbox_lkl_close(ctx->sysnrs, dir);
            seen = total;
        }
        prc = kbox_lkl_prlimit64(ctx->sysnrs, 0, 7, &want);

        long again =
            kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, flags, mode);
        if (getenv("KBOX_TRACE")) {
            long nr_open = lkl_peek_number(ctx->sysnrs, "/proc/sys/fs/nr_open");
            long file_max =
                lkl_peek_number(ctx->sysnrs, "/proc/sys/fs/file-max");
            long file_nr = lkl_peek_number(ctx->sysnrs, "/proc/sys/fs/file-nr");
            long null_fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                           "/dev/null", O_RDONLY, 0);
            long dup_fd =
                null_fd >= 0 ? kbox_lkl_dup(ctx->sysnrs, null_fd) : -1;

            if (dup_fd >= 0)
                (void) kbox_lkl_close(ctx->sysnrs, dup_fd);
            if (null_fd >= 0)
                (void) kbox_lkl_close(ctx->sysnrs, null_fd);
            static int emfile_probe_reported;

            if (emfile_probe_reported < 20) {
                emfile_probe_reported++;
                fprintf(stderr,
                        "kbox: EMFILE probe path=%s limit=%llu lkl_own_fds=%ld "
                        "dir_err=%ld raised=%ld retry=%ld nr_open=%ld "
                        "file_max=%ld file_nr=%ld null=%ld dup=%ld\n",
                        translated, before.cur, seen, dir_err, prc, again,
                        nr_open, file_max, file_nr, null_fd, dup_fd);
            }
        }
        ret = again;
    }
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr,
                "kbofdt: lkl_open path=%s flags=%#lx ret=%ld pid=%d "
                "source=%d table=%p\n",
                translated, (unsigned long) flags, ret,
                (int) kbox_syscall_request_pid(req), (int) req->source,
                (const void *) ctx->fd_table);
    if (ret == -24 && getenv("KBOX_FD_TRACE")) {
        struct {
            unsigned long long cur, max;
        } rl = {0, 0};
        long prc = kbox_lkl_getrlimit(ctx->sysnrs, 0, 7, &rl);
        fprintf(stderr,
                "kbofdt: lkl_emfile pid=%d prlimit_rc=%ld cur=%llu max=%llu\n",
                (int) kbox_syscall_request_pid(req), prc, rl.cur, rl.max);
    }
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

/* forward_openat2. */

static struct kbox_dispatch forward_openat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    struct kbox_open_how how;
    rc = guest_mem_read_open_how(ctx, kbox_syscall_request_pid(req),
                                 kbox_syscall_request_arg(req, 2),
                                 kbox_syscall_request_arg(req, 3), &how);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    long host_flags2_raw = (long) how.flags;
    how.flags = (uint64_t) host_to_lkl_open_flags((long) how.flags);

    if (should_continue_for_dirfd(lkl_dirfd)) {
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        return emulate_host_at_open_tracked(ctx, req, raw_dirfd, lkl_dirfd,
                                            translated, host_flags2_raw,
                                            (mode_t) how.mode);
    }

    {
        struct kbox_dispatch fd_link_out;

        if (try_open_virtual_fd_link(ctx, req, translated, (long) how.flags,
                                     &fd_link_out))
            return fd_link_out;
    }

    if (should_continue_virtual_path(ctx, req, 1, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags2_raw,
                                         (mode_t) how.mode);

    if (((long) how.flags & O_ACCMODE) == O_RDONLY) {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, (long) how.flags,
                                            translated, &cached_dispatch)) {
            return cached_dispatch;
        }
    }

    /* A guest FIFO is opened through its host twin, so the tracee gets a real
     * descriptor that select and pselect can watch. */
    {
        char twin[KBOX_MAX_PATH];

        if (fifo_host_twin(ctx, lkl_dirfd, translated, twin, sizeof(twin)) > 0)
            return emulate_host_open_tracked(ctx, req, AT_FDCWD, twin,
                                             (int) host_flags2_raw,
                                             (mode_t) how.mode);
    }

    long ret = kbox_lkl_openat2(ctx->sysnrs, lkl_dirfd, translated, &how,
                                (long) sizeof(how));
    if (ret == -ENOSYS) {
        if (how.resolve != 0)
            return kbox_dispatch_errno(EOPNOTSUPP);
        ret = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated,
                              (long) how.flags, (long) how.mode);
    }
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if (((long) how.flags & O_ACCMODE) != O_RDONLY ||
        ((long) how.flags & O_TRUNC)) {
        invalidate_path_shadow_cache(ctx);
    }
    return finish_open_dispatch(ctx, req, ret, (long) how.flags, translated);
}

/* forward_open_legacy (x86_64 open(2), nr=2). */

static struct kbox_dispatch forward_open_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long host_flags_legacy = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = host_to_lkl_open_flags(host_flags_legacy);
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (should_continue_for_dirfd(lkl_dirfd)) {
        return emulate_host_at_open_tracked(ctx, req, AT_FDCWD_LINUX, lkl_dirfd,
                                            translated, host_flags_legacy,
                                            (mode_t) mode);
    }

    {
        struct kbox_dispatch fd_link_out;

        if (try_open_virtual_fd_link(ctx, req, translated, flags, &fd_link_out))
            return fd_link_out;
    }

    if (should_continue_virtual_path(ctx, req, 0, translated) ||
        kbox_is_tty_like_path(translated))
        return emulate_host_open_tracked(ctx, req, AT_FDCWD, translated,
                                         (int) host_flags_legacy,
                                         (mode_t) mode);

    {
        struct kbox_dispatch cached_dispatch;
        if (try_cached_shadow_open_dispatch(ctx, req, flags, translated,
                                            &cached_dispatch))
            return cached_dispatch;
    }

    /* A guest FIFO is opened through its host twin, so the tracee gets a real
     * descriptor that select and pselect can watch. */
    {
        char twin[KBOX_MAX_PATH];

        if (fifo_host_twin(ctx, lkl_dirfd, translated, twin, sizeof(twin)) > 0)
            return emulate_host_open_tracked(ctx, req, AT_FDCWD, twin,
                                             (int) host_flags_legacy,
                                             (mode_t) mode);
    }

    long ret =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated, flags, mode);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
        invalidate_path_shadow_cache(ctx);
    return finish_open_dispatch(ctx, req, ret, flags, translated);
}

/* Does this translated path name one of the tracee's descriptors? */
int fd_magic_link_fd(const char *path, long *out_fd)
{
    const char *p = NULL;
    char *end = NULL;
    long v;

    if (!path)
        return 0;
    if (!strncmp(path, "/proc/", 6)) {
        const char *q = path + 6;

        if (!strncmp(q, "self/fd/", 8)) {
            p = q + 8;
        } else if (!strncmp(q, "thread-self/fd/", 15)) {
            p = q + 15;
        } else {
            while (*q >= '0' && *q <= '9')
                q++;
            if (!strncmp(q, "/fd/", 4))
                p = q + 4;
        }
    } else if (!strncmp(path, "/dev/fd/", 8)) {
        p = path + 8;
    }
    if (!p || !*p)
        return 0;
    v = strtol(p, &end, 10);
    if (end == p || (*end && *end != '/'))
        return 0;
    *out_fd = v;
    return 1;
}

/* open("/proc/self/fd/N") where N is a kbox virtual descriptor.
 *
 * A virtual descriptor is not a host descriptor number, so the host's
 * /proc/<pid>/fd/<N> does not exist and the open failed with ENOENT. CPython's
 * test_cmd_line_script passes a script to a child as /dev/fd/N and expects the
 * child to open it; shells and editors do the same with their own descriptors.
 * Serve the open from the file kbox already holds for that descriptor: opening
 * a magic link means "a new file description of the same file, at offset 0",
 * which is exactly a fresh description of the shadow or of a copy of the guest
 * file.
 */
static int try_open_virtual_fd_link(struct kbox_supervisor_ctx *ctx,
                                    const struct kbox_syscall_request *req,
                                    const char *translated,
                                    long flags,
                                    struct kbox_dispatch *out)
{
    long vfd;
    struct kbox_fd_entry *e;
    int sp = -1;
    long target;
    int injected;
    struct kbox_fd_entry *ne;

    if (!fd_magic_link_fd(translated, &vfd) || vfd < 0)
        return 0;
    e = fd_table_entry(ctx->fd_table, vfd);
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr,
                "kbofdt: fdlink path=%s vfd=%ld entry=%p lkl=%ld sp=%d "
                "flags=0x%lx\n",
                translated, vfd, (void *) e, e ? e->lkl_fd : -99L,
                e ? e->shadow_sp : -99, flags);
    if (!e || e->lkl_fd < 0)
        return 0;
    if ((flags & O_ACCMODE) != O_RDONLY)
        return 0;

    if (e->shadow_sp >= 0) {
        int dirfd = ensure_proc_self_fd_dir(ctx);

        if (dirfd >= 0) {
            char name[32];

            snprintf(name, sizeof(name), "%d", e->shadow_sp);
            sp = openat(dirfd, name, O_RDONLY | O_CLOEXEC);
        }
    }
    if (sp < 0) {
        sp = kbox_shadow_create_resilient(ctx, e->lkl_fd);
        if (sp < 0)
            return 0;
        kbox_shadow_seal(sp);
    }

    target = allocate_shadow_fd_from(ctx, KBOX_NATIVE_CLOSE_MAX);
    if (target < 0) {
        close(sp);
        return 0;
    }
    injected = request_addfd_at(ctx, req, sp, (int) target,
                                (flags & O_CLOEXEC) ? O_CLOEXEC : 0);
    if (injected < 0) {
        close(sp);
        return 0;
    }
    if (kbox_fd_table_insert_at(ctx->fd_table, injected, e->lkl_fd, 0) < 0) {
        close(sp);
        *out = kbox_dispatch_errno(EMFILE);
        return 1;
    }
    note_low_fd_identity(ctx, kbox_syscall_request_pid(req), injected);
    ne = fd_table_entry(ctx->fd_table, injected);
    if (ne) {
        ne->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
        ne->shadow_sp = sp;
    } else {
        close(sp);
    }
    *out = kbox_dispatch_value((int64_t) injected);
    return 1;
}

/* Writeback of a writable shadow, off the dispatch thread.
 *
 * A writable open promotes the file to a memfd copy, and close(2) copies that
 * copy back into the guest filesystem. The copy runs LKL calls, and in the pod
 * one such call never returned: the tracee stayed in the kernel waiting for
 * its close() answer, one daemon thread spun inside LKL, and the guest survived
 * `docker rm -f` and took test_ssl, test_asyncio and test_socket down with it.
 *
 * The copy therefore runs in its own thread while the dispatch thread waits for
 * it with a budget. A copy that finishes in time reports its result; a copy
 * that outstays the budget is abandoned, the guest's close(2) reports success,
 * and the LKL descriptor is retired from reuse so the abandoned call cannot
 * write into a file that later receives the same number.
 */

/* Largest number of abandoned copies one supervisor keeps track of. Each one
 * leaks an LKL descriptor on purpose; a container that wedges more files than
 * this is beyond saving anyway. */
#define KBOX_WB_ABANDONED_MAX 64
#define KBOX_WB_DEFAULT_TIMEOUT 8

static pthread_mutex_t kbox_wb_lock = PTHREAD_MUTEX_INITIALIZER;
static long kbox_wb_abandoned_fd[KBOX_WB_ABANDONED_MAX];
static int kbox_wb_abandoned_n;

void kbox_lkl_fd_mark_abandoned(long lkl_fd)
{
    pthread_mutex_lock(&kbox_wb_lock);
    if (kbox_wb_abandoned_n < KBOX_WB_ABANDONED_MAX)
        kbox_wb_abandoned_fd[kbox_wb_abandoned_n++] = lkl_fd;
    pthread_mutex_unlock(&kbox_wb_lock);
}

int kbox_lkl_fd_is_abandoned(long lkl_fd)
{
    int found = 0;

    if (lkl_fd < 0)
        return 0;
    pthread_mutex_lock(&kbox_wb_lock);
    for (int i = 0; i < kbox_wb_abandoned_n; i++) {
        if (kbox_wb_abandoned_fd[i] == lkl_fd) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&kbox_wb_lock);
    return found;
}

static int kbox_wb_budget(void)
{
    const char *env = getenv("KBOX_WB_TIMEOUT");

    if (env && *env) {
        char *end = NULL;
        long sec = strtol(env, &end, 10);

        if (end && *end == '\0' && sec > 0 && sec <= 600)
            return (int) sec;
    }
    return KBOX_WB_DEFAULT_TIMEOUT;
}

/* One copy-back job. The worker owns everything it needs: the descriptor it
 * copies from, the LKL descriptor it writes to, and the size. Nothing points
 * back into the FD table, which is free to drop the entry while the worker
 * still runs. */
struct kbox_wb_job {
    const struct kbox_sysnrs *sysnrs;
    long lkl_fd;
    int memfd;
    off_t size;
    int verbose;
    int result;
    int done;
    int abandoned;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

/* Copy the memfd back into the guest file. Returns 0 or a negative errno. */
static int writeback_copy(const struct kbox_sysnrs *sysnrs,
                          long lkl_fd,
                          int memfd,
                          off_t size,
                          int verbose)
{
    uint8_t *buf;
    off_t off = 0;
    off_t saved;
    long trunc_ret;
    int result = 0;

    /* Copy what the shadow holds now, not what it held when this job was
     * queued.
     *
     * The memfd is the authority and this call may run on a thread that was
     * started earlier: a thread exit and a close of the same file each queue a
     * copy, the later one sees the larger shadow, and the earlier one finishing
     * last used to truncate the guest file back to its own stale size. The
     * memfd only shrinks when the guest truncates it, so its current size is
     * the size the guest expects to find.
     */
    {
        struct stat now;

        if (fstat(memfd, &now) == 0 && now.st_size != size) {
            if (verbose || getenv("KBOX_FD_TRACE"))
                fprintf(stderr,
                        "kbox: writeback size lkl_fd=%ld "
                        "queued=%lld now=%lld\n",
                        lkl_fd, (long long) size, (long long) now.st_size);
            size = now.st_size;
        }
    }

    /* LKL returns -errno. A signal during a multi-gigabyte copy-back is normal,
     * and giving up on -EINTR left the guest file truncated at whatever had
     * been copied so far. */
    if (verbose)
        fprintf(stderr, "kbox: writeback truncate begin lkl_fd=%ld size=%lld\n",
                lkl_fd, (long long) size);
    trunc_ret = kbox_lkl_ftruncate_safe(sysnrs, lkl_fd, (long) size);
    while (trunc_ret == -EINTR)
        trunc_ret = kbox_lkl_ftruncate_safe(sysnrs, lkl_fd, (long) size);
    if (verbose)
        fprintf(stderr, "kbox: writeback truncate done lkl_fd=%ld ret=%ld\n",
                lkl_fd, trunc_ret);
    if (trunc_ret < 0) {
        fprintf(stderr,
                "kbox: writeback failed: ftruncate lkl_fd=%ld size=%lld: %ld\n",
                lkl_fd, (long long) size, trunc_ret);
        return -EIO;
    }

    /* The dispatch buffer does not belong to this thread. */
    buf = malloc(KBOX_IO_CHUNK_LEN);
    if (!buf)
        return -ENOMEM;

    /* The shadow is one file description shared with the tracee: ADDFD
     * installs that same struct file, so a dup of it can already be another
     * process's stdin. read(2) and lseek(2) here move the offset the guest
     * sees; pread(2) does not. Leaving the offset at EOF made a child that
     * inherited the descriptor read nothing at all
     * (test_cmd_line.test_stdin_readline). Working on a descriptor of its own
     * makes that moot, and the save/restore keeps the synchronous fallback
     * honest.
     */
    saved = lseek(memfd, 0, SEEK_CUR);
    if (verbose)
        fprintf(stderr, "kbox: writeback copy begin lkl_fd=%ld size=%lld\n",
                lkl_fd, (long long) size);

    while (off < size) {
        off_t data = off;
        off_t hole = size;

        /* Large files are copied by extent. A sparse 2 GiB file holds a few
         * blocks of data; copying the holes would materialize them in the
         * guest filesystem, which cannot hold that many (test_largefile).
         * SEEK_DATA moves the offset, so it is restored right after the scan.
         */
        if (size > KBOX_SHADOW_MAX_BYTES) {
            data = lseek(memfd, off, SEEK_DATA);
            if (data < 0) {
                if (errno == ENXIO)
                    break;  /* only holes remain */
                data = off; /* SEEK_DATA unsupported: copy from here */
            }
            hole = lseek(memfd, data, SEEK_HOLE);
            if (hole <= data)
                hole = size;
            if (saved >= 0)
                (void) lseek(memfd, saved, SEEK_SET);
        }

        while (data < hole) {
            size_t chunk = KBOX_IO_CHUNK_LEN;
            ssize_t rd;
            long done = 0;

            if ((off_t) chunk > hole - data)
                chunk = (size_t) (hole - data);
            rd = pread(memfd, buf, chunk, data);
            while (rd < 0 && errno == EINTR)
                rd = pread(memfd, buf, chunk, data);
            if (rd < 0) {
                result = -errno;
                goto out;
            }
            if (rd == 0)
                break;
            /* A short write leaves the tail of `rd` in the shadow and the
             * guest file silently shortened, so the chunk is written out
             * completely; EINTR from either layer is retried in place. */
            while (done < rd) {
                long wr =
                    kbox_lkl_pwrite64(sysnrs, lkl_fd, buf + done,
                                      (long) (rd - done), (long) (data + done));
                if (wr == -EINTR)
                    continue;
                if (wr <= 0) {
                    fprintf(stderr,
                            "kbox: writeback failed: pwrite lkl_fd=%ld "
                            "off=%lld: %ld\n",
                            lkl_fd, (long long) (data + done), wr);
                    result = wr < 0 ? (int) wr : -EIO;
                    goto out;
                }
                done += wr;
            }
            data += rd;
        }
        off = hole;
    }

out:
    if (saved >= 0)
        (void) lseek(memfd, saved, SEEK_SET);
    free(buf);
    if (verbose)
        fprintf(stderr, "kbox: writeback done lkl_fd=%ld result=%d\n", lkl_fd,
                result);
    return result;
}

static void *kbox_wb_worker(void *arg)
{
    struct kbox_wb_job *job = arg;
    int result = writeback_copy(job->sysnrs, job->lkl_fd, job->memfd, job->size,
                                job->verbose);
    int abandoned;

    close(job->memfd);
    pthread_mutex_lock(&job->lock);
    job->result = result;
    job->done = 1;
    abandoned = job->abandoned;
    pthread_cond_signal(&job->cond);
    pthread_mutex_unlock(&job->lock);

    if (abandoned) {
        pthread_mutex_destroy(&job->lock);
        pthread_cond_destroy(&job->cond);
        free(job);
    }
    return NULL;
}

/* A descriptor of the memfd with an offset of its own, so the worker never
 * moves the offset the guest reads from. Falls back to a shared dup. */
static int writeback_new_memfd(int shadow_sp)
{
    char path[48];
    int fd;

    snprintf(path, sizeof(path), "/proc/self/fd/%d", shadow_sp);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
        return fd;
    return dup(shadow_sp);
}

static int writeback_run(struct kbox_supervisor_ctx *ctx,
                         long lkl_fd,
                         int shadow_sp,
                         off_t size)
{
    struct kbox_wb_job *job;
    struct timespec deadline;
    pthread_t thread;
    pthread_attr_t attr;
    int budget = kbox_wb_budget();
    int memfd;
    int result;

    memfd = writeback_new_memfd(shadow_sp);
    if (memfd < 0)
        return writeback_copy(ctx->sysnrs, lkl_fd, shadow_sp, size,
                              ctx->verbose);

    job = calloc(1, sizeof(*job));
    if (!job) {
        close(memfd);
        return writeback_copy(ctx->sysnrs, lkl_fd, shadow_sp, size,
                              ctx->verbose);
    }
    job->sysnrs = ctx->sysnrs;
    job->lkl_fd = lkl_fd;
    job->memfd = memfd;
    job->size = size;
    job->verbose = ctx->verbose;
    pthread_mutex_init(&job->lock, NULL);
    /* The NULL attribute argument selects the default attributes; it is not a
     * dereference. cppcheck reports nullPointer for it (a fifteen-line
     * program does the same). */
    /* cppcheck-suppress nullPointer */
    pthread_cond_init(&job->cond, NULL);

    if (pthread_attr_init(&attr) != 0)
        goto synchronous;
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    result = pthread_create(&thread, &attr, kbox_wb_worker, job);
    pthread_attr_destroy(&attr);
    if (result != 0)
        goto synchronous;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += budget;

    pthread_mutex_lock(&job->lock);
    while (!job->done) {
        if (pthread_cond_timedwait(&job->cond, &job->lock, &deadline) ==
            ETIMEDOUT)
            break;
    }
    if (!job->done) {
        /* The worker is inside an LKL call that will not return. Give the
         * guest its close() back and retire the descriptor. */
        job->abandoned = 1;
        pthread_mutex_unlock(&job->lock);
        kbox_lkl_fd_mark_abandoned(lkl_fd);
        fprintf(stderr,
                "kbox: writeback stalled for %ds; lkl_fd=%ld stays open and "
                "the guest continues\n",
                budget, lkl_fd);
        return 0;
    }
    result = job->result;
    pthread_mutex_unlock(&job->lock);
    pthread_mutex_destroy(&job->lock);
    pthread_cond_destroy(&job->cond);
    free(job);
    return result;

synchronous:
    close(memfd);
    pthread_mutex_destroy(&job->lock);
    pthread_cond_destroy(&job->cond);
    free(job);
    return writeback_copy(ctx->sysnrs, lkl_fd, shadow_sp, size, ctx->verbose);
}

int sync_shadow_writeback(struct kbox_supervisor_ctx *ctx,
                          struct kbox_fd_entry *entry)
{
    struct stat st;

    if (!ctx || !entry || !entry->shadow_writeback || entry->shadow_sp < 0 ||
        entry->lkl_fd < 0)
        return 0;

    if (fstat(entry->shadow_sp, &st) < 0)
        return -errno;
    if (getenv("KBOX_FD_TRACE"))
        fprintf(stderr,
                "kbofdt: writeback entry=%p lkl=%ld sp=%d size=%lld "
                "rec_size=%ld rec_mtime=%ld\n",
                (void *) entry, entry->lkl_fd, entry->shadow_sp,
                (long long) st.st_size, entry->shadow_size,
                entry->shadow_mtime_sec);

    /* A writable open promotes the file to a memfd copy, and closing it copies
     * the whole memfd back. Nothing wrote to the memfd in the common case, and
     * an unconditional ftruncate+pwrite restamps mtime and ctime on the real
     * file: `open(path, "r+b")` followed by close then made a file that utime()
     * had just given a fixed timestamp look modified again. The memfd carries
     * the timestamp it had when it was filled, so an unchanged timestamp and
     * size mean "no writeback needed". */
    if (!entry->shadow_mmap && entry->shadow_mtime_sec != 0 &&
        (long) st.st_mtim.tv_sec == entry->shadow_mtime_sec &&
        (long) st.st_mtim.tv_nsec == entry->shadow_mtime_nsec &&
        (long) st.st_size == entry->shadow_size) {
        if (getenv("KBOX_FD_TRACE"))
            fprintf(stderr,
                    "kbofdt: writeback skip entry=%p lkl=%ld sp=%d size=%lld\n",
                    (void *) entry, entry->lkl_fd, entry->shadow_sp,
                    (long long) st.st_size);
        return 0;
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: shadow writeback lkl_fd=%ld shadow_size=%lld\n",
                entry->lkl_fd, (long long) st.st_size);

    /* The copy runs on its own thread: see writeback_run(). */
    return writeback_run(ctx, entry->lkl_fd, entry->shadow_sp, st.st_size);
}

/* forward_close. */

/* Close watches.
 *
 * A guest descriptor is a memfd on the host, and its close runs in the host
 * kernel without reaching the supervisor. An inotify watch on the memfd's
 * inode reports the moment the last reference disappears, which is exactly
 * when the LKL descriptor and the shadow must be released. The watch is keyed
 * by the watch descriptor the kernel hands back; the LKL side belongs to the
 * open file description, not to any single descriptor slot.
 */

static int close_watch_init(struct kbox_supervisor_ctx *ctx)
{
    if (ctx->close_inotify_fd >= 0)
        return 0;
    ctx->close_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    return ctx->close_inotify_fd < 0 ? -1 : 0;
}

static struct kbox_vfd_watch *close_watch_find(struct kbox_supervisor_ctx *ctx,
                                               int wd)
{
    for (size_t i = 0; i < ctx->close_watch_count; i++)
        if (ctx->close_watches[i].in_use && ctx->close_watches[i].wd == wd)
            return &ctx->close_watches[i];
    return NULL;
}

static struct kbox_vfd_watch *close_watch_alloc(struct kbox_supervisor_ctx *ctx)
{
    for (size_t i = 0; i < ctx->close_watch_count; i++)
        if (!ctx->close_watches[i].in_use)
            return &ctx->close_watches[i];
    if (ctx->close_watch_count == ctx->close_watch_cap) {
        size_t cap = ctx->close_watch_cap ? ctx->close_watch_cap * 2 : 64;
        struct kbox_vfd_watch *grown;

        if (cap > SIZE_MAX / sizeof(*grown))
            return NULL;
        grown = realloc(ctx->close_watches, sizeof(*grown) * cap);
        if (!grown)
            return NULL;
        memset(grown + ctx->close_watch_cap, 0,
               sizeof(*grown) * (cap - ctx->close_watch_cap));
        ctx->close_watches = grown;
        ctx->close_watch_cap = cap;
    }
    return &ctx->close_watches[ctx->close_watch_count++];
}

/* Free what the description owned. Called once, when the kernel says the last
 * guest reference is gone. */
static void close_watch_release(struct kbox_supervisor_ctx *ctx,
                                struct kbox_vfd_watch *w,
                                int ignored)
{
    if (ctx->fd_table) {
        /* next_fd is the highest number ever handed out, so nothing above it
         * can still hold this watch; scanning the whole array on every close
         * costs far more than the bookkeeping is worth. */
        long limit = ctx->fd_table->next_fd + 1;

        if (limit > KBOX_FD_TABLE_CAPACITY)
            limit = KBOX_FD_TABLE_CAPACITY;
        for (long fd = 0; fd < limit; fd++) {
            struct kbox_fd_entry *e = fd_table_entry(ctx->fd_table, fd);

            if (e && e->watch_wd == w->wd)
                kbox_fd_table_remove(ctx->fd_table, fd);
        }
    }
    if (w->shadow_writeback) {
        struct kbox_fd_entry tmp;

        memset(&tmp, 0, sizeof(tmp));
        tmp.lkl_fd = w->lkl_fd;
        tmp.host_fd = -1;
        tmp.host_sv_fd = -1;
        tmp.shadow_sp = w->shadow_sp;
        tmp.shadow_writeback = w->shadow_writeback;
        tmp.shadow_mtime_sec = w->shadow_mtime_sec;
        tmp.shadow_mtime_nsec = w->shadow_mtime_nsec;
        tmp.shadow_size = w->shadow_size;
        (void) sync_shadow_writeback(ctx, &tmp);
    }
    if (w->lkl_fd >= 0)
        invalidate_stat_cache_fd(ctx, w->lkl_fd);
    if (!ignored && w->wd >= 0 && ctx->close_inotify_fd >= 0)
        (void) inotify_rm_watch(ctx->close_inotify_fd, w->wd);
    if (w->lkl_fd >= 0)
        ctx_close_lkl_if_unreferenced(ctx, w->lkl_fd, 0);
    if (w->shadow_sp >= 0)
        close(w->shadow_sp);
    w->in_use = 0;
}

void kbox_drain_close_watches(struct kbox_supervisor_ctx *ctx)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    if (!ctx || ctx->close_inotify_fd < 0)
        return;
    for (;;) {
        ssize_t got = read(ctx->close_inotify_fd, buf, sizeof(buf));
        ssize_t off = 0;

        if (got < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        if (got == 0)
            return;
        while (off + (ssize_t) sizeof(struct inotify_event) <= got) {
            struct inotify_event *e = (struct inotify_event *) (buf + off);
            struct kbox_vfd_watch *w;

            off += (ssize_t) (sizeof(*e) + e->len);
            if (e->mask & IN_Q_OVERFLOW) {
                fprintf(stderr, "kbox: close watch queue overflowed\n");
                continue;
            }
            if (!(e->mask & (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)))
                continue;
            w = close_watch_find(ctx, e->wd);
            if (!w)
                continue;
            close_watch_release(ctx, w, (e->mask & IN_IGNORED) != 0);
        }
        if ((size_t) got < sizeof(buf))
            return;
    }
}

/* Start watching a memfd that the guest is about to hold. Returns the watch
 * descriptor, or -1 when watching is not possible (the descriptor then keeps
 * the old, notification-based close handling). */
static int close_watch_register(struct kbox_supervisor_ctx *ctx,
                                int memfd,
                                long lkl_fd,
                                int shadow_sp,
                                const struct kbox_fd_entry *src)
{
    char path[64];
    struct kbox_vfd_watch *w;
    int wd;

    if (!ctx || memfd < 0 || close_watch_init(ctx) != 0)
        return -1;
    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", memfd) >=
        (int) sizeof(path))
        return -1;
    wd = inotify_add_watch(ctx->close_inotify_fd, path,
                           IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
    if (wd < 0)
        return -1;
    w = close_watch_alloc(ctx);
    if (!w) {
        (void) inotify_rm_watch(ctx->close_inotify_fd, wd);
        return -1;
    }
    memset(w, 0, sizeof(*w));
    w->wd = wd;
    w->lkl_fd = lkl_fd;
    w->shadow_sp = shadow_sp;
    if (src) {
        w->shadow_writeback = src->shadow_writeback;
        w->shadow_mtime_sec = src->shadow_mtime_sec;
        w->shadow_mtime_nsec = src->shadow_mtime_nsec;
        w->shadow_size = src->shadow_size;
        w->guest_id = src->guest_id;
    }
    w->in_use = 1;
    return wd;
}

static struct kbox_dispatch forward_close(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    int same_fd_shadow = entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW;
    kbox_net_forget_fd(fd);
    if (fd_trace_enabled())
        fprintf(stderr,
                "kbofdt: close pid=%d fd=%ld lkl=%ld host_fd=%ld shadow=%d "
                "tgid=%d\n",
                (int) kbox_syscall_request_pid(req), fd, lkl_fd,
                entry ? entry->host_fd : -99L,
                entry && entry->shadow_sp >= 0 ? 1 : 0,
                ctx->active_proc ? (int) ctx->active_proc->tgid : 0);
    if (fd <= 2 && ctx->verbose)
        fprintf(stderr, "kbox: close fd=%ld lkl=%ld pid=%u\n", fd, lkl_fd,
                kbox_syscall_request_pid(req));

    if (lkl_fd >= 0) {
        struct kbox_lkl_stat lock_st;

        /* A process that closes any descriptor on a file loses its POSIX locks
         * on that file; the open file description's locks end with it too. */
        if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &lock_st) == 0)
            kbox_lock_release_file(&ctx->locks, kbox_syscall_request_pid(req),
                                   (int) lkl_fd, lock_st.st_dev,
                                   lock_st.st_ino);
        invalidate_stat_cache_fd(ctx, lkl_fd);
    }

    if (entry && entry->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Host-passthrough FDs (pipes, eventfds, stdio): the host kernel
         * tracks per-process FD lifecycle, so close via CONTINUE is correct.
         * Keep the FD table entry alive because the table is shared across
         * all supervised processes (parent + children after fork).  If the
         * child closes a pipe FD, the entry must remain so the parent (or
         * a sibling) that still holds the same FD number isn't denied.
         * Shadow socket entries (shadow_sp >= 0) hold supervisor resources
         * that must be released, so those are still removed.
         */
        if (entry->shadow_sp >= 0)
            kbox_fd_table_remove(ctx->fd_table, fd);
        if (fd_trace_enabled())
            fprintf(stderr,
                    "kbofdt: close-act fd=%ld act=shadowonly-continue\n", fd);
        return kbox_dispatch_continue();
    }

    if (lkl_fd >= 0) {
        if ((ctx->verbose || getenv("KBOX_FD_TRACE")) && fd >= 0)
            fprintf(stderr,
                    "kbox: close vfd=%ld lkl=%ld host_fd=%ld shadow_sp=%d "
                    "writeback=%d\n",
                    fd, lkl_fd, entry ? entry->host_fd : -99L,
                    entry ? entry->shadow_sp : -99,
                    entry ? entry->shadow_writeback : -99);
        if (same_fd_shadow) {
            if (entry && entry->shadow_writeback)
                (void) sync_shadow_writeback(ctx, entry);
            note_shadow_writeback_close(ctx, entry);
            kbox_fd_table_remove(ctx->fd_table, fd);
            ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 0);
            if (fd_trace_enabled())
                fprintf(stderr,
                        "kbofdt: close-act fd=%ld act=samefd-continue\n", fd);
            return kbox_dispatch_continue();
        }

        kbox_fd_table_remove(ctx->fd_table, fd);
        long ret = ctx_close_lkl_if_unreferenced(ctx, lkl_fd, 0);
        if (ret < 0 && fd >= 0) {
            if (fd_trace_enabled())
                fprintf(stderr,
                        "kbofdt: close-act fd=%ld act=vfd-errno ret=%ld\n", fd,
                        ret);
            return kbox_dispatch_errno((int) (-ret));
        }

        /* A redirect onto a number the host no longer holds must still answer
         * success: shells close the real stdio descriptor before pointing the
         * number at a virtual one, and the host would answer EBADF for a close
         * the guest has every right to expect to succeed. When the tracee does
         * hold a descriptor at this number, the close is passed through so the
         * kernel releases it too; a virtual descriptor that shares its number
         * with an injected shadow would otherwise leak on this side.
         */
        if (child_fd_is_open(ctx, fd)) {
            if (fd_trace_enabled())
                fprintf(stderr, "kbofdt: close-act fd=%ld act=vfd-continue\n",
                        fd);
            return kbox_dispatch_continue();
        }
        if (fd_trace_enabled())
            fprintf(stderr, "kbofdt: close-act fd=%ld act=vfd-value0 lkl=%ld\n",
                    fd, lkl_fd);
        return kbox_dispatch_value(0);
    }

    /* Not a virtual FD.  Check if this is a host FD that was injected
     * as shadow (the tracee closes it by the host number).  If so,
     * close the LKL side and let the host kernel close the host FD
     * via CONTINUE.
     */
    long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0) {
        struct kbox_fd_entry *shadow_entry = fd_table_entry(ctx->fd_table, vfd);
        long lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);

        if (shadow_entry && shadow_entry->shadow_writeback)
            (void) sync_shadow_writeback(ctx, shadow_entry);
        note_shadow_writeback_close(ctx, shadow_entry);
        if (lkl >= 0)
            invalidate_stat_cache_fd(ctx, lkl);
        kbox_fd_table_remove(ctx->fd_table, vfd);

        if (lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, lkl, 1);
        if (fd_trace_enabled())
            fprintf(stderr, "kbofdt: close-act fd=%ld act=byhost-continue\n",
                    fd);
        return kbox_dispatch_continue();
    }

    if (fd_trace_enabled())
        fprintf(stderr, "kbofdt: close-act fd=%ld act=none-continue\n", fd);
    return kbox_dispatch_continue();
}

/* forward_read_like (read and pread64). */

static struct kbox_dispatch forward_read_like(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_pread)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (fd <= 2 && ctx->verbose)
        fprintf(stderr, "kbox: read fd=%ld lkl=%ld n=%ld pid=%u\n", fd, lkl_fd,
                to_c_long_arg(kbox_syscall_request_arg(req, 2)),
                kbox_syscall_request_pid(req));
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW) {
                return forward_local_shadow_read_like(req, ctx, entry, lkl_fd,
                                                      is_pread);
            }
            return kbox_dispatch_continue();
        }
    }

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    if (count > KBOX_READ_MAX)
        count = KBOX_READ_MAX;

    /* A read that enters LKL on something other than a regular file can block
     * inside the kernel while holding LKL's CPU lock, which stops every other
     * LKL syscall in the daemon. Name the descriptor type when tracing so a
     * wedge of that shape is identified instead of guessed.
     */
    if (getenv("KBOX_BLOCK_TRACE")) {
        struct kbox_lkl_stat bst;

        if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &bst) >= 0 &&
            (bst.st_mode & S_IFMT) != S_IFREG &&
            (bst.st_mode & S_IFMT) != S_IFDIR) {
            static int block_reported;

            if (block_reported < 40) {
                block_reported++;
                fprintf(stderr,
                        "kbox: lkl read nonfile pid=%u fd=%ld lkl=%ld mode=%#o "
                        "count=%zu\n",
                        (unsigned) pid, fd, lkl_fd, bst.st_mode, count);
            }
        }
    }

    size_t total = 0;
    uint8_t *scratch = dispatch_scratch;

    while (total < count) {
        size_t chunk_len = KBOX_IO_CHUNK_LEN;
        if (chunk_len > count - total)
            chunk_len = count - total;

        long ret;
        if (is_pread) {
            long offset = to_c_long_arg(kbox_syscall_request_arg(req, 3));
            long pread_off;
            if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                if (total == 0)
                    return kbox_dispatch_errno(EOVERFLOW);
                break;
            }
            ret = kbox_lkl_pread64(ctx->sysnrs, lkl_fd, scratch,
                                   (long) chunk_len, pread_off);
        } else {
            ret = kbox_lkl_read(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        }

        if (ret < 0) {
            if (total == 0)
                return kbox_dispatch_errno((int) (-ret));
            break;
        }

        size_t n = (size_t) ret;
        if (n == 0)
            break;

        uint64_t remote;
        if (__builtin_add_overflow(remote_buf, (uint64_t) total, &remote)) {
            if (total == 0)
                return kbox_dispatch_errno(EFAULT);
            break;
        }
        if (ctx->verbose) {
            fprintf(stderr,
                    "kbox: %s fd=%ld lkl_fd=%ld remote=0x%llx chunk=%zu "
                    "ret=%ld\n",
                    is_pread ? "pread64" : "read", fd, lkl_fd,
                    (unsigned long long) remote, chunk_len, ret);
        }
        int wrc = guest_mem_write(ctx, pid, remote, scratch, n);
        if (wrc < 0) {
            return kbox_dispatch_errno(-wrc);
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    return kbox_dispatch_value((int64_t) total);
}

/* forward_exit_group. */

/* Copy writable shadows back to LKL before the process goes away. A process
 * that writes through a "> file" redirect and exits (ls, tr, sed) never closes
 * the descriptor, so without this its parent reads the file back empty. The
 * host kernel still performs the exit. */
static struct kbox_dispatch forward_exit_group(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    if (fd_trace_enabled())
        fprintf(stderr, "kbofdt: exit_group pid=%d table=%p\n",
                (int) kbox_syscall_request_pid(req),
                (const void *) ctx->fd_table);
    sync_table_writebacks(ctx, ctx->fd_table, 1);
    kbox_lock_release_pid(&ctx->locks, kbox_syscall_request_pid(req));
    if (ctx->verbose)
        fprintf(stderr, "kbox: exit_group pid=%u code=%lld\n",
                kbox_syscall_request_pid(req),
                (long long) kbox_syscall_request_arg(req, 0));
    return kbox_dispatch_continue();
}

/* forward_write. */

static struct kbox_dispatch forward_write(
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
    if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW) {
        if (getenv("KBOX_FD_TRACE") && fd >= 0)
            /* format-ok: a literal, split only because the call
             * does not fit on one line. */
            fprintf(/* format-ok */
                    stderr,
                    "kbofdt: write continue fd=%ld lkl=%ld "
                    "n=%lld\n",
                    fd, lkl_fd,
                    (long long) to_c_long_arg(
                        kbox_syscall_request_arg(req, 2)));
        return kbox_dispatch_continue();
    }
    if (getenv("KBOX_FD_TRACE") && fd >= 0)
        fprintf(stderr,
                "kbofdt: write fd=%ld lkl=%ld host_fd=%ld sp=%d n=%lld\n", fd,
                lkl_fd, entry ? entry->host_fd : -99L,
                entry ? entry->shadow_sp : -99,
                (long long) to_c_long_arg(kbox_syscall_request_arg(req, 2)));

    invalidate_stat_cache_fd(ctx, lkl_fd);

    int mirror_host = kbox_fd_table_mirror_tty(ctx->fd_table, fd);

    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (count_raw < 0)
        return kbox_dispatch_errno(EINVAL);
    size_t count = (size_t) count_raw;

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (count == 0)
        return kbox_dispatch_value(0);

    pid_t pid = kbox_syscall_request_pid(req);
    if (count > KBOX_READ_MAX)
        count = KBOX_READ_MAX;

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

        long ret =
            kbox_lkl_write(ctx->sysnrs, lkl_fd, scratch, (long) chunk_len);
        if (ret < 0) {
            if (total == 0)
                return kbox_dispatch_errno((int) (-ret));
            break;
        }

        size_t n = (size_t) ret;

        /* Mirror to host stdout if this is a TTY fd.  The guest fd
         * is a virtual number (4096+) that does not exist on the
         * host side, so we write to stdout instead.
         */
        if (mirror_host && n > 0) {
            ssize_t written = write(STDOUT_FILENO, scratch, n);
            (void) written;
        }

        total += n;
        if (n < chunk_len)
            break;
    }

    if (total > 0)
        invalidate_path_shadow_cache(ctx);
    if (getenv("KBOX_FD_TRACE") && fd >= 0)
        fprintf(stderr, "kbofdt: write done fd=%ld lkl=%ld n=%lld total=%zu\n",
                fd, lkl_fd,
                (long long) to_c_long_arg(kbox_syscall_request_arg(req, 2)),
                total);
    return kbox_dispatch_value((int64_t) total);
}

/* Write to a host descriptor without blocking the dispatch thread.
 *
 * The dispatch thread answers every notification for the container, so it must
 * never wait inside a write it cannot finish: while it waits, the pump that
 * frees space on the peer socket is not served and the write never completes.
 * test_socket's sendfile into a bridged socket did exactly that and wedged the
 * guest. A socket therefore writes with MSG_DONTWAIT and reports a short count,
 * which sendfile(2) is allowed to return.
 */
#define KBOX_SENDFILE_WRITE_BUDGET_MS 100
#define KBOX_SENDFILE_WRITE_STEPS 4

static ssize_t host_write_nonblocking(int fd, const void *buf, size_t len)
{
    for (int step = 0;; step++) {
        ssize_t n = send(fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int wait_ms;

        if (n >= 0)
            return n;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOTSOCK)
            return n;
        if (step >= KBOX_SENDFILE_WRITE_STEPS)
            return -EAGAIN;
        /* Wait a little so a peer that is draining normally still gets the
         * whole transfer in one call, but never long enough to stall the
         * dispatch thread: a peer that does not drain at all must yield a
         * short count, which sendfile(2) allows. */
        wait_ms = KBOX_SENDFILE_WRITE_BUDGET_MS / KBOX_SENDFILE_WRITE_STEPS;
        if (poll(&pfd, 1, wait_ms) == 0)
            return -EAGAIN;
        if (errno == ENOTSOCK) {
            /* Pipes and regular files. */
            return write(fd, buf, len);
        }
    }
}

/* forward_sendfile. */

/* Emulate sendfile(out_fd, in_fd, *offset, count).
 *
 * If both FDs are host-visible (shadow memfds, stdio, or other host FDs
 * not in the virtual table), let the host kernel handle it via CONTINUE.
 * Otherwise, emulate via LKL read + host/LKL write.
 *
 * busybox cat uses sendfile and some builds loop on ENOSYS instead of
 * falling back to read+write, so returning ENOSYS is not viable.
 */
/* A supervisor-side descriptor for a tracee FD.
 *
 * dup_tracee_fd() needs pidfd_getfd; where the runtime denies it the fallback
 * open("/proc/<pid>/fd/N") fails with ENXIO for a socket, and sendfile into a
 * bridged socket then failed without sending a byte (test_socket's
 * SendfileUsingSendfileTest.testCount in the pod). The FD table already holds a
 * supervisor descriptor that refers to the same file description: the memfd of
 * a writable shadow, or the supervisor end of a bridged socket (ADDFD installs
 * the very same struct file, so writes through it are the guest's writes).
 */
static int sv_fd_for_tracee(struct kbox_supervisor_ctx *ctx,
                            pid_t pid,
                            long fd,
                            int *close_it)
{
    struct kbox_fd_entry *e;
    int sv;

    *close_it = 0;
    sv = kbox_fd_table_get_host_sv_fd(ctx->fd_table, fd);
    if (sv >= 0)
        return sv;

    sv = dup_tracee_fd(pid, (int) fd);
    if (sv >= 0) {
        *close_it = 1;
        return sv;
    }

    e = fd_table_entry(ctx->fd_table, fd);
    if (!e) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);

        if (vfd >= 0)
            e = fd_table_entry(ctx->fd_table, vfd);
    }
    if (e && e->shadow_sp >= 0)
        return e->shadow_sp;
    if (ctx->verbose)
        fprintf(stderr,
                "kbox: sendfile sv_fd fd=%ld dup=%d entry=%p shadow_sp=%d "
                "host_fd=%d lkl_fd=%ld\n",
                fd, sv, (void *) e, e ? (int) e->shadow_sp : -99,
                e ? (int) e->host_fd : -99, e ? e->lkl_fd : -99);
    return sv;
}

/* The guest end of the socketpair standing in for a bridged socket, or -1.
 *
 * A bridged socket is two objects: the LKL socket that really talks to the
 * peer, and the AF_UNIX socketpair whose far end the tracee holds. Writing
 * sendfile's output straight into the LKL socket pushes the bytes past the
 * bridge pump, so the tracee's own descriptor never becomes unwritable: its
 * poll(POLLOUT) keeps reporting ready after the peer stopped reading, and a
 * caller that loops on poll+sendfile (Python's socket.sendfile, asyncio's
 * sock_sendfile) spins instead of waiting -- it missed SO_SNDTIMEO entirely and
 * only stopped when the peer's close arrived as ECONNRESET
 * (test_socket.SendfileUsingSendfileTest.testWithTimeoutTriggeredSend).
 *
 * Writing into the tracee's own socketpair end keeps one buffer for both, so
 * the flow control the tracee sees is the real one. ADDFD installs a duplicate
 * of this very file, so a write here is the tracee's write.
 */
static int bridged_socket_sp(struct kbox_supervisor_ctx *ctx,
                             long fd,
                             int want_type)
{
    struct kbox_fd_entry *e = NULL;
    long vfd;

    if (!kbox_net_is_active())
        return -1;
    vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (vfd >= 0)
        e = fd_table_entry(ctx->fd_table, vfd);
    if (!e || e->shadow_sp < 0)
        e = fd_table_entry(ctx->fd_table, fd);
    if (!e || e->shadow_sp < 0)
        return -1;
    if (want_type && e->sock_type != want_type)
        return -1;
    return (int) e->shadow_sp;
}

/* Do the bytes behind this guest descriptor live on the host side?
 *
 * A same-fd shadow was injected into the tracee at that number, and a
 * local-only shadow is a supervisor memfd holding the same bytes. Every other
 * tracking shape is an LKL descriptor, even when the tracee happens to have an
 * unrelated host descriptor at the same number.
 */
static int fd_bytes_are_on_host(struct kbox_supervisor_ctx *ctx, long fd)
{
    struct kbox_fd_entry *e;

    if (!ctx || !ctx->fd_table)
        return 0;
    e = fd_table_entry(ctx->fd_table, fd);
    if (!e) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);

        if (vfd >= 0)
            e = fd_table_entry(ctx->fd_table, vfd);
    }
    return e && (e->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
                 e->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW);
}

static struct kbox_dispatch forward_sendfile(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long out_fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long in_fd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    uint64_t offset_ptr = kbox_syscall_request_arg(req, 2);
    int64_t count_raw = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    long in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, in_fd);
    long out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, out_fd);
    int out_bridge_sp = -1;

    /* Resolve shadow FDs: if in_fd is a host FD injected via ADDFD (shadow
     * memfd), find_by_host_fd locates the virtual entry that holds the LKL
     * FD for the same file.
     */
    if (in_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, in_fd);
        if (vfd >= 0)
            in_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }
    if (out_lkl < 0) {
        long vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, out_fd);
        if (vfd >= 0)
            out_lkl = kbox_fd_table_get_lkl(ctx->fd_table, vfd);
    }

    /* A descriptor whose bytes live on the host side -- a shadow memfd, or the
     * guest end of a bridged socket -- has to be used on the host side.
     * Resolving it to its LKL twin instead sent the bytes into LKL, past the
     * bridge pump, and a write that the peer had not started reading blocked
     * forever: test_asyncio hung in _sock_sendfile_native_impl that way.
     *
     * The table decides, not /proc/<pid>/fd. After dup3(file, 1) the table says
     * fd 1 is that file, while the host number 1 is still the container's
     * stdio: asking the tracee answered "yes" and sendfile wrote the bytes to
     * stdout instead of the file (item 32 in three-suites-report.md).
     */
    if (in_lkl >= 0 && fd_bytes_are_on_host(ctx, in_fd))
        in_lkl = -1;

    /* A stream socket destination always goes through the tracee's own
     * socketpair end, so that its writability reflects the peer's reading. */
    {
        int out_sp = bridged_socket_sp(ctx, out_fd, SOCK_STREAM);

        if (out_sp >= 0) {
            out_lkl = -1;
            out_bridge_sp = out_sp;
        } else if (out_lkl >= 0 && fd_bytes_are_on_host(ctx, out_fd)) {
            out_lkl = -1;
        }
    }

    if (ctx->verbose)
        fprintf(stderr,
                "kbox: sendfile in=%ld lkl=%ld out=%ld lkl=%ld deny_in=%d "
                "deny_out=%d\n",
                in_fd, in_lkl, out_fd, out_lkl,
                io_should_deny_fd(ctx, req, in_fd, in_lkl),
                io_should_deny_fd(ctx, req, out_fd, out_lkl));

    /* Both FDs have no LKL backing: the host kernel handles sendfile
     * if both are known host FDs. Deny if either is in a denied range.
     */
    if (in_lkl < 0 && out_lkl < 0) {
        if (io_should_deny_fd(ctx, req, in_fd, in_lkl) ||
            io_should_deny_fd(ctx, req, out_fd, out_lkl))
            return kbox_dispatch_errno(EBADF);
        return kbox_dispatch_continue();
    }

    if (in_lkl < 0 && io_should_deny_fd(ctx, req, in_fd, in_lkl))
        return kbox_dispatch_errno(EBADF);
    if (out_lkl < 0 && io_should_deny_fd(ctx, req, out_fd, out_lkl))
        return kbox_dispatch_errno(EBADF);

    /* Both descriptors live in LKL, and the emulation below moves the bytes
     * somewhere the caller cannot read back: cp reports the whole file copied
     * and leaves an empty destination, which is how every configure script in
     * an official image fails. Answer ENOSYS instead and let the caller fall
     * back to read/write, which land correctly.
     */
    if (in_lkl >= 0 && out_lkl >= 0) {
        /* A socket destination is different: nginx (sendfile on) has no
         * read/write fallback and drops the connection on ENOSYS. The bytes
         * go out through LKL exactly as a write() would send them. */
        struct kbox_lkl_stat out_st;
        if (kbox_lkl_fstat(ctx->sysnrs, out_lkl, &out_st) < 0 ||
            (out_st.st_mode & S_IFMT) != S_IFSOCK)
            return kbox_dispatch_errno(ENOSYS);
        /* Header bytes the guest already wrote sit in the shadow socket's
         * host queue. Push them into LKL first, or the body overtakes them. */
        kbox_net_flush_socket((int) out_lkl);
    }

    if (count_raw <= 0)
        return kbox_dispatch_value(0);
    size_t count = (size_t) count_raw;
    if (count > 1024 * 1024)
        count = 1024 * 1024;

    /* Read optional offset from tracee memory. */
    pid_t pid = kbox_syscall_request_pid(req);
    off_t offset = 0;
    int has_offset = (offset_ptr != 0);
    if (has_offset) {
        int rc = guest_mem_read(ctx, pid, offset_ptr, &offset, sizeof(offset));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    int sv_in = -1;
    int sv_out = -1;
    int close_in = 0;
    int close_out = 0;
    if (in_lkl < 0) {
        sv_in = sv_fd_for_tracee(ctx, pid, in_fd, &close_in);
        if (sv_in < 0)
            return kbox_dispatch_errno(-sv_in);
    }
    if (out_lkl < 0) {
        sv_out = out_bridge_sp >= 0
                     ? out_bridge_sp
                     : sv_fd_for_tracee(ctx, pid, out_fd, &close_out);
        if (sv_out < 0) {
            if (close_in)
                close(sv_in);
            return kbox_dispatch_errno(-sv_out);
        }
    }

    /* The dispatcher must never block on guest-visible host I/O.
     *
     * One supervisor thread serves every notification of a container, so a
     * blocking read or write performed here stops that container's other
     * syscalls from being answered. busybox tar extracts a gzip stream by
     * calling sendfile(pipe -> file): the pipe is empty at that instant, the
     * dispatcher blocked in read(), and the writer's write() notification could
     * never be answered because the same thread was waiting for it -- tar hung
     * forever on every extraction. Refuse the emulation for a source or a
     * destination that is not a regular file (or a socket, whose write path is
     * already non-blocking); sendfile(2) documents ENOSYS, and every caller
     * falls back to read/write, which run in the guest's own thread.
     */
    {
        struct stat hst;

        if (in_lkl < 0 && fstat(sv_in, &hst) == 0 && !S_ISREG(hst.st_mode)) {
            if (close_in)
                close(sv_in);
            if (close_out)
                close(sv_out);
            return kbox_dispatch_errno(ENOSYS);
        }
        if (out_lkl < 0 && out_bridge_sp < 0 && fstat(sv_out, &hst) == 0 &&
            !S_ISREG(hst.st_mode)) {
            if (close_in)
                close(sv_in);
            if (close_out)
                close(sv_out);
            return kbox_dispatch_errno(ENOSYS);
        }
    }

    uint8_t *scratch = dispatch_scratch;
    struct kbox_dispatch result = kbox_dispatch_value(0);
    size_t total = 0;
    size_t rewind_bytes = 0; /* source bytes read but not written */

    while (total < count) {
        size_t chunk = KBOX_IO_CHUNK_LEN;
        if (chunk > count - total)
            chunk = count - total;

        /* Read from source (LKL fd or host tracee fd). */
        long nr;
        if (in_lkl >= 0) {
            if (has_offset) {
                long pread_off;
                if (__builtin_add_overflow(offset, (long) total, &pread_off)) {
                    if (total == 0) {
                        result = kbox_dispatch_errno(EOVERFLOW);
                        goto out_close;
                    }
                    break;
                }
                nr = kbox_lkl_pread64(ctx->sysnrs, in_lkl, scratch,
                                      (long) chunk, pread_off);
            } else {
                nr = kbox_lkl_read(ctx->sysnrs, in_lkl, scratch, (long) chunk);
            }
            if (nr < 0) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: sendfile read failed in_lkl=%ld ret=%ld "
                            "off=%lld\n",
                            in_lkl, nr, (long long) offset);
                if (total == 0) {
                    result = kbox_dispatch_errno((int) (-nr));
                    goto out_close;
                }
                break;
            }
        } else {
            ssize_t hr;
            if (has_offset) {
                off_t pread_off;
                if (__builtin_add_overflow(offset, (off_t) total, &pread_off)) {
                    if (total == 0) {
                        result = kbox_dispatch_errno(EOVERFLOW);
                        goto out_close;
                    }
                    break;
                }
                hr = pread(sv_in, scratch, chunk, pread_off);
            } else {
                hr = read(sv_in, scratch, chunk);
            }
            if (hr < 0) {
                if (total == 0) {
                    result = kbox_dispatch_errno(errno);
                    goto out_close;
                }
                break;
            }
            nr = (long) hr;
        }
        if (nr == 0)
            break;

        size_t n = (size_t) nr;

        /* Write to destination (LKL fd or host tracee fd). */
        size_t written = 0;
        while (written < n) {
            if (out_lkl >= 0) {
                /* A socket destination must not block the dispatch thread
                 * either: a full peer buffer is backpressure, and sendfile(2)
                 * is allowed to return the bytes it managed to copy. */
                long wr = kbox_lkl_sendto(
                    ctx->sysnrs, out_lkl, scratch + written,
                    (long) (n - written), 0x40 /* MSG_DONTWAIT */, NULL, 0);

                if (wr == -ENOTSOCK)
                    wr = kbox_lkl_write(ctx->sysnrs, out_lkl, scratch + written,
                                        (long) (n - written));
                if (wr <= 0) {
                    if (wr < 0 && (wr == -EAGAIN || wr == -EWOULDBLOCK)) {
                        /* Nothing copied yet: report EAGAIN so the caller waits
                         * for writability instead of reading 0 as end of file
                         * (asyncio's sock_sendfile stops on 0). */
                        if (total + written == 0) {
                            result = kbox_dispatch_errno(EAGAIN);
                            goto out_close;
                        }
                        total += written;
                        rewind_bytes = n - written;
                        goto done_rewind;
                    }
                    if (total + written == 0) {
                        result =
                            kbox_dispatch_errno(wr < 0 ? (int) (-wr) : EIO);
                        goto out_close;
                    }
                    total += written;
                    /* The chunk was already consumed from the source. Without
                     * an explicit offset the file position moved past the
                     * bytes that could not be written, and the caller's next
                     * call would start after them: a 10 MB sendfile lost 89 KB
                     * that way (test_socket.SendfileUsingSendfileTest). */
                    rewind_bytes = n - written;
                    goto done_rewind;
                }
                written += (size_t) wr;
            } else {
                ssize_t wr = host_write_nonblocking(sv_out, scratch + written,
                                                    n - written);

                if (wr <= 0 && ctx->verbose)
                    fprintf(stderr,
                            "kbox: sendfile write failed sv_out=%d ret=%zd "
                            "errno=%d\n",
                            sv_out, wr, errno);
                if (wr <= 0) {
                    /* A full socket buffer is not an error: report the bytes
                     * already copied so the guest comes back when the
                     * descriptor is writable. With nothing copied yet the
                     * answer is EAGAIN, never 0, which a caller reads as end
                     * of file. */
                    if (wr < 0 && errno == EAGAIN) {
                        if (total + written == 0) {
                            result = kbox_dispatch_errno(EAGAIN);
                            goto out_close;
                        }
                        total += written;
                        rewind_bytes = n - written;
                        goto done_rewind;
                    }
                    if (total + written == 0) {
                        result = kbox_dispatch_errno(wr < 0 ? errno : EIO);
                        goto out_close;
                    }
                    total += written;
                    rewind_bytes = n - written;
                    goto done_rewind;
                }
                written += (size_t) wr;
            }
        }

        total += written;
        if (n < chunk)
            break;
    }

done_rewind:
    /* Leave the source positioned at the first byte that was not written. */
    if (!has_offset && rewind_bytes > 0) {
        if (in_lkl >= 0)
            (void) lkl_syscall6(ctx->sysnrs->lseek, in_lkl,
                                -(long) rewind_bytes, 1, 0, 0, 0);
        else if (sv_in >= 0)
            (void) lseek(sv_in, -(off_t) rewind_bytes, SEEK_CUR);
    }

    /* The write landed, but the name it landed under is cached: a reader that
     * opens the same path next gets the pre-write shadow and sees an empty
     * file. forward_write drops that cache after every write, and this path
     * has to do the same -- otherwise cp reports success, the destination
     * holds the bytes, and everything that reads it back finds nothing.
     */
    if (total > 0)
        invalidate_path_shadow_cache(ctx);

    /* Update offset in tracee memory if provided.  Best-effort: data has
     * already been transferred, so return the byte count even if the
     * offset writeback fails (avoids data duplication on retry).
     */
    if (has_offset && total > 0) {
        off_t new_off;
        if (!__builtin_add_overflow(offset, (off_t) total, &new_off))
            guest_mem_write(ctx, pid, offset_ptr, &new_off, sizeof(new_off));
    }

    result = kbox_dispatch_value((int64_t) total);

out_close:
    if (close_in && sv_in >= 0)
        close(sv_in);
    if (close_out && sv_out >= 0)
        close(sv_out);
    return result;
}

/* forward_lseek. */

static struct kbox_dispatch forward_lseek(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    {
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }
    {
        int shadow_rc = ensure_same_fd_shadow(ctx, req, fd, lkl_fd);
        if (shadow_rc > 0) {
            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            if (entry && entry->host_fd == KBOX_FD_LOCAL_ONLY_SHADOW)
                return forward_local_shadow_lseek(req, ctx, entry, lkl_fd);
            return kbox_dispatch_continue();
        }
    }

    long off = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long whence = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long ret = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, off, whence);
    if (ctx->verbose) {
        fprintf(stderr,
                "kbox: lseek fd=%ld lkl_fd=%ld off=%ld whence=%ld ret=%ld\n",
                fd, lkl_fd, off, whence, ret);
    }
    return kbox_dispatch_from_lkl(ret);
}

static int find_available_tracee_fd(const struct kbox_supervisor_ctx *ctx,
                                    pid_t pid,
                                    int minfd);
static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd);
static struct kbox_dispatch dup_same_fd_shadow_to(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int cloexec,
    int replace_existing);

/* forward_fcntl. */

/* POSIX and OFD advisory locks.
 *
 * The guest's struct flock is at `arg`; its layout on every architecture kbox
 * serves is { short l_type; short l_whence; off_t l_start; off_t l_len; pid_t
 * l_pid; } with the fields at offsets 0, 2, 8, 16 and 24. The file is named by
 * the descriptor's own inode, so the table survives a rename or a second open.
 */
static struct kbox_dispatch dispatch_advisory_lock(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long fd,
    long lkl_fd,
    long cmd)
{
    uint8_t fl[32];
    int16_t type, whence;
    int32_t owner_pid;
    int64_t start, len;
    int64_t first, last;
    struct kbox_lkl_stat kst;
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t arg = kbox_syscall_request_arg(req, 2);
    int is_ofd =
        (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK);
    int is_get = (cmd == F_GETLK || cmd == F_OFD_GETLK);
    int ofd_key = is_ofd ? (int) lkl_fd : -1;

    /* A process killed by a signal never reaches exit_group, so its entry has
     * to be dropped here or the file stays locked for every later process. A
     * reused pid would keep a stale entry alive; that window is small and the
     * alternative is a lock nobody can ever take. */
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        struct kbox_lock *slot = &ctx->locks.slots[i];

        if (slot->used && slot->pid != pid && kill(slot->pid, 0) < 0 &&
            errno == ESRCH)
            memset(slot, 0, sizeof(*slot));
    }

    if (arg == 0)
        return kbox_dispatch_errno(EFAULT);
    if (guest_mem_read(ctx, pid, arg, fl, sizeof(fl)) < 0)
        return kbox_dispatch_errno(EFAULT);
    memcpy(&type, fl + 0, sizeof(type));
    memcpy(&whence, fl + 2, sizeof(whence));
    memcpy(&start, fl + 8, sizeof(start));
    memcpy(&len, fl + 16, sizeof(len));
    memcpy(&owner_pid, fl + 24, sizeof(owner_pid));

    if (type != F_RDLCK && type != F_WRLCK && type != F_UNLCK)
        return kbox_dispatch_errno(EINVAL);
    if (kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst) < 0)
        return kbox_dispatch_errno(EIO);

    switch (whence) {
    case SEEK_SET:
        break;
    case SEEK_CUR: {
        long cur = kbox_lkl_lseek(ctx->sysnrs, lkl_fd, 0, SEEK_CUR);

        if (cur < 0)
            return kbox_dispatch_errno((int) (-cur));
        if (__builtin_add_overflow(start, (int64_t) cur, &start))
            return kbox_dispatch_errno(EINVAL);
        break;
    }
    case SEEK_END:
        if (__builtin_add_overflow(start, (int64_t) kst.st_size, &start))
            return kbox_dispatch_errno(EINVAL);
        break;
    default:
        return kbox_dispatch_errno(EINVAL);
    }

    if (kbox_lock_range(start, len, &first, &last) < 0)
        return kbox_dispatch_errno(EINVAL);

    /* Drop locks whose owner exited or natively closed the low descriptor
     * that took the lock (low-fd closes run in the kernel, item 33). */
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        const struct kbox_lock *slot = &ctx->locks.slots[i];

        if (!slot->used || slot->dev != kst.st_dev || slot->ino != kst.st_ino)
            continue;
        if (slot->pid > 0 && kill(slot->pid, 0) < 0 && errno == ESRCH) {
            kbox_lock_release_pid(&ctx->locks, slot->pid);
            continue;
        }
        if (slot->guest_fd >= 0 && slot->guest_fd < KBOX_FD_TABLE_CAPACITY &&
            slot->guest_id != 0) {
            uint64_t now = kbox_guest_fd_identity(slot->pid, slot->guest_fd);

            if (kbox_fd_identity_stale(slot->guest_id, now, errno))
                kbox_lock_release_file(&ctx->locks, slot->pid, slot->ofd_fd,
                                       slot->dev, slot->ino);
        }
    }

    if (is_get) {
        struct kbox_lock hit;
        int found;

        memset(&hit, 0, sizeof(hit));
        found = kbox_lock_conflict(&ctx->locks, pid, ofd_key, kst.st_dev,
                                   kst.st_ino, type, first, last, &hit);
        if (ctx->verbose) {
            int used = 0;

            for (int i = 0; i < KBOX_MAX_LOCKS; i++)
                used += ctx->locks.slots[i].used != 0;
            /* format-ok: literal */
            fprintf(stderr,
                    "kbox: fcntl GETLK probe pid=%u ino=%llu type=%d found=%d "
                    "slots=%d\n",
                    (unsigned) pid, (unsigned long long) kst.st_ino, (int) type,
                    found, used);
        }
        if (found) {
            int64_t hit_len =
                (hit.end == INT64_MAX) ? 0 : hit.end - hit.start + 1;

            memset(fl, 0, sizeof(fl));
            memcpy(fl + 0, &hit.type, sizeof(hit.type));
            memcpy(fl + 2, &(int16_t) {SEEK_SET}, sizeof(int16_t));
            memcpy(fl + 8, &hit.start, sizeof(hit.start));
            memcpy(fl + 16, &hit_len, sizeof(hit_len));
            memcpy(fl + 24, &hit.pid, sizeof(hit.pid));
        } else {
            int16_t unlock = F_UNLCK;

            memcpy(fl + 0, &unlock, sizeof(unlock));
        }
        if (guest_mem_write(ctx, pid, arg, fl, sizeof(fl)) < 0)
            return kbox_dispatch_errno(EFAULT);
        if (ctx->verbose)
            /* format-ok: literal */
            fprintf(stderr,
                    "kbox: fcntl GETLK pid=%u fd=%ld ino=%llu range=%lld..%lld "
                    "-> %s\n",
                    (unsigned) pid, fd, (unsigned long long) kst.st_ino,
                    (long long) first, (long long) last,
                    (type == F_RDLCK) ? "read" : "write");
        return kbox_dispatch_value(0);
    }

    if (type != F_UNLCK) {
        if (kbox_lock_conflict(&ctx->locks, pid, ofd_key, kst.st_dev,
                               kst.st_ino, type, first, last, NULL)) {
            if (ctx->verbose)
                /* format-ok: literal */
                fprintf(stderr,
                        "kbox: fcntl SETLK pid=%u fd=%ld ino=%llu "
                        "range=%lld..%lld -> EAGAIN (held)\n",
                        (unsigned) pid, fd, (unsigned long long) kst.st_ino,
                        (long long) first, (long long) last);
            return kbox_dispatch_errno(EAGAIN);
        }
    }
    if (kbox_lock_apply(&ctx->locks, pid, ofd_key, kst.st_dev, kst.st_ino, type,
                        first, last) < 0)
        return kbox_dispatch_errno(ENOLCK);
    if (type != F_UNLCK && fd >= 0 && fd < KBOX_FD_TABLE_CAPACITY) {
        uint64_t gid = kbox_guest_fd_identity(pid, fd);

        if (gid != 0)
            kbox_lock_tag_fd(&ctx->locks, pid, ofd_key, kst.st_dev, kst.st_ino,
                             fd, gid);
    }
    if (ctx->verbose)
        /* format-ok: literal */
        fprintf(stderr,
                "kbox: fcntl SETLK pid=%u fd=%ld ino=%llu range=%lld..%lld "
                "type=%d -> ok\n",
                (unsigned) pid, fd, (unsigned long long) kst.st_ino,
                (long long) first, (long long) last, (int) type);
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch forward_fcntl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
    fcntl_host_passthrough:;
        long pt_cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
        if (ctx->verbose && pt_cmd == F_SETFL)
            fprintf(stderr,
                    "kbox: fcntl shadow-only fd=%ld cmd=F_SETFL arg=%ld "
                    "-> continue\n",
                    fd, to_c_long_arg(kbox_syscall_request_arg(req, 2)));
        if (pt_cmd == F_DUPFD || pt_cmd == F_DUPFD_CLOEXEC) {
            /* Emulate F_DUPFD on host-passthrough FD: get a supervisor copy
             * via pidfd_getfd (or /proc/<pid>/fd fallback), inject at the first
             * free tracee FD >= minfd, and track the result.
             */
            long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            uint32_t af = (pt_cmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
            int target_fd;

            if (minfd < 0)
                return kbox_dispatch_errno(EINVAL);
            target_fd = find_available_tracee_fd(
                ctx, kbox_syscall_request_pid(req), (int) minfd);
            if (target_fd < 0)
                return kbox_dispatch_errno(-target_fd);

            int copy =
                dup_tracee_fd_shared(kbox_syscall_request_pid(req), (int) fd);
            if (copy < 0) {
                if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                    track_host_passthrough_fd(ctx->fd_table, target_fd);
                    if (pt_cmd == F_DUPFD_CLOEXEC)
                        kbox_fd_table_set_cloexec(ctx->fd_table, target_fd, 1);
                    return kbox_dispatch_continue();
                }
                return kbox_dispatch_errno(-copy);
            }
            int tracee_new = request_addfd_at(ctx, req, copy, target_fd, af);
            close(copy);
            if (tracee_new < 0)
                return kbox_dispatch_errno(-tracee_new);
            if (tracee_new >= 0)
                kbox_retire_stale_host_fd_vfd(
                    ctx, kbox_syscall_request_pid(req), tracee_new, 1);
            track_host_passthrough_fd(ctx->fd_table, tracee_new);
            if (pt_cmd == F_DUPFD_CLOEXEC)
                kbox_fd_table_set_cloexec(ctx->fd_table, tracee_new, 1);
            return kbox_dispatch_value(tracee_new);
        }
        if (pt_cmd == F_SETFD && lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
            long carg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                      (carg & FD_CLOEXEC) ? 1 : 0);
        }
        if (pt_cmd == F_SETFL) {
            long carg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
            kbox_net_note_unix_nonblock(fd, (carg & O_NONBLOCK) != 0);
        }
        return kbox_dispatch_continue();
    }

    if (lkl_fd < 0) {
        /* Shadow socket: handle F_DUPFD* and F_SETFL. */
        long svfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (svfd >= 0) {
            long scmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
            if (scmd == F_DUPFD || scmd == F_DUPFD_CLOEXEC) {
                long minfd = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                /* When minfd > 0, skip ADDFD (can't honor the minimum)
                 * and let CONTINUE handle it correctly.  The dup is
                 * untracked but no FD leaks.
                 */
                struct kbox_fd_entry *orig = NULL;
                if (minfd > 0)
                    goto fcntl_shadow_continue;
                orig = fd_table_entry(ctx->fd_table, svfd);
                if (orig && orig->shadow_sp >= 0) {
                    uint32_t af = (scmd == F_DUPFD_CLOEXEC) ? O_CLOEXEC : 0;
                    int nh = request_addfd(ctx, req, orig->shadow_sp, af);
                    if (nh >= 0) {
                        long nv = kbox_fd_table_insert(ctx->fd_table,
                                                       orig->lkl_fd, 0);
                        if (nv < 0)
                            return kbox_dispatch_errno(EMFILE);
                        kbox_fd_table_set_host_fd(ctx->fd_table, nv, nh);
                        /* Clear stale SHADOW_ONLY at the ADDFD-allocated FD
                         * so resolve_lkl_socket finds the shadow socket.
                         */
                        {
                            struct kbox_fd_entry *stale =
                                fd_table_entry(ctx->fd_table, nh);
                            if (stale && nh != nv &&
                                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                                kbox_fd_table_remove(ctx->fd_table, nh);
                        }
                        int ns = dup(orig->shadow_sp);
                        if (ns >= 0) {
                            struct kbox_fd_entry *ne = NULL;
                            ne = fd_table_entry(ctx->fd_table, nv);
                            if (ne) {
                                ne->shadow_sp = ns;
                                if (scmd == F_DUPFD_CLOEXEC)
                                    ne->cloexec = 1;
                            } else {
                                close(ns);
                            }
                        }
                        return kbox_dispatch_value((int64_t) nh);
                    }
                }
            }
            if (scmd == F_SETFL) {
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                long slkl = kbox_fd_table_get_lkl(ctx->fd_table, svfd);
                if (slkl >= 0) {
                    long fr = kbox_lkl_fcntl(ctx->sysnrs, slkl, F_SETFL, sarg);
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: fcntl shadow fd=%ld svfd=%ld lkl=%ld "
                                "setfl=%ld -> %ld\n",
                                fd, svfd, slkl, sarg, fr);
                }
            }
            if (scmd == F_SETFD) {
                /* Keep fd-table cloexec in sync with host kernel. */
                long sarg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
                kbox_fd_table_set_cloexec(ctx->fd_table, svfd,
                                          (sarg & FD_CLOEXEC) ? 1 : 0);
            }
            goto fcntl_shadow_continue;
        }
        /* An untracked descriptor that really exists in the tracee (such as a
         * native kernel pipe from item 33) must take the host-passthrough
         * path: F_SETFD/F_SETFL/F_GETFL continue to the host kernel, and
         * F_DUPFD/F_DUPFD_CLOEXEC track the duplicated fd (which busybox ash
         * places elsewhere when saving stdout across redirects).
         */
        if (tracee_fd_is_open(kbox_syscall_request_pid(req), fd))
            goto fcntl_host_passthrough;
        if (!fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))
            goto fcntl_shadow_continue;
        return kbox_dispatch_errno(EBADF);
    fcntl_shadow_continue:
        return kbox_dispatch_continue();
    }

    /* An FD that has both a virtual number and a host shadow (an accepted
     * socket is one) must answer here. Its virtual number is not a host
     * descriptor, so CONTINUE would run fcntl on a number the host does not
     * have and answer EBADF -- which is how every postgres backend died with
     * "could not set socket to nonblocking mode: Bad file descriptor" right
     * after accepting a client.
     */
    {
        long pt_cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
        long pt_arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));
        struct kbox_fd_entry *he = fd_table_entry(ctx->fd_table, fd);

        if (he && he->shadow_sp >= 0 &&
            (pt_cmd == F_SETFL || pt_cmd == F_GETFL || pt_cmd == F_SETFD)) {
            if (pt_cmd == F_SETFD) {
                kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                          (pt_arg & FD_CLOEXEC) ? 1 : 0);
                /* The number the tracee uses here is a real host descriptor
                 * (the injected memfd of a same-fd shadow, or an accepted
                 * socket). Emulating the call in the supervisor updated the
                 * bookkeeping but left the descriptor's own close-on-exec bit
                 * set, so execve closed it anyway: a child that received the
                 * fd through subprocess pass_fds -- which clears FD_CLOEXEC
                 * exactly this way -- then got EBADF on its first write
                 * (test_faulthandler's fd tests).
                 */
                if (he->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW ||
                    he->host_sv_fd >= 0)
                    return kbox_dispatch_continue();
                return kbox_dispatch_value(0);
            }
            if (pt_cmd == F_SETFL) {
                if (lkl_fd >= 0)
                    (void) kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_SETFL,
                                          host_to_lkl_open_flags(pt_arg));
                if (fcntl(he->shadow_sp, F_SETFL, (int) pt_arg) < 0)
                    return kbox_dispatch_errno(errno);
                return kbox_dispatch_value(0);
            }
            {
                long hr = fcntl(he->shadow_sp, F_GETFL);
                if (hr < 0)
                    return kbox_dispatch_errno(errno);
                return kbox_dispatch_value(lkl_to_host_open_flags(hr));
            }
        }
    }

    long cmd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long arg = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        if (arg < 0)
            return kbox_dispatch_errno(EINVAL);
        sweep_stale_low_fds(ctx, kbox_syscall_request_pid(req),
                            KBOX_NATIVE_CLOSE_MAX);
        struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, fd);
        if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
            orig->shadow_sp >= 0) {
            long target_fd = allocate_dup_shadow_fd_from(
                ctx, kbox_syscall_request_pid(req), arg);
            if (target_fd < 0)
                return kbox_dispatch_errno(EMFILE);
            struct kbox_dispatch d = dup_same_fd_shadow_to(
                req, ctx, orig, target_fd, cmd == F_DUPFD_CLOEXEC, 0);
            if (getenv("KBOX_FD_TRACE"))
                fprintf(stderr,
                        "kbofdt: fcntl dupfd fd=%ld arg=%ld target=%ld "
                        "result=%lld\n",
                        fd, arg, target_fd, (long long) d.val);
            return d;
        }

        long new_vfd = allocate_dup_shadow_fd_from(
            ctx, kbox_syscall_request_pid(req), arg);
        if (new_vfd < 0)
            return kbox_dispatch_errno(EMFILE);

        long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));

        int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
        if (kbox_fd_table_insert_at(ctx->fd_table, new_vfd, ret, mirror) < 0) {
            lkl_close_and_invalidate(ctx, ret);
            return kbox_dispatch_errno(EMFILE);
        }
        if (new_vfd < KBOX_NATIVE_CLOSE_MAX)
            install_low_vfd_placeholder(ctx, req, new_vfd,
                                        cmd == F_DUPFD_CLOEXEC);
        if (cmd == F_DUPFD_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, new_vfd, 1);
        return kbox_dispatch_value((int64_t) new_vfd);
    }

    if (cmd == F_SETFD) {
        kbox_fd_table_set_cloexec(ctx->fd_table, fd,
                                  (arg & FD_CLOEXEC) ? 1 : 0);
        struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
        if (entry && entry->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW)
            return kbox_dispatch_continue();
    }

    /* Advisory locks are answered by the supervisor's own table.
     *
     * LKL's fcntl_setlk dereferences lock state it does not have for files this
     * sandbox backs on the host, and the resulting SIGSEGV takes the daemon --
     * and every container running in it -- down. Reporting every lock as
     * granted was the previous answer, and it told a second server that a lock
     * file was free while the first server held it. See include/kbox/locks.h.
     */
    if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK ||
        cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK)
        return dispatch_advisory_lock(req, ctx, fd, lkl_fd, cmd);

    /* Directory change notification (dnotify) cannot be delivered through this
     * sandbox: the signals would have to be raised by the host kernel, which
     * does not know the guest's descriptor. LKL's kernel is built without
     * CONFIG_DNOTIFY and answers EINVAL, while the host kernel accepts the call
     * -- so a program that merely enables notification (CPython's
     * test_fcntl.test_fcntl_64_bit) failed only under kbox. Accept the flag;
     * nothing in the guest can observe the missing signal in a single-process
     * sandbox.
     */
#ifndef F_NOTIFY
#define F_NOTIFY 1026
#endif
    if (cmd == F_NOTIFY)
        return kbox_dispatch_value(0);

    /* F_SETFL: translate host open flags to LKL before forwarding. */
    if (cmd == F_SETFL)
        arg = host_to_lkl_open_flags(arg);

    long ret = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, cmd, arg);

    if (ret < 0 && ctx->verbose) {
        const struct kbox_fd_entry *fe = fd_table_entry(ctx->fd_table, fd);
        fprintf(stderr, "kbox: fcntl fd=%ld lkl=%ld cmd=%ld arg=%ld -> %ld", fd,
                lkl_fd, cmd, arg, ret);
        fprintf(stderr, " (host_fd=%ld shadow=%d)\n", fe ? fe->host_fd : -999L,
                fe ? fe->shadow_sp : -999);
    }

    /* F_GETFL: translate LKL open flags back to host before returning. */
    if (cmd == F_GETFL && ret >= 0)
        ret = lkl_to_host_open_flags(ret);

    return kbox_dispatch_from_lkl(ret);
}

static int read_tracee_fd_flags(pid_t pid, int tracee_fd, int *out_flags)
{
    char path[64];
    char buf[512];
    int n = snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", (int) pid,
                     tracee_fd);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -ENAMETOOLONG;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;

    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    int saved_errno = errno;
    close(fd);
    if (nr < 0)
        return -saved_errno;
    buf[nr] = '\0';

    const char *p = strstr(buf, "flags:");
    if (!p)
        return -EINVAL;
    p += 6;
    while (*p == ' ' || *p == '\t')
        p++;
    char *end = NULL;
    unsigned long flags = strtoul(p, &end, 8);
    if (end == p)
        return -EINVAL;
    *out_flags = (int) flags;
    return 0;
}

static int open_tracee_proc_fd(pid_t pid, int tracee_fd)
{
    char path[64];
    int n =
        snprintf(path, sizeof(path), "/proc/%d/fd/%d", (int) pid, tracee_fd);
    if (n < 0 || (size_t) n >= sizeof(path))
        return -ENAMETOOLONG;

    int fd_flags = 0;
    int open_mode = O_RDONLY;
    if (read_tracee_fd_flags(pid, tracee_fd, &fd_flags) == 0) {
        if (fd_flags & O_PATH)
            open_mode = O_PATH;
        else
            open_mode = fd_flags & O_ACCMODE;
    }

    int copy = open(path, open_mode | O_CLOEXEC);
    if (copy >= 0)
        return copy;
    int saved_errno = errno;
    if (open_mode != O_RDONLY && open_mode != O_PATH) {
        copy = open(path, O_RDONLY | O_CLOEXEC);
        if (copy >= 0)
            return copy;
    }
    return -saved_errno;
}

static int open_tracee_pidfd(pid_t pid)
{
    int pidfd = (int) syscall(__NR_pidfd_open, (int) pid, (unsigned int) 0);
    if (pidfd >= 0)
        return pidfd;
    int saved_errno = errno;
    if (saved_errno == EPERM || saved_errno == ENOSYS || saved_errno == EACCES)
        return -saved_errno;
    /* pidfd_open(..., 0) fails (EINVAL/ENOENT/ESRCH) on non-leader thread TIDs;
     * resolve the thread-group leader TGID whose FD table the thread shares.
     */
    pid_t tgid = 0;
    if (read_proc_tgid_ppid(pid, &tgid, NULL, NULL) == 0 && tgid > 0 &&
        tgid != pid) {
        pidfd = (int) syscall(__NR_pidfd_open, (int) tgid, (unsigned int) 0);
        if (pidfd >= 0)
            return pidfd;
        return -errno;
    }
    return -saved_errno;
}

/* Obtain a supervisor-side copy of a tracee FD that shares the same file
 * description.  Uses pidfd_getfd (Linux 5.6+) which preserves the file
 * description identity (same position, flags, etc.) -- unlike
 * open(/proc/pid/fd/N) which creates a new description.  Falls back to
 * /proc/<pid>/fd/N when pidfd_getfd is blocked (EPERM/ENOSYS/EACCES), such as
 * under default container seccomp profiles.
 * Returns a supervisor FD on success, -errno on failure.
 */
int dup_tracee_fd(pid_t pid, int tracee_fd)
{
    int pidfd = open_tracee_pidfd(pid);
    if (pidfd >= 0) {
        int copy = (int) syscall(__NR_pidfd_getfd, pidfd,
                                 (unsigned int) tracee_fd, (unsigned int) 0);
        int saved_errno = errno;
        close(pidfd);
        if (copy >= 0)
            return copy;
        if (saved_errno != EPERM && saved_errno != ENOSYS &&
            saved_errno != EACCES)
            return -saved_errno;
    } else if (pidfd != -EPERM && pidfd != -ENOSYS && pidfd != -EACCES &&
               pidfd != -EINVAL) {
        return pidfd;
    }
    return open_tracee_proc_fd(pid, tracee_fd);
}

/* Like dup_tracee_fd, but only ever returns a copy that shares the tracee's
 * open file description. When pidfd_getfd is unavailable it fails with -EPERM
 * instead of falling back to open(/proc/<pid>/fd/N): that fallback makes a NEW
 * description (position 0, access mode and O_APPEND of its own), which is wrong
 * for dup, dup2, dup3 and F_DUPFD -- a shell's `cmd >> file` dup2'd a copy that
 * wrote over the start of the file. Callers handle -EPERM by letting the host
 * kernel perform the dup itself. */
static int dup_tracee_fd_shared(pid_t pid, int tracee_fd)
{
    int pidfd = open_tracee_pidfd(pid);
    if (pidfd >= 0) {
        int copy = (int) syscall(__NR_pidfd_getfd, pidfd,
                                 (unsigned int) tracee_fd, (unsigned int) 0);
        int saved_errno = errno;
        close(pidfd);
        if (copy >= 0)
            return copy;
        if (saved_errno != EPERM && saved_errno != ENOSYS &&
            saved_errno != EACCES)
            return -saved_errno;
        return -EPERM;
    }
    if (pidfd != -EPERM && pidfd != -ENOSYS && pidfd != -EACCES &&
        pidfd != -EINVAL)
        return pidfd;
    return -EPERM;
}

static int find_available_tracee_fd(const struct kbox_supervisor_ctx *ctx,
                                    pid_t pid,
                                    int minfd)
{
    const int limit = 65536;

    if (minfd < 0 || minfd >= limit)
        return -EINVAL;

    char proc_dir[64];
    snprintf(proc_dir, sizeof(proc_dir), "/proc/%d/fd", (int) pid);
    struct stat dir_st;
    if (stat(proc_dir, &dir_st) == 0) {
        for (int candidate = minfd; candidate < limit; candidate++) {
            /* Only skip slots owned by LKL (which may have no real /proc/pid/fd
             * entry, e.g. virtual stdio redirects). Host-managed entries are
             * closed natively in the kernel, so /proc/pid/fd is authoritative
             * for whether the number is free to reuse. */
            const struct kbox_fd_entry *entry =
                ctx ? fd_table_entry(ctx->fd_table, candidate) : NULL;
            if (kbox_fd_entry_is_lkl(entry))
                continue;
            char fd_path[80];
            struct stat st;
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", (int) pid,
                     candidate);
            if (lstat(fd_path, &st) < 0 && errno == ENOENT)
                return candidate;
        }
        return -EMFILE;
    }

    int pidfd = open_tracee_pidfd(pid);
    if (pidfd < 0)
        return pidfd;

    for (int candidate = minfd; candidate < limit; candidate++) {
        const struct kbox_fd_entry *entry =
            ctx ? fd_table_entry(ctx->fd_table, candidate) : NULL;
        if (kbox_fd_entry_is_lkl(entry))
            continue;
        int probe = (int) syscall(__NR_pidfd_getfd, pidfd,
                                  (unsigned int) candidate, (unsigned int) 0);
        if (probe >= 0) {
            close(probe);
            continue;
        }
        if (errno == EBADF) {
            close(pidfd);
            return candidate;
        }
        int saved_errno = errno;
        close(pidfd);
        return -saved_errno;
    }

    close(pidfd);
    return -EMFILE;
}

static void cleanup_replaced_fd_tracking(struct kbox_supervisor_ctx *ctx,
                                         long fd)
{
    long stale_lkl;
    long shadow_vfd;

    if (!ctx || !ctx->fd_table)
        return;

    stale_lkl = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (stale_lkl >= 0) {
        remove_fd_table_entry_with_writeback(ctx, fd);
        ctx_close_lkl_if_unreferenced(ctx, stale_lkl, 0);
    } else if (stale_lkl == KBOX_LKL_FD_SHADOW_ONLY) {
        remove_fd_table_entry_with_writeback(ctx, fd);
    }

    shadow_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
    if (shadow_vfd >= 0) {
        long shadow_lkl = kbox_fd_table_get_lkl(ctx->fd_table, shadow_vfd);
        remove_fd_table_entry_with_writeback(ctx, shadow_vfd);
        if (shadow_lkl >= 0)
            ctx_close_lkl_if_unreferenced(ctx, shadow_lkl, 1);
    }
}

/* Duplicate a KBOX_FD_HOST_SAME_FD_SHADOW entry onto target_fd so both FDs
 * share the underlying memfd (preserving offset, writeback tracking, and LKL
 * FD ownership across dup/dup2/dup3/F_DUPFD).
 */
static struct kbox_dispatch dup_same_fd_shadow_to(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int cloexec,
    int replace_existing)
{
    if (!orig || orig->lkl_fd < 0 || orig->shadow_sp < 0 ||
        !fd_table_entry(ctx->fd_table, newfd))
        return kbox_dispatch_errno(EBADF);

    long orig_lkl = orig->lkl_fd;
    int orig_wb = orig->shadow_writeback;
    int new_sp = fcntl(orig->shadow_sp, F_DUPFD_CLOEXEC, 3);
    if (new_sp < 0)
        return kbox_dispatch_errno(EMFILE);

    uint32_t af = cloexec ? O_CLOEXEC : 0;
    int injected = request_addfd_at(ctx, req, new_sp, (int) newfd, af);
    if (injected < 0) {
        close(new_sp);
        return kbox_dispatch_errno(-injected);
    }
    if (injected != newfd) {
        close(new_sp);
        return kbox_dispatch_errno(EIO);
    }

    if (replace_existing)
        cleanup_replaced_fd_tracking(ctx, newfd);

    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, orig_lkl, 0) < 0) {
        close(new_sp);
        return kbox_dispatch_errno(EMFILE);
    }
    note_low_fd_identity(ctx, kbox_syscall_request_pid(req), newfd);

    struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, newfd);
    ne->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
    ne->shadow_sp = new_sp;
    if (orig_wb)
        note_shadow_writeback_open(ctx, ne);
    if (cloexec)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);

    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup. */

static struct kbox_dispatch forward_dup(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd;

    sweep_stale_low_fds(ctx, kbox_syscall_request_pid(req),
                        KBOX_NATIVE_CLOSE_MAX);
    lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup on a host-passthrough FD (pipe, stdio, eventfd, etc.)
         * by obtaining a supervisor copy via pidfd_getfd, injecting it into
         * the tracee via ADDFD, and tracking the result.
         */
        if (ctx->active_proc &&
            (uint64_t) fd >= ctx->active_proc->rlimit_nofile_cur)
            return kbox_dispatch_errno(EMFILE);
        int copy =
            dup_tracee_fd_shared(kbox_syscall_request_pid(req), (int) fd);
        if (ctx->verbose)
            fprintf(stderr, "kbox: dup host fd=%ld shared copy=%d\n", fd, copy);
        if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO)
            return kbox_dispatch_continue(); /* kernel dup shares the file */
        if (copy < 0)
            return kbox_dispatch_errno(-copy);
        int tracee_fd = request_addfd(ctx, req, copy, 0);
        close(copy);
        if (tracee_fd < 0)
            return kbox_dispatch_errno(-tracee_fd);
        if (ctx->active_proc &&
            (uint64_t) tracee_fd >= ctx->active_proc->rlimit_nofile_cur) {
            kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                          tracee_fd, 1);
            return kbox_dispatch_errno(EMFILE);
        }
        if (tracee_fd >= 0)
            kbox_retire_stale_host_fd_vfd(ctx, kbox_syscall_request_pid(req),
                                          tracee_fd, 1);
        track_host_passthrough_fd(ctx->fd_table, tracee_fd);
        return kbox_dispatch_value(tracee_fd);
    }

    if (lkl_fd < 0) {
        /* Check for shadow socket (tracee holds host_fd from ADDFD). */
        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, fd);
        if (orig_vfd < 0) {
            if (!fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd))
                return kbox_dispatch_continue();
            return kbox_dispatch_errno(EBADF);
        }

        /* Shadow socket dup: inject a new copy of the socketpair end into
         * the tracee and track the new host_fd.
         */
        struct kbox_fd_entry *orig = NULL;
        orig = fd_table_entry(ctx->fd_table, orig_vfd);
        if (!orig || orig->shadow_sp < 0)
            return kbox_dispatch_continue();

        long orig_lkl = orig->lkl_fd;
        int new_host = request_addfd(ctx, req, orig->shadow_sp, 0);
        if (new_host < 0)
            return kbox_dispatch_errno(-new_host);

        long new_vfd = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
        if (new_vfd < 0) {
            /* Can't track the FD; return error.  The tracee already has
             * the FD via ADDFD which we can't revoke, but returning
             * EMFILE tells the caller dup failed so it won't use it.
             */
            return kbox_dispatch_errno(EMFILE);
        }
        kbox_fd_table_set_host_fd(ctx->fd_table, new_vfd, new_host);
        {
            struct kbox_fd_entry *stale =
                fd_table_entry(ctx->fd_table, new_host);
            if (stale && new_host != new_vfd &&
                stale->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
                kbox_fd_table_remove(ctx->fd_table, new_host);
        }

        /* Propagate shadow_sp so chained dups work. */
        int new_sp = dup(orig->shadow_sp);
        if (new_sp >= 0) {
            struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, new_vfd);
            if (ne)
                ne->shadow_sp = new_sp;
            else
                close(new_sp);
        }
        return kbox_dispatch_value((int64_t) new_host);
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, fd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0) {
        long target_fd =
            allocate_dup_shadow_fd_from(ctx, kbox_syscall_request_pid(req), 0);
        if (target_fd < 0)
            return kbox_dispatch_errno(EMFILE);
        return dup_same_fd_shadow_to(req, ctx, orig, target_fd, 0, 0);
    }

    long new_vfd =
        allocate_dup_shadow_fd_from(ctx, kbox_syscall_request_pid(req), 0);
    if (new_vfd < 0)
        return kbox_dispatch_errno(EMFILE);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_fd);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, fd);
    if (kbox_fd_table_insert_at(ctx->fd_table, new_vfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EMFILE);
    }
    if (new_vfd < KBOX_NATIVE_CLOSE_MAX)
        install_low_vfd_placeholder(ctx, req, new_vfd, 0);
    return kbox_dispatch_value((int64_t) new_vfd);
}

static struct kbox_dispatch finish_shadow_dup_at(
    struct kbox_supervisor_ctx *ctx,
    struct kbox_fd_entry *orig,
    long newfd,
    int new_host,
    int cloexec)
{
    long orig_lkl = orig->lkl_fd;
    int orig_sp = orig->shadow_sp;

    /* Remove any stale mapping at newfd (virtual, shadow, or SHADOW_ONLY). */
    long stale = kbox_fd_table_get_lkl(ctx->fd_table, newfd);
    if (stale == KBOX_LKL_FD_SHADOW_ONLY) {
        kbox_fd_table_remove(ctx->fd_table, newfd);
    } else if (stale >= 0) {
        remove_fd_table_entry_with_writeback(ctx, newfd);
        ctx_close_lkl_if_unreferenced(ctx, stale, 0);
    } else {
        long sv = kbox_fd_table_find_by_host_fd(ctx->fd_table, newfd);
        if (sv >= 0) {
            long sl = kbox_fd_table_get_lkl(ctx->fd_table, sv);
            remove_fd_table_entry_with_writeback(ctx, sv);
            if (sl >= 0)
                ctx_close_lkl_if_unreferenced(ctx, sl, 1);
        }
    }

    long nv = kbox_fd_table_insert(ctx->fd_table, orig_lkl, 0);
    if (nv < 0)
        return kbox_dispatch_errno(EMFILE);
    kbox_fd_table_set_host_fd(ctx->fd_table, nv, new_host);

    int ns = dup(orig_sp);
    if (ns >= 0) {
        struct kbox_fd_entry *ne = fd_table_entry(ctx->fd_table, nv);
        if (ne) {
            ne->shadow_sp = ns;
            if (cloexec)
                ne->cloexec = 1;
        } else {
            close(ns);
        }
    }
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup2. */

static struct kbox_dispatch forward_dup2(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);
    if (getenv("KBOX_FD_TRACE") && newfd < 64)
        fprintf(stderr, "kbofdt: dup2 pid=%d old=%ld new=%ld lkl_old=%ld\n",
                (int) kbox_syscall_request_pid(req), oldfd, newfd, lkl_old);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        /* Emulate dup2 on a host-passthrough FD. Use pidfd_getfd to get
         * a supervisor copy sharing the same file description, then inject
         * at the target FD via ADDFD_AT.  When blocked (container seccomp),
         * allow the kernel to perform dup2 natively via CONTINUE.
         */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);
        int copy =
            dup_tracee_fd_shared(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0) {
            if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                cleanup_replaced_fd_tracking(ctx, newfd);
                track_host_passthrough_fd(ctx->fd_table, newfd);
                return kbox_dispatch_continue();
            }
            return kbox_dispatch_errno(-copy);
        }
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, 0);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup2: dup2(fd, fd) must return fd unchanged. */
        if (oldfd == newfd)
            return kbox_dispatch_value((int64_t) newfd);

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                int new_host =
                    request_addfd_at(ctx, req, orig->shadow_sp, (int) newfd, 0);
                if (new_host >= 0)
                    return finish_shadow_dup_at(ctx, orig, newfd, new_host, 0);
            }
        }
        if (!fd_should_deny_io_ctx(ctx->fd_table, oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_value((int64_t) newfd);

    /* Redirect onto a low FD (0/1/2). Those descriptors are the guest's
     * stdio: the guest reads and closes them through the host, so the host has
     * to own whatever lands there. The file behind the source FD is only
     * reachable through a supervisor shadow -- kbox keeps read shadows local
     * and never injects them at the source number -- so a plain CONTINUE would
     * dup a host number that does not exist. Inject the shadow at the target
     * number and mark the entry as a same-fd shadow instead: reads then
     * continue to the host and see the file's bytes. Without this, postgres'
     * bootstrap read its own input as EBADF and died with "input in flex
     * scanner failed".
     */
    if (newfd < KBOX_NATIVE_CLOSE_MAX) {
        struct kbox_fd_entry *src = fd_table_entry(ctx->fd_table, oldfd);
        int memfd = (src && src->shadow_sp >= 0) ? src->shadow_sp : -1;
        int own_memfd = 0;
        int writeback = src ? src->shadow_writeback : 0;
        long src_flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_old, F_GETFL, 0);

        /* Only for read-only sources. A writable redirect has to keep writing
         * into LKL -- redirecting ">" onto fd 1 through a memfd would swallow
         * every byte the guest writes and leave the file empty, which is what
         * made every script written inside a container run as a no-op. */
        if (src_flags >= 0 && (src_flags & O_ACCMODE) != O_RDONLY)
            memfd = -2;

        if (memfd != -2 && memfd < 0) {
            memfd = kbox_shadow_create_resilient(ctx, lkl_old);
            if (memfd < 0) {
                /* Non-regular files (e.g. directories) cannot be shadowed into
                 * a memfd; fall through to LKL dup + host placeholder fd. */
                memfd = -2;
            } else {
                kbox_shadow_seal(memfd);
                own_memfd = 1;
            }
        }

        if (memfd != -2) {
            int injected = request_addfd_at(ctx, req, memfd, (int) newfd, 0);
            if (injected < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(-injected);
            }

            cleanup_replaced_fd_tracking(ctx, newfd);
            if (kbox_fd_table_insert_at(ctx->fd_table, newfd, lkl_old, 0) < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(EBADF);
            }
            note_low_fd_identity(ctx, kbox_syscall_request_pid(req), newfd);
            struct kbox_fd_entry *dst = fd_table_entry(ctx->fd_table, newfd);
            if (dst) {
                dst->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
                dst->shadow_sp = own_memfd ? memfd : -1;
                dst->shadow_writeback = writeback;
            }
            return kbox_dispatch_value((int64_t) newfd);
        }
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, oldfd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0)
        return dup_same_fd_shadow_to(req, ctx, orig, newfd, 0, 1);

    /* Dup first, then close the old mapping.  This preserves the old newfd
     * if the dup fails (e.g. EMFILE), matching dup2 atomicity semantics.
     */
    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = remove_fd_table_entry_with_writeback(ctx, newfd);
    if (existing >= 0)
        ctx_close_lkl_if_unreferenced(ctx, existing, 0);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (newfd < KBOX_NATIVE_CLOSE_MAX)
        install_low_vfd_placeholder(ctx, req, newfd, 0);
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_dup3. */

static struct kbox_dispatch forward_dup3(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx)
{
    long oldfd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long newfd = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* dup3 only accepts O_CLOEXEC; reject anything else per POSIX. */
    if (flags & ~((long) O_CLOEXEC))
        return kbox_dispatch_errno(EINVAL);
    if (getenv("KBOX_FD_TRACE") && newfd < 64)
        fprintf(stderr, "kbofdt: dup3 pid=%d old=%ld new=%ld\n",
                (int) kbox_syscall_request_pid(req), oldfd, newfd);

    long lkl_old = kbox_fd_table_get_lkl(ctx->fd_table, oldfd);

    if (lkl_old == KBOX_LKL_FD_SHADOW_ONLY) {
        if (oldfd == newfd)
            return kbox_dispatch_errno(EINVAL);
        uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
        int copy =
            dup_tracee_fd_shared(kbox_syscall_request_pid(req), (int) oldfd);
        if (copy < 0) {
            if (copy == -EPERM || copy == -ENOSYS || copy == -ENXIO) {
                cleanup_replaced_fd_tracking(ctx, newfd);
                track_host_passthrough_fd(ctx->fd_table, newfd);
                if (flags & O_CLOEXEC)
                    kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
                return kbox_dispatch_continue();
            }
            return kbox_dispatch_errno(-copy);
        }
        int injected = request_addfd_at(ctx, req, copy, (int) newfd, af);
        close(copy);
        if (injected < 0)
            return kbox_dispatch_errno(-injected);
        cleanup_replaced_fd_tracking(ctx, newfd);
        track_host_passthrough_fd(ctx->fd_table, newfd);
        if (flags & O_CLOEXEC)
            kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
        return kbox_dispatch_value((int64_t) newfd);
    }

    if (lkl_old < 0) {
        /* Shadow socket dup3: dup3(fd, fd, ...) must return EINVAL. */
        if (oldfd == newfd) {
            if (kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd) >= 0)
                return kbox_dispatch_errno(EINVAL);
        }

        long orig_vfd = kbox_fd_table_find_by_host_fd(ctx->fd_table, oldfd);
        if (orig_vfd >= 0) {
            struct kbox_fd_entry *orig =
                fd_table_entry(ctx->fd_table, orig_vfd);
            if (orig && orig->shadow_sp >= 0) {
                uint32_t af = (flags & O_CLOEXEC) ? O_CLOEXEC : 0;
                int new_host = request_addfd_at(ctx, req, orig->shadow_sp,
                                                (int) newfd, af);
                if (new_host >= 0)
                    return finish_shadow_dup_at(ctx, orig, newfd, new_host,
                                                (flags & O_CLOEXEC) != 0);
            }
        }
        if (!fd_should_deny_io_ctx(ctx->fd_table, oldfd, lkl_old)) {
            cleanup_replaced_fd_tracking(ctx, newfd);
            return kbox_dispatch_continue();
        }
        return kbox_dispatch_errno(EBADF);
    }

    if (oldfd == newfd)
        return kbox_dispatch_errno(EINVAL);

    /* Redirect onto a low FD (0/1/2). Those descriptors are the guest's
     * stdio: the guest reads and closes them through the host, so the host has
     * to own whatever lands there. The file behind the source FD is only
     * reachable through a supervisor shadow -- kbox keeps read shadows local
     * and never injects them at the source number -- so a plain CONTINUE would
     * dup a host number that does not exist. Inject the shadow at the target
     * number and mark the entry as a same-fd shadow instead: reads then
     * continue to the host and see the file's bytes. Without this, postgres'
     * bootstrap read its own input as EBADF and died with "input in flex
     * scanner failed".
     */
    if (newfd < KBOX_NATIVE_CLOSE_MAX) {
        struct kbox_fd_entry *src = fd_table_entry(ctx->fd_table, oldfd);
        int memfd = (src && src->shadow_sp >= 0) ? src->shadow_sp : -1;
        int own_memfd = 0;
        int writeback = src ? src->shadow_writeback : 0;
        long src_flags = kbox_lkl_fcntl(ctx->sysnrs, lkl_old, F_GETFL, 0);

        /* Only for read-only sources. A writable redirect has to keep writing
         * into LKL -- redirecting ">" onto fd 1 through a memfd would swallow
         * every byte the guest writes and leave the file empty, which is what
         * made every script written inside a container run as a no-op. */
        if (src_flags >= 0 && (src_flags & O_ACCMODE) != O_RDONLY)
            memfd = -2;

        if (memfd != -2 && memfd < 0) {
            memfd = kbox_shadow_create_resilient(ctx, lkl_old);
            if (memfd < 0) {
                /* Non-regular files (e.g. directories) cannot be shadowed into
                 * a memfd; fall through to LKL dup + host placeholder fd. */
                memfd = -2;
            } else {
                kbox_shadow_seal(memfd);
                own_memfd = 1;
            }
        }

        if (memfd != -2) {
            int injected = request_addfd_at(ctx, req, memfd, (int) newfd, 0);
            if (injected < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(-injected);
            }

            cleanup_replaced_fd_tracking(ctx, newfd);
            if (kbox_fd_table_insert_at(ctx->fd_table, newfd, lkl_old, 0) < 0) {
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(EBADF);
            }
            note_low_fd_identity(ctx, kbox_syscall_request_pid(req), newfd);
            struct kbox_fd_entry *dst = fd_table_entry(ctx->fd_table, newfd);
            if (dst) {
                dst->host_fd = KBOX_FD_HOST_SAME_FD_SHADOW;
                dst->shadow_sp = own_memfd ? memfd : -1;
                dst->shadow_writeback = writeback;
            }
            return kbox_dispatch_value((int64_t) newfd);
        }
    }

    struct kbox_fd_entry *orig = fd_table_entry(ctx->fd_table, oldfd);
    if (orig && orig->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
        orig->shadow_sp >= 0)
        return dup_same_fd_shadow_to(req, ctx, orig, newfd,
                                     (flags & O_CLOEXEC) != 0, 1);

    long ret = kbox_lkl_dup(ctx->sysnrs, lkl_old);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    long existing = remove_fd_table_entry_with_writeback(ctx, newfd);
    if (existing >= 0)
        ctx_close_lkl_if_unreferenced(ctx, existing, 0);

    int mirror = kbox_fd_table_mirror_tty(ctx->fd_table, oldfd);
    if (kbox_fd_table_insert_at(ctx->fd_table, newfd, ret, mirror) < 0) {
        lkl_close_and_invalidate(ctx, ret);
        return kbox_dispatch_errno(EBADF);
    }
    if (newfd < KBOX_NATIVE_CLOSE_MAX)
        install_low_vfd_placeholder(ctx, req, newfd, (flags & O_CLOEXEC) != 0);
    if (flags & O_CLOEXEC)
        kbox_fd_table_set_cloexec(ctx->fd_table, newfd, 1);
    return kbox_dispatch_value((int64_t) newfd);
}

/* forward_fstat. */

static struct kbox_dispatch forward_fstat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY) {
        /* A descriptor kbox handed to the tracee points at a host file, so the
         * kernel would report the supervisor's uid. Answer from the file
         * itself and let the stored guest owner win, exactly as the path stat
         * handlers do. */
        char link[64];
        struct stat host_stat;
        int64_t uid, gid;
        pid_t pid = kbox_syscall_request_pid(req);
        uint64_t remote = kbox_syscall_request_arg(req, 1);

        if (remote == 0)
            return kbox_dispatch_errno(EFAULT);
        snprintf(link, sizeof(link), "/proc/%d/fd/%ld", (int) pid, fd);
        if (stat(link, &host_stat) < 0)
            return kbox_dispatch_continue();
        if (kbox_owner_xattr_get(AT_FDCWD, link, 0, &uid, &gid) == 1) {
            host_stat.st_uid = (uid_t) uid;
            host_stat.st_gid = (gid_t) gid;
        } else if (ctx->root_identity) {
            kbox_owner_apply(pid, &host_stat);
        }
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote, &host_stat,
                                                 sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
    int wb_sp = -1;
    if (entry && entry->shadow_writeback && entry->shadow_sp >= 0)
        wb_sp = entry->shadow_sp;
    else if (ctx->active_writeback_shadows > 0)
        wb_sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);
    int skip_cache = (wb_sp >= 0) || (ctx->active_writeback_shadows > 0);

    /* Check the stat cache first to avoid an LKL round-trip.  Skip the static
     * LKL cache when any writeback shadow is active because writes/ftruncate
     * mutate the live memfd size before writeback.
     */
#if KBOX_STAT_CACHE_ENABLED
    if (!skip_cache) {
        for (int ci = 0; ci < KBOX_STAT_CACHE_MAX; ci++) {
            if (ctx->stat_cache[ci].lkl_fd == lkl_fd) {
                int wrc = guest_mem_write_small_metadata(
                    ctx, kbox_syscall_request_pid(req), remote_stat,
                    &ctx->stat_cache[ci].st, sizeof(ctx->stat_cache[ci].st));
                if (wrc < 0)
                    return kbox_dispatch_errno(-wrc);
                return kbox_dispatch_value(0);
            }
        }
    }
#endif

    /* Always source identity/permission metadata (st_dev, st_ino, st_mode,
     * st_uid, st_gid, st_nlink) from LKL rather than an anonymous shadow memfd
     * so writable shadows and read-only FDs to the same inode agree on
     * st_dev/st_ino (e.g. Chromium PlatformSharedMemoryRegion::Create).
     */
    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_fstat(ctx->sysnrs, lkl_fd, &kst);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    if (ctx->root_identity)
        (void) kbox_owner_apply_overlay(&host_stat);
    apply_writeback_shadow_stat(ctx, &kst, &host_stat);

    if (wb_sp >= 0) {
        struct stat mem_stat;
        if (fstat(wb_sp, &mem_stat) == 0) {
            host_stat.st_size = mem_stat.st_size;
            host_stat.st_blocks = mem_stat.st_blocks;
        }
    }

    /* Insert into stat cache (overwrite oldest slot via round-robin). */
#if KBOX_STAT_CACHE_ENABLED
    if (!skip_cache) {
        static __thread unsigned stat_cache_rr;
        unsigned slot = stat_cache_rr % KBOX_STAT_CACHE_MAX;
        stat_cache_rr++;
        ctx->stat_cache[slot].lkl_fd = lkl_fd;
        ctx->stat_cache[slot].st = host_stat;
    }
#endif

    /* Which size the guest is told, per descriptor. BFD refuses a relocatable
     * object when a section header claims bytes past the size it reads here,
     * so this line is the one that separates a wrong size from a wrong read.
     */
    if (ctx->verbose && getenv("KBOX_FSTAT_TRACE"))
        fprintf(/* format-ok: literal on the next line */
                stderr,
                "kbox: fstat pid=%u fd=%ld lkl=%ld size=%lld mode=%o "
                "cache=%d\n",
                (unsigned) kbox_syscall_request_pid(req), fd, lkl_fd,
                (long long) host_stat.st_size, (unsigned) host_stat.st_mode,
                skip_cache ? 0 : 1);

    int wrc = guest_mem_write_small_metadata(ctx, kbox_syscall_request_pid(req),
                                             remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_truncate.
 *
 * The path-based truncate(2) had no dispatch entry at all, so the deny-unknown
 * tail answered ENOSYS and os.truncate() failed on every path
 * (test_posix.test_truncate). It is a path operation, so it goes through the
 * same translation as chmod and unlink: LKL for the guest rootfs, the host for
 * a bind mount.
 */
static struct kbox_dispatch forward_truncate(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    long length = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (length < 0)
        return kbox_dispatch_errno(EINVAL);

    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 0, translated)) {
        pid_t pid = kbox_syscall_request_pid(req);
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));

        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
            translate_proc_self_at(sv_dirfd, translated, pid, sv_path,
                                   sizeof(sv_path));
        }
        int hfd = openat(sv_dirfd, sv_path, O_WRONLY | O_CLOEXEC);
        int hrc;
        int saved;

        if (hfd < 0) {
            saved = errno;
            if (close_sv)
                close(sv_dirfd);
            return kbox_dispatch_errno(saved);
        }
        hrc = ftruncate(hfd, (off_t) length);
        saved = errno;
        close(hfd);
        if (close_sv)
            close(sv_dirfd);
        if (hrc < 0)
            return kbox_dispatch_errno(saved);
        invalidate_path_shadow_cache(ctx);
        return kbox_dispatch_value(0);
    }

    /* Guest rootfs: open for writing, truncate, close. open() reports the
     * permission and directory errors truncate would report. */
    long lkl_fd = kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated,
                                  O_WRONLY | O_CLOEXEC, 0);
    if (lkl_fd < 0)
        return kbox_dispatch_errno((int) (-lkl_fd));

    /* While any descriptor of this file carries a writable shadow, the shadow
     * is the file's live copy: a read goes to it by device and inode. A close
     * no longer flushes it (item 33), so truncating only the LKL inode would
     * leave the shadow holding the old bytes and the guest would read the file
     * back as it was before the truncate. Apply the truncation to the shadow as
     * well; both share one inode once every later open reuses it. */
    {
        int sp = kbox_find_active_writeback_shadow_sp(ctx, lkl_fd);

        if (sp >= 0)
            (void) ftruncate(sp, (off_t) length);
    }

    long ret = kbox_lkl_ftruncate_safe(ctx->sysnrs, lkl_fd, length);
    kbox_lkl_close(ctx->sysnrs, lkl_fd);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_value(0);
}

/* forward_newfstatat. */

static struct kbox_dispatch forward_newfstatat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 2);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    /* /proc is the container's own procfs, so /proc/self/exe names the memfd
     * the supervisor exec'd; following it fails and official entrypoints
     * (gosu, su-exec, tini) stat it before re-exec. Follow it to the guest
     * path the container was started with instead. lstat stays on the real
     * link, which is what `ls -l` wants. */
    if (!(flags & AT_SYMLINK_NOFOLLOW) &&
        strcmp(translated, "/proc/self/exe") == 0) {
        const char *exe =
            kbox_guest_exe_for(ctx, kbox_syscall_request_pid(req));
        if (exe[0])
            snprintf(translated, sizeof(translated), "%s", exe);
    }

    /* Host dirfd or virtual path: call host fstatat with a local path copy
     * to eliminate the TOCTOU window where a sibling thread could swap the
     * path between validation and the kernel re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
            translate_proc_self_at(sv_dirfd, translated, pid, sv_path,
                                   sizeof(sv_path));
        }
        struct stat host_stat;
        int host_rc = fstatat(sv_dirfd, sv_path, &host_stat, (int) flags);
        int saved = errno;
        if (host_rc == 0)
            apply_virtual_owner(ctx, pid, &host_stat, sv_dirfd, sv_path,
                                (int) (flags & AT_SYMLINK_NOFOLLOW));
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));

    long ret;
    if (translated[0] == '\0' && (flags & AT_EMPTY_PATH))
        ret = kbox_lkl_fstat(ctx->sysnrs, lkl_dirfd, &kst);
    else
        ret = kbox_lkl_newfstatat(ctx->sysnrs, lkl_dirfd, translated, &kst,
                                  flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    if (ctx->root_identity)
        (void) kbox_owner_apply_overlay(&host_stat);
    apply_writeback_shadow_stat(ctx, &kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Guest-thread local fast-path.  Handles syscalls that never touch LKL and
 * can be resolved on the calling thread without a service-thread round-trip.
 * Returns 1 if handled (result in *out), 0 if the caller must use the service
 * thread.  Safe to call from the SIGSYS handler or rewrite trampoline context.
 *
 * Three tiers:
 *   1. Pure emulation: cached constant values (getpid, getppid, gettid).
 *   2. Always-CONTINUE: host kernel handles the syscall unmodified.
 *   3. Conditional emulation: e.g. arch_prctl(SET_FS) in trap/rewrite.
 *
 * LKL-touching syscalls (stat, openat, read on LKL FDs, etc.) are NOT
 * handled here; they MUST go through the service thread.
 */
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out)
{
    if (!h || !out)
        return 0;

    /* Tier 1: pure emulation. */
    if (nr == h->getpid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }
    if (nr == h->getppid) {
        *out = kbox_dispatch_value(0);
        return 1;
    }
    if (nr == h->gettid) {
        *out = kbox_dispatch_value(1);
        return 1;
    }

    /* Tier 2: always-CONTINUE; host kernel handles these directly. */
    if (nr == h->brk || nr == h->futex || nr == h->rseq ||
        nr == h->set_tid_address || nr == h->set_robust_list ||
        nr == h->get_robust_list || nr == h->munmap || nr == h->mremap ||
        nr == h->membarrier || nr == h->madvise || nr == h->wait4 ||
        nr == h->waitid || nr == h->exit || nr == h->exit_group ||
        nr == h->rt_sigreturn || nr == h->rt_sigaltstack ||
        nr == h->rt_sigsuspend || nr == h->rt_sigtimedwait ||
        nr == h->setitimer || nr == h->getitimer || nr == h->setpgid ||
        nr == h->getpgid || nr == h->getsid || nr == h->setsid ||
        nr == h->fork || nr == h->vfork || nr == h->sched_yield ||
        nr == h->sched_setparam || nr == h->sched_getparam ||
        nr == h->sched_setscheduler || nr == h->sched_getscheduler ||
        nr == h->sched_get_priority_max || nr == h->sched_get_priority_min ||
        nr == h->sched_setaffinity || nr == h->sched_getaffinity ||
        nr == h->getrusage || nr == h->ppoll || nr == h->pselect6 ||
        nr == h->nanosleep || nr == h->clock_nanosleep ||
        nr == h->timer_create || nr == h->timer_gettime ||
        nr == h->timer_getoverrun || nr == h->timer_settime ||
        nr == h->timer_delete || nr == h->sysinfo) {
        *out = kbox_dispatch_continue();
        return 1;
    }

    return 0;
}

static struct kbox_dispatch dispatch_host_statfs(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    const char *host_path,
    uint64_t remote_buf)
{
    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    if (statfs(host_path, &sfs) < 0)
        return kbox_dispatch_errno(errno);
    int wrc = guest_mem_write(ctx, pid, remote_buf, &sfs, sizeof(sfs));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

static struct kbox_dispatch dispatch_lkl_statfs_result(
    struct kbox_supervisor_ctx *ctx,
    pid_t pid,
    long ret,
    const struct statfs *sfs,
    uint64_t remote_buf)
{
    if (ret < 0)
        return kbox_dispatch_from_lkl(ret);
    /* The LKL overlay root reports 0 blocks. Java/Spring disk-space checks
     * then see 0 bytes free and mark the service DOWN. Borrow capacity from
     * the host RAM-backed dir that holds the rootfs, keep LKL's type/fsid. */
    struct statfs fixed = *sfs;
    if (fixed.f_blocks == 0) {
        struct statfs host;
        if (statfs("/dev/shm", &host) == 0 && host.f_blocks > 0) {
            fixed.f_bsize = host.f_bsize;
            fixed.f_frsize = host.f_frsize;
            fixed.f_blocks = host.f_blocks;
            fixed.f_bfree = host.f_bfree;
            fixed.f_bavail = host.f_bavail;
            fixed.f_files = host.f_files ? host.f_files : 1000000;
            fixed.f_ffree = host.f_ffree ? host.f_ffree : 1000000;
        }
    }
    if (fixed.f_files == 0) {
        fixed.f_files = 1000000;
        fixed.f_ffree = 1000000;
    }
    sfs = &fixed;
    int wrc = guest_mem_write(ctx, pid, remote_buf, sfs, sizeof(*sfs));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
    return kbox_dispatch_value(0);
}

/* listxattr, llistxattr, flistxattr.
 *
 * These used to answer "zero bytes" for every request, which made a missing
 * file look like a file with no extended attributes: os.listxattr() on a path
 * that does not exist returned [] instead of raising ENOENT. The guest buffer
 * is filled from the filesystem, and errors travel back unchanged.
 */
static struct kbox_dispatch finish_xattr_list(struct kbox_supervisor_ctx *ctx,
                                              pid_t pid,
                                              uint64_t remote_list,
                                              long size,
                                              const uint8_t *buf,
                                              long ret)
{
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));
    if (size > 0 && ret > 0) {
        long n = ret < size ? ret : size;
        int wrc = guest_mem_write(ctx, pid, remote_list, buf, (size_t) n);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
    }
    return kbox_dispatch_value(ret);
}

static struct kbox_dispatch forward_xattr_list_common(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int follow_links)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_list = kbox_syscall_request_arg(req, 1);
    long size = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd = AT_FDCWD_LINUX;
    long ret;
    int rc;

    if (size < 0)
        return kbox_dispatch_errno(EINVAL);
    if (size > KBOX_IO_CHUNK_LEN)
        size = KBOX_IO_CHUNK_LEN;
    if (size > 0 && remote_list == 0)
        return kbox_dispatch_errno(EFAULT);

    rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                        sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (should_continue_for_dirfd(lkl_dirfd)) {
        ret = follow_links
                  ? (long) listxattr(translated,
                                     size ? (char *) dispatch_scratch : NULL,
                                     (size_t) size)
                  : (long) llistxattr(translated,
                                      size ? (char *) dispatch_scratch : NULL,
                                      (size_t) size);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        return finish_xattr_list(ctx, pid, remote_list, size, dispatch_scratch,
                                 ret);
    }

    if (should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        ret = follow_links
                  ? (long) listxattr(sv_path,
                                     size ? (char *) dispatch_scratch : NULL,
                                     (size_t) size)
                  : (long) llistxattr(sv_path,
                                      size ? (char *) dispatch_scratch : NULL,
                                      (size_t) size);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        return finish_xattr_list(ctx, pid, remote_list, size, dispatch_scratch,
                                 ret);
    }

    /* Pick the LKL syscall that matches the follow/no-follow variant. Using
     * listxattr(2) for the no-follow call made llistxattr() on a dangling
     * symlink fail with ENOENT, because listxattr(2) resolves the link:
     * shutil.copystat() copies the attributes of a dangling link and got
     * "No such file or directory" instead of the (empty) attribute list. */
    ret = lkl_syscall6(
        follow_links ? ctx->sysnrs->listxattr : ctx->sysnrs->llistxattr,
        (long) translated, size ? (long) dispatch_scratch : 0, size, 0, 0, 0);
    return finish_xattr_list(ctx, pid, remote_list, size, dispatch_scratch,
                             ret);
}

static struct kbox_dispatch forward_listxattr(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_xattr_list_common(req, ctx, 1);
}

static struct kbox_dispatch forward_llistxattr(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_xattr_list_common(req, ctx, 0);
}

static struct kbox_dispatch forward_flistxattr(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    uint64_t remote_list = kbox_syscall_request_arg(req, 1);
    long size = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);
    if (size < 0)
        return kbox_dispatch_errno(EINVAL);
    if (size > KBOX_IO_CHUNK_LEN)
        size = KBOX_IO_CHUNK_LEN;
    if (size > 0 && remote_list == 0)
        return kbox_dispatch_errno(EFAULT);

    long ret = lkl_syscall6(ctx->sysnrs->flistxattr, lkl_fd,
                            size ? (long) dispatch_scratch : 0, size, 0, 0, 0);
    return finish_xattr_list(ctx, pid, remote_list, size, dispatch_scratch,
                             ret);
}

static struct kbox_dispatch forward_statfs(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd = AT_FDCWD_LINUX;
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    if (should_continue_for_dirfd(lkl_dirfd))
        return dispatch_host_statfs(ctx, pid, translated, remote_buf);

    if (should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        return dispatch_host_statfs(ctx, pid, sv_path, remote_buf);
    }

    char host_path[KBOX_MAX_PATH];
    if (build_host_open_path(ctx, translated, host_path, sizeof(host_path)) ==
        0)
        return dispatch_host_statfs(ctx, pid, host_path, remote_buf);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    long ret = kbox_lkl_statfs(ctx->sysnrs, translated, &sfs);
    return dispatch_lkl_statfs_result(ctx, pid, ret, &sfs, remote_buf);
}

static struct kbox_dispatch forward_fstatfs(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 1);
    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    long ret = kbox_lkl_fstatfs(ctx->sysnrs, lkl_fd, &sfs);
    return dispatch_lkl_statfs_result(ctx, pid, ret, &sfs, remote_buf);
}

/* forward_statx. */

static struct kbox_dispatch forward_statx(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    int flags = (int) to_c_long_arg(kbox_syscall_request_arg(req, 2));
    unsigned mask = (unsigned) to_c_long_arg(kbox_syscall_request_arg(req, 3));
    uint64_t remote_statx = kbox_syscall_request_arg(req, 4);
    if (remote_statx == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Host dirfd or virtual path: call host statx with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
        }
        uint8_t statx_buf[STATX_BUF_SIZE];
        memset(statx_buf, 0, sizeof(statx_buf));
        long host_rc = syscall(__NR_statx, sv_dirfd, sv_path, flags,
                               (unsigned int) mask, statx_buf);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        apply_virtual_owner_statx(ctx, pid, statx_buf);
        normalize_statx_if_needed(ctx, translated, statx_buf);
        int wrc = guest_mem_write(ctx, pid, remote_statx, statx_buf,
                                  sizeof(statx_buf));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    uint8_t statx_buf[STATX_BUF_SIZE];
    memset(statx_buf, 0, sizeof(statx_buf));

    long ret = kbox_lkl_statx(ctx->sysnrs, lkl_dirfd, translated, flags, mask,
                              statx_buf);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    apply_lkl_owner_overlay_statx(ctx, statx_buf);
    normalize_statx_if_needed(ctx, translated, statx_buf);

    int wrc =
        guest_mem_write(ctx, pid, remote_statx, statx_buf, sizeof(statx_buf));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* forward_faccessat / forward_faccessat2. */

static struct kbox_dispatch do_faccessat(const struct kbox_syscall_request *req,
                                         struct kbox_supervisor_ctx *ctx,
                                         long flags)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));

    /* Host dirfd or virtual path: call host faccessat with local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 1, translated)) {
        char sv_path[KBOX_MAX_PATH];
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        if (should_continue_for_dirfd(lkl_dirfd)) {
            long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
            int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                                   &sv_dirfd, &close_sv);
            if (drc < 0)
                return kbox_dispatch_errno(-drc);
        }
        int host_rc = (int) syscall(__NR_faccessat2, sv_dirfd, sv_path,
                                    (int) mode, (int) flags);
        int saved = errno;
        if (close_sv)
            close(sv_dirfd);
        if (host_rc < 0)
            return kbox_dispatch_errno(saved);
        return kbox_dispatch_value(0);
    }

    long ret =
        kbox_lkl_faccessat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_faccessat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx, 0);
}

static struct kbox_dispatch forward_faccessat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_faccessat(req, ctx,
                        to_c_long_arg(kbox_syscall_request_arg(req, 3)));
}

/* forward_getdents64. */

static struct kbox_dispatch forward_getdents64(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents64);
}

/* forward_getdents (legacy). */

static struct kbox_dispatch forward_getdents(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_getdents_common(req, ctx, kbox_lkl_getdents);
}

/* forward_chdir. */

static struct kbox_dispatch forward_chdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char translated[KBOX_MAX_PATH];
    if (ctx->host_bind_count > 0 || ctx->host_cwd[0] != '\0') {
        pid_t pid = kbox_syscall_request_pid(req);
        uint64_t addr = kbox_syscall_request_arg(req, 0);
        char pathbuf[KBOX_MAX_PATH];
        char norm[KBOX_MAX_PATH];
        int ro = 0;
        int rc = read_guest_string(ctx, pid, addr, pathbuf, sizeof(pathbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        int brc = resolve_host_bind_canonical(ctx, AT_FDCWD_LINUX, pathbuf,
                                              norm, sizeof(norm), translated,
                                              sizeof(translated), &ro);
        if (brc < 0)
            return kbox_dispatch_errno(-brc);
        if (brc > 0) {
            struct stat st;
            if (stat(translated, &st) < 0)
                return kbox_dispatch_errno(errno);
            if (!S_ISDIR(st.st_mode))
                return kbox_dispatch_errno(ENOTDIR);
            set_active_host_cwd(ctx, norm);
            invalidate_translated_path_cache(ctx);
            return kbox_dispatch_value(0);
        }
        if (ctx->host_cwd[0] != '\0' && pathbuf[0] != '/') {
            snprintf(translated, sizeof(translated), "%s", norm);
        } else {
            rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                        sizeof(translated));
            if (rc < 0)
                return kbox_dispatch_errno(-rc);
        }
    } else {
        int rc = translate_request_path(req, ctx, 0, ctx->host_root, translated,
                                        sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
    }

    long ret = kbox_lkl_chdir(ctx->sysnrs, translated);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    record_lkl_cwd(ctx);
    set_active_host_cwd(ctx, "");
    invalidate_translated_path_cache(ctx);
    return kbox_dispatch_value(0);
}

/* forward_fchdir. */

static struct kbox_dispatch forward_fchdir(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !io_should_deny_fd(ctx, req, fd, lkl_fd))) {
        char guest_cwd[KBOX_MAX_PATH];
        pid_t pid = kbox_syscall_request_pid(req);
        if (resolve_host_fd_guest_bind(ctx, pid, fd, guest_cwd,
                                       sizeof(guest_cwd), NULL) > 0)
            set_active_host_cwd(ctx, guest_cwd);
        else
            set_active_host_cwd(ctx, "");
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    long ret = kbox_lkl_fchdir(ctx->sysnrs, lkl_fd);
    if (ret >= 0) {
        record_lkl_cwd(ctx);
        set_active_host_cwd(ctx, "");
        invalidate_translated_path_cache(ctx);
    }
    return kbox_dispatch_from_lkl(ret);
}

/* forward_getcwd. */

static struct kbox_dispatch forward_getcwd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    uint64_t remote_buf = kbox_syscall_request_arg(req, 0);
    int64_t size_raw = to_c_long_arg(kbox_syscall_request_arg(req, 1));

    if (remote_buf == 0)
        return kbox_dispatch_errno(EFAULT);
    if (size_raw <= 0)
        return kbox_dispatch_errno(EINVAL);

    size_t size = (size_t) size_raw;
    if (size > KBOX_MAX_PATH)
        size = KBOX_MAX_PATH;

    if (ctx->host_cwd[0] != '\0') {
        size_t n = strlen(ctx->host_cwd) + 1;
        if (n > size)
            return kbox_dispatch_errno(ERANGE);
        int wrc = guest_mem_write(ctx, pid, remote_buf, ctx->host_cwd, n);
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value((int64_t) n);
    }

    char out[KBOX_MAX_PATH];
    long ret = kbox_lkl_getcwd(ctx->sysnrs, out, (long) size);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    size_t n = (size_t) ret;
    if (n == 0 || n > size)
        return kbox_dispatch_errno(EIO);

    int wrc = guest_mem_write(ctx, pid, remote_buf, out, n);
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value((int64_t) n);
}

/* Shared skeleton for simple *at() syscalls: translate path + resolve dirfd,
 * then delegate to a callback for the actual LKL call.
 */

typedef long (*at_path_invoke_fn)(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx,
                                  long lkl_dirfd,
                                  const char *translated);

static struct kbox_dispatch forward_at_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    at_path_invoke_fn invoke,
    at_path_invoke_fn host_invoke,
    int invalidate_on_success)
{
    char translated[KBOX_MAX_PATH];
    long lkl_dirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, translated,
                                       sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Absolute virtual path (/dev/shm/x and friends): open and stat already
     * serve these from the host kernel, so unlink/mkdir/chmod must as well,
     * otherwise a file created in /dev/shm cannot be removed (Chromium's
     * shm_open + unlink pattern). The path is absolute, so AT_FDCWD is exact.
     */
    if (!should_continue_for_dirfd(lkl_dirfd) && host_invoke &&
        should_continue_virtual_path(ctx, req, 1, translated)) {
        long vret = host_invoke(req, ctx, (long) AT_FDCWD, translated);
        if (invalidate_on_success && vret >= 0)
            invalidate_path_shadow_cache(ctx);
        if (vret < 0)
            return kbox_dispatch_errno((int) (-vret));
        return kbox_dispatch_value(vret);
    }

    /* Host dirfd: call the host syscall with a supervisor-owned copy of the
     * tracee's dirfd to avoid the TOCTOU re-read.
     */
    if (should_continue_for_dirfd(lkl_dirfd)) {
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        long raw_dirfd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));
        if (host_bind_is_readonly(ctx, pid, raw_dirfd, lkl_dirfd))
            return kbox_dispatch_errno(EROFS);
        int sv_dirfd = AT_FDCWD;
        int close_sv = 0;
        int drc = open_host_dirfd_for_dispatch(pid, raw_dirfd, lkl_dirfd,
                                               &sv_dirfd, &close_sv);
        if (drc < 0)
            return kbox_dispatch_errno(-drc);
        long ret = host_invoke(req, ctx, (long) sv_dirfd, translated);
        if (close_sv)
            close(sv_dirfd);
        if (invalidate_on_success && ret >= 0)
            invalidate_path_shadow_cache(ctx);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }

    long ret = invoke(req, ctx, lkl_dirfd, translated);
    if (invalidate_on_success && ret >= 0)
        invalidate_path_shadow_cache(ctx);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_mknodat(const struct kbox_syscall_request *req,
                           struct kbox_supervisor_ctx *ctx,
                           long lkl_dirfd,
                           const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long dev = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return kbox_lkl_mknodat(ctx->sysnrs, lkl_dirfd, translated, mode, dev);
}

static long host_invoke_mknodat(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long sv_dirfd,
                                const char *path)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long dev = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    if (mknodat((int) sv_dirfd, path, (mode_t) mode, (dev_t) dev) < 0)
        return -errno;
    unsigned umask_val = (ctx && ctx->active_proc)
                             ? ctx->active_proc->umask
                             : (ctx ? ctx->guest_umask : 022);
    mode_t want = (mode_t) ((unsigned) mode & ~umask_val & 07777U);
    (void) fchmodat((int) sv_dirfd, path, want, 0);
    return 0;
}

static struct kbox_dispatch forward_mknodat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_mknodat, host_invoke_mknodat,
                                1);
}

static long invoke_mkdirat(const struct kbox_syscall_request *req,
                           struct kbox_supervisor_ctx *ctx,
                           long lkl_dirfd,
                           const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    return kbox_lkl_mkdirat(ctx->sysnrs, lkl_dirfd, translated, mode);
}

static long host_invoke_mkdirat(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                long sv_dirfd,
                                const char *path)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (mkdirat((int) sv_dirfd, path, (mode_t) mode) < 0)
        return -errno;
    unsigned umask_val = (ctx && ctx->active_proc)
                             ? ctx->active_proc->umask
                             : (ctx ? ctx->guest_umask : 022);
    mode_t want = (mode_t) ((unsigned) mode & ~umask_val & 07777U);
    (void) fchmodat((int) sv_dirfd, path, want, 0);
    return 0;
}

static struct kbox_dispatch forward_mkdirat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_mkdirat, host_invoke_mkdirat,
                                1);
}

static long invoke_unlinkat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    char twin[KBOX_MAX_PATH];
    int have_twin =
        fifo_twin_name(ctx, lkl_dirfd, translated, twin, sizeof(twin), NULL);
    long ret = kbox_lkl_unlinkat(ctx->sysnrs, lkl_dirfd, translated, flags);

    /* The FIFO is gone, so its host twin must go too: a FIFO later created at
     * the same name gets a new inode and a new twin, and the old one must not
     * keep buffered bytes or a stale writer alive. */
    if (ret == 0 && have_twin)
        (void) unlink(twin);
    return ret;
}

static long host_invoke_unlinkat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (unlinkat((int) sv_dirfd, path, (int) flags) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlinkat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_unlinkat, host_invoke_unlinkat,
                                1);
}

/* forward_renameat / forward_renameat2. */

/* renameat2 flags, spelled out because the header that defines them is not
 * part of the tree everywhere this file is built. */
#define KBOX_RENAME_NOREPLACE_FLAG 0x1
#define KBOX_RENAME_EXCHANGE_FLAG 0x2

static struct kbox_dispatch do_renameat(const struct kbox_syscall_request *req,
                                        struct kbox_supervisor_ctx *ctx,
                                        long flags)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    long olddirfd, newdirfd;
    pid_t pid = kbox_syscall_request_pid(req);
    int rc = translate_request_at_path(req, ctx, 0, 1, oldtrans,
                                       sizeof(oldtrans), &olddirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_at_path(req, ctx, 2, 3, newtrans, sizeof(newtrans),
                                   &newdirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host dirfd on either side: call host renameat2 with supervisor-owned
     * copies of the tracee's dirfds.
     */
    if (should_continue_for_dirfd(olddirfd) ||
        should_continue_for_dirfd(newdirfd)) {
        if (!should_continue_for_dirfd(olddirfd) ||
            !should_continue_for_dirfd(newdirfd)) {
            if (getenv("KBOX_TRACE"))
                fprintf(stderr,
                        "kbox: rename EXDEV old=%s(dirfd=%ld) new=%s(dirfd=%ld)"
                        " pidside\n",
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
        int host_rc = (int) syscall(__NR_renameat2, sv_old, oldtrans, sv_new,
                                    newtrans, (unsigned int) flags);
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

    long ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                  newtrans, flags);

    /* The NFS client in LKL exports .rename but not .rename2, so the kernel
     * rejects RENAME_NOREPLACE and RENAME_EXCHANGE with EINVAL before any
     * request goes out. BuildKit issues RENAME_NOREPLACE for every atomic
     * write, and with no fallback the build dies at the first one. Emulate
     * the two flags here, at the only layer that knows they were asked for:
     * RENAME_NOREPLACE becomes an existence test followed by a plain rename,
     * and RENAME_EXCHANGE a three-step rotation through a temporary name. */
    if (ret == -EINVAL && flags != 0) {
        if (flags & KBOX_RENAME_NOREPLACE_FLAG) {
            struct stat st;

            if (kbox_lkl_newfstatat(ctx->sysnrs, newdirfd, newtrans, &st, 0) ==
                0) {
                return kbox_dispatch_errno(EEXIST);
            }
            ret = kbox_lkl_renameat2(ctx->sysnrs, olddirfd, oldtrans, newdirfd,
                                     newtrans, 0);
        } else if (flags & KBOX_RENAME_EXCHANGE_FLAG) {
            char tmp[KBOX_MAX_PATH];
            int n = snprintf(tmp, sizeof(tmp), "%s.kboxxchg", newtrans);

            if (n > 0 && (size_t) n < sizeof(tmp)) {
                long r1 = kbox_lkl_renameat2(ctx->sysnrs, newdirfd, newtrans,
                                             newdirfd, tmp, 0);

                if (r1 >= 0) {
                    long r2 = kbox_lkl_renameat2(
                        ctx->sysnrs, olddirfd, oldtrans, newdirfd, newtrans, 0);

                    if (r2 < 0) {
                        (void) kbox_lkl_renameat2(ctx->sysnrs, newdirfd, tmp,
                                                  newdirfd, newtrans, 0);
                        ret = r2;
                    } else {
                        ret = kbox_lkl_renameat2(ctx->sysnrs, newdirfd, tmp,
                                                 olddirfd, oldtrans, 0);
                    }
                } else {
                    ret = r1;
                }
            }
        }
    }

    if (ret >= 0)
        invalidate_path_shadow_cache(ctx);
    else if (getenv("KBOX_TRACE"))
        fprintf(stderr, "kbox: renameat2(%s -> %s flags=%ld) = %ld (%s)\n",
                oldtrans, newtrans, flags, ret, strerror((int) -ret));
    return kbox_dispatch_from_lkl(ret);
}

static struct kbox_dispatch forward_renameat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx, 0);
}

static struct kbox_dispatch forward_renameat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return do_renameat(req, ctx,
                       to_c_long_arg(kbox_syscall_request_arg(req, 4)));
}

static long invoke_fchmodat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return kbox_lkl_fchmodat(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
}

static long host_invoke_fchmodat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    if (fchmodat((int) sv_dirfd, path, (mode_t) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_fchmodat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchmodat, host_invoke_fchmodat,
                                0);
}

/* fchmodat2 is fchmodat with the flags argument the three-argument form drops.
 *
 * musl's fchmodat(path, mode, AT_SYMLINK_NOFOLLOW) calls this number first and,
 * when it answers ENOSYS, falls back to opening the path and chmod-ing
 * /proc/self/fd/N. busybox tar sets every directory's mode that way right after
 * it creates the directory, so the fallback ran for each directory entry, the
 * magic link of a virtual descriptor could not be resolved, and tar reported
 * "Cannot change mode to rwxr-xr-x: No such file or directory" and exited
 * non-zero. The same archive extracted to a host-mounted volume succeeded,
 * because there the fallback path is a real host path.
 *
 * Linux 6.6 added the call; the LKL fork is 6.12 and implements it, so the
 * request is forwarded with the flags intact.
 */
static long invoke_fchmodat2(const struct kbox_syscall_request *req,
                             struct kbox_supervisor_ctx *ctx,
                             long lkl_dirfd,
                             const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    return kbox_lkl_fchmodat2(ctx->sysnrs, lkl_dirfd, translated, mode, flags);
}

static long host_invoke_fchmodat2(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx,
                                  long sv_dirfd,
                                  const char *path)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 2));
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));
    (void) ctx;
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif
    long ret = syscall(SYS_fchmodat2, (int) sv_dirfd, path, (mode_t) mode,
                       (int) flags);
    return ret < 0 ? -errno : ret;
}

static struct kbox_dispatch forward_fchmodat2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchmodat2,
                                host_invoke_fchmodat2, 0);
}

/* fchownat on a guest path, honouring the virtual-root identity.
 *
 * A virtual-root guest is entitled to change ownership, but LKL performs the
 * call with the supervisor's unprivileged credentials, so chown_common refuses
 * with EPERM before hostfs is reached and the owner never changes. Record the
 * intended owner against the guest file's (device, inode), which stat reports
 * and a rename keeps. apk sets the owner on every file it extracts, so without
 * this each transaction fails with "Failed to set ownership: Permission
 * denied"; chown(2) and fchownat(2) must behave the same way.
 */
static long virtual_fchownat(struct kbox_supervisor_ctx *ctx,
                             long lkl_dirfd,
                             const char *translated,
                             long owner,
                             long group,
                             long flags)
{
    long ret = kbox_lkl_fchownat(ctx->sysnrs, lkl_dirfd, translated, owner,
                                 group, flags);
    if (ret < 0 && getenv("KBOX_TRACE")) {
        static int fail_reported;

        if (fail_reported < 12) {
            fail_reported++;
            fprintf(stderr,
                    "kbox: chown FAILED path=%s dirfd=%ld owner=%ld group=%ld "
                    "ret=%ld root=%d\n",
                    translated, lkl_dirfd, owner, group, ret,
                    ctx->root_identity);
        }
    }

    /* Record the requested owner both when LKL refused (virtual-root fallback)
     * and when LKL succeeded (e.g. chown to the supervisor's own uid/gid):
     * otherwise a prior overlay entry stays stale, or stat() remaps the
     * supervisor uid back to guest root (row 38). */
    if ((ret == 0 || ret == -EPERM || ret == -EACCES) && ctx->root_identity &&
        (owner != -1 || group != -1)) {
        struct kbox_lkl_stat kst;
        int open_flags =
            O_PATH | ((flags & AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0);
        long fd =
            kbox_lkl_openat(ctx->sysnrs, lkl_dirfd, translated, open_flags, 0);

        if (fd < 0)
            fd = kbox_lkl_openat(
                ctx->sysnrs, lkl_dirfd, translated,
                O_RDONLY | ((flags & AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0), 0);

        if (fd >= 0) {
            if (kbox_lkl_fstat(ctx->sysnrs, fd, &kst) >= 0) {
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
                (void) kbox_lkl_close(ctx->sysnrs, fd);
                if (getenv("KBOX_TRACE"))
                    fprintf(stderr,
                            "kbox: chown %s virtual, owner=%lld group=%lld\n",
                            translated, (long long) eff_uid,
                            (long long) eff_gid);
                return 0;
            }
            (void) kbox_lkl_close(ctx->sysnrs, fd);
        }
    }
    return ret;
}

static long invoke_fchownat(const struct kbox_syscall_request *req,
                            struct kbox_supervisor_ctx *ctx,
                            long lkl_dirfd,
                            const char *translated)
{
    long owner = (int32_t) kbox_syscall_request_arg(req, 2);
    long group = (int32_t) kbox_syscall_request_arg(req, 3);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));

    return virtual_fchownat(ctx, lkl_dirfd, translated, owner, group, flags);
}

/* chown on a host path. The host kernel refuses ownership changes (kbox runs
 * unprivileged), so a virtual-root guest's request is recorded in the ownership
 * overlay and reported back by stat, which is what the image entrypoints that
 * chown a data directory and then drop privileges check. When fchownat
 * succeeds directly (for example chown to the supervisor's own uid/gid), the
 * overlay and user.kbox.owner xattr must still be updated so an earlier
 * virtual owner does not stay stuck (row 38). */
static long host_chown_virtual(struct kbox_supervisor_ctx *ctx,
                               pid_t pid,
                               int dirfd,
                               const char *path,
                               long owner,
                               long group,
                               int flags)
{
    struct stat st;
    int nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
    int err;

    if (fchownat(dirfd, path, (uid_t) owner, (gid_t) group, flags) == 0) {
        if (ctx->root_identity && (owner != -1 || group != -1) &&
            fstatat(dirfd, path, &st, flags & AT_SYMLINK_NOFOLLOW) == 0) {
            kbox_owner_record_host(pid, dirfd, path, nofollow, &st, owner,
                                   group);
        }
        return 0;
    }
    err = errno;
    if (err == EPERM && ctx->root_identity) {
        struct kbox_vcred c;
        kbox_vcred_get(pid, &c);
        if (c.euid != 0)
            return -EPERM;
        if (fstatat(dirfd, path, &st, flags & AT_SYMLINK_NOFOLLOW) == 0) {
            kbox_owner_record_host(pid, dirfd, path, nofollow, &st, owner,
                                   group);
            return 0;
        }
        err = errno;
    }
    return -err;
}

static long host_invoke_fchownat(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 long sv_dirfd,
                                 const char *path)
{
    long owner = (int32_t) kbox_syscall_request_arg(req, 2);
    long group = (int32_t) kbox_syscall_request_arg(req, 3);
    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
    return host_chown_virtual(ctx, kbox_syscall_request_pid(req),
                              (int) sv_dirfd, path, owner, group, (int) flags);
}

static struct kbox_dispatch forward_fchownat(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_at_path_call(req, ctx, invoke_fchownat, host_invoke_fchownat,
                                0);
}

/* forward_mount. */

static struct kbox_dispatch forward_mount(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char srcbuf[KBOX_MAX_PATH];
    char tgtbuf[KBOX_MAX_PATH];
    char fsbuf[KBOX_MAX_PATH];
    char databuf[KBOX_MAX_PATH];
    int rc;

    const char *source = NULL;
    if (kbox_syscall_request_arg(req, 0) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                                   srcbuf, sizeof(srcbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        source = srcbuf;
    }

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 1),
                               tgtbuf, sizeof(tgtbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    const char *fstype = NULL;
    if (kbox_syscall_request_arg(req, 2) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 2),
                                   fsbuf, sizeof(fsbuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        fstype = fsbuf;
    }

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 3));

    const void *data = NULL;
    if (kbox_syscall_request_arg(req, 4) != 0) {
        rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 4),
                                   databuf, sizeof(databuf));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        data = databuf;
    }

    /* Translate paths through normalization and host-root confinement. */
    char translated_tgt[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, tgtbuf, ctx->host_root,
                                     translated_tgt, sizeof(translated_tgt));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Translate the source for bind mounts (MS_BIND uses a path, not a
     * device).  Non-bind sources (device names, "none") pass through
     * unmodified.
     */
    char translated_src[KBOX_MAX_PATH];
    const char *effective_src = source;
    if (source && (flags & 0x1000 /* MS_BIND */)) {
        rc =
            kbox_translate_path_for_lkl(pid, srcbuf, ctx->host_root,
                                        translated_src, sizeof(translated_src));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);
        effective_src = translated_src;
    }

    long ret = kbox_lkl_mount(ctx->sysnrs, effective_src, translated_tgt,
                              fstype, flags, data);
    return kbox_dispatch_from_lkl(ret);
}

/* forward_umount2. */

static struct kbox_dispatch forward_umount2(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    pid_t pid = kbox_syscall_request_pid(req);
    char pathbuf[KBOX_MAX_PATH];
    int rc;

    rc = guest_mem_read_string(ctx, pid, kbox_syscall_request_arg(req, 0),
                               pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    char translated[KBOX_MAX_PATH];
    rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root, translated,
                                     sizeof(translated));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long flags = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    long ret = kbox_lkl_umount2(ctx->sysnrs, translated, flags);
    return kbox_dispatch_from_lkl(ret);
}

/* Legacy x86_64 syscall forwarders (stat, lstat, access, etc.). */

static struct kbox_dispatch forward_stat_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int nofollow)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    uint64_t remote_stat = kbox_syscall_request_arg(req, 1);
    if (remote_stat == 0)
        return kbox_dispatch_errno(EFAULT);

    /* Host bind or virtual path: call host fstatat with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 0, translated)) {
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        int stat_flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;
        struct stat host_stat;
        if (fstatat(AT_FDCWD, sv_path, &host_stat, stat_flags) < 0)
            return kbox_dispatch_errno(errno);
        apply_virtual_owner(ctx, pid, &host_stat, AT_FDCWD, sv_path,
                            (stat_flags & AT_SYMLINK_NOFOLLOW));
        normalize_host_stat_if_needed(ctx, translated, &host_stat);
        int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat,
                                                 &host_stat, sizeof(host_stat));
        if (wrc < 0)
            return kbox_dispatch_errno(-wrc);
        return kbox_dispatch_value(0);
    }

    if (translated[0] != '\0' &&
        try_cached_shadow_stat_dispatch(ctx, translated, remote_stat, pid)) {
        return kbox_dispatch_value(0);
    }

    long flags = nofollow ? AT_SYMLINK_NOFOLLOW : 0;

    struct kbox_lkl_stat kst;
    memset(&kst, 0, sizeof(kst));
    long ret = kbox_lkl_newfstatat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                   &kst, flags);
    if (ret < 0)
        return kbox_dispatch_errno((int) (-ret));

    struct stat host_stat;
    kbox_lkl_stat_to_host(&kst, &host_stat);
    if (ctx->root_identity)
        (void) kbox_owner_apply_overlay(&host_stat);
    apply_writeback_shadow_stat(ctx, &kst, &host_stat);
    normalize_host_stat_if_needed(ctx, translated, &host_stat);

    int wrc = guest_mem_write_small_metadata(ctx, pid, remote_stat, &host_stat,
                                             sizeof(host_stat));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);

    return kbox_dispatch_value(0);
}

/* Shared skeleton for legacy (non-*at) path syscalls: translate a single
 * path from arg[0], then delegate to a callback for the LKL call.
 */

typedef long (*legacy_path_invoke_fn)(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *translated);

static long invoke_access_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated);

static struct kbox_dispatch forward_legacy_path_call(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    legacy_path_invoke_fn invoke,
    legacy_path_invoke_fn host_invoke)
{
    char translated[KBOX_MAX_PATH];
    pid_t pid = kbox_syscall_request_pid(req);
    long lkl_dirfd = AT_FDCWD_LINUX;
    int rc = translate_request_path_or_bind(req, ctx, 0, translated,
                                            sizeof(translated), &lkl_dirfd);
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    /* Host bind or virtual path: call host syscall with a local path copy. */
    if (should_continue_for_dirfd(lkl_dirfd) ||
        should_continue_virtual_path(ctx, req, 0, translated)) {
        if (lkl_dirfd == KBOX_LKL_DIRFD_HOST_BIND_RO &&
            invoke != invoke_access_legacy)
            return kbox_dispatch_errno(EROFS);
        if (!host_invoke)
            return kbox_dispatch_errno(ENOENT);
        char sv_path[KBOX_MAX_PATH];
        translate_proc_self(translated, pid, sv_path, sizeof(sv_path));
        long ret = host_invoke(req, ctx, sv_path);
        if (ret < 0)
            return kbox_dispatch_errno((int) (-ret));
        return kbox_dispatch_value(ret);
    }
    return kbox_dispatch_from_lkl(invoke(req, ctx, translated));
}

static long invoke_access_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_faccessat2(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode,
                               0);
}

static long host_invoke_access_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (faccessat(AT_FDCWD, path, (int) mode, 0) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_access_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_access_legacy,
                                    host_invoke_access_legacy);
}

static long invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_mkdir(ctx->sysnrs, translated, (int) mode);
}

static long host_invoke_mkdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (mkdir(path, (mode_t) mode) < 0)
        return -errno;
    unsigned umask_val = (ctx && ctx->active_proc)
                             ? ctx->active_proc->umask
                             : (ctx ? ctx->guest_umask : 022);
    mode_t want = (mode_t) ((unsigned) mode & ~umask_val & 07777U);
    (void) chmod(path, want);
    return 0;
}

static struct kbox_dispatch forward_mkdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_mkdir_legacy,
                                    host_invoke_mkdir_legacy);
}

static long invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                 struct kbox_supervisor_ctx *ctx,
                                 const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated, 0);
}

static long host_invoke_unlink_legacy(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx,
                                      const char *path)
{
    (void) req;
    (void) ctx;
    if (unlink(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_unlink_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_unlink_legacy,
                                    host_invoke_unlink_legacy);
}

static long invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    (void) req;
    return kbox_lkl_unlinkat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                             AT_REMOVEDIR);
}

static long host_invoke_rmdir_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) req;
    (void) ctx;
    if (rmdir(path) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_rmdir_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_rmdir_legacy,
                                    host_invoke_rmdir_legacy);
}

static struct kbox_dispatch forward_rename_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    char oldtrans[KBOX_MAX_PATH];
    char newtrans[KBOX_MAX_PATH];
    int rc = translate_request_path(req, ctx, 0, ctx->host_root, oldtrans,
                                    sizeof(oldtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    rc = translate_request_path(req, ctx, 1, ctx->host_root, newtrans,
                                sizeof(newtrans));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);

    long ret = kbox_lkl_renameat2(ctx->sysnrs, AT_FDCWD_LINUX, oldtrans,
                                  AT_FDCWD_LINUX, newtrans, 0);
    return kbox_dispatch_from_lkl(ret);
}

static long invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    return kbox_lkl_fchmodat(ctx->sysnrs, AT_FDCWD_LINUX, translated, mode, 0);
}

static long host_invoke_chmod_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    (void) ctx;
    long mode = to_c_long_arg(kbox_syscall_request_arg(req, 1));
    if (chmod(path, (mode_t) mode) < 0)
        return -errno;
    return 0;
}

static struct kbox_dispatch forward_chmod_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chmod_legacy,
                                    host_invoke_chmod_legacy);
}

static long invoke_chown_legacy(const struct kbox_syscall_request *req,
                                struct kbox_supervisor_ctx *ctx,
                                const char *translated)
{
    long owner = (int32_t) kbox_syscall_request_arg(req, 1);
    long group = (int32_t) kbox_syscall_request_arg(req, 2);

    return virtual_fchownat(ctx, AT_FDCWD_LINUX, translated, owner, group, 0);
}

static long host_invoke_chown_legacy(const struct kbox_syscall_request *req,
                                     struct kbox_supervisor_ctx *ctx,
                                     const char *path)
{
    long owner = (int32_t) kbox_syscall_request_arg(req, 1);
    long group = (int32_t) kbox_syscall_request_arg(req, 2);
    return host_chown_virtual(ctx, kbox_syscall_request_pid(req), AT_FDCWD,
                              path, owner, group, 0);
}

static struct kbox_dispatch forward_chown_legacy(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    return forward_legacy_path_call(req, ctx, invoke_chown_legacy,
                                    host_invoke_chown_legacy);
}

/* Syscall dispatch tables.
 *
 * X-macros eliminate the repetitive if-chains for the two most common dispatch
 * patterns. Each _(field, handler) entry expands to
 *   if (nr == h->field) return handler(req, ctx);
 *
 * Complex cases (extra args, guards, inline logic) remain as explicit if-blocks
 * after the table expansions.
 */

/* DISPATCH_FORWARD: forwarded to a handler that takes (req, ctx). */
#define DISPATCH_FORWARD_TABLE(_)                                             \
    /* Legacy x86_64 syscalls. */                                             \
    _(access, forward_access_legacy)                                          \
    _(mkdir, forward_mkdir_legacy)                                            \
    _(rmdir, forward_rmdir_legacy)                                            \
    _(unlink, forward_unlink_legacy)                                          \
    _(rename, forward_rename_legacy)                                          \
    _(chmod, forward_chmod_legacy)                                            \
    _(chown, forward_chown_legacy)                                            \
    _(open, forward_open_legacy)                                              \
    /* File open/create. */                                                   \
    _(openat, forward_openat)                                                 \
    _(openat2, forward_openat2)                                               \
    /* Metadata. */                                                           \
    _(fstat, forward_fstat)                                                   \
    _(newfstatat, forward_newfstatat)                                         \
    _(statx, forward_statx)                                                   \
    _(faccessat2, forward_faccessat2)                                         \
    /* Directories. */                                                        \
    _(getdents64, forward_getdents64)                                         \
    _(getdents, forward_getdents)                                             \
    _(mknodat, forward_mknodat)                                               \
    _(mkdirat, forward_mkdirat)                                               \
    _(unlinkat, forward_unlinkat)                                             \
    _(renameat2, forward_renameat2)                                           \
    _(fchmodat, forward_fchmodat)                                             \
    _(fchmodat2, forward_fchmodat2)                                           \
    _(fchownat, forward_fchownat)                                             \
    /* Navigation. */                                                         \
    _(chdir, forward_chdir)                                                   \
    _(fchdir, forward_fchdir)                                                 \
    _(getcwd, forward_getcwd)                                                 \
    /* Mount. */                                                              \
    _(mount, forward_mount)                                                   \
    _(umount2, forward_umount2)                                               \
    /* FD operations. */                                                      \
    _(close, forward_close)                                                   \
    _(fcntl, forward_fcntl)                                                   \
    _(dup, forward_dup)                                                       \
    _(dup2, forward_dup2)                                                     \
    _(dup3, forward_dup3)                                                     \
    _(exit_group, forward_exit_group)                                         \
    /* I/O. */                                                                \
    _(write, forward_write)                                                   \
    _(lseek, forward_lseek)                                                   \
    /* Networking. */                                                         \
    _(socket, forward_socket)                                                 \
    _(bind, forward_bind)                                                     \
    _(listen, forward_listen)                                                 \
    _(accept, forward_accept)                                                 \
    _(accept4, forward_accept4)                                               \
    _(connect, forward_connect)                                               \
    _(sendto, forward_sendto)                                                 \
    _(sendmmsg, forward_sendmmsg)                                             \
    _(recvfrom, forward_recvfrom)                                             \
    _(recvmsg, forward_recvmsg)                                               \
    _(sendmsg, forward_sendmsg)                                               \
    _(getsockopt, forward_getsockopt)                                         \
    _(setsockopt, forward_setsockopt)                                         \
    _(getsockname, forward_getsockname)                                       \
    _(getpeername, forward_getpeername)                                       \
    _(shutdown, forward_shutdown)                                             \
    /* I/O extended. */                                                       \
    _(pwrite64, forward_pwrite64)                                             \
    _(pwritev, forward_pwritev)                                               \
    _(preadv, forward_preadv)                                                 \
    _(pwritev2, forward_pwritev2)                                             \
    _(preadv2, forward_preadv2)                                               \
    _(writev, forward_writev)                                                 \
    _(readv, forward_readv)                                                   \
    _(ftruncate, forward_ftruncate)                                           \
    _(fallocate, forward_fallocate)                                           \
    _(flock, forward_flock)                                                   \
    _(fchmod, forward_fchmod)                                                 \
    _(fchown, forward_fchown)                                                 \
    _(fadvise64, forward_fadvise64)                                           \
    _(fsync, forward_fsync)                                                   \
    _(fdatasync, forward_fdatasync)                                           \
    _(sync, forward_sync)                                                     \
    _(sync_file_range, forward_sync_file_range)                               \
    _(ioctl, forward_ioctl)                                                   \
    /* File operations. */                                                    \
    _(readlinkat, forward_readlinkat)                                         \
    _(pipe2, forward_pipe2)                                                   \
    _(socketpair, forward_socketpair)                                         \
    _(getxattr, forward_xattr_nodata)                                         \
    _(lgetxattr, forward_xattr_nodata)                                        \
    _(fgetxattr, forward_xattr_nodata)                                        \
    _(listxattr, forward_listxattr)                                           \
    _(llistxattr, forward_llistxattr)                                         \
    _(flistxattr, forward_flistxattr)                                         \
    _(symlinkat, forward_symlinkat)                                           \
    _(linkat, forward_linkat)                                                 \
    _(utimensat, forward_utimensat)                                           \
    _(sendfile, forward_sendfile)                                             \
    /* Time. */                                                               \
    _(clock_gettime, forward_clock_gettime)                                   \
    _(clock_getres, forward_clock_getres)                                     \
    _(gettimeofday, forward_gettimeofday)                                     \
    /* Process lifecycle. */                                                  \
    _(umask, forward_umask)                                                   \
    _(uname, forward_uname)                                                   \
    _(getrandom, forward_getrandom)                                           \
    _(syslog, forward_syslog)                                                 \
    _(prctl, forward_prctl)                                                   \
    _(capget, forward_capget)                                                 \
    _(capset, forward_capset)                                                 \
    /* Threading. */                                                          \
    _(clone3, forward_clone3)                                                 \
    /* FD-creating syscalls tracked as host-passthrough. */                   \
    _(eventfd2, forward_eventfd)                                              \
    _(memfd_create, forward_memfd_create)                                     \
    _(timerfd_create, forward_timerfd_create)                                 \
    _(signalfd4, forward_signalfd4)                                           \
    _(epoll_create1, forward_epoll_create1)                                   \
    /* FD-consuming syscalls gated by deny check (were in CONTINUE table). */ \
    _(epoll_ctl, forward_epoll_ctl_gated)                                     \
    _(epoll_wait, forward_fd_gated_continue)                                  \
    _(epoll_pwait, forward_fd_gated_continue)                                 \
    _(poll, forward_readiness_gated)                                          \
    _(ppoll, forward_readiness_gated)                                         \
    _(pselect6, forward_readiness_gated)                                      \
    _(timerfd_settime, forward_fd_gated_continue)                             \
    _(timerfd_gettime, forward_fd_gated_continue)                             \
    _(statfs, forward_statfs)                                                 \
    _(fstatfs, forward_fstatfs)

/* DISPATCH_CONTINUE: host kernel handles directly, no LKL involvement.
 * Only non-FD syscalls remain here; FD-based syscalls are in the handler
 * table so their FD arguments can be validated.
 */
/* clang-format off */
#define DISPATCH_CONTINUE_TABLE(_)                                             \
    _(setpgid) _(getpgid) _(getsid) _(setsid) _(brk) _(wait4) _(waitid)        \
    _(exit) _(rt_sigreturn) _(rt_sigaltstack) _(rt_sigsuspend)                 \
    _(setitimer)                                                               \
    _(getitimer) _(set_tid_address) _(set_robust_list) _(get_robust_list) _(futex) _(rseq)        \
    _(membarrier) _(madvise) _(getrusage)                         \
    /* Scheduling. */                                                          \
    _(sched_yield) _(sched_setparam) _(sched_getparam) _(sched_setscheduler)   \
    _(sched_getscheduler) _(sched_get_priority_max) _(sched_get_priority_min)  \
    _(sched_setaffinity) _(sched_getaffinity)                                  \
    /* I/O multiplexing lives in DISPATCH_FORWARD_TABLE so the bridge can be
     * made current before the kernel measures readiness. */                  \
    /* Sleep. */                                                               \
    _(nanosleep) _(clock_nanosleep)                                            \
    /* POSIX per-process timers. */                                            \
    _(timer_create) _(timer_gettime) _(timer_getoverrun) _(timer_settime)      \
    _(timer_delete)                                                            \
    /* System info (path/FD statfs handled in DISPATCH_FORWARD_TABLE). */      \
    _(sysinfo) _(getcpu)
/* clang-format on */

static int is_guest_process_pid(struct kbox_supervisor_ctx *ctx,
                                pid_t caller_tid,
                                pid_t target)
{
    if (target == 1 || target == caller_tid ||
        (ctx && target == ctx->child_pid))
        return 1;
    if (!ctx || target <= 1 || ctx->child_pid <= 0)
        return 0;

    pid_t tgid = 0;
    pid_t ppid = -1;
    if (read_proc_tgid_ppid(target, &tgid, &ppid, NULL) < 0)
        return 0;
    if (tgid == ctx->child_pid || tgid == caller_tid ||
        (tgid > 0 && find_proc_fd_entry(ctx, tgid) != NULL))
        return 1;

    pid_t walk = ppid;
    for (int hop = 0; hop < 32 && walk > 1; hop++) {
        if (walk == ctx->child_pid || walk == caller_tid ||
            find_proc_fd_entry(ctx, walk) != NULL)
            return 1;
        pid_t next_ppid = -1;
        if (read_proc_tgid_ppid(walk, NULL, &next_ppid, NULL) < 0)
            break;
        if (next_ppid == walk)
            break;
        walk = next_ppid;
    }
    return 0;
}

/* Verbose-only: remember every pid that issued a syscall and, at most every
 * 100 ms, report the exit status of those that became zombies. A tracee that
 * dies by signal never reaches exit_group, so this is the only way to see it.
 */
#define VMON_MAX 512
static void verbose_monitor_pids(pid_t seen)
{
    static pid_t pids[VMON_MAX];
    static unsigned char done[VMON_MAX];
    static int npids;
    static struct timespec last;
    struct timespec now;
    int i;

    for (i = 0; i < npids; i++)
        if (pids[i] == seen)
            break;
    if (i == npids && npids < VMON_MAX)
        pids[npids++] = seen;

    clock_gettime(CLOCK_MONOTONIC, &now);
    if ((now.tv_sec - last.tv_sec) * 1000 +
            (now.tv_nsec - last.tv_nsec) / 1000000 <
        100)
        return;
    last = now;
    for (i = 0; i < npids; i++) {
        char path[48], buf[1024];
        FILE *f;
        if (done[i])
            continue;
        snprintf(path, sizeof(path), "/proc/%d/stat", (int) pids[i]);
        f = fopen(path, "r");
        if (!f) {
            done[i] = 1;
            continue;
        }
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = 0;
        char *rp = strrchr(buf, ')');
        if (rp && rp[1] == ' ' && rp[2] == 'Z') {
            /* field 52 of stat is exit_code (wait status). */
            char *t = rp + 2;
            int field = 3;
            while (field < 52 && (t = strchr(t, ' ')) != NULL) {
                t++;
                field++;
            }
            fprintf(stderr, "kbox: pid=%d zombie, wait status=%s\n",
                    (int) pids[i], t ? t : "?");
            done[i] = 1;
        }
    }
}

__thread pid_t kbox_cur_tracee_pid;

int kbox_fd_adopt_host_object(struct kbox_fd_table *t, pid_t pid, long fd)
{
    char link[64], target[128];

    if (pid <= 0)
        return 0;
    snprintf(link, sizeof(link), "/proc/%d/fd/%ld", (int) pid, fd);
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return 0;
    target[n] = '\0';
    if (strncmp(target, "socket:", 7) != 0 &&
        strncmp(target, "pipe:", 5) != 0 &&
        strncmp(target, "anon_inode:", 11) != 0 &&
        strncmp(target, "/memfd:", 7) != 0)
        return 0;
    track_host_passthrough_fd(t, (int) fd);
    return 1;
}

static struct kbox_dispatch dispatch_request_impl(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h;
    int nr;

    if (!ctx || !req)
        return kbox_dispatch_errno(EINVAL);
    h = ctx->host_nrs;
    kbox_cur_tracee_pid = kbox_syscall_request_pid(req);

    /* A vfork parent is suspended until its child execs, so its first syscall
     * afterwards is the moment the exec rewrite can be undone. Doing it here,
     * rather than from a watcher thread guessing when the exec landed, means
     * the bytes are never restored while the kernel has yet to read them. */
    /* The guest-memory writers act on the active guest, which is the process
     * making this request, so the context must be set before any restore. */
    kbox_dispatch_prepare_request_ctx(ctx, req);

    /* Low descriptors are created and closed by the kernel now (item 33), so
     * an entry left by a close is checked against the descriptor the tracee
     * really holds before this call routes anything through it. */
    validate_low_fd_routing(ctx, req);
    for (size_t i = 0;
         i < sizeof(ctx->vfork_pending) / sizeof(ctx->vfork_pending[0]); i++) {
        struct kbox_vfork_pending *slot = &ctx->vfork_pending[i];

        if (slot->nregions <= 0)
            continue;
        if (slot->parent != (pid_t) kbox_syscall_request_pid(req))
            continue;
        for (int r = 0; r < slot->nregions; r++) {
            /* The rewritten bytes are often a string literal in a read-only
             * page (static binaries keep the "/bin/sh" given to posix_spawn
             * in .rodata), so fall back to the forced write the rewrite
             * itself used. Every region the exec path touched is restored,
             * not just the pathname: the argv/envp pointer slots are the
             * parent's own and point below its stack after relocation.
             */
            if (guest_mem_write(ctx, slot->parent, slot->reg[r].addr,
                                slot->reg[r].saved, slot->reg[r].len) < 0 &&
                guest_mem_write_force(ctx, slot->parent, slot->reg[r].addr,
                                      slot->reg[r].saved,
                                      slot->reg[r].len) < 0 &&
                ctx->verbose)
                fprintf(stderr,
                        "kbox: exec: vfork parent %d restore failed at "
                        "0x%llx\n",
                        (int) slot->parent,
                        (unsigned long long) slot->reg[r].addr);
            free(slot->reg[r].saved);
            slot->reg[r].saved = NULL;
        }
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec: vfork parent %d restored %d region(s) on "
                    "syscall nr=%d\n",
                    (int) slot->parent, slot->nregions, (int) req->nr);
        slot->nregions = 0;
        slot->parent = 0;
    }

    nr = req->nr;
    if (ctx->verbose)
        verbose_monitor_pids((pid_t) kbox_syscall_request_pid(req));

    if (ctx->verbose) {
        const char *name = syscall_name_from_nr(h, nr);
        fprintf(stderr,
                "%s syscall: pid=%u nr=%d (%s) a0=%lld a1=%lld a2=%lld\n",
                req->source == KBOX_SYSCALL_SOURCE_SECCOMP ? "seccomp notify"
                                                           : "in-process",
                kbox_syscall_request_pid(req), nr, name ? name : "unknown",
                (long long) kbox_syscall_request_arg(req, 0),
                (long long) kbox_syscall_request_arg(req, 1),
                (long long) kbox_syscall_request_arg(req, 2));
        if (nr == h->openat || nr == h->newfstatat || nr == h->faccessat ||
            nr == h->readlinkat) {
            char vp[256];
            if (guest_mem_read_string(ctx, kbox_syscall_request_pid(req),
                                      kbox_syscall_request_arg(req, 1), vp,
                                      sizeof(vp)) >= 0)
                fprintf(stderr, "kbox:   path=%s\n", vp);
        }
    }

    /* exit_group is notified (not BPF-allowed) so verbose mode can show how a
     * process ended; the host kernel still performs the exit. The notify
     * round-trip is also the last chance to copy writable shadows back to the
     * LKL files, because a process exit closes its descriptors without a
     * close(2) call. */
    /* wait4/waitid: a parent reaping a child is the moment kbox learns that a
     * guest process is gone. A process that dies by signal never reaches
     * exit_group, so its writable shadows were never copied back; the parent
     * typically reads the very file the dead child was writing (faulthandler's
     * crash tests do exactly that). The copy is idempotent, so flushing every
     * pending shadow here is safe, and it keeps the entry registered for the
     * process that is still alive.
     */
    if (nr == h->wait4 || nr == h->waitid) {
        sync_all_writeback_shadows(ctx, 0);
        /* The reaped child's own table is not ctx->fd_table here: the caller is
         * the parent. Reap the dead entries so their shadows are copied back
         * before the table is freed. A blocking wait4 is notified on entry,
         * while the child may still be alive, so arm a deferred reap as well:
         * the parent's next syscall (usually the stat/open/read of the file
         * the dead child was writing) flushes it. */
        reap_dead_proc_fds(ctx);
        ctx->pending_reap = 1;
        return kbox_dispatch_continue();
    }

    if (nr == h->exit_group || nr == h->exit) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: %s pid=%u code=%lld\n",
                    nr == h->exit_group ? "exit_group" : "exit",
                    kbox_syscall_request_pid(req),
                    (long long) kbox_syscall_request_arg(req, 0));
        /* exit_group tears the whole process down, and that closes every
         * descriptor without a close(2) call, so the shadows are flushed and
         * forgotten. Plain exit(2) is what a worker thread calls: the process
         * keeps its descriptors, so its shadows must keep their registration.
         * Deregistering here lost every buffered write of a threaded writer --
         * the first thread to finish wiped the entry, and the close that
         * followed had nothing to copy back (test_io.test_threads_write).
         */
        sync_all_writeback_shadows(ctx, nr == h->exit_group);
        return kbox_dispatch_continue();
    }

    /* Syscalls kbox does not model in the arch tables. */
    if (nr == __NR_sched_rr_get_interval)
        return kbox_dispatch_continue();
    if (nr == __NR_truncate)
        return forward_truncate(req, ctx);
    if (nr == __NR_preadv2)
        return forward_preadv2(req, ctx);
    if (nr == __NR_pwritev2)
        return forward_pwritev2(req, ctx);

    /* Table-driven dispatch: forward to handler. */

#define _(field, handler) \
    if (nr == h->field)   \
        return handler(req, ctx);
    DISPATCH_FORWARD_TABLE(_)
#undef _

    /* Table-driven dispatch: CONTINUE to host kernel. */

#define _(field)        \
    if (nr == h->field) \
        return kbox_dispatch_continue();
    DISPATCH_CONTINUE_TABLE(_)
#undef _

    /* Entries with extra arguments or guards. */

    if (nr == h->stat)
        return forward_stat_legacy(req, ctx, 0);
    if (nr == h->lstat)
        return forward_stat_legacy(req, ctx, 1);
    if (nr == h->read)
        return forward_read_like(req, ctx, 0);
    if (nr == h->pread64)
        return forward_read_like(req, ctx, 1);
    if (nr == h->faccessat && h->faccessat > 0)
        return forward_faccessat(req, ctx);
    if (nr == h->renameat && h->renameat > 0)
        return forward_renameat(req, ctx);
    if (nr == h->copy_file_range)
        return kbox_dispatch_errno(ENOSYS);
    /* msync had no dispatch entry at all, so the deny-unknown tail answered
     * ENOSYS. Kafka's KRaft log -- and anything else that fsyncs a mapping --
     * then failed with "Function not implemented (msync with parameter MS_SYNC
     * failed)" and shut the broker down. The mapping belongs to LKL, so LKL has
     * to be the one to write it back.
     */
    if (ctx->verbose && (nr == 26 || nr == 227))
        fprintf(stderr, "kbox: msync seen nr=%d table_msync=%d\n", nr,
                h->msync);

    if (nr == h->msync || ((h->msync <= 0) && (nr == 26 || nr == 227))) {
        /* The mapping lives in the tracee's own address space: file mappings
         * are served from host shadows, so the kernel that has to write the
         * pages back is the host one. Asking LKL about that address answers
         * EINVAL/ENOSYS because it never mapped it. */
        return kbox_dispatch_continue();
    }
    if (nr == h->execve || nr == h->execveat) {
        if (ctx->proc_fd_count > 1)
            reap_dead_proc_fds(ctx);
        return forward_execve(req, ctx, nr == h->execveat);
    }

    /* Process info: in seccomp-notify mode, return real host PIDs/TIDs so
     * /proc/self/task entries, PID files, and kernel si_pid on tgkill match
     * getpid()/gettid() (e.g. glibc nptl_setxid). Trap/rewrite modes keep
     * constant virtualization.
     */

    /* SysV IPC lives in the pod's IPC namespace and its segments are mapped
     * into the tracee's own address space, so the host kernel has to be the
     * one handling these. Left to the default they were refused with ENOSYS,
     * and postgres died in bootstrap: its shared memory is shmget(posix is
     * only chosen when sysv is unavailable, which is never on a real host).
     */
    if (nr == h->shmget || nr == h->shmat || nr == h->shmdt ||
        nr == h->semget || nr == h->semop || nr == h->semtimedop ||
        nr == h->msgget || nr == h->msgsnd || nr == h->msgrcv)
        return kbox_dispatch_continue();

    if (nr == h->msgctl) {
        int qid = (int) kbox_syscall_request_arg(req, 0);
        int cmd = (int) kbox_syscall_request_arg(req, 1);
        uint64_t buf_ptr = kbox_syscall_request_arg(req, 2);
        if ((cmd & ~0x100) == IPC_STAT || cmd == MSG_STAT ||
            cmd == MSG_STAT_ANY) {
            struct msqid_ds ds;
            int ret = msgctl(qid, cmd, &ds);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (ds.msg_perm.uid == geteuid())
                ds.msg_perm.uid = 0;
            if (ds.msg_perm.cuid == geteuid())
                ds.msg_perm.cuid = 0;
            if (ds.msg_perm.gid == getegid())
                ds.msg_perm.gid = 0;
            if (ds.msg_perm.cgid == getegid())
                ds.msg_perm.cgid = 0;
            if (guest_mem_write(ctx, kbox_syscall_request_pid(req), buf_ptr,
                                &ds, sizeof(ds)) < 0)
                return kbox_dispatch_errno(EFAULT);
            return kbox_dispatch_value(ret);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->semctl) {
        int semid = (int) kbox_syscall_request_arg(req, 0);
        int semnum = (int) kbox_syscall_request_arg(req, 1);
        int cmd = (int) kbox_syscall_request_arg(req, 2);
        uint64_t arg4 = kbox_syscall_request_arg(req, 3);
        if ((cmd & ~0x100) == IPC_STAT || cmd == SEM_STAT ||
            cmd == SEM_STAT_ANY) {
            struct semid_ds sds;
            union kbox_semun u;
            u.buf = &sds;
            int ret = semctl(semid, semnum, cmd, u);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (sds.sem_perm.uid == geteuid())
                sds.sem_perm.uid = 0;
            if (sds.sem_perm.cuid == geteuid())
                sds.sem_perm.cuid = 0;
            if (sds.sem_perm.gid == getegid())
                sds.sem_perm.gid = 0;
            if (sds.sem_perm.cgid == getegid())
                sds.sem_perm.cgid = 0;
            if (guest_mem_write(ctx, kbox_syscall_request_pid(req), arg4, &sds,
                                sizeof(sds)) < 0)
                return kbox_dispatch_errno(EFAULT);
            return kbox_dispatch_value(ret);
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->shmctl) {
        int shmid = (int) kbox_syscall_request_arg(req, 0);
        int cmd = (int) kbox_syscall_request_arg(req, 1);
        uint64_t buf_ptr = kbox_syscall_request_arg(req, 2);
        if ((cmd & ~0x100) == IPC_STAT || cmd == SHM_STAT ||
            cmd == SHM_STAT_ANY) {
            struct shmid_ds shds;
            int ret = shmctl(shmid, cmd, &shds);
            if (ret < 0)
                return kbox_dispatch_errno(errno);
            if (shds.shm_perm.uid == geteuid())
                shds.shm_perm.uid = 0;
            if (shds.shm_perm.cuid == geteuid())
                shds.shm_perm.cuid = 0;
            if (shds.shm_perm.gid == getegid())
                shds.shm_perm.gid = 0;
            if (shds.shm_perm.cgid == getegid())
                shds.shm_perm.cgid = 0;
            if (guest_mem_write(ctx, kbox_syscall_request_pid(req), buf_ptr,
                                &shds, sizeof(shds)) < 0)
                return kbox_dispatch_errno(EFAULT);
            return kbox_dispatch_value(ret);
        }
        return kbox_dispatch_continue();
    }

    /* setpriority only touches the tracee's own scheduler state; left to the
     * default it was refused with ENOSYS and Chromium logged it per thread.
     */
    if (nr == h->setpriority || nr == h->getpriority)
        return kbox_dispatch_continue();

    if (nr == h->getpid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(1);
    }
    if (nr == h->getppid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP &&
            kbox_syscall_request_pid(req) != ctx->child_pid)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(0);
    }
    if (nr == h->gettid) {
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        return kbox_dispatch_value(1);
    }

    /* root_identity containers get per-process virtual credentials. */
    if (ctx->root_identity) {
        struct kbox_dispatch vd;
        if (dispatch_vcred_identity(req, ctx, &vd))
            return vd;
    }

    /* Identity: UID. */

    if (nr == h->getuid)
        return dispatch_get_uid(kbox_lkl_getuid, ctx);
    if (nr == h->geteuid)
        return dispatch_get_uid(kbox_lkl_geteuid, ctx);
    if (nr == h->getresuid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresuid_override(req, ctx, 0);
            if (ctx->override_uid != (uid_t) -1)
                return forward_getresuid_override(req, ctx, ctx->override_uid);
            return kbox_dispatch_continue();
        }
        return forward_getresuid(req, ctx);
    }

    /* Identity: GID. */

    if (nr == h->getgid)
        return dispatch_get_gid(kbox_lkl_getgid, ctx);
    if (nr == h->getegid)
        return dispatch_get_gid(kbox_lkl_getegid, ctx);
    if (nr == h->getresgid) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getresgid_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getresgid_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getresgid(req, ctx);
    }

    /* Identity: groups. */

    if (nr == h->getgroups) {
        if (ctx->host_root) {
            if (ctx->root_identity)
                return forward_getgroups_override(req, ctx, 0);
            if (ctx->override_gid != (gid_t) -1)
                return forward_getgroups_override(req, ctx, ctx->override_gid);
            return kbox_dispatch_continue();
        }
        return forward_getgroups(req, ctx);
    }

    /* Identity: set*. */

    if (nr == h->setuid)
        return dispatch_set_id(req, ctx, forward_setuid);
    if (nr == h->setreuid)
        return dispatch_set_id(req, ctx, forward_setreuid);
    if (nr == h->setresuid)
        return dispatch_set_id(req, ctx, forward_setresuid);
    if (nr == h->setgid)
        return dispatch_set_id(req, ctx, forward_setgid);
    if (nr == h->setregid)
        return dispatch_set_id(req, ctx, forward_setregid);
    if (nr == h->setresgid)
        return dispatch_set_id(req, ctx, forward_setresgid);
    if (nr == h->setgroups)
        return dispatch_set_id(req, ctx, forward_setgroups);
    if (nr == h->setfsgid)
        return dispatch_set_id(req, ctx, forward_setfsgid);

    /* Legacy eventfd syscall (one arg, no flags). eventfd2 is in the handler
     * table; the raw eventfd(2) syscall does not take a flags argument.
     */
    if (nr == h->eventfd) {
        unsigned int initval = (unsigned int) kbox_syscall_request_arg(req, 0);
        int host_fd = eventfd(initval, 0);
        if (host_fd < 0)
            return kbox_dispatch_errno(errno);
        int tfd = request_addfd(ctx, req, host_fd, 0);
        close(host_fd);
        if (tfd < 0)
            return kbox_dispatch_errno(-tfd);
        track_host_passthrough_fd(ctx->fd_table, tfd);
        return kbox_dispatch_value(tfd);
    }

    /* Legacy pipe syscall: one arg, create host pipe2 and inject via ADDFD. */

    if (nr == h->pipe) {
        pid_t ppid = kbox_syscall_request_pid(req);
        uint64_t remote_pfd = kbox_syscall_request_arg(req, 0);
        if (remote_pfd == 0)
            return kbox_dispatch_errno(EFAULT);

        int host_pfds[2];
        if (pipe(host_pfds) < 0)
            return kbox_dispatch_errno(errno);

        int tfd0 = request_addfd_passthrough(ctx, req, host_pfds[0], 0);
        if (tfd0 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd0);
        }
        int tfd1 = request_addfd_passthrough(ctx, req, host_pfds[1], 0);
        if (tfd1 < 0) {
            close(host_pfds[0]);
            close(host_pfds[1]);
            return kbox_dispatch_errno(-tfd1);
        }
        close(host_pfds[0]);
        close(host_pfds[1]);

        track_host_passthrough_fd(ctx->fd_table, tfd0);
        track_host_passthrough_fd(ctx->fd_table, tfd1);

        int gfds[2] = {tfd0, tfd1};
        int pwrc = guest_mem_write(ctx, ppid, remote_pfd, gfds, sizeof(gfds));
        if (pwrc < 0)
            return kbox_dispatch_errno(-pwrc);
        return kbox_dispatch_value(0);
    }

    /* Signals.
     *
     * rt_sigaction: only SIGSYS is denied (reserved for trap mode).
     * All other signals -- including SIGURG (Go async preemption),
     * SIGUSR1/2, SIGALRM, etc. -- pass through to the host kernel
     * via CONTINUE.  SIGSEGV/SIGBUS changes bump the fault handler
     * generation counter so procmem.c reinstalls its handler.
     *
     * rt_sigprocmask: in trap/rewrite mode, emulated to keep the
     * supervisor's SIGSYS unblocked.  In seccomp mode, CONTINUE.
     */

    if (nr == h->rt_sigaction) {
        {
            int signo = (int) to_c_long_arg(kbox_syscall_request_arg(req, 0));
            if (signo == 11 /* SIGSEGV */ || signo == 7 /* SIGBUS */)
                kbox_procmem_signal_changed();
        }
        return kbox_dispatch_continue();
    }
    if (nr == h->rt_sigprocmask)
        return kbox_dispatch_continue();
    if (nr == h->rt_sigpending)
        return kbox_dispatch_continue();
    /* rt_sigtimedwait waits on the tracee's own pending signals; the host
     * kernel owns those, so CONTINUE. ClickHouse's benchmark and client use
     * it to poll for SIGINT.
     */
    if (nr == h->rt_sigtimedwait)
        return kbox_dispatch_continue();
    if (h->alarm >= 0 && nr == h->alarm)
        return kbox_dispatch_continue();

    /* Signal delivery: PID validation + virtual-to-real translation.
     *
     * kill/tgkill/tkill share PID validation (guest process tree only), virtual
     * PID 1 -> real PID translation, and trap-mode pending signal bookkeeping.
     */

#define IS_GUEST_PID(p) \
    is_guest_process_pid(ctx, kbox_syscall_request_pid(req), (p))

#define DENY_NON_GUEST(pid_val, name)              \
    do {                                           \
        if (!IS_GUEST_PID(pid_val)) {              \
            if (ctx->verbose)                      \
                fprintf(stderr,                    \
                        "kbox: " name              \
                        "(%d) "                    \
                        "denied: not guest PID\n", \
                        (int) (pid_val));          \
            return kbox_dispatch_errno(EPERM);     \
        }                                          \
    } while (0)

    if (nr == h->kill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        if (target == 0 && req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        /* A process signalling itself cannot be emulated from here.
         *
         * The supervisor would have to send the signal before it answers the
         * notification, and the signal then interrupts the tracee's own wait
         * for that answer: the kernel aborts the blocked syscall and kill(2)
         * returns EINTR instead of 0. CPython turns that into InterruptedError
         * (test_signal.test_stress_delivery_dependent). Seccomp-notify mode
         * reports the real PID, so a self-target becomes the caller's own
         * thread-group and the host kernel can run the call natively.
         */
        if (req->source == KBOX_SYSCALL_SOURCE_SECCOMP) {
            pid_t caller_tgid = 0;
            pid_t caller = kbox_syscall_request_pid(req);
            if (read_proc_tgid_ppid(caller, &caller_tgid, NULL, NULL) < 0 ||
                caller_tgid <= 0)
                caller_tgid = caller;
            if (target == caller_tgid || target == caller)
                return kbox_dispatch_continue();
        }
        pid_t check_pid = (target < -1) ? -target : target;
        if (target != 0 && !IS_GUEST_PID(check_pid))
            DENY_NON_GUEST(target, "kill");
        pid_t real = (target == 0 || target == 1) ? ctx->child_pid : target;
        long ret = syscall(SYS_kill, real, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tgkill) {
        pid_t tgid = (pid_t) kbox_syscall_request_arg(req, 0);
        pid_t tid = (pid_t) kbox_syscall_request_arg(req, 1);
        int sig = (int) kbox_syscall_request_arg(req, 2);
        pid_t caller_tid = kbox_syscall_request_pid(req);
        pid_t caller_tgid = 0;

        if (read_proc_tgid_ppid(caller_tid, &caller_tgid, NULL, NULL) < 0 ||
            caller_tgid <= 0)
            caller_tgid = ctx->child_pid;
        if (!IS_GUEST_PID(tgid) && tgid != caller_tgid)
            DENY_NON_GUEST(tgid, "tgkill");
        /* When the tracee passes its own real tgid in seccomp-notify mode,
         * execute tgkill directly in the tracee via CONTINUE so the kernel
         * fills si_pid = caller_tgid and si_code = SI_TKILL natively.
         */
        if (tgid == caller_tgid && req->source == KBOX_SYSCALL_SOURCE_SECCOMP)
            return kbox_dispatch_continue();
        /* In a forked guest subprocess, virtual PID 1 maps to the caller's
         * own thread-group leader rather than the root container init PID, so
         * glibc multi-threaded setxid/pthread tgkill reaches sibling threads.
         */
        pid_t real_tgid = (tgid == 1) ? caller_tgid : tgid;
        pid_t real_tid = (tid == 1) ? caller_tid : tid;
        long ret = syscall(SYS_tgkill, real_tgid, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        return kbox_dispatch_value(0);
    }
    if (nr == h->tkill) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int sig = (int) kbox_syscall_request_arg(req, 1);
        DENY_NON_GUEST(target, "tkill");
        pid_t real_tid = (target == 1) ? kbox_syscall_request_pid(req) : target;
        long ret = syscall(SYS_tkill, real_tid, sig);
        if (ret < 0)
            return kbox_dispatch_errno(errno);
        return kbox_dispatch_value(0);
    }
#undef DENY_NON_GUEST
#undef IS_GUEST_PID
    if (nr == h->pidfd_send_signal)
        return kbox_dispatch_errno(EPERM);

    /* arch_prctl: intercept SET_FS/GET_FS in trap/rewrite mode. */

    if (nr == h->arch_prctl)
        return kbox_dispatch_continue();

    /* clone: validate namespace and thread flags. */

    if (nr == h->clone) {
        uint64_t cflags = kbox_syscall_request_arg(req, 0);
        if (getenv("KBOX_TRACE"))
            fprintf(stderr, "kbox: clone pid=%u flags=%#llx\n",
                    kbox_syscall_request_pid(req), (unsigned long long) cflags);
        if (cflags & CLONE_NEW_MASK) {
            if (ctx->verbose)
                fprintf(stderr,
                        "kbox: clone denied: namespace flags 0x%llx "
                        "(pid=%u)\n",
                        (unsigned long long) (cflags & CLONE_NEW_MASK),
                        kbox_syscall_request_pid(req));
            return kbox_dispatch_errno(EPERM);
        }
        /* CLONE_VM|CLONE_VFORK: the child shares the parent's address space,
         * and kbox performs an exec by rewriting the pathname in tracee
         * memory. The rewrite therefore lands in the parent too, which then
         * resumes with "/proc/self/fd/N" where its own path used to be, and
         * every later fork in that process execs the stale descriptor
         * (posix_spawn, popen and system all take this path). clone's flags
         * arrive in a register and cannot be rewritten the way clone3's struct
         * can, so remember the parent and let the exec path snapshot and undo
         * its own writes when the parent leaves vfork. */
        if ((cflags & (CLONE_VM | CLONE_VFORK)) == (CLONE_VM | CLONE_VFORK)) {
            pid_t vp = (pid_t) kbox_syscall_request_pid(req);
            ctx->vfork_parents[ctx->vfork_parent_next %
                               (sizeof(ctx->vfork_parents) /
                                sizeof(ctx->vfork_parents[0]))] = vp;
            ctx->vfork_parent_next++;
            if (ctx->verbose)
                fprintf(stderr, "kbox: clone: vfork parent recorded (pid=%d)\n",
                        (int) vp);
        }
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
        if (!(cflags & (CLONE_THREAD | CLONE_FILES)))
            kbox_dispatch_snapshot_fork(ctx, kbox_syscall_request_pid(req));
        return kbox_dispatch_continue();
    }

    if ((h->fork >= 0 && nr == h->fork) || (h->vfork >= 0 && nr == h->vfork)) {
        /* A vfork parent shares its address space with the child until the
         * child execs, and its own pathname strings are rewritten by that
         * exec. Remember the parent so the exec path snapshots exactly the
         * bytes it overwrites and puts them back when the parent resumes.
         * The clone(CLONE_VM|CLONE_VFORK) form is recorded above; the plain
         * vfork() syscall -- what gcc's driver uses to spawn cc1 -- needs the
         * same record. Without it the driver resumed with "/proc/self/fd/N"
         * where its own path lived and died with SIGSEGV after every compile.
         */
        if (h->vfork >= 0 && nr == h->vfork) {
            pid_t vp = (pid_t) kbox_syscall_request_pid(req);

            ctx->vfork_parents[ctx->vfork_parent_next %
                               (sizeof(ctx->vfork_parents) /
                                sizeof(ctx->vfork_parents[0]))] = vp;
            ctx->vfork_parent_next++;
        }
        kbox_dispatch_snapshot_fork(ctx, kbox_syscall_request_pid(req));
        return kbox_dispatch_continue();
    }

    /* Memory mapping: invalidate path cache, then forward/CONTINUE. */

    if (nr == h->mmap) {
        invalidate_translated_path_cache(ctx);
        return forward_mmap(req, ctx);
    }
    if (nr == h->munmap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }
    if (nr == h->mprotect) {
        invalidate_translated_path_cache(ctx);
        return forward_mprotect(req, ctx);
    }
    if (nr == h->mremap) {
        invalidate_translated_path_cache(ctx);
        return kbox_dispatch_continue();
    }

    /* prlimit64: GET is unconditional. SET is left to the host kernel for the
     * calling process itself, after the RLIMIT_NOFILE floor below.
     *
     * The old rule answered EPERM for every SET except RLIMIT_CORE and
     * RLIMIT_AS, which broke the ordinary case as well: CPython maps EPERM to
     * ValueError("not allowed to raise maximum limit"), and
     * test_resource.test_fsize_ismax re-applies the limit it just read. A
     * process lowering its own limits needs no privilege, and raising one's own
     * hard limit is exactly what the host kernel judges with CAP_SYS_RESOURCE;
     * duplicating that rule here can only disagree with it.
     *
     * A SET aimed at another pid keeps the refusal: that call reaches a host
     * pid the guest was never given, and the guest's own limits are not the
     * target.
     */
    if (nr == h->prlimit64) {
        pid_t target = (pid_t) kbox_syscall_request_arg(req, 0);
        int resource = (int) kbox_syscall_request_arg(req, 1);
        uint64_t new_limit_ptr = kbox_syscall_request_arg(req, 2);
        uint64_t old_limit_ptr = kbox_syscall_request_arg(req, 3);
        pid_t pid = kbox_syscall_request_pid(req);

        if (resource == RLIMIT_NOFILE && (target == 0 || target == pid)) {
            struct kbox_proc_fd_entry *proc =
                ctx->active_proc ? ctx->active_proc
                                 : find_proc_fd_entry(ctx, pid);
            uint64_t cur = proc ? proc->rlimit_nofile_cur : 65536;
            uint64_t max = proc ? proc->rlimit_nofile_max : 1048576;

            if (old_limit_ptr != 0) {
                uint64_t old_rl[2] = {cur, max};
                if (guest_mem_write(ctx, pid, old_limit_ptr, old_rl,
                                    sizeof(old_rl)) < 0)
                    return kbox_dispatch_errno(EFAULT);
            }
            if (new_limit_ptr != 0) {
                uint64_t new_rl[2];
                if (guest_mem_read(ctx, pid, new_limit_ptr, new_rl,
                                   sizeof(new_rl)) < 0)
                    return kbox_dispatch_errno(EFAULT);
                if (new_rl[0] > new_rl[1])
                    return kbox_dispatch_errno(EINVAL);
                if (proc) {
                    proc->rlimit_nofile_cur = new_rl[0];
                    proc->rlimit_nofile_max = new_rl[1];
                }
            }
            return kbox_dispatch_value(0);
        }
        if (new_limit_ptr == 0)
            return kbox_dispatch_continue();
        if (target == 0)
            return kbox_dispatch_continue();
        if (ctx->verbose)
            fprintf(stderr, "kbox: prlimit64 SET pid=%d denied\n",
                    (int) target);
        return kbox_dispatch_errno(EPERM);
    }

    if (h->getrlimit >= 0 && nr == h->getrlimit) {
        int resource = (int) kbox_syscall_request_arg(req, 0);
        uint64_t rlim_ptr = kbox_syscall_request_arg(req, 1);
        if (resource == RLIMIT_NOFILE && rlim_ptr != 0) {
            pid_t pid = kbox_syscall_request_pid(req);
            struct kbox_proc_fd_entry *proc =
                ctx->active_proc ? ctx->active_proc
                                 : find_proc_fd_entry(ctx, pid);
            uint64_t cur = proc ? proc->rlimit_nofile_cur : 65536;
            uint64_t max = proc ? proc->rlimit_nofile_max : 1048576;
            uint64_t rl[2] = {cur, max};
            if (guest_mem_write(ctx, pid, rlim_ptr, rl, sizeof(rl)) < 0)
                return kbox_dispatch_errno(EFAULT);
            return kbox_dispatch_value(0);
        }
        return kbox_dispatch_continue();
    }

    if (h->setrlimit >= 0 && nr == h->setrlimit) {
        int resource = (int) kbox_syscall_request_arg(req, 0);
        uint64_t rlim_ptr = kbox_syscall_request_arg(req, 1);
        if (resource == RLIMIT_NOFILE && rlim_ptr != 0) {
            pid_t pid = kbox_syscall_request_pid(req);
            struct kbox_proc_fd_entry *proc =
                ctx->active_proc ? ctx->active_proc
                                 : find_proc_fd_entry(ctx, pid);
            uint64_t rl[2];
            if (guest_mem_read(ctx, pid, rlim_ptr, rl, sizeof(rl)) < 0)
                return kbox_dispatch_errno(EFAULT);
            if (rl[0] > rl[1])
                return kbox_dispatch_errno(EINVAL);
            if (proc) {
                proc->rlimit_nofile_cur = rl[0];
                proc->rlimit_nofile_max = rl[1];
            }
            return kbox_dispatch_value(0);
        }
        return kbox_dispatch_continue();
    }

    /* readlink: TOCTOU risk, forward to LKL via readlinkat. */

    if (nr == h->readlink) {
        char path[4096];
        int ret = guest_mem_read_string(ctx, kbox_syscall_request_pid(req),
                                        kbox_syscall_request_arg(req, 0), path,
                                        sizeof(path));
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        long bufsiz = (long) kbox_syscall_request_arg(req, 2);
        char buf[4096];
        if (bufsiz > (long) sizeof(buf))
            bufsiz = (long) sizeof(buf);
        long lret =
            kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, path, buf, bufsiz);
        if (lret < 0)
            return kbox_dispatch_from_lkl(lret);
        ret = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 1), buf,
                              (size_t) lret);
        if (ret < 0)
            return kbox_dispatch_errno(-ret);
        return kbox_dispatch_value(lret);
    }

    /* Default: deny unknown syscalls. */
    if (ctx->verbose)
        fprintf(stderr, "kbox: DENY unknown syscall nr=%d (pid=%u)\n", nr,
                kbox_syscall_request_pid(req));
    return kbox_dispatch_errno(ENOSYS);
}

/* The kernel's internal "restart this syscall" codes. None of them is a
 * userspace errno: the kernel converts them into a restarted syscall or EINTR
 * before returning to userspace, and LKL hands the decision to its caller.
 * Forwarding the raw code put "OSError: [Errno 512] No error information" in
 * front of the guest -- test_ssl.test_subclass connected to its own listener
 * in the pod and the connect came back as 512 instead of a connection.
 */
#define KBOX_ERESTART_FIRST 512 /* ERESTARTSYS */
#define KBOX_ERESTART_LAST 516  /* ERESTART_RESTARTBLOCK */

static int dispatch_is_restart(const struct kbox_dispatch *d)
{
    return d->kind == KBOX_DISPATCH_RETURN && d->error >= KBOX_ERESTART_FIRST &&
           d->error <= KBOX_ERESTART_LAST;
}

/* Run one dispatch on a brand-new host thread.
 *
 * LKL gives every host thread its own kernel task, and it never resets a task's
 * signal state. A container whose task ends up with a fatal signal pending (an
 * OOM kill inside the LKL kernel is the way in) fails every read with EINTR for
 * the rest of its life, while open(2) and fstat(2) keep working. A fresh thread
 * gets a fresh task, so the call is simply re-run there.
 *
 * The dispatch thread waits for the helper, so the fd table and the scratch
 * buffer are used by one thread at a time, as usual.
 */
struct kbox_retry_job {
    struct kbox_supervisor_ctx *ctx;
    const struct kbox_syscall_request *req;
    struct kbox_dispatch result;
};

static void *kbox_retry_on_fresh_task(void *arg)
{
    struct kbox_retry_job *job = arg;

    job->result = dispatch_request_impl(job->ctx, job->req);
    return NULL;
}

struct kbox_fresh_call {
    kbox_lkl_task_fn fn;
    void *arg;
    int rc;
};

static void *kbox_fresh_call_run(void *arg)
{
    struct kbox_fresh_call *call = arg;

    call->rc = call->fn(call->arg);
    return NULL;
}

int kbox_lkl_run_fresh_task(kbox_lkl_task_fn fn, void *arg)
{
    struct kbox_fresh_call call;
    pthread_t thread;

    if (!fn)
        return -EINVAL;
    call.fn = fn;
    call.arg = arg;
    call.rc = -EINTR;
    if (pthread_create(&thread, NULL, kbox_fresh_call_run, &call) != 0)
        return -EINTR;
    pthread_join(thread, NULL);
    return call.rc;
}

static struct kbox_dispatch dispatch_on_fresh_task(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    struct kbox_retry_job job;
    pthread_t thread;

    memset(&job, 0, sizeof(job));
    job.ctx = ctx;
    job.req = req;
    if (pthread_create(&thread, NULL, kbox_retry_on_fresh_task, &job) != 0)
        return kbox_dispatch_errno(EINTR);
    pthread_join(thread, NULL);
    return job.result;
}

/* LKL never dequeues signals from the tasks it creates.
 *
 * When the LKL kernel queues a signal for the task running a syscall -- the OOM
 * killer sending SIGKILL on a failed allocation is the one that matters here --
 * nothing ever takes it off the queue. `filemap_read` returns -EINTR while a
 * fatal signal is pending, so from that moment every read in that container
 * fails with EINTR while open(2) and fstat(2) keep working, which is exactly
 * what the pod runs showed. Draining the queue with a zero-timeout
 * rt_sigtimedwait puts the task back to work.
 *
 * Returns the signal number that was pending, or a negative errno when there
 * was none.
 */
static long lkl_task_drain_signal(struct kbox_supervisor_ctx *ctx)
{
    uint64_t all_signals = ~0ULL;
    long zero_ts[2] = {0, 0};

    if (!ctx || !ctx->sysnrs || ctx->sysnrs->rt_sigtimedwait <= 0)
        return -ENOSYS;

    long sig = lkl_syscall6(ctx->sysnrs->rt_sigtimedwait, (long) &all_signals,
                            0L, (long) zero_ts, 0L, 8L, 0L);

    /* A stale TIF_SIGPENDING bit also makes every interruptible wait abort
     * even with an empty queue. Replacing the blocked set runs
     * recalc_sigpending(), which clears the bit when nothing is queued. */
    if (ctx->sysnrs->rt_sigprocmask > 0) {
        long empty[1] = {0};

        (void) lkl_syscall6(ctx->sysnrs->rt_sigprocmask, 2L /* SIG_SETMASK */,
                            (long) empty, 0L, 8L, 0L, 0L);
    }
    return sig;
}

/* File I/O that LKL serves is not interruptible: the guest's kernel would never
 * fail a regular-file read or write because a signal arrived. In the pod the
 * LKL call does return EINTR, and the guest pays for it: musl's resolver treats
 * a failed read of /etc/hosts as "the name is not listed" and falls back to
 * DNS, so a plain bind(("localhost", 0)) ended up waiting for a DNS reply
 * (test_ssl, test_asyncio, both wedged in socket_helper.bind_port).
 *
 * Only descriptors that LKL backs are retried. Sockets and pipes are host
 * descriptors here, and EINTR on those is the caller's business.
 */
static int dispatch_retryable_file_io(const struct kbox_supervisor_ctx *ctx,
                                      const struct kbox_syscall_request *req)
{
    const struct kbox_host_nrs *h;
    long fd;

    if (!ctx || !req)
        return 0;
    h = ctx->host_nrs;
    /* Vector I/O belongs here for the same reason the scalar calls do: LKL
     * can answer -EINTR when its engine is contended or its host task carries
     * a stale pending signal, and a regular file never reports EINTR to
     * userspace. Leaving the vector forms out lost real data: CPython writes
     * the SSL keylog header with writev(), LKL's only attempt came back EINTR
     * in the pod, OpenSSL ignored the failed write and the keylog file stayed
     * empty (test_ssl.TestSSLDebug.test_keylog_defaults, "0 != 1").
     *
     * Retrying the whole request is safe because dispatch_iov_transfer()
     * reports EINTR only when it transferred nothing.
     */
    /* An execve rewrites the image by opening it through LKL, and that open
     * can answer EINTR when the engine carries a stale pending signal. execve
     * never returns EINTR to userspace, so a caller reads it as a hard
     * failure: MariaDB's runner printed "Can't exec \"/bin/sh\": Interrupted
     * system call" and every test after that point failed, 398 of them. The
     * rewrite is restartable and leaves no trace when it fails, so it gets the
     * same drain-and-retry treatment as file I/O. */
    if (req->nr == h->execve || req->nr == h->execveat)
        return 1;
    if (req->nr != h->read && req->nr != h->pread64 && req->nr != h->write &&
        req->nr != h->pwrite64 && req->nr != h->readv && req->nr != h->writev &&
        req->nr != h->preadv && req->nr != h->pwritev)
        return 0;
    fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    if (fd < 0)
        return 0;
    return kbox_fd_table_get_lkl(ctx->fd_table, fd) >= 0;
}

/* Whether an EINTR'd call may be re-run on a fresh LKL task.
 *
 * Only descriptor calls qualify. A task created from a bare supervisor thread
 * belongs to no container: daemon.c reaches the container's rootfs with
 * fchdir + chroot on the task that starts the container, and a fresh task
 * inherits neither. Re-running a path call there makes the kernel answer
 * ENOENT for files the container can see, which is how a transient EINTR on
 * an execve turned into 79 failing MariaDB tests.
 */
static int dispatch_fresh_task_allowed(const struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req)
{
    long fd;

    if (!ctx || !req)
        return 0;
    if (!kbox_nr_is_fd_file_io((long) req->nr, ctx->host_nrs))
        return 0;
    fd = to_c_long_arg(kbox_syscall_request_arg(req, 0));
    if (fd < 0)
        return 0;
    return kbox_fd_table_get_lkl(ctx->fd_table, fd) >= 0;
}

/* Give the LKL task that serves this supervisor thread a working descriptor
 * limit.
 *
 * LKL creates a task per host thread the first time that thread enters the
 * kernel, and a fresh task starts from the kernel's initial RLIMIT_NOFILE
 * (1024), not from the container's. A package manager or a database then hits
 * EMFILE with only a handful of descriptors open, because the numbers it sees
 * belong to another task. Raising the limit once per thread fixes it; the
 * call is cheap and the thread-local flag keeps it off the hot path.
 */
static __thread int t_lkl_nofile_raised;

static void ensure_lkl_nofile_limit(struct kbox_supervisor_ctx *ctx)
{
    struct {
        unsigned long long cur, max;
    } want = {1048576ULL, 1048576ULL};

    if (t_lkl_nofile_raised || !ctx || !ctx->sysnrs)
        return;
    if (kbox_lkl_prlimit64(ctx->sysnrs, 0, 7 /* RLIMIT_NOFILE */, &want) < 0)
        return;
    t_lkl_nofile_raised = 1;
}

struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req)
{
    ensure_lkl_nofile_limit(ctx);
    /* Closes happen in the host kernel, so their effect arrives here as an
     * event rather than a syscall. Draining before dispatch keeps the order
     * the guest observes: a descriptor it closed is gone before its next
     * syscall is answered. */
    kbox_drain_close_watches(ctx);
    struct kbox_dispatch d = dispatch_request_impl(ctx, req);
    const char *name = NULL;

    /* A syscall interrupted before it completed is supposed to run again. The
     * retry budget keeps a signal storm from spinning here forever; after it
     * the guest gets EINTR, which every libc and CPython's PEP 475 retry loop
     * understands. */
    if (ctx && req &&
        (dispatch_is_restart(&d) ||
         (d.kind == KBOX_DISPATCH_RETURN && d.error == EINTR &&
          dispatch_retryable_file_io(ctx, req)))) {
        int restarts = 0;
        int eintrs = 0;
        int retryable;

        name = syscall_name_from_nr(ctx->host_nrs, req->nr);
        for (;;) {
            retryable = dispatch_retryable_file_io(ctx, req);
            if (d.kind == KBOX_DISPATCH_RETURN && d.error == EINTR &&
                retryable && ctx->lkl_task_poisoned &&
                dispatch_fresh_task_allowed(ctx, req)) {
                d = dispatch_on_fresh_task(ctx, req);
                continue;
            }
            if (d.kind == KBOX_DISPATCH_RETURN && d.error == EINTR &&
                retryable) {
                /* LKL documents that a syscall may come back -EINTR when the
                 * engine is contended, and that the caller should retry. The
                 * window is longer than a tight loop covers: under the ssl
                 * suite a read was interrupted on a thousand consecutive
                 * attempts. Back off exponentially with a five second budget,
                 * which is far longer than any page lock the engine holds. */
                /* Three tries and twenty milliseconds: enough for the engine
                 * to finish a page-in of its own, short enough that a
                 * permanently interrupted descriptor is not worth blocking
                 * the container on. */
                if (eintrs >= 3)
                    break;
                if (eintrs == 0) {
                    long sig = lkl_task_drain_signal(ctx);

                    if (sig > 0) {
                        static int reported;
                        if (reported < 20) {
                            reported++;
                            fprintf(stderr,
                                    "kbox: dropped pending signal %ld from the "
                                    "LKL task; file I/O was failing with "
                                    "EINTR\n",
                                    sig);
                        }
                    }
                }
                if (eintrs > 0)
                    usleep(20000);
                eintrs++;
                if (eintrs == 3 && dispatch_fresh_task_allowed(ctx, req)) {
                    /* This thread's LKL task is the suspect: try once on a
                     * fresh one before giving the guest an error its kernel
                     * would never produce. Only descriptor calls are safe
                     * there; a path call would be answered against no root. */
                    d = dispatch_on_fresh_task(ctx, req);
                    if (!(d.kind == KBOX_DISPATCH_RETURN && d.error == EINTR)) {
                        static int reported;
                        ctx->lkl_task_poisoned = 1;
                        if (reported < 20) {
                            reported++;
                            fprintf(stderr,
                                    "kbox: syscall nr=%d (%s) succeeded on a "
                                    "fresh LKL task after %d EINTR; this "
                                    "container's task stays poisoned\n",
                                    (int) req->nr, name ? name : "unknown",
                                    eintrs);
                        }
                    }
                } else {
                    d = dispatch_request_impl(ctx, req);
                }
                continue;
            }
            if (dispatch_is_restart(&d) && restarts < 8) {
                restarts++;
                d = dispatch_request_impl(ctx, req);
                continue;
            }
            break;
        }

        if (dispatch_is_restart(&d)) {
            static int reported;
            if (reported < 200) {
                reported++;
                fprintf(stderr,
                        "kbox: syscall nr=%d (%s) still interrupted after %d "
                        "restarts; reporting EINTR\n",
                        (int) req->nr, name ? name : "unknown", restarts);
            }
            d = kbox_dispatch_errno(EINTR);
        } else if (d.kind == KBOX_DISPATCH_RETURN && d.error == EINTR) {
            static int reported;
            if (reported < 200) {
                reported++;
                fprintf(stderr,
                        "kbox: syscall nr=%d (%s) on a guest file returned "
                        "EINTR %d times; reporting EINTR\n",
                        (int) req->nr, name ? name : "unknown", eintrs);
            }
        } else if (eintrs > 0) {
            static int reported;
            if (reported < 200) {
                reported++;
                fprintf(stderr,
                        "kbox: syscall nr=%d (%s) recovered after %d EINTR\n",
                        (int) req->nr, name ? name : "unknown", eintrs);
            }
        }
    }

    /* A guest process that runs out of descriptors reports EMFILE from
     * whichever call happened to need one, and the guest cannot tell which
     * component produced it. Name the call here so the source is visible
     * without guessing: an EMFILE from openat, from dup and from socket all
     * mean different things.
     */
    if (ctx && req && getenv("KBOX_TRACE") && d.kind == KBOX_DISPATCH_RETURN &&
        d.error == EMFILE) {
        static int emfile_reported;

        if (emfile_reported < 40) {
            const char *emfile_name =
                syscall_name_from_nr(ctx->host_nrs, req->nr);

            emfile_reported++;
            fprintf(stderr,
                    "kbox: EMFILE from pid=%u nr=%d (%s) a0=%#llx a1=%#llx\n",
                    kbox_syscall_request_pid(req), (int) req->nr,
                    emfile_name ? emfile_name : "unknown",
                    (unsigned long long) req->args[0],
                    (unsigned long long) req->args[1]);
        }
    }

    /* A permission refusal from an unprivileged-but-virtual-root guest says
     * nothing about which call produced it. Name the call and its arguments.
     */
    if (ctx && req && getenv("KBOX_TRACE") && d.kind == KBOX_DISPATCH_RETURN &&
        d.error == EPERM) {
        static int eperm_reported;

        if (eperm_reported < 30) {
            const char *ename = syscall_name_from_nr(ctx->host_nrs, req->nr);

            eperm_reported++;
            fprintf(stderr,
                    "kbox: EPERM from pid=%u nr=%d (%s) a0=%#llx a1=%#llx "
                    "a2=%#llx a3=%#llx\n",
                    kbox_syscall_request_pid(req), (int) req->nr,
                    ename ? ename : "unknown",
                    (unsigned long long) req->args[0],
                    (unsigned long long) req->args[1],
                    (unsigned long long) req->args[2],
                    (unsigned long long) req->args[3]);
        }
    }

    /* Ownership calls are the one family where "kbox let the host kernel
     * decide" is invisible: the host refuses for uid 65534 and the guest sees
     * EPERM from a call the dispatcher never answered. Name it.
     */
    if (ctx && req && getenv("KBOX_TRACE") &&
        d.kind == KBOX_DISPATCH_CONTINUE) {
        const char *cname = syscall_name_from_nr(ctx->host_nrs, req->nr);
        static int cont_reported;

        if (cname && cont_reported < 20 &&
            (strcmp(cname, "chown") == 0 || strcmp(cname, "fchown") == 0 ||
             strcmp(cname, "fchownat") == 0 || strcmp(cname, "chmod") == 0 ||
             strcmp(cname, "fchmod") == 0 || strcmp(cname, "fchmodat") == 0)) {
            cont_reported++;
            fprintf(stderr,
                    "kbox: CONTINUE %s pid=%u a0=%#llx a1=%#llx a2=%#llx\n",
                    cname, kbox_syscall_request_pid(req),
                    (unsigned long long) req->args[0],
                    (unsigned long long) req->args[1],
                    (unsigned long long) req->args[2]);
        }
    }

    /* Verbose mode shows entries only; without results a refused syscall is
     * invisible when diagnosing why an unmodified image misbehaves. */
    if (ctx && req && ctx->verbose && d.kind == KBOX_DISPATCH_RETURN &&
        d.error != 0) {
        const char *call_name = syscall_name_from_nr(ctx->host_nrs, req->nr);

        fprintf(stderr, "kbox: result pid=%u nr=%d (%s) -> errno %d\n",
                kbox_syscall_request_pid(req), (int) req->nr,
                call_name ? call_name : "unknown", d.error);
    }
    if (ctx && req && ctx->verbose && d.kind == KBOX_DISPATCH_RETURN &&
        d.error == 0) {
        const char *call_name = syscall_name_from_nr(ctx->host_nrs, req->nr);

        if (call_name && (strncmp(call_name, "recv", 4) == 0 ||
                          strncmp(call_name, "send", 4) == 0))
            fprintf(stderr, "kbox: result pid=%u nr=%d (%s) -> %lld\n",
                    kbox_syscall_request_pid(req), (int) req->nr, call_name,
                    (long long) d.val);
    }
    /* One line per dispatched syscall, for tracing what a guest was doing when
     * it died. Off unless KBOX_SYS_TRACE is set: the volume is one line per
     * call and it changes timing enough to hide some races.
     */
    if (ctx && req && getenv("KBOX_SYS_TRACE")) {
        const char *tname = syscall_name_from_nr(ctx->host_nrs, req->nr);

        fprintf(stderr,
                "kbosys: pid=%u tgid=%d nr=%d %s(%#llx,%#llx,%#llx) -> "
                "kind=%d val=%lld err=%d\n",
                (unsigned int) kbox_syscall_request_pid(req),
                (int) (ctx->active_proc ? ctx->active_proc->tgid : -1),
                (int) req->nr, tname ? tname : "?",
                (unsigned long long) req->args[0],
                (unsigned long long) req->args[1],
                (unsigned long long) req->args[2], (int) d.kind,
                (long long) d.val, d.error);
    }
    return d;
}

struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif_ptr)
{
    struct kbox_syscall_request req;

    if (kbox_syscall_request_from_notif(notif_ptr, &req) < 0)
        return kbox_dispatch_errno(EINVAL);
    struct kbox_dispatch d = kbox_dispatch_request(ctx, &req);

    /* A parked accept or blocking receive is waiting for exactly this kind of
     * event: the syscall that just ran may have completed the connection (a
     * guest connect) or delivered the datagram. Polling here, not only at the
     * top of the supervisor loop, makes the completion happen before the
     * guest's next syscall. Without it the deferred accept of the server side
     * completed only after the client had already closed the connection, so
     * asyncio never ran the client_connected_cb
     * (test_asyncio.test_streams.test_unhandled_exception).
     */
    if (ctx->pending_accept_count > 0 || ctx->pending_recv_count > 0 ||
        ctx->pending_fifo_open_count > 0)
        kbox_dispatch_poll_pending(ctx);

    /* Verbose diagnostics: name the syscall that was rejected, with its fd
     * arguments. Without this an unexpected EBADF inside a program is opaque.
     */
    if (ctx->verbose && d.kind == KBOX_DISPATCH_RETURN && d.error)
        fprintf(stderr, "kbox: deny nr=%d (%s) fd=%ld,%ld,%ld err=%d pid=%u\n",
                (int) req.nr, syscall_name_from_nr(ctx->host_nrs, req.nr),
                (long) req.args[0], (long) req.args[1], (long) req.args[2],
                d.error, (unsigned) req.pid);
    return d;
}
