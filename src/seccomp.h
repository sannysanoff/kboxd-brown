/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SECCOMP_H
#define KBOX_SECCOMP_H

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fd-table.h"
#include "kbox/bind-path.h"
#include "kbox/locks.h"
#include "kbox/path.h"
#include "procmem.h"
#include "seccomp-defs.h"
#include "syscall-nr.h"

struct kbox_dispatch {
    enum {
        KBOX_DISPATCH_CONTINUE,
        KBOX_DISPATCH_RETURN,
        KBOX_DISPATCH_DEFERRED,
    } kind;
    int64_t val;
    int error;
};

struct kbox_web_ctx;
struct kbox_fd_inject_ops;

#define KBOX_PATH_SHADOW_CACHE_MAX 8
#define KBOX_TRANSLATED_PATH_CACHE_MAX 8
#define KBOX_LITERAL_PATH_CACHE_MAX 8

struct kbox_path_shadow_cache_entry {
    int valid;
    int memfd;
    char path[KBOX_MAX_PATH];
    struct stat host_stat;
};

struct kbox_translated_path_cache_entry {
    int valid;
    unsigned generation;
    char guest_path[KBOX_MAX_PATH];
    char translated[KBOX_MAX_PATH];
};

struct kbox_literal_path_cache_entry {
    int valid;
    unsigned generation;
    pid_t pid;
    uint64_t guest_addr;
    char translated[KBOX_MAX_PATH];
};

/* Every request arrives through the seccomp user-notification listener. */
enum kbox_syscall_source {
    KBOX_SYSCALL_SOURCE_SECCOMP = 0,
};

struct kbox_syscall_regs {
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

struct kbox_syscall_request {
    enum kbox_syscall_source source;
    pid_t pid;
    uint64_t cookie;
    int nr;
    uint64_t instruction_pointer;
    uint64_t args[6];
    struct kbox_guest_mem guest_mem;
};

static inline pid_t kbox_syscall_request_pid(
    const struct kbox_syscall_request *req)
{
    return req->pid;
}

static inline uint64_t kbox_syscall_request_cookie(
    const struct kbox_syscall_request *req)
{
    return req->cookie;
}

static inline uint64_t kbox_syscall_request_arg(
    const struct kbox_syscall_request *req,
    size_t idx)
{
    return idx < 6 ? req->args[idx] : 0;
}

#define KBOX_PENDING_ACCEPTS_MAX 64
#define KBOX_PROC_FD_TABLES_MAX 128
#define KBOX_PID_TGID_CACHE_MAX 256
#define KBOX_HOST_BINDS_MAX 32

#define KBOX_LKL_DIRFD_HOST_BIND (-3)
#define KBOX_LKL_DIRFD_HOST_BIND_RO (-4)

/* struct kbox_host_bind lives in kbox/bind-path.h: the path translation it
 * describes is a pure function, so the unit tests build it without the
 * supervisor. */

struct kbox_proc_fd_entry {
    pid_t tgid;
    int owned;
    struct kbox_fd_table *table;
    char host_cwd[KBOX_MAX_PATH];
    /* Working directory of the process inside LKL. LKL has one cwd for the
     * whole container, so each process keeps its own here and the dispatcher
     * switches LKL to it before serving that process (a `mkdir -p` child that
     * chdir()s must not move its parent's cwd). Empty = not yet known. */
    char lkl_cwd[KBOX_MAX_PATH];
    /* Per-process file creation mask. LKL has one umask for the whole
     * container, so each process tracks its own mask here (inherited across
     * fork) and the dispatcher switches LKL to it before serving that process
     * so a child calling umask(0077) (such as mariadbd) never poisons its
     * parent's or sibling's file creation mode. */
    unsigned umask;
    uint64_t rlimit_nofile_cur;
    uint64_t rlimit_nofile_max;
};

#define KBOX_PENDING_FORKS_MAX 64

struct kbox_pending_fork {
    pid_t parent_tgid;
    struct kbox_fd_table *table;
    char host_cwd[KBOX_MAX_PATH];
    char lkl_cwd[KBOX_MAX_PATH];
    unsigned umask;
    uint64_t rlimit_nofile_cur;
    uint64_t rlimit_nofile_max;
};

struct kbox_pid_tgid_entry {
    pid_t pid;
    pid_t tgid;
};

struct kbox_pending_accept {
    int active;
    struct kbox_syscall_request req;
    long listen_fd;
    int flags;
    uint64_t addr_ptr;
    uint64_t len_ptr;
    unsigned int in_len;
};

/* A blocking datagram recvfrom that the supervisor must not wait for.
 *
 * The dispatcher is one thread: it receives a notification, runs the handler,
 * answers. A blocking recvfrom on a shadow socket therefore stalls every other
 * syscall of the whole guest, including the other threads of the same process.
 * Python's asyncio test helpers run a UDP echo server in a thread; the echo
 * thread blocked in recvfrom and the main thread never got its own sendto
 * handled, so test_asyncio hung. The request is parked here instead and the
 * main loop completes it when data arrives.
 */
struct kbox_pending_recv {
    int active;
    struct kbox_syscall_request req;
    long fd;
    uint64_t buf_ptr;
    uint64_t src_ptr;
    uint64_t addrlen_ptr;
    size_t len;
    long flags;
    unsigned int addrlen;
    long deadline_ms; /* CLOCK_MONOTONIC, -1 = no SO_RCVTIMEO */
};

#define KBOX_PENDING_RECVS_MAX 16

/* A blocking recvmsg(2) that has to wait for a datagram.
 *
 * The dispatcher answers every notification for the container on one thread, so
 * waiting inside it stops the guest's other threads (the sending thread of the
 * same process among them) from being served at all. The notification is parked
 * instead and completed by kbox_dispatch_poll_pending.
 */
struct kbox_pending_recvmsg {
    int active;
    struct kbox_syscall_request req;
    long fd;
    uint64_t msg_ptr;
    long flags;
    long deadline_ms;
};

#define KBOX_PENDING_RECVMSGS_MAX 8

/* A blocking FIFO open(2) that the supervisor must not wait for.
 *
 * A blocking open of a FIFO (O_RDONLY without O_NONBLOCK, or O_WRONLY without
 * O_NONBLOCK when no reader is present) sleeps in the kernel until the other
 * end is opened. The dispatcher serves every process in the container on one
 * thread, so waiting inside emulate_host_open_tracked() deadlocks the whole
 * container: the peer process's open() queues behind the blocked thread and
 * can never arrive. The blocking openat() runs on a helper thread instead and
 * the main loop installs and answers the notification once it completes.
 */
struct kbox_fifo_open_job;

struct kbox_pending_fifo_open {
    int active;
    int cancelling;
    struct kbox_syscall_request req;
    int host_flags;
    char path[KBOX_MAX_PATH];
    struct kbox_fifo_open_job *job;
};

#define KBOX_PENDING_FIFO_OPENS_MAX 32

/* Deferred poll/ppoll waiting for a non-blocking LKL connect() to finish.
 *
 * A bridged TCP socket's tracee descriptor is a host AF_UNIX socketpair, which
 * is already writable before LKL's TCP 3-way handshake completes. Letting the
 * host kernel run poll(POLLOUT) immediately wakes the tracee in microseconds
 * while the SYN is still in flight; the tracee then queries SO_ERROR, receives
 * EINPROGRESS, and aborts the connection (breaking apk update over HTTPS and
 * every standard POSIX non-blocking connect client). Park the poll until LKL
 * reports the handshake established, failed, or timed out.
 */
struct kbox_pending_connect_poll {
    int active;
    struct kbox_syscall_request req;
    long guest_fd;
    uint64_t fds_ptr;
    short events;
    int has_deadline;
    uint64_t deadline_ns;
};

#define KBOX_PENDING_CONNECT_POLLS_MAX 16

struct kbox_supervisor_ctx {
    const struct kbox_sysnrs *sysnrs;
    const struct kbox_host_nrs *host_nrs;
    struct kbox_fd_table *fd_table;
    int listener_fd;
    int proc_self_fd_dirfd;
    int proc_mem_fd;
    int inherited_fds_tracked;
    pid_t child_pid;
    const char *host_root;
    int verbose;
    int root_identity;
    uid_t override_uid;
    gid_t override_gid;
    int normalize;
    char own_ip[32];
    /* network_mode: host. INET sockets are real pod sockets, not LKL ones. */
    int host_net;
    long mem_limit; /* container memory limit in bytes, 0 = none */
    const struct kbox_guest_mem_ops *guest_mem_ops;
    struct kbox_guest_mem active_guest_mem;
    const struct kbox_fd_inject_ops *fd_inject_ops;
    struct kbox_web_ctx *web;
    unsigned active_writeback_shadows;
    /* Set once this container's LKL task answers file I/O with EINTR no
     * matter what: LKL never resets a task's signal state, so the remaining
     * calls have to run on a fresh task (see dispatch_on_fresh_task). */
    int lkl_task_poisoned;
    unsigned path_translation_generation;
    struct kbox_path_shadow_cache_entry
        path_shadow_cache[KBOX_PATH_SHADOW_CACHE_MAX];
    struct kbox_translated_path_cache_entry
        translated_path_cache[KBOX_TRANSLATED_PATH_CACHE_MAX];
    struct kbox_literal_path_cache_entry
        literal_path_cache[KBOX_LITERAL_PATH_CACHE_MAX];

    /* LRU stat cache: avoids repeated LKL inode lookups for fstat on the
     * same FD.  Keyed by lkl_fd.  Invalidated on write/truncate/close.
     */
#ifdef KBOX_STAT_CACHE_SIZE
#define KBOX_STAT_CACHE_MAX KBOX_STAT_CACHE_SIZE
#else
#define KBOX_STAT_CACHE_MAX 16
#endif
#if KBOX_STAT_CACHE_MAX > 0
#define KBOX_STAT_CACHE_ENABLED 1
#define KBOX_STAT_CACHE_STORAGE_MAX KBOX_STAT_CACHE_MAX
#else
#define KBOX_STAT_CACHE_ENABLED 0
#define KBOX_STAT_CACHE_STORAGE_MAX 1
#endif
    struct {
        long lkl_fd; /* -1 = empty slot */
        struct stat st;
    } stat_cache[KBOX_STAT_CACHE_STORAGE_MAX];

    /* POSIX/OFD advisory locks taken by guest processes. LKL cannot track
     * them for files kbox backs on the host (its fcntl_setlk crashed the
     * daemon), so the supervisor answers F_SETLK and F_GETLK from this table.
     */
    struct kbox_lock_table locks;

    struct kbox_pending_accept pending_accepts[KBOX_PENDING_ACCEPTS_MAX];
    size_t pending_accept_count;
    struct kbox_pending_recv pending_recvs[KBOX_PENDING_RECVS_MAX];
    size_t pending_recv_count;
    struct kbox_pending_recvmsg pending_recvmsgs[KBOX_PENDING_RECVMSGS_MAX];
    size_t pending_recvmsg_count;
    struct kbox_pending_fifo_open
        pending_fifo_opens[KBOX_PENDING_FIFO_OPENS_MAX];
    size_t pending_fifo_open_count;
    struct kbox_pending_connect_poll
        pending_connect_polls[KBOX_PENDING_CONNECT_POLLS_MAX];
    size_t pending_connect_poll_count;
    /* CLOCK_MONOTONIC timestamp (ns) of the last periodic sweep for bridged
     * sockets whose low host_fd was closed natively in the kernel. */
    uint64_t last_bridged_sweep_ns;

    struct kbox_fd_table *root_fd_table;
    struct kbox_proc_fd_entry *proc_fds;
    size_t proc_fd_count;
    struct kbox_proc_fd_entry *active_proc;
    struct kbox_pending_fork *pending_forks;
    size_t pending_fork_count;
    /* umask the guest last set. A file created on a bind mount is created by
     * the supervisor's kernel, which applies the supervisor's umask, so the
     * creation is corrected to this mask explicitly. */
    unsigned guest_umask;
    unsigned lkl_umask_cur;
    /* wait4/waitid was just dispatched. The child may still have been alive at
     * that moment, so the dead-process shadows cannot be flushed yet; the next
     * syscall of the parent is the first point where they can be. */
    int pending_reap;
    struct kbox_pid_tgid_entry pid_tgid_cache[KBOX_PID_TGID_CACHE_MAX];

    const struct kbox_host_bind *host_binds;
    size_t host_bind_count;
    char host_cwd[KBOX_MAX_PATH];
    /* What LKL's cwd currently is (see kbox_proc_fd_entry.lkl_cwd). */
    char lkl_cwd_cur[KBOX_MAX_PATH];
    /* Absolute guest path of the executable, used to synthesize
     * /proc/self/exe: /proc is the host's procfs, so the magic links of the
     * guest's own process would otherwise describe kboxd. */
    char guest_exe[KBOX_MAX_PATH];
    /* Per-process guest executable paths. guest_exe above is what the
     * container was started with, but /proc/self/exe has to name the binary
     * the *calling* process is running: the dynamic loader derives $ORIGIN
     * from it, so a container-wide answer breaks every binary that finds its
     * libraries relative to itself (libjli.so was the first casualty). */
    struct {
        pid_t pid;
        char path[KBOX_MAX_PATH];
    } exe_map[64];
    /* /proc is the container's own procfs in LKL, not the host's. */
    int private_proc;
    /* Pids that issued clone(CLONE_VM|CLONE_VFORK). Their child shares the
     * address space, so an in-place exec rewrite corrupts them; the rewrite is
     * snapshotted and undone once the parent leaves vfork. */
    pid_t vfork_parents[8];
    unsigned vfork_parent_next;
    /* Exec rewrites that landed in a vfork parent's memory, waiting for that
     * parent to resume: the parent is suspended until the child execs, so the
     * first syscall it makes is the signal that the bytes can go back.
     *
     * The exec path writes more than the pathname: when the new name overlaps
     * argv/envp strings it moves them below the stack pointer and rewrites the
     * pointer slots in the arrays themselves. Those arrays are the parent's,
     * because a vfork child shares the address space, so every region written
     * has to be recorded. Saving only the pathname left the parent with argv
     * entries pointing at stack space it then reused, and gcc's driver died
     * with SIGSEGV after every compile it completed. */
    struct kbox_vfork_pending {
        pid_t parent;
        int nregions;
        struct {
            uint64_t addr;
            size_t len;
            unsigned char *saved;
        } reg[8];
    } vfork_pending[4];

    /* Optional external child-exit notification (used by multi-threaded
     * daemon mode where a central reaper handles SIGCHLD for all children).
     * When exit_notify_fd >= 0, supervise_loop polls it instead of creating a
     * per-thread signalfd(SIGCHLD) and reads exit status from *exit_status_ptr.
     */
    int exit_notify_fd;
    int *exit_status_ptr;
};

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h);
int kbox_notify_recv(int listener_fd, void *notif);
int kbox_notify_send(int listener_fd, const void *resp);
int kbox_notify_respond(int listener_fd,
                        uint64_t id,
                        const struct kbox_dispatch *d);
/* A writeback that outstayed its budget is left running on its own thread; its
 * LKL descriptor must never be closed or reused while that thread may still be
 * inside a call on it. */
int kbox_lkl_fd_is_abandoned(long lkl_fd);
void kbox_dispatch_poll_pending(struct kbox_supervisor_ctx *ctx);
int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags);
int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags);
int kbox_syscall_request_init_from_regs(struct kbox_syscall_request *out,
                                        enum kbox_syscall_source source,
                                        pid_t pid,
                                        uint64_t cookie,
                                        const struct kbox_syscall_regs *regs,
                                        const struct kbox_guest_mem *guest_mem);
void kbox_dispatch_prepare_request_ctx(struct kbox_supervisor_ctx *ctx,
                                       const struct kbox_syscall_request *req);
void kbox_dispatch_cleanup_proc_fds(struct kbox_supervisor_ctx *ctx);
struct kbox_dispatch kbox_dispatch_syscall(struct kbox_supervisor_ctx *ctx,
                                           const void *notif);
int kbox_syscall_request_from_notif(const void *notif,
                                    struct kbox_syscall_request *out);
struct kbox_dispatch kbox_dispatch_request(
    struct kbox_supervisor_ctx *ctx,
    const struct kbox_syscall_request *req);
int kbox_dispatch_try_local_fast_path(const struct kbox_host_nrs *h,
                                      int nr,
                                      struct kbox_dispatch *out);
struct kbox_dispatch kbox_dispatch_continue(void);
struct kbox_dispatch kbox_dispatch_errno(int err);
struct kbox_dispatch kbox_dispatch_value(int64_t val);
struct kbox_dispatch kbox_dispatch_from_lkl(long ret);

/* Run a callback on a fresh LKL task and return what it returned.
 *
 * Only descriptor work is safe there. A task created from a bare supervisor
 * thread belongs to no container: daemon.c reaches the container's rootfs with
 * fchdir + chroot on the task that starts the container, and a fresh task
 * inherits neither, so a path call there answers ENOENT for files the container
 * can see.
 */
typedef int (*kbox_lkl_task_fn)(void *arg);
int kbox_lkl_run_fresh_task(kbox_lkl_task_fn fn, void *arg);
int kbox_run_supervisor(const struct kbox_sysnrs *sysnrs,
                        const char *command,
                        const char *const *args,
                        int nargs,
                        const char *host_root,
                        int exec_memfd,
                        int verbose,
                        int root_identity,
                        int normalize,
                        struct kbox_web_ctx *web);
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
                                size_t host_bind_count);
int kbox_supervise_ctx(struct kbox_supervisor_ctx *ctx);
int kbox_supervisor_send_fd(int sock, int fd);
int kbox_supervisor_recv_fd(int sock);
int kbox_supervisor_prepare_child_security(void);
int kbox_parse_host_volume(const char *spec, struct kbox_host_bind *out);
int kbox_ensure_lkl_bind_stubs(const struct kbox_sysnrs *sysnrs,
                               const struct kbox_host_bind *binds,
                               size_t count);
int kbox_resolve_host_bind_at(const struct kbox_supervisor_ctx *ctx,
                              long raw_dirfd,
                              const char *guest_path,
                              char *host_out,
                              size_t host_out_size,
                              int *ro_out);

#define KBOX_IO_CHUNK_LEN (128 * 1024)

/* Largest transfer one read() or write() may name. Linux serves a regular file
 * in full for any request up to this value (0x7ffff000), and callers rely on
 * it: mysqltest reads its expected result with a single read() and treats a
 * short count as end-of-file. kbox caps every transfer at this ceiling instead
 * of a smaller buffer size, and the transfer loop chunks it.
 */
#define KBOX_READ_MAX ((size_t) 0x7ffff000UL)

#endif /* KBOX_SECCOMP_H */
