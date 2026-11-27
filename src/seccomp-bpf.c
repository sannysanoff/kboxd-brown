/* SPDX-License-Identifier: MIT */

/* Build and install a seccomp-unotify BPF filter.
 *
 * The BPF program has four sections:
 *   1. Arch check: kill on wrong architecture
 *   2. Allow-list: sendmsg, exit, exit_group bypass the supervisor
 *   3. Deny-list:  dangerous syscalls return EPERM without reaching the
 *      supervisor (seccomp manipulation, ptrace, namespaces, io_uring, etc.)
 *   4. Default:    everything else goes to USER_NOTIF
 *
 * The deny list prevents the guest from:
 *   - Installing its own seccomp filters (breaking CONTINUE)
 *   - Tracing/manipulating the supervisor process
 *   - Escaping via io_uring (bypasses seccomp entirely)
 *   - Manipulating namespaces, loading kernel modules, etc.
 *
 * NOT in the deny list (must reach dispatch for validation):
 *   - kill/tgkill/tkill: ash needs these for job control
 *   - mount/umount2: dispatch forwards to LKL
 *   - readlink: dispatch handles TOCTOU safely
 *   - prlimit64: dispatch validates GET vs SET
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fd-table.h"
#include "kbox/compiler.h"
#include "seccomp.h"

/* Deny list: arch-specific syscall numbers. */

#if defined(__x86_64__)
static const int deny_nrs[] = {
    /* Seccomp manipulation: guest can install filters breaking CONTINUE */
    317, /* seccomp */

    /* Tracing: supervisor memory/process access attacks */
    101, /* ptrace */
    310, /* process_vm_readv */
    311, /* process_vm_writev */
    440, /* process_madvise */
    448, /* process_mrelease */

    /* Landlock: guest can restrict CONTINUE operations */
    444, /* landlock_create_ruleset */
    445, /* landlock_add_rule */
    446, /* landlock_restrict_self */

    /* System admin: reboot, hostname manipulation */
    169, /* reboot */
    170, /* sethostname */
    171, /* setdomainname */
    163, /* acct */

    /* Kernel modules: code injection */
    175, /* init_module */
    313, /* finit_module */
    176, /* delete_module */
    246, /* kexec_load */
    320, /* kexec_file_load */

    /* BPF/perf: kernel tracing and manipulation */
    321, /* bpf */
    298, /* perf_event_open */

    /* Namespaces: container escape */
    272, /* unshare */
    308, /* setns */

    /* Security keys */
    250, /* keyctl */
    248, /* add_key */
    249, /* request_key */

    /* Process personality */
    135, /* personality */
    312, /* kcmp */

    /* io_uring: bypasses seccomp entirely */
    425, /* io_uring_setup */
    426, /* io_uring_enter */
    427, /* io_uring_register */

    /* Dangerous FD operations */
    323, /* userfaultfd */
    434, /* pidfd_open */
    438, /* pidfd_getfd */
    447, /* memfd_secret: breaks process_vm_readv */

    /* New mount API: host namespace manipulation */
    428, /* open_tree */
    429, /* move_mount */
    430, /* fsopen */
    431, /* fsconfig */
    432, /* fsmount */
    433, /* fspick */
    442, /* mount_setattr */
    155, /* pivot_root */

    /* Container escape via file handles */
    304, /* open_by_handle_at */
    303, /* name_to_handle_at */

    /* Filesystem monitoring */
    300, /* fanotify_init */
    301, /* fanotify_mark */

    /* Quota */
    179, /* quotactl */
    443, /* quotactl_fd */

    /* Time manipulation */
    227, /* clock_settime */
    164, /* settimeofday */
    159, /* adjtimex */
    305, /* clock_adjtime */

    /* Privileged I/O (x86_64 only) */
    172, /* iopl */
    173, /* ioperm */
    154, /* modify_ldt */

    /* Swap */
    167, /* swapon */
    168, /* swapoff */

    /* Misc */
    153, /* vhangup */
};

/* Syscalls that should fail with ENOSYS rather than EPERM so callers such as
 * MariaDB InnoDB fall back cleanly without logging permission errors. */
static const int enosys_nrs[] = {
    206, /* io_setup */
    209, /* io_submit */
    208, /* io_getevents */
    210, /* io_cancel */
    207, /* io_destroy */
};

#elif defined(__aarch64__) || (defined(__riscv) && __riscv_xlen == 64)
static const int deny_nrs[] = {
    /* Seccomp manipulation */
    277, /* seccomp */

    /* Tracing */
    117, /* ptrace */
    270, /* process_vm_readv */
    271, /* process_vm_writev */
    440, /* process_madvise */
    448, /* process_mrelease */

    /* Landlock */
    444, /* landlock_create_ruleset */
    445, /* landlock_add_rule */
    446, /* landlock_restrict_self */

    /* System admin */
    142, /* reboot */
    161, /* sethostname */
    162, /* setdomainname */
    89,  /* acct */

    /* Kernel modules */
    105, /* init_module */
    273, /* finit_module */
    106, /* delete_module */
    -1,  /* kexec_load (not on aarch64) */
    294, /* kexec_file_load */

    /* BPF/perf */
    280, /* bpf */
    241, /* perf_event_open */

    /* Namespaces */
    97,  /* unshare */
    268, /* setns */

    /* Security keys */
    219, /* keyctl */
    217, /* add_key */
    218, /* request_key */

    /* Process */
    92,  /* personality */
    272, /* kcmp */

    /* io_uring */
    425, /* io_uring_setup */
    426, /* io_uring_enter */
    427, /* io_uring_register */

    /* Dangerous FD */
    282, /* userfaultfd */
    434, /* pidfd_open */
    438, /* pidfd_getfd */
    447, /* memfd_secret */

    /* New mount API */
    428, /* open_tree */
    429, /* move_mount */
    430, /* fsopen */
    431, /* fsconfig */
    432, /* fsmount */
    433, /* fspick */
    442, /* mount_setattr */
    41,  /* pivot_root */

    /* Container escape */
    264, /* open_by_handle_at */
    263, /* name_to_handle_at */

    /* Filesystem monitoring */
    262, /* fanotify_init */
    263, /* fanotify_mark: shares NR with name_to_handle_at on some kernels */

    /* Quota */
    -1,  /* quotactl (not on aarch64) */
    443, /* quotactl_fd */

    /* Time manipulation */
    112, /* clock_settime */
    -1,  /* settimeofday (not on aarch64) */
    171, /* adjtimex */
    266, /* clock_adjtime */

    /* Swap */
    224, /* swapon */
    225, /* swapoff */

    /* Misc */
    58, /* vhangup */
};

/* Syscalls that should fail with ENOSYS rather than EPERM so callers such as
 * MariaDB InnoDB fall back cleanly without logging permission errors. */
static const int enosys_nrs[] = {
    0, /* io_setup */
    2, /* io_submit */
    4, /* io_getevents */
    3, /* io_cancel */
    1, /* io_destroy */
};

#else
#error "unsupported architecture"
#endif

#define DENY_COUNT ((int) (sizeof(deny_nrs) / sizeof(deny_nrs[0])))
#define ENOSYS_COUNT ((int) (sizeof(enosys_nrs) / sizeof(enosys_nrs[0])))
#define ALLOW_COUNT 4
/* Must be >= KBOX_LOADER_MAX_MAPPINGS (49) to accept all executable
 * mappings from the loader without truncation.
 */
#define MAX_IP_RANGE_COUNT 64

/* Maximum BPF program length. Each deny entry is 2 instructions (compare +
 * ret_errno), each allow entry is 2 instructions. Trap-mode range checks use
 * 6 instructions per range plus one default-allow before the syscall-number
 * path. The trap-ranges filter also has an early rt_sigreturn allow for the
 * host signal restorer path.
 *
 * Use a generous upper bound for the VLA.
 *
 * Worst-case sizing: ~30 fixed + 8*N allow-ranges + 8 EMIT_ALLOW +
 * 5*5 shadow-allow + 5*8 host-fd-band + 2*DENY_COUNT ≈ 310 instructions
 * for typical inputs.  2048 provides >6x headroom; the post-emission check
 * catches unexpected growth without per-write bounds testing.
 */
#define MAX_PROG_LEN 2048

static void emit_self_pid_allow(struct kbox_sock_filter *filter,
                                int *idx,
                                int nr,
                                unsigned int pid)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 3);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, pid, 0, 1);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
}

static int install_seccomp_filter(const struct kbox_host_nrs *h,
                                  unsigned int filter_flags)
{
    struct kbox_sock_filter filter[MAX_PROG_LEN];
    struct kbox_sock_fprog prog;
    int idx = 0;
    int i;
    long ret;

    /* [0] Load architecture from seccomp_data. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_ARCH_OFFSET);

    /* [1] Arch check: skip kill if correct. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, KBOX_AUDIT_ARCH_CURRENT, 1,
        0);

    /* [2] Wrong arch: kill. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_KILL_PROCESS);

    /* Load syscall number. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    /* Allow-list: sendmsg, exit, exit_group.
     * These bypass the supervisor entirely.
     */
#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)

    /* The child's pre-exec FD transfer uses sendmsg(SCM_RIGHTS) before the
     * supervisor loop starts, so that one call (flags ==
     * KBOX_SENDMSG_HANDSHAKE_FLAG) must bypass the supervisor or the
     * handshake deadlocks. All other sendmsg calls are notified.
     */
    /* sendmsg bypasses the supervisor only for the handshake call. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (h->sendmsg), 0, 4);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG2_LO_OFFSET);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, KBOX_SENDMSG_HANDSHAKE_FLAG,
        0, 1);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
    /* getpid/gettid return the real PID and TID in seccomp-notify mode, which
     * is exactly what the kernel returns for the call itself. Leaving them for
     * the supervisor put them behind the notification window, where a signal
     * with a handler aborts the wait: libc's getpid() then returns -EINTR,
     * musl's __syscall hands that up as -errno without an error check, and
     * os.kill(os.getpid(), sig) asked the kernel to signal PID -4 (EPERM).
     */
    if (h->getpid >= 0)
        EMIT_ALLOW(h->getpid);
    if (h->gettid >= 0)
        EMIT_ALLOW(h->gettid);
    EMIT_ALLOW(h->rt_sigreturn);
#undef EMIT_ALLOW

    /* Every fd-based call is notified. The supervisor decides from its own
     * table whether the descriptor is a virtual (LKL) one or a plain host one,
     * so the filter never has to infer the owner from the number's range. */

    /* pipe() and pipe2() run in the kernel.
     *
     * A notified pipe() is committed to a notification before it can return,
     * and the kernel abandons that notification when a signal reaches the
     * tracee before the supervisor receives it. The guest then gets EINTR for
     * a syscall that a real kernel never fails: about once in 36 command
     * substitutions on a build, which is what made configure drop a line and
     * jemalloc generate a truncated header (item 33). Letting the kernel
     * create the pair removes the notification entirely; the descriptors are
     * closed in the kernel too, by the rule above.
     */
    {
        if (h->pipe >= 0) {
            filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
                KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
                (unsigned int) h->pipe, 0, 1);
            filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
                KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
        }
        if (h->pipe2 >= 0) {
            filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
                KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
                (unsigned int) h->pipe2, 0, 1);
            filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
                KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
        }
    }

    /* kill(getpid(), sig) runs in the kernel, not through the supervisor.
     *
     * Every notified syscall can come back as EINTR: while the tracee waits
     * for the supervisor's answer, a signal with a handler aborts that wait,
     * and the kernel returns -ERESTARTSYS for the blocked syscall. kill(2) is
     * not restarted, so a self-signal under signal load (test_signal's stress
     * tests fire SIGALRM through setitimer in a tight loop) failed with
     * InterruptedError instead of returning 0. A self-signal already carries
     * the real PID as its target, so the kernel can run the call natively.
     */
    if (h->kill >= 0)
        emit_self_pid_allow(filter, &idx, h->kill, (unsigned int) getpid());

    /* The arg0-based fast-fd checks above overwrite A with the file
     * descriptor. Reload the syscall number before the deny list so low FDs
     * do not alias deny-list syscall numbers (for example write(fd=1) vs
     * io_destroy on aarch64).
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

    /* Deny-list: dangerous syscalls get EPERM without reaching the supervisor.
     * Skip entries with nr == -1 (not available on this architecture).
     */
    for (i = 0; i < DENY_COUNT; i++) {
        if (deny_nrs[i] < 0)
            continue;
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
            (unsigned int) deny_nrs[i], 0, 1);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(EPERM));
    }
    for (i = 0; i < ENOSYS_COUNT; i++) {
        if (enosys_nrs[i] < 0)
            continue;
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
            (unsigned int) enosys_nrs[i], 0, 1);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(ENOSYS));
    }

    /* Notify only what the supervisor would not simply continue.
     *
     * The dispatcher's CONTINUE table is a list of syscalls whose answer is
     * "let the host kernel do it". Sending them through the notification first
     * buys nothing and costs correctness: a signal with a handler aborts the
     * tracee's wait for the answer, so the call comes back as -ERESTARTSYS.
     * For a call the kernel would never interrupt on its own (mmap, setitimer,
     * rt_sigaction, ...) that EINTR is fabricated, and CPython surfaces it:
     * pymalloc reports MemoryError when its mmap is interrupted, and
     * os.setitimer raises InterruptedError. test_signal's stress tests drive
     * exactly that. Allowing these syscalls in the filter gives every caller
     * the plain kernel behaviour.
     *
     * exit/exit_group stay notified: the supervisor flushes writable shadows
     * there. see dispatch_request_impl().
     */
#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)
#define EMIT_CONTINUE_ALLOW(field) \
    do {                           \
        if ((h->field) >= 0)       \
            EMIT_ALLOW(h->field);  \
    } while (0)
    EMIT_CONTINUE_ALLOW(setpgid);
    EMIT_CONTINUE_ALLOW(getpgid);
    EMIT_CONTINUE_ALLOW(getsid);
    EMIT_CONTINUE_ALLOW(setsid);
    EMIT_CONTINUE_ALLOW(brk);
    EMIT_CONTINUE_ALLOW(rt_sigaltstack);
    EMIT_CONTINUE_ALLOW(rt_sigsuspend);
    /* In notify mode kbox gains nothing by observing rt_sigprocmask: the
     * handler only continues it. Answering it through a notification loses the
     * call when a signal arrives before the supervisor receives it, and the
     * guest then keeps its old mask. Measured in the guest: a shell that lost
     * a SIG_SETMASK stayed with SIGCHLD blocked, its child exited into a
     * zombie, SIGCHLD sat pending in the shared set, and "wait $pid" hung in
     * sigsuspend forever.
     */
    EMIT_CONTINUE_ALLOW(rt_sigprocmask);
    EMIT_CONTINUE_ALLOW(setitimer);
    EMIT_CONTINUE_ALLOW(getitimer);
    EMIT_CONTINUE_ALLOW(set_tid_address);
    EMIT_CONTINUE_ALLOW(set_robust_list);
    EMIT_CONTINUE_ALLOW(get_robust_list);
    EMIT_CONTINUE_ALLOW(futex);
    EMIT_CONTINUE_ALLOW(rseq);
    EMIT_CONTINUE_ALLOW(membarrier);
    EMIT_CONTINUE_ALLOW(madvise);
    EMIT_CONTINUE_ALLOW(getrlimit);
    EMIT_CONTINUE_ALLOW(getrusage);
    EMIT_CONTINUE_ALLOW(sched_yield);
    EMIT_CONTINUE_ALLOW(sched_setparam);
    EMIT_CONTINUE_ALLOW(sched_getparam);
    EMIT_CONTINUE_ALLOW(sched_setscheduler);
    EMIT_CONTINUE_ALLOW(sched_getscheduler);
    EMIT_CONTINUE_ALLOW(sched_get_priority_max);
    EMIT_CONTINUE_ALLOW(sched_get_priority_min);
    EMIT_CONTINUE_ALLOW(sched_setaffinity);
    EMIT_CONTINUE_ALLOW(sched_getaffinity);
    EMIT_CONTINUE_ALLOW(nanosleep);
    EMIT_CONTINUE_ALLOW(clock_nanosleep);
    EMIT_CONTINUE_ALLOW(timer_create);
    EMIT_CONTINUE_ALLOW(timer_gettime);
    EMIT_CONTINUE_ALLOW(timer_getoverrun);
    EMIT_CONTINUE_ALLOW(timer_settime);
    EMIT_CONTINUE_ALLOW(timer_delete);
    EMIT_CONTINUE_ALLOW(sysinfo);
    EMIT_CONTINUE_ALLOW(getcpu);
#undef EMIT_ALLOW
#undef EMIT_CONTINUE_ALLOW

    /* mmap: the supervisor only invalidates a path cache for the fd-backed
     * case. Anonymous mappings need no supervisor at all.
     */
    if (h->mmap >= 0) {
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) h->mmap, 0,
            3);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
            KBOX_SECCOMP_DATA_ARG4_LO_OFFSET);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, 0xffffffffU, 0, 1);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
            KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
            KBOX_SECCOMP_DATA_NR_OFFSET);
    }

    /* Default: everything else goes to the supervisor. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_USER_NOTIF);

    if (idx > MAX_PROG_LEN) {
        fprintf(stderr, "kbox: BPF program overflow (%d > %d)\n", idx,
                MAX_PROG_LEN);
        errno = EINVAL;
        return -1;
    }

    prog.len = (unsigned short) idx;
    prog.filter = filter;

    ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER, filter_flags,
                  &prog);
    if (ret < 0) {
        int saved = errno;

        fprintf(stderr, "kbox: seccomp(SET_MODE_FILTER, 0x%x) failed: %s\n",
                filter_flags, strerror(saved));
        errno = saved;
        return -1;
    }

    return (int) ret;
}

int kbox_install_seccomp_listener(const struct kbox_host_nrs *h)
{
    /* WAIT_KILLABLE_RECV is required, not optional: without it a signal that
     * reaches the tracee while the supervisor waits in NOTIF_RECV abandons the
     * wait, and the guest sees EINTR from a call a real kernel never fails.
     * Kernel 6.4 and later have it; an older host is refused rather than run
     * with semantics that lose syscalls. */
    int fd = install_seccomp_filter(
        h, KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER |
               KBOX_SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV);

    if (fd < 0 && (errno == EINVAL || errno == ENOSYS)) {
        int saved = errno;
        const char *why = strerror(saved);

        fprintf(stderr,
                "kbox: host kernel lacks WAIT_KILLABLE_RECV (%s): kbox needs "
                "Linux 6.4 or later\n",
                why);
        errno = ENOTSUP;
    }
    return fd;
}
