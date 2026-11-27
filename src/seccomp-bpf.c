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
#include "syscall-trap-signal.h"

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

static void emit_fast_shadow_allow(struct kbox_sock_filter *filter,
                                   int *idx,
                                   int nr)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, KBOX_FD_FAST_BASE, 0, 1);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
    /* Reload syscall number on fallthrough so the next helper compares nr, not
     * arg0 (item 30 side observation). */
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
}

static void emit_host_fd_band_allow(struct kbox_sock_filter *filter,
                                    int *idx,
                                    int nr,
                                    unsigned int min_fd)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, min_fd, 0, 1);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
}

/* close() of a host-passthrough descriptor in kbox's own band runs in the
 * kernel. Answering it through a notification can lose the close: a signal
 * delivered while the tracee waits for the answer abandons the notification,
 * the supervisor's answer then fails with ENOENT, and the descriptor stays
 * open. A shell hits that on command substitutions and a pipeline reader waits
 * for an end-of-file that never comes (item 30 in three-suites-report.md).
 * Nothing in kbox has to observe these closes: the descriptors are plain host
 * objects and the table slot is rewritten when the number is reused.
 */
static void emit_pipe_band_close_allow(struct kbox_sock_filter *filter,
                                       int *idx,
                                       int nr)
{
    /* Reload the syscall number: the helper before this one leaves arg0 in the
     * accumulator, so a JEQ here would compare the descriptor with the number.
     */
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, KBOX_FD_PIPE_BASE, 0, 2);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, KBOX_FD_PIPE_TOP, 1, 0);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
}

/* close() of any host descriptor below the virtual base runs in the kernel.
 *
 * Such a descriptor is real in the tracee: stdio, a kbox pipe, a shadow, or a
 * descriptor the kernel created for a native pipe(). Answering its close
 * through a notification can lose the close when a signal arrives before the
 * supervisor receives it; the descriptor then stays open and a pipeline
 * reader waits for an end of file that never comes (items 30 and 33 in
 * three-suites-report.md). Virtual descriptors (KBOX_FD_BASE and above) still
 * go to the supervisor, which has to flush a writable shadow and release the
 * LKL side.
 */
static void emit_low_fd_close_allow(struct kbox_sock_filter *filter,
                                    int *idx,
                                    int nr)
{
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (unsigned int) nr, 0, 3);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_ARG0_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, KBOX_FD_BASE, 1, 0);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
}

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

static int emit_ip_range_allow(struct kbox_sock_filter *filter,
                               int *idx,
                               const struct kbox_syscall_trap_ip_range *range)
{
    uint64_t start;
    uint64_t end_inclusive;
    uint32_t hi;
    uint32_t lo_start;
    uint32_t lo_end;

    if (!filter || !idx || !range || range->start >= range->end)
        return -1;

    start = (uint64_t) range->start;
    end_inclusive = (uint64_t) range->end - 1;
    if ((start >> 32) != (end_inclusive >> 32))
        return -1;

    hi = (uint32_t) (start >> 32);
    lo_start = (uint32_t) start;
    lo_end = (uint32_t) end_inclusive;

    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_HI_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, hi, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, lo_start, 0, 2);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGT | KBOX_BPF_K, lo_end, 1, 0);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);
    return 0;
}

static int emit_ip_range_trap_match(
    struct kbox_sock_filter *filter,
    int *idx,
    const struct kbox_syscall_trap_ip_range *range,
    int *jump_index_out)
{
    uint64_t start;
    uint64_t end_inclusive;
    uint32_t hi;
    uint32_t lo_start;
    uint32_t lo_end;

    if (!filter || !idx || !range || !jump_index_out ||
        range->start >= range->end)
        return -1;

    start = (uint64_t) range->start;
    end_inclusive = (uint64_t) range->end - 1;
    if ((start >> 32) != (end_inclusive >> 32))
        return -1;

    hi = (uint32_t) (start >> 32);
    lo_start = (uint32_t) start;
    lo_end = (uint32_t) end_inclusive;

    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_HI_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, hi, 0, 4);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS,
        KBOX_SECCOMP_DATA_IP_LO_OFFSET);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGE | KBOX_BPF_K, lo_start, 0, 2);
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JGT | KBOX_BPF_K, lo_end, 1, 0);
    *jump_index_out = *idx;
    filter[(*idx)++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_K, 0, 0, 0);
    return 0;
}

static int install_seccomp_filter(
    const struct kbox_host_nrs *h,
    unsigned int default_action,
    unsigned int filter_flags,
    const struct kbox_syscall_trap_ip_range *allow_ranges,
    size_t allow_range_count)
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

    if (allow_ranges) {
        for (size_t r = 0; r < allow_range_count; r++) {
            if (emit_ip_range_allow(filter, &idx, &allow_ranges[r]) < 0) {
                errno = EINVAL;
                return -1;
            }
        }
    }

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

    /* EXPERIMENT (off by default): every fd-based call goes through the
     * notification, so the supervisor decides by its own table instead of the
     * filter deciding by the descriptor's range. Measured on the same stand as
     * the stock filter: the dup'd-directory close that fails on stock passes,
     * pipe-eintr (3000 rounds) and pipe-churn (1500 rounds x 1200 forks) lose
     * nothing on either build, and the full guest suite is identical (53 pass,
     * 5 fail, same 5). The cost is +3% on a command-substitution loop
     * (42.7s -> 43.9s per 1000 rounds). Enable with
     * -DKBOX_EXPERIMENT_NOTIFY_ALL_FDS to re-measure. */
#ifndef KBOX_EXPERIMENT_NOTIFY_ALL_FDS
    emit_fast_shadow_allow(filter, &idx, h->read);
    emit_fast_shadow_allow(filter, &idx, h->pread64);
    emit_fast_shadow_allow(filter, &idx, h->write);
    emit_fast_shadow_allow(filter, &idx, h->lseek);
    emit_host_fd_band_allow(filter, &idx, h->read, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->pread64, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->lseek, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->fstat, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->close, KBOX_FD_HOSTONLY_BASE);
    if (default_action == KBOX_SECCOMP_RET_USER_NOTIF)
        emit_low_fd_close_allow(filter, &idx, h->close);
    else
        emit_pipe_band_close_allow(filter, &idx, h->close);

    /* both helpers leave arg0 in A on the path that continues, so the
     * accumulator has to be reloaded before the next syscall-number compare. */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
#endif

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
    if (default_action == KBOX_SECCOMP_RET_USER_NOTIF) {
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
     * sigsuspend forever. Trap mode emulates this call to keep the reserved
     * SIGSYS unblocked, so it stays notified there.
     */
    if (default_action == KBOX_SECCOMP_RET_USER_NOTIF)
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
        KBOX_BPF_RET | KBOX_BPF_K, default_action);

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
    int fd =
        install_seccomp_filter(h, KBOX_SECCOMP_RET_USER_NOTIF,
                               KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER |
                                   KBOX_SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
                               NULL, 0);

    /* Older kernels reject the flag with EINVAL; a kernel without seccomp user
     * notifications answers ENOSYS. Retry with the plain listener so the host
     * still runs, with the pre-6.4 semantics. The downgrade is announced
     * BEFORE the retry: once the fallback filter is installed this process is
     * under its own notification, and a write() here would wait for a
     * supervisor that has not been handed the listener yet. */
    if (fd < 0 && (errno == EINVAL || errno == ENOSYS)) {
        int saved = errno;

        fprintf(stderr,
                "kbox: WAIT_KILLABLE_RECV refused (%s): notifications are "
                "interruptible by signals, expect spurious EINTR\n",
                strerror(saved));
        fd = install_seccomp_filter(h, KBOX_SECCOMP_RET_USER_NOTIF,
                                    KBOX_SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL,
                                    0);
    }
    return fd;
}

int kbox_install_seccomp_trap(const struct kbox_host_nrs *h)
{
    struct kbox_syscall_trap_ip_range allow_range;

    if (kbox_syscall_trap_host_syscall_range(&allow_range) < 0) {
        errno = EINVAL;
        return -1;
    }
    return install_seccomp_filter(h, KBOX_SECCOMP_RET_TRAP, 0, &allow_range, 1);
}

/* A successful seccomp install returns into userspace with the filter already
 * active. Keep this return path free of sanitizer/runtime syscalls so the
 * launch code can branch straight into the guest.
 */
__attribute__((no_stack_protector))
#if KBOX_HAS_ASAN
__attribute__((no_sanitize("address")))
#endif
__attribute__((no_sanitize("undefined"))) static int
install_seccomp_trap_ranges_ex(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    struct kbox_sock_filter filter[MAX_PROG_LEN];
    struct kbox_sock_fprog prog;
    int match_jumps[MAX_IP_RANGE_COUNT];
    struct kbox_syscall_trap_ip_range internal_ranges[16];
    int internal_jumps[16];
    size_t internal_count = 0;
    int idx = 0;
    int internal_allow_idx = -1;
    int nr_load_idx;
    int i;
    long ret;

    if (!h || !trap_ranges || trap_range_count == 0 ||
        trap_range_count > MAX_IP_RANGE_COUNT) {
        errno = EINVAL;
        return -1;
    }
    if (kbox_syscall_trap_internal_ip_ranges(
            internal_ranges,
            sizeof(internal_ranges) / sizeof(internal_ranges[0]),
            &internal_count) < 0) {
        errno = EINVAL;
        return -1;
    }

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_ARCH_OFFSET);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, KBOX_AUDIT_ARCH_CURRENT, 1,
        0);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_KILL_PROCESS);

    /* The kernel's signal restorer may live outside guest exec mappings.
     * Allow rt_sigreturn before the IP gate so SIGSYS delivery can unwind
     * without reopening general host-IP syscall execution.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(
        KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K,
        (unsigned int) h->rt_sigreturn, 0, 1);
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);

    for (i = 0; i < (int) internal_count; i++) {
        if (emit_ip_range_trap_match(filter, &idx, &internal_ranges[i],
                                     &internal_jumps[i]) < 0) {
            errno = EINVAL;
            return -1;
        }
    }

    for (i = 0; i < (int) trap_range_count; i++) {
        if (emit_ip_range_trap_match(filter, &idx, &trap_ranges[i],
                                     &match_jumps[i]) < 0) {
            errno = EINVAL;
            return -1;
        }
    }

    /* Non-guest, non-trampoline IPs must not reach the host kernel.
     *
     * The dedicated host trampoline covers the small set of syscalls kbox
     * executes on the trapped guest thread. Guest executable mappings are
     * matched above and routed into the dispatcher path. Any other IP is
     * outside the permitted syscall origin set and is rejected.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ERRNO(EPERM));

    internal_allow_idx = idx;
    for (i = 0; i < (int) internal_count; i++) {
        int rel = internal_allow_idx - (internal_jumps[i] + 1);

        if (rel < 0) {
            errno = EINVAL;
            return -1;
        }
        filter[internal_jumps[i]].k = (unsigned int) rel;
    }
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);

    nr_load_idx = idx;
    for (i = 0; i < (int) trap_range_count; i++) {
        int rel = nr_load_idx - (match_jumps[i] + 1);

        if (rel < 0) {
            errno = EINVAL;
            return -1;
        }
        filter[match_jumps[i]].k = (unsigned int) rel;
    }

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

#define EMIT_ALLOW(nr)                                             \
    do {                                                           \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_JUMP(   \
            KBOX_BPF_JMP | KBOX_BPF_JEQ | KBOX_BPF_K, (nr), 0, 1); \
        filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(   \
            KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_ALLOW);    \
    } while (0)

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
    EMIT_ALLOW(h->exit);
    EMIT_ALLOW(h->rt_sigreturn);
#undef EMIT_ALLOW

    emit_fast_shadow_allow(filter, &idx, h->read);
    emit_fast_shadow_allow(filter, &idx, h->pread64);
    emit_fast_shadow_allow(filter, &idx, h->write);
    emit_fast_shadow_allow(filter, &idx, h->lseek);
    emit_host_fd_band_allow(filter, &idx, h->read, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->pread64, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->lseek, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->fstat, KBOX_FD_HOSTONLY_BASE);
    emit_host_fd_band_allow(filter, &idx, h->close, KBOX_FD_HOSTONLY_BASE);
    emit_pipe_band_close_allow(filter, &idx, h->close);

    /* The arg0-based fast-fd checks above overwrite A with the file
     * descriptor. Reload the syscall number before the deny list so low FDs
     * do not alias deny-list syscall numbers.
     */
    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_LD | KBOX_BPF_W | KBOX_BPF_ABS, KBOX_SECCOMP_DATA_NR_OFFSET);

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

    filter[idx++] = (struct kbox_sock_filter) KBOX_BPF_STMT(
        KBOX_BPF_RET | KBOX_BPF_K, KBOX_SECCOMP_RET_TRAP);

    if (idx > MAX_PROG_LEN) {
        errno = EINVAL;
        return -1;
    }

    prog.len = (unsigned short) idx;
    prog.filter = filter;

    ret = syscall(__NR_seccomp, KBOX_SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (ret < 0) {
        fprintf(stderr,
                "kbox: seccomp(SET_MODE_FILTER, trap ranges) failed: %s\n",
                strerror(errno));
        return -1;
    }

    return (int) ret;
}

int kbox_install_seccomp_trap_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    return install_seccomp_trap_ranges_ex(h, trap_ranges, trap_range_count);
}

int kbox_install_seccomp_rewrite_ranges(
    const struct kbox_host_nrs *h,
    const struct kbox_syscall_trap_ip_range *trap_ranges,
    size_t trap_range_count)
{
    return install_seccomp_trap_ranges_ex(h, trap_ranges, trap_range_count);
}
