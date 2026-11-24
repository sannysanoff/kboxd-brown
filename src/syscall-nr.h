/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SYSCALL_NR_H
#define KBOX_SYSCALL_NR_H

#include <stdbool.h>

#define KBOX_HOST_NR_FIELDS(X) \
    X(openat)                  \
    X(openat2)                 \
    X(open)                    \
    X(stat)                    \
    X(lstat)                   \
    X(access)                  \
    X(rename)                  \
    X(mkdir)                   \
    X(rmdir)                   \
    X(unlink)                  \
    X(chmod)                   \
    X(chown)                   \
    X(fstat)                   \
    X(newfstatat)              \
    X(statx)                   \
    X(faccessat)               \
    X(faccessat2)              \
    X(getdents64)              \
    X(getdents)                \
    X(mkdirat)                 \
    X(mknodat)                 \
    X(unlinkat)                \
    X(renameat)                \
    X(renameat2)               \
    X(fchmodat)                \
    X(fchmodat2)               \
    X(fchownat)                \
    X(fchown)                  \
    X(close)                   \
    X(sendmsg)                 \
    X(socket)                  \
    X(connect)                 \
    X(bind)                    \
    X(listen)                  \
    X(accept)                  \
    X(accept4)                 \
    X(sendto)                  \
    X(sendmmsg)                \
    X(recvfrom)                \
    X(recvmsg)                 \
    X(getsockopt)              \
    X(setsockopt)              \
    X(getsockname)             \
    X(getpeername)             \
    X(shutdown)                \
    X(exit)                    \
    X(exit_group)              \
    X(fcntl)                   \
    X(dup)                     \
    X(dup2)                    \
    X(dup3)                    \
    X(read)                    \
    X(write)                   \
    X(pread64)                 \
    X(lseek)                   \
    X(chdir)                   \
    X(fchdir)                  \
    X(getcwd)                  \
    X(getuid)                  \
    X(geteuid)                 \
    X(getresuid)               \
    X(getgid)                  \
    X(getegid)                 \
    X(getresgid)               \
    X(setuid)                  \
    X(setreuid)                \
    X(setresuid)               \
    X(setgid)                  \
    X(setregid)                \
    X(setresgid)               \
    X(getgroups)               \
    X(setgroups)               \
    X(setfsgid)                \
    X(mount)                   \
    X(umount2)                 \
    X(execve)                  \
    X(execveat)                \
    X(getpid)                  \
    X(getppid)                 \
    X(gettid)                  \
    X(setpgid)                 \
    X(getpgid)                 \
    X(getsid)                  \
    X(setsid)                  \
    X(clock_gettime)           \
    X(clock_getres)            \
    X(gettimeofday)            \
    X(readlinkat)              \
    X(pipe2)                   \
    X(pipe)                    \
    X(sendfile)                \
    X(copy_file_range)         \
    X(pwrite64)                \
    X(pwritev)                 \
    X(preadv)                  \
    X(pwritev2)                \
    X(preadv2)                 \
    X(writev)                  \
    X(readv)                   \
    X(ftruncate)               \
    X(fallocate)               \
    X(flock)                   \
    X(fsync)                   \
    X(msync)                   \
    X(fdatasync)               \
    X(sync)                    \
    X(sync_file_range)         \
    X(symlinkat)               \
    X(linkat)                  \
    X(utimensat)               \
    X(ioctl)                   \
    X(syslog)                  \
    X(umask)                   \
    X(uname)                   \
    X(brk)                     \
    X(getrandom)               \
    X(prctl)                   \
    X(wait4)                   \
    X(waitid)                  \
    X(rt_sigaction)            \
    X(rt_sigprocmask)          \
    X(rt_sigreturn)            \
    X(rt_sigpending)           \
    X(rt_sigtimedwait)         \
    X(rt_sigsuspend)           \
    X(rt_sigaltstack)          \
    X(kill)                    \
    X(tgkill)                  \
    X(tkill)                   \
    X(pidfd_send_signal)       \
    X(setitimer)               \
    X(getitimer)               \
    X(alarm)                   \
    X(set_tid_address)         \
    X(set_robust_list)         \
    X(get_robust_list)         \
    X(futex)                   \
    X(clone3)                  \
    X(arch_prctl)              \
    X(rseq)                    \
    X(clone)                   \
    X(fork)                    \
    X(vfork)                   \
    X(mmap)                    \
    X(munmap)                  \
    X(mprotect)                \
    X(mremap)                  \
    X(membarrier)              \
    X(sched_yield)             \
    X(sched_setparam)          \
    X(sched_getparam)          \
    X(sched_setscheduler)      \
    X(sched_getscheduler)      \
    X(sched_get_priority_max)  \
    X(sched_get_priority_min)  \
    X(sched_setaffinity)       \
    X(sched_getaffinity)       \
    X(prlimit64)               \
    X(madvise)                 \
    X(getrlimit)               \
    X(setrlimit)               \
    X(getrusage)               \
    X(epoll_create1)           \
    X(epoll_ctl)               \
    X(epoll_wait)              \
    X(epoll_pwait)             \
    X(ppoll)                   \
    X(pselect6)                \
    X(poll)                    \
    X(shmget)                  \
    X(shmat)                   \
    X(shmdt)                   \
    X(shmctl)                  \
    X(semget)                  \
    X(semop)                   \
    X(semctl)                  \
    X(semtimedop)              \
    X(msgget)                  \
    X(msgsnd)                  \
    X(msgrcv)                  \
    X(msgctl)                  \
    X(nanosleep)               \
    X(clock_nanosleep)         \
    X(timerfd_create)          \
    X(signalfd4)               \
    X(timerfd_settime)         \
    X(timerfd_gettime)         \
    X(eventfd)                 \
    X(eventfd2)                \
    X(memfd_create)            \
    X(setpriority)             \
    X(getpriority)             \
    X(statfs)                  \
    X(fstatfs)                 \
    X(sysinfo)                 \
    X(readlink)                \
    X(capget)                  \
    X(capset)                  \
    X(getcpu)                  \
    X(fchmod)                  \
    X(fadvise64)               \
    X(socketpair)              \
    X(timer_create)            \
    X(timer_gettime)           \
    X(timer_getoverrun)        \
    X(timer_settime)           \
    X(timer_delete)            \
    X(getxattr)                \
    X(lgetxattr)               \
    X(fgetxattr)               \
    X(listxattr)               \
    X(llistxattr)              \
    X(flistxattr)

struct kbox_sysnrs {
    long chdir, fchdir, getcwd;
    long execve, exit, wait4;
    long getuid, geteuid, getresuid;
    long getgid, getegid, getresgid;
    long setuid, setreuid, setresuid;
    long setgid, setregid, setresgid;
    long getgroups, setgroups, setfsgid;
    long chroot, mknodat;
    /* LKL never dequeues signals from its own tasks; kbox drops a stale
     * pending signal so file I/O stops failing with EINTR. */
    long rt_sigtimedwait;
    long rt_sigprocmask;
    long mkdir_no;
    bool mkdirat_style;
    long mount, umount2;
    long openat, openat2, fcntl, ioctl, socket, connect;
    long bind, listen, accept, accept4, sendto, recvfrom, sendmsg, recvmsg;
    long getsockopt, setsockopt, getsockname, getpeername, shutdown;
    long ppoll, unshare, setns, sethostname, new_thread_group_leader;
    long dup, dup3, close;
    long read, write, pread64, pwrite64, lseek;
    long readv, writev;
    long readlinkat;
    long fstat, newfstatat, faccessat2, statx;
    long getdents, getdents64;
    long mkdirat, unlinkat, renameat2;
    long fchmodat, fchmodat2, fchmod, fchownat;
    long symlinkat, linkat, utimensat;
    long mmap, munmap;
    long ftruncate, fallocate, flock;
    long statfs, fstatfs;
    long fsync, fdatasync, sync, msync, sync_file_range;
    long pipe2;
    long sendfile, copy_file_range;
    long umask;
    long uname;
    long getrandom;
    long prctl;
    long clock_settime;
    long getpriority;
    long listxattr, llistxattr, flistxattr;
    long syslog;
    long prlimit64;
};

extern const struct kbox_sysnrs SYSNRS_X86_64;
extern const struct kbox_sysnrs SYSNRS_GENERIC;

#define AT_FDCWD_LINUX (-100L)

struct kbox_host_nrs {
#define KBOX_DECLARE_HOST_NR_FIELD(name) int name;
    KBOX_HOST_NR_FIELDS(KBOX_DECLARE_HOST_NR_FIELD)
#undef KBOX_DECLARE_HOST_NR_FIELD
};

extern const struct kbox_host_nrs HOST_NRS_X86_64;
extern const struct kbox_host_nrs HOST_NRS_GENERIC;

const struct kbox_sysnrs *detect_sysnrs(void);
const char *syscall_name_from_nr(const struct kbox_host_nrs *h, int nr);

/* True when a host syscall number names regular-file I/O through an already
 * open descriptor: read, write, pread64, pwrite64 and their vector forms.
 *
 * These calls can be re-run on a task that does not carry the container's
 * root, because they name an open file rather than a path. Path calls cannot:
 * a task created from a bare supervisor thread has no rootfs of the
 * container's, so it answers ENOENT for every file the container can see.
 */
int kbox_nr_is_fd_file_io(long nr, const struct kbox_host_nrs *h);

#endif /* KBOX_SYSCALL_NR_H */
