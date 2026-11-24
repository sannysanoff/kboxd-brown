/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>

#include "lkl-wrap.h"

/* Every LKL call in flight, so a stuck engine can name its holder.
 *
 * lkl_syscall() takes LKL's CPU lock for the whole call: one call that never
 * returns stops every other LKL syscall, of every container, forever. Only the
 * guest notices, as a syscall that never gets an answer (the pod wedged while a
 * guest waited for getrandom()). Each entry point publishes its number and
 * start time here; the supervisor's stall reporter prints them.
 *
 * A thread claims one slot for its lifetime and clears only the call number
 * when a call returns, so two threads can never share a slot.
 */
#define KBOX_LKL_SLOTS 64

struct kbox_lkl_slot {
    int claimed;
    volatile long nr;
    long a1;
    unsigned long tid;
    uint64_t start_ns;
};

static struct kbox_lkl_slot g_lkl_slots[KBOX_LKL_SLOTS];
static __thread int t_lkl_slot = -1;

static uint64_t lkl_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static int lkl_slot_enter(long nr, long a1)
{
    int slot = t_lkl_slot;

    if (slot < 0) {
        for (int i = 0; i < KBOX_LKL_SLOTS; i++) {
            int unclaimed = 0;

            if (__atomic_compare_exchange_n(&g_lkl_slots[i].claimed, &unclaimed,
                                            1, 0, __ATOMIC_ACQ_REL,
                                            __ATOMIC_RELAXED)) {
                slot = i;
                t_lkl_slot = i;
                break;
            }
        }
        if (slot < 0)
            return -1;
    }
    g_lkl_slots[slot].a1 = a1;
    g_lkl_slots[slot].tid = (unsigned long) pthread_self();
    __atomic_store_n(&g_lkl_slots[slot].start_ns, lkl_now_ns(),
                     __ATOMIC_RELAXED);
    __atomic_store_n(&g_lkl_slots[slot].nr, nr, __ATOMIC_RELEASE);
    return slot;
}

static void lkl_slot_leave(int slot)
{
    if (slot < 0)
        return;
    __atomic_store_n(&g_lkl_slots[slot].nr, 0, __ATOMIC_RELEASE);
}

void kbox_lkl_report_stalls(int min_ms)
{
    static uint64_t reported;
    uint64_t now_reported = 0;
    uint64_t now = lkl_now_ns();

    for (int i = 0; i < KBOX_LKL_SLOTS; i++) {
        uint64_t since;
        uint64_t age_ms;

        if (!__atomic_load_n(&g_lkl_slots[i].claimed, __ATOMIC_ACQUIRE))
            continue;
        if (__atomic_load_n(&g_lkl_slots[i].nr, __ATOMIC_ACQUIRE) == 0)
            continue;
        since = __atomic_load_n(&g_lkl_slots[i].start_ns, __ATOMIC_RELAXED);
        if (since == 0 || now <= since)
            continue;
        age_ms = (now - since) / 1000000ull;
        if (age_ms < (uint64_t) min_ms)
            continue;
        now_reported |= 1ull << i;
        if (reported & (1ull << i))
            continue;
        fprintf(stderr,
                "kbox: lkl: syscall nr=%ld a1=%ld tid=%lu in flight for "
                "%llums (slot %d)\n",
                g_lkl_slots[i].nr, g_lkl_slots[i].a1, g_lkl_slots[i].tid,
                (unsigned long long) age_ms, i);
    }
    reported = now_reported;
}

long lkl_syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long args[6] = {a1, a2, a3, a4, a5, a6};
    int slot = lkl_slot_enter(nr, a1);
    long ret = lkl_syscall(nr, args);

    lkl_slot_leave(slot);
    return ret;
}

const char *kbox_err_text(long code)
{
    return lkl_strerror((int) code);
}

int kbox_boot_kernel(const char *cmdline)
{
    const char *effective = cmdline;
    char buf[512];
    int ret;
    sigset_t mask;

    /* Block SIGCHLD before booting LKL so that all kernel threads created
     * by lkl_start_kernel inherit the blocked mask.
     */
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    if (!cmdline || !*cmdline) {
        effective = "console=null";
    } else if (!strstr(cmdline, "console=")) {
        snprintf(buf, sizeof(buf), "%s console=null", cmdline);
        effective = buf;
    }

    ret = lkl_init(&lkl_host_ops);
    if (ret < 0) {
        fprintf(stderr, "lkl_init failed: %s (%d)\n", lkl_strerror(ret), ret);
        return -1;
    }

    ret = lkl_start_kernel("%s", effective);
    if (ret < 0) {
        fprintf(stderr, "lkl_start_kernel failed: %s (%d)\n", lkl_strerror(ret),
                ret);
        lkl_cleanup();
        return -1;
    }

    return 0;
}

/* Point the guest's realtime clock at the host's.
 *
 * LKL derives the guest wall clock from the host's CLOCK_MONOTONIC (see
 * read_persistent_clock64 in arch/lkl/kernel/time.c), so without this the
 * guest believes it is the year 1970 plus the host's uptime. Every kernel
 * timestamp then disagrees with time.time(), which kbox answers from the
 * host clock: file mtimes, utime(2) with UTIME_NOW, and anything that
 * compares a timestamp against the current time (make, pip, tar) goes
 * wrong. Setting CLOCK_REALTIME once after boot fixes the offset for good,
 * because after boot the wall clock advances with the same monotonic
 * source.
 */
void kbox_sync_guest_realtime(void)
{
    const struct kbox_sysnrs *s = detect_sysnrs();
    struct timespec ts;

    if (!s || s->clock_settime <= 0)
        return;
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        return;
    long ret =
        lkl_syscall6(s->clock_settime, CLOCK_REALTIME, (long) &ts, 0, 0, 0, 0);
    if (ret < 0)
        fprintf(stderr, "kbox: guest clock_settime failed: %s (%ld)\n",
                lkl_strerror((int) ret), ret);
}

void kbox_halt_kernel(void)
{
    long ret = lkl_sys_halt();
    if (ret < 0)
        fprintf(stderr, "lkl_sys_halt failed: %s (%ld)\n",
                lkl_strerror((int) ret), ret);
}

/* Typed LKL syscall wrappers. */

long kbox_lkl_mount(const struct kbox_sysnrs *s,
                    const char *src,
                    const char *target,
                    const char *fstype,
                    long flags,
                    const void *data)
{
    return lkl_syscall6(s->mount, (long) src, (long) target, (long) fstype,
                        flags, (long) data, 0);
}

long kbox_lkl_umount2(const struct kbox_sysnrs *s,
                      const char *target,
                      long flags)
{
    return lkl_syscall6(s->umount2, (long) target, flags, 0, 0, 0, 0);
}

long kbox_lkl_openat(const struct kbox_sysnrs *s,
                     long dirfd,
                     const char *path,
                     long flags,
                     long mode)
{
    return lkl_syscall6(s->openat, dirfd, (long) path, flags, mode, 0, 0);
}

long kbox_lkl_openat2(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      const struct kbox_open_how *how,
                      long size)
{
    return lkl_syscall6(s->openat2, dirfd, (long) path, (long) how, size, 0, 0);
}

long kbox_lkl_close(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->close, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_read(const struct kbox_sysnrs *s, long fd, void *buf, long len)
{
    return lkl_syscall6(s->read, fd, (long) buf, len, 0, 0, 0);
}

long kbox_lkl_write(const struct kbox_sysnrs *s,
                    long fd,
                    const void *buf,
                    long len)
{
    return lkl_syscall6(s->write, fd, (long) buf, len, 0, 0, 0);
}

long kbox_lkl_pread64(const struct kbox_sysnrs *s,
                      long fd,
                      void *buf,
                      long len,
                      long offset)
{
    return lkl_syscall6(s->pread64, fd, (long) buf, len, offset, 0, 0);
}

long kbox_lkl_lseek(const struct kbox_sysnrs *s,
                    long fd,
                    long offset,
                    long whence)
{
    return lkl_syscall6(s->lseek, fd, offset, whence, 0, 0, 0);
}

long kbox_lkl_fcntl(const struct kbox_sysnrs *s, long fd, long cmd, long arg)
{
    return lkl_syscall6(s->fcntl, fd, cmd, arg, 0, 0, 0);
}

long kbox_lkl_ioctl(const struct kbox_sysnrs *s, long fd, long cmd, long arg)
{
    return lkl_syscall6(s->ioctl, fd, cmd, arg, 0, 0, 0);
}

long kbox_lkl_dup(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->dup, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_fstat(const struct kbox_sysnrs *s, long fd, void *buf)
{
    return lkl_syscall6(s->fstat, fd, (long) buf, 0, 0, 0, 0);
}

long kbox_lkl_newfstatat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         void *buf,
                         long flags)
{
    return lkl_syscall6(s->newfstatat, dirfd, (long) path, (long) buf, flags, 0,
                        0);
}

long kbox_lkl_faccessat2(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         long mode,
                         long flags)
{
    return lkl_syscall6(s->faccessat2, dirfd, (long) path, mode, flags, 0, 0);
}

long kbox_lkl_statx(const struct kbox_sysnrs *s,
                    long dirfd,
                    const char *path,
                    int flags,
                    unsigned mask,
                    void *buf)
{
    return lkl_syscall6(s->statx, dirfd, (long) path, (long) flags, (long) mask,
                        (long) buf, 0);
}

long kbox_lkl_getdents(const struct kbox_sysnrs *s,
                       long fd,
                       void *dirp,
                       long count)
{
    return lkl_syscall6(s->getdents, fd, (long) dirp, count, 0, 0, 0);
}

long kbox_lkl_getdents64(const struct kbox_sysnrs *s,
                         long fd,
                         void *dirp,
                         long count)
{
    return lkl_syscall6(s->getdents64, fd, (long) dirp, count, 0, 0, 0);
}

long kbox_lkl_mkdirat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode)
{
    return lkl_syscall6(s->mkdirat, dirfd, (long) path, mode, 0, 0, 0);
}

long kbox_lkl_mknodat(const struct kbox_sysnrs *s,
                      long dirfd,
                      const char *path,
                      long mode,
                      long dev)
{
    return lkl_syscall6(s->mknodat, dirfd, (long) path, mode, dev, 0, 0);
}

long kbox_lkl_mkdir(const struct kbox_sysnrs *s, const char *path, int mode)
{
    if (s->mkdirat_style)
        return lkl_syscall6(s->mkdir_no, AT_FDCWD_LINUX, (long) path,
                            (long) mode, 0, 0, 0);
    return lkl_syscall6(s->mkdir_no, (long) path, (long) mode, 0, 0, 0, 0);
}

long kbox_lkl_unlinkat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long flags)
{
    return lkl_syscall6(s->unlinkat, dirfd, (long) path, flags, 0, 0, 0);
}

long kbox_lkl_renameat2(const struct kbox_sysnrs *s,
                        long olddirfd,
                        const char *oldpath,
                        long newdirfd,
                        const char *newpath,
                        long flags)
{
    return lkl_syscall6(s->renameat2, olddirfd, (long) oldpath, newdirfd,
                        (long) newpath, flags, 0);
}

long kbox_lkl_fchmodat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long mode,
                       long flags)
{
    return lkl_syscall6(s->fchmodat, dirfd, (long) path, mode, flags, 0, 0);
}

long kbox_lkl_fchmodat2(const struct kbox_sysnrs *s,
                        long dirfd,
                        const char *path,
                        long mode,
                        long flags)
{
    return lkl_syscall6(s->fchmodat2, dirfd, (long) path, mode, flags, 0, 0);
}

long kbox_lkl_fchmod(const struct kbox_sysnrs *s, long fd, long mode)
{
    return lkl_syscall6(s->fchmod, fd, mode, 0, 0, 0, 0);
}

long kbox_lkl_statfs(const struct kbox_sysnrs *s, const char *path, void *buf)
{
    return lkl_syscall6(s->statfs, (long) path, (long) buf, 0, 0, 0, 0);
}

long kbox_lkl_fstatfs(const struct kbox_sysnrs *s, long fd, void *buf)
{
    return lkl_syscall6(s->fstatfs, fd, (long) buf, 0, 0, 0, 0);
}

long kbox_lkl_fchownat(const struct kbox_sysnrs *s,
                       long dirfd,
                       const char *path,
                       long owner,
                       long group,
                       long flags)
{
    return lkl_syscall6(s->fchownat, dirfd, (long) path, owner, group, flags,
                        0);
}

long kbox_lkl_chroot(const struct kbox_sysnrs *s, const char *path)
{
    return lkl_syscall6(s->chroot, (long) path, 0, 0, 0, 0, 0);
}

long kbox_lkl_chdir(const struct kbox_sysnrs *s, const char *path)
{
    return lkl_syscall6(s->chdir, (long) path, 0, 0, 0, 0, 0);
}

long kbox_lkl_fchdir(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fchdir, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_getcwd(const struct kbox_sysnrs *s, char *buf, long size)
{
    return lkl_syscall6(s->getcwd, (long) buf, size, 0, 0, 0, 0);
}

long kbox_lkl_socket(const struct kbox_sysnrs *s,
                     long domain,
                     long type,
                     long protocol)
{
    return lkl_syscall6(s->socket, domain, type, protocol, 0, 0, 0);
}

long kbox_lkl_connect(const struct kbox_sysnrs *s,
                      long fd,
                      const void *addr,
                      long addrlen)
{
    return lkl_syscall6(s->connect, fd, (long) addr, addrlen, 0, 0, 0);
}

long kbox_lkl_getuid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getuid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_geteuid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->geteuid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_getgid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getgid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_getegid(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->getegid, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_setuid(const struct kbox_sysnrs *s, long uid)
{
    return lkl_syscall6(s->setuid, uid, 0, 0, 0, 0, 0);
}

long kbox_lkl_setreuid(const struct kbox_sysnrs *s, long ruid, long euid)
{
    return lkl_syscall6(s->setreuid, ruid, euid, 0, 0, 0, 0);
}

long kbox_lkl_setresuid(const struct kbox_sysnrs *s,
                        long ruid,
                        long euid,
                        long suid)
{
    return lkl_syscall6(s->setresuid, ruid, euid, suid, 0, 0, 0);
}

long kbox_lkl_setgid(const struct kbox_sysnrs *s, long gid)
{
    return lkl_syscall6(s->setgid, gid, 0, 0, 0, 0, 0);
}

long kbox_lkl_setregid(const struct kbox_sysnrs *s, long rgid, long egid)
{
    return lkl_syscall6(s->setregid, rgid, egid, 0, 0, 0, 0);
}

long kbox_lkl_setresgid(const struct kbox_sysnrs *s,
                        long rgid,
                        long egid,
                        long sgid)
{
    return lkl_syscall6(s->setresgid, rgid, egid, sgid, 0, 0, 0);
}

long kbox_lkl_getgroups(const struct kbox_sysnrs *s, long size, unsigned *list)
{
    return lkl_syscall6(s->getgroups, size, (long) list, 0, 0, 0, 0);
}

long kbox_lkl_setgroups(const struct kbox_sysnrs *s,
                        long size,
                        const unsigned *list)
{
    return lkl_syscall6(s->setgroups, size, (long) list, 0, 0, 0, 0);
}

long kbox_lkl_setfsgid(const struct kbox_sysnrs *s, long gid)
{
    return lkl_syscall6(s->setfsgid, gid, 0, 0, 0, 0, 0);
}

long kbox_lkl_pwrite64(const struct kbox_sysnrs *s,
                       long fd,
                       const void *buf,
                       long len,
                       long offset)
{
    return lkl_syscall6(s->pwrite64, fd, (long) buf, len, offset, 0, 0);
}

long kbox_lkl_readlinkat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         char *buf,
                         long bufsiz)
{
    return lkl_syscall6(s->readlinkat, dirfd, (long) path, (long) buf, bufsiz,
                        0, 0);
}

long kbox_lkl_umask(const struct kbox_sysnrs *s, long mask)
{
    return lkl_syscall6(s->umask, mask, 0, 0, 0, 0, 0);
}

long kbox_lkl_ftruncate(const struct kbox_sysnrs *s, long fd, long length)
{
    return lkl_syscall6(s->ftruncate, fd, length, 0, 0, 0, 0);
}

/* ftruncate that also works where the guest kernel refuses to grow a file.
 *
 * In the pod, ftruncate(2) of a file on an overlay (and on the tmpfs mounted at
 * /tmp) answers -EFBIG once the requested size passes 4 MiB, while writes at
 * the very same offsets are accepted: the file-size check is enforced in
 * do_truncate/notify_change but not in the write path. A 10 MB file written
 * through a shadow therefore came back as 0 bytes, because the copy-back
 * pre-sizes the file with ftruncate before writing it.
 *
 * Growing a file does not actually need ftruncate: one zero byte at the last
 * offset extends it to the same length and leaves the same holes. Only a
 * shrink keeps using ftruncate, and a shrink never leaves the old size.
 */
long kbox_lkl_ftruncate_safe(const struct kbox_sysnrs *s, long fd, long length)
{
    struct kbox_lkl_stat st;
    uint8_t zero = 0;
    long ret;

    memset(&st, 0, sizeof(st));
    if (kbox_lkl_fstat(s, fd, &st) < 0)
        return kbox_lkl_ftruncate(s, fd, length);

    ret = kbox_lkl_ftruncate(s, fd, length);
    if (ret >= 0 || ret != -EFBIG || (long long) st.st_size >= length ||
        length <= 0)
        return ret;

    ret = kbox_lkl_pwrite64(s, fd, &zero, 1, length - 1);
    return ret < 0 ? ret : 0;
}

long kbox_lkl_fallocate(const struct kbox_sysnrs *s,
                        long fd,
                        long mode,
                        long offset,
                        long len)
{
    return lkl_syscall6(s->fallocate, fd, mode, offset, len, 0, 0);
}

long kbox_lkl_flock(const struct kbox_sysnrs *s, long fd, long operation)
{
    return lkl_syscall6(s->flock, fd, operation, 0, 0, 0, 0);
}

long kbox_lkl_fsync(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fsync, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_msync(const struct kbox_sysnrs *s,
                    long addr,
                    long length,
                    long flags)
{
    return lkl_syscall6(s->msync, addr, length, flags, 0, 0, 0);
}

long kbox_lkl_fdatasync(const struct kbox_sysnrs *s, long fd)
{
    return lkl_syscall6(s->fdatasync, fd, 0, 0, 0, 0, 0);
}

long kbox_lkl_sync(const struct kbox_sysnrs *s)
{
    return lkl_syscall6(s->sync, 0, 0, 0, 0, 0, 0);
}

long kbox_lkl_sync_file_range(const struct kbox_sysnrs *s,
                              long fd,
                              long offset,
                              long nbytes,
                              long flags)
{
    return lkl_syscall6(s->sync_file_range, fd, offset, nbytes, flags, 0, 0);
}

long kbox_lkl_symlinkat(const struct kbox_sysnrs *s,
                        const char *target,
                        long newdirfd,
                        const char *linkpath)
{
    return lkl_syscall6(s->symlinkat, (long) target, newdirfd, (long) linkpath,
                        0, 0, 0);
}

long kbox_lkl_linkat(const struct kbox_sysnrs *s,
                     long olddirfd,
                     const char *oldpath,
                     long newdirfd,
                     const char *newpath,
                     long flags)
{
    return lkl_syscall6(s->linkat, olddirfd, (long) oldpath, newdirfd,
                        (long) newpath, flags, 0);
}

long kbox_lkl_utimensat(const struct kbox_sysnrs *s,
                        long dirfd,
                        const char *path,
                        const void *times,
                        long flags)
{
    return lkl_syscall6(s->utimensat, dirfd, (long) path, (long) times, flags,
                        0, 0);
}

/* Socket wrappers. */

long kbox_lkl_bind(const struct kbox_sysnrs *s,
                   long fd,
                   const void *addr,
                   long addrlen)
{
    return lkl_syscall6(s->bind, fd, (long) addr, addrlen, 0, 0, 0);
}

long kbox_lkl_getsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         void *optval,
                         void *optlen)
{
    return lkl_syscall6(s->getsockopt, fd, level, optname, (long) optval,
                        (long) optlen, 0);
}

long kbox_lkl_setsockopt(const struct kbox_sysnrs *s,
                         long fd,
                         long level,
                         long optname,
                         const void *optval,
                         long optlen)
{
    return lkl_syscall6(s->setsockopt, fd, level, optname, (long) optval,
                        optlen, 0);
}

long kbox_lkl_getsockname(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen)
{
    return lkl_syscall6(s->getsockname, fd, (long) addr, (long) addrlen, 0, 0,
                        0);
}

long kbox_lkl_getpeername(const struct kbox_sysnrs *s,
                          long fd,
                          void *addr,
                          void *addrlen)
{
    return lkl_syscall6(s->getpeername, fd, (long) addr, (long) addrlen, 0, 0,
                        0);
}

long kbox_lkl_shutdown(const struct kbox_sysnrs *s, long fd, long how)
{
    return lkl_syscall6(s->shutdown, fd, how, 0, 0, 0, 0);
}

long kbox_lkl_sendto(const struct kbox_sysnrs *s,
                     long fd,
                     const void *buf,
                     long len,
                     long flags,
                     const void *addr,
                     long addrlen)
{
    return lkl_syscall6(s->sendto, fd, (long) buf, len, flags, (long) addr,
                        addrlen);
}

long kbox_lkl_recvfrom(const struct kbox_sysnrs *s,
                       long fd,
                       void *buf,
                       long len,
                       long flags,
                       void *addr,
                       void *addrlen)
{
    return lkl_syscall6(s->recvfrom, fd, (long) buf, len, flags, (long) addr,
                        (long) addrlen);
}

long kbox_lkl_listen(const struct kbox_sysnrs *s, long fd, long backlog)
{
    return lkl_syscall6(s->listen, fd, backlog, 0, 0, 0, 0);
}

long kbox_lkl_accept(const struct kbox_sysnrs *s,
                     long fd,
                     void *addr,
                     void *addrlen)
{
    return lkl_syscall6(s->accept, fd, (long) addr, (long) addrlen, 0, 0, 0);
}

long kbox_lkl_accept4(const struct kbox_sysnrs *s,
                      long fd,
                      void *addr,
                      void *addrlen,
                      long flags)
{
    return lkl_syscall6(s->accept4, fd, (long) addr, (long) addrlen, flags, 0,
                        0);
}

long kbox_lkl_ppoll(const struct kbox_sysnrs *s,
                    void *fds,
                    unsigned long nfds,
                    const void *tmo_p,
                    const void *sigmask,
                    unsigned long sigsetsize)
{
    return lkl_syscall6(s->ppoll, (long) fds, (long) nfds, (long) tmo_p,
                        (long) sigmask, (long) sigsetsize, 0);
}

long kbox_lkl_unshare(const struct kbox_sysnrs *s, long flags)
{
    return lkl_syscall6(s->unshare, flags, 0, 0, 0, 0, 0);
}

long kbox_lkl_prlimit64(const struct kbox_sysnrs *s,
                        long pid,
                        long resource,
                        const void *new_limit)
{
    return lkl_syscall6(s->prlimit64, pid, resource, (long) new_limit, 0, 0, 0);
}

long kbox_lkl_getrlimit(const struct kbox_sysnrs *s,
                        long pid,
                        long resource,
                        void *old_limit)
{
    return lkl_syscall6(s->prlimit64, pid, resource, 0, (long) old_limit, 0, 0);
}

long kbox_lkl_setns(const struct kbox_sysnrs *s, long fd, long nstype)
{
    return lkl_syscall6(s->setns, fd, nstype, 0, 0, 0, 0);
}

long kbox_lkl_sethostname(const struct kbox_sysnrs *s,
                          const char *name,
                          long len)
{
    return lkl_syscall6(s->sethostname, (long) name, len, 0, 0, 0, 0);
}

long kbox_lkl_new_thread_group_leader(const struct kbox_sysnrs *s)
{
    if (s->new_thread_group_leader < 0)
        return -ENOSYS;
    return lkl_syscall6(s->new_thread_group_leader, 0, 0, 0, 0, 0, 0);
}
