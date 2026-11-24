/* SPDX-License-Identifier: MIT */

#include "syscall-nr.h"
#include "test-runner.h"

static void test_x86_64_openat(void)
{
    ASSERT_EQ(SYSNRS_X86_64.openat, 257);
}

static void test_x86_64_read(void)
{
    ASSERT_EQ(SYSNRS_X86_64.read, 0);
}

static void test_x86_64_write(void)
{
    ASSERT_EQ(SYSNRS_X86_64.write, 1);
}

static void test_x86_64_close(void)
{
    ASSERT_EQ(SYSNRS_X86_64.close, 3);
}

static void test_x86_64_execve(void)
{
    ASSERT_EQ(SYSNRS_X86_64.execve, 59);
}

static void test_x86_64_mkdirat_style(void)
{
    ASSERT_TRUE(!SYSNRS_X86_64.mkdirat_style);
}

static void test_generic_openat(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.openat, 56);
}

static void test_generic_read(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.read, 63);
}

static void test_generic_write(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.write, 64);
}

static void test_generic_close(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.close, 57);
}

static void test_generic_mkdirat_style(void)
{
    ASSERT_TRUE(SYSNRS_GENERIC.mkdirat_style);
}

static void test_generic_getdents_unavailable(void)
{
    /* aarch64/generic has no legacy getdents, only getdents64 */
    ASSERT_EQ(SYSNRS_GENERIC.getdents, -1);
    ASSERT_EQ(SYSNRS_GENERIC.getdents64, 61);
}

static void test_host_x86_64_sendmsg(void)
{
    ASSERT_EQ(HOST_NRS_X86_64.sendmsg, 46);
}

static void test_host_aarch64_gettimeofday(void)
{
    ASSERT_EQ(HOST_NRS_GENERIC.gettimeofday, 169);
}

static void test_host_aarch64_no_open(void)
{
    /* aarch64 has no legacy open syscall */
    ASSERT_EQ(HOST_NRS_GENERIC.open, -1);
    ASSERT_EQ(HOST_NRS_GENERIC.stat, -1);
    ASSERT_EQ(HOST_NRS_GENERIC.lstat, -1);
}

static void test_at_fdcwd(void)
{
    ASSERT_EQ(AT_FDCWD_LINUX, -100L);
}

static void test_host_cap_syscalls(void)
{
    ASSERT_EQ(HOST_NRS_X86_64.capget, 125);
    ASSERT_EQ(HOST_NRS_X86_64.capset, 126);
    ASSERT_EQ(HOST_NRS_GENERIC.capget, 90);
    ASSERT_EQ(HOST_NRS_GENERIC.capset, 91);
}

static void test_host_statfs_fchmod_fadvise_syscalls(void)
{
    ASSERT_EQ(HOST_NRS_X86_64.statfs, 137);
    ASSERT_EQ(HOST_NRS_GENERIC.statfs, 43);
    ASSERT_EQ(HOST_NRS_X86_64.fchmod, 91);
    ASSERT_EQ(HOST_NRS_GENERIC.fchmod, 52);
    ASSERT_EQ(HOST_NRS_X86_64.fadvise64, 221);
    ASSERT_EQ(HOST_NRS_GENERIC.fadvise64, 223);
    ASSERT_EQ(HOST_NRS_X86_64.rt_sigsuspend, 130);
    ASSERT_EQ(HOST_NRS_GENERIC.rt_sigsuspend, 133);
    ASSERT_EQ(HOST_NRS_X86_64.rt_sigtimedwait, 128);
    ASSERT_EQ(HOST_NRS_GENERIC.rt_sigtimedwait, 137);
    ASSERT_EQ(HOST_NRS_X86_64.socketpair, 53);
    ASSERT_EQ(HOST_NRS_GENERIC.socketpair, 199);
    ASSERT_EQ(HOST_NRS_X86_64.timer_create, 222);
    ASSERT_EQ(HOST_NRS_GENERIC.timer_create, 107);
    ASSERT_EQ(HOST_NRS_X86_64.lgetxattr, 192);
    ASSERT_EQ(HOST_NRS_GENERIC.lgetxattr, 9);
}

/* busybox tar sets a directory's mode with fchmodat(AT_SYMLINK_NOFOLLOW),
 * which musl implements as fchmodat2 and, on ENOSYS, as chmod of
 * /proc/self/fd/N. The fallback could not resolve a virtual descriptor, so
 * every directory entry failed with ENOENT. The number must be in both tables,
 * for both architectures, or the same path breaks silently again.
 */
static void test_fchmodat2_numbers(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.fchmodat2, 452);
    ASSERT_EQ(SYSNRS_X86_64.fchmodat2, 452);
    ASSERT_EQ(HOST_NRS_GENERIC.fchmodat2, 452);
    ASSERT_EQ(HOST_NRS_X86_64.fchmodat2, 452);
}

static void test_sync_file_range_numbers(void)
{
    /* redis 7 calls sync_file_range while saving an RDB and treats an error as
     * a fatal write failure. It was not in any table, so kbox denied it with
     * ENOSYS and every save of a large database failed. The number must match
     * the architecture the guest reports, or the call would be denied again or
     * land on a different system call. */
    ASSERT_EQ(SYSNRS_GENERIC.sync_file_range, 84);
    ASSERT_EQ(HOST_NRS_GENERIC.sync_file_range, 84);
    ASSERT_EQ(SYSNRS_X86_64.sync_file_range, 277);
    ASSERT_EQ(HOST_NRS_X86_64.sync_file_range, 277);
}

/* The fresh-task retry may only re-run descriptor I/O. A task created from a
 * bare supervisor thread carries no container root, so a path call there
 * answers ENOENT for files the container can see. MariaDB lost 79 tests to
 * exactly that: an execve that answered EINTR was re-run on a fresh task. */
static void test_fresh_task_only_for_fd_file_io(void)
{
    struct kbox_host_nrs h;

    memset(&h, 0, sizeof(h));
    h.read = 63;
    h.write = 64;
    h.pread64 = 67;
    h.pwrite64 = 68;
    h.readv = 65;
    h.writev = 66;
    h.preadv = 69;
    h.pwritev = 70;
    h.execve = 221;
    h.execveat = 281;
    h.openat = 56;
    h.newfstatat = 79;

    ASSERT_EQ(kbox_nr_is_fd_file_io(63, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(64, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(67, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(68, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(65, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(66, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(69, &h), 1);
    ASSERT_EQ(kbox_nr_is_fd_file_io(70, &h), 1);

    ASSERT_EQ(kbox_nr_is_fd_file_io(221, &h), 0);
    ASSERT_EQ(kbox_nr_is_fd_file_io(281, &h), 0);
    ASSERT_EQ(kbox_nr_is_fd_file_io(56, &h), 0);
    ASSERT_EQ(kbox_nr_is_fd_file_io(79, &h), 0);
    ASSERT_EQ(kbox_nr_is_fd_file_io(-1, &h), 0);
    ASSERT_EQ(kbox_nr_is_fd_file_io(63, NULL), 0);
}

void test_syscall_nr_init(void)
{
    TEST_REGISTER(test_x86_64_openat);
    TEST_REGISTER(test_x86_64_read);
    TEST_REGISTER(test_x86_64_write);
    TEST_REGISTER(test_x86_64_close);
    TEST_REGISTER(test_x86_64_execve);
    TEST_REGISTER(test_x86_64_mkdirat_style);
    TEST_REGISTER(test_generic_openat);
    TEST_REGISTER(test_generic_read);
    TEST_REGISTER(test_generic_write);
    TEST_REGISTER(test_generic_close);
    TEST_REGISTER(test_generic_mkdirat_style);
    TEST_REGISTER(test_generic_getdents_unavailable);
    TEST_REGISTER(test_host_x86_64_sendmsg);
    TEST_REGISTER(test_host_aarch64_gettimeofday);
    TEST_REGISTER(test_host_aarch64_no_open);
    TEST_REGISTER(test_at_fdcwd);
    TEST_REGISTER(test_host_cap_syscalls);
    TEST_REGISTER(test_host_statfs_fchmod_fadvise_syscalls);
    TEST_REGISTER(test_sync_file_range_numbers);
    TEST_REGISTER(test_fchmodat2_numbers);
    TEST_REGISTER(test_fresh_task_only_for_fd_file_io);
}
