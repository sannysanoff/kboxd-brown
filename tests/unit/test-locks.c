/* SPDX-License-Identifier: MIT */
#include <fcntl.h>
#include <stdint.h>

#include "kbox/locks.h"
#include "test-runner.h"

static void test_lock_range_positive_len(void)
{
    int64_t first = 0, last = 0;

    ASSERT_EQ(kbox_lock_range(100, 10, &first, &last), 0);
    ASSERT_EQ(first, 100);
    ASSERT_EQ(last, 109);
}

static void test_lock_range_zero_len_is_to_eof(void)
{
    int64_t first = 0, last = 0;

    ASSERT_EQ(kbox_lock_range(4096, 0, &first, &last), 0);
    ASSERT_EQ(first, 4096);
    ASSERT_EQ(last, INT64_MAX);
}

static void test_lock_range_negative_len_covers_bytes_before_start(void)
{
    int64_t first = 0, last = 0;

    ASSERT_EQ(kbox_lock_range(200, -50, &first, &last), 0);
    ASSERT_EQ(first, 150);
    ASSERT_EQ(last, 199);
}

static void test_lock_range_rejects_negative_start(void)
{
    int64_t first = 0, last = 0;

    ASSERT_EQ(kbox_lock_range(-1, 10, &first, &last), -1);
}

/* A read lock and a read lock share the file. */
static void test_lock_conflict_read_read_is_free(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_RDLCK, 0, 99), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_RDLCK, 0, 99, NULL), 0);
}

/* A write lock excludes a read lock on the same bytes. */
static void test_lock_conflict_write_vs_read(void)
{
    struct kbox_lock_table t;
    struct kbox_lock hit;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 10, 20), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_RDLCK, 15, 25, &hit), 1);
    ASSERT_EQ(hit.pid, 100);
    ASSERT_EQ(hit.type, F_WRLCK);
    ASSERT_EQ(hit.start, 10);
    ASSERT_EQ(hit.end, 20);
}

static void test_lock_conflict_disjoint_ranges_are_free(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 10, 20), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 21, 30, NULL), 0);
}

static void test_lock_conflict_same_process_is_free(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 10, 20), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 100, -1, 1, 1, F_RDLCK, 10, 20, NULL), 0);
}

static void test_lock_conflict_on_another_inode_is_free(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 0, 0), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 2, F_WRLCK, 0, 0, NULL), 0);
}

static void test_lock_to_eof_conflicts_with_later_range(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 4096, INT64_MAX), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 9000, 9000, NULL),
              1);
}

/* An explicit unlock removes only the bytes it names. */
static void test_lock_unlock_middle_splits(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 0, 99), 0);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_UNLCK, 40, 59), 0);
    /* Both sides still conflict for another process. */
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 10, 10, NULL), 1);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 50, 50, NULL), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 90, 90, NULL), 1);
}

static void test_lock_unlock_left_edge_keeps_remainder(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 0, 99), 0);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_UNLCK, 0, 49), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 20, 20, NULL), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 60, 60, NULL), 1);
}

static void test_lock_release_file_drops_posix_locks(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 0, 99), 0);
    kbox_lock_release_file(&t, 100, -1, 1, 1);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 0, 99, NULL), 0);
}

static void test_lock_release_pid_drops_every_held_lock(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 1, F_WRLCK, 0, 9), 0);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 2, F_WRLCK, 0, 9), 0);
    kbox_lock_release_pid(&t, 100);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 1, F_WRLCK, 0, 9, NULL), 0);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 2, F_WRLCK, 0, 9, NULL), 0);
}

/* OFD locks belong to the open file description, not the process, and always
 * conflict with a POSIX lock taken on the same bytes. */
static void test_lock_ofd_and_posix_owners(void)
{
    struct kbox_lock_table t;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, 7, 1, 1, F_WRLCK, 0, 9), 0);
    /* Same description in another process: no conflict. */
    ASSERT_EQ(kbox_lock_conflict(&t, 200, 7, 1, 1, F_WRLCK, 0, 9, NULL), 0);
    /* Another description: conflict. */
    ASSERT_EQ(kbox_lock_conflict(&t, 200, 8, 1, 1, F_WRLCK, 0, 9, NULL), 1);
    /* A POSIX lock in the same process conflicts with the OFD lock. */
    ASSERT_EQ(kbox_lock_conflict(&t, 100, -1, 1, 1, F_WRLCK, 0, 9, NULL), 1);
}

static void test_lock_tag_fd_stamps_owner_slots(void)
{
    struct kbox_lock_table t;
    struct kbox_lock hit;

    kbox_lock_init(&t);
    ASSERT_EQ(kbox_lock_apply(&t, 100, -1, 1, 5, F_WRLCK, 0, 19), 0);
    kbox_lock_tag_fd(&t, 100, -1, 1, 5, 9, 0x1234ULL);
    ASSERT_EQ(kbox_lock_conflict(&t, 200, -1, 1, 5, F_WRLCK, 0, 19, &hit), 1);
    ASSERT_EQ(hit.guest_fd, 9);
    ASSERT_EQ(hit.guest_id, 0x1234ULL);
}

void test_locks_init(void)
{
    TEST_REGISTER(test_lock_range_positive_len);
    TEST_REGISTER(test_lock_range_zero_len_is_to_eof);
    TEST_REGISTER(test_lock_range_negative_len_covers_bytes_before_start);
    TEST_REGISTER(test_lock_range_rejects_negative_start);
    TEST_REGISTER(test_lock_conflict_read_read_is_free);
    TEST_REGISTER(test_lock_conflict_write_vs_read);
    TEST_REGISTER(test_lock_conflict_disjoint_ranges_are_free);
    TEST_REGISTER(test_lock_conflict_same_process_is_free);
    TEST_REGISTER(test_lock_conflict_on_another_inode_is_free);
    TEST_REGISTER(test_lock_to_eof_conflicts_with_later_range);
    TEST_REGISTER(test_lock_unlock_middle_splits);
    TEST_REGISTER(test_lock_unlock_left_edge_keeps_remainder);
    TEST_REGISTER(test_lock_release_file_drops_posix_locks);
    TEST_REGISTER(test_lock_release_pid_drops_every_held_lock);
    TEST_REGISTER(test_lock_ofd_and_posix_owners);
    TEST_REGISTER(test_lock_tag_fd_stamps_owner_slots);
}
