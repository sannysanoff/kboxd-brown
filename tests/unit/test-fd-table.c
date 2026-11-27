/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <string.h>

#include "fd-table.h"
#include "test-runner.h"

static void test_fd_table_init_zeros(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    ASSERT_EQ(t.next_fd, 0);
    for (int i = 0; i < KBOX_FD_TABLE_CAPACITY; i++) {
        ASSERT_EQ(t.slots[i].lkl_fd, -1);
        ASSERT_EQ(t.slots[i].flags, KBOX_FD_FLAG_NONE);
    }
}

static void test_fd_table_insert_basic(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    ASSERT_EQ(vfd, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 42);
}

static void test_fd_table_insert_sequential(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 0);
    long vfd3 = kbox_fd_table_insert(&t, 30, 0);
    ASSERT_EQ(vfd1, 0);
    ASSERT_EQ(vfd2, 1);
    ASSERT_EQ(vfd3, 2);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd1), 10);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd2), 20);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd3), 30);
}

static void test_fd_table_remove(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 99, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 99);
    long old = kbox_fd_table_remove(&t, vfd);
    ASSERT_EQ(old, 99);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), -1);
}

static void test_fd_table_remove_nonexistent(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long old = kbox_fd_table_remove(&t, KBOX_FD_TABLE_CAPACITY + 500);
    ASSERT_EQ(old, -1);
}

static void test_fd_table_insert_at(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    int rc = kbox_fd_table_insert_at(&t, 1234, 77, 1);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 1234), 77);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, 1234));
}

static void test_fd_table_mirror_tty(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 1);
    ASSERT_TRUE(!kbox_fd_table_mirror_tty(&t, vfd1));
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, vfd2));
}

static void test_fd_table_cloexec(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 55, 0);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 0);
    kbox_fd_table_set_cloexec(&t, vfd, 1);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 1);
    kbox_fd_table_set_cloexec(&t, vfd, 0);
    ASSERT_EQ(kbox_fd_table_get_cloexec(&t, vfd), 0);
}

static void test_fd_table_out_of_range(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    /* Every number below the ceiling is trackable; nothing is reserved. */
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 0), -1);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 1023), -1);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_FD_TABLE_CAPACITY - 1), -1);
    /* Above range */
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, KBOX_FD_TABLE_CAPACITY), -1);
}

static void test_fd_table_insert_at_arbitrary(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);

    /* Stdin redirect via dup2 */
    int rc = kbox_fd_table_insert_at(&t, 0, 10, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 0), 10);

    /* Arbitrary descriptor numbers are ordinary slots. */
    rc = kbox_fd_table_insert_at(&t, 100, 55, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 100), 55);

    rc = kbox_fd_table_insert_at(&t, 2000, 77, 1);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 2000), 77);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, 2000));

    /* Remove and reverse-map host_fd operations */
    long old = kbox_fd_table_remove(&t, 100);
    ASSERT_EQ(old, 55);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 100), -1);

    kbox_fd_table_set_host_fd(&t, 0, 42);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, 0), 42);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 42), 0);
}

static void test_fd_table_overwrite_at(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 10, 0);
    kbox_fd_table_insert_at(&t, vfd, 20, 1);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, vfd), 20);
    ASSERT_TRUE(kbox_fd_table_mirror_tty(&t, vfd));
}

static void test_fd_table_host_fd_init(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    for (int i = 0; i < KBOX_FD_TABLE_CAPACITY; i++)
        ASSERT_EQ(t.slots[i].host_fd, -1);
}

static void test_fd_table_host_fd_default(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), -1);
}

static void test_fd_table_set_get_host_fd(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    kbox_fd_table_set_host_fd(&t, vfd, 99);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), 99);
}

static void test_fd_table_find_by_host_fd(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd1 = kbox_fd_table_insert(&t, 10, 0);
    long vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd2, 77);

    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 77), vfd2);
    /* vfd1 has no host_fd set; should not match */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, -1), -1);

    (void) vfd1;
}

static void test_fd_table_find_by_host_fd_unknown(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    kbox_fd_table_insert(&t, 10, 0);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 999), -1);
}

static void test_fd_table_remove_resets_host_fd(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);
    long vfd = kbox_fd_table_insert(&t, 42, 0);
    kbox_fd_table_set_host_fd(&t, vfd, 88);
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), 88);
    kbox_fd_table_remove(&t, vfd);
    /* After removal, slot is free; get_host_fd returns -1. */
    ASSERT_EQ(kbox_fd_table_get_host_fd(&t, vfd), -1);
    /* Reverse lookup should also fail. */
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 88), -1);
}

static void test_fd_table_find_by_host_fd_duplicate_holder_survives(void)
{
    /* After duplicate set_host_fd the reverse map enters the MULTI
     * sentinel state and find_by_host_fd falls through to the linear
     * scan, which returns the first matching entry in scan order.
     * Once one holder is removed, the remaining holder is still
     * findable (via either the fast path or the slow scan).
     */
    static struct kbox_fd_table t;
    long vfd1;
    long vfd2;
    long found;

    kbox_fd_table_init(&t);
    vfd1 = kbox_fd_table_insert(&t, 10, 0);
    vfd2 = kbox_fd_table_insert(&t, 20, 0);
    kbox_fd_table_set_host_fd(&t, vfd1, 77);
    kbox_fd_table_set_host_fd(&t, vfd2, 77);

    found = kbox_fd_table_find_by_host_fd(&t, 77);
    ASSERT_TRUE(found == vfd1 || found == vfd2);
    ASSERT_EQ(kbox_fd_table_remove(&t, vfd2), 20);
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 77), vfd1);
}

static void test_fd_table_find_by_host_fd_requires_api(void)
{
    /* Invariant: positive host_fd values must be installed via
     * kbox_fd_table_set_host_fd so the O(1) reverse map stays
     * consistent. Direct writes to entry->host_fd with positive
     * values bypass the reverse map and are intentionally not
     * findable; the authoritative-NONE fast path in
     * find_by_host_fd returns -1 without scanning. Only the
     * negative sentinel values (KBOX_FD_HOST_SAME_FD_SHADOW and
     * KBOX_FD_LOCAL_ONLY_SHADOW) may be written directly, and
     * only on entries whose host_fd is already negative.
     */
    static struct kbox_fd_table t;
    long vfd;

    kbox_fd_table_init(&t);
    vfd = kbox_fd_table_insert(&t, 10, 0);
    t.slots[vfd].host_fd = 123;
    ASSERT_EQ(kbox_fd_table_find_by_host_fd(&t, 123), -1);
}

/* A descriptor's identity is the hash of its /proc link target. Two names for
 * the same object must hash alike, and anything else must not, because the
 * value decides whether an entry is dropped as reused. */
static void test_fd_link_identity_same_target(void)
{
    ASSERT_EQ(kbox_fd_link_identity("/data/report.txt"),
              kbox_fd_link_identity("/data/report.txt"));
}

static void test_fd_link_identity_different_targets(void)
{
    ASSERT_NE(kbox_fd_link_identity("/data/report.txt"),
              kbox_fd_link_identity("/data/report.txt.bak"));
    ASSERT_NE(kbox_fd_link_identity("pipe:[1234]"),
              kbox_fd_link_identity("pipe:[1235]"));
}

static void test_fd_link_identity_is_never_zero(void)
{
    ASSERT_TRUE(kbox_fd_link_identity("/") != 0);
    ASSERT_TRUE(kbox_fd_link_identity("pipe:[1]") != 0);
    ASSERT_TRUE(kbox_fd_link_identity("socket:[7]") != 0);
}

static void test_fd_link_identity_empty(void)
{
    ASSERT_EQ(kbox_fd_link_identity(NULL), 0);
    ASSERT_EQ(kbox_fd_link_identity(""), 0);
}

/* The value is part of the protocol between entry creation and routing, so a
 * stable input is pinned here: changing the hash without meaning to would make
 * every recorded identity stop matching. */
static void test_fd_link_identity_golden(void)
{
    ASSERT_EQ(kbox_fd_link_identity("pipe:[1234]"), 0xe35d2686a9917b57ULL);
}

/* The reuse decision, including the one subtle case: a failed read drops the
 * entry only when the descriptor is really gone. */
static void test_fd_identity_stale(void)
{
    uint64_t id = kbox_fd_link_identity("/data/a");

    ASSERT_TRUE(!kbox_fd_identity_stale(0, 0, ENOENT));
    ASSERT_TRUE(!kbox_fd_identity_stale(0, id, 0));
    ASSERT_TRUE(!kbox_fd_identity_stale(id, id, 0));
    ASSERT_TRUE(
        kbox_fd_identity_stale(id, kbox_fd_link_identity("/data/b"), 0));
    ASSERT_TRUE(kbox_fd_identity_stale(id, 0, ENOENT));
    ASSERT_TRUE(kbox_fd_identity_stale(id, 0, EBADF));
    ASSERT_TRUE(!kbox_fd_identity_stale(id, 0, EACCES));
    ASSERT_TRUE(!kbox_fd_identity_stale(id, 0, 0));
}

static void test_fd_stat_identity(void)
{
    uint64_t a = kbox_fd_stat_identity(10, 200);
    uint64_t b = kbox_fd_stat_identity(10, 201);
    uint64_t c = kbox_fd_stat_identity(11, 200);

    ASSERT_EQ(a, kbox_fd_stat_identity(10, 200));
    ASSERT_NE(a, b);
    ASSERT_NE(a, c);
    ASSERT_TRUE(a != 0);
    ASSERT_TRUE(kbox_fd_stat_identity(0, 0) != 0);
}

static void test_fd_table_low_host_bitmap(void)
{
    static struct kbox_fd_table t;
    long vfd1, vfd2;
    size_t word;
    uint64_t expected;

    kbox_fd_table_init(&t);
    ASSERT_EQ(t.low_host_count, 0);
    vfd1 = kbox_fd_table_insert(&t, 10, 0);
    vfd2 = kbox_fd_table_insert(&t, 20, 0);
    word = (size_t) vfd1 >> 6;
    expected =
        (1ULL << ((size_t) vfd1 & 63U)) | (1ULL << ((size_t) vfd2 & 63U));
    kbox_fd_table_set_host_fd(&t, vfd1, 7);
    kbox_fd_table_set_host_fd(&t, vfd2, 8);
    ASSERT_EQ(t.low_host_count, 2);
    ASSERT_TRUE((t.low_host_bitmap[word] & expected) == expected);
    kbox_fd_table_remove(&t, vfd1);
    ASSERT_EQ(t.low_host_count, 1);
    kbox_fd_table_set_host_fd(&t, vfd2, -1);
    ASSERT_EQ(t.low_host_count, 0);
    ASSERT_EQ(t.low_host_bitmap[word], 0ULL);
}

static void test_fd_table_insert_lowest_and_from(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);

    /* Lowest free slot on clean table is 0 */
    long fd0 = kbox_fd_table_insert_lowest(&t, 100, 0);
    ASSERT_EQ(fd0, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 0), 100);

    /* Next lowest is 1 */
    long fd1 = kbox_fd_table_insert_lowest(&t, 101, 0);
    ASSERT_EQ(fd1, 1);

    /* Insert from min_fd 5 */
    long fd5 = kbox_fd_table_insert_from(&t, 5, 105, 0);
    ASSERT_EQ(fd5, 5);

    /* Remove slot 0, then lowest should reuse slot 0 */
    kbox_fd_table_remove(&t, 0);
    long fd_reuse = kbox_fd_table_insert_lowest(&t, 200, 0);
    ASSERT_EQ(fd_reuse, 0);
    ASSERT_EQ(kbox_fd_table_get_lkl(&t, 0), 200);
}

static void test_fd_table_ownership_flags(void)
{
    static struct kbox_fd_table t;
    kbox_fd_table_init(&t);

    /* LKL-backed slot */
    long lkl_vfd = kbox_fd_table_insert_lowest(&t, 42, 0);
    ASSERT_EQ(lkl_vfd, 0);
    ASSERT_TRUE(kbox_fd_entry_is_active(&t.slots[lkl_vfd]));
    ASSERT_TRUE(kbox_fd_entry_is_lkl(&t.slots[lkl_vfd]));
    ASSERT_TRUE(!kbox_fd_entry_is_host(&t.slots[lkl_vfd]));

    /* Host-managed slot */
    ASSERT_EQ(kbox_fd_table_insert_at(&t, 3, KBOX_LKL_FD_SHADOW_ONLY, 0), 0);
    ASSERT_TRUE(kbox_fd_entry_is_active(&t.slots[3]));
    ASSERT_TRUE(kbox_fd_entry_is_host(&t.slots[3]));
    ASSERT_TRUE(!kbox_fd_entry_is_lkl(&t.slots[3]));

    /* Shadow flag tracks host_fd */
    kbox_fd_table_set_host_fd(&t, lkl_vfd, 77);
    ASSERT_TRUE((t.slots[lkl_vfd].flags & KBOX_FD_FLAG_SHADOW) != 0);
    kbox_fd_table_set_host_fd(&t, lkl_vfd, -1);
    ASSERT_TRUE((t.slots[lkl_vfd].flags & KBOX_FD_FLAG_SHADOW) == 0);

    /* Removal clears all flags */
    kbox_fd_table_remove(&t, lkl_vfd);
    ASSERT_TRUE(!kbox_fd_entry_is_active(&t.slots[lkl_vfd]));
    ASSERT_EQ(t.slots[lkl_vfd].flags, KBOX_FD_FLAG_NONE);
}

void test_fd_table_init(void)
{
    TEST_REGISTER(test_fd_table_init_zeros);
    TEST_REGISTER(test_fd_table_insert_basic);
    TEST_REGISTER(test_fd_table_insert_sequential);
    TEST_REGISTER(test_fd_table_remove);
    TEST_REGISTER(test_fd_table_remove_nonexistent);
    TEST_REGISTER(test_fd_table_insert_at);
    TEST_REGISTER(test_fd_table_mirror_tty);
    TEST_REGISTER(test_fd_table_cloexec);
    TEST_REGISTER(test_fd_table_out_of_range);
    TEST_REGISTER(test_fd_table_insert_at_arbitrary);
    TEST_REGISTER(test_fd_table_overwrite_at);
    TEST_REGISTER(test_fd_table_host_fd_init);
    TEST_REGISTER(test_fd_table_host_fd_default);
    TEST_REGISTER(test_fd_table_set_get_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd_unknown);
    TEST_REGISTER(test_fd_table_remove_resets_host_fd);
    TEST_REGISTER(test_fd_table_find_by_host_fd_duplicate_holder_survives);
    TEST_REGISTER(test_fd_table_find_by_host_fd_requires_api);
    TEST_REGISTER(test_fd_link_identity_same_target);
    TEST_REGISTER(test_fd_link_identity_different_targets);
    TEST_REGISTER(test_fd_link_identity_is_never_zero);
    TEST_REGISTER(test_fd_link_identity_empty);
    TEST_REGISTER(test_fd_link_identity_golden);
    TEST_REGISTER(test_fd_identity_stale);
    TEST_REGISTER(test_fd_stat_identity);
    TEST_REGISTER(test_fd_table_low_host_bitmap);
    TEST_REGISTER(test_fd_table_insert_lowest_and_from);
    TEST_REGISTER(test_fd_table_ownership_flags);
}
