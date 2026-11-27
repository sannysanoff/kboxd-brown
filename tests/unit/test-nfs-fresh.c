/* SPDX-License-Identifier: MIT */
/* Tests for the fresh-entry bind retry policy. */

#include "kbox/nfs-fresh.h"
#include "test-runner.h"

/* Creating a directory on an export and binding it in the same instant fails
 * with ESTALE or EIO: mkdir succeeded but the client's attribute cache has not
 * confirmed the entry. Retrying is what let the first container of a stack stop
 * dying on `chown -R` over a named volume while every later one worked.
 */
static void test_stale_and_io_are_retried(void)
{
    ASSERT_EQ(1, kbox_nfs_should_retry_bind(116)); /* ESTALE */
    ASSERT_EQ(1, kbox_nfs_should_retry_bind(5));   /* EIO */
    ASSERT_EQ(1, kbox_nfs_should_retry_bind(2));   /* ENOENT: the entry is not
                                                    * visible yet either */
}

/* A permission error is a real answer and must fail at once: sleeping through
 * it would turn a clear EACCES into a two-second stall and then the same
 * failure, which reads as a hung daemon. */
static void test_permission_errors_are_final(void)
{
    ASSERT_EQ(0, kbox_nfs_should_retry_bind(13)); /* EACCES */
    ASSERT_EQ(0, kbox_nfs_should_retry_bind(1));  /* EPERM */
    ASSERT_EQ(0, kbox_nfs_should_retry_bind(22)); /* EINVAL */
    ASSERT_EQ(0, kbox_nfs_should_retry_bind(0));  /* success */
}

/* The delay has to grow so a slow server gets progressively more room, and it
 * has to stay bounded so a broken export still fails quickly. */
static void test_delay_grows_and_is_bounded(void)
{
    int first = kbox_nfs_bind_delay_ms(0);
    ASSERT_TRUE(first >= 0);
    ASSERT_TRUE(kbox_nfs_bind_delay_ms(3) > kbox_nfs_bind_delay_ms(1));
    ASSERT_TRUE(kbox_nfs_bind_delay_ms(1) > kbox_nfs_bind_delay_ms(0));
    /* The whole ladder must finish well inside a container start budget. */
    int total = 0;
    for (int i = 0; i < 12; i++)
        total += kbox_nfs_bind_delay_ms(i);
    ASSERT_TRUE(total <= 5000);
}

void test_nfs_fresh_init(void)
{
    TEST_REGISTER(test_stale_and_io_are_retried);
    TEST_REGISTER(test_permission_errors_are_final);
    TEST_REGISTER(test_delay_grows_and_is_bounded);
}
