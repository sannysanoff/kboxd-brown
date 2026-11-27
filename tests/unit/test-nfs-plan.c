/* SPDX-License-Identifier: MIT */
/* Tests for the NFS bind directory plan. */

#include "kbox/nfs-plan.h"
#include "test-runner.h"

#include <string.h>

/* A compose file binds a config file as a file. Creating either side as a
 * directory made the bind fail with "Not a directory" while the source was a
 * perfectly good regular file, so the whole stack refused to start.
 */
static void test_file_bind_creates_only_the_parent(void)
{
    char src_mkdir[256] = {0};
    char dst_mkdir[256] = {0};
    int is_file = kbox_nfs_bind_plan(
        1, "/kbox-vol/nfs/persist/home/app/docker/monitoring/prometheus.yml",
        "/rootfs/etc/app/prometheus.yml", src_mkdir, sizeof(src_mkdir),
        dst_mkdir, sizeof(dst_mkdir));

    ASSERT_EQ(1, is_file);
    /* The source already exists as a file and must not be mkdir'd. */
    ASSERT_TRUE(src_mkdir[0] == '\0');
    /* Only the destination's parent is created. */
    ASSERT_TRUE(strcmp(dst_mkdir, "/rootfs/etc/app") == 0);
}

/* A directory bind still creates both sides, as before. */
static void test_directory_bind_creates_both(void)
{
    char src_mkdir[256] = {0};
    char dst_mkdir[256] = {0};
    int is_file = kbox_nfs_bind_plan(
        0, "/kbox-vol/nfs/persist/home/app/data", "/rootfs/data", src_mkdir,
        sizeof(src_mkdir), dst_mkdir, sizeof(dst_mkdir));

    ASSERT_EQ(0, is_file);
    ASSERT_TRUE(strcmp(src_mkdir, "/kbox-vol/nfs/persist/home/app/data") == 0);
    ASSERT_TRUE(strcmp(dst_mkdir, "/rootfs/data") == 0);
}

/* A destination directly under the root keeps a usable parent. */
static void test_root_level_destination(void)
{
    char src_mkdir[64];
    char dst_mkdir[64] = {0};
    kbox_nfs_bind_plan(1, "/kbox-vol/x/file.txt", "/file.txt", src_mkdir,
                       sizeof(src_mkdir), dst_mkdir, sizeof(dst_mkdir));
    ASSERT_TRUE(strcmp(dst_mkdir, "/") == 0);
}

void test_nfs_plan_init(void)
{
    TEST_REGISTER(test_file_bind_creates_only_the_parent);
    TEST_REGISTER(test_directory_bind_creates_both);
    TEST_REGISTER(test_root_level_destination);
}
