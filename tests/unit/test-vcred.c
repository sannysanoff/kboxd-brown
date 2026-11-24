/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test-runner.h"
#include "vcred.h"

#define P 910001 /* a pid nothing else uses; its /proc entry does not exist */

static void test_new_pid_is_root(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 0);
    ASSERT_EQ(c.euid, 0);
    ASSERT_EQ(c.egid, 0);
}

static void test_root_setuid_sets_all_ids(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setuid(P, 999), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 999);
    ASSERT_EQ(c.euid, 999);
    ASSERT_EQ(c.suid, 999);
}

static void test_nonroot_cannot_regain_root(void)
{
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgid(P, 999), 0);
    ASSERT_EQ(kbox_vcred_setuid(P, 999), 0); /* the gosu sequence */
    ASSERT_EQ(kbox_vcred_setuid(P, 0), -EPERM);
    ASSERT_EQ(kbox_vcred_setresuid(P, 0, 0, 0), -EPERM);
}

static void test_nonroot_can_swap_within_set(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setresuid(P, 5, 6, 7), 0);
    ASSERT_EQ(kbox_vcred_setresuid(P, 6, 7, 5), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 6);
    ASSERT_EQ(c.euid, 7);
    ASSERT_EQ(c.suid, 5);
}

static void test_setreuid_minus_one_keeps_value(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setreuid(P, -1, 42), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.ruid, 0);
    ASSERT_EQ(c.euid, 42);
    ASSERT_EQ(c.suid, 42); /* e differs from the old real id */
}

static void test_group_ids_follow_euid_privilege(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgid(P, 101), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.egid, 101);
    ASSERT_EQ(kbox_vcred_setuid(P, 101), 0);
    /* setpriv drops the uid first, then the gid, relying on kept capabilities:
     * a process that was root may still change group ids ... */
    ASSERT_EQ(kbox_vcred_setresgid(P, 102, 102, 102), 0);
    /* ... but never regain uid 0. */
    ASSERT_EQ(kbox_vcred_setuid(P, 0), -EPERM);
}

static void test_setpriv_order_uid_then_gid(void)
{
    struct kbox_vcred c;
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setresuid(P, 999, 999, 999), 0);
    ASSERT_EQ(kbox_vcred_setresgid(P, 1000, 1000, 1000), 0);
    kbox_vcred_get(P, &c);
    ASSERT_EQ(c.euid, 999);
    ASSERT_EQ(c.egid, 1000);
}

static void test_owner_overlay_wins(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 12345;
    st.st_uid = getuid();
    st.st_gid = getgid();
    kbox_owner_set(7, 12345, 999, 998);
    kbox_owner_apply(P, &st);
    ASSERT_EQ(st.st_uid, 999);
    ASSERT_EQ(st.st_gid, 998);
}

static void test_owner_default_follows_caller(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 777;
    st.st_uid = getuid();
    st.st_gid = getgid();
    kbox_owner_apply(P, &st); /* root caller: file looks root-owned */
    ASSERT_EQ(st.st_uid, 0);
    st.st_uid = getuid();
    ASSERT_EQ(kbox_vcred_setuid(P, 101), 0);
    kbox_owner_apply(P, &st); /* uid 101 caller: file looks owned by it */
    ASSERT_EQ(st.st_uid, 101);
}

static void test_owner_foreign_uid_untouched(void)
{
    struct stat st = {0};
    kbox_vcred_reset_for_test();
    st.st_dev = 7;
    st.st_ino = 778;
    st.st_uid = getuid() + 12345;
    kbox_owner_apply(P, &st);
    ASSERT_EQ(st.st_uid, getuid() + 12345);
}

static void test_default_group_list_is_effective_gid(void)
{
    uint32_t out[KBOX_VCRED_MAX_GROUPS];
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgid(P, 77), 0);
    ASSERT_EQ(kbox_vcred_group_count(P), 1);
    ASSERT_EQ(kbox_vcred_getgroups(P, KBOX_VCRED_MAX_GROUPS, out), 1);
    ASSERT_EQ(out[0], 77);
}

static void test_setgroups_replaces_the_list(void)
{
    uint32_t groups[16];
    uint32_t out[KBOX_VCRED_MAX_GROUPS];

    kbox_vcred_reset_for_test();
    for (int i = 0; i < 16; i++)
        groups[i] = (uint32_t) i;
    ASSERT_EQ(kbox_vcred_setgroups(P, 16, groups), 0);
    ASSERT_EQ(kbox_vcred_group_count(P), 16);
    ASSERT_EQ(kbox_vcred_getgroups(P, KBOX_VCRED_MAX_GROUPS, out), 16);
    for (int i = 0; i < 16; i++)
        ASSERT_EQ(out[i], (uint32_t) i);
}

static void test_setgroups_empty_list_is_legal(void)
{
    uint32_t groups[2] = {5, 6};
    uint32_t out[KBOX_VCRED_MAX_GROUPS];

    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgroups(P, 2, groups), 0);
    ASSERT_EQ(kbox_vcred_setgroups(P, 0, NULL), 0);
    ASSERT_EQ(kbox_vcred_group_count(P), 0);
    ASSERT_EQ(kbox_vcred_getgroups(P, KBOX_VCRED_MAX_GROUPS, out), 0);
}

static void test_setgroups_allowed_after_dropping_root(void)
{
    uint32_t groups[2] = {3, 4};
    uint32_t out[KBOX_VCRED_MAX_GROUPS];

    /* gosu and setpriv drop the uid first and change groups afterwards, which
     * the model permits once the process has held root. */
    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setuid(P, 999), 0);
    ASSERT_EQ(kbox_vcred_setgroups(P, 2, groups), 0);
    ASSERT_EQ(kbox_vcred_getgroups(P, KBOX_VCRED_MAX_GROUPS, out), 2);
    ASSERT_EQ(out[0], 3);
    ASSERT_EQ(out[1], 4);
}

static void test_getgroups_rejects_small_buffer(void)
{
    uint32_t groups[4] = {1, 2, 3, 4};
    uint32_t out[KBOX_VCRED_MAX_GROUPS];

    kbox_vcred_reset_for_test();
    ASSERT_EQ(kbox_vcred_setgroups(P, 4, groups), 0);
    ASSERT_EQ(kbox_vcred_getgroups(P, 2, out), -EINVAL);
}

static void test_setgroups_rejects_oversized_list(void)
{
    uint32_t groups[KBOX_VCRED_MAX_GROUPS + 1];

    kbox_vcred_reset_for_test();
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++)
        groups[i] = (uint32_t) i;
    ASSERT_EQ(kbox_vcred_setgroups(P, KBOX_VCRED_MAX_GROUPS + 1, groups),
              -EINVAL);
}

static void test_owner_xattr_format_round_trip(void)
{
    char buf[64];
    int64_t uid = -1, gid = -1;

    ASSERT_EQ(kbox_owner_xattr_format(buf, sizeof(buf), 101, 102), 0);
    ASSERT_EQ(strcmp(buf, "101:102"), 0);
    ASSERT_EQ(kbox_owner_xattr_parse(buf, &uid, &gid), 0);
    ASSERT_EQ(uid, 101);
    ASSERT_EQ(gid, 102);
}

static void test_owner_xattr_parse_rejects_junk(void)
{
    int64_t uid = -1, gid = -1;

    ASSERT_EQ(kbox_owner_xattr_parse("", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse("101", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse("101:", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse(":102", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse("10x:102", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse("101:102:3", &uid, &gid), -EINVAL);
    ASSERT_EQ(kbox_owner_xattr_parse("-5:102", &uid, &gid), -EINVAL);
}

static void test_owner_xattr_stores_and_reads_back(void)
{
    char path[] = "/tmp/kbox-owner-XXXXXX";
    int fd = mkstemp(path);
    int64_t uid = -1, gid = -1;
    int stored;

    if (fd < 0) {
        perror("mkstemp");
        ASSERT_EQ(fd >= 0, 1);
        return;
    }
    close(fd);
    stored = kbox_owner_xattr_set(AT_FDCWD, path, 0, 101, 102) == 0;
    if (!stored) {
        /* A filesystem without user xattrs: nothing to check here. */
        unlink(path);
        return;
    }
    ASSERT_EQ(kbox_owner_xattr_get(AT_FDCWD, path, 0, &uid, &gid), 1);
    ASSERT_EQ(uid, 101);
    ASSERT_EQ(gid, 102);
    unlink(path);
}

static void test_owner_xattr_absent_is_zero(void)
{
    char path[] = "/tmp/kbox-owner-XXXXXX";
    int fd = mkstemp(path);
    int64_t uid = -1, gid = -1;

    if (fd < 0) {
        perror("mkstemp");
        ASSERT_EQ(fd >= 0, 1);
        return;
    }
    close(fd);
    ASSERT_EQ(kbox_owner_xattr_get(AT_FDCWD, path, 0, &uid, &gid), 0);
    ASSERT_EQ(kbox_owner_xattr_get(AT_FDCWD, "/nonexistent/kbox-owner", 0, &uid,
                                   &gid),
              0);
    unlink(path);
}

static void test_owner_record_host_resolves_partial_and_self_uid(void)
{
    char path[] = "/tmp/kbox-owner-rec-XXXXXX";
    int fd = mkstemp(path);
    struct stat st;
    struct stat eff;
    int64_t xuid = -1, xgid = -1;

    if (fd < 0) {
        ASSERT_EQ(fd >= 0, 1);
        return;
    }
    ASSERT_EQ(fstat(fd, &st), 0);
    close(fd);
    kbox_vcred_reset_for_test();

    kbox_owner_record_host(P, AT_FDCWD, path, 0, &st, 7, 8);
    eff = st;
    kbox_owner_apply(P, &eff);
    ASSERT_EQ(eff.st_uid, 7);
    ASSERT_EQ(eff.st_gid, 8);

    /* Partial chgrp (-1:10) must preserve uid=7 in both overlay and xattr. */
    kbox_owner_record_host(P, AT_FDCWD, path, 0, &st, -1, 10);
    eff = st;
    kbox_owner_apply(P, &eff);
    ASSERT_EQ(eff.st_uid, 7);
    ASSERT_EQ(eff.st_gid, 10);
    if (kbox_owner_xattr_get(AT_FDCWD, path, 0, &xuid, &xgid) == 1) {
        ASSERT_EQ(xuid, 7);
        ASSERT_EQ(xgid, 10);
    }

    /* Chowning back to the supervisor's own uid/gid must overwrite 7:10. */
    kbox_owner_record_host(P, AT_FDCWD, path, 0, &st, (int64_t) getuid(),
                           (int64_t) getgid());
    eff = st;
    kbox_owner_apply(P, &eff);
    ASSERT_EQ(eff.st_uid, getuid());
    ASSERT_EQ(eff.st_gid, getgid());
    if (kbox_owner_xattr_get(AT_FDCWD, path, 0, &xuid, &xgid) == 1) {
        ASSERT_EQ(xuid, (int64_t) getuid());
        ASSERT_EQ(xgid, (int64_t) getgid());
    }

    unlink(path);
}

void test_vcred_init(void)
{
    TEST_REGISTER(test_new_pid_is_root);
    TEST_REGISTER(test_root_setuid_sets_all_ids);
    TEST_REGISTER(test_nonroot_cannot_regain_root);
    TEST_REGISTER(test_nonroot_can_swap_within_set);
    TEST_REGISTER(test_setreuid_minus_one_keeps_value);
    TEST_REGISTER(test_group_ids_follow_euid_privilege);
    TEST_REGISTER(test_setpriv_order_uid_then_gid);
    TEST_REGISTER(test_owner_overlay_wins);
    TEST_REGISTER(test_owner_default_follows_caller);
    TEST_REGISTER(test_owner_foreign_uid_untouched);
    TEST_REGISTER(test_default_group_list_is_effective_gid);
    TEST_REGISTER(test_setgroups_replaces_the_list);
    TEST_REGISTER(test_setgroups_empty_list_is_legal);
    TEST_REGISTER(test_setgroups_allowed_after_dropping_root);
    TEST_REGISTER(test_owner_xattr_format_round_trip);
    TEST_REGISTER(test_owner_xattr_parse_rejects_junk);
    TEST_REGISTER(test_owner_xattr_stores_and_reads_back);
    TEST_REGISTER(test_owner_xattr_absent_is_zero);
    TEST_REGISTER(test_owner_record_host_resolves_partial_and_self_uid);
    TEST_REGISTER(test_getgroups_rejects_small_buffer);
    TEST_REGISTER(test_setgroups_rejects_oversized_list);
}
