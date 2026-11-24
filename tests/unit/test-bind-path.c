/* SPDX-License-Identifier: MIT */
/* The guest and host names of a mounted volume differ, and a symlink stored on
 * the volume is resolved by the host kernel. These tests pin the translation
 * that makes an absolute guest target resolvable, and its inverse for
 * readlink.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kbox/bind-path.h"
#include "test-runner.h"

static void make_bind(struct kbox_host_bind *b,
                      const char *guest,
                      const char *host)
{
    memset(b, 0, sizeof(*b));
    snprintf(b->guest_path, sizeof(b->guest_path), "%s", guest);
    snprintf(b->host_path, sizeof(b->host_path), "%s", host);
    b->guest_len = strlen(guest);
}

static void test_guest_path_maps_to_the_host_directory(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/vol", "/data/vol");
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/vol/data/x", out, sizeof(out)),
              1);
    ASSERT_STREQ(out, "/data/vol/data/x");
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/vol", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/data/vol");
}

static void test_guest_match_stops_at_a_component_boundary(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/vol", "/data/vol");
    /* "/volume" is not inside "/vol". */
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/volume/x", out, sizeof(out)), 0);
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/etc/passwd", out, sizeof(out)),
              0);
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "vol/x", out, sizeof(out)), 0);
}

static void test_longest_guest_prefix_wins(void)
{
    struct kbox_host_bind binds[2];
    char out[KBOX_MAX_PATH];

    make_bind(&binds[0], "/vol", "/a");
    make_bind(&binds[1], "/vol/sub", "/b");
    ASSERT_EQ(kbox_bind_guest_to_host(binds, 2, "/vol/sub/x", out, sizeof(out)),
              1);
    ASSERT_STREQ(out, "/b/x");
    ASSERT_EQ(kbox_bind_guest_to_host(binds, 2, "/vol/other", out, sizeof(out)),
              1);
    ASSERT_STREQ(out, "/a/other");
}

static void test_host_path_maps_back_to_the_guest_name(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/vol", "/data/vol");
    ASSERT_EQ(
        kbox_bind_host_to_guest(&b, 1, "/data/vol/t1.MYD", out, sizeof(out)),
        1);
    ASSERT_STREQ(out, "/vol/t1.MYD");
    ASSERT_EQ(kbox_bind_host_to_guest(&b, 1, "/data/vol", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/vol");
    ASSERT_EQ(kbox_bind_host_to_guest(&b, 1, "/data/volume", out, sizeof(out)),
              0);
}

static void test_root_bind_keeps_the_whole_path(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/", "/srv/root");
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/etc/x", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/srv/root/etc/x");
    ASSERT_EQ(
        kbox_bind_host_to_guest(&b, 1, "/srv/root/etc/x", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/etc/x");
}

static void test_a_daemon_mounted_bind_is_left_alone(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/vol", "/data/vol");
    b.is_nfs = 1;
    /* The daemon mounts this one inside LKL, so the guest path already
     * resolves there and rewriting it would break the link. */
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/vol/x", out, sizeof(out)), 0);
}

static void test_a_short_buffer_is_reported(void)
{
    struct kbox_host_bind b;
    char out[8];

    make_bind(&b, "/vol", "/data/vol");
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "/vol/abcdef", out, sizeof(out)),
              -ENAMETOOLONG);
}

static void test_no_binds_or_relative_paths_translate_nothing(void)
{
    struct kbox_host_bind b;
    char out[KBOX_MAX_PATH];

    make_bind(&b, "/vol", "/data/vol");
    ASSERT_EQ(kbox_bind_guest_to_host(NULL, 0, "/vol/x", out, sizeof(out)), 0);
    ASSERT_EQ(kbox_bind_guest_to_host(&b, 1, "relative/x", out, sizeof(out)),
              0);
    ASSERT_EQ(kbox_bind_host_to_guest(&b, 1, "data/vol/x", out, sizeof(out)),
              0);
}

void test_bind_path_init(void)
{
    TEST_REGISTER(test_guest_path_maps_to_the_host_directory);
    TEST_REGISTER(test_guest_match_stops_at_a_component_boundary);
    TEST_REGISTER(test_longest_guest_prefix_wins);
    TEST_REGISTER(test_host_path_maps_back_to_the_guest_name);
    TEST_REGISTER(test_root_bind_keeps_the_whole_path);
    TEST_REGISTER(test_a_daemon_mounted_bind_is_left_alone);
    TEST_REGISTER(test_a_short_buffer_is_reported);
    TEST_REGISTER(test_no_binds_or_relative_paths_translate_nothing);
}
