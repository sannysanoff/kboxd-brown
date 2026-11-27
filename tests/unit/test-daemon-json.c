/* SPDX-License-Identifier: MIT */
/* Tests for the daemon's RPC request parser. */

#include "kbox/daemon-json.h"
#include "test-runner.h"

#include <stdlib.h>
#include <string.h>

/* An argv entry is not bounded by one page. The parser used to copy each array
 * element into a fixed 4096-byte buffer, so a long command reached the guest
 * truncated mid-token; the resulting failure named an innocent line of the
 * script (a Python syntax error at the line where the cut landed).
 */
static void test_str_array_keeps_a_long_entry(void)
{
    char big[9000];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char json[9100];
    snprintf(json, sizeof(json), "{\"cmd\":[\"sh\",\"%s\"]}", big);

    char *out[8] = {0};
    int n = kbox_json_get_str_array(json, "cmd", out, 8);
    ASSERT_EQ(n, 2);
    ASSERT_TRUE(out[0] && strcmp(out[0], "sh") == 0);
    ASSERT_TRUE(out[1] != NULL);
    ASSERT_EQ((long) strlen(out[1]), (long) strlen(big));
    ASSERT_TRUE(strcmp(out[1], big) == 0);
    for (int i = 0; i < n; i++)
        free(out[i]);
}

/* Just past the old cap, where the cut used to land. */
static void test_str_array_past_the_page_boundary(void)
{
    char big[4097];
    memset(big, 'B', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char json[4200];
    snprintf(json, sizeof(json), "{\"env\":[\"X=%s\"]}", big);

    char *out[4] = {0};
    int n = kbox_json_get_str_array(json, "env", out, 4);
    ASSERT_EQ(n, 1);
    ASSERT_TRUE(out[0] != NULL);
    ASSERT_EQ((long) strlen(out[0]), 2 + (long) strlen(big));
    for (int i = 0; i < n; i++)
        free(out[i]);
}

/* Short values must still parse, and an absent key must yield nothing. */
static void test_str_array_short_and_absent(void)
{
    char *out[4] = {0};
    int n = kbox_json_get_str_array("{\"cmd\":[\"a\",\"b\"]}", "cmd", out, 4);
    ASSERT_EQ(n, 2);
    for (int i = 0; i < n; i++)
        free(out[i]);

    n = kbox_json_get_str_array("{\"cmd\":[]}", "cmd", out, 4);
    ASSERT_EQ(n, 0);

    n = kbox_json_get_str_array("{\"other\":[\"x\"]}", "cmd", out, 4);
    ASSERT_EQ(n, 0);
}

/* The scalar accessors honour their caller's cap and must not lose a value that
 * fits. */
static void test_get_str_honours_cap(void)
{
    char out[16];
    ASSERT_EQ(
        kbox_json_get_str("{\"op\":\"exec_start\"}", "op", out, sizeof(out)),
        0);
    ASSERT_TRUE(strcmp(out, "exec_start") == 0);

    char small[4];
    memset(small, 0, sizeof(small));
    kbox_json_get_str("{\"op\":\"exec_start\"}", "op", small, sizeof(small));
    ASSERT_TRUE(strlen(small) < sizeof(small));
}

void test_daemon_json_init(void)
{
    TEST_REGISTER(test_str_array_keeps_a_long_entry);
    TEST_REGISTER(test_str_array_past_the_page_boundary);
    TEST_REGISTER(test_str_array_short_and_absent);
    TEST_REGISTER(test_get_str_honours_cap);
}
