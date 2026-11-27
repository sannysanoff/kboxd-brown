/* SPDX-License-Identifier: MIT */
/* Tests for the container resolv.conf renderer. */

#include "kbox/daemon-resolv.h"
#include "test-runner.h"

#include <string.h>

/* A pod resolves a sibling service by its SHORT name only through the search
 * domains in its own resolv.conf. A container given just a nameserver fails
 * every short cluster name with NXDOMAIN while the fully-qualified form works,
 * which reads like a broken network instead of a missing line.
 */
static void test_search_domains_are_carried_over(void)
{
    const char *pod =
        "search nfs-beta.svc.cluster.local svc.cluster.local "
        "cluster.local ec2.internal\n"
        "nameserver 172.20.0.10\n"
        "options ndots:5\n";
    char out[512] = {0};
    kbox_render_resolv(out, sizeof(out), "172.31.0.1", pod);

    ASSERT_TRUE(strstr(out, "search nfs-beta.svc.cluster.local") != NULL);
    ASSERT_TRUE(strstr(out, "cluster.local") != NULL);
    ASSERT_TRUE(strstr(out, "nameserver 172.31.0.1") != NULL);
    /* The pod's own nameserver must NOT be copied: the container talks to the
     * LKL gateway, which forwards. */
    ASSERT_TRUE(strstr(out, "nameserver 172.20.0.10") == NULL);
}

/* With no pod resolv.conf the renderer must still emit a usable nameserver. */
static void test_nameserver_alone_when_pod_has_none(void)
{
    char out[128] = {0};
    size_t n = kbox_render_resolv(out, sizeof(out), "172.31.0.1", NULL);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strcmp(out, "nameserver 172.31.0.1\n") == 0);
}

/* "domain" is the singular spelling of the same idea and must survive too. */
static void test_domain_line_is_carried_over(void)
{
    char out[256] = {0};
    kbox_render_resolv(out, sizeof(out), "172.31.0.1",
                       "domain example.internal\nnameserver 1.1.1.1\n");
    ASSERT_TRUE(strstr(out, "domain example.internal") != NULL);
}

/* A truncated buffer must never produce an unterminated file. */
static void test_small_buffer_stays_terminated(void)
{
    char out[24];
    memset(out, 'X', sizeof(out));
    kbox_render_resolv(out, sizeof(out), "172.31.0.1",
                       "search a.very.long.search.domain.example\n");
    ASSERT_TRUE(memchr(out, '\0', sizeof(out)) != NULL);
}

void test_daemon_resolv_init(void)
{
    TEST_REGISTER(test_search_domains_are_carried_over);
    TEST_REGISTER(test_nameserver_alone_when_pod_has_none);
    TEST_REGISTER(test_domain_line_is_carried_over);
    TEST_REGISTER(test_small_buffer_stays_terminated);
}
