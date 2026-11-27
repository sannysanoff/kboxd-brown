/* SPDX-License-Identifier: MIT */
/* daemon-resolv.c - renders a container's /etc/resolv.conf.
 *
 * Kept out of daemon.c so the rendering can be unit-tested: daemon.c pulls in
 * LKL and cannot link into the unit suite.
 */

#include "kbox/daemon-resolv.h"

#include <stdio.h>
#include <string.h>

size_t kbox_render_resolv(char *out,
                          size_t cap,
                          const char *gateway_ip,
                          const char *pod_resolv)
{
    if (!out || cap == 0)
        return 0;
    size_t len = 0;

    /* Search/domain first, copied from the pod: they are what make a short
     * cluster service name resolvable. */
    if (pod_resolv && *pod_resolv) {
        const char *p = pod_resolv;
        while (*p) {
            const char *e = strchr(p, '\n');
            size_t n = e ? (size_t) (e - p) : strlen(p);
            if ((n > 7 && strncmp(p, "search ", 7) == 0) ||
                (n > 7 && strncmp(p, "domain ", 7) == 0)) {
                size_t need = n + 1;
                if (len + need + 1 >= cap)
                    break;
                memcpy(out + len, p, n);
                len += n;
                out[len++] = '\n';
            }
            if (!e)
                break;
            p = e + 1;
        }
    }

    if (gateway_ip && *gateway_ip) {
        int w = snprintf(out + len, cap - len, "nameserver %s\n", gateway_ip);
        if (w > 0)
            len += (size_t) w;
    }
    if (len < cap)
        out[len] = '\0';
    return len;
}
