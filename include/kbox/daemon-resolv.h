/* SPDX-License-Identifier: MIT */
/* daemon-resolv.h - renders a container's /etc/resolv.conf. */
#ifndef KBOX_DAEMON_RESOLV_H
#define KBOX_DAEMON_RESOLV_H

#include <stddef.h>

/* kbox_render_resolv writes the nameserver line plus the pod's search/domain
 * lines into out.
 *
 * The search line is not decoration: a pod resolves a sibling service by its
 * short name ("nexus", "clickhouse") only through the search domains in its own
 * resolv.conf. A container given just a nameserver therefore fails every short
 * cluster name with NXDOMAIN while the fully-qualified form works, which reads
 * like a networking fault rather than a missing line.
 *
 * pod_resolv is the text of the POD's /etc/resolv.conf (may be NULL or empty).
 * Returns the number of bytes written, or 0 when nothing fits.
 */
size_t kbox_render_resolv(char *out,
                          size_t cap,
                          const char *gateway_ip,
                          const char *pod_resolv);

#endif /* KBOX_DAEMON_RESOLV_H */
