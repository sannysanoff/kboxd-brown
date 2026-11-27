/* SPDX-License-Identifier: MIT */
/* nfs-fresh.h - decide when a path created on an export may be bound. */
#ifndef KBOX_NFS_FRESH_H
#define KBOX_NFS_FRESH_H

#include <stddef.h>

/* kbox_nfs_should_retry_bind says whether an NFS bind failure is the
 * "created a moment ago" class and worth retrying.
 *
 * Creating a directory on the export and binding it in the same instant fails
 * with ESTALE or EIO: mkdir returned success, but the client's attribute cache
 * has not confirmed the new entry yet, so the follow-up lookup cannot resolve
 * it. The same bind, run a second later, succeeds -- which is why the first
 * container of a stack died on `chown -R` over a named volume while every
 * later one worked.
 *
 * Retrying is only safe for errors that mean "not visible yet". A real
 * permission error must fail at once, not after a dozen sleeps.
 */
int kbox_nfs_should_retry_bind(int err);

/* kbox_nfs_bind_delay_ms returns the wait before retry `attempt` (0-based).
 * Grows so a slow server is given progressively more time, bounded so a
 * genuinely broken export still fails in a few seconds.
 */
int kbox_nfs_bind_delay_ms(int attempt);

#endif /* KBOX_NFS_FRESH_H */
