/* SPDX-License-Identifier: MIT */
/* nfs-fresh.c - decide when a path created on an export may be bound.
 *
 * Kept out of daemon-nfs.c so the decision is unit-testable: that file pulls in
 * LKL and cannot link into the unit suite.
 */

#include "kbox/nfs-fresh.h"

/* Linux errno values, spelled out to keep this file free of host headers that
 * would differ between the build image and the kernels kbox runs on. */
#define KBOX_ESTALE 116
#define KBOX_EIO 5
#define KBOX_ENOENT 2

int kbox_nfs_should_retry_bind(int err)
{
    /* Positive errno, as kbox_err_text and the syscall wrappers report it. */
    switch (err) {
    case KBOX_ESTALE:
    case KBOX_EIO:
    case KBOX_ENOENT:
        return 1;
    default:
        return 0;
    }
}

int kbox_nfs_bind_delay_ms(int attempt)
{
    if (attempt < 0)
        attempt = 0;
    /* 25, 50, 100, 200, 400ms then 400ms: a fresh entry is normally visible
     * within the first two, and the whole ladder stays under two seconds so a
     * genuinely broken export fails quickly instead of hanging a container. */
    if (attempt > 4)
        attempt = 4;
    return 50 * (1 << attempt) / 2;
}
