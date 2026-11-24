/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SHADOW_FD_H
#define KBOX_SHADOW_FD_H

struct kbox_sysnrs;

#define KBOX_SHADOW_MAX_SIZE (1024L * 1024 * 1024)

int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd);
int kbox_shadow_create_from_host_fd(int host_fd);
int kbox_shadow_seal(int memfd);

/* Copy a file kbox serves from LKL into a memfd, and retry an interrupted copy
 * on a fresh LKL task.
 *
 * kbox_shadow_create() reads the whole file through LKL. A container's LKL task
 * can carry a stale pending signal, and then every page-cache read answers
 * EINTR; the copy names a descriptor rather than a path, so a fresh task can do
 * it even when the same task cannot resolve a path.
 */
struct kbox_supervisor_ctx;
int kbox_shadow_create_resilient(const struct kbox_supervisor_ctx *ctx,
                                 long lkl_fd);

#endif /* KBOX_SHADOW_FD_H */
