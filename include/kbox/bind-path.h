/* SPDX-License-Identifier: MIT */
/* bind-path.h - Translate paths between the guest's name space and the host
 * paths that back a mounted volume.
 *
 * A `-v` mount is not a mount inside LKL: kbox redirects each path call that
 * names the guest path onto the host directory. A symlink stored on such a
 * volume is resolved by the *host* kernel, which knows only host paths, so an
 * absolute target written by the guest (for example /vol/data/x) has to be
 * stored as its host form and shown back in its guest form by readlink.
 */
#ifndef KBOX_BIND_PATH_H
#define KBOX_BIND_PATH_H

#include <stddef.h>

#include "path.h"

#define KBOX_NFS_REF_PREFIX "nfs://"

struct kbox_host_bind {
    char host_path[KBOX_MAX_PATH];
    char guest_path[KBOX_MAX_PATH];
    size_t guest_len;
    int readonly;
    /* Source was an "nfs://<name>[/subdir]" reference rather than a host path;
     * the daemon bind-mounts it instead of the dispatch layer redirecting it.
     */
    int is_nfs;
};

/* Translate an absolute guest path through the bind that contains it.
 *
 * The longest matching guest prefix wins, and matching is on whole path
 * components, so guest "/vol" does not claim "/volume". Binds that the daemon
 * mounts itself (is_nfs) are skipped: their guest path already exists inside
 * LKL, so rewriting it would break the link.
 *
 * Returns 1 when a translation was made, 0 when the path lies outside every
 * bind, and -ENAMETOOLONG when the result does not fit in `out`.
 */
int kbox_bind_guest_to_host(const struct kbox_host_bind *binds,
                            size_t count,
                            const char *guest,
                            char *out,
                            size_t out_size);

/* Resolve a path that lies inside a bind the daemon mounts itself.
 *
 * Those binds keep an "nfs://<name>[/subdir]" reference in host_path, and the
 * daemon mounts it at KBOX_NFS_ROOT/<name>/<subdir>. A container path inside
 * such a bind has no usable counterpart under the container root: only a
 * placeholder exists there, and a subdirectory of it does not exist at all, so
 * a bind of that subdirectory fails with ENOENT. Returns 1 when the path was
 * resolved, 0 when it lies outside every such bind, -ENAMETOOLONG otherwise.
 */
int kbox_bind_nfs_source(const struct kbox_host_bind *binds,
                         size_t count,
                         const char *guest,
                         char *out,
                         size_t out_size);

/* Translate an absolute host path back to the guest path of its bind.
 * Same return convention as kbox_bind_guest_to_host(). */
int kbox_bind_host_to_guest(const struct kbox_host_bind *binds,
                            size_t count,
                            const char *host,
                            char *out,
                            size_t out_size);

#endif /* KBOX_BIND_PATH_H */
