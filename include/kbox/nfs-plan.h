/* SPDX-License-Identifier: MIT */
/* nfs-plan.h - which directories an NFS bind needs created first. */
#ifndef KBOX_NFS_PLAN_H
#define KBOX_NFS_PLAN_H

#include <stddef.h>

/* kbox_nfs_bind_plan decides what has to exist before a bind from an export
 * into a container can succeed.
 *
 * src_is_file reports whether the export path is a regular file. A compose file
 * binds single files as well as trees (a ClickHouse settings fragment, a
 * prometheus.yml), and both the source and the destination used to be created
 * as directories unconditionally. For a file that turns the destination into a
 * directory, so the bind fails with "Not a directory" even though the source is
 * a perfectly good regular file.
 *
 * Writes the directory to create for the source (empty when the source already
 * exists) and for the destination, and returns 1 when the destination's parent
 * must be created instead of the destination itself (file case), 0 otherwise.
 */
int kbox_nfs_bind_plan(int src_is_file,
                       const char *src,
                       const char *dst,
                       char *src_mkdir,
                       size_t src_mkdir_size,
                       char *dst_mkdir,
                       size_t dst_mkdir_size);

#endif /* KBOX_NFS_PLAN_H */
