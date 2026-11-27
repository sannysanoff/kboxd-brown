/* SPDX-License-Identifier: MIT */
/* nfs-plan.c - which directories an NFS bind needs created first.
 *
 * Kept apart from daemon-nfs.c so the decision can be unit-tested: that file
 * pulls in LKL and cannot link into the unit suite.
 */

#include "kbox/nfs-plan.h"

#include <stdio.h>
#include <string.h>

static void parent_dir(const char *path, char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return;
    snprintf(out, out_size, "%s", path ? path : "");
    char *slash = strrchr(out, '/');
    if (slash && slash != out)
        *slash = '\0';
    else if (slash == out)
        out[1] = '\0';
}

int kbox_nfs_bind_plan(int src_is_file,
                       const char *src,
                       const char *dst,
                       char *src_mkdir,
                       size_t src_mkdir_size,
                       char *dst_mkdir,
                       size_t dst_mkdir_size)
{
    if (src_mkdir && src_mkdir_size)
        src_mkdir[0] = '\0';
    if (dst_mkdir && dst_mkdir_size)
        dst_mkdir[0] = '\0';

    if (src_is_file) {
        /* Leave the existing file alone and create only the destination's
         * parent: the bind itself places the file. */
        parent_dir(dst, dst_mkdir, dst_mkdir_size);
        return 1;
    }

    if (src_mkdir && src_mkdir_size)
        snprintf(src_mkdir, src_mkdir_size, "%s", src ? src : "");
    if (dst_mkdir && dst_mkdir_size)
        snprintf(dst_mkdir, dst_mkdir_size, "%s", dst ? dst : "");
    return 0;
}
