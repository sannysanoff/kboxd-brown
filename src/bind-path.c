/* SPDX-License-Identifier: MIT */
/* bind-path.c - Guest/host path translation for mounted volumes. */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "daemon.h"
#include "kbox/bind-path.h"

/* True when `path` is `prefix` itself or a child of it on a component
 * boundary. A prefix of "/" matches every absolute path. */
static int prefix_dir(const char *path, const char *prefix, size_t len)
{
    if (len == 0)
        return 0;
    if (len == 1 && prefix[0] == '/')
        return path[0] == '/';
    if (strncmp(path, prefix, len) != 0)
        return 0;
    return path[len] == '\0' || path[len] == '/';
}

/* Join `base` and `tail`. `tail` starts with '/' or is empty. A base of "/"
 * must not produce a doubled separator. */
static int join_path(const char *base,
                     const char *tail,
                     char *out,
                     size_t out_size)
{
    size_t blen = strlen(base);
    int n;

    if (tail[0] == '\0')
        n = snprintf(out, out_size, "%s", base);
    else if (blen > 0 && base[blen - 1] == '/')
        n = snprintf(out, out_size, "%s%s", base, tail + 1);
    else
        n = snprintf(out, out_size, "%s%s", base, tail);
    if (n < 0 || (size_t) n >= out_size)
        return -ENAMETOOLONG;
    return 1;
}

static int translate(const struct kbox_host_bind *binds,
                     size_t count,
                     const char *path,
                     char *out,
                     size_t out_size,
                     int guest_to_host)
{
    const struct kbox_host_bind *best = NULL;
    size_t best_len = 0;

    if (!binds || count == 0 || !path || !out || out_size == 0)
        return 0;
    if (path[0] != '/')
        return 0;

    for (size_t i = 0; i < count; i++) {
        const struct kbox_host_bind *b = &binds[i];
        const char *from = guest_to_host ? b->guest_path : b->host_path;
        size_t len;

        if (b->is_nfs)
            continue;
        len = guest_to_host ? b->guest_len : 0;
        if (len == 0)
            len = strlen(from);
        if (!prefix_dir(path, from, len) || len < best_len)
            continue;
        best = b;
        best_len = len;
    }
    if (!best)
        return 0;

    const char *from = guest_to_host ? best->guest_path : best->host_path;
    const char *to = guest_to_host ? best->host_path : best->guest_path;
    const char *tail =
        (best_len == 1 && from[0] == '/') ? path : path + best_len;

    return join_path(to, tail, out, out_size);
}

int kbox_bind_guest_to_host(const struct kbox_host_bind *binds,
                            size_t count,
                            const char *guest,
                            char *out,
                            size_t out_size)
{
    return translate(binds, count, guest, out, out_size, 1);
}

int kbox_bind_nfs_source(const struct kbox_host_bind *binds,
                         size_t count,
                         const char *guest,
                         char *out,
                         size_t out_size)
{
    const struct kbox_host_bind *best = NULL;
    size_t best_len = 0;
    size_t ref_len = strlen(KBOX_NFS_REF_PREFIX);
    const char *tail;
    int n;

    if (!binds || count == 0 || !guest || !out || out_size == 0)
        return 0;
    if (guest[0] != '/')
        return 0;

    for (size_t i = 0; i < count; i++) {
        const struct kbox_host_bind *b = &binds[i];
        size_t len = b->guest_len ? b->guest_len : strlen(b->guest_path);

        if (!b->is_nfs ||
            strncmp(b->host_path, KBOX_NFS_REF_PREFIX, ref_len) != 0)
            continue;
        if (!prefix_dir(guest, b->guest_path, len) || len < best_len)
            continue;
        best = b;
        best_len = len;
    }
    if (!best)
        return 0;

    tail = (best_len == 1 && best->guest_path[0] == '/') ? guest
                                                         : guest + best_len;
    n = snprintf(out, out_size, "%s/%s%s", KBOX_NFS_ROOT,
                 best->host_path + ref_len, tail);
    if (n < 0 || (size_t) n >= out_size)
        return -ENAMETOOLONG;
    return 1;
}

int kbox_bind_host_to_guest(const struct kbox_host_bind *binds,
                            size_t count,
                            const char *host,
                            char *out,
                            size_t out_size)
{
    return translate(binds, count, host, out, out_size, 0);
}
