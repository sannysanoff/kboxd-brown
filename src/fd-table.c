/* SPDX-License-Identifier: MIT */

/* Virtual FD table mapping guest FDs to LKL or host-managed descriptors.
 *
 * Backed by a single flat array slots[KBOX_FD_TABLE_CAPACITY] indexed directly
 * by guest FD. Each slot carries explicit ownership flags (KBOX_FD_FLAG_LKL vs
 * KBOX_FD_FLAG_HOST) and lkl_fd == -1 when free. All lookups go through
 * fd_lookup() in O(1).
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fd-table.h"
#include "lkl-wrap.h"

/* Unified entry lookup.
 * Returns a pointer to the kbox_fd_entry for the given FD, or NULL if out of
 * range.
 */
static struct kbox_fd_entry *fd_lookup(const struct kbox_fd_table *t, long fd)
{
    if (fd >= 0 && fd < KBOX_FD_TABLE_CAPACITY)
        return (struct kbox_fd_entry *) &t->slots[fd];
    return NULL;
}

/* Reset a slot to its "free" state: flags == KBOX_FD_FLAG_NONE and
 * lkl_fd == -1 act as the free sentinel, and every other field is cleared
 * so that a later insert starts from a known-zero baseline.
 */
static inline void clear_fd_entry(struct kbox_fd_entry *e)
{
    e->flags = KBOX_FD_FLAG_NONE;
    e->lkl_fd = -1;
    e->host_fd = -1;
    e->host_sv_fd = -1;
    e->shadow_sp = -1;
    e->shadow_writeback = 0;
    e->shadow_mtime_sec = 0;
    e->shadow_mtime_nsec = 0;
    e->shadow_size = 0;
    e->mirror_tty = 0;
    e->cloexec = 0;
    e->opath = 0;
    e->sock_type = 0;
    e->sock_connected = 0;
    e->sock_peer_family = 0;
    memset(&e->sock_peer, 0, sizeof(e->sock_peer));
    e->sock_established = 0;
    e->shadow_mmap = 0;
    e->guest_id = 0;
    e->watch_wd = -1;
}

/* Populate an already-free slot with a fresh lkl_fd and ownership flags. All
 * other fields are reset to their default "no shadow / no host_fd / no cloexec"
 * state so callers never inherit stale bookkeeping from a previous occupant.
 * The caller is responsible for bumping the lkl_fd refcount.
 */
static inline void init_live_entry(struct kbox_fd_entry *e,
                                   long lkl_fd,
                                   int mirror_tty)
{
    uint32_t flags = KBOX_FD_FLAG_ACTIVE;

    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
        flags |= KBOX_FD_FLAG_HOST;
    else if (lkl_fd >= 0)
        flags |= KBOX_FD_FLAG_LKL;

    e->flags = flags;
    e->lkl_fd = lkl_fd;
    e->host_fd = -1;
    e->host_sv_fd = -1;
    e->shadow_sp = -1;
    e->shadow_writeback = 0;
    e->shadow_mtime_sec = 0;
    e->shadow_mtime_nsec = 0;
    e->shadow_size = 0;
    e->mirror_tty = mirror_tty;
    e->cloexec = 0;
    e->opath = 0;
    e->sock_type = 0;
    e->sock_connected = 0;
    e->sock_peer_family = 0;
    memset(&e->sock_peer, 0, sizeof(e->sock_peer));
    e->sock_established = 0;
    e->shadow_mmap = 0;
    e->guest_id = 0;
    e->watch_wd = -1;
}

/* Reverse-map and refcount maintenance helpers.
 *
 * The reverse map (host_to_vfd) gives O(1) find_by_host_fd. Each slot
 * holds one of:
 *   -1  (KBOX_HOST_VFD_NONE):  no entry currently has this host_fd.
 *   -2  (KBOX_HOST_VFD_MULTI): two or more entries share this host_fd;
 *                              exact holders unknown, fall through to
 *                              the linear scan.
 *   >=0:                       the unique vfd currently holding this
 *                              host_fd.
 *
 * Invariant: host_to_vfd[h] == KBOX_HOST_VFD_NONE implies no live
 * entry in any of the three ranges has host_fd == h. This lets
 * find_by_host_fd return -1 in O(1) without scanning (authoritative
 * miss), which is the common case for close() of a host fd that
 * isn't tracked in the fd_table at all (e.g. cached-shadow opens
 * that inject an ADDFD without ever creating an fd_table entry).
 *
 * Duplicate holders arise only from dup2/dup3-style operations; they
 * are rare and tracked with the MULTI sentinel so the common single-
 * or no-holder paths stay O(1). A MULTI slot is never downgraded back
 * to a single-holder value; it stays MULTI until the last duplicate
 * closes, at which point find_by_host_fd's slow-path scan leaves
 * matches to subsequent lookups or to a future set that overwrites
 * it.
 *
 * The lkl_fd refcount covers all three storage ranges. It lets
 * close-path callers replace their O(n) sibling scans with an O(1)
 * comparison.
 */
#define KBOX_HOST_VFD_NONE ((int32_t) -1)
#define KBOX_HOST_VFD_MULTI ((int32_t) -2)

static inline void rev_host_set(struct kbox_fd_table *t, long host_fd, long vfd)
{
    int32_t cur;

    /* A bridged entry is one whose host descriptor lives at a different
     * number than the guest descriptor: shadows at the same number are not
     * bridged and need no sweeping. */
    if (vfd >= 0 && vfd < KBOX_FD_TABLE_CAPACITY && host_fd >= 0 &&
        host_fd != vfd) {
        size_t idx = (size_t) vfd;
        uint64_t mask = 1ULL << (idx & 63U);

        if (!(t->low_host_bitmap[idx >> 6] & mask)) {
            t->low_host_bitmap[idx >> 6] |= mask;
            t->low_host_count++;
        }
    }
    if (host_fd < 0 || (uint64_t) host_fd >= KBOX_HOST_FD_REVERSE_MAX)
        return;
    cur = t->host_to_vfd[host_fd];
    if (cur == KBOX_HOST_VFD_NONE || cur == (int32_t) vfd) {
        t->host_to_vfd[host_fd] = (int32_t) vfd;
        return;
    }
    /* A different vfd already claims this host_fd, OR the slot is
     * already MULTI. Either way we now have two or more holders.
     */
    t->host_to_vfd[host_fd] = KBOX_HOST_VFD_MULTI;
}

static inline void rev_host_clear(struct kbox_fd_table *t,
                                  long host_fd,
                                  long vfd)
{
    if (vfd >= 0 && vfd < KBOX_FD_TABLE_CAPACITY && host_fd >= 0 &&
        host_fd != vfd) {
        size_t idx = (size_t) vfd;
        uint64_t mask = 1ULL << (idx & 63U);

        if (t->low_host_bitmap[idx >> 6] & mask) {
            t->low_host_bitmap[idx >> 6] &= ~mask;
            if (t->low_host_count > 0)
                t->low_host_count--;
        }
    }
    if (host_fd < 0 || (uint64_t) host_fd >= KBOX_HOST_FD_REVERSE_MAX)
        return;
    /* Only the single-holder case can be cleared authoritatively. If
     * the slot is MULTI, leave it: we cannot prove this is the last
     * holder without scanning, and the slow path will handle later
     * lookups correctly. If the slot is NONE or claims a different
     * vfd, we were not the indexed holder; nothing to do.
     */
    if (t->host_to_vfd[host_fd] == (int32_t) vfd)
        t->host_to_vfd[host_fd] = KBOX_HOST_VFD_NONE;
}

static inline void lkl_ref_inc(struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd >= 0 && (uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX &&
        t->lkl_fd_refs[lkl_fd] < UINT16_MAX) {
        t->lkl_fd_refs[lkl_fd]++;
    }
}

static inline void lkl_ref_dec(struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd >= 0 && (uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX &&
        t->lkl_fd_refs[lkl_fd] > 0) {
        t->lkl_fd_refs[lkl_fd]--;
    }
}

void kbox_fd_table_init(struct kbox_fd_table *t)
{
    long i;

    for (i = 0; i < KBOX_FD_TABLE_CAPACITY; i++)
        clear_fd_entry(&t->slots[i]);
    for (i = 0; i < KBOX_HOST_FD_REVERSE_MAX; i++)
        t->host_to_vfd[i] = KBOX_HOST_VFD_NONE;
    for (i = 0; i < KBOX_LKL_FD_REFMAX; i++)
        t->lkl_fd_refs[i] = 0;
    memset(t->low_host_bitmap, 0, sizeof(t->low_host_bitmap));
    t->low_host_count = 0;
    t->next_fd = 0;
}

/* Auto-allocate a virtual descriptor from [0, KBOX_FD_TABLE_CAPACITY). */
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty)
{
    long start_fd = t->next_fd;
    long fd;

    if (start_fd < 0 || start_fd >= KBOX_FD_TABLE_CAPACITY)
        start_fd = 0;

    for (fd = start_fd; fd < KBOX_FD_TABLE_CAPACITY; fd++) {
        if (t->slots[fd].lkl_fd == -1) {
            init_live_entry(&t->slots[fd], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fd = fd + 1;
            return fd;
        }
    }

    /* Wrap around: scan from 0 up to start_fd. */
    for (fd = 0; fd < start_fd; fd++) {
        if (t->slots[fd].lkl_fd == -1) {
            init_live_entry(&t->slots[fd], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fd = fd + 1;
            return fd;
        }
    }

    /* A JVM or database can legitimately hold thousands of files, and a leak
     * shows up here too, so say how full the pool is when it runs out. */
    {
        long live = 0;
        long cap = KBOX_FD_TABLE_CAPACITY;
        for (fd = 0; fd < KBOX_FD_TABLE_CAPACITY; fd++)
            if (t->slots[fd].lkl_fd != -1)
                live++;
        fprintf(stderr, "kbox: virtual fd table full (%ld live of %ld)\n", live,
                cap);
    }
    return -1; /* table truly full */
}

long kbox_fd_table_insert_from(struct kbox_fd_table *t,
                               long min_fd,
                               long lkl_fd,
                               int mirror_tty)
{
    long fd;

    if (min_fd < 0)
        min_fd = 0;

    for (fd = min_fd; fd < KBOX_FD_TABLE_CAPACITY; fd++) {
        if (t->slots[fd].lkl_fd == -1) {
            init_live_entry(&t->slots[fd], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            return fd;
        }
    }

    return -1;
}

long kbox_fd_table_insert_lowest(struct kbox_fd_table *t,
                                 long lkl_fd,
                                 int mirror_tty)
{
    return kbox_fd_table_insert_from(t, 0, lkl_fd, mirror_tty);
}

int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e)
        return -1;

    /* Replacing a live slot: release the previous lkl_fd ref and the
     * old reverse-map entry first. insert_at semantics permit reusing
     * an in-use slot (e.g. dup2 over an existing FD).
     */
    if (e->lkl_fd != -1) {
        lkl_ref_dec(t, e->lkl_fd);
        rev_host_clear(t, e->host_fd, fd);
#ifndef KBOX_UNIT_TEST
        if (e->host_sv_fd >= 0) {
            close(e->host_sv_fd);
            e->host_sv_fd = -1;
        }
#endif
    }

    init_live_entry(e, lkl_fd, mirror_tty);
    lkl_ref_inc(t, lkl_fd);

    /* Keep next_fd ahead of the highest occupied slot. */
    if (fd >= t->next_fd)
        t->next_fd = fd + 1;

    return 0;
}

long kbox_fd_table_get_lkl(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e)
        return -1;
    return e->lkl_fd;
}

long kbox_fd_table_remove(struct kbox_fd_table *t, long fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    long old;

    if (!e)
        return -1;

    old = e->lkl_fd;
    /* Release reverse-map and refcount tracking before clobbering
     * the entry fields. rev_host_clear is safe for sentinel host_fd
     * values and for entries whose host_fd was not in the reverse
     * table. lkl_ref_dec is safe for KBOX_LKL_FD_SHADOW_ONLY and
     * other negative sentinels.
     */
    rev_host_clear(t, e->host_fd, fd);
    if (e->lkl_fd != -1)
        lkl_ref_dec(t, e->lkl_fd);
#ifndef KBOX_UNIT_TEST
    /* For shadow sockets (shadow_sp >= 0), host_fd is a tracee-namespace FD
     * number from ADDFD, NOT a supervisor-owned FD. Don't close it in the
     * supervisor; it would close an unrelated local FD.
     */
    if (e->host_fd >= 0 && e->shadow_sp < 0)
        close((int) e->host_fd);
    if (e->host_sv_fd >= 0)
        close(e->host_sv_fd);
    if (e->shadow_sp >= 0)
        close(e->shadow_sp);
#endif
    clear_fd_entry(e);
    if (fd >= 0 && fd < t->next_fd)
        t->next_fd = fd;
    return old;
}

bool kbox_fd_table_mirror_tty(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return false;
    return e->mirror_tty != 0;
}

void kbox_fd_table_set_cloexec(struct kbox_fd_table *t, long fd, int val)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    e->cloexec = val ? 1 : 0;
}

int kbox_fd_table_get_cloexec(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return 0;
    return e->cloexec;
}

void kbox_fd_table_set_opath(struct kbox_fd_table *t, long fd, int val)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    e->opath = val ? 1 : 0;
}

int kbox_fd_table_get_opath(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return 0;
    return e->opath;
}

#ifndef KBOX_UNIT_TEST
/* Is this entry the last reference to its lkl_fd? Uses the
 * maintained refcount; fd_table_refs[e->lkl_fd] counts the entry
 * itself, so "last reference" means refcount == 1.
 *
 * lkl_fds at or above KBOX_LKL_FD_REFMAX are tracked only with the
 * legacy scan because we cannot store a refcount for them. This path
 * is a safety net; real LKL kernels allocate small FDs.
 */
static int lkl_fd_is_sole_ref(const struct kbox_fd_table *t,
                              const struct kbox_fd_entry *skip,
                              long lkl_fd)
{
    if (lkl_fd < 0)
        return 1;
    if ((uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX)
        return t->lkl_fd_refs[lkl_fd] <= 1;

    /* Fallback for out-of-range lkl_fd: linear scan over the unified table. */
    for (long i = 0; i < KBOX_FD_TABLE_CAPACITY; i++)
        if (&t->slots[i] != skip && t->slots[i].lkl_fd == lkl_fd)
            return 0;
    return 1;
}

static void close_cloexec_entry(struct kbox_fd_table *t,
                                struct kbox_fd_entry *e,
                                long vfd,
                                const struct kbox_sysnrs *s)
{
    if (e->lkl_fd != -1 && e->cloexec) {
        /* Host-passthrough entries are shared across supervised processes,
         * but FD_CLOEXEC is per-process.  Clearing a passthrough slot here
         * on one process's exec would drop tracking for siblings/parent that
         * still hold the same FD number.  Leave the shared bookkeeping intact.
         */
        if (kbox_fd_entry_is_host(e))
            return;

        /* Only close real LKL FDs; host-passthrough entries are not LKL file
         * descriptors.
         */
        if (e->lkl_fd >= 0 && lkl_fd_is_sole_ref(t, e, e->lkl_fd))
            kbox_lkl_close(s, e->lkl_fd);

        rev_host_clear(t, e->host_fd, vfd);
        if (e->lkl_fd != -1)
            lkl_ref_dec(t, e->lkl_fd);

        /* Shadow sockets: host_fd is tracee-namespace, don't close. */
        if (e->host_fd >= 0 && e->shadow_sp < 0) {
            close((int) e->host_fd);
            e->host_fd = -1;
        }
        if (e->shadow_sp >= 0) {
            close(e->shadow_sp);
            e->shadow_sp = -1;
        }
        clear_fd_entry(e);
    }
}

void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s)
{
    for (long i = 0; i < KBOX_FD_TABLE_CAPACITY; i++)
        close_cloexec_entry(t, &t->slots[i], i, s);
}
#endif

void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    /* Drop our claim on the old host_fd, then install the new one. */
    rev_host_clear(t, e->host_fd, fd);
    e->host_fd = host_fd;
    if (host_fd >= 0)
        e->flags |= KBOX_FD_FLAG_SHADOW;
    else
        e->flags &= ~KBOX_FD_FLAG_SHADOW;
    rev_host_set(t, host_fd, fd);
}

long kbox_fd_table_get_host_fd(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return -1;
    return e->host_fd;
}

void kbox_fd_table_set_host_sv_fd(struct kbox_fd_table *t, long fd, int sv_fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
#ifndef KBOX_UNIT_TEST
    if (e->host_sv_fd >= 0 && e->host_sv_fd != sv_fd)
        close(e->host_sv_fd);
#endif
    e->host_sv_fd = sv_fd;
}

int kbox_fd_table_get_host_sv_fd(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return -1;
    return e->host_sv_fd;
}

long kbox_fd_table_find_by_host_fd(const struct kbox_fd_table *t, long host_fd)
{
    long i;

    if (host_fd < 0)
        return -1;

    /* Fast path: O(1) reverse-map lookup.
     *   NONE  -> authoritative miss (no holder).
     *   vfd   -> forward-check and return.
     *   MULTI -> fall through to the linear scan.
     */
    if ((uint64_t) host_fd < KBOX_HOST_FD_REVERSE_MAX) {
        int32_t slot = t->host_to_vfd[host_fd];
        if (slot == KBOX_HOST_VFD_NONE)
            return -1;
        if (slot != KBOX_HOST_VFD_MULTI) {
            long vfd = slot;
            const struct kbox_fd_entry *e = fd_lookup(t, vfd);
            if (e && e->lkl_fd != -1 && e->host_fd == host_fd)
                return vfd;
            /* Stale single-holder entry (e.g. host_fd rewritten
             * directly to a sentinel). Fall through to the linear
             * scan, which will still find any other holder that
             * exists.
             */
        }
    }

    /* Slow path: MULTI slot, stale single-holder, or out-of-range
     * host_fd. Preserves the original linear-scan semantics exactly.
     */
    for (i = 0; i < KBOX_FD_TABLE_CAPACITY; i++) {
        if (t->slots[i].lkl_fd != -1 && t->slots[i].host_fd == host_fd)
            return i;
    }
    return -1;
}

unsigned kbox_fd_table_lkl_ref_count(const struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd < 0)
        return 0;
    if ((uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX)
        return t->lkl_fd_refs[lkl_fd];
    /* Out-of-range fallback: linear scan over the unified table. */
    unsigned count = 0;
    for (long i = 0; i < KBOX_FD_TABLE_CAPACITY; i++)
        if (t->slots[i].lkl_fd == lkl_fd)
            count++;
    return count;
}

unsigned kbox_fd_table_count(const struct kbox_fd_table *t)
{
    unsigned n = 0;

    for (long i = 0; i < KBOX_FD_TABLE_CAPACITY; i++) {
        if (t->slots[i].lkl_fd != -1)
            n++;
    }
    return n;
}

uint64_t kbox_fd_link_identity(const char *target)
{
    uint64_t h = 1469598103934665603ULL;

    if (!target || !target[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *) target; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    /* Zero is reserved for "no identity", so a real target can never hash
     * to it and be mistaken for an entry that was never recorded. */
    return h ? h : 1;
}

uint64_t kbox_fd_stat_identity(uint64_t dev, uint64_t ino)
{
    uint64_t h = 1469598103934665603ULL;
    uint64_t vals[2] = {dev, ino};

    for (size_t i = 0; i < 2; i++) {
        uint64_t v = vals[i];
        for (int b = 0; b < 8; b++) {
            h ^= (unsigned char) (v & 0xffU);
            h *= 1099511628211ULL;
            v >>= 8;
        }
    }
    return h ? h : 1;
}

bool kbox_fd_identity_stale(uint64_t recorded, uint64_t now, int err)
{
    if (recorded == 0)
        return false;
    if (now != 0)
        return now != recorded;
    return err == ENOENT || err == EBADF;
}
