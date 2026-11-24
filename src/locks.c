/* SPDX-License-Identifier: MIT */

/* POSIX and open-file-description advisory byte-range locks.
 *
 * See include/kbox/locks.h for the contract. The table is small and fixed: a
 * guest holds a handful of locks at a time, and a static array keeps every
 * operation allocation-free on the dispatch path.
 */

#include <fcntl.h>
#include <string.h>

#include "kbox/locks.h"

int kbox_lock_range(int64_t start, int64_t len, int64_t *first, int64_t *last)
{
    if (!first || !last)
        return -1;

    if (len > 0) {
        int64_t end;

        if (__builtin_add_overflow(start, len - 1, &end))
            return -1;
        *first = start;
        *last = end;
    } else if (len == 0) {
        /* To end of file, including bytes appended later. */
        *first = start;
        *last = INT64_MAX;
    } else {
        /* POSIX: a negative length covers the bytes before start. */
        int64_t begin;

        if (__builtin_add_overflow(start, len, &begin))
            return -1;
        *first = begin;
        *last = start - 1;
    }
    if (*first < 0 || *last < *first)
        return -1;
    return 0;
}

static int lock_overlaps(int64_t a_first,
                         int64_t a_last,
                         int64_t b_first,
                         int64_t b_last)
{
    return a_first <= b_last && b_first <= a_last;
}

/* Two locks are the same owner when they name the same process (POSIX) or the
 * same open file description (OFD). A POSIX lock and an OFD lock are never the
 * same owner, even inside one process: Linux makes them conflict. */
static int lock_same_owner(const struct kbox_lock *a, pid_t pid, int ofd_fd)
{
    if (a->ofd_fd < 0 && ofd_fd < 0)
        return a->pid == pid;
    if (a->ofd_fd >= 0 && ofd_fd >= 0)
        return a->ofd_fd == ofd_fd;
    return 0;
}

static int lock_clear(struct kbox_lock *slot)
{
    memset(slot, 0, sizeof(*slot));
    return 0;
}

static struct kbox_lock *lock_alloc(struct kbox_lock_table *t)
{
    for (int i = 0; i < KBOX_MAX_LOCKS; i++)
        if (!t->slots[i].used)
            return &t->slots[i];
    return NULL;
}

static void lock_insert(struct kbox_lock_table *t,
                        pid_t pid,
                        int ofd_fd,
                        uint64_t dev,
                        uint64_t ino,
                        short type,
                        int64_t first,
                        int64_t last)
{
    struct kbox_lock *slot = lock_alloc(t);

    if (!slot)
        return; /* table full: the caller reports ENOLCK below */
    slot->used = 1;
    slot->pid = pid;
    slot->ofd_fd = ofd_fd;
    slot->dev = dev;
    slot->ino = ino;
    slot->type = type;
    slot->start = first;
    slot->end = last;
    slot->guest_fd = -1;
    slot->guest_id = 0;
}

int kbox_lock_apply(struct kbox_lock_table *t,
                    pid_t pid,
                    int ofd_fd,
                    uint64_t dev,
                    uint64_t ino,
                    short type,
                    int64_t first,
                    int64_t last)
{
    if (!t || last < first)
        return -1;

    /* An owner's previous lock over the same bytes is replaced, whether the
     * new request is a different type or an explicit unlock. */
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        struct kbox_lock *slot = &t->slots[i];

        if (!slot->used || slot->dev != dev || slot->ino != ino)
            continue;
        if (!lock_same_owner(slot, pid, ofd_fd))
            continue;
        if (!lock_overlaps(slot->start, slot->end, first, last))
            continue;

        if (slot->start >= first && slot->end <= last) {
            lock_clear(slot);
            continue;
        }
        if (slot->start < first && slot->end > last) {
            /* The new range punches a hole: keep both sides. */
            int64_t old_end = slot->end;

            slot->end = first - 1;
            lock_insert(t, pid, ofd_fd, dev, ino, slot->type, last + 1,
                        old_end);
            continue;
        }
        if (slot->start < first) {
            slot->end = first - 1;
            continue;
        }
        slot->start = last + 1;
    }

    if (type == F_UNLCK)
        return 0;
    if (!lock_alloc(t))
        return -1;
    lock_insert(t, pid, ofd_fd, dev, ino, type, first, last);
    return 0;
}

int kbox_lock_conflict(const struct kbox_lock_table *t,
                       pid_t pid,
                       int ofd_fd,
                       uint64_t dev,
                       uint64_t ino,
                       short type,
                       int64_t first,
                       int64_t last,
                       struct kbox_lock *out)
{
    if (!t)
        return 0;
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        const struct kbox_lock *slot = &t->slots[i];

        if (!slot->used || slot->dev != dev || slot->ino != ino)
            continue;
        if (lock_same_owner(slot, pid, ofd_fd))
            continue;
        /* Two read locks share the file; every other pair conflicts. */
        if (slot->type == F_RDLCK && type == F_RDLCK)
            continue;
        if (!lock_overlaps(slot->start, slot->end, first, last))
            continue;
        if (out)
            *out = *slot;
        return 1;
    }
    return 0;
}

void kbox_lock_release_file(struct kbox_lock_table *t,
                            pid_t pid,
                            int ofd_fd,
                            uint64_t dev,
                            uint64_t ino)
{
    if (!t)
        return;
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        struct kbox_lock *slot = &t->slots[i];

        if (!slot->used || slot->dev != dev || slot->ino != ino)
            continue;
        /* Closing any descriptor drops the process's POSIX locks; an OFD lock
         * ends with its description. */
        if ((slot->ofd_fd < 0 && slot->pid == pid) ||
            (slot->ofd_fd >= 0 && slot->ofd_fd == ofd_fd))
            lock_clear(slot);
    }
}

void kbox_lock_tag_fd(struct kbox_lock_table *t,
                      pid_t pid,
                      int ofd_fd,
                      uint64_t dev,
                      uint64_t ino,
                      long guest_fd,
                      uint64_t guest_id)
{
    if (!t)
        return;
    for (int i = 0; i < KBOX_MAX_LOCKS; i++) {
        struct kbox_lock *slot = &t->slots[i];

        if (!slot->used || slot->dev != dev || slot->ino != ino)
            continue;
        if (!lock_same_owner(slot, pid, ofd_fd))
            continue;
        slot->guest_fd = guest_fd;
        slot->guest_id = guest_id;
    }
}

void kbox_lock_release_pid(struct kbox_lock_table *t, pid_t pid)
{
    if (!t)
        return;
    for (int i = 0; i < KBOX_MAX_LOCKS; i++)
        if (t->slots[i].used && t->slots[i].pid == pid)
            lock_clear(&t->slots[i]);
}

void kbox_lock_init(struct kbox_lock_table *t)
{
    if (t)
        memset(t, 0, sizeof(*t));
}
