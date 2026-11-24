/* SPDX-License-Identifier: MIT */

#ifndef KBOX_LOCKS_H
#define KBOX_LOCKS_H

#include <stdint.h>
#include <sys/types.h>

/* POSIX and open-file-description advisory byte-range locks.
 *
 * kbox answered F_SETLK with success and F_GETLK with ENOSYS. A server that
 * uses a lock file to detect a second instance was therefore told that every
 * lock was free, and a test that expects the second attempt to fail passed
 * while the two instances ran against the same data. The table below gives
 * both calls their real answers, keyed by the inode the lock names.
 *
 * A lock is owned by a process (POSIX) or by one open file description (OFD,
 * Linux). Same-owner locks never conflict; a read lock conflicts only with a
 * write lock. The supervisor is single-threaded, so F_SETLKW cannot wait for
 * another guest process to release a lock: it reports the conflict instead of
 * hanging the whole engine.
 */

#define KBOX_MAX_LOCKS 64

struct kbox_lock {
    unsigned used;
    pid_t pid;
    int ofd_fd;    /* >= 0 for an open-file-description lock, -1 for POSIX */
    uint64_t dev;  /* st_dev of the locked inode */
    uint64_t ino;  /* st_ino of the locked inode */
    short type;    /* F_RDLCK or F_WRLCK */
    int64_t start; /* first byte, inclusive */
    int64_t end;   /* last byte, inclusive; INT64_MAX means "to EOF" */
    long guest_fd; /* guest descriptor that took the lock, or -1 */
    uint64_t guest_id; /* host object identity when guest_fd < KBOX_FD_BASE */
};

struct kbox_lock_table {
    struct kbox_lock slots[KBOX_MAX_LOCKS];
};

/* Turn (start, len) into an inclusive [*first, *last] range.
 *
 * len > 0  -> [start, start + len - 1]
 * len == 0 -> [start, EOF]
 * len < 0  -> [start + len, start - 1], as POSIX defines a negative length.
 * A negative start is an error.
 */
int kbox_lock_range(int64_t start, int64_t len, int64_t *first, int64_t *last);

/* Record a lock (type F_RDLCK/F_WRLCK) or remove the caller's locks over the
 * range (type F_UNLCK). Returns 0, or -1 when the table has no free slot.
 */
int kbox_lock_apply(struct kbox_lock_table *t,
                    pid_t pid,
                    int ofd_fd,
                    uint64_t dev,
                    uint64_t ino,
                    short type,
                    int64_t first,
                    int64_t last);

/* Find another owner's lock that conflicts with the requested one.
 * Returns 1 and copies it to *out, or 0 when the request may be granted.
 */
int kbox_lock_conflict(const struct kbox_lock_table *t,
                       pid_t pid,
                       int ofd_fd,
                       uint64_t dev,
                       uint64_t ino,
                       short type,
                       int64_t first,
                       int64_t last,
                       struct kbox_lock *out);

/* A process that closes any descriptor on a file loses its POSIX locks on it;
 * an OFD lock survives until the last descriptor of that description closes. */
void kbox_lock_release_file(struct kbox_lock_table *t,
                            pid_t pid,
                            int ofd_fd,
                            uint64_t dev,
                            uint64_t ino);

/* Stamp the guest descriptor and host object identity onto matching lock slots
 * so a lock taken on a low descriptor whose close runs natively in the kernel
 * can be detected as stale when the descriptor is closed or reused. */
void kbox_lock_tag_fd(struct kbox_lock_table *t,
                      pid_t pid,
                      int ofd_fd,
                      uint64_t dev,
                      uint64_t ino,
                      long guest_fd,
                      uint64_t guest_id);

/* A process that exits loses every lock it held. */
void kbox_lock_release_pid(struct kbox_lock_table *t, pid_t pid);

void kbox_lock_init(struct kbox_lock_table *t);

#endif /* KBOX_LOCKS_H */
