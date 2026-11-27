/* SPDX-License-Identifier: MIT */

#ifndef KBOX_FD_TABLE_H
#define KBOX_FD_TABLE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct kbox_sysnrs; /* forward declaration */

/* Virtual FD table.
 *
 * Maps guest descriptors to LKL-internal or host-managed descriptors. Flat
 * array indexed by the descriptor number itself. O(1) lookup, zero allocator
 * overhead, cache-friendly.
 */

/* Guest descriptor ceiling: one flat slot per possible descriptor number, so
 * a descriptor keeps its number from the moment it is minted. 65536 is the
 * ceiling a guest may raise RLIMIT_NOFILE to.
 */
#define KBOX_FD_TABLE_MAX 65536

/* One slot per descriptor number; nothing is reserved by position. */
#define KBOX_FD_TABLE_CAPACITY KBOX_FD_TABLE_MAX

/* Native close boundary [0, KBOX_NATIVE_CLOSE_MAX).
 *
 * Host-kernel descriptors created natively (pipes, pipe2, stdio, host sockets)
 * take the lowest free numbers below this boundary, and the seccomp filter
 * allows close(fd) for fd < KBOX_NATIVE_CLOSE_MAX directly in the host kernel.
 * That avoids the seccomp_unotify pre-NOTIF_RECV signal race (SIGCHLD aborting
 * close() with ERESTARTSYS/EINTR before the supervisor receives it, leaking
 * pipe descriptors in shells). Virtual LKL descriptors auto-allocate from
 * KBOX_NATIVE_CLOSE_MAX upward so their close() always reaches the supervisor;
 * any virtual descriptor explicitly placed below it (via dup2/dup3/F_DUPFD)
 * receives a real host placeholder fd so native close() succeeds with 0.
 */
#define KBOX_NATIVE_CLOSE_MAX 1024

/* Reverse lookup for host_fd -> virtual fd. Sized to cover the
 * child's RLIMIT_NOFILE (65536). Host FDs at or above this bound
 * fall through to a slow linear scan.
 */
#define KBOX_HOST_FD_REVERSE_MAX 65536
/* Refcount array for lkl_fd. Sized to cover realistic LKL kernel FD
 * numbers; LKL is in-process and typically allocates low integers.
 * lkl_fds at or above this bound are tracked by a slow scan.
 */
#define KBOX_LKL_FD_REFMAX 16384

/* Sentinel lkl_fd value for host-passthrough FDs (pipes, eventfds, timerfds,
 * epoll FDs, stdio) that have no LKL backing.  Stored in kbox_fd_entry.lkl_fd
 * alongside KBOX_FD_FLAG_HOST to mark the slot as occupied by a host-managed
 * descriptor.  I/O handlers CONTINUE these to the host kernel; untracked FDs
 * (flags == KBOX_FD_FLAG_NONE / lkl_fd == -1) get EBADF instead.
 */
#define KBOX_LKL_FD_SHADOW_ONLY (-2)

/* Ownership and state flags for each descriptor slot in the unified table. */
enum kbox_fd_flags {
    KBOX_FD_FLAG_NONE = 0,
    KBOX_FD_FLAG_ACTIVE = (1U << 0), /* slot is occupied */
    KBOX_FD_FLAG_LKL = (1U << 1),    /* backed by an LKL descriptor */
    KBOX_FD_FLAG_HOST = (1U << 2),   /* host-managed passthrough descriptor */
    KBOX_FD_FLAG_SHADOW = (1U << 3), /* has a host shadow memfd/socket */
};

struct kbox_fd_entry {
    uint32_t flags; /* bitmask of enum kbox_fd_flags */
    long lkl_fd;    /* LKL-internal FD, -1 if slot is free */
    long host_fd;   /* host memfd shadow / tracee FD number, -1 if none */
    /* Identity of the descriptor the tracee held at this number when the
     * entry was created, hashed from the /proc/<pid>/fd link target.
     *
     * A low descriptor's guest close now runs in the kernel, so kbox does not
     * see it and the entry stays behind. The number can then be reused by a
     * native pipe, and routing the pipe's bytes through this entry would send
     * them into the old file. The hash is what tells the two objects apart;
     * 0 means the entry predates this check or the descriptor could not be
     * read.
     */
    uint64_t guest_id;
    int watch_wd;   /* inotify watch on this descriptor's memfd, -1 if none */
    int host_sv_fd; /* supervisor-side FD sharing host-passthrough struct file
                     */
    int shadow_sp;  /* supervisor's dup of shadow socket sp[1], -1 if none.
                     * Kept alive so dup/dup2/dup3 can inject new copies into
                     * the tracee via ADDFD.
                     */
    int shadow_writeback;   /* 1 if shadow_sp must be synced back to lkl_fd */
    long shadow_mtime_sec;  /* shadow_sp timestamp when it was filled; */
    long shadow_mtime_nsec; /* unchanged means nothing wrote to it, so */
    long shadow_size;       /* the writeback at close can be skipped */
    int mirror_tty;         /* 1 if this FD mirrors a host TTY */
    int cloexec;            /* O_CLOEXEC tracking */
    int opath;              /* 1 if the guest opened it with O_PATH */
    int sock_type;          /* SOCK_STREAM / SOCK_DGRAM for shadow sockets */
    int sock_connected;     /* 1 once connect() or accept() produced a peer */
    /* The peer address the guest connected to, recorded at connect()/accept().
     *
     * A bridged socket's guest descriptor is a socketpair end, so the host's
     * getpeername() would name the socketpair. The connection's real peer is
     * the sockaddr the guest passed to connect(): Linux returns it for any
     * connected socket, and it stays true after the LKL twin has been retired
     * and its descriptor number reused.
     */
    int sock_peer_family; /* 0, AF_INET or AF_INET6 when recorded */
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } sock_peer;
    /* 1 once the connection is known to be established: connect() returned 0,
     * or the guest's SO_ERROR read came back 0, or LKL answered getpeername()
     * for it. A peer that is gone after that (a reset) must be reported as
     * ENOTCONN, so the recorded peer is only a substitute while the connection
     * is still coming up. */
    int sock_established;
    int shadow_mmap; /* 1 once a writable shared mapping covers the
                      * shadow: such writes change neither its size nor
                      * reliably its mtime, so the copy back at close can
                      * never be skipped. */
};

struct kbox_fd_table {
    /* Unified flat descriptor map indexed directly by guest FD in
     * [0, KBOX_FD_TABLE_CAPACITY). Each slot carries explicit ownership flags
     * (KBOX_FD_FLAG_LKL vs KBOX_FD_FLAG_HOST) instead of inferring ownership
     * from numeric partition ranges.
     */
    struct kbox_fd_entry slots[KBOX_FD_TABLE_CAPACITY];
    /* Reverse host-fd map: host_to_vfd[h] = virtual fd currently
     * holding host_fd h, or -1 if none. Eliminates the O(n) scan in
     * kbox_fd_table_find_by_host_fd() on the close() hot path.
     */
    int32_t host_to_vfd[KBOX_HOST_FD_REVERSE_MAX];
    /* Refcount: how many virtual fds currently reference each
     * lkl_fd. Replaces the O(n) lkl_fd_has_other_ref scan and the
     * still_ref loop in forward_close.
     */
    uint16_t lkl_fd_refs[KBOX_LKL_FD_REFMAX];
    /* Bitmap of high slots currently mapped to a low host_fd
     * (host_fd != vfd), letting the supervisor sweep natively closed bridged
     * sockets in O(number of bridged sockets) instead of scanning all 4096
     * slots. */
    uint64_t low_host_bitmap[KBOX_FD_TABLE_MAX / 64];
    unsigned low_host_count;
    long next_fd; /* Next virtual FD to allocate */
};

static inline bool kbox_fd_entry_is_active(const struct kbox_fd_entry *e)
{
    return e && (e->flags & KBOX_FD_FLAG_ACTIVE) != 0;
}

static inline bool kbox_fd_entry_is_host(const struct kbox_fd_entry *e)
{
    return e && (e->flags & KBOX_FD_FLAG_HOST) != 0;
}

static inline bool kbox_fd_entry_is_lkl(const struct kbox_fd_entry *e)
{
    return e && (e->flags & KBOX_FD_FLAG_LKL) != 0;
}

void kbox_fd_table_init(struct kbox_fd_table *t);
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty);
long kbox_fd_table_insert_lowest(struct kbox_fd_table *t,
                                 long lkl_fd,
                                 int mirror_tty);
long kbox_fd_table_insert_from(struct kbox_fd_table *t,
                               long min_fd,
                               long lkl_fd,
                               int mirror_tty);
long kbox_fd_table_insert_fast(struct kbox_fd_table *t,
                               long lkl_fd,
                               int mirror_tty);
int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty);
long kbox_fd_table_get_lkl(const struct kbox_fd_table *t, long fd);
long kbox_fd_table_remove(struct kbox_fd_table *t, long fd);
bool kbox_fd_table_mirror_tty(const struct kbox_fd_table *t, long fd);
void kbox_fd_table_set_cloexec(struct kbox_fd_table *t, long fd, int val);
int kbox_fd_table_get_cloexec(const struct kbox_fd_table *t, long fd);
void kbox_fd_table_set_opath(struct kbox_fd_table *t, long fd, int val);
int kbox_fd_table_get_opath(const struct kbox_fd_table *t, long fd);
void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s);
void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd);
long kbox_fd_table_get_host_fd(const struct kbox_fd_table *t, long fd);
long kbox_fd_table_find_by_host_fd(const struct kbox_fd_table *t, long host_fd);
void kbox_fd_table_set_host_sv_fd(struct kbox_fd_table *t, long fd, int sv_fd);
int kbox_fd_table_get_host_sv_fd(const struct kbox_fd_table *t, long fd);
/* Return the number of virtual FDs currently referencing @lkl_fd. */
unsigned kbox_fd_table_lkl_ref_count(const struct kbox_fd_table *t,
                                     long lkl_fd);
unsigned kbox_fd_table_count(const struct kbox_fd_table *t);

/* Identity of the object a descriptor names, hashed from the link target that
 * /proc/<pid>/fd/<n> resolves to ("/data/report.txt", "pipe:[1234]", ...).
 *
 * A guest close of a low descriptor runs in the kernel now, so kbox does not
 * observe it and the descriptor's table entry outlives the close. The number
 * can then be reused by a native pipe(), and routing the pipe's bytes through
 * the old entry would send them into the file the entry was made for. Entries
 * record this value at creation and compare it before routing.
 *
 * Returns 0 for NULL or an empty target, which callers treat as "no identity".
 */
uint64_t kbox_fd_link_identity(const char *target);

/* Identity of the object a descriptor names, derived from stat(2)'s
 * (st_dev, st_ino) on /proc/<pid>/fd/<n>.
 *
 * Unlike readlink(), stat() follows the magic link to the kernel inode, so
 * two distinct memfds with the same name ("/memfd:kbox-shadow (deleted)")
 * still produce distinct identities. Never returns 0 (0 is reserved for
 * "no identity").
 */
uint64_t kbox_fd_stat_identity(uint64_t dev, uint64_t ino);

/* Should an entry recorded as @recorded be dropped because the descriptor now
 * names a different object?
 *
 * @now is the fresh identity, and @err is the errno of the read that produced
 * it (0 when it succeeded). A mismatch is evidence of reuse. A failed read is
 * only evidence when it says the descriptor is gone: ENOENT or EBADF means the
 * call is about to fail with EBADF anyway, so the stale entry has to go. Any
 * other failure (EACCES, for instance) says nothing about the object and the
 * entry is kept.
 */
bool kbox_fd_identity_stale(uint64_t recorded, uint64_t now, int err);

#endif /* KBOX_FD_TABLE_H */
