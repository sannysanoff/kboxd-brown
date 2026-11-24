/* SPDX-License-Identifier: MIT */

#ifndef KBOX_FD_TABLE_H
#define KBOX_FD_TABLE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct kbox_sysnrs; /* forward declaration */

/* Virtual FD table.
 *
 * Maps guest-visible FDs (starting at KBOX_FD_BASE) to LKL-internal FDs. Flat
 * array indexed by (vfd - KBOX_FD_BASE). O(1) lookup, zero allocator overhead,
 * cache-friendly.
 */

#define KBOX_FD_BASE 32768
/* Guest descriptor space: 3072 descriptors a guest process can hold open at
 * once (the general band plus the writable-shadow band; the last quarter is
 * reserved for host-passthrough descriptors whose syscalls the BPF filter lets
 * through without a supervisor round trip).
 *
 * Growing this table is not a one-line change: sizes above 4096 expose a
 * descriptor-accounting leak under sustained open/close load (a 16384-entry
 * table loses the whole general band after one 12288-descriptor batch, with
 * /proc/self/fd empty in the guest and no entry ever removed twice). The
 * suites this table serves need a few hundred descriptors, so the proven size
 * is kept until that accounting bug is understood.
 */
#define KBOX_FD_TABLE_MAX 4096
#define KBOX_FD_FAST_BASE (KBOX_FD_BASE + (KBOX_FD_TABLE_MAX / 2))
#define KBOX_FD_HOSTONLY_BASE (KBOX_FD_BASE + ((KBOX_FD_TABLE_MAX * 3) / 4))

/* Host-passthrough descriptors that kbox injects itself -- pipes today -- are
 * installed in this band of low numbers, and the seccomp filter lets the kernel
 * close them without asking the supervisor.
 *
 * A close that goes through a notification can be lost: while the tracee waits
 * for the answer another task of its process group may deliver a signal, the
 * kernel then abandons the notification and the supervisor's answer fails with
 * ENOENT ("answer lost"). The close never runs, and the descriptor stays open.
 * A shell hits this on every command substitution whose child exits while the
 * parent closes the pipe, leaks the descriptor, and a pipeline reader waits for
 * an end-of-file that never comes. Measured: 20 -> 76 descriptors over 120
 * command substitutions while plain Docker stayed at 4, and jemalloc's
 * config.status hung on it.
 *
 * The band is below KBOX_LOW_FD_MAX so a program that selects on these
 * descriptors keeps them inside FD_SETSIZE. Nothing kbox must observe on close
 * lives here: the entries are plain host descriptors whose close is the
 * kernel's own business, and the table slot is rewritten when the number is
 * reused.
 */
#define KBOX_FD_PIPE_BASE 512
#define KBOX_FD_PIPE_TOP KBOX_LOW_FD_MAX /* exclusive */

/* The lowest RLIMIT_NOFILE a guest may set.
 *
 * A guest descriptor is a real descriptor in the tracee, numbered at
 * KBOX_FD_BASE or above: the forwarded mmap names it, and the kernel refuses
 * SECCOMP_IOCTL_NOTIF_ADDFD for a target at or above RLIMIT_NOFILE with EBADF.
 * A guest that lowers the limit to exercise descriptor exhaustion therefore
 * loses the ability to map any file. MariaDB's test runner does this, and every
 * library failed with ENODEV until the requested limit was raised back here.
 */
#define KBOX_GUEST_NOFILE_FLOOR (KBOX_FD_BASE + KBOX_FD_TABLE_MAX)

static inline void kbox_fd_floor_nofile_limit(uint64_t *cur, uint64_t *max)
{
    /* RLIM_INFINITY is UINT64_MAX and needs no change. */
    if (*max != UINT64_MAX && *max < KBOX_GUEST_NOFILE_FLOOR)
        *max = KBOX_GUEST_NOFILE_FLOOR;
    if (*cur < KBOX_GUEST_NOFILE_FLOOR)
        *cur = KBOX_GUEST_NOFILE_FLOOR;
}

/* redirect slots for FDs 0..1023 (dup2 targets) */
#define KBOX_LOW_FD_MAX 1024
/* tracked host-passthrough FDs in the gap [1024, 32768) */
#define KBOX_MID_FD_MAX (KBOX_FD_BASE - KBOX_LOW_FD_MAX)
#define KBOX_FD_TABLE_CAPACITY \
    (KBOX_FD_TABLE_MAX + KBOX_LOW_FD_MAX + KBOX_MID_FD_MAX)

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
     * (< KBOX_FD_BASE), letting the supervisor sweep natively closed bridged
     * sockets in O(number of bridged sockets) instead of scanning all 4096
     * slots. */
    uint64_t low_host_bitmap[KBOX_FD_TABLE_MAX / 64];
    unsigned low_host_count;
    long next_fd;          /* Next virtual FD to allocate */
    long next_fast_fd;     /* Next host-shadow fast FD to allocate */
    long next_hostonly_fd; /* Next host-only cached-shadow FD to allocate */
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
