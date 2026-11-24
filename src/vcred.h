/* SPDX-License-Identifier: MIT */
#ifndef KBOX_VCRED_H
#define KBOX_VCRED_H

/* Per-process virtual credentials and a file-ownership overlay.
 *
 * kbox runs unprivileged, so the host kernel cannot change a process's uid or
 * a file's owner. Official images do both: their entrypoints chown a data
 * directory and then drop privileges (gosu, su-exec, setpriv, clickhouse su),
 * and the server refuses to start as root or when the directory owner differs
 * from its euid. The guest therefore gets a virtual identity that follows the
 * setuid family's real semantics, and chown records the wanted owner in an
 * overlay that stat reports back.
 */

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Largest supplementary group list kbox models. Linux allows NGROUPS_MAX
 * (65536); a container process realistically holds a handful, and the guest
 * gets EINVAL above this, the same answer an oversized list gets from the
 * kernel when the buffer is too small. */
#define KBOX_VCRED_MAX_GROUPS 32

struct kbox_vcred {
    uint32_t ruid, euid, suid;
    uint32_t rgid, egid, sgid;
    /* Set once the process held euid 0. Group-id changes stay permitted
     * afterwards: setpriv and libcap-based droppers change the uid first and
     * rely on capabilities kept across setresuid(), which kbox does not model.
     */
    int had_root;
    /* Supplementary groups as last replaced by setgroups(2). Until a process
     * calls setgroups, the list is the effective gid alone, which is what a
     * container process starts with; `groups_set` tells the two cases apart,
     * because setgroups([]) is a legal empty list.
     */
    int groups_set;
    uint32_t ngroups;
    uint32_t groups[KBOX_VCRED_MAX_GROUPS];
};

/* True when pid may change group ids / supplementary groups. */
int kbox_vcred_may_setgid(pid_t pid);

/* Copy of pid's credentials. A pid never seen before inherits from its parent
 * (as fork would) and falls back to root. */
void kbox_vcred_get(pid_t pid, struct kbox_vcred *out);

/* setuid family. Arguments of -1 mean "leave unchanged". Return 0 or -errno
 * with Linux semantics: euid 0 may set anything, others only values already in
 * {real, effective, saved}. The gid variants follow the same rule keyed on
 * euid == 0 (stand-in for CAP_SETGID). */
/* setgroups(2): replace the supplementary group list. Returns 0, -EPERM when
 * pid may not change groups, or -EINVAL above KBOX_VCRED_MAX_GROUPS. */
int kbox_vcred_setgroups(pid_t pid, size_t n, const uint32_t *list);

/* Number of supplementary groups pid holds: the stored list after setgroups, or
 * one entry (the effective gid) for a process that never called it. */
int kbox_vcred_group_count(pid_t pid);

/* getgroups(2): copy the group list into out, at most size entries. Returns the
 * number of groups, or -EINVAL when size is smaller than the count. */
int kbox_vcred_getgroups(pid_t pid, size_t size, uint32_t *out);

int kbox_vcred_setresuid(pid_t pid, int64_t r, int64_t e, int64_t s);
int kbox_vcred_setresgid(pid_t pid, int64_t r, int64_t e, int64_t s);
int kbox_vcred_setuid(pid_t pid, int64_t u);
int kbox_vcred_setgid(pid_t pid, int64_t g);
int kbox_vcred_setreuid(pid_t pid, int64_t r, int64_t e);
int kbox_vcred_setregid(pid_t pid, int64_t r, int64_t e);

/* Drop a pid's record (called when it execs nothing special; kept for tests).
 */
void kbox_vcred_forget(pid_t pid);

/* Ownership overlay keyed by (device, inode). uid/gid of -1 keep the current
 * value. */
void kbox_owner_set(dev_t dev, ino_t ino, int64_t uid, int64_t gid);

/* Apply an explicit ownership overlay entry if one exists for (st_dev, st_ino).
 * Returns 1 when an overlay entry was applied, 0 otherwise. Unlike
 * kbox_owner_apply(), this never remaps the supervisor's real uid/gid, so it
 * is safe for LKL-backed files whose uid/gid already belong to the guest. */
int kbox_owner_apply_overlay(struct stat *st);

/* Rewrite st_uid/st_gid of a host stat result so the guest sees the virtual
 * identity: an overlay entry wins; otherwise a file owned by the supervisor's
 * real uid/gid appears owned by pid's effective ids. */
void kbox_owner_apply(pid_t pid, struct stat *st);

/* Guest ownership of a host file behind a bind mount, stored in the same
 * "uid:gid" form as the LKL hostfs driver uses, so the identity survives a
 * container restart and is shared by every container that sees the file.
 *
 * path may be absolute, or relative to dirfd, or empty (dirfd itself). The
 * lookup follows symlinks unless nofollow is set. Returns 1 when the xattr is
 * present and parsed, 0 when it is absent or unreadable. */
int kbox_owner_xattr_get(int dirfd,
                         const char *path,
                         int nofollow,
                         int64_t *uid,
                         int64_t *gid);
int kbox_owner_xattr_set(int dirfd,
                         const char *path,
                         int nofollow,
                         int64_t uid,
                         int64_t gid);

/* Record a guest chown on a host-backed file in both the in-memory overlay and
 * the persistent user.kbox.owner xattr, resolving any -1 component against the
 * file's current effective guest owner so the stored xattr is always valid. */
void kbox_owner_record_host(pid_t pid,
                            int dirfd,
                            const char *path,
                            int nofollow,
                            const struct stat *st,
                            int64_t owner,
                            int64_t group);
int kbox_owner_xattr_format(char *buf, size_t len, int64_t uid, int64_t gid);
int kbox_owner_xattr_parse(const char *buf, int64_t *uid, int64_t *gid);

/* Test hook: forget everything. */
void kbox_vcred_reset_for_test(void);

#endif
