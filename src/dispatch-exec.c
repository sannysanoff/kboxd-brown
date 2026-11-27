/* SPDX-License-Identifier: MIT */

/* Exec, mmap, mprotect, and clone3 handlers for the seccomp dispatch engine.
 *
 * forward_execve performs the seccomp-unotify pathname rewrite that lets the
 * guest exec a file it can open but not otherwise name.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#include "dispatch-internal.h"
#include "kbox/elf.h"
#include "kbox/path.h"
#include "procmem.h"
#include "shadow-fd.h"
#include "syscall-nr.h"

/* AT_EMPTY_PATH flag for execveat: indicates fexecve() usage. Defined here to
 * avoid pulling in the full linux/fcntl.h.
 */
#define KBOX_AT_EMPTY_PATH 0x1000

/* Load biases for the userspace ELF loader. Must match
 * prepare_userspace_launch. The loader places main and interpreter ELFs at
 * these fixed virtual addresses, and the stack just below stack_top.
 */
#define KBOX_EXEC_MAIN_LOAD_BIAS 0x600000000000ULL
#define KBOX_EXEC_INTERP_LOAD_BIAS 0x610000000000ULL
#define KBOX_EXEC_STACK_TOP 0x700000010000ULL

static pid_t tracee_parent_of(pid_t pid)
{
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int) pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    char *paren = strrchr(buf, ')');
    if (!paren)
        return -1;
    pid_t pp = -1;
    if (sscanf(paren + 2, "%*c %d", &pp) != 1)
        return -1;
    return pp;
}

static pid_t tracee_tgid_of(pid_t pid)
{
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/status", (int) pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    const char *p = strstr(buf, "Tgid:");
    if (!p)
        return -1;
    pid_t tgid = -1;
    if (sscanf(p + 5, "%d", &tgid) != 1)
        return -1;
    return tgid;
}

static const char *find_guest_exe_exact(const struct kbox_supervisor_ctx *ctx,
                                        pid_t pid)
{
    if (pid <= 0)
        return NULL;
    for (size_t i = 0; i < sizeof(ctx->exe_map) / sizeof(ctx->exe_map[0]);
         i++) {
        if (ctx->exe_map[i].pid == pid && ctx->exe_map[i].path[0])
            return ctx->exe_map[i].path;
    }
    return NULL;
}

/* /proc/self/exe for a given process: the path it last exec'd, else its thread
 * group leader / recent ancestor's exe_map entry, else the container's initial
 * guest_exe. */
const char *kbox_guest_exe_for(struct kbox_supervisor_ctx *ctx, pid_t pid)
{
    const char *found = find_guest_exe_exact(ctx, pid);
    if (found)
        return found;

    pid_t tgid = tracee_tgid_of(pid);
    if (tgid > 0 && tgid != pid) {
        found = find_guest_exe_exact(ctx, tgid);
        if (found)
            return found;
    }

    pid_t cur = (tgid > 0) ? tgid : pid;
    for (int depth = 0; depth < 4 && cur > 1; depth++) {
        pid_t pp = tracee_parent_of(cur);
        if (pp <= 1)
            break;
        found = find_guest_exe_exact(ctx, pp);
        if (found)
            return found;
        cur = pp;
    }
    return ctx->guest_exe;
}

/* Resolve every symlink in an absolute guest path through LKL, like the
 * kernel does for /proc/<pid>/exe. A loader that expands $ORIGIN from that link
 * (glibc and musl both do) must see the real directory: /usr/bin/java is a
 * symlink into /usr/lib/jvm/..., and java finds libjli.so relative to the real
 * binary. Returns 0 and fills out, or -1 (caller keeps the unresolved path). */
int kbox_guest_exe_realpath(const struct kbox_supervisor_ctx *ctx,
                            const char *in,
                            char *out,
                            size_t out_size)
{
    char rest[KBOX_MAX_PATH];
    char cur[KBOX_MAX_PATH];
    int hops = 0;

    if (in[0] != '/' || strlen(in) >= sizeof(rest))
        return -1;
    snprintf(rest, sizeof(rest), "%s", in);
    cur[0] = '\0';

    while (rest[0]) {
        char *comp = rest;
        while (*comp == '/')
            comp++;
        if (!*comp)
            break;
        char *end = comp;
        while (*end && *end != '/')
            end++;
        char saved = *end;
        *end = '\0';

        if (strcmp(comp, ".") == 0) {
            /* nothing */
        } else if (strcmp(comp, "..") == 0) {
            char *slash = strrchr(cur, '/');
            if (slash)
                *slash = '\0';
        } else {
            size_t cl = strlen(cur);
            if (cl + 1 + strlen(comp) >= sizeof(cur))
                return -1;
            cur[cl] = '/';
            snprintf(cur + cl + 1, sizeof(cur) - cl - 1, "%s", comp);

            char target[KBOX_MAX_PATH];
            long n = kbox_lkl_readlinkat(ctx->sysnrs, AT_FDCWD_LINUX, cur,
                                         target, sizeof(target) - 1);
            if (n > 0) {
                if (++hops > 40)
                    return -1;
                target[n] = '\0';
                char tail[KBOX_MAX_PATH];
                *end = saved;
                snprintf(tail, sizeof(tail), "%s", end);
                if (target[0] == '/')
                    cur[0] = '\0';
                else
                    *strrchr(cur, '/') = '\0';
                if (snprintf(rest, sizeof(rest), "%s%s", target, tail) >=
                    (int) sizeof(rest))
                    return -1;
                continue;
            }
        }
        *end = saved;
        memmove(rest, end, strlen(end) + 1);
    }
    if (snprintf(out, out_size, "%s", cur[0] ? cur : "/") >= (int) out_size)
        return -1;
    return 0;
}

void kbox_guest_exe_set(struct kbox_supervisor_ctx *ctx,
                        pid_t pid,
                        const char *path)
{
    size_t n = sizeof(ctx->exe_map) / sizeof(ctx->exe_map[0]);
    size_t free_slot = n;

    if (!path || !path[0])
        return;

    for (size_t i = 0; i < n; i++) {
        if (ctx->exe_map[i].pid == pid) {
            snprintf(ctx->exe_map[i].path, sizeof(ctx->exe_map[i].path), "%s",
                     path);
            return;
        }
        if (free_slot == n && ctx->exe_map[i].pid == 0)
            free_slot = i;
    }
    /* Slots are never released when a process exits, so a long-running
     * container (a shell script forking sed/grep/dirname in a loop) fills all
     * of them. A full table silently dropped the new entry and /proc/self/exe
     * then named an ancestor -- the JVM launcher computed $ORIGIN from
     * /bin/bash and could not find libjli.so. Reuse the slot of a dead
     * process; if every one is alive, replace the oldest-numbered pid. */
    if (free_slot == n) {
        for (size_t i = 0; i < n; i++) {
            if (kill(ctx->exe_map[i].pid, 0) < 0 && errno == ESRCH) {
                free_slot = i;
                break;
            }
        }
    }
    if (free_slot == n) {
        free_slot = 0;
        for (size_t i = 1; i < n; i++)
            if (ctx->exe_map[i].pid < ctx->exe_map[free_slot].pid)
                free_slot = i;
    }
    if (free_slot < n) {
        ctx->exe_map[free_slot].pid = pid;
        snprintf(ctx->exe_map[free_slot].path,
                 sizeof(ctx->exe_map[free_slot].path), "%s", path);
    }
}

/* mmap dispatch: if the FD is a virtual FD with no host shadow, create the
 * shadow on demand (lazy shadow) and inject it into the tracee at the same FD
 * number, then CONTINUE so the host kernel mmaps the real fd.
 *
 * Lazy shadow creation avoids the memfd_create + file-copy cost at every open.
 * The shadow is only materialized when the guest actually mmaps.
 */
struct kbox_dispatch forward_mmap(const struct kbox_syscall_request *req,
                                  struct kbox_supervisor_ctx *ctx)
{
    long fd = to_dirfd_arg(kbox_syscall_request_arg(req, 4));

    if (fd == -1)
        return kbox_dispatch_continue();

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    if (lkl_fd == KBOX_LKL_FD_SHADOW_ONLY ||
        (lkl_fd < 0 && !fd_should_deny_io_ctx(ctx->fd_table, fd, lkl_fd)))
        return kbox_dispatch_continue();
    if (lkl_fd < 0)
        return kbox_dispatch_errno(EBADF);

    /* A writable shared mapping of a shadow memfd modifies the memfd through
     * the page cache: its size does not change and its mtime is not stamped
     * when the guest expects it. Record that so the copy back at close always
     * runs; gdbm's ndbm backend writes its pages this way, and the skipped
     * copy lost every stored key (test_dbm_ndbm).
     */
    {
        int mmap_flags = (int) kbox_syscall_request_arg(req, 3);
        int mmap_prot = (int) kbox_syscall_request_arg(req, 2);
        struct kbox_fd_entry *hp = fd_table_entry(ctx->fd_table, fd);

        if (hp && hp->host_fd == KBOX_FD_HOST_SAME_FD_SHADOW &&
            (mmap_flags & MAP_SHARED) != 0 && (mmap_prot & PROT_WRITE) != 0) {
            hp->shadow_mmap = 1;
            invalidate_path_shadow_cache(ctx);
        }
    }

    if (lkl_fd >= 0) {
        long host = kbox_fd_table_get_host_fd(ctx->fd_table, fd);
        if (host == -1 || host == KBOX_FD_LOCAL_ONLY_SHADOW) {
            /* Only create lazy shadows for read-only/private mappings.
             * Writable MAP_SHARED mappings on LKL files cannot be supported
             * via memfd (writes would go to the copy, not LKL).
             */
            int mmap_flags = (int) kbox_syscall_request_arg(req, 3);
            int mmap_prot = (int) kbox_syscall_request_arg(req, 2);
            if ((mmap_flags & MAP_SHARED) && (mmap_prot & PROT_WRITE)) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: mmap ENODEV: writable shared fd=%ld lkl=%ld "
                            "prot=0x%x flags=0x%x\n",
                            fd, lkl_fd, mmap_prot, mmap_flags);
                return kbox_dispatch_errno(ENODEV);
            }

            struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);
            int memfd = -1;
            int own_memfd = 0;
            if (host == KBOX_FD_LOCAL_ONLY_SHADOW && entry &&
                entry->shadow_sp >= 0) {
                memfd = entry->shadow_sp;
            } else if (kbox_reopen_writeback_shadow_ro(ctx, lkl_fd, &memfd)) {
                own_memfd = 1;
            } else {
                memfd = kbox_shadow_create_resilient(ctx, lkl_fd);
                if (memfd < 0) {
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: mmap ENODEV: shadow fd=%ld lkl=%ld "
                                "ret=%d\n",
                                fd, lkl_fd, memfd);
                    return kbox_dispatch_errno(ENODEV);
                }
                kbox_shadow_seal(memfd);
                own_memfd = 1;
            }
            int injected = request_addfd_at(ctx, req, memfd, (int) fd, 0);
            if (injected < 0) {
                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: mmap ENODEV: addfd fd=%ld memfd=%d ret=%d\n",
                            fd, memfd, injected);
                if (own_memfd)
                    close(memfd);
                return kbox_dispatch_errno(ENODEV);
            }
            /* Mark that a shadow was injected so repeated mmaps do not
             * re-create it. Use -2 as a sentinel: host_fd >= 0 means
             * "supervisor-owned shadow fd" (closed on remove). host_fd == -2
             * means "tracee-owned shadow, don't close in supervisor."
             * fd_table_remove only closes host_fd when host_fd >= 0 AND
             * shadow_sp < 0, so -2 is safe.
             */
            kbox_fd_table_set_host_fd(ctx->fd_table, fd,
                                      KBOX_FD_HOST_SAME_FD_SHADOW);
            if (entry && own_memfd)
                entry->shadow_sp = memfd;
        }
    }

    return kbox_dispatch_continue();
}

/* mprotect needs no supervision: the host kernel applies it unchanged. */
struct kbox_dispatch forward_mprotect(const struct kbox_syscall_request *req,
                                      struct kbox_supervisor_ctx *ctx)
{
    (void) req;
    (void) ctx;
    return kbox_dispatch_continue();
}

/* clone3 namespace-flag sanitization. */

/* CLONE_NEW* flags that clone3 can smuggle in via clone_args.flags. The BPF
 * deny-list blocks unshare/setns, but clone3 bypasses it unless we check here.
 */
struct kbox_dispatch forward_clone3(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx)
{
    uint64_t flags;
    int rc;

    /* clone3(struct clone_args *args, size_t size). flags is the first uint64_t
     * field in clone_args. We only need to read the first 8 bytes.
     */
    rc =
        guest_mem_read(ctx, kbox_syscall_request_pid(req),
                       kbox_syscall_request_arg(req, 0), &flags, sizeof(flags));
    if (rc < 0) {
        /* Can't read tracee memory; fail closed with EPERM.
         *
         * CONTINUE is unsafe here: a tracee can clear dumpability via
         * prctl(PR_SET_DUMPABLE, 0), causing process_vm_readv to fail with
         * EPERM. If we CONTINUE, clone3 reaches host kernel with unchecked
         * namespace flags: a sandbox escape. Returning EPERM is the only safe
         * option.
         */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: cannot read clone_args "
                    "(pid=%u, rc=%d)\n",
                    kbox_syscall_request_pid(req), rc);
        return kbox_dispatch_errno(EPERM);
    }

    if (flags & CLONE_NEW_MASK) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: clone3 denied: namespace flags 0x%llx "
                    "(pid=%u)\n",
                    (unsigned long long) (flags & CLONE_NEW_MASK),
                    kbox_syscall_request_pid(req));
        return kbox_dispatch_errno(EPERM);
    }
    if (getenv("KBOX_TRACE"))
        fprintf(stderr, "kbox: clone3 pid=%u flags=%#llx\n",
                kbox_syscall_request_pid(req), (unsigned long long) flags);

    /* vfork. kbox performs an exec by rewriting the pathname in the tracee's
     * memory, which is unsafe for a child that shares the parent's address
     * space: the rewrite lands in the parent's stack, so after the child
     * execs the parent resumes with "/proc/self/fd/N" where its own path used
     * to be and every later fork execs that stale descriptor (initdb's
     * bootstrap, popen, system all go through CLONE_VM|CLONE_VFORK).
     *
     * Turn it into a plain fork. The child still execs immediately and the
     * parent still waits for it to exit, which is all posix_spawn and popen
     * need; the only difference is that the parent may run alongside the child
     * until it execs, which nothing in this path observes.
     */
    if (flags & CLONE_VFORK) {
        flags &=
            ~(uint64_t) (CLONE_VFORK | CLONE_VM | CLONE_SIGHAND | CLONE_THREAD);
        flags |= SIGCHLD;
        if (ctx->verbose || getenv("KBOX_TRACE"))
            fprintf(stderr, "kbox: clone3: vfork downgraded to fork (pid=%u)\n",
                    kbox_syscall_request_pid(req));
    }

    /* Write the validated flags back to the guest's clone_args struct to
     * narrow the TOCTOU window: if a sibling thread mutated the flags between
     * our read and the host kernel's re-read, this overwrites the mutation.
     *
     * A residual race remains (sibling writes after our write-back but before
     * the host kernel reads), but for single-threaded guests -- kbox's normal
     * mode -- the risk is zero.
     */
    int wrc = guest_mem_write(ctx, kbox_syscall_request_pid(req),
                              kbox_syscall_request_arg(req, 0), &flags,
                              sizeof(flags));
    if (wrc < 0)
        return kbox_dispatch_errno(-wrc);
#ifndef CLONE_FILES
#define CLONE_FILES 0x00000400
#endif
    if (!(flags & (CLONE_THREAD | CLONE_FILES)))
        kbox_dispatch_snapshot_fork(ctx, kbox_syscall_request_pid(req));
    return kbox_dispatch_continue();
}

/* Handle execve/execveat from inside the image.
 *
 * For fexecve (execveat with AT_EMPTY_PATH on a host memfd): CONTINUE, the host
 * kernel handles it directly. This is the initial exec path from image.c.
 *
 * For in-image exec (e.g. shell runs /bin/ls):
 *   1. Read the pathname from tracee memory
 *   2. Open the binary from LKL, create a memfd
 *   3. Check for PT_INTERP; if dynamic, extract interpreter into a second memfd
 *      and patch PT_INTERP to /proc/self/fd/N
 *   4. Inject memfds into the tracee via ADDFD
 *   5. Overwrite the pathname in tracee memory with /proc/self/fd/N
 *   6. CONTINUE: kernel re-reads the rewritten path and execs
 *
 * The seccomp-unotify guarantees the tracee is blocked during steps 1-5, and
 * the kernel has not yet copied the pathname (getname happens after the seccomp
 * check), so the overwrite is race-free.
 */
static int read_tracee_sp(pid_t pid, uint64_t *sp_out)
{
    char pbuf[64];
    char sbuf[512];
    int fd;
    ssize_t n;

    snprintf(pbuf, sizeof(pbuf), "/proc/%d/syscall", (int) pid);
    fd = open(pbuf, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = read(fd, sbuf, sizeof(sbuf) - 1);
    close(fd);
    if (n <= 0)
        return -ENOENT;
    sbuf[n] = '\0';

    /* Format: "<nr> <arg0> <arg1> <arg2> <arg3> <arg4> <arg5> <sp> <ip>" */
    char *p = sbuf;
    for (int col = 0; col < 7; col++) {
        while (*p && *p != ' ' && *p != '\t')
            p++;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            return -ENOENT;
    }
    errno = 0;
    uint64_t sp = (uint64_t) strtoull(p, NULL, 16);
    if (errno || sp < 4096)
        return -EINVAL;
    *sp_out = sp;
    return 0;
}

static int write_guest_mem_any(const struct kbox_supervisor_ctx *ctx,
                               pid_t pid,
                               uint64_t addr,
                               const void *buf,
                               size_t len)
{
    int rc = guest_mem_write(ctx, pid, addr, buf, len);
    if (rc < 0)
        rc = guest_mem_write_force(ctx, pid, addr, buf, len);
    return rc;
}

#define MAX_EXEC_RELOC 32
#define MAX_EXEC_ARG_STR (256 * 1024)

struct exec_str_reloc {
    uint64_t old_ptr;
    size_t offset;
    size_t len_with_nul;
    char *str;
};

struct exec_slot_update {
    uint64_t slot_addr;
    size_t reloc_idx;
};

/* Read a NUL-terminated string from tracee memory up to @max_len bytes.
 * Needed for execve argv[]/envp[] entries (such as long shell commands in
 * make/libtool) that exceed KBOX_MAX_PATH and still sit immediately after a
 * short pathname like "/bin/sh".
 */
static int read_guest_cstr_alloc(const struct kbox_supervisor_ctx *ctx,
                                 pid_t pid,
                                 uint64_t addr,
                                 size_t max_len,
                                 char **out_str,
                                 size_t *out_len)
{
    size_t cap = 4096;
    size_t pos = 0;
    char *buf = malloc(cap);

    if (!buf)
        return -ENOMEM;

    while (pos < max_len) {
        size_t chunk = 4096;
        if (chunk > max_len - pos)
            chunk = max_len - pos;
        if (pos + chunk > cap) {
            size_t new_cap = cap * 2;
            if (new_cap < pos + chunk)
                new_cap = pos + chunk;
            char *nb = realloc(buf, new_cap);
            if (!nb) {
                free(buf);
                return -ENOMEM;
            }
            buf = nb;
            cap = new_cap;
        }
        /* Read in page-aligned pieces so we don't fault past the end of a VMA
         * when the string sits near a page boundary. */
        uint64_t cur = addr + (uint64_t) pos;
        size_t to_page = 4096 - (size_t) (cur & 4095U);
        if (chunk > to_page)
            chunk = to_page;

        if (guest_mem_read(ctx, pid, cur, buf + pos, chunk) < 0) {
            /* Retry byte-by-byte only if the very first chunk failed? No, a
             * page-aligned read inside a valid mapping always succeeds. */
            free(buf);
            return -EFAULT;
        }
        const void *nul = memchr(buf + pos, '\0', chunk);
        if (nul) {
            size_t len_with_nul = (size_t) ((const char *) nul - buf) + 1;
            *out_str = buf;
            *out_len = len_with_nul;
            return 0;
        }
        pos += chunk;
    }

    free(buf);
    return -ENAMETOOLONG;
}

static int relocate_overlapping_exec_vecs(const struct kbox_supervisor_ctx *ctx,
                                          pid_t pid,
                                          uint64_t path_addr,
                                          size_t new_bytes,
                                          uint64_t argv_addr,
                                          uint64_t envp_addr)
{
    struct exec_str_reloc relocs[MAX_EXEC_RELOC];
    struct exec_slot_update slots[MAX_EXEC_RELOC * 2];
    size_t reloc_cnt = 0;
    size_t slot_cnt = 0;
    size_t total_bytes = 0;
    uint64_t win_end = path_addr + (uint64_t) new_bytes;
    uint64_t vecs[2] = {argv_addr, envp_addr};
    int rc = 0;

    for (int vi = 0; vi < 2; vi++) {
        uint64_t base = vecs[vi];
        if (!base)
            continue;
        for (size_t idx = 0; idx < 8192; idx++) {
            uint64_t ptr = 0;
            uint64_t slot_addr = base + (uint64_t) idx * sizeof(uint64_t);
            if (guest_mem_read(ctx, pid, slot_addr, &ptr, sizeof(ptr)) < 0 ||
                ptr == 0)
                break;

            if (ptr >= win_end)
                continue;
            if (ptr < path_addr && path_addr - ptr >= MAX_EXEC_ARG_STR)
                continue;

            size_t found = (size_t) -1;
            for (size_t r = 0; r < reloc_cnt; r++) {
                if (relocs[r].old_ptr == ptr) {
                    found = r;
                    break;
                }
            }
            if (found == (size_t) -1) {
                char *str_buf = NULL;
                size_t slen = 0;
                if (read_guest_cstr_alloc(ctx, pid, ptr, MAX_EXEC_ARG_STR,
                                          &str_buf, &slen) < 0)
                    continue;
                if (ptr < path_addr && ptr + (uint64_t) slen <= path_addr) {
                    free(str_buf);
                    continue;
                }
                if (reloc_cnt >= MAX_EXEC_RELOC) {
                    free(str_buf);
                    rc = -E2BIG;
                    goto out;
                }
                found = reloc_cnt++;
                relocs[found].old_ptr = ptr;
                relocs[found].offset = total_bytes;
                relocs[found].len_with_nul = slen;
                relocs[found].str = str_buf;
                total_bytes += slen;
            }
            if (slot_cnt >= MAX_EXEC_RELOC * 2) {
                rc = -E2BIG;
                goto out;
            }
            slots[slot_cnt].slot_addr = slot_addr;
            slots[slot_cnt].reloc_idx = found;
            slot_cnt++;
        }
    }

    if (reloc_cnt == 0)
        goto out;

    uint64_t sp = 0;
    rc = read_tracee_sp(pid, &sp);
    if (rc < 0)
        goto out;

    char *packed = malloc(total_bytes);
    if (!packed) {
        rc = -ENOMEM;
        goto out;
    }
    for (size_t r = 0; r < reloc_cnt; r++)
        memcpy(packed + relocs[r].offset, relocs[r].str,
               relocs[r].len_with_nul);

    /* Place packed strings safely below tracee stack pointer (past redzone). */
    uint64_t scratch = (sp - 512 - (uint64_t) total_bytes) & ~(uint64_t) 15;
    rc = write_guest_mem_any(ctx, pid, scratch, packed, total_bytes);
    free(packed);
    if (rc < 0)
        goto out;

    for (size_t s = 0; s < slot_cnt; s++) {
        uint64_t new_ptr =
            scratch + (uint64_t) relocs[slots[s].reloc_idx].offset;
        rc = write_guest_mem_any(ctx, pid, slots[s].slot_addr, &new_ptr,
                                 sizeof(new_ptr));
        if (rc < 0)
            goto out;
    }

out:
    for (size_t r = 0; r < reloc_cnt; r++)
        free(relocs[r].str);
    return rc;
}


/* Rewrite a #! script so the host kernel can exec it.
 *
 * binfmt_script resolves the shebang to a host path, which for a guest script
 * names an interpreter that does not exist outside LKL. The interpreter is
 * opened and shadowed inside the guest instead, injected into the tracee, and
 * the shebang is rewritten to /proc/self/fd/<n>; the kernel then execs the
 * injected interpreter and passes the script as argv[1]. The script itself is
 * rebuilt as a fresh memfd (new shebang line, then the body from the first
 * newline on) and handed back through *exec_memfd, to be injected without
 * O_CLOEXEC so it is still open when the interpreter tries to read it.
 *
 * Returns 0, or -errno.
 */
/* Escape a path for POSIX sh, in single quotes. */
static void shell_quote_into(char *out, size_t size, const char *s)
{
    size_t n = 0;
    if (n + 1 < size)
        out[n++] = '\'';
    for (; *s && n + 5 < size; s++) {
        if (*s == '\'') {
            memcpy(out + n, "'\\''", 4);
            n += 4;
        } else {
            out[n++] = *s;
        }
    }
    if (n + 1 < size)
        out[n++] = '\'';
    out[n] = '\0';
}

/* Does this shebang run a POSIX shell? Either the interpreter itself is one, or
 * it is an exec wrapper (env, busybox) whose first argument names one. */
static int shebang_runs_a_shell(const char *interp_name,
                                const char *arg,
                                size_t arg_len)
{
    static const char *const shells[] = {"sh",  "bash", "dash", "ash",
                                         "ksh", "zsh",  "mksh", NULL};
    const char *names[2] = {interp_name, NULL};
    char argbuf[64];

    if (arg && arg_len > 0 && arg_len < sizeof(argbuf)) {
        memcpy(argbuf, arg, arg_len);
        argbuf[arg_len] = '\0';
        names[1] = argbuf;
    }
    for (size_t i = 0; i < 2; i++) {
        if (!names[i])
            continue;
        const char *slash = strrchr(names[i], '/');
        const char *base = (slash && slash[1]) ? slash + 1 : names[i];
        for (size_t k = 0; shells[k]; k++) {
            if (strcmp(base, shells[k]) == 0)
                return 1;
        }
    }
    return 0;
}

/* 1 when pathbuf names a path the *guest* can open.
 *
 * An exec through a descriptor (execveat AT_EMPTY_PATH, execve of
 * /proc/self/fd/N) has no such path: kbox passes a placeholder or the magic
 * link itself. Writing that into the script prologue makes the interpreter
 * report "can't open '<fexecve>'" and the exec fails, so the prologue is only
 * emitted for a real path.
 *
 * A relative path names a real file: the prologue runs in the working
 * directory the exec was made from, so "./configure" resolves to the file the
 * guest asked for. Requiring an absolute path here left every make-driven
 * build with $0 still pointing at the descriptor, and autoconf reads its
 * source directory from $0 ("cannot find sources (Makefile.in) in
 * /proc/self/fd or .." when a build runs "cd jemalloc && ./configure").
 */
static int script_path_is_usable(const char *pathbuf)
{
    if (!pathbuf || !pathbuf[0] || pathbuf[0] == '<')
        return 0;
    if (!strncmp(pathbuf, "/proc/self/fd/", 14) ||
        !strncmp(pathbuf, "/proc/thread-self/fd/", 21) ||
        !strncmp(pathbuf, "/dev/fd/", 8))
        return 0;
    return 1;
}

static int rewrite_script_shebang(struct kbox_supervisor_ctx *ctx,
                                  const struct kbox_syscall_request *req,
                                  int *exec_memfd,
                                  const char *pathbuf)
{
    unsigned char hdr[512];
    ssize_t hn = pread(*exec_memfd, hdr, sizeof(hdr), 0);
    if (hn < 3 || hdr[0] != '#' || hdr[1] != '!')
        return -ENOEXEC;

    size_t i = 2;
    while (i < (size_t) hn && (hdr[i] == ' ' || hdr[i] == '\t'))
        i++;
    size_t interp_start = i;
    while (i < (size_t) hn && hdr[i] != '\n' && hdr[i] != ' ' && hdr[i] != '\t')
        i++;
    size_t interp_len = i - interp_start;
    if (interp_len == 0 || interp_len >= 256)
        return -ENOEXEC;

    char interp[256];
    memcpy(interp, hdr + interp_start, interp_len);
    interp[interp_len] = '\0';

    while (i < (size_t) hn && (hdr[i] == ' ' || hdr[i] == '\t'))
        i++;
    size_t arg_start = i;
    while (i < (size_t) hn && hdr[i] != '\n')
        i++;
    size_t arg_len = i - arg_start;

    off_t body = -1;
    for (ssize_t k = 0; k < hn; k++) {
        if (hdr[k] == '\n') {
            body = (off_t) k + 1;
            break;
        }
    }
    if (body < 0)
        return -ENOEXEC;

    long interp_lkl =
        kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, interp, O_RDONLY, 0);
    if (interp_lkl < 0)
        return (int) interp_lkl;

    int interp_memfd = kbox_shadow_create_resilient(ctx, interp_lkl);
    lkl_close_and_invalidate(ctx, interp_lkl);
    if (interp_memfd < 0)
        return interp_memfd;

    /* The interpreter may itself be a script: Oracle Linux ships /usr/bin/env
     * as "#!/usr/bin/coreutils --coreutils-prog-shebang=env". Its shebang names
     * a guest path as well, so rewrite it the same way. The kernel then follows
     * two shebang levels, both pointing at injected descriptors. */
    static __thread int nested_depth;
    int interp_is_script = 0;
    {
        char magic[2];

        if (pread(interp_memfd, magic, sizeof(magic), 0) ==
                (ssize_t) sizeof(magic) &&
            magic[0] == '#' && magic[1] == '!') {
            if (nested_depth >= 4) {
                close(interp_memfd);
                return -ELOOP;
            }
            nested_depth++;
            int nrc = rewrite_script_shebang(ctx, req, &interp_memfd, interp);
            nested_depth--;
            if (nrc < 0) {
                close(interp_memfd);
                return nrc;
            }
            interp_is_script = 1;
        }
    }

    /* The interpreter is a program in its own right: when it is dynamically
     * linked its PT_INTERP names the guest loader, which the host kernel
     * cannot open either. Patch it to an injected memfd of the loader, the
     * same way the ELF path does for the executable. */
    {
        unsigned char *elf_buf = NULL;
        size_t elf_buf_len = 0;

        if (kbox_read_elf_header_window_fd(interp_memfd, &elf_buf,
                                           &elf_buf_len) == 0) {
            char loader[256];
            uint64_t pt_offset, pt_filesz;
            int llen = kbox_find_elf_interp_loc(elf_buf, elf_buf_len, loader,
                                                sizeof(loader), &pt_offset,
                                                &pt_filesz);
            munmap(elf_buf, elf_buf_len);

            if (llen > 0) {
                long loader_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  loader, O_RDONLY, 0);
                if (loader_lkl >= 0) {
                    int loader_memfd =
                        kbox_shadow_create_resilient(ctx, loader_lkl);
                    lkl_close_and_invalidate(ctx, loader_lkl);
                    if (loader_memfd >= 0) {
                        int tracee_loader_fd =
                            request_addfd(ctx, req, loader_memfd, O_CLOEXEC);
                        close(loader_memfd);
                        if (tracee_loader_fd >= 0) {
                            char patched[64];
                            int plen =
                                snprintf(patched, sizeof(patched),
                                         "/proc/self/fd/%d", tracee_loader_fd);
                            char patch[256];
                            size_t pl = (size_t) pt_filesz;
                            if (pl > sizeof(patch))
                                pl = sizeof(patch);
                            memset(patch, 0, pl);
                            memcpy(patch, patched, (size_t) plen);
                            if (pwrite(interp_memfd, patch, pl,
                                       (off_t) pt_offset) != (ssize_t) pl) {
                                close(interp_memfd);
                                return -EIO;
                            }
                        }
                    }
                }
            }
        }
    }

    /* A script interpreter stays open across exec: the interpreter that runs it
     * can still be handed its path as an argument. */
    int tracee_interp_fd =
        request_addfd(ctx, req, interp_memfd, interp_is_script ? 0 : O_CLOEXEC);
    close(interp_memfd);
    if (tracee_interp_fd < 0)
        return tracee_interp_fd;

    /* The kernel sets argv[0] to the interpreter path it was given, and
     * busybox picks its applet from basename(argv[0]) -- "/proc/self/fd/10"
     * would look for an applet called "10". Point the shebang at a symlink
     * that keeps the interpreter's own name and resolves, in the tracee's
     * context, to the injected memfd. */
    /* The interpreter is referenced by descriptor, not by a symlink under the
     * daemon's /tmp: that directory is the supervisor's, the guest has its own
     * /tmp (a tmpfs), and a shebang naming a path only the daemon can see makes
     * the kernel answer ENOENT for the whole exec. Scripts run from initdb,
     * popen and other spawn helpers died exactly that way.
     *
     * The cost is that argv[0] of the interpreter reads "/proc/self/fd/<n>",
     * which matters only to applets that dispatch on their own name (busybox).
     */
    char interp_name[128];
    {
        const char *slash = strrchr(interp, '/');
        snprintf(interp_name, sizeof(interp_name), "%s",
                 (slash && slash[1]) ? slash + 1 : interp);
    }
    /* Give the interpreter a path whose basename is its own name. The kernel
     * sets the interpreter's argv[0] to the path in the shebang, and multi-call
     * binaries dispatch on it: busybox answers "10: applet not found" for
     * /proc/self/fd/10, and uutils coreutils refuses the exec outright. The
     * link target stays the injected descriptor, so the bytes still come from
     * the guest's own interpreter.
     *
     * The directory has to sit on a mount the tracee shares with this process:
     * /dev/shm is a tmpfs of the pod, /tmp is tried second because some
     * containers get their own tmpfs there.
     */
    static char interp_link[320];
    int have_link_ref = 0;
    interp_link[0] = '\0';
    {
        static const char *const link_bases[] = {"/dev/shm/kbox-exec-links",
                                                 "/tmp/kbox-exec-links"};
        static unsigned exec_link_seq;
        char link_path[320] = {0};

        for (size_t b = 0;
             b < sizeof(link_bases) / sizeof(link_bases[0]) && !link_path[0];
             b++) {
            (void) mkdir(link_bases[b], 0777);
            for (unsigned attempt = 0; attempt < 8; attempt++) {
                unsigned seq =
                    __atomic_add_fetch(&exec_link_seq, 1, __ATOMIC_RELAXED);
                char link_dir[256];
                snprintf(link_dir, sizeof(link_dir), "%s/%d-%u", link_bases[b],
                         (int) getpid(), seq);
                if (mkdir(link_dir, 0777) == 0) {
                    char candidate[320];
                    snprintf(candidate, sizeof(candidate), "%s/%s", link_dir,
                             interp_name);
                    char target[64];
                    snprintf(target, sizeof(target), "/proc/self/fd/%d",
                             tracee_interp_fd);
                    if (symlink(target, candidate) == 0)
                        snprintf(link_path, sizeof(link_path), "%s", candidate);
                    else
                        (void) rmdir(link_dir);
                    if (link_path[0])
                        break;
                }
            }
        }

        if (link_path[0]) {
            have_link_ref = 1;
            memcpy(interp_link, link_path, sizeof(interp_link));
        }
    }


    char shebang[512];
    int shebang_len;
    const char *interp_ref = have_link_ref ? interp_link : NULL;
    if (!interp_ref) {
        /* Fall back to the memfd path: fine for interpreters that do not
         * dispatch on argv[0], broken for busybox. */
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec %s: no interpreter symlink, argv[0] will be "
                    "%s\n",
                    pathbuf, interp_name);
        static char fallback[64];
        snprintf(fallback, sizeof(fallback), "/proc/self/fd/%d",
                 tracee_interp_fd);
        interp_ref = fallback;
    }

    if (arg_len > 0 && arg_len < 128)
        shebang_len = snprintf(shebang, sizeof(shebang), "#!%s %.*s\n",
                               interp_ref, (int) arg_len, hdr + arg_start);
    else
        shebang_len = snprintf(shebang, sizeof(shebang), "#!%s\n", interp_ref);
    if (shebang_len <= 0 || (size_t) shebang_len >= sizeof(shebang))
        return -ENAMETOOLONG;

    int script_memfd = (int) syscall(SYS_memfd_create, "kbox-script", 0);
    if (script_memfd < 0)
        return -errno;

    if (write(script_memfd, shebang, (size_t) shebang_len) !=
        (ssize_t) shebang_len)
        goto fail;

    /* A script's $0 is the path the kernel was given, and here that is the
     * descriptor carrying this copy, not the script's own name. Shell launchers
     * derive their install layout from it -- base_dir=$(dirname $0)/.. is in
     * kafka-run-class.sh and in every other Apache launcher -- and end up with
     * an empty classpath. So the copy starts by re-execing the interpreter on
     * the real path. The guest file still carries its original shebang, so the
     * second pass runs the script exactly as written: no loop.
     */
    if (script_path_is_usable(pathbuf) &&
        shebang_runs_a_shell(interp_name, hdr + arg_start, arg_len)) {
        char qinterp[600];
        char qscript[KBOX_MAX_PATH + 8];
        char qarg[200];
        char prologue[1400];
        int prologue_len;

        shell_quote_into(qinterp, sizeof(qinterp), interp);
        shell_quote_into(qscript, sizeof(qscript), pathbuf);
        if (arg_len > 0 && arg_len < 128) {
            char argbuf[128];
            memcpy(argbuf, hdr + arg_start, arg_len);
            argbuf[arg_len] = '\0';
            shell_quote_into(qarg, sizeof(qarg), argbuf);
            prologue_len =
                snprintf(prologue, sizeof(prologue), "exec %s %s %s \"$@\"\n",
                         qinterp, qarg, qscript);
        } else {
            prologue_len = snprintf(prologue, sizeof(prologue),
                                    "exec %s %s \"$@\"\n", qinterp, qscript);
        }
        if (prologue_len > 0 && (size_t) prologue_len < sizeof(prologue) &&
            write(script_memfd, prologue, (size_t) prologue_len) !=
                (ssize_t) prologue_len)
            goto fail;
    }

    char *buf = malloc(65536);
    if (!buf)
        goto fail;
    long long copied = 0;
    for (;;) {
        ssize_t n = pread(*exec_memfd, buf, 65536, body);
        if (n < 0) {
            free(buf);
            goto fail;
        }
        if (n == 0)
            break;
        if (write(script_memfd, buf, (size_t) n) != n) {
            free(buf);
            goto fail;
        }
        body += n;
        copied += n;
    }
    free(buf);
    if (ctx->verbose)
        fprintf(stderr,
                "kbox: exec %s: script hdr=%zd body_start=%lld copied=%lld "
                "shebang=%d\n",
                pathbuf, hn, (long long) (body - copied), copied, shebang_len);

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s: shebang %s -> /proc/self/fd/%d\n",
                pathbuf, interp, tracee_interp_fd);

    close(*exec_memfd);
    *exec_memfd = script_memfd;
    return 0;

fail: {
    int saved = errno ? errno : EIO;
    close(script_memfd);
    return -saved;
}
}

/* Prepare an exec image for the host kernel.
 *
 * A non-ELF file is a #! script. The host kernel would run binfmt_script on the
 * memfd and resolve the shebang to a *host* path, which does not exist, so kbox
 * used to answer ENOEXEC and leave the script to the calling shell. That works
 * for shells and breaks every program that execs a script and expects the
 * kernel to honour the shebang -- gosu, su-exec, tini, env -- which is how
 * official images re-exec their entrypoints. Instead, rewrite the shebang to
 * the interpreter's injected memfd and let binfmt_script do the rest: the
 * kernel execs /proc/self/fd/<interp> and passes the script as argv[1]. The
 * script fd therefore has to survive the exec, which is why the caller is told
 * not to set O_CLOEXEC on it.
 *
 * A dynamic ELF gets the same treatment for PT_INTERP: the interpreter is
 * extracted from the guest rootfs and injected, and the header is patched.
 *
 * Returns 0 on success, or a negative errno. On failure the memfd is closed and
 * *exec_memfd_io is set to -1. On success *exec_memfd_io holds the image to
 * inject and *cloexec_out says whether the descriptor has to survive the exec.
 */
static int prepare_exec_image(struct kbox_supervisor_ctx *ctx,
                              const struct kbox_syscall_request *req,
                              int *exec_memfd_io,
                              const char *pathbuf,
                              int *cloexec_out)
{
    int exec_memfd = *exec_memfd_io;
    int exec_fd_cloexec = O_CLOEXEC;
    {
        unsigned char elf_magic[4];
        if (pread(exec_memfd, elf_magic, 4, 0) != 4 || memcmp(elf_magic,
                                                              "\x7f"
                                                              "ELF",
                                                              4) != 0) {
            int rewritten =
                rewrite_script_shebang(ctx, req, &exec_memfd, pathbuf);
            if (rewritten < 0 && ctx->verbose)
                fprintf(stderr, "kbox: exec %s: shebang rewrite failed: %s\n",
                        pathbuf, kbox_err_text(rewritten));
            if (rewritten < 0) {
                close(exec_memfd);
                *exec_memfd_io = -1;
                return rewritten;
            }
            exec_fd_cloexec = 0;
        }
    }

    /* Check for PT_INTERP (dynamic binary). */
    {
        unsigned char *elf_buf = NULL;
        size_t elf_buf_len = 0;

        if (kbox_read_elf_header_window_fd(exec_memfd, &elf_buf,
                                           &elf_buf_len) == 0) {
            char interp_path[256];
            uint64_t pt_offset, pt_filesz;
            int ilen = kbox_find_elf_interp_loc(
                elf_buf, elf_buf_len, interp_path, sizeof(interp_path),
                &pt_offset, &pt_filesz);

            munmap(elf_buf, elf_buf_len);

            if (ilen < 0) {
                close(exec_memfd);
                *exec_memfd_io = -1;
                return -ENOEXEC;
            }

            if (ilen > 0) {
                /* Dynamic binary. Extract the interpreter from LKL and inject
                 * it into the tracee.
                 */
                long interp_lkl = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX,
                                                  interp_path, O_RDONLY, 0);
                if (interp_lkl < 0) {
                    if (ctx->verbose)
                        fprintf(stderr,
                                "kbox: exec %s: cannot open "
                                "interpreter %s: %s\n",
                                pathbuf, interp_path,
                                kbox_err_text(interp_lkl));
                    close(exec_memfd);
                    *exec_memfd_io = -1;
                    return (int) interp_lkl;
                }

                int interp_memfd =
                    kbox_shadow_create_resilient(ctx, interp_lkl);
                lkl_close_and_invalidate(ctx, interp_lkl);

                if (interp_memfd < 0) {
                    close(exec_memfd);
                    *exec_memfd_io = -1;
                    return interp_memfd;
                }

                /* Inject the interpreter memfd first so we know its FD number
                 * in the tracee for the PT_INTERP patch. O_CLOEXEC is safe: the
                 * kernel resolves /proc/self/fd/N via open_exec() before
                 * begin_new_exec() closes CLOEXEC descriptors.
                 */
                int tracee_interp_fd =
                    request_addfd(ctx, req, interp_memfd, O_CLOEXEC);
                close(interp_memfd);

                if (tracee_interp_fd < 0) {
                    close(exec_memfd);
                    *exec_memfd_io = -1;
                    return -tracee_interp_fd;
                }

                /* Patch PT_INTERP in the exec memfd to point at the injected
                 * interpreter: /proc/self/fd/<N>.
                 */
                char new_interp[64];
                int new_len = snprintf(new_interp, sizeof(new_interp),
                                       "/proc/self/fd/%d", tracee_interp_fd);

                if ((uint64_t) (new_len + 1) > pt_filesz) {
                    close(exec_memfd);
                    *exec_memfd_io = -1;
                    return -ENOMEM;
                }

                char patch[256];
                size_t patch_len = (size_t) pt_filesz;
                if (patch_len > sizeof(patch))
                    patch_len = sizeof(patch);
                memset(patch, 0, patch_len);
                memcpy(patch, new_interp, (size_t) new_len);

                if (pwrite(exec_memfd, patch, patch_len, (off_t) pt_offset) !=
                    (ssize_t) patch_len) {
                    close(exec_memfd);
                    *exec_memfd_io = -1;
                    return -EIO;
                }

                if (ctx->verbose)
                    fprintf(stderr,
                            "kbox: exec %s: interpreter %s "
                            "-> /proc/self/fd/%d\n",
                            pathbuf, interp_path, tracee_interp_fd);
            }
        } else {
            munmap(elf_buf, elf_buf_len);
        }
    }

    *exec_memfd_io = exec_memfd;
    *cloexec_out = exec_fd_cloexec;
    return 0;
}

static struct kbox_dispatch forward_execve_impl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat);


/* Undo an exec rewrite that landed in a vfork parent's memory.
 *
 * A vfork child shares its parent's address space, and the exec path rewrites
 * the pathname in place (and relocates argv/envp when it does not fit). The
 * parent is suspended until the child execs, so the bytes can be restored as
 * soon as it leaves the vfork wait -- otherwise the parent resumes with
 * "/proc/self/fd/N" where its own path used to be and every later fork in it
 * execs a descriptor that belongs to the child.
 */
/* Do two tracees run on one address space (CLONE_VM)? */
static int tracee_shares_vm(pid_t a, pid_t b)
{
    long r = syscall(SYS_kcmp, (long) a, (long) b, 1 /* KCMP_VM */, 0L, 0L);

    if (r >= 0)
        return r == 0;

    /* kcmp needs CAP_SYS_PTRACE and is often filtered in containers. A vfork
     * parent sleeps uninterruptibly ('D') until its child execs; a plain-fork
     * parent never does. */
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int) a);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, line, sizeof(line) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    line[n] = '\0';
    char *rp = strrchr(line, ')');
    return rp && rp[1] == ' ' && rp[2] == 'D';
}

/* Record that vfork parent is waiting for exec. */
static int vfork_parent_recorded(const struct kbox_supervisor_ctx *ctx,
                                 pid_t pp)
{
    size_t n = sizeof(ctx->vfork_parents) / sizeof(ctx->vfork_parents[0]);
    for (size_t i = 0; i < n; i++) {
        if (ctx->vfork_parents[i] == pp)
            return 1;
    }
    return 0;
}

/* Save bytes in a vfork parent's shared memory before the exec path writes
 * over them.
 *
 * The parent is suspended until the child execs, so the first syscall it makes
 * afterwards is the moment to put every recorded region back. Reading the
 * current bytes first is what makes the restore exact: the pathname may be in a
 * read-only page, and the argv/envp arrays are the parent's own.
 */
static int vfork_pending_record(struct kbox_supervisor_ctx *ctx,
                                pid_t pp,
                                pid_t pid,
                                uint64_t addr,
                                size_t len)
{
    struct kbox_vfork_pending *slot = NULL;
    unsigned char *buf;

    if (!ctx || addr == 0 || len == 0)
        return 0;
    for (size_t i = 0;
         i < sizeof(ctx->vfork_pending) / sizeof(ctx->vfork_pending[0]); i++) {
        if (ctx->vfork_pending[i].parent == pp &&
            ctx->vfork_pending[i].nregions > 0) {
            slot = &ctx->vfork_pending[i];
            break;
        }
    }
    if (!slot) {
        for (size_t i = 0;
             i < sizeof(ctx->vfork_pending) / sizeof(ctx->vfork_pending[0]);
             i++) {
            if (ctx->vfork_pending[i].nregions == 0) {
                slot = &ctx->vfork_pending[i];
                slot->parent = pp;
                break;
            }
        }
    }
    if (!slot ||
        slot->nregions >= (int) (sizeof(slot->reg) / sizeof(slot->reg[0])))
        return -1;
    buf = malloc(len);
    if (!buf)
        return -1;
    if (guest_mem_read(ctx, pid, addr, buf, len) != 0) {
        free(buf);
        return -1;
    }
    slot->reg[slot->nregions].addr = addr;
    slot->reg[slot->nregions].len = len;
    slot->reg[slot->nregions].saved = buf;
    slot->nregions++;
    if (ctx->verbose)
        fprintf(stderr,
                "kbox: exec: vfork parent %d snapshotted 0x%llx+%zu (%d)\n",
                (int) pp, (unsigned long long) addr, len, slot->nregions);
    return 0;
}

/* Snapshot a NULL-terminated exec vector, including the terminating slot. */
static void vfork_pending_record_vec(struct kbox_supervisor_ctx *ctx,
                                     pid_t pp,
                                     pid_t pid,
                                     uint64_t base)
{
    size_t count = 0;

    if (!base)
        return;
    for (size_t idx = 0; idx < 1024; idx++) {
        uint64_t ptr = 0;

        if (guest_mem_read(ctx, pid, base + idx * sizeof(uint64_t), &ptr,
                           sizeof(ptr)) != 0 ||
            ptr == 0)
            break;
        count++;
    }
    if (count > 0)
        (void) vfork_pending_record(ctx, pp, pid, base,
                                    (count + 1) * sizeof(uint64_t));
}

struct kbox_dispatch forward_execve(const struct kbox_syscall_request *req,
                                    struct kbox_supervisor_ctx *ctx,
                                    int is_execveat)
{
    struct kbox_dispatch d = forward_execve_impl(req, ctx, is_execveat);
    if (ctx->verbose && d.kind == KBOX_DISPATCH_RETURN && d.error) {
        char pbuf[KBOX_MAX_PATH] = {0};
        (void) guest_mem_read_string(
            ctx, kbox_syscall_request_pid(req),
            kbox_syscall_request_arg(req, is_execveat ? 1 : 0), pbuf,
            sizeof(pbuf));
        fprintf(stderr, "kbox: exec denied: %s path=%s (pid=%u)\n",
                kbox_err_text(-d.error), pbuf,
                (unsigned) kbox_syscall_request_pid(req));
    }
    return d;
}

/* Resolve a symlink chain that starts at a path on a bind mount.
 *
 * The host resolves a link found on the mount against the *host* root, but an
 * absolute target names a file in the guest rootfs. test_sysconfig and
 * test_platform symlink the interpreter into a temporary directory and exec
 * the link; the host has no /usr/local/bin/python3, so execve answered ENOENT.
 *
 * Returns 1 when out holds a host path that can be opened directly, 0 when out
 * holds an absolute guest path that must be resolved through the guest rootfs,
 * and -errno on failure.
 */
static int resolve_mount_exec_path(const char *host_path,
                                   char *out,
                                   size_t out_size)
{
    char cur[KBOX_MAX_PATH];

    if (snprintf(cur, sizeof(cur), "%s", host_path) >= (int) sizeof(cur))
        return -ENAMETOOLONG;
    for (int hop = 0; hop < 8; hop++) {
        struct stat st;
        char tgt[KBOX_MAX_PATH];
        char *slash;
        ssize_t n;

        if (lstat(cur, &st) < 0)
            return -errno;
        if (!S_ISLNK(st.st_mode)) {
            if (snprintf(out, out_size, "%s", cur) >= (int) out_size)
                return -ENAMETOOLONG;
            return 1;
        }
        n = readlink(cur, tgt, sizeof(tgt) - 1);
        if (n <= 0)
            return n < 0 ? -errno : -EINVAL;
        tgt[n] = '\0';
        if (tgt[0] == '/') {
            if (snprintf(out, out_size, "%s", tgt) >= (int) out_size)
                return -ENAMETOOLONG;
            return 0; /* guest absolute path */
        }
        slash = strrchr(cur, '/');
        if (!slash)
            return -EINVAL;
        *slash = '\0';
        if (snprintf(out, out_size, "%s/%s", cur, tgt) >= (int) out_size)
            return -ENAMETOOLONG;
        if (snprintf(cur, sizeof(cur), "%s", out) >= (int) sizeof(cur))
            return -ENAMETOOLONG;
    }
    return -ELOOP;
}

/* fexecve() through a kbox descriptor.
 *
 * execveat(fd, "", argv, envp, AT_EMPTY_PATH) names the executable by
 * descriptor. A virtual descriptor exists only in kbox's table, so the host
 * kernel answers EBADF. The file is copied out of the guest filesystem into an
 * executable image, prepared like any other exec (shebang or PT_INTERP), and
 * injected at the same descriptor number. The empty pathname is never touched.
 */
/* Materialize the guest file behind a virtual descriptor as an executable
 * image and install it at that same number, then let the kernel exec it.
 *
 * Two callers need this: execveat(fd, "", AT_EMPTY_PATH) — fexecve — and
 * execve("/proc/self/fd/N"), which apk uses to run the trigger scripts it
 * writes during a transaction. The second one used to be a bare CONTINUE: the
 * host kernel then resolved the script's "#!/bin/sh" against the *host* root
 * instead of the guest root, so every apk trigger died with ENOENT and apk
 * left its database in "inconsistent" state.
 *
 * force=1 re-materializes even when the tracee already holds a host descriptor
 * for the number: a writable shadow memfd is a byte copy, not a prepared exec
 * image, so continuing would exec a script without the shebang rewrite.
 */
static struct kbox_dispatch exec_via_virtual_fd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    long fd,
    int force,
    int content_fd)
{
    if (fd < 0)
        return kbox_dispatch_continue();

    long lkl_fd = kbox_fd_table_get_lkl(ctx->fd_table, fd);
    struct kbox_fd_entry *entry = fd_table_entry(ctx->fd_table, fd);

    /* A descriptor served from the path shadow cache is tracked as
     * KBOX_LKL_FD_SHADOW_ONLY: it has no LKL file, only the supervisor's copy
     * of the bytes, which is enough to build the executable image. */
    if (getenv("KBOX_TRACE"))
        fprintf(stderr,
                "kbox: exec vfd fd=%ld lkl=%ld sp=%d force=%d content=%d "
                "entry=%p\n",
                fd, lkl_fd, entry ? entry->shadow_sp : -99, force, content_fd,
                (void *) entry);
    if (content_fd < 0 && lkl_fd < 0 && !(entry && entry->shadow_sp >= 0)) {
        if (getenv("KBOX_TRACE"))
            fprintf(stderr, "kbox: exec vfd fd=%ld: untracked, continue\n", fd);
        return kbox_dispatch_continue();
    }

    /* Shadow content lives in the supervisor's memfd until close. Copy it
     * back first so the image is what the guest wrote. */
    if (entry && entry->shadow_writeback)
        (void) sync_shadow_writeback(ctx, entry);

    /* The tracee already holds a host descriptor here: the kernel can exec it
     * without help (this is the re-exec through the image.c exec memfd). */
    if (!force && child_fd_is_open(ctx, fd))
        return kbox_dispatch_continue();

    /* Build the image from the bytes the guest wrote. A writable open keeps
     * them in the supervisor's shadow memfd, and a descriptor opened O_WRONLY
     * cannot be read back through LKL, so the shadow is the first choice.
     */
    int exec_memfd = -1;

    if (content_fd >= 0) {
        exec_memfd = kbox_shadow_create_from_host_fd(content_fd);
    } else if (entry && entry->shadow_sp >= 0) {
        int dup_sp = dup(entry->shadow_sp);

        if (dup_sp >= 0) {
            exec_memfd = kbox_shadow_create_from_host_fd(dup_sp);
            close(dup_sp);
        }
    }
    if (exec_memfd < 0 && lkl_fd >= 0) {
        long acc = kbox_lkl_fcntl(ctx->sysnrs, lkl_fd, F_GETFL, 0);

        if (acc >= 0 && (acc & O_ACCMODE) != O_RDONLY) {
            /* Reopen the guest file read-only through LKL's own procfs; the
             * kernel re-opens the inode, so a write-only descriptor is enough
             * to execute what it holds (linkat/execveat semantics). */
            char link[64];
            long ro;

            snprintf(link, sizeof(link), "/proc/self/fd/%ld", lkl_fd);
            ro =
                kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, link, O_RDONLY, 0);
            if (ro >= 0) {
                exec_memfd = kbox_shadow_create_resilient(ctx, ro);
                lkl_close_and_invalidate(ctx, ro);
            }
        } else {
            exec_memfd = kbox_shadow_create_resilient(ctx, lkl_fd);
        }
    }
    if (exec_memfd < 0) {
        if (getenv("KBOX_TRACE"))
            fprintf(stderr, "kbox: exec vfd fd=%ld: no image, continue\n", fd);
        return kbox_dispatch_continue();
    }
    if (getenv("KBOX_TRACE"))
        fprintf(stderr, "kbox: exec vfd fd=%ld: image ready\n", fd);

    int cloexec = O_CLOEXEC;
    int rc = prepare_exec_image(ctx, req, &exec_memfd, "<fexecve>", &cloexec);
    if (rc < 0) {
        if (exec_memfd >= 0)
            close(exec_memfd);
        return kbox_dispatch_errno(-rc);
    }

    int injected = request_addfd_at(ctx, req, exec_memfd, (int) fd, cloexec);
    close(exec_memfd);
    if (injected < 0)
        return kbox_dispatch_errno(-injected);
    if (injected != fd) {
        /* ADDFD_AT promises the requested number; anything else would leave a
         * descriptor the guest never asked for. */
        fprintf(stderr,
                "kbox: fexecve ADDFD_AT returned %d, expected %ld -- "
                "aborting\n",
                injected, fd);
        abort();
    }
    return kbox_dispatch_continue();
}

static struct kbox_dispatch fexecve_virtual_fd(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx)
{
    long fd = to_dirfd_arg(kbox_syscall_request_arg(req, 0));

    return exec_via_virtual_fd(req, ctx, fd, 0, -1);
}

static struct kbox_dispatch forward_execve_impl(
    const struct kbox_syscall_request *req,
    struct kbox_supervisor_ctx *ctx,
    int is_execveat)
{
    pid_t pid = kbox_syscall_request_pid(req);

    /* Detect fexecve: execveat(fd, "", argv, envp, AT_EMPTY_PATH). A descriptor
     * the tracee really holds on the host (the exec memfd from image.c, a
     * shadow, an interpreter's own fd) is resolved by the kernel directly.
     * A kbox virtual descriptor has no host descriptor behind it, so the
     * kernel answered EBADF and every fexecve() failed
     * (test_posix.test_fexecve, and the child left behind kept running the test
     * suite, which is what aborted the whole module on a timeout).
     *
     * With AT_EMPTY_PATH the pathname is ignored, so nothing can be rewritten
     * in the tracee's (empty) path buffer. Instead the file is materialised as
     * an executable image at the very descriptor number the guest named, and
     * the syscall continues: the kernel resolves that number and execs the
     * image.
     */
    if (is_execveat) {
        long flags = to_c_long_arg(kbox_syscall_request_arg(req, 4));
        if (flags & KBOX_AT_EMPTY_PATH)
            return fexecve_virtual_fd(req, ctx);
    }

    /* Read pathname from tracee memory. */
    uint64_t path_addr = is_execveat ? kbox_syscall_request_arg(req, 1)
                                     : kbox_syscall_request_arg(req, 0);
    char pathbuf[KBOX_MAX_PATH];
    int rc =
        guest_mem_read_string(ctx, pid, path_addr, pathbuf, sizeof(pathbuf));
    if (rc < 0)
        return kbox_dispatch_errno(-rc);
    if (getenv("KBOX_TRACE"))
        fprintf(stderr, "kbox: exec enter pid=%d path=%s\n", (int) pid,
                pathbuf);

    /* Already a descriptor path: that descriptor is a host fd kbox injected
     * (the exec memfd itself, on a re-exec through /proc/self/exe), so the
     * host kernel can resolve it directly and LKL cannot resolve it at all. */
    if (strncmp(pathbuf, "/proc/self/fd/", 14) == 0 ||
        strncmp(pathbuf, "/proc/thread-self/fd/", 21) == 0) {
        long magic_fd = -1;

        /* A descriptor kbox tracks has no guest-visible host file behind it
         * when it is served from the path shadow cache (the kernel picks a low
         * number for those) or from the virtual table, so the kernel could not
         * resolve the magic link. Materialize it the same way fexecve does.
         * An untracked descriptor is a real host descriptor (the exec image
         * itself on a re-exec), so the kernel resolves it on its own. */
        if (fd_magic_link_fd(pathbuf, &magic_fd) && magic_fd >= 0) {
            long magic_lkl = kbox_fd_table_get_lkl(ctx->fd_table, magic_fd);
            struct kbox_fd_entry *me = fd_table_entry(ctx->fd_table, magic_fd);

            /* A guest file, or a shadow whose bytes the supervisor keeps:
             * materialize it from the entry. */
            if (magic_lkl >= 0 || (me && me->shadow_sp >= 0))
                return exec_via_virtual_fd(req, ctx, magic_fd, 1, -1);

            /* Everything else is a real host descriptor in the tracee, and its
             * file may be a byte copy of a guest file (a path-shadow memfd).
             * Continuing would let the host kernel resolve the script's
             * "#!/bin/sh" against the host root, so copy the bytes out and
             * build an image with the guest interpreter instead. */
            char link[64];
            int host_content;

            snprintf(link, sizeof(link), "/proc/%d/fd/%ld", (int) pid,
                     magic_fd);
            host_content = open(link, O_RDONLY | O_CLOEXEC);
            if (host_content >= 0) {
                struct kbox_dispatch d =
                    exec_via_virtual_fd(req, ctx, magic_fd, 1, host_content);

                close(host_content);
                return d;
            }
        }
        return kbox_dispatch_continue();
    }

    /* Re-exec through /proc/self/exe (e.g. Chromium zygote/GPU/network
     * subprocess spawning): /proc/self/exe is blocked as a virtual path and
     * on host procfs names kbox's memfd, so resolve it to the guest binary path
     * tracked in exe_map / ctx->guest_exe.
     */
    if (strcmp(pathbuf, "/proc/self/exe") == 0 ||
        strcmp(pathbuf, "/proc/thread-self/exe") == 0) {
        const char *exe = kbox_guest_exe_for(ctx, pid);
        if (exe && exe[0])
            snprintf(pathbuf, sizeof(pathbuf), "%s", exe);
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec enter pid=%d path=%s\n", (int) pid,
                pathbuf);

    /* Resolve host bind mount or translate path for LKL. */
    char translated[KBOX_MAX_PATH];
    int bind_ro = 0;
    long raw_dirfd = is_execveat
                         ? to_dirfd_arg(kbox_syscall_request_arg(req, 0))
                         : AT_FDCWD_LINUX;
    int brc = kbox_resolve_host_bind_at(ctx, raw_dirfd, pathbuf, translated,
                                        sizeof(translated), &bind_ro);
    if (brc < 0) {
        if (ctx->verbose)
            fprintf(stderr, "kbox: exec stage=bind path=%s err=%d\n", pathbuf,
                    brc);
        return kbox_dispatch_errno(-brc);
    }
    if (ctx->verbose)
        fprintf(stderr, "kbox: exec translated path=%s -> %s\n", pathbuf,
                translated);

    int exec_memfd = -1;

    /* Follow symlinks that live on a bind mount. A link there may point at a
     * sibling inside the same mount (a host path) or at an absolute guest path
     * such as the interpreter in the guest rootfs. Neither case can be left to
     * the host kernel, which resolves both against the host root.
     */
    for (int hop = 0; hop < 8; hop++) {
        char resolved[KBOX_MAX_PATH];
        int kind;

        brc = kbox_resolve_host_bind_at(ctx, raw_dirfd, pathbuf, translated,
                                        sizeof(translated), &bind_ro);
        if (brc < 0) {
            if (ctx->verbose)
                fprintf(stderr, /* format-ok: literal */
                        "kbox: exec bind resolve failed path=%s err=%d\n",
                        pathbuf, brc);
            return kbox_dispatch_errno(-brc);
        }
        if (brc > 0) {
            kind =
                resolve_mount_exec_path(translated, resolved, sizeof(resolved));
            if (ctx->verbose)
                fprintf(stderr, /* format-ok: literal */
                        "kbox: exec bind hop path=%s translated=%s kind=%d\n",
                        pathbuf, translated, kind);
            if (kind < 0)
                return kbox_dispatch_errno(-kind);
            if (kind == 0) {
                /* Absolute target: resolve it from the top, it may be another
                 * bind mount or a guest rootfs path. */
                snprintf(pathbuf, sizeof(pathbuf), "%s", resolved);
                raw_dirfd = AT_FDCWD_LINUX;
                continue;
            }
            int hfd = open(resolved, O_RDONLY | O_CLOEXEC);
            if (hfd < 0) {
                if (ctx->verbose)
                    fprintf(/* format-ok: literal */
                            stderr,
                            "kbox: exec host open failed resolved=%s "
                            "errno=%d\n",
                            resolved, errno);
                return kbox_dispatch_errno(errno);
            }
            exec_memfd = kbox_shadow_create_from_host_fd(hfd);
            close(hfd);
            break;
        }

        rc = kbox_translate_path_for_lkl(pid, pathbuf, ctx->host_root,
                                         translated, sizeof(translated));
        if (rc < 0)
            return kbox_dispatch_errno(-rc);

        /* Virtual paths (/proc, /sys, /dev) are not executable binaries.
         * Return ENOENT/EACCES rather than CONTINUE to avoid a TOCTOU window
         * where a sibling thread could swap the path after validation.
         */
        if (kbox_is_lkl_virtual_path(translated)) {
            if (ctx->verbose)
                fprintf(/* format-ok: literal */
                        stderr,
                        "kbox: exec virtual path refused path=%s "
                        "translated=%s\n",
                        pathbuf, translated);
            return kbox_dispatch_errno(EACCES);
        }

        /* Open the binary from LKL. */
        long lkl_fd = kbox_lkl_openat(ctx->sysnrs, AT_FDCWD_LINUX, translated,
                                      O_RDONLY, 0);
        if (lkl_fd < 0) {
            if (ctx->verbose || getenv("KBOX_TRACE")) {
                struct stat hst;
                int hrc = stat(translated, &hst);

                fprintf(stderr, /* format-ok: literal */
                        "kbox: exec open failed path=%s translated=%s err=%ld "
                        "hoststat=%d hosterrno=%d\n",
                        pathbuf, translated, -lkl_fd, hrc, hrc < 0 ? errno : 0);
            }
            return kbox_dispatch_errno((int) (-lkl_fd));
        }

        /* Create a memfd with the binary contents. */
        exec_memfd = kbox_shadow_create_resilient(ctx, lkl_fd);
        lkl_close_and_invalidate(ctx, lkl_fd);
        if (exec_memfd < 0 && ctx->verbose)
            fprintf(stderr, "kbox: exec stage=shadow path=%s err=%d\n", pathbuf,
                    exec_memfd);
        break;
    }

    if (exec_memfd < 0)
        return kbox_dispatch_errno(-exec_memfd);

    int exec_fd_cloexec = O_CLOEXEC;
    rc = prepare_exec_image(ctx, req, &exec_memfd, pathbuf, &exec_fd_cloexec);
    if (rc < 0) {
        if (exec_memfd >= 0)
            close(exec_memfd);
        return kbox_dispatch_errno(-rc);
    }

    /* Inject the exec memfd into the tracee. O_CLOEXEC keeps the tracee's FD
     * table clean after exec succeeds.
     */
    int tracee_exec_fd = request_addfd(ctx, req, exec_memfd, exec_fd_cloexec);
    close(exec_memfd);

    if (tracee_exec_fd < 0) {
        if (getenv("KBOX_TRACE"))
            fprintf(stderr, "kbox: exec addfd failed pid=%d path=%s rc=%d\n",
                    (int) pid, pathbuf, tracee_exec_fd);
        return kbox_dispatch_errno(-tracee_exec_fd);
    }
    if (getenv("KBOX_TRACE")) {
        char fdp[64];
        struct stat st;

        snprintf(fdp, sizeof(fdp), "/proc/%d/fd/%d", (int) pid, tracee_exec_fd);
        fprintf(stderr, "kbox: exec ok pid=%d path=%s fd=%d present=%d\n",
                (int) pid, pathbuf, tracee_exec_fd, stat(fdp, &st) == 0);
    }

    if (ctx->verbose) {
        char fdp[64];
        struct stat st;
        snprintf(fdp, sizeof(fdp), "/proc/%d/fd/%d", (int) pid, tracee_exec_fd);
        fprintf(stderr, "kbox: exec %s: tracee fd %d present=%d\n", pathbuf,
                tracee_exec_fd, stat(fdp, &st) == 0);
    }

    /* Overwrite the pathname in the tracee's memory with /proc/self/fd/<N>.
     * Relocate any overlapping argv[]/envp[] strings (including aliased
     * argv[0] and short pathnames packed adjacent to argv[1..]) below the
     * tracee stack pointer before overwriting path_addr.
     */
    char new_path[64];
    int new_path_len = snprintf(new_path, sizeof(new_path), "/proc/self/fd/%d",
                                tracee_exec_fd);
    size_t total_write = (size_t) (new_path_len + 1);

    uint64_t argv_addr = is_execveat ? kbox_syscall_request_arg(req, 2)
                                     : kbox_syscall_request_arg(req, 1);
    uint64_t envp_addr = is_execveat ? kbox_syscall_request_arg(req, 3)
                                     : kbox_syscall_request_arg(req, 2);

    /* If this is a vfork child, the parent shares these pages and is suspended
     * until this exec completes. Record every byte this path is about to write
     * so the parent's memory can be put back when it resumes -- otherwise it
     * wakes up with "/proc/self/fd/N" where its own path used to be, and with
     * argv/envp slots pointing at stack space it is about to reuse. */
    {
        pid_t pp = tracee_parent_of(pid);
        /* vfork_parents remembers every process that ever vforked, so a later
         * plain fork() of the same parent also lands here. Its child has a
         * private copy of the memory; "restoring" the saved bytes into the live
         * parent would write stale data over whatever it has done since (dash's
         * heap -- "malloc(): unaligned tcache chunk detected"). Only snapshot
         * when the two really share one address space. */
        if (pp > 0 && vfork_parent_recorded(ctx, pp) &&
            tracee_shares_vm(pp, pid)) {
            /* The pathname is usually a string literal in a read-only page,
             * restored with guest_mem_write on the parent's next syscall.
             * The arrays matter because relocation rewrites their pointer
             * slots, and those slots belong to the parent too: gcc's driver
             * resumed with argv entries aimed below its own stack pointer and
             * died with SIGSEGV after every compile it completed.
             */
            if (getenv("KBOX_TRACE"))
                fprintf(stderr,
                        "kbox: exec vfork-child pid=%u parent=%d "
                        "snapshot path=0x%llx+%zu\n",
                        (unsigned int) pid, (int) pp,
                        (unsigned long long) path_addr, total_write);
            (void) vfork_pending_record(ctx, pp, pid, path_addr, total_write);
            vfork_pending_record_vec(ctx, pp, pid, argv_addr);
            vfork_pending_record_vec(ctx, pp, pid, envp_addr);
        } else if (getenv("KBOX_TRACE") && pp > 0) {
            fprintf(stderr,
                    "kbox: exec pid=%u parent=%d vfork_recorded=%d "
                    "shares_vm=%d\n",
                    (unsigned int) pid, (int) pp,
                    vfork_parent_recorded(ctx, pp) ? 1 : 0,
                    tracee_shares_vm(pp, pid) ? 1 : 0);
        }
    }

    rc = relocate_overlapping_exec_vecs(ctx, pid, path_addr, total_write,
                                        argv_addr, envp_addr);
    if (rc < 0 && ctx->verbose) {
        fprintf(stderr, "kbox: exec %s: vector relocation skipped (%s)\n",
                pathbuf, strerror(-rc));
    }

    rc = write_guest_mem_any(ctx, pid, path_addr, new_path, total_write);
    if (rc < 0) {
        if (ctx->verbose)
            fprintf(stderr,
                    "kbox: exec %s: cannot rewrite "
                    "pathname: %s\n",
                    pathbuf, strerror(-rc));
        return kbox_dispatch_errno(ENOEXEC);
    }

    {
        char real_exe[KBOX_MAX_PATH];
        kbox_guest_exe_set(ctx, pid,
                           kbox_guest_exe_realpath(ctx, pathbuf, real_exe,
                                                   sizeof(real_exe)) == 0
                               ? real_exe
                               : pathbuf);
    }

    if (ctx->verbose)
        fprintf(stderr, "kbox: exec %s -> /proc/self/fd/%d\n", pathbuf,
                tracee_exec_fd);

    /* Clean up CLOEXEC entries from the FD table, matching what a successful
     * exec will do in the kernel.
     *
     * This is still conservative: if exec later fails, tracee resumes after we
     * have already purged those mappings. That rollback problem is preferable
     * to keeping stale mappings alive across a successful exec, which misroutes
     * future FD operations in the new image.
     */
    close_cloexec_with_writeback(ctx);

    /* Invalidate the cached /proc/pid/mem FD. After exec, the kernel may revoke
     * access to the old FD even though the PID is the same (credential check
     * against the new binary). Forcing a reopen on the next write ensures we
     * have valid access.
     */
    if (ctx->proc_mem_fd >= 0) {
        close(ctx->proc_mem_fd);
        ctx->proc_mem_fd = -1;
    }

    return kbox_dispatch_continue();
}
