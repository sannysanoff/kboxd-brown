/* SPDX-License-Identifier: MIT */
/* shadow-fd.c - Create host-visible memfd shadows of LKL files.
 *
 * When the guest opens a regular file O_RDONLY, we create a memfd
 * containing the file's contents and inject it into the tracee.
 * This lets the host kernel handle mmap natively; critical for
 * dynamic linkers that mmap .so files with MAP_PRIVATE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#include "lkl-wrap.h"
#include "seccomp.h"
#include "shadow-fd.h"

/* Read chunk size: 128 KB, matches KBOX_IO_CHUNK_LEN. */
#define SHADOW_CHUNK_LEN (128 * 1024)

static int write_all_memfd(int memfd, const char *buf, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(memfd, buf + written, len - written);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        written += (size_t) w;
    }
    return 0;
}

static int shadow_create_common(const struct kbox_sysnrs *s,
                                long fd,
                                int is_host,
                                off_t file_size)
{
    static __thread char buf[SHADOW_CHUNK_LEN];
    int memfd;
    off_t off = 0;
    off_t remaining = file_size;

    if (file_size > KBOX_SHADOW_MAX_SIZE)
        return -EFBIG;

    memfd = memfd_create("kbox-shadow", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0)
        return -errno;

    if (ftruncate(memfd, file_size) < 0) {
        int e = errno;
        close(memfd);
        return -e;
    }

    while (remaining > 0) {
        long chunk = (long) remaining;
        long ret;
        if (chunk > SHADOW_CHUNK_LEN)
            chunk = SHADOW_CHUNK_LEN;

        if (is_host) {
            ssize_t r;
            do {
                r = pread((int) fd, buf, (size_t) chunk, off);
            } while (r < 0 && errno == EINTR);
            ret = r < 0 ? -errno : (long) r;
        } else {
            ret = kbox_lkl_pread64(s, fd, buf, chunk, (long) off);
        }

        if (ret < 0) {
            close(memfd);
            return (int) ret;
        }
        if (ret == 0) {
            close(memfd);
            return -EIO;
        }

        int wrc = write_all_memfd(memfd, buf, (size_t) ret);
        if (wrc < 0) {
            close(memfd);
            return wrc;
        }

        off += ret;
        remaining -= ret;
    }

    if (lseek(memfd, 0, SEEK_SET) < 0) {
        int e = errno;
        close(memfd);
        return -e;
    }

    return memfd;
}

int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd)
{
    struct kbox_lkl_stat kst;
    long ret;

    memset(&kst, 0, sizeof(kst));
    ret = kbox_lkl_fstat(s, lkl_fd, &kst);
    if (ret < 0)
        return (int) ret;

    if (!S_ISREG(kst.st_mode))
        return -ENODEV;

    return shadow_create_common(s, lkl_fd, 0, (off_t) kst.st_size);
}

struct shadow_job {
    const struct kbox_sysnrs *s;
    long lkl_fd;
};

static int shadow_job_run(void *arg)
{
    const struct shadow_job *job = arg;

    return kbox_shadow_create(job->s, job->lkl_fd);
}

int kbox_shadow_create_resilient(const struct kbox_supervisor_ctx *ctx,
                                 long lkl_fd)
{
    struct shadow_job job;
    int rc;

    if (!ctx || !ctx->sysnrs)
        return -EINVAL;
    rc = kbox_shadow_create(ctx->sysnrs, lkl_fd);
    if (rc != -EINTR)
        return rc;

    job.s = ctx->sysnrs;
    job.lkl_fd = lkl_fd;
    for (int attempt = 0; attempt < 3 && rc == -EINTR; attempt++) {
        /* The copy names a descriptor, not a path, so a task that cannot
         * resolve the container's files can still read this file. */
        rc = kbox_lkl_run_fresh_task(shadow_job_run, &job);
        if (ctx->verbose && rc != -EINTR)
            fprintf(stderr,
                    "kbox: shadow copy answered EINTR; a fresh LKL task copied "
                    "it (attempt %d)\n",
                    attempt + 1);
    }
    return rc;
}

int kbox_shadow_create_from_host_fd(int host_fd)
{
    struct stat st;

    if (fstat(host_fd, &st) < 0)
        return -errno;
    if (!S_ISREG(st.st_mode))
        return -ENODEV;

    return shadow_create_common(NULL, (long) host_fd, 1, st.st_size);
}

int kbox_shadow_seal(int memfd)
{
    if (memfd < 0)
        return -1;
    return fcntl(memfd, F_ADD_SEALS,
                 F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
}
