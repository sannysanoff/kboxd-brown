/* SPDX-License-Identifier: MIT */
/* Guest test: files and directories created under /dev/shm must be removable.
 * Chromium does shm_open + unlink on /dev/shm; open() was served by the host
 * kernel while unlinkat() went to LKL and failed with ENOENT.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

int main(void)
{
    const char *file = "/dev/shm/kbox-shm-unlink-test";
    const char *dir = "/dev/shm/kbox-shm-unlink-dir";
    struct stat st;

    /* unlink() (legacy) and unlinkat() both must see the file open() made. */
    int fd = open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "create file in /dev/shm");
    CHECK(write(fd, "x", 1) == 1, "write file");
    close(fd);
    CHECK(unlinkat(AT_FDCWD, file, 0) == 0, "unlinkat file in /dev/shm");
    CHECK(stat(file, &st) < 0 && errno == ENOENT, "file gone after unlinkat");

    fd = open(file, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "re-create file in /dev/shm");
    close(fd);
    CHECK(unlink(file) == 0, "unlink file in /dev/shm");

    /* mkdirat + unlinkat(AT_REMOVEDIR). */
    CHECK(mkdirat(AT_FDCWD, dir, 0700) == 0, "mkdirat in /dev/shm");
    CHECK(stat(dir, &st) == 0 && S_ISDIR(st.st_mode), "stat new dir");
    CHECK(unlinkat(AT_FDCWD, dir, AT_REMOVEDIR) == 0,
          "unlinkat AT_REMOVEDIR in /dev/shm");

    printf("shm-unlink-test: PASS\n");
    return 0;
}
