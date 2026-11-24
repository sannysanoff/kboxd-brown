/* SPDX-License-Identifier: MIT */
/* Guest test: statx must report the file type bits in stx_mode.
 * The permission normalization used for /etc, /usr and friends overwrote the
 * whole mode field, so glibc ls/stat saw "weird file" and the JDK's
 * Files.isDirectory() failed (DynamoDB Local: "Can't read cryptographic
 * policy directory"). Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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
    struct statx sx;

    CHECK(statx(AT_FDCWD, "/etc", 0, STATX_BASIC_STATS, &sx) == 0,
          "statx /etc");
    CHECK(S_ISDIR(sx.stx_mode), "/etc is a directory in statx");
    CHECK(statx(AT_FDCWD, "/usr", 0, STATX_BASIC_STATS, &sx) == 0,
          "statx /usr");
    CHECK(S_ISDIR(sx.stx_mode), "/usr is a directory in statx");
    CHECK(statx(AT_FDCWD, "/etc/passwd", 0, STATX_BASIC_STATS, &sx) == 0,
          "statx /etc/passwd");
    CHECK(S_ISREG(sx.stx_mode), "/etc/passwd is a regular file in statx");

    printf("statx-type-test: PASS\n");
    return 0;
}
