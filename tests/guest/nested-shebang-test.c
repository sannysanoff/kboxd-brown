/* SPDX-License-Identifier: MIT */
/* Guest test: a script whose interpreter is itself a script must run.
 *
 * Oracle Linux ships /usr/bin/env as a one-line script
 * ("#!/usr/bin/coreutils --coreutils-prog-shebang=env"), so every
 * "#!/usr/bin/env bash" script has two shebang levels. The interpreter named in
 * the inner shebang does not exist outside the guest, and the exec answered
 * ENOENT ("bad interpreter"). Compiled statically and placed in the rootfs.
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

static void write_script(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    size_t n = strlen(text);

    CHECK(fd >= 0, "create script");
    CHECK(write(fd, text, n) == (ssize_t) n, "write script");
    CHECK(fchmod(fd, 0755) == 0, "chmod script");
    close(fd);
}

static void slurp(const char *path, char *buf, size_t n)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t r;

    CHECK(fd >= 0, "reopen for read");
    r = read(fd, buf, n - 1);
    CHECK(r >= 0, "read back");
    buf[r] = 0;
    close(fd);
}

int main(void)
{
    char buf[256];

    unlink("/tmp/nested-out");

    /* The inner script is the interpreter of the outer one. */
    write_script("/tmp/nested-interp", "#!/bin/sh\necho interp \"$@\"\n");
    write_script("/tmp/nested-outer", "#!/tmp/nested-interp\nignored\n");

    CHECK(system("/tmp/nested-outer arg1 > /tmp/nested-out") == 0,
          "outer script failed");
    slurp("/tmp/nested-out", buf, sizeof(buf));
    /* The script path may arrive as /proc/self/fd/N, so check only the shape.
     */
    CHECK(strncmp(buf, "interp ", 7) == 0, "interpreter script did not run");
    CHECK(strstr(buf, " arg1") != NULL, "script argument was lost");

    printf("nested-shebang-test: PASS\n");
    return 0;
}
