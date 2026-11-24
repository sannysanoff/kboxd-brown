/* SPDX-License-Identifier: MIT */
/* Guest test: a script started by a relative path keeps that path in $0.
 *
 * Build systems run their own scripts relatively ("cd jemalloc &&
 * ./configure"), and kbox executes a script through a descriptor. The
 * interpreter's $0 is then /proc/self/fd/N instead of the name the caller used,
 * and autoconf reads its source directory from $0, so the configure step
 * reported "cannot find sources (Makefile.in) in /proc/self/fd or ..". A
 * prologue that re-execs the interpreter on the real path restores $0; it used
 * to be emitted only for absolute paths, which is every path a make-driven
 * build does not use.
 *
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
    char *cwd;

    CHECK(mkdir("/tmp/rel-script", 0755) == 0 || errno == EEXIST,
          "create directory");
    /* The prologue must quote the path, and $0 has to come back unchanged. */
    write_script("/tmp/rel-script/probe", "#!/bin/sh\necho \"argv0=$0\"\n");
    unlink("/tmp/rel-script-out");

    CHECK(chdir("/tmp/rel-script") == 0, "chdir");
    CHECK(system("./probe > /tmp/rel-script-out") == 0, "relative script");
    slurp("/tmp/rel-script-out", buf, sizeof(buf));
    CHECK(strcmp(buf, "argv0=./probe\n") == 0, "relative path was not kept");
    printf("relative: %s", buf);

    /* A parent directory and a file in it, as a build system spells it. */
    write_script("/tmp/rel-script/cfg",
                 "#!/bin/sh\necho \"argv0=$0 dir=$(dirname \"$0\")\"\n");
    CHECK(chdir("/tmp") == 0, "chdir to parent");
    CHECK(system("./rel-script/cfg > /tmp/rel-script-out") == 0,
          "nested relative script");
    slurp("/tmp/rel-script-out", buf, sizeof(buf));
    CHECK(strcmp(buf, "argv0=./rel-script/cfg dir=./rel-script\n") == 0,
          "nested relative path was not kept");
    printf("nested: %s", buf);

    /* An absolute path keeps working, and so does the argument list. */
    CHECK(system("/tmp/rel-script/probe arg1 > /tmp/rel-script-out") == 0,
          "absolute script");
    slurp("/tmp/rel-script-out", buf, sizeof(buf));
    CHECK(strcmp(buf, "argv0=/tmp/rel-script/probe\n") == 0,
          "absolute path changed");
    printf("absolute: %s", buf);

    cwd = getcwd(NULL, 0);
    CHECK(cwd != NULL && strcmp(cwd, "/tmp") == 0, "cwd changed by the exec");
    free(cwd);

    printf("relative-script-test: PASS\n");
    return 0;
}
