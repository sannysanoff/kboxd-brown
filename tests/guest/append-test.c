/* SPDX-License-Identifier: MIT */
/* Guest test: O_APPEND must write at end of file, for files the guest wrote
 * itself and for ones that already exist. The postgres entrypoint does
 * `echo "host all all all scram-sha-256" >> pg_hba.conf` and got the line
 * written over the start of the file.
 * Usage: append-test DIR   (DIR is on the filesystem under test)
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

int main(int argc, char **argv)
{
    char path[512], buf[256];
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    int fd;

    snprintf(path, sizeof(path), "%s/append-test.txt", dir);
    unlink(path);

    /* Create, close, then append: the existing-file case. */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0, "create");
    CHECK(write(fd, "HEADER-LINE-ONE\n", 16) == 16, "write header");
    close(fd);

    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    CHECK(fd >= 0, "open O_APPEND");
    CHECK(write(fd, "appended\n", 9) == 9, "append write");
    close(fd);
    slurp(path, buf, sizeof(buf));
    if (strcmp(buf, "HEADER-LINE-ONE\nappended\n") != 0)
        fprintf(stderr, "got [%s]\n", buf);
    CHECK(strcmp(buf, "HEADER-LINE-ONE\nappended\n") == 0,
          "append lands at end of existing file");

    /* O_CREAT|O_APPEND on a fresh path, two writes. */
    unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    CHECK(fd >= 0, "create O_APPEND");
    CHECK(write(fd, "one\n", 4) == 4, "first");
    CHECK(write(fd, "two\n", 4) == 4, "second");
    close(fd);
    slurp(path, buf, sizeof(buf));
    if (strcmp(buf, "one\ntwo\n") != 0)
        fprintf(stderr, "got [%s]\n", buf);
    CHECK(strcmp(buf, "one\ntwo\n") == 0, "two appends in order");
    /* The shell's `cmd >> file`: open with O_APPEND, dup2 onto another fd,
     * write through the copy. The duplicate shares the open file description,
     * so it must append too. */
    unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0, "create for dup test");
    CHECK(write(fd, "HEAD-HEAD-HEAD-HEAD\n", 20) == 20, "seed content");
    close(fd);
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    CHECK(fd >= 0, "open O_APPEND for dup");
    int copy = dup2(fd, 40);
    CHECK(copy == 40, "dup2");
    close(fd);
    CHECK(write(copy, "via-dup2\n", 9) == 9, "write through dup2 copy");
    int copy3 = dup3(copy, 41, 0);
    CHECK(copy3 == 41, "dup3");
    CHECK(write(copy3, "via-dup3\n", 9) == 9, "write through dup3 copy");
    close(copy);
    close(copy3);
    slurp(path, buf, sizeof(buf));
    if (strcmp(buf, "HEAD-HEAD-HEAD-HEAD\nvia-dup2\nvia-dup3\n") != 0)
        fprintf(stderr, "got [%s]\n", buf);
    CHECK(strcmp(buf, "HEAD-HEAD-HEAD-HEAD\nvia-dup2\nvia-dup3\n") == 0,
          "appends through dup2/dup3 copies land at end");

    unlink(path);
    printf("append-test: PASS (%s)\n", dir);
    return 0;
}
