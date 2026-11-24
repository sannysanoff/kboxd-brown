/* SPDX-License-Identifier: MIT */
/* Guest test: a program that writes through stdio to a redirected stdout and
 * then simply exits must leave its output in the file.
 *
 * "> file" gives the process a memfd shadow of the file; the bytes only reached
 * the real file when the process closed the descriptor, called fsync or ran
 * exec. stdio programs (ls, tr, sed) never do: they flush and exit. The file
 * stayed empty, so every `cmd > file` in an entrypoint script lost its output.
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

static void run(const char *cmd)
{
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "FAIL: command failed (rc=%d): %s\n", rc, cmd);
        exit(1);
    }
}

static void expect_content(const char *path, const char *want)
{
    char buf[512];
    slurp(path, buf, sizeof(buf));
    if (strcmp(buf, want) != 0) {
        fprintf(stderr, "FAIL: %s holds \"%s\", want \"%s\"\n", path, buf,
                want);
        exit(1);
    }
}

int main(void)
{
    struct stat st;

    run("rm -f /tmp/redir-*.out /tmp/redir-in");

    run("echo hello | tr a-z A-Z > /tmp/redir-tr.out");
    expect_content("/tmp/redir-tr.out", "HELLO\n");

    run("ls -l /etc > /tmp/redir-ls.out");
    CHECK(stat("/tmp/redir-ls.out", &st) == 0 && st.st_size > 0,
          "ls > file left the file empty");

    run("echo banana > /tmp/redir-in; sed s/a/o/g < /tmp/redir-in > "
        "/tmp/redir-sed.out");
    expect_content("/tmp/redir-sed.out", "bonono\n");

    /* Append keeps the existing bytes and adds the program's output. */
    run("echo first > /tmp/redir-app.out");
    run("echo hello | tr a-z A-Z >> /tmp/redir-app.out");
    expect_content("/tmp/redir-app.out", "first\nHELLO\n");

    run("ls -l /etc >> /tmp/redir-app.out");
    CHECK(stat("/tmp/redir-app.out", &st) == 0 && st.st_size > 12,
          "ls >> file added nothing");

    printf("redirect-exit-test: PASS\n");
    return 0;
}
