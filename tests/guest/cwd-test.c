/* SPDX-License-Identifier: MIT */
/* Guest test: a child's chdir() must not move its parent's working directory.
 * LKL has a single cwd per container; `mkdir -p /tmp/x` (coreutils savewd)
 * chdir()s inside its own process, and the parent shell then resolved every
 * relative path against /tmp -- the Maven image entrypoint's
 * `cd /usr/share/maven/ref; mkdir -p ...; cp -rv . ...` copied the wrong tree.
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
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

static void expect_cwd(const char *want, const char *when)
{
    char buf[256];
    char msg[300];

    CHECK(getcwd(buf, sizeof(buf)) != NULL, "getcwd");
    if (strcmp(buf, want) != 0) {
        snprintf(msg, sizeof(msg), "cwd %s: got %s want %s", when, buf, want);
        CHECK(0, msg);
    }
}

int main(void)
{
    struct stat st;
    int status;
    pid_t pid;

    CHECK(chdir("/usr") == 0, "chdir /usr");
    expect_cwd("/usr", "after chdir");

    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        if (chdir("/tmp") != 0)
            _exit(2);
        char b[64];
        if (!getcwd(b, sizeof(b)) || strcmp(b, "/tmp") != 0)
            _exit(3);
        _exit(0);
    }
    CHECK(waitpid(pid, &status, 0) == pid, "waitpid");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child chdir ok");

    expect_cwd("/usr", "after child chdir");
    CHECK(stat("./bin", &st) == 0 && S_ISDIR(st.st_mode),
          "relative path still resolves under /usr");

    /* A grandchild started after the parent moved inherits the parent's cwd. */
    CHECK(chdir("/etc") == 0, "chdir /etc");
    pid = fork();
    CHECK(pid >= 0, "fork 2");
    if (pid == 0) {
        char b[64];
        _exit((getcwd(b, sizeof(b)) && strcmp(b, "/etc") == 0) ? 0 : 4);
    }
    CHECK(waitpid(pid, &status, 0) == pid, "waitpid 2");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child inherits parent's cwd");
    expect_cwd("/etc", "end");

    printf("cwd-test: PASS\n");
    return 0;
}
