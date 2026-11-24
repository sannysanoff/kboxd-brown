/* SPDX-License-Identifier: MIT */
/* Guest test: posix_spawn / popen (vfork + exec) of an image binary, and the
 * same after dropping to an unprivileged uid. initdb starts postgres this way.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

static void spawn_true(const char *label)
{
    char *argv[] = {"sh", "-c", "exit 0", NULL};
    pid_t pid;
    int st = 0;
    int rc = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s posix_spawn rc=%d\n", label, rc);
        exit(1);
    }
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid");
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "FAIL: %s child status 0x%x (127 = exec failed)\n",
                label, st);
        exit(1);
    }

    FILE *p = popen("echo popen-ok", "r");
    char buf[32] = {0};
    CHECK(p != NULL, "popen");
    CHECK(fgets(buf, sizeof(buf), p) != NULL, "popen read");
    CHECK(pclose(p) == 0, "pclose");
    CHECK(strncmp(buf, "popen-ok", 8) == 0, "popen output");
}

int main(void)
{
    spawn_true("as root");
    CHECK(setgid(70) == 0, "setgid");
    CHECK(setuid(70) == 0, "setuid");
    CHECK(getuid() == 70, "getuid after setuid");
    spawn_true("as uid 70");
    printf("spawn-test: PASS\n");
    return 0;
}
