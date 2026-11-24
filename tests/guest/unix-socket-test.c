/* SPDX-License-Identifier: MIT */
/* Guest test: path-named AF_UNIX stream sockets. Postgres listens on
 * /var/run/postgresql/.s.PGSQL.5432, chmods it, and pg_isready connects to it.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
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
    const char *path = "/tmp/kbox-unix-test.sock";
    struct sockaddr_un a;
    struct stat st;

    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);
    unlink(path);

    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(srv >= 0, "socket AF_UNIX");
    CHECK(bind(srv, (struct sockaddr *) &a, sizeof(a)) == 0, "bind");
    CHECK(listen(srv, 4) == 0, "listen");
    CHECK(chmod(path, 0777) == 0, "chmod socket file");
    CHECK(stat(path, &st) == 0, "stat socket file");

    /* A second bind to the same path must fail like on Linux. */
    int dup = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(dup >= 0, "socket 2");
    CHECK(
        bind(dup, (struct sockaddr *) &a, sizeof(a)) < 0 && errno == EADDRINUSE,
        "second bind -> EADDRINUSE");
    close(dup);

    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        int c = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (c < 0 || connect(c, (struct sockaddr *) &a, sizeof(a)) != 0)
            _exit(2);
        if (write(c, "hi", 2) != 2)
            _exit(3);
        _exit(0);
    }

    int conn = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
    CHECK(conn >= 0, "accept");
    char buf[4] = {0};
    CHECK(read(conn, buf, 2) == 2 && !strcmp(buf, "hi"), "read from client");
    int stt = 0;
    CHECK(waitpid(child, &stt, 0) == child && WIFEXITED(stt) &&
              WEXITSTATUS(stt) == 0,
          "client exit 0");
    close(conn);
    close(srv);

    CHECK(unlink(path) == 0, "unlink socket file");
    /* The path can be bound again after unlink. */
    srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(bind(srv, (struct sockaddr *) &a, sizeof(a)) == 0, "rebind");
    close(srv);
    unlink(path);
    printf("unix-socket-test: PASS\n");
    return 0;
}
