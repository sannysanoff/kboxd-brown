/* SPDX-License-Identifier: MIT */
/* Guest test: sendfile() from a file to a TCP socket must deliver the bytes.
 * nginx (sendfile on) has no read/write fallback and drops the connection
 * when sendfile fails, so serving any static file depended on this.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
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
    const char *path = "/tmp/kbox-sendfile-test";
    const char payload[] = "sendfile payload over tcp";
    size_t len = sizeof(payload) - 1;

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "create file");
    CHECK(write(fd, payload, len) == (ssize_t) len, "write file");

    int srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(srv >= 0, "socket");
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(srv, (struct sockaddr *) &a, sizeof(a)) == 0, "bind");
    CHECK(listen(srv, 1) == 0, "listen");
    socklen_t al = sizeof(a);
    CHECK(getsockname(srv, (struct sockaddr *) &a, &al) == 0, "getsockname");

    int cli = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(cli >= 0, "client socket");
    CHECK(connect(cli, (struct sockaddr *) &a, sizeof(a)) == 0, "connect");
    int conn = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
    CHECK(conn >= 0, "accept");

    off_t off = 0;
    ssize_t n = sendfile(conn, fd, &off, len);
    CHECK(n == (ssize_t) len, "sendfile length");
    CHECK(off == (off_t) len, "sendfile advanced the offset");

    char buf[64] = {0};
    ssize_t got = read(cli, buf, sizeof(buf) - 1);
    CHECK(got == (ssize_t) len && memcmp(buf, payload, len) == 0,
          "bytes arrive through the socket");

    unlink(path);
    printf("sendfile-test: PASS\n");
    return 0;
}
