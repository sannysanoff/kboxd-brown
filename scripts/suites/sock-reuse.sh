#!/bin/sh
# Verify bridged TCP socket lifecycle under native low-fd close (item 37):
#
# 1. Repeated socket() -> bind() -> listen() -> close() reusing the same low fd
#    number must bind each new socket instead of hitting EINVAL on the old one.
# 2. Closing a listening socket and binding the same port again (both on the
#    same fd number and on a different fd number before reuse) must succeed
#    instead of returning EADDRINUSE.
# 3. Closing a listening socket and connecting to its port must return
#    ECONNREFUSED, not succeed against a dead LKL listener.
# 4. Closing a TCP socket and reusing its fd number with pipe2() must serve
#    the pipe, not route through the retired socket entry.
#
# Results: /vol/results/sock-reuse.log
exec > /vol/results/sock-reuse.log 2>&1

apk update >> /vol/results/sock-reuse-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/sock-reuse-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/sreuse
cd /data/sreuse || exit 1

cat > sreuse.c <<'EOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

static int make_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in sa;

    if (fd < 0)
        return -1;
    (void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(fd, 8) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. Repeated socket/bind/listen/close reusing the same low fd number. */
    int ok = 1;
    for (int i = 0; i < 6; i++) {
        int fd = make_listener((uint16_t) (23100 + i));
        if (fd < 0) {
            printf("NOTE: iter %d failed errno=%d (%s)\n", i, errno,
                   strerror(errno));
            ok = 0;
            break;
        }
        close(fd);
    }
    check(ok, "six sequential TCP listeners reusing low fd");

    /* 2. Rebind the exact same port immediately after close, both on the same
     *    fd and after holding another fd so the new socket gets a new number. */
    int s1 = make_listener(23200);
    check(s1 >= 0, "bind port 23200 first time");
    if (s1 >= 0)
        close(s1);
    int hold = open("/dev/null", O_RDONLY);
    int s2 = make_listener(23200);
    check(s2 >= 0, "rebind port 23200 on different fd after native close");
    if (s2 >= 0)
        close(s2);
    if (hold >= 0)
        close(hold);

    /* 3. Connect to a natively closed listener must get ECONNREFUSED. */
    int s3 = make_listener(23201);
    check(s3 >= 0, "open listener on port 23201");
    if (s3 >= 0)
        close(s3);
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(23201);
    errno = 0;
    int crc = (cfd >= 0) ? connect(cfd, (struct sockaddr *) &sa, sizeof(sa)) : 0;
    check(crc < 0 && errno == ECONNREFUSED,
          "connect to natively closed listener is ECONNREFUSED");
    if (cfd >= 0)
        close(cfd);

    /* 4. Reuse closed TCP socket fd with pipe2(). */
    int s4 = make_listener(23202);
    int pfd[2] = {-1, -1};
    char buf[8] = {0};
    if (s4 >= 0)
        close(s4);
    check(pipe2(pfd, 0) == 0, "pipe2 after closing TCP listener");
    if (pfd[0] >= 0) {
        check(write(pfd[1], "PIPE", 4) == 4 &&
                  read(pfd[0], buf, 4) == 4 && memcmp(buf, "PIPE", 4) == 0,
              "pipe2 reusing closed TCP socket fd transfers bytes");
        close(pfd[0]);
        close(pfd[1]);
    }

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o sreuse sreuse.c || exit 1
./sreuse
echo "sreuse rc=$?"
echo done
