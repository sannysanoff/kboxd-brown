#!/bin/sh
# Verify standard POSIX non-blocking connect() + poll(POLLOUT) + SO_ERROR
# across loopback, refused port, and WAN HTTPS (item 40):
#
# A bridged TCP socket's tracee descriptor is a host AF_UNIX socketpair that
# is immediately writable before LKL's TCP handshake completes. Without
# deferring poll(POLLOUT) until LKL finishes the handshake, poll() returned in
# microseconds while the SYN was still in flight, getsockopt(SO_ERROR) returned
# EINPROGRESS (115), and every standard client (including apk update over
# HTTPS) aborted the connection.
#
# Results: /vol/results/nonblock-connect.log
exec > /vol/results/nonblock-connect.log 2>&1

for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/nonblock-connect-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/nbc
cd /data/nbc || exit 1

cat > nbc.c <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what, const char *detail)
{
    if (detail && detail[0])
        printf("%-54s %s (%s)\n", what, ok ? "ok" : "FAIL", detail);
    else
        printf("%-54s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

static int nonblock_connect_check(const struct sockaddr *sa,
                                  socklen_t salen,
                                  int tmo_ms,
                                  int *out_poll_rc,
                                  short *out_revents,
                                  int *out_soerr,
                                  int *out_fd)
{
    int s = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0);
    if (s < 0)
        return -1;
    int rc = connect(s, sa, salen);
    if (rc == 0) {
        *out_poll_rc = 99;
        *out_revents = POLLOUT;
        *out_soerr = 0;
        *out_fd = s;
        return 0;
    }
    if (errno != EINPROGRESS) {
        int e = errno;
        close(s);
        *out_poll_rc = -2;
        *out_revents = 0;
        *out_soerr = e;
        *out_fd = -1;
        return 0;
    }
    struct pollfd pfd = {.fd = s, .events = POLLOUT, .revents = 0};
    int pr = poll(&pfd, 1, tmo_ms);
    *out_poll_rc = pr;
    *out_revents = pfd.revents;
    int err = -1;
    socklen_t elen = sizeof(err);
    if (pr > 0)
        (void) getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen);
    *out_soerr = err;
    *out_fd = s;
    return 0;
}

int main(void)
{
    char det[128];
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. Loopback listener: non-blocking connect + poll(POLLOUT) + SO_ERROR=0 */
    {
        int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int one = 1;
        setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;
        bind(l, (struct sockaddr *) &sa, sizeof(sa));
        listen(l, 8);
        socklen_t sl = sizeof(sa);
        getsockname(l, (struct sockaddr *) &sa, &sl);

        pid_t srv = fork();
        if (srv == 0) {
            int c = accept(l, NULL, NULL);
            if (c >= 0) {
                char b[8] = {0};
                if (read(c, b, 2) == 2)
                    (void) write(c, "OK", 2);
                close(c);
            }
            close(l);
            _exit(0);
        }
        close(l);

        int pr = 0, soerr = -1, fd = -1;
        short rev = 0;
        nonblock_connect_check((struct sockaddr *) &sa, sizeof(sa), 5000, &pr,
                               &rev, &soerr, &fd);
        int io_ok = 0;
        if (fd >= 0 && soerr == 0) {
            int fl = fcntl(fd, F_GETFL);
            fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
            char b[4] = {0};
            if (write(fd, "HI", 2) == 2 && read(fd, b, 2) == 2 &&
                b[0] == 'O' && b[1] == 'K')
                io_ok = 1;
        }
        if (fd >= 0)
            close(fd);
        waitpid(srv, NULL, 0);
        snprintf(det, sizeof(det), "poll=%d rev=%#x soerr=%d io=%d", pr,
                 (unsigned) rev, soerr, io_ok);
        check(soerr == 0 && io_ok,
              "loopback non-blocking connect + poll + SO_ERROR=0", det);
    }

    /* 2. Closed loopback port: poll(POLLOUT) wakes with SO_ERROR=ECONNREFUSED */
    {
        int tmp = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0;
        bind(tmp, (struct sockaddr *) &sa, sizeof(sa));
        socklen_t sl = sizeof(sa);
        getsockname(tmp, (struct sockaddr *) &sa, &sl);
        close(tmp);

        int pr = 0, soerr = -1, fd = -1;
        short rev = 0;
        nonblock_connect_check((struct sockaddr *) &sa, sizeof(sa), 5000, &pr,
                               &rev, &soerr, &fd);
        if (fd >= 0)
            close(fd);
        snprintf(det, sizeof(det), "poll=%d rev=%#x soerr=%d", pr,
                 (unsigned) rev, soerr);
        check(soerr == ECONNREFUSED,
              "closed loopback port reports SO_ERROR=ECONNREFUSED", det);
    }

    /* 3. Real WAN non-blocking connect (dl-cdn.alpinelinux.org:443):
     *    poll(POLLOUT) MUST wait for TCP handshake and yield SO_ERROR=0,
     *    never EINPROGRESS (115). */
    {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo("dl-cdn.alpinelinux.org", "443", &hints, &res);
        if (gai == 0 && res) {
            int ok_cnt = 0;
            int last_pr = 0, last_err = -1;
            short last_rev = 0;
            for (int k = 0; k < 4; k++) {
                int pr = 0, soerr = -1, fd = -1;
                short rev = 0;
                nonblock_connect_check(res->ai_addr, res->ai_addrlen, 10000,
                                       &pr, &rev, &soerr, &fd);
                last_pr = pr;
                last_rev = rev;
                last_err = soerr;
                if (fd >= 0)
                    close(fd);
                if (pr > 0 && soerr == 0)
                    ok_cnt++;
            }
            freeaddrinfo(res);
            snprintf(det, sizeof(det), "%d/4 ok last_poll=%d rev=%#x err=%d",
                     ok_cnt, last_pr, (unsigned) last_rev, last_err);
            check(ok_cnt == 4,
                  "WAN non-blocking connect waits for SYN-ACK (SO_ERROR=0)",
                  det);
        } else {
            check(0, "WAN DNS resolve dl-cdn.alpinelinux.org", "gai failed");
        }
    }

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o nbc nbc.c || exit 1
./nbc
nbc_rc=$?
echo "nbc rc=$nbc_rc"

echo "=== apk update (HTTPS) ==="
apk update --repositories-file /dev/null \
    --repository https://dl-cdn.alpinelinux.org/alpine/v3.21/main
apk_rc=$?
echo "apk_https rc=$apk_rc"

if [ "$nbc_rc" -eq 0 ] && [ "$apk_rc" -eq 0 ]; then
    echo "OVERALL: PASS"
    exit 0
fi
echo "OVERALL: FAIL"
exit 1
