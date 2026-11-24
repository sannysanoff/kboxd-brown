#!/bin/sh
# Verify SO_RCVTIMEO and SO_SNDTIMEO on bridged TCP sockets (item 42):
#
# read()/write() on a bridged TCP socket run directly on the host AF_UNIX
# socketpair (entry->shadow_sp). forward_setsockopt() previously forwarded
# SO_RCVTIMEO/SO_SNDTIMEO only to the LKL socket, leaving the host socketpair
# with no timeout at all. Any guest reading via read(2) (including OpenSSL's
# BIO_sock in MariaDB's main.ssl_timeout) blocked forever instead of returning
# EAGAIN/EWOULDBLOCK when the timeout expired.
#
# Results: /vol/results/sock-timeout.log
exec > /vol/results/sock-timeout.log 2>&1

for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/sock-timeout-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/stmo
cd /data/stmo || exit 1

cat > stmo.c <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
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

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int main(void)
{
    char det[128];
    setvbuf(stdout, NULL, _IONBF, 0);

    int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(l, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(l, 4) < 0) {
        perror("bind/listen");
        return 1;
    }
    socklen_t sl = sizeof(sa);
    getsockname(l, (struct sockaddr *) &sa, &sl);

    int p2c[2];
    if (pipe(p2c) != 0)
        return 1;

    pid_t srv = fork();
    if (srv == 0) {
        close(p2c[1]);
        int c = accept(l, NULL, NULL);
        close(l);
        if (c < 0)
            _exit(2);
        /* Stay silent until parent signals us to exit. */
        char ch;
        (void) read(p2c[0], &ch, 1);
        close(c);
        close(p2c[0]);
        _exit(0);
    }
    close(l);
    close(p2c[0]);

    int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connect(c, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("connect");
        return 1;
    }

    struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
    int ssrc = setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    snprintf(det, sizeof(det), "rc=%d errno=%d", ssrc, ssrc < 0 ? errno : 0);
    check(ssrc == 0, "setsockopt(SO_RCVTIMEO=300ms) on bridged TCP socket", det);

    /* 1. read(2) must honor SO_RCVTIMEO on the host socketpair. */
    char buf[16];
    long long t0 = now_ms();
    errno = 0;
    ssize_t n = read(c, buf, sizeof(buf));
    int e = errno;
    long long dt = now_ms() - t0;
    snprintf(det, sizeof(det), "n=%zd errno=%d in %lldms", n, e, dt);
    check(n < 0 && (e == EAGAIN || e == EWOULDBLOCK) && dt >= 200 && dt < 2000,
          "read(2) times out with EAGAIN under SO_RCVTIMEO", det);

    /* 2. recv(2) must also honor SO_RCVTIMEO. */
    t0 = now_ms();
    errno = 0;
    n = recv(c, buf, sizeof(buf), 0);
    e = errno;
    dt = now_ms() - t0;
    snprintf(det, sizeof(det), "n=%zd errno=%d in %lldms", n, e, dt);
    check(n < 0 && (e == EAGAIN || e == EWOULDBLOCK) && dt >= 200 && dt < 2000,
          "recv(2) times out with EAGAIN under SO_RCVTIMEO", det);

    /* 3. getsockopt(SO_RCVTIMEO) reads back the configured timeout. */
    struct timeval got = {0, 0};
    socklen_t gl = sizeof(got);
    int grc = getsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &got, &gl);
    snprintf(det, sizeof(det), "rc=%d tv=%ld.%06ld", grc, (long) got.tv_sec,
             (long) got.tv_usec);
    check(grc == 0 && got.tv_sec == 0 && got.tv_usec >= 250000,
          "getsockopt(SO_RCVTIMEO) reports configured timeout", det);

    (void) write(p2c[1], "X", 1);
    close(p2c[1]);
    close(c);
    waitpid(srv, NULL, 0);

    /* 4. AF_UNIX path socket with SO_RCVTIMEO set BEFORE connect() must keep
     *    the timeout across handle_unix_bind_connect()'s ADDFD_AT swap. */
    {
        const char *upath = "/data/stmo/u.sock";
        unlink(upath);
        int ul = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un su;
        memset(&su, 0, sizeof(su));
        su.sun_family = AF_UNIX;
        snprintf(su.sun_path, sizeof(su.sun_path), "%s", upath);
        if (ul >= 0 && bind(ul, (struct sockaddr *) &su, sizeof(su)) == 0 &&
            listen(ul, 4) == 0) {
            int up[2];
            if (pipe(up) == 0) {
                pid_t usrv = fork();
                if (usrv == 0) {
                    close(up[1]);
                    int uc = accept(ul, NULL, NULL);
                    close(ul);
                    char ch;
                    (void) read(up[0], &ch, 1);
                    if (uc >= 0)
                        close(uc);
                    close(up[0]);
                    _exit(0);
                }
                close(ul);
                close(up[0]);

                int uc = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                struct timeval utv = {.tv_sec = 0, .tv_usec = 300000};
                int uss = setsockopt(uc, SOL_SOCKET, SO_RCVTIMEO, &utv,
                                     sizeof(utv));
                int ucn = connect(uc, (struct sockaddr *) &su, sizeof(su));
                char ubuf[16];
                long long ut0 = now_ms();
                errno = 0;
                ssize_t un = (ucn == 0) ? read(uc, ubuf, sizeof(ubuf)) : -2;
                int ue = errno;
                long long udt = now_ms() - ut0;
                snprintf(det, sizeof(det),
                         "ss=%d cn=%d n=%zd errno=%d in %lldms", uss, ucn, un,
                         ue, udt);
                check(uss == 0 && ucn == 0 && un < 0 &&
                          (ue == EAGAIN || ue == EWOULDBLOCK) && udt >= 200 &&
                          udt < 2000,
                      "AF_UNIX pre-connect SO_RCVTIMEO survives connect()",
                      det);
                (void) write(up[1], "X", 1);
                close(up[1]);
                close(uc);
                waitpid(usrv, NULL, 0);
            }
        } else {
            check(0, "AF_UNIX pre-connect SO_RCVTIMEO survives connect()",
                  "bind/listen failed");
        }
        unlink(upath);
    }

    /* 5. AF_UNIX path socket with fcntl(F_SETFL, O_NONBLOCK) set BEFORE
     *    connect() must keep O_NONBLOCK across ADDFD_AT swap (MariaDB
     *    main.ssl_timeout on localhost). */
    {
        const char *upath = "/data/stmo/u_nb.sock";
        unlink(upath);
        int ul = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un su;
        memset(&su, 0, sizeof(su));
        su.sun_family = AF_UNIX;
        snprintf(su.sun_path, sizeof(su.sun_path), "%s", upath);
        if (ul >= 0 && bind(ul, (struct sockaddr *) &su, sizeof(su)) == 0 &&
            listen(ul, 4) == 0) {
            int up[2];
            if (pipe(up) == 0) {
                pid_t usrv = fork();
                if (usrv == 0) {
                    close(up[1]);
                    int uc = accept(ul, NULL, NULL);
                    close(ul);
                    char ch;
                    (void) read(up[0], &ch, 1);
                    if (uc >= 0)
                        close(uc);
                    close(up[0]);
                    _exit(0);
                }
                close(ul);
                close(up[0]);

                int uc = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                int fl0 = fcntl(uc, F_GETFL);
                int sfl = fcntl(uc, F_SETFL, fl0 | O_NONBLOCK);
                int ucn = connect(uc, (struct sockaddr *) &su, sizeof(su));
                int fl1 = fcntl(uc, F_GETFL);
                char ubuf[16];
                errno = 0;
                ssize_t un = read(uc, ubuf, sizeof(ubuf));
                int ue = errno;
                snprintf(det, sizeof(det),
                         "sfl=%d cn=%d nb=%d n=%zd errno=%d", sfl, ucn,
                         (fl1 >= 0 && (fl1 & O_NONBLOCK)) ? 1 : 0, un, ue);
                check(sfl == 0 && (ucn == 0 || errno == EINPROGRESS) &&
                          fl1 >= 0 && (fl1 & O_NONBLOCK) && un < 0 &&
                          (ue == EAGAIN || ue == EWOULDBLOCK),
                      "AF_UNIX pre-connect fcntl(O_NONBLOCK) survives connect()",
                      det);
                (void) write(up[1], "X", 1);
                close(up[1]);
                close(uc);
                waitpid(usrv, NULL, 0);
            }
        } else {
            check(0, "AF_UNIX pre-connect fcntl(O_NONBLOCK) survives connect()",
                  "bind/listen failed");
        }
        unlink(upath);
    }

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o stmo stmo.c || exit 1
timeout 10 ./stmo
rc=$?
echo "stmo rc=$rc"
echo done
