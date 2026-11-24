#!/bin/sh
# Stress the SLIRP TX path and shadow-socket backpressure (item 40):
#
# 1. Slow-reader backpressure: a loopback TCP peer writes 2 MiB while the
#    reader pauses 400 ms (filling to_supervisor_buf to 65536/65536 and the
#    socketpair). Meanwhile a second loopback connection performs 100 small
#    request/response hops so we detect pump starvation, and afterwards the
#    slow reader drains all 2 MiB and verifies byte integrity.
# 2. Outbound SLIRP TX burst alongside active shadow sockets: send 512 x 1400 B
#    UDP datagrams (> 700 KiB, >11x the 64 KiB tx_pipe) to 10.0.2.2 while a
#    loopback TCP pair exchanges messages. When net_tx() blocked on tx_pipe[1]
#    under LKL's BKL while slirp_event_loop entered pump_shadow_sockets()
#    (stage=4), both threads deadlocked permanently.
#
# Results: /vol/results/net-pump-stress.log
exec > /vol/results/net-pump-stress.log 2>&1

apk update >> /vol/results/net-pump-stress-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/net-pump-stress-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/nps
cd /data/nps || exit 1

cat > nps.c <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
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

static int listen_lo(uint16_t *out_port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0 || listen(s, 16) < 0) {
        close(s);
        return -1;
    }
    socklen_t len = sizeof(sa);
    if (getsockname(s, (struct sockaddr *) &sa, &len) < 0) {
        close(s);
        return -1;
    }
    *out_port = ntohs(sa.sin_port);
    return s;
}

static int connect_lo(uint16_t port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static int write_full(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t) n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t) n;
    }
    return 0;
}

int main(void)
{
    char det[128];

    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    /* Test 0: getrandom(512) returns full 512 bytes quickly without LKL stall. */
    {
        uint8_t rnd[512];
        memset(rnd, 0, sizeof(rnd));
        long long t0 = now_ms();
        ssize_t n = getrandom(rnd, sizeof(rnd), 0);
        long long dt = now_ms() - t0;
        int nonzero = 0;
        for (size_t i = 0; i < sizeof(rnd); i++) {
            if (rnd[i] != 0)
                nonzero++;
        }
        snprintf(det, sizeof(det), "n=%zd nonzero=%d in %lldms", n, nonzero,
                 dt);
        check(n == 512 && nonzero > 400 && dt < 500,
              "getrandom(512) returns full CSPRNG buffer without LKL stall",
              det);
    }

    /* Test 1: Slow-reader backpressure + concurrent active loopback socket. */
    {
        uint16_t port_bulk = 0, port_ping = 0;
        int l_bulk = listen_lo(&port_bulk);
        int l_ping = listen_lo(&port_ping);
        check(l_bulk >= 0 && l_ping >= 0, "open bulk and ping listeners", "");

        const size_t total = 2 * 1024 * 1024;
        pid_t srv = fork();
        if (srv == 0) {
            int c1 = accept(l_bulk, NULL, NULL);
            int c2 = accept(l_ping, NULL, NULL);
            close(l_bulk);
            close(l_ping);
            if (c1 < 0 || c2 < 0)
                _exit(2);

            pid_t p2 = fork();
            if (p2 == 0) {
                close(c1);
                char b[16];
                for (int i = 0; i < 100; i++) {
                    if (read_full(c2, (uint8_t *) b, 4) < 0)
                        _exit(3);
                    if (write_full(c2, (const uint8_t *) "PONG", 4) < 0)
                        _exit(4);
                }
                close(c2);
                _exit(0);
            }
            close(c2);

            uint8_t chunk[16384];
            size_t sent = 0;
            while (sent < total) {
                size_t n = total - sent;
                if (n > sizeof(chunk))
                    n = sizeof(chunk);
                for (size_t i = 0; i < n; i++)
                    chunk[i] = (uint8_t) ((sent + i) * 31u + 7u);
                if (write_full(c1, chunk, n) < 0)
                    _exit(5);
                sent += n;
            }
            close(c1);
            int st = 0;
            waitpid(p2, &st, 0);
            _exit(WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : 6);
        }
        close(l_bulk);
        close(l_ping);

        int bulk_c = connect_lo(port_bulk);
        int ping_c = connect_lo(port_ping);
        check(bulk_c >= 0 && ping_c >= 0, "connect bulk and ping clients", "");

        /* Leave bulk_c unread while server fills socketpair + to_supervisor_buf,
         * and run 100 ping-pong hops on ping_c during backpressure. */
        usleep(150000);
        long long t0 = now_ms();
        int pings_ok = 0;
        for (int i = 0; i < 100; i++) {
            char b[8] = {0};
            if (write_full(ping_c, (const uint8_t *) "PING", 4) < 0)
                break;
            if (read_full(ping_c, (uint8_t *) b, 4) < 0)
                break;
            if (memcmp(b, "PONG", 4) != 0)
                break;
            pings_ok++;
        }
        long long ping_ms = now_ms() - t0;
        close(ping_c);
        snprintf(det, sizeof(det), "%d/100 in %lldms", pings_ok, ping_ms);
        check(pings_ok == 100,
              "concurrent TCP ping-pong stays responsive under backpressure",
              det);

        /* Now drain all 2 MiB from bulk_c and verify every byte. */
        uint8_t rbuf[16384];
        size_t got = 0;
        int corrupt = 0;
        t0 = now_ms();
        while (got < total) {
            ssize_t n = read(bulk_c, rbuf, sizeof(rbuf));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            for (ssize_t i = 0; i < n; i++) {
                uint8_t exp = (uint8_t) ((got + (size_t) i) * 31u + 7u);
                if (rbuf[i] != exp) {
                    corrupt = 1;
                    break;
                }
            }
            got += (size_t) n;
        }
        long long bulk_ms = now_ms() - t0;
        close(bulk_c);

        int st = 0;
        waitpid(srv, &st, 0);
        snprintf(det, sizeof(det), "got=%zu/%zu corrupt=%d in %lldms", got,
                 total, corrupt, bulk_ms);
        check(got == total && !corrupt && WIFEXITED(st) &&
                  WEXITSTATUS(st) == 0,
              "slow reader drains 2 MiB cleanly with zero corruption", det);
    }

    /* Test 2: Outbound SLIRP TX burst (> 700 KiB UDP) alongside active TCP. */
    {
        uint16_t port_lo = 0;
        int l_lo = listen_lo(&port_lo);
        pid_t echo = fork();
        if (echo == 0) {
            int c = accept(l_lo, NULL, NULL);
            close(l_lo);
            if (c < 0)
                _exit(2);
            char b[64];
            for (;;) {
                ssize_t n = read(c, b, sizeof(b));
                if (n <= 0)
                    break;
                if (write_full(c, (const uint8_t *) b, (size_t) n) < 0)
                    _exit(3);
            }
            close(c);
            _exit(0);
        }
        close(l_lo);

        int c_lo = connect_lo(port_lo);
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr("10.0.2.2");
        dst.sin_port = htons(9999);

        uint8_t pkt[1400];
        memset(pkt, 0x5a, sizeof(pkt));

        int sent_udp = 0;
        int lo_hops = 0;
        long long t0 = now_ms();
        for (int round = 0; round < 8; round++) {
            for (int k = 0; k < 128; k++) {
                ssize_t r = sendto(udp, pkt, sizeof(pkt), 0,
                                   (struct sockaddr *) &dst, sizeof(dst));
                if (r == (ssize_t) sizeof(pkt))
                    sent_udp++;
            }
            char msg[16] = "TXBURST!";
            char rep[16] = {0};
            if (write_full(c_lo, (const uint8_t *) msg, 8) == 0 &&
                read_full(c_lo, (uint8_t *) rep, 8) == 0 &&
                memcmp(rep, msg, 8) == 0)
                lo_hops++;
        }
        long long tx_ms = now_ms() - t0;
        close(udp);
        close(c_lo);
        waitpid(echo, NULL, 0);

        snprintf(det, sizeof(det), "udp=%d/1024 lo_hops=%d/8 in %lldms",
                 sent_udp, lo_hops, tx_ms);
        check(sent_udp == 1024 && lo_hops == 8,
              "1.4 MiB SLIRP TX burst with active TCP does not deadlock", det);
    }

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o nps nps.c || exit 1
./nps
echo "nps rc=$?"
echo done
