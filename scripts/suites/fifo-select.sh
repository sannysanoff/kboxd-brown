#!/bin/sh
# A guest FIFO must be usable with select/pselect, the way it is on a bare
# kernel.
#
# GNU make's jobserver is a FIFO under $TMPDIR. kbox served guest files from
# LKL, and an LKL descriptor is virtual: 32768 and above, with no counterpart in
# the tracee's own descriptor table. The kernel cannot wait on such a number,
# and make never even reached pselect: its FD_SET fired the library's own
# bounds check and the process died with SIGTRAP (item 28 in
# three-suites-report.md). This is the shape without make: create a FIFO, put a
# token in it, and wait for it with pselect.
#
# The program prints the descriptor number it was given, so a virtual one is
# visible even on a system whose library does not check FD_SET.
#
# Results: /vol/results/fifo-select.log
exec > /vol/results/fifo-select.log 2>&1

apk update >> /vol/results/fifo-select-apk.log 2>&1
for pkg in build-base make; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/fifo-select-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1))
        sleep 2
    done
done

mkdir -p /data/fifo
cd /data/fifo || exit 1

cat > probe.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-52s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

int main(void)
{
    const char *path = "/data/fifo/pipe";
    char token = '+';
    char got = 0;
    fd_set set;
    struct timespec ts;
    int rfd, wfd, rc;

    unlink(path);
    check(mkfifo(path, 0600) == 0, "mkfifo in the guest filesystem");

    rfd = open(path, O_RDONLY | O_NONBLOCK);
    check(rfd >= 0, "open the read side non-blocking");
    wfd = open(path, O_WRONLY);
    check(wfd >= 0, "open the write side");
    if (rfd < 0 || wfd < 0)
        return 1;

    printf("read fd=%d write fd=%d FD_SETSIZE=%d\n", rfd, wfd, FD_SETSIZE);
    check(rfd < FD_SETSIZE && wfd < FD_SETSIZE,
          "both descriptors are below FD_SETSIZE");

    /* The jobserver shape: write a token, then wait for it with pselect. */
    check(write(wfd, &token, 1) == 1, "write one token");

    FD_ZERO(&set);
    FD_SET(rfd, &set);
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    rc = pselect(rfd + 1, &set, NULL, NULL, &ts, NULL);
    check(rc == 1, "pselect reports the FIFO readable");
    check(FD_ISSET(rfd, &set) != 0, "pselect sets the descriptor");
    check(read(rfd, &got, 1) == 1 && got == token, "read the token back");

    /* A quiet FIFO must time out instead of reporting readiness. */
    FD_ZERO(&set);
    FD_SET(rfd, &set);
    ts.tv_sec = 0;
    ts.tv_nsec = 200 * 1000 * 1000;
    rc = pselect(rfd + 1, &set, NULL, NULL, &ts, NULL);
    check(rc == 0, "pselect times out on an empty FIFO");

    /* End of file when the last writer closes, which is how make drains its
       jobserver at the end of a build. */
    close(wfd);
    {
        fd_set r;
        struct timeval tv;
        int n;

        FD_ZERO(&r);
        FD_SET(rfd, &r);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        n = select(rfd + 1, &r, NULL, NULL, &tv);
        check(n == 1, "select reports end of file readable");
    }
    check(read(rfd, &got, 1) == 0, "read returns end of file");
    close(rfd);
    unlink(path);

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o probe probe.c || exit 1
./probe
probe_rc=$?
echo "probe rc=$probe_rc"

echo
echo "=== the same FIFO through make -j2, five rounds"
printf 'all: a b\na b:\n\t/bin/true\n' > m.mk
i=0
traps=0
while [ $i -lt 5 ]; do
    rm -f a b
    make -f m.mk -j2 > /dev/null 2>&1
    rc=$?
    [ $rc -eq 133 ] && traps=$((traps + 1))
    [ $rc -ne 0 ] && echo "make round $i rc=$rc"
    i=$((i + 1))
done
echo "make: rounds=5 traps=$traps"

echo
if [ $probe_rc -eq 0 ] && [ $traps -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
echo done
