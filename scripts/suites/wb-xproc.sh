#!/bin/sh
# Verify cross-process writeback shadow coherency on the internal filesystem
# (item 39):
#
# A writable open on the internal LKL filesystem creates a writeback shadow
# memfd in the opening process's fd_table. When another process in the same
# container (forked before the open, so it does not hold the descriptor in its
# own fd_table) calls stat(), open(O_RDONLY)+read(), open(O_WRONLY|O_APPEND),
# or truncate() on that path while the writer still holds it open (or after a
# native low-fd close), all processes must observe the live shadow bytes.
#
# Results: /vol/results/wb-xproc.log
exec > /vol/results/wb-xproc.log 2>&1

apk update >> /vol/results/wb-xproc-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/wb-xproc-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/xproc
cd /data/xproc || exit 1

cat > xproc.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what, const char *detail)
{
    if (detail && detail[0])
        printf("%-56s %s (%s)\n", what, ok ? "ok" : "FAIL", detail);
    else
        printf("%-56s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

static void sync_send(int fd, char c)
{
    (void) write(fd, &c, 1);
}

static char sync_recv(int fd)
{
    char c = 0;
    if (read(fd, &c, 1) != 1)
        return 0;
    return c;
}

static ssize_t read_whole(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n >= 0)
        buf[n] = '\0';
    return n;
}

int main(void)
{
    int p2c[2], c2p[2];
    char det[128];

    setvbuf(stdout, NULL, _IONBF, 0);
    if (pipe(p2c) != 0 || pipe(c2p) != 0) {
        perror("pipe");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child B: forked BEFORE parent A opens any of the test files, so B's
         * fd_table has none of A's writeback shadow entries. */
        close(p2c[1]);
        close(c2p[0]);

        /* Step 1: stat + read while A holds live.dat open. */
        if (sync_recv(p2c[0]) != '1')
            _exit(2);
        struct stat st;
        int src = stat("/data/xproc/live.dat", &st);
        snprintf(det, sizeof(det), "rc=%d size=%lld", src,
                 src == 0 ? (long long) st.st_size : -1LL);
        check(src == 0 && st.st_size == 13,
              "child stat() sees parent's unclosed writeback size", det);

        char buf[64] = {0};
        ssize_t n = read_whole("/data/xproc/live.dat", buf, sizeof(buf));
        snprintf(det, sizeof(det), "n=%zd data=[%s]", n, buf);
        check(n == 13 && strcmp(buf, "hello-from-A\n") == 0,
              "child open(O_RDONLY)+read() sees parent's live bytes", det);

        /* Step 2: B appends while A still holds live.dat open. */
        int afd = open("/data/xproc/live.dat", O_WRONLY | O_APPEND);
        ssize_t wn = (afd >= 0) ? write(afd, "from-B\n", 7) : -1;
        if (afd >= 0)
            close(afd);
        snprintf(det, sizeof(det), "afd=%d wn=%zd", afd, wn);
        check(wn == 7, "child O_APPEND write while parent holds shadow", det);
        sync_send(c2p[1], '2');

        /* Step 3: after A writes "tail\n" and closes, B checks final content. */
        if (sync_recv(p2c[0]) != '3')
            _exit(3);
        memset(buf, 0, sizeof(buf));
        n = read_whole("/data/xproc/live.dat", buf, sizeof(buf));
        snprintf(det, sizeof(det), "n=%zd", n);
        check(n == 25 && strcmp(buf, "hello-from-A\nfrom-B\ntail\n") == 0,
              "parent close preserves child O_APPEND bytes", det);

        /* Step 4: B truncates trunc.dat while A holds it open. */
        if (sync_recv(p2c[0]) != '4')
            _exit(4);
        int trc = truncate("/data/xproc/trunc.dat", 4);
        snprintf(det, sizeof(det), "rc=%d errno=%d", trc, trc < 0 ? errno : 0);
        check(trc == 0, "child truncate() on parent's open writeback file",
              det);
        sync_send(c2p[1], '5');

        if (sync_recv(p2c[0]) != '6')
            _exit(5);
        memset(buf, 0, sizeof(buf));
        n = read_whole("/data/xproc/trunc.dat", buf, sizeof(buf));
        snprintf(det, sizeof(det), "n=%zd data=[%s]", n, buf);
        check(n == 4 && strcmp(buf, "0123") == 0,
              "file stays truncated to 4 bytes after parent closes", det);

        /* Step 5: A wrote via low fd 12 and closed 12 natively; B reads. */
        if (sync_recv(p2c[0]) != '7')
            _exit(6);
        memset(buf, 0, sizeof(buf));
        n = read_whole("/data/xproc/low.dat", buf, sizeof(buf));
        snprintf(det, sizeof(det), "n=%zd data=[%s]", n, buf);
        check(n == 9 && strcmp(buf, "low-close") == 0,
              "child reads bytes after parent's native low-fd close", det);

        sync_send(c2p[1], '8');
        _exit(fail ? 1 : 0);
    }

    /* Parent A */
    close(p2c[0]);
    close(c2p[1]);

    int fd1 = open("/data/xproc/live.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd1 < 0 || write(fd1, "hello-from-A\n", 13) != 13) {
        perror("write live.dat");
        return 1;
    }
    sync_send(p2c[1], '1');

    if (sync_recv(c2p[0]) != '2')
        return 1;
    if (lseek(fd1, 0, SEEK_END) < 0 || write(fd1, "tail\n", 5) != 5) {
        perror("write tail");
        return 1;
    }
    close(fd1);
    sync_send(p2c[1], '3');

    int fd2 = open("/data/xproc/trunc.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd2 < 0 || write(fd2, "0123456789", 10) != 10) {
        perror("write trunc.dat");
        return 1;
    }
    sync_send(p2c[1], '4');
    if (sync_recv(c2p[0]) != '5')
        return 1;
    close(fd2);
    sync_send(p2c[1], '6');

    int fd3 = open("/data/xproc/low.dat", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd3 < 0 || dup2(fd3, 12) != 12) {
        perror("dup2 low.dat");
        return 1;
    }
    close(fd3);
    if (write(12, "low-close", 9) != 9) {
        perror("write low.dat");
        return 1;
    }
    close(12);
    sync_send(p2c[1], '7');
    (void) sync_recv(c2p[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    int child_fail = !(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Step 6: parent holds writeback shadow, forks a child that closes and
     * exits (must not underflow active_writeback_shadows to 0), then parent
     * writes more and stats/reads its own still-open file. */
    {
        int fd4 = open("/data/xproc/forkwb.dat", O_RDWR | O_CREAT | O_TRUNC,
                       0644);
        if (fd4 >= 0 && write(fd4, "parent-1", 8) == 8) {
            pid_t c = fork();
            if (c == 0) {
                close(fd4);
                _exit(0);
            }
            if (c > 0)
                waitpid(c, NULL, 0);
            (void) write(fd4, "parent-2", 8);
            struct stat st4;
            int src4 = stat("/data/xproc/forkwb.dat", &st4);
            char buf4[64] = {0};
            ssize_t n4 = read_whole("/data/xproc/forkwb.dat", buf4,
                                    sizeof(buf4));
            snprintf(det, sizeof(det), "stat_sz=%lld read_n=%zd data=[%s]",
                     src4 == 0 ? (long long) st4.st_size : -1LL, n4, buf4);
            check(src4 == 0 && st4.st_size == 16 && n4 == 16 &&
                      strcmp(buf4, "parent-1parent-2") == 0,
                  "writeback tracking survives child fork+close+exit", det);
            close(fd4);
        } else {
            check(0, "writeback tracking survives child fork+close+exit",
                  "open/write failed");
        }
    }

    int any_fail = child_fail || fail;
    printf("%s\n", any_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return any_fail ? 1 : 0;
}
EOF

cc -O1 -o xproc xproc.c || exit 1
./xproc
echo "xproc rc=$?"
echo done
