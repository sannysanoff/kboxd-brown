#!/bin/sh
# Edge cases of native low-fd close (item 35):
#
# 1. A POSIX advisory lock taken on a low descriptor must be released once the
#    holder closes that descriptor natively in the kernel, even before the
#    number is reused or the holder exits.
# 2. A closed low descriptor reused by a memfd carrying the same name as a kbox
#    shadow ("kbox-shadow") must be detected as a different object (stat
#    dev+ino, not readlink string) so reads return the new memfd's bytes.
# 3. A closed low descriptor reused by a socketpair end must route socket
#    syscalls to the socket rather than the stale file entry.
#
# Results: /vol/results/low-fd-edge.log
exec > /vol/results/low-fd-edge.log 2>&1

apk update >> /vol/results/low-fd-edge-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/low-fd-edge-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/lfde
cd /data/lfde || exit 1

cat > lfde.c <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

static void test_low_fd_lock_release(void)
{
    const char *p = "/data/lfde/lockfile";
    int fd, status = 0;
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    unlink(p);
    fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0644);
    check(fd >= 0 && dup2(fd, 9) == 9, "dup2 lock target onto low fd 9");
    if (fd >= 0)
        close(fd);
    check(fcntl(9, F_SETLK, &fl) == 0, "parent takes POSIX write lock on fd 9");
    check(close(9) == 0, "parent closes fd 9 natively");

    pid_t pid = fork();
    if (pid == 0) {
        int cfd = open(p, O_RDWR);
        struct flock gl = fl;
        int grc = (cfd >= 0) ? fcntl(cfd, F_GETLK, &gl) : -1;
        int src = (cfd >= 0) ? fcntl(cfd, F_SETLK, &fl) : -1;
        if (cfd >= 0)
            close(cfd);
        if (grc == 0 && gl.l_type == F_UNLCK && src == 0)
            _exit(0);
        printf("NOTE: child getlk rc=%d type=%d pid=%d setlk rc=%d errno=%d\n",
               grc, gl.l_type, (int) gl.l_pid, src, src < 0 ? errno : 0);
        _exit(1);
    }
    waitpid(pid, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child sees lock free and acquires it after native close");
    unlink(p);
}

static void test_same_name_memfd_reuse(void)
{
    const char *p = "/data/lfde/oldfile";
    char buf[32];
    int fd, mfd;
    ssize_t n;

    unlink(p);
    fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd >= 0) {
        (void) write(fd, "OLDFILE", 7);
        (void) lseek(fd, 0, SEEK_SET);
        (void) dup2(fd, 9);
        close(fd);
    }
    close(9);

    /* Create a memfd with the exact name kbox uses for shadow memfds and put
     * it onto the same low descriptor number 9. */
    mfd = memfd_create("kbox-shadow", 0);
    check(mfd >= 0, "memfd_create(\"kbox-shadow\")");
    if (mfd >= 0) {
        (void) write(mfd, "NEWMEMFD", 8);
        (void) lseek(mfd, 0, SEEK_SET);
        if (mfd != 9) {
            dup2(mfd, 9);
            close(mfd);
        }
        memset(buf, 0, sizeof(buf));
        n = read(9, buf, sizeof(buf) - 1);
        check(n == 8 && memcmp(buf, "NEWMEMFD", 8) == 0,
              "read(9) returns new memfd bytes, not stale shadow");
        close(9);
    }
    unlink(p);
}

static void test_socket_reuse(void)
{
    const char *p = "/data/lfde/sockfile";
    int fd, sp[2] = {-1, -1};
    char buf[16];
    ssize_t n;

    unlink(p);
    fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd >= 0) {
        (void) write(fd, "STALE", 5);
        (void) dup2(fd, 9);
        close(fd);
    }
    close(9);

    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
          "socketpair reuses freed low descriptors");
    if (sp[0] >= 0) {
        if (sp[0] != 9 && sp[1] != 9) {
            dup2(sp[0], 9);
            close(sp[0]);
            sp[0] = 9;
        }
        int peer = (sp[0] == 9) ? sp[1] : sp[0];
        check(sendto(peer, "PING", 4, 0, NULL, 0) == 4,
              "sendto on reused low socketpair");
        memset(buf, 0, sizeof(buf));
        n = recvfrom(9, buf, sizeof(buf) - 1, 0, NULL, NULL);
        check(n == 4 && memcmp(buf, "PING", 4) == 0,
              "recvfrom(9) reads socket bytes, not stale file");
        close(sp[0]);
        close(sp[1]);
    }
    unlink(p);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_low_fd_lock_release();
    test_same_name_memfd_reuse();
    test_socket_reuse();
    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o lfde lfde.c || exit 1
./lfde
echo "lfde rc=$?"
echo done
