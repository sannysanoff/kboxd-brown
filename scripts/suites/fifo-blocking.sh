#!/bin/sh
# Does a blocking open(2) of a FIFO succeed without deadlocking the container?
#
# Item 34: emulate_host_open_tracked() called openat() on the single supervisor
# dispatch thread. A guest process opening a FIFO without O_NONBLOCK (either a
# guest FIFO twin or a FIFO on a mounted volume) therefore blocked that thread
# waiting for a peer whose own open() could never be dispatched.
#
# This exercises both directions (blocking reader first, then blocking writer
# first), both filesystems (/data internal twin and /vol mounted volume), and
# cancellation (a child killed while blocked in open(O_RDONLY) must not wedge
# subsequent opens).
#
# Results: /vol/results/fifo-blocking.log
exec > /vol/results/fifo-blocking.log 2>&1

apk update >> /vol/results/fifo-blocking-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/fifo-blocking-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/fifob /vol/fifob
cd /data/fifob || exit 1

cat > blocking.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int run_pair(const char *path, int writer_first)
{
    const char *msg = "hello-blocking-fifo\n";
    size_t len = strlen(msg);
    pid_t pid;
    int status = 0;

    unlink(path);
    if (mkfifo(path, 0644) < 0)
        return 0;

    pid = fork();
    if (pid < 0)
        return 0;
    if (pid == 0) {
        int fd;

        if (!writer_first)
            usleep(150 * 1000);
        fd = open(path, O_WRONLY);
        if (fd < 0)
            _exit(2);
        if (write(fd, msg, len) != (ssize_t) len)
            _exit(3);
        close(fd);
        _exit(0);
    }

    if (writer_first)
        usleep(150 * 1000);
    int rfd = open(path, O_RDONLY);
    char buf[64];
    ssize_t n = -1;
    if (rfd >= 0) {
        n = read(rfd, buf, sizeof(buf) - 1);
        close(rfd);
    }
    waitpid(pid, &status, 0);
    unlink(path);
    return rfd >= 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
           n == (ssize_t) len && memcmp(buf, msg, len) == 0;
}

static int run_cancel(const char *path)
{
    pid_t pid;
    int status = 0;

    unlink(path);
    if (mkfifo(path, 0644) < 0)
        return 0;

    pid = fork();
    if (pid < 0)
        return 0;
    if (pid == 0) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0)
            close(fd);
        _exit(0);
    }

    usleep(150 * 1000);
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    unlink(path);
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    check(run_pair("/data/fifob/rfirst", 0),
          "internal FIFO: blocking O_RDONLY then O_WRONLY");
    check(run_pair("/data/fifob/wfirst", 1),
          "internal FIFO: blocking O_WRONLY then O_RDONLY");
    check(run_pair("/vol/fifob/rfirst", 0),
          "volume FIFO: blocking O_RDONLY then O_WRONLY");
    check(run_pair("/vol/fifob/wfirst", 1),
          "volume FIFO: blocking O_WRONLY then O_RDONLY");
    check(run_cancel("/data/fifob/cancel"),
          "internal FIFO: SIGKILL unblocks cancelled waiter");
    check(run_pair("/data/fifob/after", 0),
          "internal FIFO: blocking pair works after cancel");

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o blocking blocking.c || exit 1
./blocking
echo "blocking rc=$?"
rm -rf /vol/fifob
echo done
