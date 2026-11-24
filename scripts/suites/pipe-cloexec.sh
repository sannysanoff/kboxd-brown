#!/bin/sh
# Verify fcntl(F_SETFD, F_SETFL, F_GETFL) on native kernel pipes (item 38):
#
# Item 33 moved pipe()/pipe2() into the kernel, so pipe descriptors are not in
# ctx->fd_table. forward_fcntl() used to swallow F_SETFD/F_SETFL/F_GETFL on
# untracked descriptors and answer 0 / O_RDWR locally instead of continuing to
# the host kernel. That silently dropped FD_CLOEXEC on Tcl's exec error pipe,
# so every spawned redis-server kept the write end open and runtest hung in
# read().
#
# Results: /vol/results/pipe-cloexec.log
exec > /vol/results/pipe-cloexec.log 2>&1

apk update >> /vol/results/pipe-cloexec-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/pipe-cloexec-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/pce
cd /data/pce || exit 1

cat > pce.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

int main(void)
{
    int pfd[2] = {-1, -1};
    int fl, fdfl;
    char ch;
    ssize_t n;

    setvbuf(stdout, NULL, _IONBF, 0);

    check(pipe(pfd) == 0, "pipe() creates native kernel pipe");

    /* 1. F_SETFL(O_NONBLOCK) and F_GETFL must take effect in the host kernel. */
    fl = fcntl(pfd[0], F_GETFL);
    check(fl >= 0 && (fl & O_ACCMODE) == O_RDONLY && !(fl & O_NONBLOCK),
          "F_GETFL on pipe read end reports O_RDONLY");
    check(fcntl(pfd[0], F_SETFL, fl | O_NONBLOCK) == 0,
          "F_SETFL(O_NONBLOCK) on pipe read end");
    fl = fcntl(pfd[0], F_GETFL);
    check(fl >= 0 && (fl & O_NONBLOCK) != 0,
          "F_GETFL reflects O_NONBLOCK");
    errno = 0;
    n = read(pfd[0], &ch, 1);
    check(n < 0 && errno == EAGAIN,
          "read on O_NONBLOCK empty pipe returns EAGAIN");
    check(fcntl(pfd[0], F_SETFL, fl & ~O_NONBLOCK) == 0,
          "clear O_NONBLOCK on pipe read end");

    /* 2. F_SETFD(FD_CLOEXEC) on write end must close it on child execve(). */
    check(fcntl(pfd[1], F_SETFD, FD_CLOEXEC) == 0,
          "F_SETFD(FD_CLOEXEC) on pipe write end");
    fdfl = fcntl(pfd[1], F_GETFD);
    check(fdfl >= 0 && (fdfl & FD_CLOEXEC) != 0,
          "F_GETFD reports FD_CLOEXEC set");

    pid_t pid = fork();
    if (pid == 0) {
        close(pfd[0]);
        execl("/bin/sleep", "sleep", "5", (char *) NULL);
        _exit(127);
    }
    close(pfd[1]);

    /* Parent must see immediate EOF once the child execs /bin/sleep, not block
     * for 5 seconds waiting for sleep to exit. */
    alarm(3);
    n = read(pfd[0], &ch, 1);
    alarm(0);
    check(n == 0, "parent read() sees immediate EOF after child execve");

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    close(pfd[0]);

    /* 3. F_DUPFD_CLOEXEC of a native pipe above KBOX_FD_BASE (busybox ash
     *    savefd() pattern) followed by dup2() back onto a low fd. */
    {
        int p2[2] = {-1, -1};
        int saved = -1;
        char buf[8] = {0};

        check(pipe(p2) == 0, "second native pipe for high F_DUPFD_CLOEXEC");
        if (p2[0] >= 0) {
            int target = 20;
            while (target == p2[0] || target == p2[1])
                target++;
            saved = fcntl(p2[1], F_DUPFD_CLOEXEC, 34817);
            check(saved >= 34817, "F_DUPFD_CLOEXEC onto fd >= 34817");
            if (saved >= 0) {
                check(dup2(saved, target) == target,
                      "dup2(saved_high_pipe, low_fd) succeeds");
                close(saved);
                close(p2[1]);
                p2[1] = -1;
                check(write(target, "OK", 2) == 2 && read(p2[0], buf, 2) == 2 &&
                          buf[0] == 'O' && buf[1] == 'K',
                      "restored high-duped pipe transfers bytes");
                close(target);
            }
            close(p2[0]);
            if (p2[1] >= 0)
                close(p2[1]);
        }
    }

    /* 4. fcntl on a closed descriptor must still return EBADF. */
    errno = 0;
    check(fcntl(pfd[0], F_GETFL) < 0 && errno == EBADF,
          "F_GETFL on closed pipe returns EBADF");

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o pce pce.c || exit 1
./pce
echo "pce rc=$?"
echo done
