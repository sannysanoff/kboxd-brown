/* SPDX-License-Identifier: MIT */
/* Guest test: the Chromium zygote handshake. A SOCK_SEQPACKET socketpair with
 * SO_PASSCRED, a forked (and re-exec'd) child that sends a hello carrying
 * SCM_CREDENTIALS, and a parent that checks the credential pid is the child's
 * pid. Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

static int child_send(int fd)
{
    char buf[] = "HELLO";
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    char cbuf[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = cbuf,
                         .msg_controllen = sizeof(cbuf)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    struct ucred cred = {.pid = getpid(), .uid = getuid(), .gid = getgid()};

    memset(cbuf, 0, sizeof(cbuf));
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_CREDENTIALS;
    c->cmsg_len = CMSG_LEN(sizeof(cred));
    memcpy(CMSG_DATA(c), &cred, sizeof(cred));
    ssize_t r = sendmsg(fd, &msg, 0);
    if (r != (ssize_t) sizeof(buf))
        fprintf(stderr, "child sendmsg: r=%zd errno=%d\n", r, errno);
    return r == (ssize_t) sizeof(buf) ? 0 : 1;
}

int main(int argc, char **argv)
{
    int sv[2];

    if (argc > 2 && !strcmp(argv[1], "child"))
        return child_send((int) strtol(argv[2], NULL, 10));

    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0,
          "socketpair SEQPACKET");
    int one = 1;
    CHECK(setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) == 0,
          "SO_PASSCRED");

    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        char fdarg[16];
        /* Re-exec like Chromium does for its zygote; the socket must survive
         * the exec, so clear CLOEXEC on the child's end. */
        close(sv[0]);
        if (argc > 1 && !strcmp(argv[1], "noexec"))
            _exit(child_send(sv[1]));
        fcntl(sv[1], F_SETFD, 0);
        snprintf(fdarg, sizeof(fdarg), "%d", sv[1]);
        execl("/proc/self/exe", argv[0], "child", fdarg, (char *) NULL);
        _exit(127);
    }
    close(sv[1]);

    char buf[32] = {0};
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    char cbuf[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = cbuf,
                         .msg_controllen = sizeof(cbuf)};
    ssize_t n = recvmsg(sv[0], &msg, 0);
    if (n != 6 || strcmp(buf, "HELLO") != 0)
        fprintf(stderr, "recvmsg: n=%zd errno=%d flags=0x%x controllen=%zu\n",
                n, errno, msg.msg_flags, (size_t) msg.msg_controllen);
    CHECK(n == 6 && !strcmp(buf, "HELLO"), "recvmsg hello");

    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    CHECK(c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS,
          "SCM_CREDENTIALS present");
    struct ucred cred;
    memcpy(&cred, CMSG_DATA(c), sizeof(cred));
    CHECK(cred.pid == child, "credential pid equals child pid");

    int st = 0;
    CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) &&
              WEXITSTATUS(st) == 0,
          "child exited 0");
    printf("scm-creds-test: PASS\n");
    return 0;
}
