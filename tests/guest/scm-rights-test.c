/* SPDX-License-Identifier: MIT */
/* Guest test: a descriptor received over SCM_RIGHTS must be usable.
 * Chromium hands shared-memory regions (memfd) and pipes between its browser,
 * GPU and renderer processes this way. The receiver never saw the fd being
 * created, so it was unknown to the supervisor and every read, write, fstat or
 * mmap on it failed with EBADF; the renderer then hung after navigation.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

static int recv_fd(int sock)
{
    char data;
    struct iovec iov = {.iov_base = &data, .iov_len = 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = u.buf,
                         .msg_controllen = sizeof(u.buf)};
    if (recvmsg(sock, &msg, 0) != 1)
        return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_type != SCM_RIGHTS)
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    return fd;
}

static void send_fd(int sock, int fd)
{
    char data = 'x';
    struct iovec iov = {.iov_base = &data, .iov_len = 1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof(u));
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = u.buf,
                         .msg_controllen = sizeof(u.buf)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    CHECK(sendmsg(sock, &msg, 0) == 1, "sendmsg SCM_RIGHTS");
}

int main(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0,
          "socketpair");

    int mfd = (int) syscall(SYS_memfd_create, "kbox-scm-rights", 0);
    CHECK(mfd >= 0, "memfd_create");
    CHECK(ftruncate(mfd, 4096) == 0, "ftruncate in sender");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(sv[0]);
        int fd = recv_fd(sv[1]);
        CHECK(fd >= 0, "receive memfd");
        struct stat st;
        CHECK(fstat(fd, &st) == 0 && st.st_size == 4096,
              "fstat on received memfd");
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(p != MAP_FAILED && p != NULL, "mmap received memfd");
        memcpy(p, "from-child", 11);
        CHECK(pwrite(fd, "W", 1, 100) == 1, "write on received memfd");
        _exit(0);
    }

    close(sv[1]);
    send_fd(sv[0], mfd);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0,
          "child used the received fd");

    char *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, mfd, 0);
    CHECK(p != MAP_FAILED && p != NULL, "mmap in parent");
    CHECK(memcmp(p, "from-child", 11) == 0, "child's shared write is visible");
    char c = 0;
    CHECK(pread(mfd, &c, 1, 100) == 1 && c == 'W', "child's pwrite is visible");

    printf("scm-rights-test: PASS\n");
    return 0;
}
