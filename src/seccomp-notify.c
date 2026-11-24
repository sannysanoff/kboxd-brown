/* SPDX-License-Identifier: MIT */
/* seccomp-notify.c - ioctl wrappers for seccomp user notifications.
 *
 * Thin wrappers around the three seccomp-unotify ioctls:
 *   SECCOMP_IOCTL_NOTIF_RECV   - receive a notification
 *   SECCOMP_IOCTL_NOTIF_SEND   - send a response
 *   SECCOMP_IOCTL_NOTIF_ADDFD  - inject an FD into the tracee
 *
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#include "seccomp.h"

int kbox_notify_recv(int listener_fd, void *notif)
{
    int ret;

    memset(notif, 0, sizeof(struct kbox_seccomp_notif));

    ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_RECV, notif);
    if (ret < 0)
        return -errno;
    return 0;
}

int kbox_notify_send(int listener_fd, const void *resp)
{
    int ret;

    /* The kernel takes notify_lock with mutex_lock_interruptible in both of
     * these ioctls, so a signal that reaches the supervisor can make them
     * answer EINTR without doing anything. An interrupted ioctl did not run:
     * retry it instead of handing the guest a failure it never caused. */
    do {
        ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_SEND, resp);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0)
        return -errno;
    return 0;
}

int kbox_notify_respond(int listener_fd,
                        uint64_t id,
                        const struct kbox_dispatch *d)
{
    struct kbox_seccomp_notif_resp resp;

    memset(&resp, 0, sizeof(resp));
    resp.id = id;

    switch (d->kind) {
    case KBOX_DISPATCH_CONTINUE:
        resp.flags = KBOX_NOTIF_FLAG_CONTINUE;
        resp.val = 0;
        resp.error = 0;
        break;
    case KBOX_DISPATCH_RETURN:
        resp.flags = 0;
        resp.val = d->val;
        resp.error = d->error ? -d->error : 0;
        break;
    case KBOX_DISPATCH_DEFERRED:
        return 0;
    }

    return kbox_notify_send(listener_fd, &resp);
}

int kbox_notify_addfd(int listener_fd,
                      uint64_t id,
                      int srcfd,
                      uint32_t newfd_flags)
{
    struct kbox_seccomp_notif_addfd addfd;
    int ret;

    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.srcfd = (uint32_t) srcfd;
    addfd.newfd = 0; /* kernel picks the FD number */
    addfd.newfd_flags = newfd_flags;
    addfd.flags = 0;

    /* Same reason as kbox_notify_send: the kernel's notify_lock is taken with
     * mutex_lock_interruptible, so an interrupted ADDFD did not install
     * anything and has to be retried. */
    do {
        ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0)
        return -errno;
    return ret; /* remote FD number */
}

int kbox_notify_addfd_at(int listener_fd,
                         uint64_t id,
                         int srcfd,
                         int target_fd,
                         uint32_t newfd_flags)
{
    struct kbox_seccomp_notif_addfd addfd;
    int ret;

    memset(&addfd, 0, sizeof(addfd));
    addfd.id = id;
    addfd.srcfd = (uint32_t) srcfd;
    addfd.newfd = (uint32_t) target_fd;
    addfd.newfd_flags = newfd_flags;
    addfd.flags = 1; /* SECCOMP_ADDFD_FLAG_SETFD: install at exact newfd */

    do {
        ret = ioctl(listener_fd, KBOX_SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0)
        return -errno;
    return ret;
}
