/* SPDX-License-Identifier: MIT */

/* The kernel behaviour the close-watch design rests on.
 *
 * A guest descriptor is a memfd on the host, and the supervisor learns that
 * the guest released it from IN_CLOSE events on that memfd's inode. Every
 * property checked here is load-bearing: an event that arrives late breaks the
 * causal order between a close and the next syscall, an event for the
 * supervisor's own copy closes a descriptor the guest still holds, and an
 * event for the original memfd does the same.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test-runner.h"

#define IN_CLOSE_ANY (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)

/* Read every queued event. Returns the number of events read, or -1 when the
 * read itself failed for a reason other than "queue empty". */
static int read_events(int ifd, struct inotify_event *out, int max)
{
    int n = 0;

    for (;;) {
        ssize_t got = read(ifd, out + n, sizeof(out[0]));

        if (got < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return n;
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (got < (ssize_t) sizeof(out[0]))
            return n;
        if (++n >= max)
            return n;
    }
}

/* Drain the queue once and report how many events carried each of the two
 * masks, so a second query cannot consume the event the first one looked for.
 */
static int read_batch(int ifd, int *closes, int *ignored)
{
    struct inotify_event ev[16];
    int n = read_events(ifd, ev, 16);

    *closes = 0;
    *ignored = 0;
    if (n < 0)
        return -1;
    for (int i = 0; i < n; i++) {
        if (ev[i].mask & IN_CLOSE_ANY)
            (*closes)++;
        if (ev[i].mask & IN_IGNORED)
            (*ignored)++;
    }
    return n;
}

static int make_memfd(const char *data)
{
    int mfd = memfd_create("kbox-test", MFD_CLOEXEC | MFD_ALLOW_SEALING);

    if (mfd < 0)
        return -1;
    if (data && write(mfd, data, strlen(data)) != (ssize_t) strlen(data)) {
        close(mfd);
        return -1;
    }
    return mfd;
}

static int watch_memfd(int ifd, int mfd, int *wd_out)
{
    char path[64];
    int wd;

    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    wd = inotify_add_watch(ifd, path, IN_CLOSE_ANY);
    if (wd < 0)
        return -1;
    *wd_out = wd;
    return 0;
}

/* The last reference closed in the guest must produce the event before the
 * closing syscall returns: the supervisor reads the queue on its next
 * iteration and must already see it. */
static void test_close_watch_last_reference(void)
{
    struct inotify_event ev[16];
    char path[64];
    char buf[8];
    int ifd, mfd, wd, g, g2;

    mfd = make_memfd("hello");
    ASSERT_TRUE(mfd >= 0);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    ASSERT_TRUE(ifd >= 0);
    ASSERT_EQ(watch_memfd(ifd, mfd, &wd), 0);

    g = open(path, O_RDWR | O_CLOEXEC);
    ASSERT_TRUE(g >= 0);
    g2 = dup(g);
    ASSERT_TRUE(g2 >= 0);

    /* One of two references goes away: nothing to report. */
    close(g);
    ASSERT_EQ(read_events(ifd, ev, 16), 0);

    /* The last one goes away: the event is queued by the time close returns. */
    close(g2);
    ASSERT_EQ(read_events(ifd, ev, 16), 1);
    ASSERT_EQ(ev[0].wd, wd);
    ASSERT_TRUE((ev[0].mask & IN_CLOSE_ANY) != 0);

    /* The data stays readable through the supervisor's own descriptor. */
    ASSERT_EQ(lseek(mfd, 0, SEEK_SET), 0);
    memset(buf, 0, sizeof(buf));
    ASSERT_EQ(read(mfd, buf, sizeof(buf)), 5);
    ASSERT_EQ(strcmp(buf, "hello"), 0);

    /* Closing the original memfd retires the watch and reports no close. */
    {
        int closes = -1, ignored = -1;

        close(mfd);
        ASSERT_TRUE(read_batch(ifd, &closes, &ignored) >= 0);
        ASSERT_EQ(closes, 0);
        ASSERT_EQ(ignored, 1);
    }
    close(ifd);
}

/* A supervisor copy that exists only to be injected must not look like a
 * guest close when it is dropped: the reference count falls from two to one. */
static void test_close_watch_supervisor_copy_is_silent(void)
{
    struct inotify_event ev[16];
    char path[64];
    int ifd, mfd, wd, g, copy;

    mfd = make_memfd(NULL);
    ASSERT_TRUE(mfd >= 0);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    ASSERT_TRUE(ifd >= 0);
    ASSERT_EQ(watch_memfd(ifd, mfd, &wd), 0);

    g = open(path, O_RDONLY | O_CLOEXEC);
    ASSERT_TRUE(g >= 0);
    /* ADDFD hands the tracee the same open file description, which is what a
     * dup models; a second open() would be a different description and would
     * legitimately raise its own event. */
    copy = dup(g);
    ASSERT_TRUE(copy >= 0);

    close(copy);
    ASSERT_EQ(read_events(ifd, ev, 16), 0);

    close(g);
    {
        int closes = -1, ignored = -1;

        ASSERT_TRUE(read_batch(ifd, &closes, &ignored) >= 0);
        ASSERT_EQ(closes, 1);
    }
    close(mfd);
    close(ifd);
}

/* A sealed memfd can only be reopened for reading, and the event it raises is
 * IN_CLOSE_NOWRITE. */
static void test_close_watch_sealed_memfd(void)
{
    struct inotify_event ev[16];
    char path[64];
    int ifd, mfd, wd, g;

    mfd = make_memfd("sealed");
    ASSERT_TRUE(mfd >= 0);
    ASSERT_EQ(fcntl(mfd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW), 0);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    ASSERT_TRUE(ifd >= 0);
    ASSERT_EQ(watch_memfd(ifd, mfd, &wd), 0);

    /* A writable reopen of a sealed memfd is accepted, but writing through it
     * is refused, so the seal is what protects the contents rather than the
     * open mode. */
    {
        int wr = open(path, O_RDWR | O_CLOEXEC);

        ASSERT_TRUE(wr >= 0);
        ASSERT_TRUE(write(wr, "x", 1) < 0);
        ASSERT_EQ(errno, EPERM);
        close(wr);
        {
            int closes = -1, ignored = -1;

            ASSERT_TRUE(read_batch(ifd, &closes, &ignored) >= 0);
            ASSERT_EQ(closes, 1);
        }
    }

    g = open(path, O_RDONLY | O_CLOEXEC);
    ASSERT_TRUE(g >= 0);
    close(g);
    ASSERT_EQ(read_events(ifd, ev, 16), 1);
    ASSERT_TRUE((ev[0].mask & IN_CLOSE_NOWRITE) != 0);
    close(mfd);
    close(ifd);
}

/* fork() shares the descriptor; only the last closer raises the event. */
static void test_close_watch_after_fork(void)
{
    struct inotify_event ev[16];
    char path[64];
    int ifd, mfd, wd, g;
    pid_t pid;
    int status = 0;

    mfd = make_memfd(NULL);
    ASSERT_TRUE(mfd >= 0);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
    ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    ASSERT_TRUE(ifd >= 0);
    ASSERT_EQ(watch_memfd(ifd, mfd, &wd), 0);
    g = open(path, O_RDWR | O_CLOEXEC);
    ASSERT_TRUE(g >= 0);

    pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        close(g);
        _exit(0);
    }
    ASSERT_EQ(waitpid(pid, &status, 0), pid);
    ASSERT_EQ(read_events(ifd, ev, 16), 0);

    close(g);
    {
        int closes = -1, ignored = -1;

        ASSERT_TRUE(read_batch(ifd, &closes, &ignored) >= 0);
        ASSERT_EQ(closes, 1);
    }
    close(mfd);
    close(ifd);
}

void test_inotify_close_init(void)
{
    TEST_REGISTER(test_close_watch_last_reference);
    TEST_REGISTER(test_close_watch_supervisor_copy_is_silent);
    TEST_REGISTER(test_close_watch_sealed_memfd);
    TEST_REGISTER(test_close_watch_after_fork);
}
