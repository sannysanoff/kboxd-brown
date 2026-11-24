/* SPDX-License-Identifier: MIT */
/* Guest test: one read() of a regular file returns the whole request.
 *
 * mysqltest reads its expected result with a single read(). kbox capped the
 * transfer at 1 MiB, so a 1.1 MB result file came back as a short read and the
 * suite reported "Unexpected end-of-file found when reading file". A short
 * count is legal for read(2), but Linux fills the buffer for a regular file,
 * and callers depend on it.
 *
 * Usage: large-read-test DIR   (DIR is on the filesystem under test)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

/* Larger than the 1 MiB cap that used to truncate the read. */
#define BODY (1180 * 1024)

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char path[512];
    unsigned char *wbuf = malloc(BODY);
    unsigned char *rbuf;
    int fd;

    CHECK(wbuf != NULL, "malloc write buffer");
    for (int i = 0; i < BODY; i++)
        wbuf[i] = (unsigned char) (i * 31 + (i >> 8));

    snprintf(path, sizeof(path), "%s/large-read-test.bin", dir);
    unlink(path);

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    CHECK(fd >= 0, "create");
    CHECK(write(fd, wbuf, BODY) == BODY, "write body");
    close(fd);

    fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0, "reopen for read");
    off_t end = lseek(fd, 0, SEEK_END);
    CHECK(end == BODY, "file size");
    CHECK(lseek(fd, 0, SEEK_SET) == 0, "rewind");

    rbuf = malloc((size_t) end);
    CHECK(rbuf != NULL, "malloc read buffer");
    ssize_t got = read(fd, rbuf, (size_t) end);
    if (got != (ssize_t) end) {
        fprintf(stderr, "FAIL: one read returned %zd of %lld\n", got,
                (long long) end);
        return 1;
    }
    CHECK(memcmp(wbuf, rbuf, (size_t) end) == 0, "bytes match");

    /* Chunked reads must still work too. */
    CHECK(lseek(fd, 0, SEEK_SET) == 0, "rewind for chunks");
    size_t total = 0;
    for (;;) {
        ssize_t n = read(fd, rbuf, 64 * 1024);

        if (n < 0)
            CHECK(0, "chunked read");
        if (n == 0)
            break;
        total += (size_t) n;
    }
    CHECK(total == (size_t) end, "chunked total");

    close(fd);
    unlink(path);
    free(rbuf);
    free(wbuf);
    printf("large-read-test %s ok (%d bytes in one read)\n", dir, BODY);
    return 0;
}
