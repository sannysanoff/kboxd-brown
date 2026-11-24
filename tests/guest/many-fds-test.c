/* SPDX-License-Identifier: MIT */
/* Guest test: a process must be able to hold thousands of files open at once.
 * LKL started with a soft RLIMIT_NOFILE of 1024 for the whole daemon, so a
 * broker or JVM that kept log segments and jars open got EMFILE after a few
 * minutes ("No file descriptors available" in Kafka), and unrelated work such
 * as creating a container interface failed with it too.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define COUNT 3000

int main(void)
{
    static int fds[COUNT];
    int i;

    for (i = 0; i < COUNT; i++) {
        fds[i] = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
        if (fds[i] < 0) {
            fprintf(stderr, "FAIL: open #%d (errno=%d)\n", i, errno);
            return 1;
        }
    }
    for (i = 0; i < COUNT; i++)
        close(fds[i]);

    printf("many-fds-test: PASS\n");
    return 0;
}
