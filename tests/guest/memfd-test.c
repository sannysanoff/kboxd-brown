/* SPDX-License-Identifier: MIT */
/* Guest test: memfd_create and setpriority must work (Chromium shared memory
 * and thread priorities). Both used to be refused with ENOSYS.
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
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno); \
            exit(1);                                              \
        }                                                         \
    } while (0)

int main(void)
{
    int fd = (int) syscall(SYS_memfd_create, "kbox-test", 0);
    CHECK(fd >= 0, "memfd_create");
    CHECK(ftruncate(fd, 4096) == 0, "ftruncate memfd");
    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(p != MAP_FAILED, "mmap shared memfd");
    if (!p)
        return 1;
    memcpy(p, "hello", 6);
    char buf[8] = {0};
    CHECK(pread(fd, buf, 6, 0) == 6 && !strcmp(buf, "hello"),
          "memfd content visible through read");
    munmap(p, 4096);
    close(fd);

    /* Lowering our own priority (nice +1) is always permitted. */
    CHECK(setpriority(PRIO_PROCESS, 0, 1) == 0, "setpriority");

    printf("memfd-test: PASS\n");
    return 0;
}
