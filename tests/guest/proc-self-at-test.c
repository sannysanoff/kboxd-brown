/* SPDX-License-Identifier: MIT */
/* Guest test: "self" resolved relative to a /proc dirfd must mean this
 * process, not the supervisor. Chromium's ThreadHelpers::IsSingleThreaded()
 * does fstatat(open("/proc/"), "self/task") and needs st_nlink == 3.
 * Compiled statically and placed in the rootfs.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
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
    struct stat st;
    int proc = open("/proc/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    CHECK(proc >= 0, "open /proc/");
    CHECK(fstatat(proc, "self/task", &st, 0) == 0, "fstatat self/task");
    CHECK(st.st_nlink == 3, "single-threaded: self/task nlink == 3");

    int task = openat(proc, "self/task", O_DIRECTORY | O_RDONLY);
    CHECK(task >= 0, "openat self/task");
    DIR *d = fdopendir(task);
    CHECK(d, "fdopendir");
    int tids = 0;
    struct dirent *e;
    while ((e = readdir(d)))
        if (e->d_name[0] != '.')
            tids++;
    CHECK(tids == 1, "exactly one task entry");
    closedir(d);
    close(proc);
    printf("proc-self-at-test: PASS\n");
    return 0;
}
