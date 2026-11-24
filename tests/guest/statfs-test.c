/* SPDX-License-Identifier: MIT */
/* Guest test: statfs on the LKL rootfs must report non-zero capacity.
 * Spring Boot's DiskSpaceHealthIndicator marks a service DOWN when
 * getUsableSpace() is 0.
 * Compiled statically and placed in the rootfs.
 */
#include <errno.h>
#include <stdio.h>
#include <sys/statfs.h>

int main(void)
{
    struct statfs sfs;

    if (statfs("/", &sfs) < 0) {
        fprintf(stderr, "FAIL: statfs(/) errno=%d\n", errno);
        return 1;
    }
    if (sfs.f_blocks == 0 || sfs.f_bavail == 0) {
        fprintf(stderr, "FAIL: statfs(/) blocks=%lu avail=%lu\n",
                (unsigned long) sfs.f_blocks, (unsigned long) sfs.f_bavail);
        return 1;
    }
    printf("statfs-test: PASS\n");
    return 0;
}
