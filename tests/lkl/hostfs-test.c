/*
 * Standalone LKL test for hostfs + overlayfs with host-backed lower/upper.
 *
 * Boots the kernel, mounts host directories as hostfs, stacks them under an
 * overlay whose upper/work also live on the host, and exercises the paths a
 * container write goes through: read from lower, copy-up, whiteout, xattr,
 * fallocate, copy_file_range and O_TMPFILE.
 *
 * Build (inside the kbox build image):
 *   cc -O1 -o hostfs-test hostfs-test.c -I lkl-aarch64 -L lkl-aarch64 \
 *      -llkl -lpthread -lrt -lm
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lkl.h>
#include <lkl_host.h>

/* asm-generic values, same for aarch64 and x86_64 */
#define G_O_RDONLY 0
#define G_O_WRONLY 1
#define G_O_RDWR 2
#define G_O_CREAT 0100
#define G_O_TRUNC 01000
#define G_O_DIRECTORY 00200000
#define G_O_TMPFILE (020000000 | 00200000)
#define G_AT_FDCWD (-100)
#define G_AT_SYMLINK_FOLLOW 0x400

static long g(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long p[6] = {a1, a2, a3, a4, a5, a6};
    return lkl_syscall(nr, p);
}

static int fails;

static void check(const char *what, long rc, long expect)
{
    if (rc == expect) {
        printf("PASS  %s\n", what);
    } else {
        printf("FAIL  %s (rc=%ld want=%ld)\n", what, rc, expect);
        fails++;
    }
}

static long g_open(const char *path, int flags)
{
    return g(__lkl__NR_openat, G_AT_FDCWD, (long) path, flags, 0644, 0, 0);
}

static long g_read_all(const char *path, char *buf, int len)
{
    long fd = g_open(path, G_O_RDONLY);
    long n;

    if (fd < 0)
        return fd;
    n = g(__lkl__NR_read, fd, (long) buf, len, 0, 0, 0);
    g(__lkl__NR_close, fd, 0, 0, 0, 0, 0);
    if (n >= 0 && n < len)
        buf[n] = '\0';
    return n;
}

static long g_write_all(const char *path, const char *data)
{
    long fd = g_open(path, G_O_WRONLY | G_O_CREAT | G_O_TRUNC);
    long n;

    if (fd < 0)
        return fd;
    n = g(__lkl__NR_write, fd, (long) data, strlen(data), 0, 0, 0);
    g(__lkl__NR_close, fd, 0, 0, 0, 0, 0);
    return n;
}

static long g_mount(const char *src,
                    const char *dst,
                    const char *type,
                    const char *data)
{
    return g(__lkl__NR_mount, (long) src, (long) dst, (long) type, 0,
             (long) data, 0);
}

int main(int argc, char **argv)
{
    const char *root = argc > 1 ? argv[1] : "/tmp/hostfs-test";
    /* copy_mount_options() reads a full page from the caller's pointer and
     * LKL has no fault fixup, so the option buffer needs a page of slack. */
    static char opt[8192];
    char buf[4096], path[512];
    long rc, fd;
    int i;

    struct {
        const char *name;
        const char *dir;
    } layers[2];

    layers[0].name = "l1";
    layers[0].dir = NULL;
    layers[1].name = "l2";
    layers[1].dir = NULL;

    if (lkl_init(&lkl_host_ops) < 0) {
        printf("FAIL  lkl_init\n");
        return 1;
    }
    if (lkl_start_kernel("mem=256M loglevel=3 console=null") < 0) {
        printf("FAIL  lkl_start_kernel\n");
        return 1;
    }

    /* Guest-side mount points on the ramfs root. */
    const char *dirs[] = {"/proc",      "/layers",    "/layers/l1",
                          "/layers/l2", "/ephemeral", "/merged"};
    for (i = 0; i < (int) (sizeof(dirs) / sizeof(dirs[0])); i++)
        g(__lkl__NR_mkdirat, G_AT_FDCWD, (long) dirs[i], 0755, 0, 0, 0);
    /* /proc is needed to link an O_TMPFILE file through /proc/self/fd. */
    g(__lkl__NR_mount, (long) "proc", (long) "/proc", (long) "proc", 0, 0, 0);

    /* ---- 1. hostfs mounts: two read-only layers and one ephemeral dir */
    snprintf(opt, sizeof(opt), "hostfs=%s/l1", root);
    rc = g_mount("none", "/layers/l1", "hostfs", opt);
    check("mount hostfs layer1", rc, 0);
    if (rc)
        goto out;

    snprintf(opt, sizeof(opt), "hostfs=%s/l2", root);
    rc = g_mount("none", "/layers/l2", "hostfs", opt);
    check("mount hostfs layer2", rc, 0);

    snprintf(opt, sizeof(opt), "hostfs=%s/eph", root);
    rc = g_mount("none", "/ephemeral", "hostfs", opt);
    check("mount hostfs ephemeral (upper+work, one sb)", rc, 0);

    rc = g_read_all("/layers/l1/base.txt", buf, sizeof(buf));
    printf("      layer1/base.txt -> %s\n", rc >= 0 ? buf : "ERR");
    check("read file through hostfs", rc > 0, 1);

    /* ---- 2. overlay with host-backed lower and upper ------------------ */
    snprintf(opt, sizeof(opt),
             "lowerdir=/layers/l2:/layers/l1,upperdir=/ephemeral/upper,"
             "workdir=/ephemeral/work,userxattr");
    rc = g_mount("overlay", "/merged", "overlay", opt);
    check("mount overlay lower=hostfs upper=hostfs userxattr", rc, 0);
    if (rc)
        goto out;

    rc = g_read_all("/merged/base.txt", buf, sizeof(buf));
    printf("      merged/base.txt -> %s\n", rc >= 0 ? buf : "ERR");
    check("lower layers stack (l2 overrides l1)", rc > 0, 1);

    rc = g_read_all("/merged/only-l1.txt", buf, sizeof(buf));
    printf("      merged/only-l1.txt -> %s\n", rc >= 0 ? buf : "ERR");
    check("file present only in l1 is visible", rc > 0, 1);

    /* ---- 3. write path: copy-up and new file in the upper ------------ */
    rc = g_write_all("/merged/newfile.txt", "hello-from-guest");
    check("create new file through overlay", rc > 0, 1);

    rc = g_write_all("/merged/base.txt", "copied-up");
    printf("      copy-up write rc=%ld\n", rc);
    check("modify lower file (copy-up)", rc, 9);

    /* ---- 4. whiteout: delete a file that only exists in lower -------- */
    rc = g(__lkl__NR_unlinkat, G_AT_FDCWD, (long) "/merged/only-l1.txt", 0, 0,
           0, 0);
    check("delete lower-only file (whiteout)", rc, 0);
    rc = g_open("/merged/only-l1.txt", G_O_RDONLY);
    check("deleted file is gone from merged view", rc, -2 /* -ENOENT */);
    if (rc >= 0)
        g(__lkl__NR_close, rc, 0, 0, 0, 0, 0);

    /* ---- 5. xattr through the stack --------------------------------- */
    rc = g(__lkl__NR_setxattr, (long) "/merged/newfile.txt",
           (long) "user.overlay.check", (long) "yes", 3, 0, 0);
    check("setxattr user.* on merged new file", rc, 0);

    memset(buf, 0, sizeof(buf));
    rc = g(__lkl__NR_getxattr, (long) "/merged/newfile.txt",
           (long) "user.overlay.check", (long) buf, sizeof(buf) - 1, 0, 0);
    printf("      getxattr -> %ld %s\n", rc, rc > 0 ? buf : "");
    check("getxattr returns the value", rc, 3);

    /* overlay's own xattr on the upper must be settable: this is what
     * userxattr buys us when the pod has no CAP_SYS_ADMIN. */
    rc = g(__lkl__NR_setxattr, (long) "/ephemeral/upper/newfile.txt",
           (long) "user.overlay.whiteout", (long) "y", 1, 0, 0);
    check("setxattr user.overlay.* on upper (overlay metadata)", rc, 0);

    /* ---- 5b. chown to another uid: the host process cannot do it, so
     * hostfs keeps the owner in an xattr and reports it from stat. */
    {
        /* asm-generic struct stat: st_uid at 24, st_gid at 28 */
        unsigned char sb[256];
        unsigned uid, gid;

        rc = g(__lkl__NR_fchownat, G_AT_FDCWD, (long) "/merged/newfile.txt",
               999, 998, 0, 0);
        check("chown to uid 999 gid 998 through overlay", rc, 0);
        memset(sb, 0, sizeof(sb));
        rc = g(__lkl__NR_newfstatat, G_AT_FDCWD, (long) "/merged/newfile.txt",
               (long) sb, 0, 0, 0);
        memcpy(&uid, sb + 24, sizeof(uid));
        memcpy(&gid, sb + 28, sizeof(gid));
        printf("      stat after chown -> uid=%u gid=%u\n", uid, gid);
        check("stat reports the virtual owner",
              rc == 0 && uid == 999 && gid == 998, 1);
    }

    /* ---- 6. fallocate / copy_file_range ------------------------------ */
    fd = g_open("/merged/falloc.bin", G_O_WRONLY | G_O_CREAT | G_O_TRUNC);
    check("open for fallocate", fd >= 0, 1);
    if (fd >= 0) {
        rc = g(__lkl__NR_fallocate, fd, 0, 0, 65536, 0, 0);
        check("fallocate 64K on hostfs upper", rc, 0);
        g(__lkl__NR_close, fd, 0, 0, 0, 0, 0);
    }

    long src = g_open("/merged/base.txt", G_O_RDONLY);
    long dst = g_open("/merged/copy.bin", G_O_WRONLY | G_O_CREAT | G_O_TRUNC);
    if (src >= 0 && dst >= 0) {
        rc = g(__lkl__NR_copy_file_range, src, 0, dst, 0, 4096, 0);
        printf("      copy_file_range -> %ld\n", rc);
        check("copy_file_range between hostfs files", rc, 9);
    } else {
        check("open files for copy_file_range", -1, 0);
    }
    if (src >= 0)
        g(__lkl__NR_close, src, 0, 0, 0, 0, 0);
    if (dst >= 0)
        g(__lkl__NR_close, dst, 0, 0, 0, 0, 0);

    /* ---- 7. O_TMPFILE + link into the merged view -------------------- */
    fd = g(__lkl__NR_openat, G_AT_FDCWD, (long) "/merged",
           G_O_TMPFILE | G_O_RDWR, 0600, 0, 0);
    if (fd >= 0) {
        check("O_TMPFILE on hostfs", fd >= 0, 1);
        rc = g(__lkl__NR_write, fd, (long) "tmpfile", 7, 0, 0, 0);
        check("write into tmpfile", rc, 7);
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", fd);
        rc = g(__lkl__NR_linkat, G_AT_FDCWD, (long) path, G_AT_FDCWD,
               (long) "/merged/linked.txt", G_AT_SYMLINK_FOLLOW, 0);
        check("linkat tmpfile through /proc/self/fd", rc, 0);
    } else {
        printf("FAIL  O_TMPFILE on hostfs (rc=%ld)\n", fd);
        fails++;
    }

    rc = g_read_all("/merged/linked.txt", buf, sizeof(buf));
    check("tmpfile content visible after link", rc, 7);

out:
    printf("\n%s (%d failures)\n", fails ? "FAILED" : "ALL PASS", fails);
    lkl_cleanup();
    return fails ? 1 : 0;
}
