#!/bin/sh
# Does a file stay consistent inside the guest when a writable shadow is
# flushed late?
#
# A close of a low descriptor runs in the kernel now (item 33), so kbox no
# longer sees the moment a writable shadow's descriptor goes away. The bytes are
# flushed when the number is reused or at process exit. Everything a guest
# program does to that file in between has to keep seeing one consistent answer:
# a truncate, an overwrite through a second open, an append, a rename, and a
# plain read.
#
# Each case writes through fd 9 (a kbox writeback shadow), closes it, then does
# one operation on the file, and reads the result the way a real kernel would
# answer. A FAIL is a case where the guest sees stale bytes or a resurrected
# file.
#
# Results: /vol/results/wb-consistency.log
exec > /vol/results/wb-consistency.log 2>&1

apk update >> /vol/results/wb-consistency-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/wb-consistency-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/wbc
cd /data/wbc || exit 1

cat > wbc.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

/* Write @text through a low descriptor that carries a writable shadow, then
 * close that descriptor while keeping the file's path. The close is the one
 * kbox no longer sees. */
static int seed(const char *path, const char *text)
{
    int fd, low = 9;

    unlink(path);
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    if (dup2(fd, low) != low) {
        close(fd);
        return -1;
    }
    close(fd);
    if (write(low, text, strlen(text)) != (ssize_t) strlen(text))
        return -1;
    if (close(low) < 0)
        return -1;
    return 0;
}

static ssize_t slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -1;
    n = read(fd, buf, cap);
    close(fd);
    return n;
}

int main(void)
{
    const char *a = "/data/wbc/a";
    const char *b = "/data/wbc/b";
    char buf[64];
    ssize_t n;
    int fd;

    /* 1. truncate(2) after the deferred close must leave an empty file. */
    check(seed(a, "AAA") == 0, "seed a through a shadowed low fd");
    check(truncate(a, 0) == 0, "truncate it to zero");
    memset(buf, 0, sizeof(buf));
    n = slurp(a, buf, sizeof(buf));
    if (!(n == 0)) {
        printf("NOTE: read after truncate returned %ld bytes [%.*s]\n", (long) n,
               (int) (n > 0 ? n : 0), buf);
    }
    check(n == 0, "a read after truncate sees an empty file");

    /* 2. A second open with O_TRUNC and a write must replace the contents. */
    check(seed(a, "AAA") == 0, "seed a again");
    fd = open(a, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        check(0, "second open with O_TRUNC");
    } else {
        check(write(fd, "BBBB", 4) == 4, "overwrite through the second open");
        close(fd);
        memset(buf, 0, sizeof(buf));
        n = slurp(a, buf, sizeof(buf));
        check(n == 4 && !memcmp(buf, "BBBB", 4),
              "the overwrite is what a read sees");
    }

    /* 3. An append after the deferred close must extend, not replace. */
    check(seed(b, "AAA") == 0, "seed b");
    fd = open(b, O_WRONLY | O_APPEND);
    if (fd < 0) {
        check(0, "open for append");
    } else {
        check(write(fd, "BB", 2) == 2, "append two bytes");
        close(fd);
        memset(buf, 0, sizeof(buf));
        n = slurp(b, buf, sizeof(buf));
        check(n == 5 && !memcmp(buf, "AAABB", 5),
              "the append extends the file");
    }

    /* 4. ftruncate through a fresh descriptor must still win. */
    check(seed(a, "AAAA") == 0, "seed a for ftruncate");
    fd = open(a, O_WRONLY);
    if (fd < 0) {
        check(0, "open for ftruncate");
    } else {
        check(ftruncate(fd, 2) == 0, "ftruncate to two bytes");
        close(fd);
        memset(buf, 0, sizeof(buf));
        n = slurp(a, buf, sizeof(buf));
        check(n == 2 && !memcmp(buf, "AA", 2),
              "the file is two bytes afterwards");
    }

    /* 5. Rename after the deferred close: the new name reads the same bytes. */
    check(seed(a, "AAA") == 0, "seed a for rename");
    check(rename(a, b) == 0, "rename a to b");
    memset(buf, 0, sizeof(buf));
    n = slurp(b, buf, sizeof(buf));
    check(n == 3 && !memcmp(buf, "AAA", 3), "the renamed file keeps its bytes");

    /* 6. unlink then re-create: the new file must not inherit the old bytes. */
    check(seed(a, "OLD") == 0, "seed a for unlink");
    check(unlink(a) == 0, "unlink it");
    fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        check(0, "create a new file at the same name");
    } else {
        check(write(fd, "NEW", 3) == 3, "write the new contents");
        close(fd);
        memset(buf, 0, sizeof(buf));
        n = slurp(a, buf, sizeof(buf));
        check(n == 3 && !memcmp(buf, "NEW", 3),
              "the new file holds only the new bytes");
    }

    /* 7. mmap after the deferred close: the mapping must show the bytes the
     *    guest wrote, not the LKL inode the shadow has not reached yet. */
    check(seed(a, "MMMM") == 0, "seed a for mmap");
    fd = open(a, O_RDONLY);
    if (fd < 0) {
        check(0, "open for mmap");
    } else {
        struct stat st;
        void *p = MAP_FAILED;

        if (fstat(fd, &st) == 0)
            p = mmap(NULL, (size_t) st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) {
            check(0, "mmap the file");
        } else {
            check(st.st_size == 4 && !memcmp(p, "MMMM", 4),
                  "the mapping shows the written bytes");
            munmap(p, (size_t) st.st_size);
        }
        close(fd);
    }

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o wbc wbc.c || exit 1
./wbc
echo "wbc rc=$?"
echo done
