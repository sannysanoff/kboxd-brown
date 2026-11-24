#!/bin/sh
# Is a low descriptor's number safe to reuse after a native close?
#
# pipe() and pipe2() now run in the kernel, and so do closes of descriptors
# below kbox's virtual base (item 33 in three-suites-report.md). A close kbox
# never sees leaves the descriptor's table entry behind. The number can then be
# handed to a new pipe, and if kbox routed the pipe's bytes through the old
# entry they would go to the file that entry was made for -- a closed file the
# guest can no longer name.
#
# This probe forces that exact sequence: dup2 a guest-filesystem file onto a low
# number, close it, confirm the number is really free, take it back with pipe2,
# and check that reads see the pipe.
#
# Results: /vol/results/fd-reuse.log
exec > /vol/results/fd-reuse.log 2>&1

apk update >> /vol/results/fd-reuse-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/fd-reuse-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/fdreuse
cd /data/fdreuse || exit 1

cat > reuse.c <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail;

static void check(int ok, const char *what)
{
    printf("%-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fail = 1;
}

int main(void)
{
    const char *path = "/data/fdreuse/target";
    const long low = 9;
    char file_bytes[16] = "FILE-CONTENTS";
    char pipe_bytes[16] = "PIPE-CONTENTS";
    char got[16];
    struct stat st;
    int fd, p[2], n;

    unlink(path);
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    check(fd >= 0, "create the file in the guest filesystem");
    if (fd < 0)
        return 1;
    check(write(fd, file_bytes, sizeof(file_bytes)) == sizeof(file_bytes),
          "write the file's contents");
    check(lseek(fd, 0, SEEK_SET) == 0, "rewind before the dup");
    check(dup2(fd, low) == low, "dup2 it onto a low descriptor");
    close(fd);

    memset(got, 0, sizeof(got));
    check(read(low, got, sizeof(file_bytes)) == (int) sizeof(file_bytes),
          "read the file back");
    check(!memcmp(got, file_bytes, sizeof(file_bytes)),
          "the low descriptor still serves the file");

    check(close(low) == 0, "close the low descriptor");

    /* The close ran in the kernel, so this is the interesting moment: the
     * number is free even though kbox still has an entry for it. */
    errno = 0;
    n = (int) read(low, got, sizeof(file_bytes));
    check(n < 0 && errno == EBADF, "reading it after the close is EBADF");

    check(pipe2(p, 0) == 0, "pipe2");
    printf("pipe fds: %d %d (wanted %ld first)\n", p[0], p[1], low);
    check(p[0] == low, "the pipe reused the closed number");

    check(write(p[1], pipe_bytes, sizeof(pipe_bytes)) == sizeof(pipe_bytes),
          "write the pipe's own bytes");
    memset(got, 0, sizeof(got));
    n = (int) read(p[0], got, sizeof(got));
    check(n == (int) sizeof(pipe_bytes), "read them back through the reused fd");
    check(!memcmp(got, pipe_bytes, sizeof(got)),
          "the bytes come from the pipe, not from the closed file");
    if (memcmp(got, file_bytes, sizeof(got)) == 0)
        printf("NOTE: the read returned the closed file's contents\n");

    check(fstat(p[0], &st) == 0 && S_ISFIFO(st.st_mode),
          "fstat on the reused number says FIFO");
    if (fstat(p[0], &st) == 0 && !S_ISFIFO(st.st_mode))
        printf("NOTE: fstat says mode=%o (not a FIFO)\n",
               (unsigned) (st.st_mode & 07777));

    /* Same question for a virtual descriptor: a kbox file whose number is
     * closed normally and then reused must not leak its old bytes either. */
    close(p[0]);
    close(p[1]);

    fd = open(path, O_RDONLY);
    check(fd >= 0, "reopen the file");
    if (fd >= 0) {
        int vfd = fd;

        check(dup2(vfd, low) == low, "dup2 the virtual descriptor onto it");
        if (vfd != low)
            close(vfd);
        check(close(low) == 0, "close the low copy");
        check(pipe2(p, 0) == 0, "pipe2 again");
        check(write(p[1], pipe_bytes, sizeof(pipe_bytes)) ==
                  sizeof(pipe_bytes),
              "write again");
        memset(got, 0, sizeof(got));
        check(read(p[0], got, sizeof(got)) == (int) sizeof(pipe_bytes),
              "read again");
        check(!memcmp(got, pipe_bytes, sizeof(got)),
              "still the pipe's bytes");
        close(p[0]);
        close(p[1]);
    }

    close(low);
    unlink(path);

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o reuse reuse.c || exit 1
./reuse
echo "reuse rc=$?"
echo done
