#!/bin/sh
# Does a guest FIFO keep its own identity and behaviour when kbox serves it
# through a host twin?
#
# Item 28's fix opens a guest FIFO through a twin on the supervisor's tmpfs, so
# the tracee gets a real descriptor that select and pselect can watch. The twin
# is a different inode on a different filesystem, so the guest can tell the
# difference unless the identity is handled: fstat on the open descriptor,
# rename, unlink and re-create all have answers on a bare kernel that a twin
# could get wrong, and a wrong answer would be a new defect traded for the old
# one.
#
# This measures each answer and prints what fstat reports, so a difference can
# be recorded even where it is not treated as a failure.
#
# Results: /vol/results/fifo-twin.log
exec > /vol/results/fifo-twin.log 2>&1

apk update >> /vol/results/fifo-twin-apk.log 2>&1
for pkg in build-base; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/fifo-twin-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data/fifot
cd /data/fifot || exit 1

cat > twin.c <<'EOF'
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

static void show(const char *label, const struct stat *st)
{
    printf("%s dev=%llx ino=%llu mode=%o (isfifo=%d)\n", label,
           (unsigned long long) st->st_dev, (unsigned long long) st->st_ino,
           (unsigned) (st->st_mode & 07777), S_ISFIFO(st->st_mode) ? 1 : 0);
}

static void clean(const char *a, const char *b)
{
    unlink(a);
    unlink(b);
}

int main(void)
{
    const char *p = "/data/fifot/p";
    const char *q = "/data/fifot/q";
    char token = '+', got = 0;
    struct stat ps, fs;
    int rfd, wfd, w2, r2, w3, rc;

    clean(p, q);
    check(mkfifo(p, 0640) == 0, "mkfifo");

    check(stat(p, &ps) == 0, "stat on the path");
    show("stat:", &ps);
    check(S_ISFIFO(ps.st_mode), "path stat says FIFO");

    rfd = open(p, O_RDONLY | O_NONBLOCK);
    check(rfd >= 0, "open the read side");
    check(fstat(rfd, &fs) == 0, "fstat on the descriptor");
    show("fstat:", &fs);
    check(S_ISFIFO(fs.st_mode), "descriptor fstat says FIFO");
    check((fs.st_mode & 07777) == (ps.st_mode & 07777),
          "descriptor mode matches the path");
    check(fs.st_uid == ps.st_uid && fs.st_gid == ps.st_gid,
          "descriptor owner matches the path");
    if (fs.st_dev != ps.st_dev || fs.st_ino != ps.st_ino)
        printf("NOTE: descriptor identity differs from the path "
               "(dev %llx/%llx ino %llu/%llu)\n",
               (unsigned long long) fs.st_dev, (unsigned long long) ps.st_dev,
               (unsigned long long) fs.st_ino, (unsigned long long) ps.st_ino);

    /* A chmod after the FIFO exists must be visible on the descriptor. */
    check(chmod(p, 0604) == 0, "chmod the FIFO to 0604");
    wfd = open(p, O_WRONLY | O_NONBLOCK);
    check(wfd >= 0, "open the write side after the chmod");
    check(fstat(wfd, &fs) == 0 && (fs.st_mode & 07777) == 0604,
          "the descriptor now reports 0604");
    check(write(wfd, &token, 1) == 1, "write one token");
    check(read(rfd, &got, 1) == 1 && got == token, "read it back");

    /* A writer with no reader must be refused, as on a bare kernel. */
    close(rfd);
    errno = 0;
    rc = open(p, O_WRONLY | O_NONBLOCK);
    check(rc < 0 && errno == ENXIO,
          "O_WRONLY|O_NONBLOCK with no reader is ENXIO");
    if (rc >= 0)
        close(rc);
    rfd = open(p, O_RDONLY | O_NONBLOCK);

    /* Rename: the same FIFO under a new name must be the same pipe, so a
     * reader opened before the rename sees a write made after it. */
    check(rename(p, q) == 0, "rename the FIFO");
    w2 = open(q, O_WRONLY | O_NONBLOCK);
    check(w2 >= 0, "open the write side under the new name");
    check(write(w2, &token, 1) == 1, "write after the rename");
    check(read(rfd, &got, 1) == 1 && got == token,
          "reader opened before the rename gets it");

    /* Unlink then re-create: the old pipe must not be connected to the new
     * FIFO that happens to carry the old name. */
    close(w2);
    close(wfd);
    check(unlink(q) == 0, "unlink the FIFO");
    check(mkfifo(q, 0640) == 0, "create a new FIFO at the same name");
    r2 = open(q, O_RDONLY | O_NONBLOCK);
    w3 = open(q, O_WRONLY | O_NONBLOCK);
    check(r2 >= 0 && w3 >= 0, "open both ends of the new FIFO");
    check(write(w3, &token, 1) == 1, "write into the new FIFO");
    check(read(r2, &got, 1) == 1 && got == token, "the new reader gets it");
    errno = 0;
    rc = read(rfd, &got, 1);
    check(rc == 0 || (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)),
          "the old reader is not attached to the new FIFO");

    close(r2);
    close(w3);
    close(rfd);
    clean(p, q);

    printf("%s\n", fail ? "RESULT: FAIL" : "RESULT: PASS");
    return fail;
}
EOF

cc -O1 -o twin twin.c || exit 1
./twin
echo "twin rc=$?"
echo done
