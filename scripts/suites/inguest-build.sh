#!/bin/sh
# Item 14: does a build inside the guest work on the internal filesystem?
#
# The defect was that ld and objdump rejected correct object files that lived on
# the internal filesystem while accepting the same bytes from a mounted volume.
# This repeats the checks section 14 of three-suites-report.md relies on:
# object files shipped in the image, one object copied to both filesystems, a
# relocatable link, a full compile and link written to the internal filesystem,
# a multi-file build with a static library, a make-driven build, and a serial
# make over forty translation units.
#
# Everything is built under /data, which is the internal filesystem. /vol is the
# mounted volume, used only for the comparison and for the log.
#
# Usage, with the package repository already staged on the volume:
#   docker run --rm -v /data/vol:/vol alpine:3.21 sh /vol/three/inguest-build.sh
#
# Writes /vol/results/inguest-build.log.
exec > /vol/results/inguest-build.log 2>&1

apk update > /vol/results/inguest-build-apk.log 2>&1
for pkg in build-base make; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/inguest-build-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

WORK=/data/inguest
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK" || exit 1

echo "=== tools"
for t in gcc ld objdump readelf ar nm make; do
    printf '%-10s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
done

echo
echo "=== object files shipped in the image, internal filesystem"
for f in /usr/lib/Scrt1.o /usr/lib/crt1.o /usr/lib/crti.o /usr/lib/crtn.o; do
    [ -f "$f" ] || continue
    if objdump -f "$f" > /dev/null 2>&1; then
        verdict=ok
    else
        verdict=FAIL
    fi
    printf '%-24s %7s %s\n' "$f" "$(wc -c < "$f")" "$verdict"
done

echo
echo "=== the same object from a mounted volume"
cp /usr/lib/Scrt1.o /vol/inguest-scrt1.o 2>/dev/null
if objdump -f /vol/inguest-scrt1.o > /dev/null 2>&1; then
    printf '%-24s %7s %s\n' /vol/inguest-scrt1.o \
        "$(wc -c < /vol/inguest-scrt1.o)" ok
else
    printf '%-24s %7s %s\n' /vol/inguest-scrt1.o \
        "$(wc -c < /vol/inguest-scrt1.o)" FAIL
fi

echo
echo "=== objdump output, internal filesystem"
objdump -f /usr/lib/Scrt1.o 2>&1 | head -6

echo
echo "=== readelf, internal filesystem"
readelf -h /usr/lib/Scrt1.o 2>&1 | head -4

echo
echo "=== relocatable link of an internal object"
cp /usr/lib/crti.o crti-copy.o
ld -r -o reloc.o crti-copy.o >> reloc.log 2>&1
echo "ld -r rc=$?"
[ -f reloc.o ] && echo "reloc.o $(wc -c < reloc.o) bytes"

echo
echo "=== full compile and link, output on the internal filesystem"
cat > hello.c <<'EOF'
#include <stdio.h>
int main(void)
{
    printf("hello from kbox\n");
    return 0;
}
EOF
gcc -O1 -o hello hello.c > cc.log 2>&1
echo "gcc link rc=$?"
./hello
echo "run rc=$?"

echo
echo "=== a multi-file build with a static library"
cat > util.c <<'EOF'
int answer(void) { return 42; }
EOF
cat > main.c <<'EOF'
#include <stdio.h>
int answer(void);
int main(void)
{
    printf("%d\n", answer());
    return 0;
}
EOF
gcc -c -o util.o util.c > multi.log 2>&1 && echo "compile util rc=0"
gcc -c -o main.o main.c >> multi.log 2>&1 && echo "compile main rc=0"
ar rcs libutil.a util.o >> multi.log 2>&1 && echo "archive rc=0"
gcc -o multi main.o libutil.a >> multi.log 2>&1 && echo "archive link rc=$?"
./multi
echo "run rc=$?"

echo
echo "=== make-driven build, as a package build does"
cat > Makefile <<'EOF'
all: prog
prog: main.o util.o
	$(CC) -o prog main.o util.o
main.o: main.c
	$(CC) -c -o main.o main.c
util.o: util.c
	$(CC) -c -o util.o util.c
EOF
rm -f main.o util.o prog
make >> make.log 2>&1
echo "make build rc=$?"
./prog
echo "run rc=$?"

echo
echo "=== a serial make over forty translation units"
mkdir -p tree
i=1
while [ $i -lt 39 ]; do
    printf 'int f%d(void) { return %d; }\n' "$i" "$i" > "tree/f$i.c"
    i=$((i + 1))
done
printf 'int f0(void) { return 0; }\n' > tree/f0.c
printf 'int f39(void) { return 39; }\n' > tree/f39.c
cat > tree/main.c <<'EOF'
#include <stdio.h>
int f0(void);
int f39(void);
int main(void)
{
    printf("%d %d\n", f0(), f39());
    return 0;
}
EOF
{
    printf 'all: prog\n\nOBJS ='
    for f in tree/*.c; do
        printf ' %s' "${f%.c}.o"
    done
    printf '\n\nprog: $(OBJS)\n'
    printf '\t$(CC) -o prog $(OBJS)\n\n'
    printf 'tree/%%.o: tree/%%.c\n'
    printf '\t$(CC) -c -o $@ $<\n'
} > Makefile.tree
make -f Makefile.tree >> make-tree.log 2>&1
echo "make -f Makefile.tree rc=$?"
echo "objects built: $(ls tree/*.o 2>/dev/null | wc -l)"
[ -x prog ] && ./prog
echo "run rc=$?"

echo
echo "=== sizes and checksums of what the guest produced"
ls -l hello multi 2>&1
md5sum hello multi 2>&1
echo done
