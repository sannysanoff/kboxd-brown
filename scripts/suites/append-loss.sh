#!/bin/sh
# Does an append to a guest file survive a second process?
#
# autoconf's config.status writes a generated header with one `cat > file` and
# then several `cat >> file` chunks. In the guest the header came out 307 bytes
# short with a token missing mid-line (`#  define je_nallocx je_nallocx` had
# become `#  define je_ je_nallocx`) and a block of lines gone from the middle,
# so the jemalloc build died with "jemalloc.h:1: unterminated #ifndef".
#
# This reproduces the shape without a compiler: one block written with `>`,
# then a second block appended with `>>` by another process. On the internal
# filesystem the append is lost every time; on the mounted volume it is not.
#
# Usage, from the volume the pod already has staged:
#   docker run --rm -v /data/vol:/vol alpine:3.21 sh /vol/three/append-loss.sh
#
# Writes /vol/results/append-loss.log.
exec > /vol/results/append-loss.log 2>&1

mkblock() {
    awk -v tag="$1" 'BEGIN { for (i = 0; i < 220; i++) printf "block %s line %04d aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", tag, i }'
}

run() {
    dir=$1
    label=$2
    f="$dir/appended.bin"
    ref="$dir/appended-ref.bin"
    rm -f "$f" "$ref"
    mkblock A > "$dir/blk-a"
    mkblock B > "$dir/blk-b"
    cat "$dir/blk-a" "$dir/blk-b" > "$ref"
    cat "$dir/blk-a" > "$f"
    cat "$dir/blk-b" >> "$f"
    echo "$label: bytes=$(wc -c < "$f") expected=$(wc -c < "$ref")"
    echo "$label: first=[$(head -1 "$f")] line221=[$(sed -n 221p "$f")]"
    if cmp -s "$f" "$ref"; then
        echo "$label: identical"
    else
        echo "$label: the appended block is missing"
        cmp "$f" "$ref" 2>&1 | head -1
    fi
}

mkdir -p /data
round=1
while [ $round -le 3 ]; do
    run /data "internal-$round"
    round=$((round + 1))
done
run /vol "volume"
echo done
