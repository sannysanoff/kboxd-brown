#!/bin/sh
# Does a redirect's data reach the file before the writer exits?
#
# A close of a low descriptor now runs in the kernel (item 33), so kbox no
# longer sees the moment a writable shadow is closed. Its bytes are flushed when
# the number is reused, or at process exit # (which is notified), and any reader
# that asks kbox for the file finds the live shadow by inode. This measures the
# case a reader would notice: bytes written through a redirect, the descriptor
# closed explicitly, and the file read by another process before the writer
# exits.
#
# Results: /vol/results/redir-writeback.log
exec > /vol/results/redir-writeback.log 2>&1

V=$(printf 'payload-%03d\n' 1 2 3 4 5 6 7 8 9 10)
fail=0

report() {
    printf '%-56s %s\n' "$1" "$2"
    [ "$2" = "ok" ] || fail=1
}

mkdir -p /data
F=/data/redir-writeback.txt
rm -f "$F"

# 1. Redirect, write, close the descriptor, then read as a child of the same
#    shell (a different process than the one that closed it).
exec 5>"$F"
printf '%s' "$V" >&5
exec 5>&-
child_out=`cat "$F"`
if [ "$child_out" = "$V" ]; then
    report "explicitly closed redirect is readable by a child" ok
else
    report "explicitly closed redirect is readable by a child" \
        "FAIL (got ${#child_out} of ${#V} bytes)"
fi

# 2. The file's size, asked by a child, must be the full size while the writer
#    is still alive.
size=`wc -c < "$F" | tr -d ' '`
if [ "$size" = "${#V}" ]; then
    report "size seen by a child while the writer lives" ok
else
    report "size seen by a child while the writer lives" \
        "FAIL (got $size, want ${#V})"
fi

# 3. The same shape through a subshell that exits: the closing process is gone,
#    so only the flush can carry the bytes.
(
    exec 6>"$F"
    printf 'second' >&6
    exec 6>&-
)
after=`cat "$F"`
if [ "$after" = "second" ]; then
    report "a subshell's closed redirect lands in the file" ok
else
    report "a subshell's closed redirect lands in the file" \
        "FAIL (got [$after])"
fi

# 4. A plain ">" redirect through a command, then read back.
printf 'third' >"$F"
third=`cat "$F"`
if [ "$third" = "third" ]; then
    report "a command's > redirect lands in the file" ok
else
    report "a command's > redirect lands in the file" "FAIL (got [$third])"
fi

rm -f "$F"
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
echo done
