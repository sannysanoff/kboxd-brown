#!/bin/sh
# Which step loses an append: the open, the redirect, fork, or exec?
# Every case starts from a file holding "A\n" and appends "B\n" one way.
exec > /vol/results/append-matrix.log 2>&1

mkdir -p /data/am
cd /data/am || exit 1

show() {
    label=$1
    f=$2
    printf '%-34s size=%s content=[%s]\n' "$label" "$(wc -c < "$f")" "$(tr '\n' ' ' < "$f")"
}

# 1. Both writes in this shell, builtins only.
printf 'A\n' > f1
printf 'B\n' >> f1
show "1 builtin > then builtin >>" f1

# 2. The append done by a child shell, builtin.
printf 'A\n' > f2
sh -c 'printf "B\n" >> f2'
show "2 builtin > then child builtin >>" f2

# 3. The append done by an external command (cat).
printf 'A\n' > blk
printf 'A\n' > f3
cat blk >> f3
show "3 builtin > then cat >>" f3

# 4. Same, with the child shell in between.
printf 'A\n' > f4
sh -c 'cat blk >> f4'
show "4 builtin > then child cat >>" f4

# 5. Redirect through an explicit subshell and exec.
printf 'A\n' > f5
sh -c 'exec 1>>f5; printf "B\n"'
show "5 builtin > then exec 1>> and builtin" f5

# 6. The same shapes with > instead of >>, as a control.
printf 'C\n' > f6a
cat blk > f6a
show "6a cat > (control)" f6a
printf 'C\n' > f6b
sh -c 'cat blk > f6b'
show "6b child cat > (control)" f6b

# 7. Append to a larger file through an external command.
awk 'BEGIN{for(i=0;i<220;i++)printf "line %04d\n",i}' > big
awk 'BEGIN{for(i=0;i<220;i++)printf "line %04d\n",i}' > f7
cat big >> f7
show "7 cat >> onto 220-line file" f7

# 8. The shell's own redirection without a child, append.
printf 'A\n' > f8
printf 'B\n' 1>>f8
show "8 explicit 1>> in this shell" f8

# 9. dd, which is external and uses the same redirect.
printf 'A\n' > f9
dd if=blk >> f9 2>/dev/null
show "9 dd >>" f9

echo done
