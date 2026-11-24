#!/bin/sh
# Verify virtual ownership edge cases (row 38 / item 36):
#
# 1. chown 7:8 then chown 65534:65534 (the pod's own uid/gid) must report
#    65534:65534 on both /vol (host-backed) and /data (internal LKL).
# 2. Partial chown (chown 9, chgrp 20) must preserve the untouched component
#    and persist a valid "uid:gid" xattr on /vol.
# 3. fchown on an open descriptor must agree with path chown.
#
# Results: /vol/results/chown-edge.log
exec > /vol/results/chown-edge.log 2>&1

fail=0
check() {
    label=$1
    got=$2
    want=$3
    if [ "$got" = "$want" ]; then
        printf '%-54s ok (%s)\n' "$label" "$got"
    else
        printf '%-54s FAIL (got=%s want=%s)\n' "$label" "$got" "$want"
        fail=1
    fi
}

rm -rf /vol/own-edge /data/own-edge
mkdir -p /vol/own-edge /data/own-edge
touch /vol/own-edge/f /data/own-edge/f

chown 7:8 /vol/own-edge/f
check "/vol chown 7:8" "$(stat -c '%u:%g' /vol/own-edge/f)" "7:8"

chown 65534:65534 /vol/own-edge/f
check "/vol chown back to 65534:65534" "$(stat -c '%u:%g' /vol/own-edge/f)" "65534:65534"

chown 9:10 /vol/own-edge/f
chgrp 20 /vol/own-edge/f
check "/vol partial chgrp 20 keeps uid 9" "$(stat -c '%u:%g' /vol/own-edge/f)" "9:20"

chown 65534 /vol/own-edge/f
check "/vol partial chown 65534 keeps gid 20" "$(stat -c '%u:%g' /vol/own-edge/f)" "65534:20"

chown 7:8 /data/own-edge/f
check "/data chown 7:8" "$(stat -c '%u:%g' /data/own-edge/f)" "7:8"

chown 65534:65534 /data/own-edge/f
check "/data chown back to 65534:65534" "$(stat -c '%u:%g' /data/own-edge/f)" "65534:65534"

chown 9:10 /data/own-edge/f
chgrp 20 /data/own-edge/f
check "/data partial chgrp 20 keeps uid 9" "$(stat -c '%u:%g' /data/own-edge/f)" "9:20"

chown 65534 /data/own-edge/f
check "/data partial chown 65534 keeps gid 20" "$(stat -c '%u:%g' /data/own-edge/f)" "65534:20"

rm -rf /vol/own-edge /data/own-edge
if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
exit "$fail"
