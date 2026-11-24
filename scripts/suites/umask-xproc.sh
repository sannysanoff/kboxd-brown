#!/bin/sh
# Verify per-process umask isolation across fork/subshells on both /vol and
# /tmp (item 43):
#
# Previously ctx->guest_umask and LKL's umask were container-global. Any child
# calling umask(0077) (such as mariadbd) permanently poisoned its parent's and
# siblings' umask, causing files created on /vol and /tmp to get mode 0600
# instead of 0644 (breaking MariaDB's main.mysqlbinlog LOAD_FILE() check).
#
# Results: /vol/results/umask-xproc.log
mkdir -p /vol/results
exec > /vol/results/umask-xproc.log 2>&1

fail=0
check() {
    ok=$1
    desc=$2
    det=$3
    if [ "$ok" -eq 1 ]; then
        printf "%-54s ok (%s)\n" "$desc" "$det"
    else
        printf "%-54s FAIL (%s)\n" "$desc" "$det"
        fail=1
    fi
}

rm -f /vol/um_p1 /vol/um_c1 /vol/um_p2 /tmp/um_p1 /tmp/um_c1 /tmp/um_p2

umask 0022
echo hi > /vol/um_p1
echo hi > /tmp/um_p1
m_vp1=$(stat -c '%a' /vol/um_p1)
m_tp1=$(stat -c '%a' /tmp/um_p1)
check "$([ "$m_vp1" = "644" ] && echo 1 || echo 0)" "parent umask 0022 creates /vol file 644" "mode=$m_vp1"
check "$([ "$m_tp1" = "644" ] && echo 1 || echo 0)" "parent umask 0022 creates /tmp file 644" "mode=$m_tp1"

(
    umask 0077
    echo hi > /vol/um_c1
    echo hi > /tmp/um_c1
)
m_vc1=$(stat -c '%a' /vol/um_c1)
m_tc1=$(stat -c '%a' /tmp/um_c1)
check "$([ "$m_vc1" = "600" ] && echo 1 || echo 0)" "child umask 0077 creates /vol file 600" "mode=$m_vc1"
check "$([ "$m_tc1" = "600" ] && echo 1 || echo 0)" "child umask 0077 creates /tmp file 600" "mode=$m_tc1"

echo hi > /vol/um_p2
echo hi > /tmp/um_p2
m_vp2=$(stat -c '%a' /vol/um_p2)
m_tp2=$(stat -c '%a' /tmp/um_p2)
p_um=$(umask)
check "$([ "$m_vp2" = "644" ] && echo 1 || echo 0)" "parent /vol file stays 644 after child umask 0077" "mode=$m_vp2 umask=$p_um"
check "$([ "$m_tp2" = "644" ] && echo 1 || echo 0)" "parent /tmp file stays 644 after child umask 0077" "mode=$m_tp2 umask=$p_um"

rm -f /vol/um_p1 /vol/um_c1 /vol/um_p2 /tmp/um_p1 /tmp/um_c1 /tmp/um_p2

if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: FAIL"
exit 1
