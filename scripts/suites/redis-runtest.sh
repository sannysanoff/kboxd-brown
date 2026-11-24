#!/bin/sh
# Measure how often the redis test harness dies inside the guest.
#
# One full run went quiet after 121 [ok]; a single-file run prints
# "Starting test server at port 21079" and then Trace/breakpoint trap. The same
# file passes when the daemon logs every syscall, so the claim has to be a rate,
# not a verdict: this builds the tree the way the suite does and runs one file
# twenty times, printing pass, trap or the exit status of each attempt.
#
# Measured on image v160: 20 of 20 trapped against a daemon without -v, 5 of 5
# on the host-built tree in the same pod, and 9 of 9 passed against a daemon
# with -v. See item 31 in three-suites-report.md.
#
# Usage, from the volume the pod already has staged:
#   docker run --rm -v /data/vol:/vol alpine:3.21 \
#       sh /vol/three/redis-runtest.sh
#
# Needs /vol/apk-repo and /vol/cache/redis-7.4.2.tar.gz. Writes
# /vol/results/rt-loop.log and one log per attempt.
exec > /vol/results/rt-loop.log 2>&1

apk update >> /vol/results/rt-loop-apk.log 2>&1
for pkg in build-base make linux-headers tcl procps; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/rt-loop-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data
cd /data || exit 1
tar xzf /vol/cache/redis-7.4.2.tar.gz || exit 1
cd redis-7.4.2 || exit 1

make -j1 MALLOC=libc OPTIMIZATION="-O3 -flto=1" > /data/redis-build.log 2>&1
echo "build rc=$?"
./src/redis-server --version

pass=0
trap=0
fail=0
i=1
while [ "$i" -le 20 ]; do
    rm -rf tests/tmp
    ./runtest --single unit/acl --clients 1 --timeout 60 \
        > "/vol/results/rt-loop-$i.log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        pass=$((pass + 1))
        verdict=pass
    elif grep -q "Trace/breakpoint trap" "/vol/results/rt-loop-$i.log"; then
        trap=$((trap + 1))
        verdict=trap
    else
        fail=$((fail + 1))
        verdict="fail rc=$rc"
    fi
    last=$(tail -1 "/vol/results/rt-loop-$i.log")
    echo "run $i: $verdict  last=[$last]"
    i=$((i + 1))
done

echo "=== totals"
echo "pass=$pass trap=$trap fail=$fail of 20"
echo done
