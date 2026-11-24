#!/bin/sh
# Reproduce the parallel-build trap: make -j1 finishes, make -jN dies with
# SIGTRAP.
#
# Building nginx in the guest with the harness's make -j4 stopped at the first
# compiler with "Trace/breakpoint trap", and a full build with make -j1
# finished. No compiler is needed to see it: GNU make with more than one job
# creates a jobserver and starts several children before the first is reaped,
# and that shape alone kills make.
#
# Measured on the same pod, same image:
#   make -j1  rc=0    eight targets built
#   make -j2  rc=133  128 + 5, SIGTRAP, no target built
#   make -j4  rc=133  same
#   make -j4 -n       rc=0    dry run, no jobs started
#   make -j4 --jobserver-style=fifo  rc=133   same, so the pipe is not it
#   shell-only concurrent forks (three children, twenty rounds) all rc=0
# and image v157, built before the readv fix, gives the same -j1/-j2/-j4
# results, so the trap predates that fix.
#
# A partial in-guest build therefore works and a parallel one does not; the
# suite harnesses build with -j1 until this is understood, which is what
# BUILD_JOBS selects.
#
# Usage, from the volume the pod already has staged:
#   docker run --rm -v /data/vol:/vol alpine:3.21 \
#       sh /vol/three/parallel-build.sh
#
# Needs /vol/apk-repo (see scripts/suites/mariadb.sh for how that is staged).
# Writes /vol/results/parallel-build.log and one log per job count.
exec > /vol/results/parallel-build.log 2>&1

APK_REPO=""
if [ -f /vol/apk-repo/APKINDEX.tar.gz ] ||
    [ -f /vol/apk-repo/aarch64/APKINDEX.tar.gz ]; then
    APK_REPO="--repository /vol/apk-repo --allow-untrusted"
fi

attempt=1
while :; do
    # shellcheck disable=SC2086
    apk add --no-cache $APK_REPO make >> /vol/results/parallel-build-apk.log 2>&1 &&
        break
    [ "$attempt" -ge 4 ] && { echo "apk make failed"; exit 1; }
    attempt=$((attempt + 1))
    sleep 2
done

echo "make: $(make --version | head -1)"

mkdir -p /data/parallel-build
cd /data/parallel-build || exit 1
printf 'all: a b c d e f g h\na b c d e f g h:\n\tsleep 1\n\ttouch $@\n' \
    > Makefile

try() {
    jobs=$1
    rm -f a b c d e f g h
    make -j"$jobs" > "/vol/results/parallel-build-$jobs.log" 2>&1
    rc=$?
    built=$(ls a b c d e f g h 2>/dev/null | tr '\n' ' ')
    echo "jobs=$jobs rc=$rc built=$built"
    tail -1 "/vol/results/parallel-build-$jobs.log"
}

try 1
try 2
try 4
echo "a nonzero status above is the defect: 133 is 128 + 5, SIGTRAP"
echo done
