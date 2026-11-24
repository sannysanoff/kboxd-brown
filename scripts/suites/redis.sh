#!/bin/sh
# Redis: build from source and run its whole TCL test suite (runtest).
#
# Needs tcl (runtest is TCL) and a toolchain, which the guest installs.
# Results: /data/results/redis/{build.log,runtest.log,counts.txt}
set -u

OUT=/vol/results/redis
mkdir -p "$OUT" /data/redis
REDIS_VERSION="${REDIS_VERSION:-7.4.2}"
PREBUILT="${REDIS_PREBUILT_DIR:-/vol/cache/redis-$REDIS_VERSION}"
# A parallel make works: make -j2 and make -j4 build this tree (item 28 in
# three-suites-report.md). The tree is still built with one job because of a
# separate defect: the kernel abandons a seccomp notification when a signal
# arrives for the tracee, so pipe() returns EINTR to the guest about once in
# 36 calls once the tree is compiling and reaping children. A shell abandons
# the command, and jemalloc's configure then generates its header from a list
# it never read. BUILD_JOBS overrides the job count.
JOBS="${BUILD_JOBS:-1}"

echo "=== install"
# A local package repository can be staged on the volume (/vol/apk-repo,
# built with `apk fetch --recursive` then `apk index`). The guest's HTTPS
# stream occasionally stalls inside kbox's socket pump, and installing from
# the volume keeps a run reproducible; the network stays the default when no
# repository is present.
APK_REPO=""
# apk reads a repository whose packages sit in an <arch>/ subdirectory as one
# whose index is <repo>/<arch>/APKINDEX.tar.gz. A flat repository (index at the
# top) is also accepted. Both layouts are staged in different runs, so both are
# recognised here.
if [ -f /vol/apk-repo/APKINDEX.tar.gz ] ||
    [ -f /vol/apk-repo/aarch64/APKINDEX.tar.gz ]; then
    APK_REPO="--repository /vol/apk-repo --allow-untrusted"
    echo "using local package repository /vol/apk-repo"
fi
# apk streams each package from HTTPS into the extractor, and that read side
# has failed transiently ("BAD archive" / "Connection aborted") before
# succeeding on retry, so a bounded retry keeps a network hiccup from failing
# the run.
attempt=1
while :; do
    # shellcheck disable=SC2086
    # procps is what the suite's own helpers use: pause_process reads the
    # state column of "ps j <pid>" and process_is_alive calls "ps -p". Alpine
    # ships busybox ps, which ignores both, so those checks could never pass;
    # plain Docker with this image has the same gap.
    apk add --no-cache $APK_REPO tcl build-base linux-headers curl \
        openssl openssl-dev procps > "$OUT/apk.log" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && break
    [ "$attempt" -ge 3 ] && break
    attempt=$((attempt + 1))
    echo "retrying apk after failure (attempt $attempt)" >> "$OUT/apk.log"
    sleep 3
done
echo "apk exit=$rc attempts=$attempt"
[ "$rc" -eq 0 ] || exit "$rc"

echo "=== fetch $REDIS_VERSION"
cd /data/redis || exit 1
# A tarball prefetched to /vol/cache avoids repeating a slow download on every
# run; the guest fetches it when the cache is cold. /vol is the host-mounted
# volume, so it survives a container but not a pod restart.
CACHE="/vol/cache/redis-$REDIS_VERSION.tar.gz"
if [ ! -d "redis-$REDIS_VERSION" ]; then
    if [ -f "$CACHE" ]; then
        echo "using cached $CACHE"
        cp "$CACHE" redis.tar.gz || exit 3
    else
        curl -sSfL --retry 3 \
            "https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz" \
            -o redis.tar.gz || exit 3
    fi
    tar xzf redis.tar.gz || exit 3
fi

echo "=== build"
# A tree can be supplied prebuilt on the mounted volume (REDIS_PREBUILT=1). The
# guest builds the tree itself by default, which is the normal path since the
# linker learned to read object files from the internal filesystem (image
# v159). The prebuilt switch remains for comparing a guest build against a
# host build of the same source.
TREE="/data/redis/redis-$REDIS_VERSION"
if [ "${REDIS_PREBUILT:-0}" = "1" ] && [ -x "$PREBUILT/src/redis-server" ]; then
    # Run the tree where it lives: /vol is the host-mounted volume, so this is
    # also the run that exercises the suite on a mounted volume rather than the
    # guest's internal filesystem.
    echo "using prebuilt $PREBUILT"
    TREE="$PREBUILT"
else
    cd "$TREE" || exit 1
    # The guest builds redis's default configuration: the bundled jemalloc and
    # -O3. One flag is still chosen for the guest, not for redis:
    #  - OPTIMIZATION with -flto=1 instead of -flto=auto. The automatic form
    #    makes gcc run its LTRANS stage through a parallel make, which now
    #    works (item 28), but each compile it starts is another chance to lose
    #    a pipe to the EINTR defect described above, and this tree's configure
    #    already loses enough output at one job. Set REDIS_OPTIMIZATION to
    #    override, for example to redis's own default.
    make -j"$JOBS" MALLOC="${REDIS_MALLOC:-jemalloc}" \
        OPTIMIZATION="${REDIS_OPTIMIZATION:--O3 -flto=1}" > "$OUT/build.log" 2>&1
    rc=$?
    echo "build exit=$rc malloc=${REDIS_MALLOC:-jemalloc} opt=${REDIS_OPTIMIZATION:--O3 -flto=1}"
    [ "$rc" -eq 0 ] || { tail -40 "$OUT/build.log"; exit "$rc"; }
fi

echo "=== runtest"
# --clients 1: the daemon starts one container at a time and the pod has a
# single LKL engine, so one client is the honest configuration.
# --skipunit is not used: the objective is every TCL file.
cd "$TREE" || exit 1
# Every syscall in the guest goes through the supervisor, so a test that
# drives many round trips is slower here than on a bare kernel. Two measured
# cases: the maxmemory policies take about 33 s each, and
# "MIGRATE can correctly transfer large values" issues 80000 request/response
# round trips before it migrates, which took about 750 s in unit/dump. The
# suite's own 120 s per-test limit fired while the work was still correct, so
# the budget is sized for the measured overhead instead of reading a slow pass
# as a failure. REDIS_TEST_TIMEOUT overrides it.
REDIS_TIMEOUT="${REDIS_TEST_TIMEOUT:-2400}"
./runtest --clients 1 --timeout "$REDIS_TIMEOUT" > "$OUT/runtest.log" 2>&1
echo "runtest exit=$?" >> "$OUT/runtest.log"

# Redis prints a detail line per verdict and then repeats each failure in the
# summary as "*** [err]: <test> in <file>". Counting the detail lines counts
# every failure twice, so the distinct summary lines are what the totals use.
{
    echo "ok=$(grep -ac '^\[ok\]' "$OUT/runtest.log" || true)"
    echo "err=$(grep -a '^\*\*\* \[err\]' "$OUT/runtest.log" | sort -u | wc -l | tr -d ' ')"
    echo "exception=$(grep -a '^\*\*\* \[exception\]' "$OUT/runtest.log" | sort -u | wc -l | tr -d ' ')"
    grep -a '^\*\*\* \[err\]\|^\*\*\* \[exception\]' "$OUT/runtest.log" | sort -u > "$OUT/failed.list"
    head -20 "$OUT/failed.list"
} > "$OUT/counts.txt" 2>/dev/null
cat "$OUT/counts.txt"
