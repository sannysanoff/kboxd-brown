#!/bin/sh
# MariaDB: run the test suite the distribution package installs.
#
# The package ships the runner together with its suite files and helpers in
# /usr/mariadb-test, so the tests, the runner and the server under test all come
# from the same build. mtr refuses to start unless its own directory is the
# current directory and it contains mariadb-test-run.pl, so the run happens
# inside the tree.
#
# The tree and the data directory can both be moved onto the host-mounted
# volume, which is the configuration a persistent volume gives:
#   MB_SUITE_DIR=/vol/mariadb-test MB_VARDIR=/vol/mtr-var
#
# Results: /vol/results/mariadb/
#   apk.log          package installation
#   mtr.log          complete runner output
#   results.list     every test line with a non-pass verdict
#   failed.list      failed tests
#   skipped.list     skipped tests
#   counts.txt       totals
set -u

MB_VERSION="${MB_VERSION:-11.4.13}"
TARBALL="${MB_TARBALL:-/vol/cache/mariadb-$MB_VERSION.tar.gz}"
OUT=/vol/results/mariadb
WORK=/data/mtr
VARDIR="${MB_VARDIR:-$WORK/var}"
mkdir -p "$OUT" "$WORK" "$VARDIR"

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
# One package at a time: a single transaction over the whole set extracts
# thousands of files and is the configuration that exposes descriptor
# accounting bugs, so staging keeps the harness honest and the failure small.
apk update > "$OUT/apk.log" 2>&1
for p in perl patch mariadb-common mariadb-client mariadb mariadb-test; do
    # A streaming install reads a 70 MB package from HTTPS straight into the
    # extractor. That failed twice across these runs with "BAD archive" /
    # "Connection aborted" and then succeeded on retry, and five separate
    # downloads of the same object verified byte-identical, so it is a
    # transient read-side failure rather than a repeatable one. Retry a bounded
    # number of times and record the attempt count.
    attempt=1
    while :; do
        # shellcheck disable=SC2086
        apk add --no-cache $APK_REPO "$p" >> "$OUT/apk.log" 2>&1
        rc=$?
        [ "$rc" -eq 0 ] && break
        [ "$attempt" -ge 3 ] && break
        attempt=$((attempt + 1))
        echo "retrying $p after failure (attempt $attempt)" >> "$OUT/apk.log"
        sleep 3
    done
    echo "apk $p exit=$rc attempts=$attempt"
    [ "$rc" -eq 0 ] || { tail -20 "$OUT/apk.log"; exit "$rc"; }
done

# mariadb-test-run.pl resolves every tool it will hand to a test at startup and
# treats a missing one as fatal, but Alpine ships neither mariadb-upgrade nor
# perror in any mariadb package (`apk search -x '*upgrade*'` is empty and
# neither file exists anywhere in the installed tree). Without them the runner
# never starts and no test runs. Stubs are installed so the suite runs; they
# report the real situation and fail, so a test that genuinely needs one fails
# visibly instead of passing on a fake success. Those failures are the
# distribution's gap, not kbox's, and the report classifies them.
stub_missing_tool() {
    tool=$1
    [ -x "/usr/bin/$tool" ] && return 0
    {
        echo '#!/bin/sh'
        echo "# Placeholder: Alpine's mariadb packages do not ship $tool."
        echo "echo \"$tool: not provided by this distribution\" >&2"
        echo 'exit 1'
    } > "/usr/bin/$tool"
    chmod 755 "/usr/bin/$tool"
    echo "missing tool $tool: installed a stub" | tee -a "$OUT/missing-tools.txt"
}
stub_missing_tool mariadb-upgrade
stub_missing_tool perror

# The runner computes its tree path as <prefix>/mysql-test and requires its
# helpers there (lib/My/SafeProcess/my_safe_process and the share files), but
# Alpine installs the same tree as /usr/mariadb-test. Rename the packaged tree
# so the directory name is the one the runner computes. A symlink will not do:
# the runner discovers suites through both paths, treats the second as an
# overlay, and dies while collecting them.
if [ -d /usr/mariadb-test ] && [ ! -e /usr/mysql-test ]; then
    mv /usr/mariadb-test /usr/mysql-test 2>/dev/null || true
fi

echo "=== locate the suite"
SRC="${MB_SUITE_DIR:-}"
if [ -z "$SRC" ]; then
    for d in /usr/mysql-test /usr/mariadb-test /usr/share/mysql-test \
        /usr/share/mariadb-test; do
        if [ -f "$d/mariadb-test-run.pl" ]; then
            SRC="$d"
            break
        fi
    done
fi
if [ -z "$SRC" ]; then
    # No packaged suite: extract the matching source release instead. The
    # runner and mysql-test/ must come from the same version as the server.
    SRC="$WORK/src/mysql-test"
    if [ ! -d "$SRC" ]; then
        if [ ! -f "$TARBALL" ]; then
            mkdir -p "$(dirname "$TARBALL")" || exit 3
            echo "fetching $MB_VERSION source"
            wget -q -O "$TARBALL" \
                "https://archive.mariadb.org/mariadb-$MB_VERSION/source/mariadb-$MB_VERSION.tar.gz" \
                || { echo "cannot fetch $TARBALL" >&2; exit 3; }
        fi
        mkdir -p "$WORK/x"
        tar xzf "$TARBALL" -C "$WORK/x" "mariadb-$MB_VERSION/mysql-test" \
            || exit 3
        mkdir -p "$(dirname "$SRC")"
        mv "$WORK/x/mariadb-$MB_VERSION/mysql-test" "$SRC"
        rm -rf "$WORK/x"
    fi
fi
echo "suite=$SRC"


RUNNER=""
for r in mariadb-test-run.pl mysql-test-run.pl; do
    if [ -f "$SRC/$r" ]; then
        RUNNER="$SRC/$r"
        break
    fi
done
[ -n "$RUNNER" ] || { echo "no runner in $SRC" >&2; exit 3; }
echo "runner=$RUNNER"

# The suites to run: main plus every directory the tree offers besides it.
SUITES="main"
for d in "$SRC"/suite/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    SUITES="$SUITES,$name"
done
echo "suites=$SUITES" | tee "$OUT/suites.txt"

echo "=== run"
# --force keeps going after a failing case, --retry=0 makes a failure
# reproducible instead of hidden by a retry, --parallel=1 keeps one server at
# a time because the daemon runs one container and the pod one LKL engine.
# MTR_BINDIR is the tree the runner reads bin/ and share/ from: the
# distribution's prefix is /usr, which holds both.
# shellcheck disable=SC2086
(
    cd "$SRC" || exit 1
    # The kernel kbox provides does not give a guest process aio contexts:
    # io_setup arrives at the supervisor and is refused, and InnoDB then logs
    # "native AIO failed: falling back to innodb_use_native_aio=OFF". The
    # runner counts a new server-log line as a test failure, so every test that
    # starts a server fails on that warning. Running without native AIO is a
    # configuration the server documents and supports; set MB_NATIVE_AIO=1 to
    # keep it when the kernel implements io_setup for guests.
    AIO_OPT=--mysqld=--loose-innodb-use-native-aio=0
    [ "${MB_NATIVE_AIO:-0}" = "1" ] && AIO_OPT=""
    # The runner hands every server --slave-load-tmpdir=../tmp, a deliberately
    # relative path ("the path need to have constant length otherwise test
    # results will vary").  mariadbd resolves it against its data directory,
    # which makes it <vardir>/mysqld.N/tmp, and that directory does not exist,
    # so a replica's SQL thread stops at once:
    #
    #   [ERROR] Slave SQL: Unable to use slave's temporary directory
    #   ../../tmp - Can't read dir of '/vol/mtr-var/mysqld.2/tmp/' (Errcode: 2)
    #
    # Replication tests then wait for a slave that will never catch up, and the
    # run hangs.  Naming the directory absolutely removes the ambiguity; the
    # directory the runner already created is <vardir>/tmp.
    SLAVE_TMP_OPT="--mysqld=--slave-load-tmpdir=$VARDIR/tmp"
    # A hung test would otherwise block the whole suite: mtr's default is no
    # per-test timeout.  Ten minutes is far above any healthy test's run time
    # and turns a hang into a verdict.
    TIMEOUT_OPT="--testcase-timeout=${MB_TEST_TIMEOUT:-10}"
    MB_MTR_ARGS="${MB_MTR_ARGS:-}" MTR_BINDIR=/usr \
        perl "$RUNNER" \
        --client-bindir=/usr/bin \
        --vardir="$VARDIR" \
        --suite="$SUITES" \
        --parallel=1 \
        --retry=0 \
        --force \
        --max-test-fail=0 \
        --noreorder \
        "$AIO_OPT" \
        "$SLAVE_TMP_OPT" \
        "$TIMEOUT_OPT" \
        ${MB_MTR_ARGS:-} \
        > "$OUT/mtr.log" 2>&1
)
echo "mtr exit=$?" >> "$OUT/mtr.log"

echo "=== verdicts"
# Every test line looks like "main.1st    [ pass ]   834". Keep the ones that
# did not pass; skips stay visible with their native reason.
grep -aE '\[ (fail|skipped|disabled) \]' "$OUT/mtr.log" 2>/dev/null |
    sed 's/^\([^ ]*\) *\[ /\1 [ /' > "$OUT/results.list" || true
sed -n 's/^\([^ ]*\) \[ fail \].*/\1/p' "$OUT/results.list" |
    sort -u > "$OUT/failed.list" || true
sed -n 's/^\([^ ]*\) \[ skipped \].*/\1/p' "$OUT/results.list" |
    sort -u > "$OUT/skipped.list" || true

{
    echo "failed=$(wc -l < "$OUT/failed.list" 2>/dev/null || echo 0)"
    echo "skipped=$(wc -l < "$OUT/skipped.list" 2>/dev/null || echo 0)"
    echo "passed=$(grep -ac '\[ pass \]' "$OUT/mtr.log" 2>/dev/null || echo 0)"
    grep -aE '^Failed [0-9]+ tests?|^All [0-9]+ tests? were successful|^The test suite was stopped' \
        "$OUT/mtr.log" 2>/dev/null || true
} > "$OUT/counts.txt"
cat "$OUT/counts.txt"
