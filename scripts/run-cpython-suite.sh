#!/bin/sh
# SPDX-License-Identifier: MIT
# Run the CPython regression suite one module at a time, inside a guest.
#
# The suite is run in turn rather than in one regrtest pass, because a single
# module that hangs must cost one module: regrtest's own --timeout aborts the
# whole run, and a hang in an early module otherwise hides the other 400.
#
# Usage (from inside the guest, with the suite importable):
#   ./run-cpython-suite.sh OUTDIR [PER_MODULE_TIMEOUT] [module ...]
#
# Each module writes OUTDIR/<module>.log and appends one line to
# OUTDIR/summary.txt: "<module> <status> <seconds>", where status is one of
# PASS, FAIL, TIMEOUT or SKIP.
#
# Environment:
#   PYTEST_SKIP   space-separated module names to skip
#   PYTEST_PYTHON interpreter (default: python3)

set -u

OUTDIR="${1:-/out}"
if [ "$#" -gt 0 ]; then
    shift
fi
PER_TIMEOUT="${1:-300}"
if [ "$#" -gt 0 ]; then
    case "$PER_TIMEOUT" in
        '' | *[!0-9]*) ;; # keep the default
        *) shift ;;
    esac
fi
PYTHON="${PYTEST_PYTHON:-python3}"
SKIP="${PYTEST_SKIP:-}"

mkdir -p "$OUTDIR" || exit 1
: > "$OUTDIR/summary.txt"

# Every test_*.py plus every test_* package directory, in the same order
# regrtest would discover them.
TESTDIR=$("$PYTHON" -c 'import test, os; print(os.path.dirname(test.__file__))')
MODULES=$(cd "$TESTDIR" && ls -d test_*.py test_*/ 2>/dev/null |
    sed -e 's|/\(.*\)$|\1|' -e 's|\.py$||' | sort -u)

if [ "$#" -gt 0 ]; then
    MODULES="$*"
fi

for mod in $MODULES; do
    case " $SKIP " in
        *" $mod "*)
            printf '%s SKIP 0\n' "$mod" >> "$OUTDIR/summary.txt"
            continue
            ;;
    esac

    start=$(date +%s)
    timeout "$PER_TIMEOUT" "$PYTHON" -m test -q --timeout "$PER_TIMEOUT" "$mod" \
        > "$OUTDIR/$mod.log" 2>&1
    rc=$?
    end=$(date +%s)
    el=$((end - start))

    case "$rc" in
        0) status=PASS ;;
        124) status=TIMEOUT ;;
        *) status=FAIL ;;
    esac
    printf '%s %s %s\n' "$mod" "$status" "$el" >> "$OUTDIR/summary.txt"
    printf '%-34s %-8s %ss\n' "$mod" "$status" "$el"
done

printf '\n== summary\n'
awk '{c[$2]++} END {for (k in c) printf "%s %d\n", k, c[k]}' \
    "$OUTDIR/summary.txt"
exit 0
