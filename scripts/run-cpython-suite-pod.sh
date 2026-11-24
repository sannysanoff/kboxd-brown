#!/bin/sh
# SPDX-License-Identifier: MIT
# Run the CPython regression suite inside the kbox pod, one module per
# container.
#
# A hung module must cost one module: regrtest's own --timeout aborts its whole
# run, and a hang inside the sandbox can wedge the guest so completely that the
# guest-side `timeout` wrapper never returns. One `docker run` per module keeps
# every other module independent, and the per-module limit is enforced from the
# outside (`docker rm -f`).
#
# Usage:
#   ./run-cpython-suite-pod.sh OUTDIR [PER_MODULE_TIMEOUT] [module ...]
#
# Requires the docker context `kbox-python-e2e` (port-forward to the pod's shim)
# and the prepared library tree at /data/python3.12 inside the pod.
#
# Environment:
#   IMAGE       guest image (default: python:3.12-alpine)
#   SUITE_LIB   local dir holding the suite (…/python3.12 with test/)
#   DOCKER      docker command prefix (default: docker --context kbox-python-e2e)

set -u

OUTDIR="${1:-./suite-pod}"
shift 2>/dev/null || true
PER_TIMEOUT="${1:-300}"
shift 2>/dev/null || true
MODULES="$*"

IMAGE="${IMAGE:-python:3.12-alpine}"
# WORKDIR and GUEST_TMPDIR select where the suite runs. The default is the
# container's own writable layer (/tmp). Pointing both at a bind mount
# (WORKDIR=/data/tmp GUEST_TMPDIR=/data/tmp) exercises the mounted-volume path:
# every test file is then created on the host filesystem that kbox serves
# through its bind mounts.
WORKDIR="${WORKDIR:-/tmp}"
GUEST_TMPDIR="${GUEST_TMPDIR:-/tmp}"
# Per-test timeout inside regrtest. Without it a single hanging test (for
# example an asyncio test waiting on a socket event) consumes the whole module
# budget and the external kill reports the module as TIMEOUT, hiding the other
# 2500 tests that did run.
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"
DOCKER="${DOCKER:-docker --context kbox-python-e2e}"
# A port-forward to the pod dies after a while; KPF_HOOK, when set, is a script
# that re-establishes it. Without it the driver stops instead of recording
# every remaining module as a failure for the wrong reason.
KPF_HOOK="${KPF_HOOK:-}"

# dt SECONDS ARGS...: docker, bounded, with the KPF_HOOK retry. A wedged
# container blocks the shim on
# unrelated calls, so an unbounded `rm -f` or `run` stalls the whole sweep: on
# the mounted run a wedged test_socket cost 159 minutes before the outer
# timeout killed the driver.
dt() {
    t="$1"
    shift
    if timeout "$t" $DOCKER version > /dev/null 2>&1; then
        timeout "$t" $DOCKER "$@"
        return $?
    fi
    if [ -n "$KPF_HOOK" ]; then
        sh "$KPF_HOOK" > /dev/null 2>&1
        sleep 2
        timeout "$t" $DOCKER "$@"
        return $?
    fi
    echo "docker daemon unreachable and no KPF_HOOK set" >&2
    return 1
}

mkdir -p "$OUTDIR" || exit 1
: > "$OUTDIR/summary.txt"

# Enumerate from a local copy of the suite: the shim drops attached stdout, so
# asking the guest for the list is not reliable.
if [ -z "$MODULES" ]; then
    LIB="${SUITE_LIB:-}"
    if [ -n "$LIB" ] && [ -d "$LIB/test" ]; then
        MODULES=$(ls -d "$LIB"/test/test_*.py "$LIB"/test/test_*/ 2>/dev/null |
            sed -e 's|.*/test_|test_|' -e 's|/$||' -e 's|\.py$||' |
            sort -u)
    fi
fi
if [ -z "$MODULES" ]; then
    echo "no module list: set SUITE_LIB to a local python lib holding test/" >&2
    exit 1
fi

for mod in $MODULES; do
    name="pytest-$(echo "$mod" | tr '._' '--')"
    dt 25 rm -f "$name" > /dev/null 2>&1

    start=$(date +%s)
    run_rc=0
    dt 90 run --name "$name" \
        -v /data:/data \
        -v /data/python3.12:/usr/local/lib/python3.12 \
        "$IMAGE" /bin/sh -c "cd $WORKDIR && TMPDIR=$GUEST_TMPDIR exec python3 -m test -q --timeout $TEST_TIMEOUT '$mod'" \
        > /dev/null 2>&1 || run_rc=$?
    if [ "$run_rc" = 124 ]; then
        # The shim never accepted the run: an earlier guest is wedged. Record
        # the module and keep going instead of stalling the whole sweep.
        echo "  WARNING: docker run for $mod timed out; the shim is wedged" >&2
        printf '%-34s %-8s %ss\n' "$mod" RUNBLOCKED "$(( $(date +%s) - start ))"
        printf '%s %s %s\n' "$mod" RUNBLOCKED "$(( $(date +%s) - start ))" >> "$OUTDIR/summary.txt"
        continue
    fi

    # docker run returns before the container ends here; poll the state.
    elapsed=0
    status=running
    while [ "$elapsed" -lt "$PER_TIMEOUT" ]; do
        # Every docker call is bounded: a guest that kbox cannot kill leaves
        # `docker rm -f` waiting forever, and a blocked inspect wedges the
        # whole sweep (test_socket did exactly that for 49 minutes).
        status=$(timeout 10 $DOCKER inspect -f '{{.State.Status}}' "$name" 2>/dev/null)
        case "$status" in
            running) ;;
            *) break ;;
        esac
        sleep 1
        elapsed=$((elapsed + 1))
    done
    if [ "$status" = "running" ]; then
        timeout 20 $DOCKER rm -f "$name" > /dev/null 2>&1
        status=$(timeout 10 $DOCKER inspect -f '{{.State.Status}}' "$name" 2>/dev/null)
        if [ "$status" = "running" ]; then
            result=WEDGED
            echo "  WARNING: $name survived docker rm -f; it may block later containers" >&2
        else
            result=TIMEOUT
        fi
    else
        code=$(timeout 10 $DOCKER inspect -f '{{.State.ExitCode}}' "$name" 2>/dev/null)
        timeout 60 $DOCKER logs "$name" > "$OUTDIR/$mod.log" 2>&1
        timeout 20 $DOCKER rm -f "$name" > /dev/null 2>&1
        case "$code" in
            0) result=PASS ;;
            "") result=UNKNOWN ;;
            *) result=FAIL ;;
        esac
    fi
    now=$(date +%s)
    printf '%s %s %s\n' "$mod" "$result" "$((now - start))" >> "$OUTDIR/summary.txt"
    printf '%-34s %-8s %ss\n' "$mod" "$result" "$((now - start))"
done

printf '\n== summary\n'
awk '{c[$2]++} END {for (k in c) printf "%s %d\n", k, c[k]}' "$OUTDIR/summary.txt"
