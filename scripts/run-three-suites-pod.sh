#!/bin/sh
# One command to run the three suites in the kbox pod.
#
#   scripts/run-three-suites-pod.sh [suite ...]
#
# Suites default to "mariadb redis nginx". Each suite runs in its own
# container, started through the Docker shim that fronts the kbox daemon, with
# an external timeout so a hung guest cannot hold the run. Full logs stay on
# the pod's volume under /data/results/<suite>/ and are copied to
# ./artifacts/<suite>/ when the run ends.
#
# The script never runs plain Docker: the point is what kbox does, and a
# plain-Docker number would answer a different question.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NS="${KBOX_NS:-kbox-three-suites}"
MANIFEST="${KBOX_MANIFEST:-$ROOT/deploy/three-suites/kbox.yaml}"
GUEST_IMAGE="${KBOX_GUEST_IMAGE:-alpine:3.21}"
VOLUME="${KBOX_VOLUME:-/data/vol}"      # pod-side path mounted as /vol
ARTIFACTS="${KBOX_ARTIFACTS:-$ROOT/artifacts}"
SUITE_TIMEOUT="${SUITE_TIMEOUT:-7200}"  # seconds per suite
PORT="${KBOX_DOCKER_PORT:-23776}"

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- cluster ---

command -v kubectl >/dev/null 2>&1 || die "kubectl not found"

say "=== apply $MANIFEST"
kubectl apply -f "$MANIFEST" >/dev/null

say "=== wait for the pod"
i=0
while :; do
    pod=$(kubectl -n "$NS" get pods \
        --sort-by=.metadata.creationTimestamp -o name 2>/dev/null |
        tail -1 | sed 's|pod/||')
    if [ -n "${pod:-}" ]; then
        state=$(kubectl -n "$NS" get "pod/$pod" \
            -o jsonpath='{.status.phase} {.status.containerStatuses[*].ready}' \
            2>/dev/null || true)
        case "$state" in
            *"Running true true"*) break ;;
        esac
    fi
    i=$((i + 1))
    [ "$i" -lt 90 ] || die "pod never became ready"
    sleep 4
done
say "pod=$pod"

# ------------------------------------------------------------- port-forward -

pkill -f "port-forward.*:$PORT" 2>/dev/null || true
sleep 1
kubectl -n "$NS" port-forward "pod/$pod" "$PORT:2376" >/dev/null 2>&1 &
PF_PID=$!
cleanup() { kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

i=0
while :; do
    if DOCKER_HOST="tcp://127.0.0.1:$PORT" docker version >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    [ "$i" -lt 40 ] || die "shim never answered on 127.0.0.1:$PORT"
    sleep 1
done
say "shim reachable on 127.0.0.1:$PORT"

# ------------------------------------------------------------------ helpers -

shim_exec() { kubectl -n "$NS" exec "$pod" -c kboxd -- sh -c "$1"; }

prepare_volume() {
    shim_exec "mkdir -p $VOLUME/three $VOLUME/cache $VOLUME/results &&
               chmod 777 $VOLUME $VOLUME/three $VOLUME/cache $VOLUME/results"
}

copy_in() {  # copy_in LOCAL REMOTE
    kubectl -n "$NS" cp "$1" "$pod:$2" -c kboxd >/dev/null
    shim_exec "chmod 777 $2"
}

# run_suite NAME SCRIPT
run_suite() {
    name=$1
    script=$2
    say "=== suite: $name"
    copy_in "$script" "$VOLUME/three/suite-$name.sh"
    shim_exec "rm -rf $VOLUME/results/$name; mkdir -p $VOLUME/results/$name;
               chmod 777 $VOLUME/results/$name"

    DOCKER_HOST="tcp://127.0.0.1:$PORT" docker rm -f "suite-$name" \
        >/dev/null 2>&1 || true

    start=$(date +%s)
    if ! DOCKER_HOST="tcp://127.0.0.1:$PORT" docker run -d \
        --name "suite-$name" -v "$VOLUME:/vol" "$GUEST_IMAGE" \
        sh "/vol/three/suite-$name.sh" >/dev/null; then
        say "suite $name: container did not start"
        return 1
    fi

    # External timeout: a hung guest must not hold the whole run.
    i=0
    status=""
    while [ "$i" -lt "$SUITE_TIMEOUT" ]; do
        running=$(DOCKER_HOST="tcp://127.0.0.1:$PORT" docker inspect \
            -f '{{.State.Running}}' "suite-$name" 2>/dev/null || echo unknown)
        if [ "$running" != "true" ]; then
            status=$running
            break
        fi
        i=$((i + 5))
        sleep 5
    done
    elapsed=$(($(date +%s) - start))

    if [ -z "$status" ]; then
        say "suite $name: TIMEOUT after ${elapsed}s, stopping the container"
        DOCKER_HOST="tcp://127.0.0.1:$PORT" docker kill "suite-$name" \
            >/dev/null 2>&1 || true
        rc=124
    else
        rc=$(DOCKER_HOST="tcp://127.0.0.1:$PORT" docker inspect \
            -f '{{.State.ExitCode}}' "suite-$name" 2>/dev/null || echo 1)
    fi
    say "suite $name: exit=$rc in ${elapsed}s"

    # Copy the results out; a failure here must not hide the suite result.
    mkdir -p "$ARTIFACTS/$name"
    shim_exec "tar cf - -C $VOLUME/results/$name ." 2>/dev/null |
        tar xf - -C "$ARTIFACTS/$name" 2>/dev/null || \
        say "suite $name: could not copy results"
    DOCKER_HOST="tcp://127.0.0.1:$PORT" docker rm -f "suite-$name" \
        >/dev/null 2>&1 || true
    [ "$rc" = "0" ]
}

# --------------------------------------------------------------------- main -

SUITES=${*:-"mariadb redis nginx"}
prepare_volume

overall=0
printf '\n'
printf '%-10s %-8s %s\n' suite exit artifact
for s in $SUITES; do
    script="$HERE/suites/$s.sh"
    [ -f "$script" ] || { say "no harness for $s"; overall=1; continue; }
    if run_suite "$s" "$script"; then
        rc=0
    else
        rc=1
        overall=1
    fi
    printf '%-10s %-8s %s\n' "$s" "$rc" "$ARTIFACTS/$s"
done

say ""
say "results in $ARTIFACTS"
exit "$overall"
