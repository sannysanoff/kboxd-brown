#!/bin/sh
# SPDX-License-Identifier: MIT
# Deploy kbox to the kbox-sqlite namespace and drive the sqllogictest corpus.
#
# Usage:
#   ./scripts/run-sqllogictest-pod.sh deploy
#   ./scripts/run-sqllogictest-pod.sh push
#   ./scripts/run-sqllogictest-pod.sh run [driver options]
#   ./scripts/run-sqllogictest-pod.sh start [driver options]
#   ./scripts/run-sqllogictest-pod.sh status
#   ./scripts/run-sqllogictest-pod.sh collect OUTDIR
#
# Environment:
#   NS        namespace (default: kbox-sqlite)
#   IMAGE     pod image (default: the tag in deploy/sqlite/kbox.yaml)
#   SLT_DIR   corpus directory on this machine (default: build/sqllogictest)
#   RESULTS   pod results directory (default: /data/slt/results)
#   CMD       kubectl command prefix (default: kubectl)

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

NS="${NS:-kbox-sqlite}"
SLT_DIR="${SLT_DIR:-build/sqllogictest}"
CMD="${CMD:-kubectl}"
MANIFEST="deploy/sqlite/kbox.yaml"
POD_ROOT="/data/slt"
RESULTS="${RESULTS:-${POD_ROOT}/results}"

IMAGE="${IMAGE:-$(awk '/image: kbox-sqlite/ {print $2; exit}' "$MANIFEST")}"

pod_exec()
{
    $CMD -n "$NS" exec deploy/kbox -c shim -- "$@"
}

command="${1:-}"
[ -n "$command" ] || die "usage: $0 deploy|push|run|start|status|collect"

case "$command" in
deploy)
    [ -x kbox ] || die "kbox binary missing; run make BUILD=release first"
    [ -f scripts/kbox-dockerd.py ] || die "shim missing"

    echo "  BUILD   ${IMAGE}"
    rm -rf .deploy-image
    mkdir .deploy-image
    cp deploy/sqlite/Dockerfile .deploy-image/Dockerfile
    cp kbox .deploy-image/kbox
    cp scripts/kbox-dockerd.py .deploy-image/kbox-dockerd.py
    cp scripts/slt-pod-driver.py .deploy-image/slt-pod-driver.py
    docker build -q -t "$IMAGE" .deploy-image
    rm -rf .deploy-image

    $CMD get ns "$NS" > /dev/null 2>&1 || $CMD create ns "$NS"
    $CMD apply -f "$MANIFEST"
    $CMD -n "$NS" set image deploy/kbox "kboxd=$IMAGE" "shim=$IMAGE" > /dev/null
    $CMD -n "$NS" rollout status deploy/kbox --timeout=300s
    $CMD -n "$NS" get pods -l app=kbox
    ;;

push)
    [ -x "${SLT_DIR}/sqllogictest" ] || die "run scripts/fetch-sqllogictest.sh first"
    [ -d "${SLT_DIR}/test" ] || die "corpus missing under ${SLT_DIR}/test"

    echo "  PUSH    corpus -> ${NS}:${POD_ROOT}"
    # bsdtar writes an AppleDouble ._name sidecar for each file from a macOS
    # source, which doubles the corpus file count in the pod.
    COPYFILE_DISABLE=1 tar -C "$SLT_DIR" -czf - sqllogictest test |
        $CMD -n "$NS" exec -i deploy/kbox -c shim -- \
            sh -c "mkdir -p ${POD_ROOT} ${RESULTS} && tar -C ${POD_ROOT} -xzf - && \
                find ${POD_ROOT} -name '._*' -delete"
    pod_exec find "${POD_ROOT}/test" -name '*.test' | wc -l | tr -d ' '
    echo "  files in pod"
    ;;

run)
    shift
    pod_exec python3 /usr/local/bin/slt-pod-driver.py "$@"
    ;;

start)
    shift
    pod_exec sh -c "nohup python3 /usr/local/bin/slt-pod-driver.py $* \
        >> ${RESULTS}/driver.log 2>&1 & echo started"
    ;;

status)
    pod_exec sh -c "cat ${RESULTS}/progress.txt 2>/dev/null; \
        echo '--- last results ---'; \
        tail -n 8 ${RESULTS}/summary.tsv 2>/dev/null; \
        echo '--- driver ---'; tail -n 5 ${RESULTS}/driver.log 2>/dev/null"
    ;;

collect)
    outdir="${2:-slt-results}"
    mkdir -p "$outdir"
    $CMD -n "$NS" exec deploy/kbox -c shim -- \
        tar -C "${RESULTS}" -czf - . | tar -C "$outdir" -xzf -
    echo "results in $outdir"
    ;;

*)
    die "unknown command: $command"
    ;;
esac
