#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end verification of kbox Docker Engine backend using standard
# `docker` CLI + `docker compose` against a `--cap-drop=ALL` kboxd instance.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_PORT="${KBOX_DOCKER_PORT:-2375}"
HTTP_PORT="${KBOX_HTTP_PORT:-18080}"
LOCAL_PORT="$((HTTP_PORT + 1))"
CONT_NAME="kbox-dockerd-e2e-$$"
CTX_NAME="kbox-e2e-$$"
PREV_CTX="$(docker context show 2>/dev/null || echo default)"
WORKDIR="$(mktemp -d "${REPO_ROOT}/.docker-e2e.XXXXXX")"
CONT_WORKDIR="/work/$(basename "$WORKDIR")"
REMOVE_RUNTIME_IMG=0
IMAGE="${KBOX_TEST_IMAGE:-}"
UNIX_SOCK="${CONT_WORKDIR}/docker.sock"

mkdir -p "$WORKDIR/volumes"
# 0777, not the 0700 mktemp default: kboxd here runs as container root under
# --cap-drop=ALL, so guest root has no CAP_DAC_OVERRIDE and cannot traverse or
# write through bits it does not own. In a pod the daemon and the bind sources
# share one uid; this is a property of the harness, not of kbox.
chmod 0777 "$WORKDIR" "$WORKDIR/volumes"
cat > "$WORKDIR/kbox-config.yaml" <<YAML
network:
  start_ip: 172.19.0.10
  gateway: 172.19.0.1
volumes:
  root: ${CONT_WORKDIR}/volumes
YAML

HOST_CTX="${KBOX_HOST_CONTEXT:-orbstack}"
if ! docker context inspect "$HOST_CTX" >/dev/null 2>&1; then
    HOST_CTX="default"
fi

cleanup() {
    rc=$?
    set +e
    if [ "$rc" -ne 0 ]; then
        echo "--- Container logs on failure (rc=$rc) ---" >&2
        docker --context "$HOST_CTX" exec "$CONT_NAME" cat /tmp/kboxd.log 2>/dev/null | tail -n 50 >&2 || true
        docker --context "$HOST_CTX" exec "$CONT_NAME" cat /tmp/dockerd.log 2>/dev/null | tail -n 50 >&2 || true
    fi
    docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" down >/dev/null 2>&1 || true
    docker --context "$HOST_CTX" context rm -f "$CTX_NAME" >/dev/null 2>&1 || true
    docker --context "$HOST_CTX" rm -f "$CONT_NAME" >/dev/null 2>&1 || true
    if [ "$REMOVE_RUNTIME_IMG" -eq 1 ]; then
        docker --context "$HOST_CTX" rmi -f kbox-runtime:e2e >/dev/null 2>&1 || true
    fi
    rm -rf "$WORKDIR"
    exit "$rc"
}
trap cleanup EXIT

if [ ! -x "$REPO_ROOT/kbox" ]; then
    echo "Error: $REPO_ROOT/kbox binary not found; build inside kbox-dev first." >&2
    exit 1
fi

if [ -z "$IMAGE" ]; then
    if docker --context "$HOST_CTX" image inspect kbox-runtime:latest >/dev/null 2>&1; then
        IMAGE="kbox-runtime:latest"
    else
        echo "[0/6] Building minimal kbox-runtime:e2e image (python3 + asan/ubsan + ca-certificates)..."
        docker --context "$HOST_CTX" build -q -t kbox-runtime:e2e - <<'DOCKERFILE' >/dev/null
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    python3 ca-certificates libasan8 libubsan1 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
        IMAGE="kbox-runtime:e2e"
        REMOVE_RUNTIME_IMG=1
    fi
fi

echo "[1/6] Starting single-LKL kbox daemon + kbox-dockerd (--cap-drop=ALL)..."
docker --context "$HOST_CTX" run -d --name "$CONT_NAME" \
    --cap-drop=ALL \
    -p "127.0.0.1:${DOCKER_PORT}:2375" \
    -p "127.0.0.1:${HTTP_PORT}:${HTTP_PORT}" \
    -v "${REPO_ROOT}:/work" \
    "$IMAGE" \
    bash -lc "
        rm -rf /tmp/kboxd-logs /tmp/kbox-dockerd /tmp/kboxd.sock
        /work/kbox daemon --sock /tmp/kboxd.sock --config ${CONT_WORKDIR}/kbox-config.yaml -v >/tmp/kboxd.log 2>&1 &
        for i in \$(seq 1 80); do
            [ -S /tmp/kboxd.sock ] && break
            sleep 0.1
        done
        exec python3 /work/scripts/kbox-dockerd.py \
            --kbox-sock /tmp/kboxd.sock \
            --config ${CONT_WORKDIR}/kbox-config.yaml \
            --listen 0.0.0.0:2375 \
            --unix-socket ${UNIX_SOCK} \
            --path-map \"${REPO_ROOT}:/work\" \
            -v >/tmp/dockerd.log 2>&1
    " >/dev/null

echo "[2/6] Creating Docker context $CTX_NAME..."
docker context create "$CTX_NAME" --docker "host=tcp://127.0.0.1:${DOCKER_PORT}" >/dev/null
for i in $(seq 1 50); do
    if docker --context "$CTX_NAME" info >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
docker --context "$CTX_NAME" version

# The unix socket is what the CLI and Compose reach with NO configuration at
# all, which is the shape a pod uses. python3 is in the runtime image and the
# Docker CLI is not, so probe the socket directly over AF_UNIX.
docker --context "$HOST_CTX" exec "$CONT_NAME" python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect('${UNIX_SOCK}')
s.sendall(b'GET /_ping HTTP/1.1\\r\\nHost: docker\\r\\nConnection: close\\r\\n\\r\\n')
body = s.makefile('rb').read()
s.close()
if b'OK' not in body:
    sys.exit('unix socket did not answer /_ping: %r' % body[:200])
print('unix socket ${UNIX_SOCK} answered /_ping')
" || exit 1

echo "[3/6] Pulling alpine:latest and testing 'docker run' + ':ro' bind mount..."
docker --context "$CTX_NAME" pull alpine:latest
OUT=$(docker --context "$CTX_NAME" run --rm \
    -v "${REPO_ROOT}/scripts:/mnt:ro" \
    alpine:latest sh -c 'hostname && head -n 1 /mnt/kbox-dockerd.py')
echo "$OUT"
echo "$OUT" | grep -q "#!/usr/bin/env python3"

echo "[4/6] Writing two-service docker-compose stack (server + client)..."
mkdir -p "$WORKDIR/www" "$WORKDIR/out"
chmod 0777 "$WORKDIR/www" "$WORKDIR/out"
echo "COMPOSE_E2E_OK" > "$WORKDIR/www/index.html"
cat > "$WORKDIR/compose.yml" <<EOF
services:
  internal:
    image: alpine:latest
    expose:
      - "8080"
    volumes:
      - "${WORKDIR}/www:/srv:ro"
    command:
      - /bin/sh
      - -c
      - |
        printf '#!/bin/sh\nprintf "HTTP/1.1 200 OK\\r\\nContent-Length: 15\\r\\n\\r\\n"\ncat /srv/index.html\n' > /tmp/resp.sh
        while true; do
          nc -l -p 8080 -e /bin/sh /tmp/resp.sh
        done
  server:
    image: alpine:latest
    ports:
      - "0.0.0.0:${HTTP_PORT}:8080"
      - "127.0.0.1:${LOCAL_PORT}:8080"
    volumes:
      - "${WORKDIR}/www:/srv:ro"
      - "dbdata:/var/lib/db"
    command:
      - /bin/sh
      - -c
      - |
        printf '#!/bin/sh\nprintf "HTTP/1.1 200 OK\\r\\nContent-Length: 15\\r\\n\\r\\n"\ncat /srv/index.html\n' > /tmp/resp.sh
        while true; do
          nc -l -p 8080 -e /bin/sh /tmp/resp.sh
        done
  client:
    image: alpine:latest
    depends_on:
      - server
      - internal
    volumes:
      - "${WORKDIR}/out:/out"
    command:
      - /bin/sh
      - -c
      - |
        for i in \$(seq 1 30); do
          if wget -qO /out/got.txt http://server:8080/ 2>/dev/null && \
             wget -qO /out/internal.txt http://internal:8080/ 2>/dev/null; then
            cat /out/got.txt
            break
          fi
          sleep 0.2
        done
        sleep 30
volumes:
  dbdata:
EOF

docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" up -d

echo "[5/6] Verifying /32 config IPs, host port forward, service discovery, exec, logs, and persistent volume..."
BODY=""
for i in $(seq 1 40); do
    BODY=$(curl -fsS --max-time 5 "http://127.0.0.1:${HTTP_PORT}/" 2>/dev/null | tr -d '\r\n' || true)
    [ "$BODY" = "COMPOSE_E2E_OK" ] && break
    sleep 0.2
done
[ "$BODY" = "COMPOSE_E2E_OK" ] || { echo "Host curl failed: '$BODY'" >&2; exit 1; }
echo "Host curl -> $BODY"

for i in $(seq 1 40); do
    [ -s "$WORKDIR/out/got.txt" ] && [ -s "$WORKDIR/out/internal.txt" ] && break
    sleep 0.2
done
[ "$(cat "$WORKDIR/out/got.txt" 2>/dev/null || true)" = "COMPOSE_E2E_OK" ] || {
    echo "Client out failed: '$(cat "$WORKDIR/out/got.txt" 2>/dev/null || true)'" >&2
    docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" logs >&2 || true
    exit 1
}
[ "$(cat "$WORKDIR/out/internal.txt" 2>/dev/null || true)" = "COMPOSE_E2E_OK" ] || {
    echo "Client internal expose out failed: '$(cat "$WORKDIR/out/internal.txt" 2>/dev/null || true)'" >&2
    exit 1
}
echo "Client bind write -> $(cat "$WORKDIR/out/got.txt") (internal -> $(cat "$WORKDIR/out/internal.txt"))"

# Verify 127.0.0.1:LOCAL_PORT is loopback-only and 0.0.0.0:HTTP_PORT is all-IPv4 inside kbox host.
docker --context "$HOST_CTX" exec "$CONT_NAME" python3 -c "
import socket, sys, time
eth0_ip = socket.gethostbyname(socket.gethostname())

# Verify kernel listening sockets in /proc/net/tcp.
want_all = '00000000:%04X' % ${HTTP_PORT}
want_loc = '0100007F:%04X' % ${LOCAL_PORT}
with open('/proc/net/tcp') as f:
    tcp = f.read()
assert want_all in tcp, f'missing {want_all} in /proc/net/tcp'
assert want_loc in tcp, f'missing {want_loc} in /proc/net/tcp'
assert ('00000000:%04X' % ${LOCAL_PORT}) not in tcp, 'LOCAL_PORT bound to 0.0.0.0'

def probe(ip, port):
    for attempt in range(10):
        s = socket.socket()
        s.settimeout(3)
        chunks = []
        try:
            s.connect((ip, port))
            s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            s.shutdown(socket.SHUT_WR)
            while True:
                data = s.recv(1024)
                if not data:
                    break
                chunks.append(data)
                if b'COMPOSE_E2E_OK\n' in b''.join(chunks):
                    break
            body = b''.join(chunks)
            if b'COMPOSE_E2E_OK' in body:
                return body
        except ConnectionResetError:
            pass
        finally:
            s.close()
        time.sleep(0.1)
    return b''

assert b'COMPOSE_E2E_OK' in probe('127.0.0.1', ${HTTP_PORT})
assert b'COMPOSE_E2E_OK' in probe(eth0_ip, ${HTTP_PORT})
assert b'COMPOSE_E2E_OK' in probe('127.0.0.1', ${LOCAL_PORT})
try:
    probe(eth0_ip, ${LOCAL_PORT})
    sys.exit('ERROR: 127.0.0.1-bound port accepted connection on ' + eth0_ip)
except OSError:
    pass
print('Host bind verification OK (0.0.0.0:' + str(${HTTP_PORT}) + ', 127.0.0.1:' + str(${LOCAL_PORT}) + ', expose-only internal)')
"

SRV_ETH0=$(docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" exec -T server sh -c 'ip -4 addr')
echo "server eth0:"
echo "$SRV_ETH0"
echo "$SRV_ETH0" | grep -qE "172\.19\.0\.[0-9]+/32"

SRV_HOST=$(docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" exec -T server hostname)
CLI_EXEC=$(docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" exec -T client sh -c 'hostname && wget -qO- http://server:8080/')
echo "server hostname via exec: $SRV_HOST"
echo "client exec result:"
echo "$CLI_EXEC"
echo "$CLI_EXEC" | grep -q "COMPOSE_E2E_OK"
[ "$SRV_HOST" != "$(echo "$CLI_EXEC" | head -n 1)" ]

docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" logs --tail 5 client | grep -q "COMPOSE_E2E_OK"

# Verify persistent named volume across Compose restart (down + up -d).
docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" exec -T server sh -c 'echo PERSISTENT_DB_OK > /var/lib/db/state.txt'
docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" down
docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" up -d
DB_STATE=$(docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" exec -T server cat /var/lib/db/state.txt)
echo "Persisted DB volume after compose down+up -> $DB_STATE"
[ "$DB_STATE" = "PERSISTENT_DB_OK" ]

echo "[6/6] Tearing down Compose stack..."
docker --context "$CTX_NAME" compose -f "$WORKDIR/compose.yml" down
echo "PASS: kbox Docker Engine E2E passed!"
