#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Expose a kbox Docker Engine API socket to macOS through OrbStack.

OrbStack only forwards ports that were published when the container was
created, so a container port such as the shim's 2376 is unreachable from the
mac even though it listens inside the Linux container.  This proxy listens on
127.0.0.1:<listen-port> on the mac and, for every connection, opens one
``docker exec -i`` stream into the container that speaks to the shim socket.

Usage:
    scripts/kbox-dev-proxy.py [--container kbox-dev] [--shim-addr 127.0.0.1:2376]
                              [--listen 127.0.0.1:2376]

Then point the client at it:
    DOCKER_HOST=tcp://127.0.0.1:2376 docker compose ...
"""

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import threading

BRIDGE = '''\
import socket, select, os
host, _, port = {shim_addr!r}.rpartition(":")
sock = socket.create_connection((host, int(port)))
sock.setblocking(False)
os.set_blocking(0, False)
os.set_blocking(1, False)
eof_in = False
while True:
    rl = [sock] + ([] if eof_in else [0])
    rd, _, _ = select.select(rl, [], [], 30)
    if not rd:
        continue
    if 0 in rd:
        data = os.read(0, 65536)
        if data == b"":
            sock.shutdown(socket.SHUT_WR)
            eof_in = True
        else:
            sock.sendall(data)
    if sock in rd:
        data = sock.recv(65536)
        if not data:
            break
        os.write(1, data)
'''

BRIDGE_PATH = "/tmp/kbox-dev-bridge.py"


def build_bridge(container, shim_addr):
    src = BRIDGE.format(shim_addr=shim_addr)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write(src)
        path = tmp.name
    subprocess.run(
        ["docker", "cp", path, f"{container}:{BRIDGE_PATH}"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    os.unlink(path)


def pump_conn_to_proc(conn, proc):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            proc.stdin.write(data)
            proc.stdin.flush()
    except (OSError, ValueError):
        pass
    finally:
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass


def pump_proc_to_conn(proc, conn):
    try:
        while True:
            data = proc.stdout.read1(65536)
            if not data:
                break
            conn.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_connection(conn, container):
    proc = subprocess.Popen(
        ["docker", "exec", "-i", container, "python3", "-u", BRIDGE_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    threading.Thread(
        target=pump_conn_to_proc, args=(conn, proc), daemon=True
    ).start()
    pump_proc_to_conn(proc, conn)
    proc.wait()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default=os.environ.get("KBOX_DEV_CONTAINER", "kbox-dev"))
    ap.add_argument("--shim-addr", default=os.environ.get("KBOX_SHIM_ADDR", "127.0.0.1:2376"))
    ap.add_argument("--listen", default="127.0.0.1:2376")
    args = ap.parse_args()

    host, _, port = args.listen.rpartition(":")
    build_bridge(args.container, args.shim_addr)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(64)
    sys.stderr.write(f"proxy {host}:{port} -> {args.container}:{args.shim_addr}\n")
    sys.stderr.flush()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve_connection, args=(conn, args.container), daemon=True).start()


if __name__ == "__main__":
    main()
