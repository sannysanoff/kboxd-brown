#!/usr/bin/env python3
"""kbox process control inside kbox-dev.

Safety: patterns are matched against /proc/<pid>/cmdline and our own pid and
parent are excluded, so a shell command line that merely *mentions* the
pattern can never kill itself.
"""
import os
import signal
import sys
import time

PATTERNS = [
    "/work/kbox daemon",
    "kbox-dockerd.py",
    "kbox-dev-bridge.py",
    "clickhouse-server",
]


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def matches():
    me = os.getpid()
    parent = os.getppid()
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid in (me, parent):
            continue
        cl = cmdline(pid)
        if not cl:
            continue
        if any(p in cl for p in PATTERNS):
            out.append((pid, cl.strip()))
    return out


def stop():
    for sig in (signal.SIGTERM, signal.SIGKILL):
        found = matches()
        if not found:
            break
        for pid, cl in found:
            try:
                os.kill(pid, sig)
                print(f"kill -{int(sig)} {pid} {cl[:90]}")
            except OSError as e:
                print(f"kill {pid} failed: {e}")
        time.sleep(1.5)
    left = matches()
    print(f"leftover: {len(left)}")
    return 0 if not left else 1


def status():
    for pid, cl in matches():
        print(pid, cl[:110])
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    sys.exit(stop() if cmd == "stop" else status())
