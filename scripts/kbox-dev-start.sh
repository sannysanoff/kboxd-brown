#!/bin/sh
# Start kbox daemon + Docker shim inside kbox-dev (no gdb).
# Cores are enabled for the daemon only: guest cores are disabled in code.
# Usage: kbox-dev-start.sh [daemon-args...]
set -u
rm -f /work/core /tmp/kboxd-ch.sock /tmp/kboxd-ch.log /tmp/kbox-dockerd-ch.log
cd /work || exit 1
ulimit -c unlimited
setsid nohup /work/kbox daemon --sock /tmp/kboxd-ch.sock --config /root/.config/kbox-config.yaml "$@" \
  >/tmp/kboxd-ch.log 2>&1 </dev/null &
for i in $(seq 1 300); do [ -S /tmp/kboxd-ch.sock ] && break; sleep 0.1; done
# Make sure the daemon can dump core on an LKL panic, whatever the caller's
# soft limit was (dash `ulimit -c` in a nested shell does not always stick).
dpid=$(pgrep -f "/work/kbox daemo[n]" | head -1)
[ -n "$dpid" ] && prlimit --core=unlimited:unlimited --pid "$dpid" 2>/dev/null
setsid nohup python3 /work/scripts/kbox-dockerd.py --kbox-sock /tmp/kboxd-ch.sock \
  --config /root/.config/kbox-config.yaml --state-dir /dev/shm/kbox-dockerd \
  --listen 0.0.0.0:2376 \
  --path-map /Users/san/Fun/tmp/1/kbox:/work \
  --path-map /Users/san/.m2:/var/tmp/ch-m2 >/tmp/kbox-dockerd-ch.log 2>&1 </dev/null &
for i in $(seq 1 300); do grep -q listening /tmp/kbox-dockerd-ch.log 2>/dev/null && break; sleep 0.1; done
tail -1 /tmp/kboxd-ch.log
tail -1 /tmp/kbox-dockerd-ch.log
