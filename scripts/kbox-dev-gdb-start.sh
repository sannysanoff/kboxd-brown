#!/bin/sh
# Start the kbox daemon under gdb so the LKL panic (assert -> SIGABRT) is caught
# with thread backtraces. Cores are disabled: guest SIGSEGV dumps would write
# tens of GB onto the mac disk through /work.
set -u
rm -f /work/core /tmp/kboxd-ch.sock /tmp/kboxd-ch.log /tmp/kbox-dockerd-ch.log /tmp/kboxd-gdb.log
cd /work || exit 1
ulimit -c 0
setsid nohup gdb -q -batch \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "handle SIGCHLD nostop noprint pass" \
  -ex "handle SIGPIPE nostop noprint pass" \
  -ex "handle SIGABRT stop print" \
  -ex "run" \
  -ex "echo \n=== SIGABRT CAUGHT ===\n" \
  -ex "bt 25" \
  -ex "thread apply all bt 8" \
  -ex "kill" \
  --args /work/kbox daemon --sock /tmp/kboxd-ch.sock --config /root/.config/kbox-config.yaml ${1:-} \
  >/tmp/kboxd-gdb.log 2>&1 </dev/null &

for i in $(seq 1 300); do [ -S /tmp/kboxd-ch.sock ] && break; sleep 0.1; done
setsid nohup python3 /work/scripts/kbox-dockerd.py --kbox-sock /tmp/kboxd-ch.sock \
  --config /root/.config/kbox-config.yaml --state-dir /dev/shm/kbox-dockerd \
  --listen 0.0.0.0:2376 -v \
  --path-map /Users/san/Fun/tmp/1/kbox:/work \
  --path-map /Users/san/.m2:/var/tmp/ch-m2 >/tmp/kbox-dockerd-ch.log 2>&1 </dev/null &
for i in $(seq 1 300); do grep -q listening /tmp/kbox-dockerd-ch.log 2>/dev/null && break; sleep 0.1; done
tail -2 /tmp/kboxd-gdb.log
tail -1 /tmp/kbox-dockerd-ch.log
