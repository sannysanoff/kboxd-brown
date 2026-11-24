#!/bin/sh
# Does the redis binary the guest built actually serve requests?
#
# The guest build finishes, then the tree's runtest stalls after 121 [ok] with
# no server process (item 31). This separates the two: build the same way the
# harness does, start the built server by hand and ask it to PING and to store
# and return a key.
#
# Usage, from the volume the pod already has staged:
#   docker run --rm -v /data/vol:/vol alpine:3.21 \
#       sh /vol/three/redis-serve.sh
#
# Writes /vol/results/redis-serve.log.
exec > /vol/results/redis-serve.log 2>&1

apk update >> /vol/results/redis-serve-apk.log 2>&1
for pkg in build-base make linux-headers; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/redis-serve-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

mkdir -p /data
cd /data || exit 1
tar xzf /vol/cache/redis-7.4.2.tar.gz || exit 1
cd redis-7.4.2 || exit 1

make -j1 MALLOC=libc OPTIMIZATION="-O3 -flto=1" > /data/redis-build.log 2>&1
echo "build rc=$?"
tail -3 /data/redis-build.log
./src/redis-server --version

echo "=== start the built server"
./src/redis-server --port 7777 --save '' --appendonly no --dir /tmp \
    --logfile /tmp/redis-server.log --daemonize yes
echo "start rc=$?"
sleep 2
ps -o pid,args 2>/dev/null | grep redis-server | head -2

echo "=== ping and a round trip"
./src/redis-cli -p 7777 ping
./src/redis-cli -p 7777 set kbox v159
./src/redis-cli -p 7777 get kbox
./src/redis-cli -p 7777 incr counter
./src/redis-cli -p 7777 dbsize

echo "=== server log tail"
tail -5 /tmp/redis-server.log

./src/redis-cli -p 7777 shutdown nosave
echo "shutdown rc=$?"
echo done
