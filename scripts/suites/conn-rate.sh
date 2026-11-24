#!/bin/sh
# Measure how often a guest loopback TCP connect completes.
#
# The MariaDB TLS tests failed intermittently with
#   Lost connection to server at 'handshake: reading initial communication
#   packet', system error: 115
# and this loop is the reproducer: one client process per iteration, connecting
# to a server that runs in the same guest, over the transports the tests use.
#
# Before the fix (commit c9afe16) a plain loopback connect completed only 126 of
# 200 times while plain Docker completed 200 of 200, TLS and pacing made no
# difference, and the unix socket (a host-fd passthrough, not a bridged TCP
# socket) was always fine. After the fix all four shapes complete 200 of 200.
#
# Usage, from the volume the pod already has staged:
#   docker run --rm -e N=200 -v /data/vol:/vol alpine:3.21 \
#       sh /vol/three/conn-rate.sh
#
# The script needs /vol/apk-repo (see scripts/suites/mariadb.sh for how that is
# staged) and writes /vol/results/conn-rate.log.
exec > /vol/results/conn-rate.log 2>&1

N="${N:-200}"
VAR=/vol/mtr-rate
OUT=/vol/results/conn-rate
rm -rf "$VAR"; mkdir -p "$OUT"

apk update >> "$OUT/apk.log" 2>&1
for pkg in perl patch mariadb-common mariadb-client mariadb mariadb-test; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> "$OUT/apk.log" 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1))
        sleep 2
    done
done

# The distribution ships neither of these two, and mtr's own tests call them.
for t in mariadb-upgrade perror; do
    [ -x "/usr/bin/$t" ] || {
        printf '#!/bin/sh\necho "%s: not provided by this distribution" >&2\nexit 1\n' "$t" > "/usr/bin/$t"
        chmod 755 "/usr/bin/$t"
    }
done
[ -d /usr/mariadb-test ] && [ ! -e /usr/mysql-test ] && mv /usr/mariadb-test /usr/mysql-test

# A server started by mtr itself, so the client speaks to exactly the server
# configuration the failing tests use.
cd /usr/mysql-test || exit 1
MTR_BINDIR=/usr perl mariadb-test-run.pl --vardir="$VAR" --suite=main \
    --do-test=1st --start-and-exit \
    --mysqld=--loose-innodb-use-native-aio=0 \
    --mysqld=--slave-load-tmpdir="$VAR/tmp" > "$OUT/start.log" 2>&1
rc=$?
echo "start exit=$rc"
[ "$rc" -eq 0 ] || { tail -6 "$OUT/start.log"; exit 1; }

CNF="$VAR/my.cnf"
i=0
while [ $i -lt 60 ]; do
    mariadb --defaults-file="$CNF" -e 'select 1' >/dev/null 2>&1 && break
    i=$((i + 1)); sleep 1
done
echo "server reachable after ${i}s"

count_shape() {
    label=$1; pace=$2; shift 2
    ok=0; lost=0; refused=0; other=0
    : > "$OUT/$label.seq"
    : > "$OUT/$label.errors"
    n=0
    while [ $n -lt "$N" ]; do
        mariadb --defaults-file="$CNF" "$@" -e 'select 1' > "$OUT/$label.out" 2>&1
        rc=$?
        if [ $rc -eq 0 ]; then
            ok=$((ok + 1)); printf '.' >> "$OUT/$label.seq"
        elif grep -qa "system error: 115" "$OUT/$label.out"; then
            lost=$((lost + 1)); printf 'X' >> "$OUT/$label.seq"
            head -1 "$OUT/$label.out" >> "$OUT/$label.errors"
        elif grep -qa "Can't connect" "$OUT/$label.out"; then
            refused=$((refused + 1)); printf 'R' >> "$OUT/$label.seq"
            head -1 "$OUT/$label.out" >> "$OUT/$label.errors"
        else
            other=$((other + 1)); printf '?' >> "$OUT/$label.seq"
            head -1 "$OUT/$label.out" >> "$OUT/$label.errors"
        fi
        n=$((n + 1))
        [ "$pace" != "0" ] && sleep "$pace"
    done
    echo "$label: n=$N ok=$ok lost115=$lost refused=$refused other=$other"
    echo "sequence: $(fold -w 100 < "$OUT/$label.seq" | tr '\n' ' ')"
    sort "$OUT/$label.errors" 2>/dev/null | uniq -c | sort -rn | head -3
    echo "server connections logged: $(grep -ac 'Connect.*on ' "$VAR/mysqld.1/mysqld.log" 2>/dev/null)"
}

echo "=== plain TCP, TLS off (client paces itself)"
count_shape tcp-noTLS 0 --protocol tcp -u root --skip-ssl
echo "=== plain TCP, TLS on"
count_shape tcp-tls 0 --protocol tcp -u root
echo "=== plain TCP, TLS off, 100 ms between iterations"
count_shape tcp-noTLS-slow 0.1 --protocol tcp -u root --skip-ssl
echo "=== unix socket"
count_shape unix 0 --socket="$VAR/tmp/mysqld.1.sock" -u root

PIDF=$(ls "$VAR"/mysqld.1/mysqld.pid 2>/dev/null | head -1)
[ -n "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null
echo done
