#!/bin/sh
# Does a command substitution still lose its pipe?
#
# Every pipeline a shell builds is a pipe(), and pipe() used to be answered
# through a seccomp notification. When a signal reached the tracee before the
# supervisor received that notification the kernel abandoned the wait, and the
# guest got EINTR from a call a real kernel never fails. A 3000-round loop of
# "echo | tr | awk" lost 81 to 113 of them on a build, and jemalloc's configure
# then produced a truncated header from a missing line (item 33 in
# three-suites-report.md).
#
# pipe() and pipe2() now run in the kernel, so this counts the same losses. Any
# non-zero count, or any "Interrupted system call" in the log, is the defect.
#
# The last step generates the header that failed before, so the measurement is
# not only the loop.
#
# Results: /vol/results/pipe-eintr.log
exec > /vol/results/pipe-eintr.log 2>&1

apk update >> /vol/results/pipe-eintr-apk.log 2>&1
apk add --no-cache --repository /vol/apk-repo --allow-untrusted build-base make \
    >> /vol/results/pipe-eintr-apk.log 2>&1

rounds=${ROUNDS:-3000}
V=5.3.0-0-g0

echo "=== echo | tr | awk"
i=0
bad=0
while [ "$i" -lt "$rounds" ]; do
    got=`echo "$V" | tr ".g-" " " | awk '{print $2}'`
    if [ "$got" != "3" ]; then
        bad=$((bad + 1))
        [ "$bad" -le 5 ] && echo "round $i: awk=[$got]"
    fi
    i=$((i + 1))
done
echo "awk rounds=$rounds bad=$bad"

echo
echo "=== echo | tr"
i=0
bad=0
while [ "$i" -lt "$rounds" ]; do
    out=`echo "$V" | tr ".g-" " "`
    # "5.3.0-0-g0" with '.', '-' and 'g' replaced by spaces is ten characters.
    [ "${#out}" != "10" ] && {
        bad=$((bad + 1))
        [ "$bad" -le 5 ] && echo "round $i: tr=[$out] len=${#out}"
    }
    i=$((i + 1))
done
echo "tr rounds=$rounds bad=$bad"

echo
echo "=== jemalloc configure"
mkdir -p /data
cd /data || exit 1
rm -rf redis-7.4.2
tar xzf /vol/cache/redis-7.4.2.tar.gz || exit 1
cd redis-7.4.2/deps/jemalloc || exit 1
./configure --disable-cxx --with-version=5.3.0-0-g0 --with-lg-quantum=3 \
    --disable-cache-oblivious --with-jemalloc-prefix=je_ \
    > /data/jem-conf.log 2>&1
conf_rc=$?
H=include/jemalloc/jemalloc.h
echo "configure rc=$conf_rc bytes=$(wc -c < $H) lines=$(wc -l < $H)"
echo "last line: $(tail -1 $H)"
echo "usable-size const defs: $(grep -ac 'define JEMALLOC_USABLE_SIZE_CONST' $H)"
echo "define count: $(grep -ac '^#define' $H)"
echo "version line: $(grep -a 'JEMALLOC_VERSION ' $H)"

echo
echo "interrupted lines: $(grep -ac 'Interrupted system call' /vol/results/pipe-eintr.log)"
if [ "$bad" -eq 0 ] && [ "$conf_rc" -eq 0 ]; then
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL"
fi
echo done
