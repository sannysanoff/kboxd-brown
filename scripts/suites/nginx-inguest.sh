#!/bin/sh
# Does a real project build inside the guest, on the internal filesystem?
#
# Section 14 of the report claims nginx configured and built inside the guest on
# image v159. This repeats the build on the image that is running now, from the
# source tarball, with the tree under /data (the internal filesystem), and then
# starts the binary the guest just built and asks it for a page.
#
# The build is serial by default so a run matches the earlier measurements. A
# parallel make itself works: item 28 is fixed, and BUILD_JOBS overrides the job
# count. The lost pipe that used to make a long build unsafe is item 33, fixed on
# image v185; redis's tree builds at -j2 with it.
#
# Usage, with the source tarball staged at /vol/cache/nginx-1.26.3.tar.gz:
#   docker run --rm -v /data/vol:/vol alpine:3.21 sh /vol/three/nginx-inguest.sh
#
# Writes /vol/results/nginx-inguest.log.
exec > /vol/results/nginx-inguest.log 2>&1

apk update > /vol/results/nginx-inguest-apk.log 2>&1
for pkg in build-base pcre-dev zlib-dev openssl-dev linux-headers curl tar; do
    attempt=1
    while :; do
        apk add --no-cache --repository /vol/apk-repo --allow-untrusted "$pkg" \
            >> /vol/results/nginx-inguest-apk.log 2>&1 && break
        [ "$attempt" -ge 4 ] && { echo "apk $pkg failed"; exit 1; }
        attempt=$((attempt + 1)); sleep 2
    done
done

V=1.26.3
JOBS="${BUILD_JOBS:-1}"
SRC=/data/nginx-inguest
rm -rf "$SRC"
mkdir -p "$SRC"
cd "$SRC" || exit 1

echo "=== source"
cp /vol/cache/nginx-$V.tar.gz . || exit 3
tar xzf nginx-$V.tar.gz || exit 3
echo "tree at $SRC/nginx-$V"
echo "files: $(find "nginx-$V" -type f | wc -l)"

cd "nginx-$V" || exit 1

echo
echo "=== configure"
./configure \
    --prefix="$SRC/prefix" \
    --with-http_ssl_module \
    --with-http_v2_module \
    > "$SRC/configure.log" 2>&1
echo "configure rc=$?"
tail -3 "$SRC/configure.log"

echo
echo "=== make -j$JOBS"
start=$(date +%s)
make -j"$JOBS" > "$SRC/make.log" 2>&1
rc=$?
end=$(date +%s)
echo "make rc=$rc seconds=$((end - start))"
echo "compilations: $(grep -c 'cc -c' "$SRC/make.log")"
echo "objects on the internal filesystem: $(find . -name '*.o' | wc -l)"
[ "$rc" -eq 0 ] || { tail -30 "$SRC/make.log"; exit 4; }

echo
echo "=== make install"
make install >> "$SRC/make.log" 2>&1
echo "install rc=$?"

NGX="$SRC/prefix/sbin/nginx"
echo
echo "=== the binary the guest built"
ls -l "$NGX"
"$NGX" -V 2>&1 | head -3

echo
echo "=== serve one request from it"
WWW="$SRC/www"
RUN="$SRC/run"
mkdir -p "$WWW" "$RUN/conf" "$RUN/logs" "$RUN/tmp"
printf 'built-in-the-guest\n' > "$WWW/index.html"
cat > "$RUN/conf/nginx.conf" <<EOF
worker_processes 1;
error_log $RUN/logs/error.log;
pid $RUN/nginx.pid;
events { worker_connections 64; }
http {
    access_log $RUN/logs/access.log;
    client_body_temp_path $RUN/tmp;
    server {
        listen 127.0.0.1:18080;
        location / { root $WWW; }
    }
}
EOF
"$NGX" -p "$RUN" -c "$RUN/conf/nginx.conf" 2>> "$SRC/serve.log"
echo "start rc=$?"
i=0
while [ $i -lt 20 ]; do
    if curl -sS --max-time 2 http://127.0.0.1:18080/ > "$SRC/body.txt" 2>> "$SRC/serve.log"; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
echo "body: [$(cat "$SRC/body.txt" 2>/dev/null)]"
"$NGX" -p "$RUN" -c "$RUN/conf/nginx.conf" -s stop 2>> "$SRC/serve.log"
echo "stop rc=$?"

echo
echo "=== sha of the guest-built binary"
md5sum "$NGX"
echo done
