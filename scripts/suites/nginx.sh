#!/bin/sh
# nginx 1.26.3: build from source, then exercise a configuration matrix and
# run h2spec against every HTTP/2-capable configuration.
#
# Runs inside the guest, driven by scripts/run-three-suites-pod.sh.
# Results land on the mounted volume:
#   /data/results/nginx/build.log       configure + make output
#   /data/results/nginx/matrix.log      one line per configuration
#   /data/results/nginx/h2spec-*.log    full h2spec output per h2 config
#   /data/results/nginx/counts.txt      totals
#
# A configuration passes when every check in it returns the expected status and
# body, and, for an HTTP/2 configuration, h2spec reports zero failures. nginx's
# own exit status only says whether the daemon started, so it is not the
# verdict.
set -u

OUT=/vol/results/nginx
SRC=/data/nginx
V="${NGINX_VERSION:-1.26.3}"
# A parallel make works: make -j2 and make -j4 build this tree (item 28 in
# three-suites-report.md). The tree is still built with one job because of a
# separate defect: the kernel abandons a seccomp notification when a signal
# arrives for the tracee, so pipe() returns EINTR to the guest while make is
# compiling and reaping children. BUILD_JOBS overrides the job count.
JOBS="${BUILD_JOBS:-1}"
H2SPEC_VERSION="${H2SPEC_VERSION:-2.6.0}"
mkdir -p "$OUT" "$SRC"

echo "=== install"
# A local package repository can be staged on the volume (/vol/apk-repo,
# built with `apk fetch --recursive` then `apk index`). The guest's HTTPS
# stream occasionally stalls inside kbox's socket pump, and installing from
# the volume keeps a run reproducible; the network stays the default when no
# repository is present.
APK_REPO=""
# apk reads a repository whose packages sit in an <arch>/ subdirectory as one
# whose index is <repo>/<arch>/APKINDEX.tar.gz. A flat repository (index at the
# top) is also accepted. Both layouts are staged in different runs, so both are
# recognised here.
if [ -f /vol/apk-repo/APKINDEX.tar.gz ] ||
    [ -f /vol/apk-repo/aarch64/APKINDEX.tar.gz ]; then
    APK_REPO="--repository /vol/apk-repo --allow-untrusted"
    echo "using local package repository /vol/apk-repo"
fi
# apk streams packages from HTTPS into the extractor, and that read side has
# failed transiently before succeeding on retry, so a bounded retry keeps a
# network hiccup from failing the run.
attempt=1
while :; do
    # shellcheck disable=SC2086
    apk add --no-cache $APK_REPO build-base pcre-dev zlib-dev \
        openssl openssl-dev linux-headers curl tar > "$OUT/apk.log" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && break
    [ "$attempt" -ge 3 ] && break
    attempt=$((attempt + 1))
    echo "retrying apk after failure (attempt $attempt)" >> "$OUT/apk.log"
    sleep 3
done
echo "apk exit=$rc attempts=$attempt"
[ "$rc" -eq 0 ] || exit "$rc"

# A prebuilt install tree on the volume lets the configuration matrix and
# h2spec run without a guest build. The guest builds the tree itself by
# default, which is the normal path since the linker learned to read object
# files from the internal filesystem (image v159). With the prebuilt switch the
# source tarball is not needed at all.
PREBUILT=0
if [ "${NGINX_PREBUILT:-0}" = "1" ] &&
   [ -x /vol/cache/nginx-prefix/sbin/nginx ]; then
    PREBUILT=1
fi

echo "=== fetch"
cd "$SRC" || exit 1
if [ "$PREBUILT" = 0 ] && [ ! -d "nginx-$V" ]; then
    CACHE="/vol/cache/nginx-$V.tar.gz"
    if [ -f "$CACHE" ]; then
        echo "using cached $CACHE"
        cp "$CACHE" nginx.tar.gz || exit 3
    else
        curl -sSfL --retry 3 "https://nginx.org/download/nginx-$V.tar.gz" \
            -o nginx.tar.gz || exit 3
    fi
    tar xzf nginx.tar.gz || exit 3
fi
if [ ! -x h2spec ]; then
    # h2spec publishes only amd64 binaries, and the guest is arm64, so the
    # binary is cross-built on the host and copied to the volume as
    # /vol/tools/h2spec. Building it in the guest needs a Go toolchain
    # (≈400 MB) and is kept as the fallback.
    H2SPEC=""
    for c in /vol/tools/h2spec /data/tools/h2spec "$SRC/h2spec"; do
        [ -x "$c" ] && { H2SPEC="$c"; break; }
    done
    if [ -z "$H2SPEC" ] && apk add --no-cache go >> "$OUT/apk.log" 2>&1; then
        cd "$SRC" || exit 3
        if [ ! -d h2spec-src ]; then
            curl -sSfL \
                "https://github.com/summerwind/h2spec/archive/refs/tags/v$H2SPEC_VERSION.tar.gz" \
                -o h2spec.tar.gz || exit 3
            mkdir -p h2spec-src
            tar xzf h2spec.tar.gz -C h2spec-src --strip-components=1 || exit 3
        fi
        ( cd h2spec-src && go build -o "$SRC/h2spec" ./cmd/h2spec ) \
            >> "$OUT/build.log" 2>&1 || true
        [ -x "$SRC/h2spec" ] && H2SPEC="$SRC/h2spec"
    fi
    if [ -n "$H2SPEC" ]; then
        cp "$H2SPEC" "$SRC/h2spec"
        H2SPEC="$SRC/h2spec"
        echo "h2spec=$H2SPEC ($("$H2SPEC" --version 2>&1 | head -1))" \
            > "$OUT/h2spec-version.txt"
    else
        echo "h2spec unavailable: no host-built binary and no Go toolchain" \
            > "$OUT/h2spec-version.txt"
    fi
else
    H2SPEC="$SRC/h2spec"
fi

echo "=== build nginx"
if [ "$PREBUILT" = 1 ]; then
    echo "skipping the guest build: using the prebuilt tree"
else
cd "nginx-$V" || exit 1
if [ ! -x objs/nginx ]; then
    ./configure \
        --prefix="$SRC/prefix" \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-threads \
        > "$OUT/build.log" 2>&1 || exit 4
    make -j"$JOBS" >> "$OUT/build.log" 2>&1 || { tail -40 "$OUT/build.log"; exit 4; }
    make install >> "$OUT/build.log" 2>&1 || exit 4
fi
fi
NGX="$SRC/prefix/sbin/nginx"
if [ "$PREBUILT" = 1 ]; then
    echo "using prebuilt /vol/cache/nginx-prefix"
    rm -rf "$SRC/prefix"
    cp -a /vol/cache/nginx-prefix "$SRC/prefix" || exit 4
fi
[ -x "$NGX" ] || { echo "nginx not built" >&2; exit 4; }
"$NGX" -v > "$OUT/version.txt" 2>&1

WWW="$SRC/www"
PREFIX="$SRC/run"
mkdir -p "$WWW" "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/tmp"
printf 'hello-from-nginx\n' > "$WWW/index.html"
head -c 262144 /dev/urandom > "$WWW/big.bin"
mkdir -p "$WWW/dir"
printf 'one\n' > "$WWW/dir/one.txt"
printf 'two\n' > "$WWW/dir/two.txt"

# A self-signed certificate for the TLS configurations.
if [ ! -f "$PREFIX/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -subj /CN=localhost \
        -keyout "$PREFIX/key.pem" -out "$PREFIX/cert.pem" \
        > "$OUT/cert.log" 2>&1 || exit 5
fi

MATRIX="$OUT/matrix.log"
: > "$MATRIX"
pass=0
fail=0
skip=0

# verdict NAME MODE RESULT DETAIL
verdict() {
    printf '%-22s %-8s %-6s %s\n' "$1" "$2" "$3" "$4" >> "$MATRIX"
    case "$3" in
        pass) pass=$((pass + 1)) ;;
        fail) fail=$((fail + 1)) ;;
        *) skip=$((skip + 1)) ;;
    esac
}

# check NAME PORT PATH EXPECTED STATUS_BODY
# Runs curl and compares the status code, and the body when one is given.
check() {
    name=$1
    port=$2
    path=$3
    want=$4
    want_body=${5:-}
    args="-s -o /tmp/body -w %{http_code}"
    [ -n "${EXTRA_CURL:-}" ] && args="$args $EXTRA_CURL"
    code=$(curl $args "http://127.0.0.1:$port$path" 2>/dev/null)
    if [ "$code" != "$want" ]; then
        echo "$name: $path -> $code, want $want" >> "$MATRIX"
        return 1
    fi
    if [ -n "$want_body" ]; then
        got=$(cat /tmp/body 2>/dev/null)
        if [ "$got" != "$want_body" ]; then
            echo "$name: $path body mismatch" >> "$MATRIX"
            return 1
        fi
    fi
    return 0
}

start_nginx() {
    "$NGX" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -e "$PREFIX/logs/error.log"
}

stop_nginx() {
    "$NGX" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null
    sleep 0.3
}

# run_config NAME PORT MODE CONFIG_BODY
# Installs CONFIG_BODY as the http block, starts nginx, and returns 0 when it
# accepted the configuration and is answering.
run_config() {
    name=$1
    port=$2
    body=$3
    # The body is written literally: it is nginx configuration and contains
    # variables such as $uri and $remote_addr that must reach nginx unexpanded.
    {
        printf 'worker_processes 1;\n'
        printf 'daemon on;\n'
        printf 'pid %s/logs/nginx.pid;\n' "$PREFIX"
        printf 'error_log %s/logs/error.log warn;\n' "$PREFIX"
        printf 'events { worker_connections 128; }\n'
        printf 'http {\n'
        printf '    access_log %s/logs/access.log;\n' "$PREFIX"
        printf '    client_body_temp_path %s/tmp/body;\n' "$PREFIX"
        printf '    proxy_temp_path %s/tmp/proxy;\n' "$PREFIX"
        printf '    fastcgi_temp_path %s/tmp/fastcgi;\n' "$PREFIX"
        printf '    uwsgi_temp_path %s/tmp/uwsgi;\n' "$PREFIX"
        printf '    scgi_temp_path %s/tmp/scgi;\n' "$PREFIX"
        printf '%s\n' "$body"
        printf '}\n'
    } > "$PREFIX/conf/nginx.conf"
    start_nginx || return 1
    # nginx forks; wait for the listening socket.
    i=0
    while [ $i -lt 40 ]; do
        if curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------- matrix ----

# 1. Plain HTTP/1.1 static server.
if run_config plain 8081 "    server { listen 8081; root $WWW; index index.html; }"; then
    ok=1
    check plain 8081 / 200 "hello-from-nginx" || ok=0
    check plain 8081 /dir/one.txt 200 "one" || ok=0
    check plain 8081 /missing 404 || ok=0
    EXTRA_CURL="-I" check plain 8081 / 200 || ok=0
    [ "$ok" = 1 ] && verdict plain http1 pass "root,index,404,HEAD" \
        || verdict plain http1 fail "see matrix lines above"
else
    verdict plain http1 fail "nginx did not start"
fi
stop_nginx

# 2. gzip on, static + gzip_static.
# gzip_min_length 0: the body used here is 17 bytes, and nginx compresses
# nothing below its 20-byte default, so the negotiation would never run.
if run_config gzip 8082 "    server { listen 8082; root $WWW; gzip on; gzip_min_length 0; gzip_types text/plain; gzip_static on; }"; then
    ok=1
    check gzip 8082 /index.html 200 || ok=0
    enc=$(curl -s -H 'Accept-Encoding: gzip' -o /dev/null -D - \
        "http://127.0.0.1:8082/index.html" 2>/dev/null | tr -d '\r' |
        awk 'tolower($1)=="content-encoding:"{print $2}')
    [ "$enc" = "gzip" ] || { echo "gzip: content-encoding=$enc" >> "$MATRIX"; ok=0; }
    [ "$ok" = 1 ] && verdict gzip http1 pass "gzip negotiated" \
        || verdict gzip http1 fail "gzip not applied"
else
    verdict gzip http1 fail "nginx did not start"
fi
stop_nginx

# 3. keepalive: three requests over one connection.
if run_config keepalive 8083 "    server { listen 8083; root $WWW; keepalive_requests 10; keepalive_timeout 5s; }"; then
    # One -o per URL: curl applies a single -o to one transfer, and the bodies
    # of the rest would then be printed next to the status codes.
    got=$(curl -s -o /dev/null -o /dev/null -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:8083/" "http://127.0.0.1:8083/" \
        "http://127.0.0.1:8083/" 2>/dev/null)
    [ "$got" = "200200200" ] && verdict keepalive http1 pass "3 requests, one connection" \
        || verdict keepalive http1 fail "codes=$got"
else
    verdict keepalive http1 fail "nginx did not start"
fi
stop_nginx

# 4. return codes and redirect.
if run_config returns 8084 "    server { listen 8084; location = /r { return 301 /t; } location = /t { return 200 'target'; } location = /n { return 404; } }"; then
    ok=1
    check returns 8084 /r 301 || ok=0
    check returns 8084 /t 200 "target" || ok=0
    check returns 8084 /n 404 || ok=0
    [ "$ok" = 1 ] && verdict returns http1 pass "301,200,404" \
        || verdict returns http1 fail "see matrix lines above"
else
    verdict returns http1 fail "nginx did not start"
fi
stop_nginx

# 5. autoindex.
if run_config autoindex 8085 "    server { listen 8085; root $WWW; location /dir/ { autoindex on; } }"; then
    body=$(curl -s "http://127.0.0.1:8085/dir/" 2>/dev/null)
    case "$body" in
        *one.txt*) verdict autoindex http1 pass "listing rendered" ;;
        *) verdict autoindex http1 fail "no listing" ;;
    esac
else
    verdict autoindex http1 fail "nginx did not start"
fi
stop_nginx

# 6. try_files with a fallback.
if run_config tryfiles 8086 "    server { listen 8086; root $WWW; location / { try_files \$uri \$uri/ /index.html; } }"; then
    check tryfiles 8086 /nope 200 "hello-from-nginx" \
        && verdict tryfiles http1 pass "fallback served" \
        || verdict tryfiles http1 fail "fallback not served"
else
    verdict tryfiles http1 fail "nginx did not start"
fi
stop_nginx

# 7. byte ranges on a large file.
if run_config ranges 8087 "    server { listen 8087; root $WWW; }"; then
    first=$(curl -s -r 0-3 "http://127.0.0.1:8087/big.bin" 2>/dev/null |
        od -An -tx1 | tr -d ' \n')
    want=$(od -An -tx1 -N4 "$WWW/big.bin" | tr -d ' \n')
    code=$(curl -s -r 0-3 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:8087/big.bin" 2>/dev/null)
    if [ "$code" = "206" ] && [ "$first" = "$want" ]; then
        verdict ranges http1 pass "206, first 4 bytes match"
    else
        verdict ranges http1 fail "code=$code bytes=$first"
    fi
else
    verdict ranges http1 fail "nginx did not start"
fi
stop_nginx

# 8. POST body with client_max_body_size and Expect: 100-continue.
if run_config post 8088 "    server { listen 8088; client_max_body_size 8k; location /echo { return 200 'ok'; } location /small { client_max_body_size 1k; return 200 'ok'; } }"; then
    ok=1
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary \
        '0123456789' "http://127.0.0.1:8088/echo" 2>/dev/null)
    [ "$code" = "200" ] || ok=0
    # A body over client_max_body_size must be refused with 413.
    dd if=/dev/zero of=/tmp/big.body bs=4096 count=1 2>/dev/null
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary \
        @/tmp/big.body "http://127.0.0.1:8088/small" 2>/dev/null)
    [ "$code" = "413" ] || ok=0
    [ "$ok" = 1 ] && verdict post http1 pass "200 and 413" \
        || verdict post http1 fail "codes=$code"
else
    verdict post http1 fail "nginx did not start"
fi
stop_nginx

# 9. Large request headers.
if run_config headers 8089 "    server { listen 8089; large_client_header_buffers 4 16k; return 200 'ok'; }"; then
    big=$(head -c 3000 /dev/zero | tr '\0' 'a')
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Big: $big" \
        "http://127.0.0.1:8089/" 2>/dev/null)
    [ "$code" = "200" ] && verdict headers http1 pass "3k header accepted" \
        || verdict headers http1 fail "code=$code"
else
    verdict headers http1 fail "nginx did not start"
fi
stop_nginx

# 10. HTTP/2 cleartext (h2c prior knowledge) + h2spec.
if [ -z "${H2SPEC:-}" ]; then
    verdict h2c http2 skip "no h2spec binary"
elif run_config h2c 8090 "    server { listen 8090 http2; root $WWW; }"; then
    ok=1
    curl --version | grep -q HTTP2 || echo "h2c: curl without HTTP/2" >> "$MATRIX"
    code=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:8090/" 2>/dev/null)
    [ "$code" = "200" ] || { ok=0; echo "h2c: curl -> $code" >> "$MATRIX"; }
    "$H2SPEC" -h 127.0.0.1 -p 8090 > "$OUT/h2spec-h2c.log" 2>&1
    h2rc=$?
    if ! grep -q 'Failures: 0' "$OUT/h2spec-h2c.log"; then
        ok=0
        echo "h2c: h2spec rc=$h2rc $(grep -a 'Failures:' "$OUT/h2spec-h2c.log" | tail -1)" \
            >> "$MATRIX"
    fi
    [ "$ok" = 1 ] && verdict h2c http2 pass "curl 200, h2spec 0 failures" \
        || verdict h2c http2 fail "see matrix lines above"
else
    verdict h2c http2 fail "nginx did not start"
fi
stop_nginx

# 11. TLS with ALPN h2 + h2spec over TLS.
if [ -z "${H2SPEC:-}" ]; then
    verdict https-h2 http2 skip "no h2spec binary"
elif run_config https-h2 8443 "    server { listen 8443 ssl; http2 on; root $WWW; ssl_certificate $PREFIX/cert.pem; ssl_certificate_key $PREFIX/key.pem; ssl_protocols TLSv1.2 TLSv1.3; }"; then
    ok=1
    code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:8443/" 2>/dev/null)
    [ "$code" = "200" ] || { ok=0; echo "https-h2: curl -> $code" >> "$MATRIX"; }
    proto=$(curl -sk --http2 -o /dev/null -w '%{http_version}' \
        "https://127.0.0.1:8443/" 2>/dev/null)
    [ "$proto" = "2" ] || { ok=0; echo "https-h2: negotiated $proto" >> "$MATRIX"; }
    "$SRC/h2spec" -h 127.0.0.1 -p 8443 -t -k > "$OUT/h2spec-tls.log" 2>&1
    h2rc=$?
    if ! grep -q 'Failures: 0' "$OUT/h2spec-tls.log"; then
        ok=0
        echo "https-h2: h2spec rc=$h2rc $(grep -a 'Failures:' "$OUT/h2spec-tls.log" | tail -1)" \
            >> "$MATRIX"
    fi
    [ "$ok" = 1 ] && verdict https-h2 http2 pass "ALPN h2, h2spec 0 failures" \
        || verdict https-h2 http2 fail "see matrix lines above"
else
    verdict https-h2 http2 fail "nginx did not start"
fi
stop_nginx

# 12. TLS without h2: ALPN must stay on HTTP/1.1.
if run_config https-h1 8444 "    server { listen 8444 ssl; root $WWW; ssl_certificate $PREFIX/cert.pem; ssl_certificate_key $PREFIX/key.pem; }"; then
    code=$(curl -sk --http2 -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:8444/" 2>/dev/null)
    proto=$(curl -sk --http2 -o /dev/null -w '%{http_version}' \
        "https://127.0.0.1:8444/" 2>/dev/null)
    if [ "$code" = "200" ] && [ "$proto" = "1.1" ]; then
        verdict https-h1 http1 pass "TLS, negotiated 1.1"
    else
        verdict https-h1 http1 fail "code=$code proto=$proto"
    fi
else
    verdict https-h1 http1 fail "nginx did not start"
fi
stop_nginx

# 13. Reverse proxy to a second listener on the same daemon.
if run_config proxy 8091 "    upstream backend { server 127.0.0.1:8092; keepalive 4; }
    server { listen 8091; location / { proxy_pass http://backend; proxy_http_version 1.1; proxy_set_header Connection \"\"; } }
    server { listen 8092; location / { return 200 'from-backend'; } }"; then
    code=$(curl -s -o /tmp/body -w '%{http_code}' "http://127.0.0.1:8091/" 2>/dev/null)
    body=$(cat /tmp/body 2>/dev/null)
    if [ "$code" = "200" ] && [ "$body" = "from-backend" ]; then
        verdict proxy http1 pass "proxied 200 from-backend"
    else
        verdict proxy http1 fail "code=$code body=$body"
    fi
else
    verdict proxy http1 fail "nginx did not start"
fi
stop_nginx

# 14. stub_status.
if run_config status 8093 "    server { listen 8093; location /status { stub_status; } }"; then
    body=$(curl -s "http://127.0.0.1:8093/status" 2>/dev/null)
    case "$body" in
        *"Active connections"*) verdict status http1 pass "stub_status rendered" ;;
        *) verdict status http1 fail "no status page" ;;
    esac
else
    verdict status http1 fail "nginx did not start"
fi
stop_nginx

# ---------------------------------------------------------------- totals ----
{
    echo "configs=$((pass + fail + skip))"
    echo "pass=$pass"
    echo "fail=$fail"
    echo "skip=$skip"
    # h2spec ends with "N tests, P passed, S skipped, F failed"; that line is
    # the verdict, not the per-group "Failures:" heading.
    echo "h2spec_h2c=$(grep -aE '^[0-9]+ tests,' "$OUT/h2spec-h2c.log" 2>/dev/null | tail -1)"
    echo "h2spec_tls=$(grep -aE '^[0-9]+ tests,' "$OUT/h2spec-tls.log" 2>/dev/null | tail -1)"
} > "$OUT/counts.txt"
cat "$MATRIX"
cat "$OUT/counts.txt"
[ "$fail" -eq 0 ]
