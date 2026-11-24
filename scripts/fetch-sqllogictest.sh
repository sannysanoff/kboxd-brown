#!/bin/sh
# SPDX-License-Identifier: MIT
# Fetch the SQLite sqllogictest corpus and build its runner.
#
# Usage: ./scripts/fetch-sqllogictest.sh
#   SLT_DIR      output directory (default: build/sqllogictest)
#   SLT_REF      commit to check out (default: the pinned commit below)
#   SLT_REPO     source repository
#   SLT_BUILDER  image used to compile the runner (default: alpine:3.21)
#
# The runner links the SQLite amalgamation that ships with the corpus, so the
# engine and the expected results come from the same commit. It is built
# statically against musl, which lets any guest image run it without a SQLite
# package or locale data.
#
# The corpus is 1.1 GB of scripts and is not vendored. This script fills a
# gitignored directory.

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

SLT_DIR="${SLT_DIR:-build/sqllogictest}"
SLT_REPO="${SLT_REPO:-https://github.com/gregrahn/sqllogictest}"
# 2026-10-07, "Merge the 3.54.0 beta sources for testing".
SLT_REF="${SLT_REF:-c93ac416f05635ff5cc490009add936d9753d01d}"
SLT_BUILDER="${SLT_BUILDER:-alpine:3.21}"
EXPECTED_FILES=622

case "$SLT_DIR" in
    /* | "" | . | .. | */..*)
        die "SLT_DIR must be a relative sub-path without .."
        ;;
esac

# ---- Fetch ---------------------------------------------------------------

if [ ! -d "${SLT_DIR}/.git" ]; then
    echo "  FETCH   ${SLT_REPO} ${SLT_REF}"
    rm -rf "${SLT_DIR}"
    mkdir -p "${SLT_DIR}"
    git -C "${SLT_DIR}" init -q
    git -C "${SLT_DIR}" remote add origin "${SLT_REPO}"
fi

if ! git -C "${SLT_DIR}" cat-file -e "${SLT_REF}^{commit}" 2> /dev/null; then
    echo "  FETCH   ${SLT_REF}"
    git -C "${SLT_DIR}" fetch -q --depth=1 origin "${SLT_REF}"
fi

git -C "${SLT_DIR}" checkout -q --detach "${SLT_REF}"

head=$(git -C "${SLT_DIR}" rev-parse HEAD)
[ "$head" = "$SLT_REF" ] || die "checked out ${head}, expected ${SLT_REF}"

files=$(find "${SLT_DIR}/test" -name '*.test' | wc -l | tr -d ' ')
bytes=$(find "${SLT_DIR}/test" -name '*.test' -exec cat {} + | wc -c | tr -d ' ')
echo "  CORPUS  ${files} files, ${bytes} bytes"

if [ "$files" -ne "$EXPECTED_FILES" ]; then
    die "expected ${EXPECTED_FILES} test files, found ${files}"
fi

# ---- Build ---------------------------------------------------------------

echo "  BUILD   sqllogictest (static musl)"

docker run --rm -v "$(cd "${SLT_DIR}" && pwd):/slt" -w /slt "${SLT_BUILDER}" sh -c '
    set -eu
    apk add --no-cache build-base > /dev/null
    gcc -static -O2 -o sqllogictest \
        -DOMIT_ODBC=1 \
        -DSQLITE_THREADSAFE=0 \
        -DSQLITE_OMIT_LOAD_EXTENSION \
        -DSQLITE_NO_SYNC=1 \
        src/sqllogictest.c src/md5.c src/sqlite3.c
' || die "runner build failed"

test -x "${SLT_DIR}/sqllogictest" || die "runner not produced"

# A static binary must not report any shared library.
if file "${SLT_DIR}/sqllogictest" | grep -q "dynamically linked"; then
    die "runner is dynamically linked"
fi

echo "OK: ${SLT_DIR}/sqllogictest"
echo "Run the corpus with: ./scripts/run-sqllogictest-pod.sh"
