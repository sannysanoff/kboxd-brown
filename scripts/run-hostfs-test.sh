#!/bin/sh
# Run the hostfs regression test against a throwaway fixture.
#
# The fixture is two read-only layers plus an ephemeral tree with upper/work,
# all under a temporary directory on the host filesystem. The test binary boots
# LKL itself, mounts those directories as hostfs, stacks them under overlayfs
# and checks reads, copy-up, whiteout, xattr, fallocate, copy_file_range and
# O_TMPFILE.
#
# The upper layer must support xattr on regular files (any modern filesystem);
# whiteouts are emulated with user.overlay.whiteout, so no privileges are
# required.

set -eu

BIN="${1:-tests/lkl/hostfs-test}"

if [ ! -x "${BIN}" ]; then
    echo "FAIL: ${BIN} not built" >&2
    exit 1
fi

FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/kbox-hostfs-XXXXXX")"
trap 'rm -rf "${FIXTURE}"' EXIT

mkdir -p "${FIXTURE}/l1" "${FIXTURE}/l2" \
    "${FIXTURE}/eph/upper" "${FIXTURE}/eph/work"
printf 'from-l1\n' > "${FIXTURE}/l1/base.txt"
printf 'only-l1\n' > "${FIXTURE}/l1/only-l1.txt"
printf 'from-l2\n' > "${FIXTURE}/l2/base.txt"

# The ephemeral tree is created by the test process itself in real use, so make
# it writable by the current user only.
chmod -R u+rwX "${FIXTURE}"

"${BIN}" "${FIXTURE}"
