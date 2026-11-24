#!/bin/sh
# SPDX-License-Identifier: MIT
# Build liblkl.a from source (sannysanoff/linux, a fork of lkl/linux) and
# populate lkl-<ARCH>/.
#
# Usage: ./scripts/build-lkl.sh [ARCH]
#   ARCH defaults to the host architecture (x86_64 or aarch64).
#   Override LKL_DIR   to change the output directory.
#   Override LKL_SRC   to reuse an existing source tree (skip clone).
#   Override LKL_REF   to check out a specific branch/tag/commit
#                      (default: HEAD of master).

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

detect_arch "${1:-}"

LKL_DIR="${LKL_DIR:-lkl-${ARCH}}"
LKL_SRC="${LKL_SRC:-build/lkl-src}"
# Fork of lkl/linux that carries the LKL commit kbox is built and tested
# against (branch "kbox"). Use LKL_REF=kbox to pin to that branch; the
# default keeps the fork's default branch.
LKL_UPSTREAM="${LKL_UPSTREAM:-https://github.com/sannysanoff/linux}"

is_commit_sha()
{
    case "$1" in
        [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*)
            case "$1" in
                *[!0-9a-fA-F]*)
                    return 1
                    ;;
            esac
            return 0
            ;;
    esac

    return 1
}

checkout_lkl_ref()
{
    ref="$1"

    echo "  CHECKOUT ${ref}"
    if is_commit_sha "$ref"; then
        # Bare commit SHAs are not advertised as remote refs, so a shallow
        # ref fetch is not reliable. Ensure full history before checkout.
        if git -C "${LKL_SRC}" rev-parse --is-shallow-repository > /dev/null 2>&1 \
            && [ "$(git -C "${LKL_SRC}" rev-parse --is-shallow-repository)" = "true" ]; then
            git -C "${LKL_SRC}" fetch --unshallow origin
        else
            git -C "${LKL_SRC}" fetch origin
        fi
        git -C "${LKL_SRC}" checkout "${ref}"
    else
        git -C "${LKL_SRC}" fetch --depth=1 origin "${ref}"
        git -C "${LKL_SRC}" checkout FETCH_HEAD
    fi
}

# ---- Clone or update source tree ----------------------------------------

if [ -d "${LKL_SRC}/.git" ]; then
    echo "  SRC     ${LKL_SRC} (exists, skipping clone)"
    if [ -n "${LKL_REF:-}" ]; then
        checkout_lkl_ref "${LKL_REF}"
    fi
else
    echo "  CLONE   ${LKL_UPSTREAM} -> ${LKL_SRC}"
    mkdir -p "$(dirname "${LKL_SRC}")"

    if [ -n "${LKL_REF:-}" ] && is_commit_sha "${LKL_REF}"; then
        # Commit SHAs require full history because remotes typically do not
        # advertise arbitrary object IDs as shallow-fetchable refs.
        git clone "${LKL_UPSTREAM}" "${LKL_SRC}"
        checkout_lkl_ref "${LKL_REF}"
    else
        # Shallow clone of default branch, then checkout specific branch/tag if
        # requested. git clone --branch does not accept bare commit SHAs.
        git clone --depth=1 "${LKL_UPSTREAM}" "${LKL_SRC}"
        if [ -n "${LKL_REF:-}" ]; then
            checkout_lkl_ref "${LKL_REF}"
        fi
    fi
fi

# ---- Kernel-side requirements -------------------------------------------

# hostfs (the host directory filesystem) and the overlayfs fix that makes an
# unprivileged upper understand its xattr whiteouts live in the fork:
#
#   4710939b6 overlayfs: honour userxattr whiteouts in the upper layer
#   ba619e886 hostfs: support xattrs, tmpfiles and unprivileged whiteouts
#
# Nothing is patched here, so a fresh clone of the fork is the source of truth.

# ---- Configure -----------------------------------------------------------

if [ ! -f "${LKL_SRC}/.config" ]; then
    echo "  CONF    tools/lkl"
    make -C "${LKL_SRC}/tools/lkl" conf

    echo "  CONFIG  ARCH=lkl defconfig"
    make -C "${LKL_SRC}" ARCH=lkl defconfig
    if [ -f "${LKL_SRC}/tools/lkl/kernel.config" ]; then
        cat "${LKL_SRC}/tools/lkl/kernel.config" >> "${LKL_SRC}/.config"
    fi

    # Enable features required by kbox (mirrors build-lkl.yml) plus
    # container namespaces, veth/bridge/NAT networking, loop, tmpfs, overlayfs.
    for opt in \
        CONFIG_DEVTMPFS \
        CONFIG_DEVTMPFS_MOUNT \
        CONFIG_DEVPTS_FS \
        CONFIG_NAMESPACES \
        CONFIG_NET_NS \
        CONFIG_UTS_NS \
        CONFIG_IPC_NS \
        CONFIG_PID_NS \
        CONFIG_NET_CORE \
        CONFIG_NETDEVICES \
        CONFIG_INET \
        CONFIG_IP_ADVANCED_ROUTER \
        CONFIG_IP_MULTIPLE_TABLES \
        CONFIG_VETH \
        CONFIG_LLC \
        CONFIG_STP \
        CONFIG_BRIDGE \
        CONFIG_NETFILTER \
        CONFIG_NETFILTER_XTABLES \
        CONFIG_NF_CONNTRACK \
        CONFIG_NF_NAT \
        CONFIG_IP_NF_IPTABLES \
        CONFIG_IP_NF_FILTER \
        CONFIG_IP_NF_NAT \
        CONFIG_IP_NF_TARGET_MASQUERADE \
        CONFIG_NETFILTER_XT_TARGET_MASQUERADE \
        CONFIG_BLK_DEV_LOOP \
        CONFIG_TMPFS \
        CONFIG_OVERLAY_FS \
        CONFIG_SCHED_DEBUG \
        CONFIG_PROC_SYSCTL \
        CONFIG_PRINTK \
        CONFIG_DEBUG_FS \
        CONFIG_FILE_LOCKING \
        CONFIG_SIGNALFD \
        CONFIG_TIMERFD \
        CONFIG_EVENTFD \
        CONFIG_FS_POSIX_ACL \
        CONFIG_NETWORK_FILESYSTEMS \
        CONFIG_DNS_RESOLVER \
        CONFIG_KEYS \
        CONFIG_NFS_FS \
        CONFIG_NFS_V3 \
        CONFIG_NFS_V4 \
        CONFIG_NFS_V4_1 \
        CONFIG_NFS_V4_2 \
        CONFIG_NFS_USE_KERNEL_DNS \
        CONFIG_LOCKD \
        CONFIG_LOCKD_V4 \
        CONFIG_HOSTFS; do
        "${LKL_SRC}/scripts/config" --file "${LKL_SRC}/.config" --enable "${opt}"
    done

    # CONFIG_LKL_HOST_MEMCPY routes the guest kernel's memcpy to the host libc.
    # glibc's aarch64 memcpy reads up to a block past the end of the source, and
    # raw_copy_from_user() uses memcpy directly, so a user buffer that ends at a
    # page boundary faults: mount(2) option strings hit this reliably
    # (copy_mount_options). Use the kernel's own byte-accurate memcpy instead.
    for opt in \
        CONFIG_DEBUG_INFO \
        CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
        CONFIG_GDB_SCRIPTS \
        CONFIG_TRACEPOINTS \
        CONFIG_FTRACE \
        CONFIG_BTRFS_FS \
        CONFIG_XFS_FS \
        CONFIG_F2FS_FS \
        CONFIG_MODULES \
        CONFIG_SOUND \
        CONFIG_USB_SUPPORT \
        CONFIG_INPUT \
        CONFIG_LKL_HOST_MEMCPY \
        CONFIG_CIFS; do
        "${LKL_SRC}/scripts/config" --file "${LKL_SRC}/.config" --disable "${opt}"
    done

    make -C "${LKL_SRC}" ARCH=lkl olddefconfig
    make -C "${LKL_SRC}" ARCH=lkl syncconfig
fi

# ---- Build ---------------------------------------------------------------

NPROC=$(nproc 2> /dev/null || echo 1)

echo "  BUILD   ARCH=lkl kernel (-j${NPROC})"
make -C "${LKL_SRC}" ARCH=lkl -j"${NPROC}"

echo "  BUILD   tools/lkl (-j${NPROC})"
make -C "${LKL_SRC}/tools/lkl" -j"${NPROC}"

# ---- Verify --------------------------------------------------------------

test -f "${LKL_SRC}/tools/lkl/liblkl.a" \
    || die "build succeeded but liblkl.a not found"

echo "  VERIFY  symbols"
for sym in lkl_init lkl_start_kernel lkl_cleanup lkl_syscall \
    lkl_strerror lkl_disk_add lkl_mount_dev \
    lkl_host_ops lkl_dev_blk_ops \
    veth_newlink br_add_if net_ns_init sys_unshare; do
    if ! nm "${LKL_SRC}/tools/lkl/liblkl.a" 2> /dev/null \
        | awk -v s="$sym" '$3==s && $2~/^[TtDdBbRr]$/{found=1} END{exit !found}'; then
        die "MISSING symbol: ${sym}"
    fi
done

# ---- Install into lkl-<ARCH>/ -------------------------------------------

echo "  INSTALL ${LKL_DIR}/"
mkdir -p "${LKL_DIR}"

cp "${LKL_SRC}/tools/lkl/liblkl.a" "${LKL_DIR}/"
cp "${LKL_SRC}/tools/lkl/include/lkl.h" "${LKL_DIR}/" 2> /dev/null || true
cp "${LKL_SRC}/tools/lkl/include/lkl/autoconf.h" "${LKL_DIR}/" 2> /dev/null || true
cp "${LKL_SRC}/scripts/gdb/vmlinux-gdb.py" "${LKL_DIR}/" 2> /dev/null || true

printf 'commit=%s\ndate=%s\narch=%s\n' \
    "$(git -C "${LKL_SRC}" rev-parse HEAD)" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${ARCH}" \
    > "${LKL_DIR}/BUILD_INFO"

# Hash the installed files only. The directory may also hold header trees from
# an older layout, and sha256sum fails on a directory under `set -e`.
(cd "${LKL_DIR}" && find . -maxdepth 1 -type f | sort | xargs sha256sum \
    > sha256sums.txt)

echo "OK: ${LKL_DIR}/liblkl.a"
