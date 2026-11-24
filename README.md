# kboxd-brown

> **Experiment.** This tree is not a product. It is a copy of the original
> [kbox](https://github.com/sysprog21/kbox) project with the LKL source
> vendored by value and a Docker Engine backend exercised on top. The results
> below describe one machine at one moment; treat them as a snapshot, not a
> warranty.

**Docker for restricted userspace, based on the original
[kbox](https://github.com/sysprog21/kbox) project.** An unprivileged process —
uid 65534, every capability dropped — answers `docker run`, `docker compose`
and `-v` volumes, because the kernel work happens in LKL inside the same
process instead of in a daemon that needs privileges.

## Purpose

The main reason for this project is to run `docker compose` inside
unprivileged Kubernetes containers. Two targets drive the work: CI/CD
pipelines, where the runner pod holds no privilege and cannot start a real
Docker daemon, and agentic development, where an agent needs containers to
build, test and run code without a privileged host.

kbox boots a real Linux kernel as an in-process library
([LKL, the Linux Kernel Library](https://github.com/lkl/linux)) and routes
intercepted syscalls to it. Programs get real
[VFS](https://www.kernel.org/doc/html/latest/filesystems/vfs.html), real
[ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/), real
[procfs](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
at near-native syscall speed, without root privileges, containers, VMs,
or [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

## Baseline for this brown slopware

This brown slopware is based on the original
[`sysprog21/kbox`](https://github.com/sysprog21/kbox) project. The kbox sources
are a re-import with their git history dropped, and the LKL tree from
[`lkl/linux`](https://github.com/lkl/linux) is vendored by value in `vendor/lkl`.

| Component | Repository | Commit | Commit date |
|---|---|---|---|
| kbox base | [`sysprog21/kbox`](https://github.com/sysprog21/kbox) | `86df60a932c826fc147db0a79c2bc5ecd6397f04` | 2026-04-29 08:49:13 +0000 |
| LKL base | [`lkl/linux`](https://github.com/lkl/linux) | `d0f76a77e8c2ca68bd7d96190b8da09040eab072` | 2026-09-28 21:44:38 +0000 |

The kbox sources carry 294 commits on top of the kbox base. The vendored LKL
tree carries five hostfs and overlayfs patches on top of the LKL base; they
live in `vendor/lkl` and are not part of the upstream history.

| Commit | Subject |
|---|---|
| `54accd5c21` | lkl: Wait for TASK_DEAD before longjmping out of del_host_task |
| `ba619e8862` | hostfs: support xattrs, tmpfiles and unprivileged whiteouts |
| `4710939b6a` | overlayfs: honour userxattr whiteouts in the upper layer |
| `e7a0d32c9d` | hostfs: emulate chown with a user.kbox.owner xattr |
| `9265c16bf6` | hostfs: stop unlocking a new inode in tmpfile |

`vendor/lkl` is that tree copied without git metadata, so a checkout of this
repository builds the same kernel. `make` reads the tree in place; nothing is
cloned and nothing is checked out.

`vendor/` is exempt from the repository hooks: formatting, whitespace and C
safety checks see kbox's own sources only.

LKL names that differ only in case appear once, under the lowercase spelling,
because a case-insensitive filesystem cannot hold both. Twelve removed paths
are netfilter targets that are disabled in the kbox LKL configuration; the
thirteenth is a litmus test that the kernel build never reads. The full list
is in `vendor/lkl/BASELINE`.

## Building

Linux only (host kernel 5.0+ for
[seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html),
5.9+ for
[FSGSBASE](https://docs.kernel.org/arch/x86/x86_64/fsgs.html) trap
optimization). Requires [GCC](https://gcc.gnu.org/) and
[GNU Make](https://www.gnu.org/software/make/). `liblkl.a` is built from
source automatically on the first build from the vendored tree in
`vendor/lkl`, and the library is reused from then on. No
[`libseccomp`](https://github.com/seccomp/libseccomp) dependency.

```bash
make defconfig              # bootstrap default config
make                        # debug build (ASAN + UBSAN enabled)
make BUILD=release          # release build
make KBOX_HAS_WEB=1         # enable web-based kernel observatory
```

For cross-compilation, use `ARCH` and `CC`:

```bash
make BUILD=release ARCH=aarch64 CC=aarch64-linux-gnu-gcc
```

To use a custom LKL:

```bash
make LKL_DIR=/path/to/lkl   # point to a directory with liblkl.a + lkl.h
make LKL_SRC=/path/to/linux # build another LKL source tree
make FORCE_LKL_BUILD=1      # force a from-source LKL rebuild
```

## Running as a Docker backend

`kbox daemon` is one LKL instance that serves containers. In front of it,
`scripts/kbox-dockerd.py` speaks the Docker Engine API (version 1.47,
`Server Version: 29.0.0-kbox`), so the stock `docker` CLI and `docker compose`
work against it:

```bash
./kbox daemon --sock /run/kbox/kboxd.sock --config ~/.config/kbox-config.yaml
./scripts/kbox-dockerd.py --kbox-sock /run/kbox/kboxd.sock --listen 127.0.0.1:2375

docker context create kboxd --docker host=tcp://127.0.0.1:2375
docker --context kboxd run --rm alpine:3.21 uname -s
```

Each container gets its own mount, net and UTS namespaces and its own overlay
root filesystem, built by the LKL kernel inside the daemon. No host privilege
is involved: the manifests under `deploy/` run the daemon as uid 65534 with
`capabilities.drop: ["ALL"]` and no service-account token. The daemon container
asks for `Unconfined` seccomp because `pidfd_getfd` is denied by the runtime
default profile; the shim stays on `RuntimeDefault`.

`scripts/test-docker-engine.sh` is the end-to-end check: `docker` CLI and
`docker compose` against a `--cap-drop=ALL` daemon.

## Mounting the guest filesystem

Directly, with the CLI:

| Flag | Mounts |
|---|---|
| `-r, --root-dir IMAGE` | the rootfs image alone |
| `-R, --recommended-root IMAGE` | the image plus `/proc`, `/sys` and `/dev` |
| `-S, --system-root IMAGE` | those mounts plus root identity inside the guest |
| `-b, --bind-mount SRC:DST` | a host directory |
| `-V, --volume HOST:DST[:ro]` | a host directory as a volume, optionally read-only |

Through the Docker backend the same shapes arrive as Docker sends them: image
layers from a registry pull, and host paths as `-v /host:/guest`,
`--mount type=bind,source=...,target=...` or an `nfs://` source declared in the
daemon config.

The guest never writes into an image. The daemon stacks read-only lower layers
under one writable upper per container with overlayfs inside LKL, and whiteouts
use the `user.overlay.whiteout` xattr, so no privileges are required. That is
what the `hostfs` and `overlayfs` patches in `vendor/lkl` add.

Storage can stay on the host instead of guest memory: `storage.images=hostfs`
and `storage.ephemeral=hostfs` keep layers and upper directories in a host
path, which is how the pod manifests put them under `/data`.

Two `-v` limits are worth knowing, with details in
[docs/nfs-volumes.md](docs/nfs-volumes.md): `-v nfs://host/sub:/dest:ro`
silently drops the `ro` flag, so use `--mount` for read-only; and compose's
short volume syntax cannot express an `nfs://` source.

## Test suites

The suites below were run under kboxd. Each linked report records
the environment, the result and, where a suite is still blocked, the defect
that blocks it.

| Suite | Target or script | Scope |
|---|---|---|
| Unit | `make check-unit` | 25 programs: trap runtime, userspace loader, rewrite engine, site classification, procmem, syscall decoding |
| Integration | `make check-integration` | 29 guest binaries inside kbox against an Alpine ext4 image |
| Stress | `make check-stress` | fork storms, FD exhaustion, concurrent I/O, signal races, long-running processes |
| Hostfs and overlay | `make check-hostfs` | reads, copy-up, whiteout, xattr, fallocate, copy_file_range and `O_TMPFILE` through hostfs under overlayfs |
| CPython 3.12 | `scripts/run-cpython-suite.sh` | CPython `Lib/test`, one module per container, one timeout per module; see [python-regression-report.md](python-regression-report.md) |
| SQLite sqllogictest | `scripts/run-sqllogictest-pod.sh` | 622 script files, 1.1 GB, run by the corpus's own runner linked against its own SQLite; see [sqllogictest-report.md](sqllogictest-report.md) |
| Server suites | `scripts/run-three-suites-pod.sh` | mariadb-test, redis `runtest`, nginx config matrix plus h2spec, each container through the Docker shim; see [three-suites-report.md](three-suites-report.md) |
| Scenario reproducers | `scripts/suites/*.sh` | 29 focused cases: FIFO and `pselect` wakeups, wait and exec, parallel build, in-guest build, redis, nginx and mariadb serving |
| Docker Engine | `scripts/test-docker-engine.sh` | `docker` CLI and `docker compose` against a `--cap-drop=ALL` daemon |

`make check` runs the first four. The rest are pod scripts: they need a
Kubernetes namespace and the manifests under `deploy/`.

Unit, integration and stress tests run under
[AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
and
[UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
Guest binaries are compiled without sanitizers (shadow memory interferes with
[`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)).

## Credits

**kbox** is the original project,
[sysprog21/kbox](https://github.com/sysprog21/kbox). Copyright (c) 2026
National Cheng Kung University, Taiwan. Principal author: Jim Huang (jserv),
with contributions from Chisheng Chen, Yiwei Lin and ChuWeiChang. MIT-style
license, see [LICENSE](LICENSE).

**LKL**, the Linux Kernel Library, is
[lkl/linux](https://github.com/lkl/linux). The LKL port was introduced by
Octavian Purdila, Lucian Adrian Grijincu and Nicolae Tapus in 2010 and is
developed by its contributors. It carries the Linux kernel of Linus Torvalds
and the kernel community; `vendor/lkl/COPYING` holds the GPL-2.0-only text
that applies to the kernel code.

`vendor/lkl` is a copy and not a fork: all credit for it belongs to the LKL
project.

## License

`kbox` is available under a permissive
[MIT](https://opensource.org/license/mit)-style license.
Use of this source code is governed by a MIT license that can be found
in the [LICENSE](LICENSE) file.
