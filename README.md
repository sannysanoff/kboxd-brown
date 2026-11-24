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

kbox boots a real Linux kernel as an in-process library
([LKL, the Linux Kernel Library](https://github.com/lkl/linux)) and routes
intercepted syscalls to it. Programs get real
[VFS](https://www.kernel.org/doc/html/latest/filesystems/vfs.html), real
[ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/), real
[procfs](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
at near-native syscall speed, without root privileges, containers, VMs,
or [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

It serves two roles:

- a rootless [`chroot`](https://man7.org/linux/man-pages/man2/chroot.2.html) /
  [`proot`](https://proot-me.github.io/) alternative with kernel-level
  syscall accuracy, and
- a high-observability execution substrate for AI agent tool calls.

The name `kbox` started as shorthand for "kernel sandboxing", but the
project outgrew that label: a real Linux kernel in-process gives you
semantic fidelity, introspection, and dispatch flexibility that a plain
sandbox cannot. Think of it as a rootless execution substrate that
happens to contain the kernel, not as a box around one.

## At a glance

```
┌──────────────────────────────────────────────────┐
│                   kbox process                   │
│                                                  │
│  ┌────────────────────────────────────────────┐  │
│  │ guest binary (Alpine, musl, gcc, ...)      │  │
│  │ loaded from rootfs.ext4                    │  │
│  └─────────────────┬──────────────────────────┘  │
│                    ▼ syscall                     │
│  ┌────────────────────────────────────────────┐  │
│  │  interception (auto-select)                │  │
│  │  ┌────────┐  ┌──────┐  ┌─────────┐         │  │
│  │  │seccomp │  │SIGSYS│  │ binary  │         │  │
│  │  │unotify │  │ trap │  │ rewrite │         │  │
│  │  └────────┘  └──────┘  └─────────┘         │  │
│  └─────────────────┬──────────────────────────┘  │
│                    ▼                             │
│  ┌────────────────────────────────────────────┐  │
│  │  unified dispatch (kbox_dispatch_request)  │  │
│  └──────┬────────────────────────────┬────────┘  │
│         ▼                            ▼           │
│  ┌──────────────┐             ┌──────────────┐   │
│  │ REAL Linux   │             │ host kernel  │   │
│  │ kernel (LKL) │             │ futex / brk  │   │
│  │ ext4 / VFS / │             │ mmap signals │   │
│  │ procfs / net │             └──────────────┘   │
│  └──────┬───────┘                                │
│         │ in-proc /proc reads                    │
│         │ (no ftrace, no perf, no root)          │
│         ▼                                        │
│  ┌─────────────────────────────┐                 │
│  │ web observatory* + GDB hooks│ ────────────────┼──▶ browser
│  │ (in-proc kernel inspection) │                 │    dashboard
│  └─────────────────────────────┘                 │
└──────────────────────────────────────────────────┘
```

The Linux kernel itself (LKL) is linked into the kbox binary and
runs in the same address space as the supervisor. In trap and rewrite
mode, the guest also shares that address space, so guest, kernel, and
dispatch all live in one process. In seccomp mode, the guest runs as a
forked child while LKL stays in the supervisor; the supervisor handles
syscall notifications and forwards them to the in-process kernel. Either
way: no VM, no container daemon, no `ptrace`, no separate kernel.

\* The web observatory and per-syscall event stream are currently driven
by the seccomp supervisor. Trap and rewrite modes still boot LKL
in-process and remain inspectable via GDB, but do not yet emit telemetry
events. Pin `--syscall-mode=seccomp` if you need the dashboard.

## What makes kbox unique

| Property | kbox | `chroot` | `proot` | UML | gVisor | containers |
|----------|:----:|:--------:|:-------:|:---:|:------:|:----------:|
| Rootless, no daemon                    | yes | no | yes | yes | yes | depends |
| Real Linux kernel for syscalls         | yes | yes | no  | yes | no  | yes |
| In-process kernel                      | yes | n/a | no  | no  | no  | no |
| No `ptrace` dispatch                   | yes | n/a | no  | no  | yes | yes |
| Near-native latency                    | yes | yes | no  | no  | no  | yes |
| Host-side guest `/proc` inspection     | yes | no | no  | no  | no  | no |
| Built-in latency tracing               | yes | no | via `strace` | no | partial | no |
| Web observatory                        | yes | no | no | no | no | no |
| Rewrite mode                           | yes | no | no | no | no | no |

The point is the combination. Most tools cover one or two of these
properties; kbox combines a real Linux kernel, in-process execution,
rootless operation, observability, and low overhead in one design.
It implements the in-process kernel with LKL.
It also exposes a browser observatory for telemetry and inspection.

The rewrite mode is kbox-specific and applies to eligible direct
binaries, where patched syscall sites provide the fastest dispatch path.

## Why kbox

Running Linux userspace programs in a rootless, unprivileged environment
requires intercepting their syscalls and providing a convincing kernel
interface. Existing tools fall short:

- [`chroot`](https://man7.org/linux/man-pages/man2/chroot.2.html)
  requires root privileges (or
  [user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
  which are unavailable on many systems including
  [Termux](https://termux.dev/) and locked-down shared hosts).
- [`proot`](https://proot-me.github.io/) uses
  [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) for
  syscall interception. `ptrace` is slow, cannot faithfully emulate all
  syscalls, breaks under complex multi-threaded workloads, and its path
  translation is vulnerable to
  [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
  races.
- [User Mode Linux (UML)](http://user-mode-linux.sourceforge.net/) runs
  as a separate supervisor/guest process tree with `ptrace`-based syscall
  routing, imposing overhead and complexity that
  [LKL](https://github.com/lkl/linux) avoids by running in-process.
- [gVisor](https://gvisor.dev/) implements a userspace kernel from
  scratch, with millions of lines reimplementing Linux semantics, inevitably
  diverging from the real kernel on edge cases.

kbox takes a different approach: boot the actual
[Linux kernel](https://www.kernel.org/) as an in-process library and
route intercepted syscalls to it. The kernel that handles your `open()`
is the same kernel that runs on servers in production. No
reimplementation, no approximation.

kbox offers three interception tiers
([seccomp-unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html),
[SIGSYS trap](https://man7.org/linux/man-pages/man2/seccomp.2.html),
binary rewriting), each trading isolation for speed. The default
`auto` mode picks the fastest tier per command. See
[docs/interception-tiers.md](docs/interception-tiers.md) for the
trade-offs and selection rules.

## Baseline for this brown slopware

This brown vibeware is based on the original
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

## Quick start

Build a test rootfs image (requires
[`e2fsprogs`](https://e2fsprogs.sourceforge.net/), no root needed). The
script auto-detects the host architecture and downloads the matching
[Alpine minirootfs](https://alpinelinux.org/downloads/):

```bash
make rootfs                                       # host arch
make ARCH=aarch64 CC=aarch64-linux-gnu-gcc rootfs # cross
```

To pull from a Docker [v2 registry](https://distribution.github.io/distribution/spec/api/)
instead, pass `--image=docker://...` to the rootfs script (no
[`docker`](https://www.docker.com/) daemon required, `python3` stdlib
only):

```bash
ROOTFS=alpine.ext4 ./scripts/mkrootfs.sh --image=docker://alpine:3.21
ROOTFS=node.ext4   ./scripts/mkrootfs.sh --image=docker://node:alpine \
                                         --rewrite-uid --size=512
```

`--rewrite-uid` restores OCI tar-header ownership into the ext4 inodes
via [`tools/oci-chown`](tools/oci-chown/) (built on demand, links
against [`libext2fs`](https://e2fsprogs.sourceforge.net/)) and is
required for [`--root-id`](#selecting-an-interception-mode) guests.
See [docs/oci-image-import.md](docs/oci-image-import.md) for the full
pipeline, layer cache, and threat model.

Run a guest binary:

```bash
# Interactive shell with recommended mounts + root identity
./kbox -S alpine.ext4 -- /bin/sh -i

# Run a specific command
./kbox -S alpine.ext4 -- /bin/ls -la /

# Raw mount only (no /proc, /sys, /dev), for targeted commands
./kbox -r alpine.ext4 -- /bin/cat /etc/os-release

# Custom kernel cmdline, bind mount, explicit identity
./kbox -r alpine.ext4 -k "mem=2048M loglevel=7" \
    -b /home/user/data:/mnt/data --change-id 1000:1000 -- /bin/sh -i
```

Use `/bin/sh -i` for interactive sessions; the `-i` flag forces
interactive mode regardless of terminal detection.

### Selecting an interception mode

`--syscall-mode` controls the dispatch mechanism:

```bash
# Auto (default): rewrite/trap for direct binaries, seccomp for shells
./kbox -S alpine.ext4 -- /bin/ls /

# Force seccomp (most compatible, handles fork+exec)
./kbox -S alpine.ext4 --syscall-mode=seccomp -- /bin/sh -i

# Force trap (single-exec commands, SIGSYS dispatch)
./kbox -r alpine.ext4 --syscall-mode=trap -- /bin/cat /etc/hostname

# Force rewrite (patched syscall sites, fastest stat path)
./kbox -r alpine.ext4 --syscall-mode=rewrite -- /opt/tests/bench-test 200
```

Run `./kbox --help` for the full option list.

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

## Documentation

| Topic | Document |
|-------|----------|
| Three syscall interception tiers and auto selection | [docs/interception-tiers.md](docs/interception-tiers.md) |
| Internal design: dispatch routing, FD table, shadow FDs, ABI translation | [docs/architecture.md](docs/architecture.md) |
| Threat model and deployment tiers | [docs/security-model.md](docs/security-model.md) |
| Building rootfs images from OCI registries | [docs/oci-image-import.md](docs/oci-image-import.md) |
| Using kbox as an AI agent execution layer | [docs/ai-agents.md](docs/ai-agents.md) |
| Web dashboard and telemetry endpoints | [docs/web-observatory.md](docs/web-observatory.md) |
| GDB workflow and helper commands | [docs/gdb-workflow.md](docs/gdb-workflow.md) |
| LKL API surface used by kbox | [docs/lkl-api-surface.md](docs/lkl-api-surface.md) |
| LKL threading modes | [docs/lkl-threading-modes.md](docs/lkl-threading-modes.md) |
| Syscall parity specification | [docs/syscall-parity-spec.md](docs/syscall-parity-spec.md) |
| `cancel-wrapper` fast path | [docs/cancel-wrapper.md](docs/cancel-wrapper.md) |

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

## Targets

- x86_64
- aarch64
- riscv64 (Only the trap mode and the seccomp mode are available)

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
