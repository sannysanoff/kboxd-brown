# NFS-backed volumes

A service can mount a subtree of an NFS export. The export is declared once in
the daemon config, and services refer to it by a hard-coded scheme name that
carries the handle:

```yaml
# ~/.config/kbox-config.yaml
mounts:
  "nfs://mounted_here":
    source: 10.0.0.7:/export/data
    options: vers=4.2,proto=tcp,port=20490
```

```bash
docker run --mount type=bind,source=nfs://mounted_here/subdir,target=/destination \
  alpine:latest sh -c 'echo hello > /destination/probe.txt'
```

The daemon mounts the export once, retrying with a warning until it succeeds,
and binds the requested subtree into each container's own mount namespace.
Missing subdirectories are created on the export. The export root itself is
never reachable from a container.

## What each client actually accepts

| Form | Result |
|---|---|
| `docker run --mount type=bind,source=nfs://h/sub,target=/dest` | works, read-write |
| same, plus `,readonly` | works, enforced read-only |
| `docker run -v nfs://h/sub:/dest` | works, read-write |
| `docker run -v nfs://h/sub:/dest:ro` | **mode silently dropped** — binds read-write; use `--mount` |
| `docker compose`, short syntax | unusable: compose parses the spec itself, splits on `:`, then reports "undefined volume nfs" |
| `docker compose`, long syntax `type: bind` | unusable: compose rewrites a non-absolute source against the project directory, producing `<project>/nfs:/h/sub` |
| Docker Engine API `Mounts` with `ReadOnly` | works (what `--mount` sends) |

The `-v …:ro` row is the trap worth remembering: the Docker CLI accepts the
string, drops the mode, and the mount comes up writable without a warning.

## Known problems

The kernel-side path is not yet trustworthy under load: `fcntl` locks on an
NFS file crash the daemon, and concurrent or repeated small writes lose data.
`docs/nfs-test-findings.md` has the measurements and the reproductions.

## Why the daemon mounts, not the guest

Guest processes in LKL run with no capabilities (`CapEff` is zero by
construction), so a guest `mount(2)` of any filesystem is refused with `EPERM`.
The daemon runs with the kernel's initial credentials, so the mount happens
there and containers only ever see a bind mount of the subtree they asked for.
The same is true at the cluster level: kbox in a Kubernetes pod needs no
capabilities, because every namespace and every mount lives inside the
in-process kernel.

## The addr= detail

`mount(2)` with a raw option string does not resolve the server name — unlike
`mount.nfs`, which always appends `addr=`. Without it the kernel rejects the
mount with `EINVAL`, so kbox derives it from the `source` field and resolves
hostnames on the host, where the daemon's sockets actually leave the pod. That
is what lets `source: ganesha.nfs-test.svc.cluster.local:/` work even though
LKL has no resolver of its own.

## What the server has to be

NFSv4.2 on a single TCP port, which can be above 1024 so the server needs no
privileges either. The export must live on a filesystem that supports file
handles: ganesha's `FSAL_VFS` resolves them with `name_to_handle_at` and
`open_by_handle_at`, and overlayfs or a btrfs subvolume answers `EOPNOTSUPP`,
which the client sees as `EIO` on readdir. A loopback ext4 image is the
portable answer in a container.
