# Handover: sqllogictest corpus under kbox (`kbox-sqlite` namespace)

Written 18 November 2026, after rebuilding kbox and LKL from source and running
the whole corpus twice on the local OrbStack cluster. This file states what is
deployed, how to drive it, and what the numbers mean.

## State of the deployment

| Item | Value |
|---|---|
| Namespace | `kbox-sqlite` |
| Deployment / file | `kbox` in [`deploy/sqlite/kbox.yaml`](deploy/sqlite/kbox.yaml) |
| Pod image | `kbox-sqlite/kbox:v7` (built locally, `imagePullPolicy: IfNotPresent`) |
| Containers | `kboxd` (LKL daemon) and `shim` (Docker Engine API on 2376) |
| LKL | `sannysanoff/linux` master `e7a0d32c9d`, rebuilt by `scripts/build-lkl.sh` |
| kbox | `make BUILD=release`, linux/arm64 |
| Guest kernel | `Linux 6.8.0-kbox aarch64` |
| Privileges | uid 65534, CapInh/Prm/Eff/Bnd all `0000000000000000`, `NoNewPrivs: 1` |
| Corpus | `gregrahn/sqllogictest` `c93ac416`, 622 files, 1.1 GB, SQLite 3.54.0 |
| Corpus volume | PVC `kbox-data` (local-path, 3 Gi) at `/data` in both containers |
| Image store | `/dev/shm` tmpfs, 8 Gi, also `HOME` |

`kboxd` runs with `seccompProfile: Unconfined` because it needs `pidfd_getfd`
to copy a tracee descriptor that shares a file description. Everything else is
the strictest setting Kubernetes offers: no capabilities, no escalation, no
service-account token, non-root.

The deployment uses `strategy: Recreate`, because the corpus volume is
`ReadWriteOnce`. The volume is a PVC rather than an `emptyDir`, so an image
update keeps the corpus and every result file.

## How to drive it

```sh
./scripts/run-sqllogictest-pod.sh deploy   # build image, apply, wait for rollout
./scripts/run-sqllogictest-pod.sh push     # corpus + runner into the PVC (12 s)
./scripts/run-sqllogictest-pod.sh run --filter evidence --timeout 300
./scripts/run-sqllogictest-pod.sh start --workers 3 --timeout 1800
./scripts/run-sqllogictest-pod.sh status
./scripts/run-sqllogictest-pod.sh collect slt-results
```

`run` executes the driver in the pod over `kubectl exec` and streams one line
per file. `start` detaches it with `nohup` and writes to
`/data/slt/results/driver.log`; a dropped exec therefore costs nothing, and the
driver resumes where it stopped. `--retry-failed` reruns everything that is not
recorded as PASS.

The driver speaks the Docker Engine API on `127.0.0.1:2376` from inside the pod,
so no port-forward is involved and a long sweep cannot be killed by one.

Driver options that matter:

| Option | Meaning |
|---|---|
| `--root` / `--mount` | pod directory of the corpus (default `/data/slt`) and the guest mount point (default `/data`) |
| `--db-dir` | guest directory for per-file `test.db` directories (default `/tmp`) |
| `--results` | pod directory for logs and `summary.tsv` |
| `--workers` | files in flight at once (3 was stable; the daemon allows 64 containers) |
| `--timeout` | per-file wall-clock cap, enforced by deleting the container |

The corpus location is fixed: `/data/slt/test`. Do not edit it. The runner only
reads it and writes `test.db` under `--db-dir`.

### Volume semantics

| Form | Behaviour |
|---|---|
| `-v /pod/path:/dst` | bind of a pod path, read/write |
| `-v /pod/path:/dst:ro` | bind, writes answer `Read-only file system` |
| `-v name:/dst` (no leading slash) | named volume under `--state-dir`, survives container removal |
| `-v /missing:/dst` | the source directory is created, as the Docker daemon does |
| `--mount type=bind` with a missing source | create answers 400, `bind source path does not exist` |
| `nfs://…` | passed to the daemon's NFS binder, see `nfs-volumes.md` |

The last two rules were added while testing this workload. The shim had started
containers with a mount that pointed at nothing, which only showed up as `ENOENT`
inside the guest.

## Measured behaviour

| Run | Files | PASS | Tests | Errors | Skipped | Wall clock |
|---|---|---|---|---|---|---|
| primary (db in container `/tmp`) | 622 | 622 | 5,939,879 | 0 | 1,480,844 | 21 min 7 s at `--workers 3` |
| bind mount (db on the PVC) | 622 | 622 | 5,939,879 | 0 | 1,480,844 | 8 min 16 s at `--workers 3` |

Per-file samples: `evidence/in1.test` 214 tests in 2 s; a 4.8 MB
`index/between/100` file 10,121 tests in 4 s; `index/delete/10` files 16–20 s
each.

The primary path is about three times slower per file. The database location is
the only difference between the runs: on the primary path it sits on the
container's overlay, so a commit passes through the memfd shadow and the
writeback into the guest filesystem; on the bind mount it is a `hostfs` file.
The test totals are identical, so this is throughput, not correctness. It is
not yet isolated to one function.

The daemon log holds four lines for a whole sweep (startup). No writeback
failure, no `EFBIG`, no dropped connection.

## Rebuild and redeploy

LKL first, then kbox. The toolchain image `kbox-python/build:1` is plain
`ubuntu:24.04` plus `build-essential`, `python3`, `xxd`, `pkg-config`, `flex`,
`bison`, `bc`, `libelf-dev`.

```sh
# 1. LKL from the local fork tree (~4 min after the first build)
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp/home \
  -v /Users/san/Fun/tmp/2:/w -w /w/kbox kbox-python/build:1 \
  ./scripts/build-lkl.sh aarch64
# build-lkl.sh wants LKL_SRC=/w/lkl-src when the tree is not build/lkl-src

# 2. kbox release binary
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp/home \
  -v /Users/san/Fun/tmp/2:/w -w /w/kbox kbox-python/build:1 \
  sh -c 'make clean >/dev/null && make BUILD=release -j14'

# 3. Bump the tag in deploy/sqlite/kbox.yaml, then deploy
./scripts/run-sqllogictest-pod.sh deploy
```

Bump the image tag on every rebuild. `imagePullPolicy: IfNotPresent` with a
reused tag serves the cached image.

## Resetting

```sh
# containers only, images and corpus kept
kubectl -n kbox-sqlite exec deploy/kbox -c shim -- sh -c \
  'python3 - <<EOF
import json,urllib.request
ids=[c["Id"] for c in json.load(urllib.request.urlopen("http://127.0.0.1:2376/containers/json?all=1"))]
for i in ids: urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:2376/containers/"+i+"?force=1",method="DELETE"))
print(len(ids),"removed")
EOF'

# full reset: drops the corpus volume, so push again afterwards
kubectl -n kbox-sqlite delete pvc kbox-data
```

## Notes for the next run

1. **The corpus has no timeouts of its own.** A wedged guest is caught only by
   the driver's `--timeout`, which deletes the container. Keep it at 1800 s or
   below so one defect cannot consume a sweep.
2. **Per-file database directories are required for `--workers > 1`.** The
   runner unlinks `test.db` at startup, so two files in one directory would
   destroy each other.
3. **Corpus integrity** can be checked at any time with
   `git -C build/sqllogictest status --porcelain`; only the built binary is
   untracked.
4. **Databases are cleaned after each file** when `--db-dir` is under the mount.
   The PVC therefore stays near the corpus size.
5. **This workload does not test durability, locks, `mmap`, or processes.**
   See the closing section of `sqllogictest-report.md`.
