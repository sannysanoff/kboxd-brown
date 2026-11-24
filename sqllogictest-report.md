# sqllogictest corpus under kbox

Environment: local OrbStack Kubernetes, namespace `kbox-sqlite`, unprivileged
pod (uid 65534, every capability set empty, `allowPrivilegeEscalation: false`,
no service-account token). Pod image `kbox-sqlite/kbox:v7`, built from the pushed tree at `9371812`. Guest kernel
`Linux 6.8.0-kbox aarch64`, LKL from `sannysanoff/linux` commit `e7a0d32c9d`.

Workload: the SQLite sqllogictest corpus, 622 script files, 1,116,799,996
bytes, from `gregrahn/sqllogictest` commit `c93ac416` (7 October 2026, the
commit that merges the SQLite 3.54.0 sources). The runner is the corpus's own
`src/sqllogictest.c` linked against that commit's `src/sqlite3.c`, so the
engine and the expected results come from the same tree. A result mismatch
therefore points at the sandbox, not at engine drift.

The corpus is used unmodified. `git status --porcelain` in the fetched tree
lists only the built `sqllogictest` binary; every `.test` file is byte-identical
to the commit.

## Method

One container per script file, through the Docker Engine shim that fronts the
kbox daemon. The runner is compiled once, statically against musl:

```
gcc -static -O2 -DOMIT_ODBC=1 -DSQLITE_THREADSAFE=0 \
    -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_NO_SYNC=1 \
    -o sqllogictest src/sqllogictest.c src/md5.c src/sqlite3.c
```

Guest command, one per file:

```
mkdir -p /data/db/<container> && cd /data/db/<container> && \
  exec /data/sqllogictest -verify /data/test/<file> > /data/results/<file>.log 2>&1
```

`sqllogictest -verify` compares every result and returns the number of
mismatches as its exit status, so exit 0 is the perfect signal for a file and
any non-zero value is a real mismatch count.

Two storage paths were measured, because they reach different kbox code:

| Run | Database directory | What it exercises |
|---|---|---|
| primary | `/tmp` in the container | guest overlay, memfd shadow, writeback to the guest's own filesystem |
| bind mount | `/data/db` (pod volume) | `hostfs`-backed file, shadow writeback into the pod's volume |

The corpus scripts themselves are always read from the pod volume through the
bind mount, in both runs.

## Result

| Run | Files | PASS | FAIL | Tests executed | Errors | Skipped |
|---|---|---|---|---|---|---|
| primary, guest filesystem | 622 | 622 | 0 | 5,939,879 | 0 | 1,480,844 |
| bind mount, pod volume | 622 | 622 | 0 | 5,939,879 | 0 | 1,480,844 |

Timings on image `v7`: 21 min 7 s for the primary path, 8 min 16 s for the bind
mount, both at three files in flight.

Every file ran once in each run. Each run has its own summary
(`summary.tsv`) with one line per file and its log.

Both rows are from image `v7`, which contains the upstream hostfs and guest
ownership work merged with this harness. Each row is one single run with one
line per file.

The two paths differ in speed by about 3x, and only in speed: the primary path
sustained ~30 files per minute, the bind-mount path ~90. The database is the
only difference. On the primary path it lives on the container's overlay, so
each SQLite commit goes through the memfd shadow and its writeback into the
guest filesystem. On the bind mount it is a `hostfs` file. The corpus produces
the same results either way, so this is a throughput observation, not a
correctness defect; it is not yet isolated to a single cause.

The skip count is a property of the corpus, not of the sandbox. `skipif` and
`onlyif` records name other engines (MySQL, PostgreSQL, MSSQL) and kbox reports
itself as `SQLite`, exactly as the runner does on a native host.

## Control

The same binary and corpus run under plain Docker on the same machine produce
identical counts. Ten files sampled across `random/` and `index/`:

| File | Pod (tests / skipped) | Plain Docker |
|---|---|---|
| `index/between/1/slt_good_0.test` | 10022 / 0 | 10022 / 0 |
| `index/commute/100/slt_good_9.test` | 10123 / 0 | 10123 / 0 |
| `index/orderby/100/slt_good_2.test` | 10142 / 0 | 10142 / 0 |
| `index/random/10/slt_good_3.test` | 10034 / 2120 | 10034 / 2120 |
| `random/aggregates/slt_good_121.test` | 10012 / 3915 | 10012 / 3915 |
| `random/aggregates/slt_good_6.test` | 10012 / 3937 | 10012 / 3937 |
| `random/expr/slt_good_112.test` | 10012 / 5865 | 10012 / 5865 |
| `random/expr/slt_good_6.test` | 10012 / 5840 | 10012 / 5840 |
| `random/select/slt_good_10.test` | 10011 / 1521 | 10011 / 1521 |
| `random/select/slt_good_40.test` | 10010 / 1720 | 10010 / 1720 |

## Harness self-check

A mismatch cannot pass silently. A three-line script that asks for `2` from
`SELECT 1` reports:

```
/data/results/selftest.test:4: wrong result - expected [2] got [1]
1 errors out of 1 tests in /data/results/selftest.test - 0 skipped.
```

and the container exits 1. A container that exits 7 reports
`.State.ExitCode` 7 through the shim, so the driver reads the runner's own
status and not the shim's opinion of it.

## Defects found and fixed

| Defect | Fix |
|---|---|
| `scripts/build-lkl.sh` aborted with `sha256sum: ./include: Is a directory` when `lkl-aarch64/` held a header tree from an older layout, after the library had already been installed | the checksum step hashes regular files at the top level only |
| A short `-v` bind with a missing source started a container whose mount pointed at nothing; every access was `ENOENT` | the shim creates the source directory, as the Docker daemon does, and answers 400 when it cannot |
| A long `--mount` bind with a missing source started silently | the shim rejects it at create with Docker's `bind source path does not exist` wording |

No kbox daemon or LKL defect surfaced under this workload. The kernel paths the
corpus drives (hostfs reads of 1.1 GB of scripts, overlay and shadow writes of
SQLite pages, `pread`/`pwrite`, `ftruncate` on journal rollback, `unlink` of
temporary sort files, `fstat` of the database) all behaved as the native
control did.

## Volume path handling

The corpus binds the pod's `/data/slt` at `/data`, which is the existing-source
branch. The rest of the `-v` and `--mount` paths were probed directly, because
Compose files and scripts depend on them:

| Probe | Result |
|---|---|
| existing directory, read-only (`:ro`) | read succeeds, write answers `Read-only file system` |
| file as source (`sqllogictest:/bin/slt:ro`) | the static binary runs from the mount |
| named volume (`probevol:/x`) | data written in one container is readable in the next |
| relative source (`reldir:/x`) | treated as a named volume, as Docker does |
| missing source through `-v` | the directory is created on the pod and the container writes into it |
| missing source through `--mount` | create answers 400, `bind source path does not exist`, and no directory appears |

The last two rows failed before this work: `-v` produced a container whose mount
pointed at nothing, and `--mount` started silently. Both are now handled in the
shim, with unit tests, and the pod runs image `v7` with the fix.

## What the corpus does not cover

These are properties of the corpus, and they stay untested here:

- durability: the runner sets `PRAGMA synchronous=OFF` and links with
  `SQLITE_NO_SYNC=1`, so no `fsync` order is checked;
- concurrency: the runner uses one connection, so kbox's "advisory locks are
  always granted" shortcut is never contended;
- `mmap`: SQLite's default `mmap_size` is 0, so no mapped I/O;
- process lifecycle: no `fork`, `exec`, threads, or signals.

Those belong to the CPython suite results in `python-regression-report.md`.

## Repro

```sh
./scripts/fetch-sqllogictest.sh              # corpus + static runner (1.1 GB)
./scripts/run-sqllogictest-pod.sh deploy     # image, namespace, pod
./scripts/run-sqllogictest-pod.sh push       # corpus into the pod volume

# primary path, one container per file
./scripts/run-sqllogictest-pod.sh start --workers 3 --timeout 1800
./scripts/run-sqllogictest-pod.sh status

# bind-mount path, separate result set
kubectl -n kbox-sqlite exec deploy/kbox -c shim -- sh -c \
  'nohup python3 /usr/local/bin/slt-pod-driver.py --db-dir /data/db \
   --results /data/slt/results-bind --workers 3 --timeout 1800 \
   >> /data/slt/results-bind/driver.log 2>&1 &'

./scripts/run-sqllogictest-pod.sh collect slt-results
```

`status` prints `done=…` with a per-result breakdown, and the summary is
resumable: a later run skips every file already recorded as PASS unless
`--retry-failed` is given.
