# Handover: testing Python under kbox (`kbox-python` namespace)

Written 17 November 2026, after building kbox from source and deploying it to
local OrbStack. This file is for the process that will test Python inside kbox
extensively. It states what is measured, what is a shim limitation, and how to
get evidence.

## State of the deployment

| Item | Value |
|---|---|
| Namespace | `kbox-python` |
| Deployment / file | `kbox` in [`deploy/python/kbox.yaml`](deploy/python/kbox.yaml) |
| Pod image | `kbox-python/kbox:v2` (built locally, `imagePullPolicy: IfNotPresent`) |
| Pod | `kubectl -n kbox-python get pods`, 2/2 Running, 0 restarts |
| Containers in pod | `kboxd` (LKL daemon) and `shim` (Docker Engine API on 2376) |
| LKL | `sannysanoff/linux` master, commit `54accd5c2`, built by `scripts/build-lkl.sh` |
| kbox | `make BUILD=release`, linux/arm64, in `kbox-python/build:1` |
| Guest kernel | `Linux 6.8.0-kbox aarch64` (`os.uname()` inside a container) |
| Privileges | uid 65534, CapInh/Prm/Eff/Bnd all `0000000000000000`, `Seccomp: 2` |

The nightly `liblkl.a` from the `lkl-nightly` release does **not** work here. It
lacks `CONFIG_BRIDGE` and `CONFIG_VETH`, so kboxd exits with
`failed to create br0: -95 (Operation not supported)`. Build LKL from source.

## How to drive it

The shim speaks the Docker Engine API over plain TCP. Two access paths:

```sh
# From the Mac host (what this session used).
kubectl -n kbox-python port-forward pod/<pod> 12376:2376
docker context create kbox-python-e2e --docker host=tcp://127.0.0.1:12376
docker --context kbox-python-e2e info     # Server Version: 29.0.0-kbox
```

The context `kbox-python-e2e` already exists on this Mac. The port-forward dies
with the terminal; recreate it after a pod restart, then reuse the context.

```sh
# From inside the pod, no forward needed: python3 is in the image.
kubectl -n kbox-python exec deploy/kbox -c kboxd -- python3 -c \
  'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:2376/version").read())'
```

Kernel traces and container lifecycle lines are in the `kboxd` log. The shim
writes one log per container exec under `/tmp/kboxd-logs/` inside the pod.

```sh
kubectl -n kbox-python logs deploy/kbox -c kboxd --tail=50
kubectl -n kbox-python logs deploy/kbox -c shim --tail=50
```

`kboxd` runs with `-v`, so its log carries every intercepted syscall
(`seccomp notify syscall: pid=… nr=…`). Expect noise; filter by pid.

## Measured behaviour

Host image `python:3.12-alpine`, pulled by the shim from Docker Hub. Every row
below was run in this namespace.

| Test | Result |
|---|---|
| `docker run --rm python:3.12-alpine python -c 'print("hello world")'` | prints `hello world`, 3/3 runs |
| `python --version` | `Python 3.12.16` |
| `os.uname()` | `Linux 6.8.0-kbox aarch64` |
| Environment and workdir (`-e`, `-w`) | honoured |
| `docker inspect`, `docker ps -a`, `docker logs`, `docker images` | work |
| Named container exit 3 | `.State.ExitCode` = 3, `docker wait` = 3 |
| `docker exec` into a running container | works |
| `pip install --no-cache-dir requests` (pypi over TLS) | exit 0 |
| `pip install --no-cache-dir flask` as the container command | exit 0 |
| sqlite3 in-memory DDL, insert, select | PASS |
| 4 threads × 2000 increments | PASS, counters exact |
| `asyncio.run` + `asyncio.sleep` | PASS |
| `os.fork` + `waitpid` | PASS |
| `subprocess.run` of a python child | PASS |
| Loopback TCP in one container (server thread + client) | PASS |
| HTTPS to `https://pypi.org/simple/` with default CA bundle | 200 |
| Bind mount `-v /data:/mnt:ro` (pod path) | works, file readable |
| Named volume across two containers | data persists |
| Container-to-container by name, `http://pysrv:8000/` | `GET 200` |
| Published port `-p 18081:8000`, fetched from inside the pod | 200 |

The nine-item python probe that produced the sqlite/thread/asyncio/fork/TCP row
is at `/tmp/pyprobe.py` on this Mac; it is also copied to `/data/pyprobe.py` in
the pod. Run it again with:

```sh
docker --context kbox-python-e2e run --name pyprobe -v /data:/mnt:ro \
  python:3.12-alpine python /mnt/pyprobe.py
docker --context kbox-python-e2e wait pyprobe
docker --context kbox-python-e2e logs pyprobe
```

## Shim limitations to design the tests around

These are properties of `scripts/kbox-dockerd.py`, not of LKL. Measure them
again before you build a conclusion on them.

1. **Attached stdout can be empty.** Several `docker run` calls printed nothing
   while the container worked. Always pass `--name`, then read
   `docker logs <name>`. Do not treat empty output as failure.
2. **`docker run` exit status is 0 even when the container fails.** It returned
   0 for a container that exited 3. Read `docker wait <name>`, or
   `docker inspect -f '{{.State.ExitCode}}' <name>`.
3. **`-i`/stdin is not forwarded.** `echo x | docker run -i … python -c
   'print(sys.stdin.read())'` printed an empty line.
4. **`sh -c 'pip install …'` fails with EACCES.** The error is
   `Permission denied: '/dev/shm/kbox-exec-links/<n>/python3.12'`: when `sh`
   execs the `pip` console script, the interpreter is rewritten to a path under
   `/dev/shm/kbox-exec-links`, and pip then cannot write it. Workaround that
   worked: `sh -c 'python -m pip install …'` (verified once, exit 0) or run
   `pip` as the container command instead of behind `sh -c`.
5. **No `docker build`, `docker load`, `docker cp`, or registry push.** Pull by
   tag or digest only. Built images must reach the pod through a registry.
6. **Bind mount sources are pod paths.** The shim runs without `--path-map`
   here, so `-v /data:/mnt` means the pod's `/data` (an `emptyDir`), not a
   Mac path. Mounts are read from the pod filesystem, which is why
   `kubectl cp` into `/data` is the way to hand a script to a container.

## Resource envelope

| Resource | Value | Consequence |
|---|---|---|
| `mem=` cmdline for LKL | `6144M` | guest RAM ceiling |
| Pod memory limit | `12Gi` | kboxd plus every guest process |
| `/dev/shm` `emptyDir` | `8Gi`, `medium: Memory` | holds the image store (`HOME=/dev/shm`) and exec links |
| `/data` `emptyDir` | node disk | shim state at `/data/kbox-dockerd`, scripts for tests |
| Container image size | `python:3.12-alpine` is 18.5 MB | heavy images (numpy wheels, playwright) consume the 8 GiB tmpfs |

A pod restart empties `/dev/shm` and `/data`: the image list goes back to zero
and every image is pulled again. That is the fast reset path.

```sh
kubectl -n kbox-python rollout restart deploy/kbox
kubectl -n kbox-python rollout status deploy/kbox
```

For a lighter reset, delete containers and keep images:
`docker --context kbox-python-e2e rm -f $(docker --context kbox-python-e2e ps -aq)`.

## Rebuild and redeploy

The current Mac clone is `/Users/san/Fun/kbox`, on `main`. The HALO experiments
live in `/Users/san/Fun/tmp/2`; they are a different tree and must not be mixed
in.

```sh
# 1. LKL from source (~3 min; produces lkl-aarch64/liblkl.a)
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/work/.home \
  -v "$PWD:/work" -w /work kbox-python/build:1 ./scripts/build-lkl.sh aarch64

# 2. kbox release binary
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/work/.home \
  -v "$PWD:/work" -w /work kbox-python/build:1 make BUILD=release -j8

# 3. Pod image from a small staging context (do not send the repo itself)
rm -rf .deploy-image && mkdir .deploy-image
cp deploy/python/Dockerfile .deploy-image/Dockerfile
cp kbox .deploy-image/kbox
cp scripts/kbox-dockerd.py .deploy-image/kbox-dockerd.py
docker build -t kbox-python/kbox:v3 .deploy-image
rm -rf .deploy-image

# 4. Deploy
sed -i '' 's|kbox-python/kbox:v2|kbox-python/kbox:v3|g' deploy/python/kbox.yaml
kubectl apply -f deploy/python/kbox.yaml
kubectl -n kbox-python rollout status deploy/kbox
```

The toolchain image `kbox-python/build:1` is `ubuntu:24.04` with
`build-essential` (plain `gcc` has no libc headers there), `python3`, `xxd`,
`pkg-config`, `flex`, `bison`, `bc`, `libelf-dev`.

## What "extensive Python testing" should still cover

These are open points, not measured facts:

1. **ASGI and WSGI servers under load.** uvicorn (asyncio), gunicorn (fork
   workers), Flask and FastAPI with a real request loop, not one request.
2. **Concurrency at scale.** `concurrent.futures` thread and process pools,
   `multiprocessing` queues and locks, `asyncio` with many tasks and sockets.
3. **Signal handling.** `SIGTERM`/`SIGINT` delivery to the guest, the
   `kboxd` teardown path, and whether a container reaps its children.
4. **Timer fidelity.** `time.sleep`, `time.monotonic`, `select`/`epoll`
   timeouts and their skew under load.
5. **Filesystem semantics.** `os.replace` atomicity, `flock` on shared files,
   sqlite WAL mode on a bind mount, `stat` fields (`st_dev`/`st_ino`) as seen
   through `/proc/self/fd`.
6. **Native wheels.** numpy and pandas under musl (alpine) and manylinux
   (slim). Wheel size against the 8 GiB `/dev/shm` budget.
7. **Memory.** Resident growth of a long-running python process, `gc` heartbeat
   thread, and whether kboxd survives `MemoryError` and OOM within the pod
   limit.
8. **Stability over pod age.** Earlier kbox work found connection handling
   degrading as a pod aged. Record pod age with every network result, and
   repeat a failing measurement on a fresh pod before filing a defect.
9. **Stdin, exit codes and logs at scale.** Confirm limitations 1–4 above on
   many runs, so the test process knows which ones are deterministic.

## Files added by this work

| Path | Purpose |
|---|---|
| `deploy/python/Dockerfile` | pod image: kbox, shim, python3, ca-certificates |
| `deploy/python/kbox.yaml` | ConfigMap, Deployment, Service in `kbox-python` |
| `handover-kbox-python.md` | this file |

Both are untracked in git on `main`. The LKL source tree is `build/lkl-src`
(gitignored); the discarded nightly download is `lkl-aarch64.nightly/`.
