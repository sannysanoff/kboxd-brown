# kbox / HALO hand-off — 2026-11-16 (agy)

Goal (from [halo-on-kbox.md](halo-on-kbox.md)): run the whole HALO stack inside `kbox` (k8s ns `nfs-test`, OrbStack) with unmodified official images, and verify login + Market Inspection price chart in a browser that also runs inside `kbox`.

Facts below are things I observed in tool output this session. Anything marked **(unverified)** is a hypothesis.

## 1. Where things stand

| Item | State |
|---|---|
| All HALO services inside kbox (`pgmain redis kafka clickhouse configmanager auth inspection search market-data-api ui`) | Running together on `kbox:v96` (last seen: all 10 `running`) |
| Login `POST /api/v1/auth/login` (admin@local.test / Passw0rd!) through ui nginx `:8088` | 200 + JWT (checked on an earlier pod, v93/v94-era) |
| `market-data-api` → ClickHouse | `general-trades-json` returned 180 rows for `PUBLIC:BINANCE BTC/USD` (from its log) |
| Browser inside kbox (`chromedp/headless-shell`) | Starts, prints `DevTools listening on ws://127.0.0.1:9223/...`, **then dies**: `GPU process launch failed: error_code=1002` x6 → `FATAL ... GPU process isn't usable`, exit 133 |
| Chart rendered in browser, zero failed API calls | **NOT DONE** |
| `make check-unit` | 282/282 C tests + 8/8 docker-engine tests passed on the last build (2 stale-looking warnings in dispatch-net.c/dispatch-exec.c are pre-existing compiler warnings, not failures) |
| lkl-src pushed | **YES** — `47bf7a1c0` → `fork/kbox` (https://github.com/sannysanoff/linux) |
| kbox pushed | **NO** — see §5 |
| halo-on-kbox.md updated with this session's results | **NO** |

## 2. Fixed this session (root causes, all in kbox `main`, commit `0000f63`, local only)

1. **ClickHouse exit 174** — `kboxd` runs as uid 65534, bind `/data/chdata` is owned by `nobody`, process started as root → `Code 430 MISMATCHING_USERS_FOR_PROCESS_AND_DATA`. `su`/`setpriv`/`chroot --userspec` all fail inside kbox (no privilege). Working launch: `Entrypoint ["clickhouse","su","65534:65534"]`, `Cmd ["clickhouse-server","--config-file=/etc/clickhouse-server/config.xml"]`, binds `/data/chdata:/var/lib/clickhouse`, `/data/chlog:/var/log/clickhouse-server`.
2. **Chromium `Writable and read-only inodes don't match; bailing`** — `fstat` on a writeback memfd shadow went to the host kernel (BPF `emit_fast_shadow_allow(..., fstat)` and `forward_fstat` CONTINUE) and returned the anonymous memfd's dev/ino, while the O_RDONLY reopen was an LKL fd with different dev/ino. Fix: removed fstat from the BPF fast-allow ([seccomp-bpf.c](../src/seccomp-bpf.c)); `forward_fstat` now takes identity from LKL and size/blocks from the live writeback memfd; read-only reopen/mmap of a file that has an active writeback shadow reuses that memfd via `/proc/self/fd` (`kbox_reopen_writeback_shadow_ro`, `kbox_find_active_writeback_shadow_sp` in [seccomp-dispatch.c](../src/seccomp-dispatch.c), used by `ensure_same_fd_shadow` and mmap in [dispatch-exec.c](../src/dispatch-exec.c)). Verified: error gone, browser reaches DevTools listening.
3. **Chromium `LaunchProcess: failed to execvp: /proc/self/exe`** — `forward_execve_impl` rejected `/proc/self/exe` (virtual path). Now resolves `/proc/self/exe` and `/proc/thread-self/exe` through `kbox_guest_exe_for()`, which also falls back to the thread-group leader and up to 4 ancestors in `exe_map` before `ctx->guest_exe` ([dispatch-exec.c](../src/dispatch-exec.c)). Verified: the execvp error is gone in the v96 browser log.
4. Pod memory limit `8Gi` → `12Gi` in [kbox.yaml](../deploy/nfs-test/kbox.yaml) (kboxd was OOMKilled, exit 137, twice). Image bumped to `kbox-nfs-test/kbox:v96`.
5. Earlier in the task (from my previous notes, not re-run today): LKL `container_rm` deadlock (`TIF_HOST_EXIT` in lkl-src), shadow-socket ABA race, `sendmmsg`, SOCK_DGRAM recvfrom/recvmsg race. Already in the same kbox commit range / pushed lkl commit.

## 3. Open problems, in the order I would attack them

### 3.1 Browser GPU process crash (blocker for the chart check)
Log tail (v96): `GPU process launch failed: error_code=1002` repeated, plus non-fatal `inotify_init() failed: Function not implemented (38)` and `Failed to recv from netlink socket: Bad file descriptor (9)`. Image `run.sh` adds `--use-gl=angle --use-angle=swiftshader`.
Ideas **(unverified)**: try `--disable-gpu --disable-software-rasterizer`, `--in-process-gpu`, `--single-process`; or find what the GPU child's syscall actually fails on (run kboxd with verbose / `KBOX_NET_TRACE`, look at the child's last refused syscall). Spawn via `/proc/self/exe` now works, so look at what the child does next (memfd/shm, socketpair, mmap of writable-shared memfd — `dispatch-exec.c` returns `ENODEV` for `MAP_SHARED|PROT_WRITE` on LKL files).
Container spec that currently starts: Entrypoint `["sh"]`, Cmd `["-c","socat TCP4-LISTEN:9222,fork TCP4:127.0.0.1:9223 & exec /headless-shell/headless-shell --no-sandbox --use-gl=angle --use-angle=swiftshader --disable-dev-shm-usage --remote-debugging-port=9223 --window-size=1440,900 '--host-resolver-rules=MAP localhost <ui_ip>'"]`. (Image's default entrypoint + extra `--remote-debugging-*` flags fails with "Multiple targets are not supported".) `ui_ip` must be read from the ui container after start; it changes per pod start.
Playwright image (`mcr.microsoft.com/playwright/python`) is too big: it OOM-killed kboxd (image store lives in `/dev/shm`, a 4 GiB tmpfs that counts against the pod limit; ~2.0–2.3 GiB already used).

### 3.2 Market Inspection chart data path
- `POST /api/v2/dashboard/charts-data` (inspection :8089) → 500: `SnowflakeConnectionFactory.getConnection` NPE (`Properties.put` with a null value) via `SnowflakeChartsDataRepositoryImpl.selectCandleData`. Inspection candle queries go to Snowflake, not ClickHouse; inspection `/actuator/health` is DOWN for the same reason (`snowflakeConnectivity`).
- The UI also calls `market-data-api` (`:8883` → `:8086`) for general trades (see `ng-solidus-tardis/.../market-data-api.service.ts`). Which of the two actually draws the price chart in this build is **unverified** — check in the browser's network log once 3.1 is solved. If the Snowflake path is required, options: feed the Snowflake properties with dummy non-null values to get past the NPE (still no data), or find a ClickHouse-backed switch/flag in market-inspection config.
- `GET /api/v2/dashboard/filters` and `filters-v2` → 404 "Solidus Client Storage error": inspection downloads `ranked-daily-volume/ranked-daily-volume-json.gz` from S3 (bucket `solidus-market-inspection-client-resources`) and gets 403 `InvalidAccessKeyId`. A local S3 (minio is in the local docker image cache; `quay.io/minio/minio:latest` was listed on the host) plus an endpoint override env would be the unmodified-image way — **(unverified)** that the SDK honors `AWS_ENDPOINT_URL`.
- `search` health is DOWN only because of `awsSdkV2S3Connectivity` (403); app itself runs.
- `/api/v3/dashboard/filters/getUserState` → 200 after the seeds in §4 (`privateData:true` after `system@1` was added). `/api/v1/orderbook/general-trades-json` needs `exchange, instrument, from, to, barsize` (from/to as `yyyy-MM-dd HH:mm:ss`, URL-encoded; `barsize=1m` worked).

### 3.3 configmanager Hikari/Kafka drops — not root-caused
Seen on the older pod: `HikariPool-1 Failed to validate connection ... (This connection has been closed.)` bursts (16:19, 16:21) and `Kafka AdminClient Node -1/1 disconnected` at 16:21:03, 16:26:03, and again 16:38:52 on a later pod (about 5 min cadence on the first one). No request failures were observed. Could be Kafka idle-connection reaping (**unverified**) or a kbox socket-retire bug in `net-slirp.c` (also unverified). Worth a targeted test: idle TCP client held open across container churn.

### 3.4 Smaller things
- After a kboxd restart the old container records stay `exited` and `DELETE` without `force=1` returns 409; stale names are reused fine once `force=1`-deleted. Cause not investigated.
- nginx `ui` logs `[emerg] io_setup() failed (1: Operation not permitted)` at start (aio); it still serves the SPA (wget returned the HTML).
- `scripts/build-lkl.sh` exits 1 at its final `sha256sum ./*` after installing `liblkl.a` (from my notes, not re-run today).
- Compiler warnings still present: `getenv` implicit decl was fixed by adding `<stdlib.h>`; remaining ones are `-Wpointer-sign` and `-Wformat-truncation` in dispatch-exec.c and a few in daemon.c.

## 4. How the stack is launched (what I used; there is no saved script)

All via the kbox docker API (inside the `kboxd` container: `http://127.0.0.1:2376`, python3 `urllib`; container logs are `/tmp/kboxd-logs/<full_id>.log` with Docker 8-byte frame headers). Persistent data on the PVC at `/data`.

| Container | Image | Notes |
|---|---|---|
| pgmain | `postgres:16` | Entrypoint `gosu nobody postgres -D /pgdata -c listen_addresses=* -c max_connections=200 -c unix_socket_directories=`, bind `/data/pgdata:/pgdata`; **delete `/data/pgdata/postmaster.pid` before start** after a kill. Creds postgres/admin. DBs `authdb configdb market_inspection advanced_search halo`. `psql` must be called as `/usr/lib/postgresql/16/bin/psql` |
| redis | `redis:7` | `redis-server --bind 0.0.0.0 --protected-mode no --save ""`. `FLUSHALL` after re-seeding (inspection caches) |
| kafka | `apache/kafka:3.9.0` | KRaft env as before + `KAFKA_HEAP_OPTS=-Xmx256m -Xms128m` and **`KAFKA_GC_LOG_OPTS=-Xlog:gc`** (default flags crash Java 21: `Unrecognized VM option 'PrintGCDateStamps'`) |
| clickhouse | `clickhouse/clickhouse-server:24.8` | see §2.1. Databases are not created by `/data/seed_ch_all.sql`: run `CREATE DATABASE abn_fsync0; CREATE DATABASE external_market_data;` first, then the seed (2160 rows each in `clear_trades2`, `public_clear_trades`, `clear_bbo_minutes`, `public_clear_bbo_minutes`). Data is on the PVC and survives restarts |
| configmanager | `eclipse-temurin:21-jre` | `java -Xmx320m -jar /app/cm.jar`, bind `/data/halo:/app:ro`; env datasource configdb, `KAFKA_BOOTSTRAPSERVERS=kafka:9092`, `SOLIDUS_SERVICE_AUTH_URL=http://auth:8088` |
| auth | same | `solidus-auth-service-0.0.4-SNAPSHOT.jar`; datasource authdb, redis, kafka, `AUTH_CLIENT_ENCRYPTION_HASH=my-test-secret`, config-manager + auth URLs |
| inspection | same | `solidus-market-inspection-1.0-SNAPSHOT.jar` (-Xmx448m); datasource market_inspection; `CLICKHOUSE_URL*` as `jdbc:clickhouse://clickhouse:8123/abn_fsync0` (shared market data: `/external_market_data`), user `default`, empty password; auth + config-manager URLs |
| search | same | `solidus-advanced-search-0.0.1-SNAPSHOT.jar`; `LOCAL_DB_*` + `SPRING_DATASOURCE_*` → advanced_search, `SPRING_FLYWAY_ENABLED=true`, **`CLICKHOUSE_URL=http://clickhouse:8123` (not jdbc:)** + `CLICKHOUSE_DB=abn_fsync0`, redis, dummy `SNOWFLAKE_*` |
| market-data-api | same | **`java -jar /app/market-data-api/solidus-market-data-api-1.0.335.jar`** (do not use `-cp .../lib/*`: it picks up `solidus-market-data-shared-*-tests.jar` and fails with duplicate `cleanDataSource` / missing `clickhouse.*`). Env: `SERVER_PORT=8086`, `CLICKHOUSE_URL=jdbc:clickhouse://clickhouse:9000/abn_fsync0` (native), `COM_CLICKHOUSE_URL=jdbc:clickhouse://clickhouse:8123/abn_fsync0`, `SHARED_CLICKHOUSE_{HOST,PORT=8123,DB=external_market_data,USERNAME,PASSWORD}`, redis, config-manager URL. Health `:8581/actuator/health` was UP |
| ui | `nginx:alpine` | binds `/data/ui:/usr/share/nginx/html:ro`, `/data/nginx-halo.conf:/etc/nginx/nginx.conf:ro` (source copy: `/Users/san/Fun/tmp/2/image/nginx-halo.conf`). One listener per backend port (8088 auth, 8089 inspection, 8084 search, 8078 configmanager, 8080 → auth, 8883 → market-data-api:8086); UI `env-var.json` uses `domain: localhost`, so the browser maps `localhost` to the ui container IP |
| browser | `chromedp/headless-shell:latest` | §3.1 |

Seeds done this session (all on the PVC, survive restarts):
- `market_inspection`: `exchange_symbols` (BINANCE/COINBASE/KRAKEN/PRIVATE for client `1`; BINANCE/COINBASE/PRIVATE for `TEST_CLIENT`), `client_package` (PREMIUM, kaiko on), `private_exchanges`.
- `configdb`: `solidus_client_ms_config` and `client_config` rows for `1` and `TEST_CLIENT` (without them inspection's classifier lookup failed).
- `authdb`: system user `system@1` (client `1`, `isSystemUser`, password hash copied from `/data/seed_sys.sql`, in permission group 2). Without a system user for client `1`, inspection got `401` on `/api/v1/internal/auth/system-login`.
- Earlier: `system@test.local` (TEST_CLIENT) + permission groups; admin@local.test.

## 5. Git state — read before pushing

- **lkl-src** (`/Users/san/Fun/tmp/2/lkl-src`, branch `master`): commit `47bf7a1c0` "lkl: Wait for TASK_DEAD before longjmping out of del_host_task" pushed to `fork/kbox`. Uncommitted and deliberately left alone: macOS case-collision files under `include/uapi/linux/netfilter*`, `net/netfilter/xt_*.c`, a litmus file, untracked `arch/lkl/kernel/vmlinux-fuzzing-postlink.lds`, `tools/lkl/stCYlNRl` (an `ar` archive).
- **kbox** (`/Users/san/Fun/tmp/2/kbox`, branch `main`): my commit is local `0000f63` ("Fix shadow DGRAM, fstat, and /proc/self/exe"). `origin/main` has 3 commits that local lacks (`00009af` Net: flush LKL IRQs once per pump pass; `0000e82` Recreate volume directories when starting a container; `0000cff` Fix guest write corruption, per-syscall latency, and shim bugs — touches `net-slirp.c`, `seccomp-dispatch.c`, `seccomp-supervisor.c`, `syscall-nr.[ch]`, `dispatch-misc.c`, shim scripts). Local has 46 commits origin lacks. **Expect merge conflicts** (not yet attempted).
- **Push is blocked by the `pre-push` hook**, not by git: `scripts/check-commitlog.sh` rejects 40+ older local commits ("Missing Change-Id (commit-msg hook bypassed)", some subjects > 72 chars, one WIP commit). My first `git push origin main` also failed with "Revision range start ... not found" because I had not fetched; after `git fetch` the range is the 46 local commits and they fail validation. A push to a new branch (`halo-kbox`) failed for the same reason. I did **not** bypass the hook. Options: (a) rebase onto `origin/main` and rewrite old commits through the commit-msg hook so they get Change-Ids / shorter subjects, (b) ask the repo owner whether those old commits may be exempted. Vanity-hash note: commits get a `0000` prefix rewritten by `post-commit`.
- Commit requirements learned: `pre-commit` runs clang-format (use `git clang-format` / `clang-format -i` on touched files, then re-stage), a security-pattern scan (a `printf`-family call whose format literal is on the *next* line is flagged — keep the literal on the call line), and cppcheck with the suppressions in `scripts/pre-commit.hook` (flagged and fixed: `duplicateCondition`, `unsignedLessThanZero`, `%d` vs `size_t`). Commit-message body lines > 72 chars only warn.

## 6. Build / deploy recipe (works)

```sh
# build + tests (Linux aarch64 via docker; mac host has no cross compiler)
docker run --rm -v /Users/san/Fun/tmp/2:/work -w /work/kbox ubuntu:24.04 bash -c \
 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc make python3 pkg-config xxd >/dev/null \
  && make -j8 && make check-unit && make BUILD=release clean && make BUILD=release -j8'
cp kbox/kbox image/kbox
docker build -t kbox-nfs-test/kbox:vNN image/
# bump image: in kbox/deploy/nfs-test/kbox.yaml (two places), then
kubectl apply -f kbox/deploy/nfs-test/kbox.yaml && kubectl -n nfs-test rollout status deploy/kbox
# new pod name: kubectl -n nfs-test get pods -l app=kbox   (the old pod stays Terminating for a bit — pick the Running one)
```
Gotchas: without `xxd`, `src/web-assets.c` is generated truncated and the build breaks — delete it and rebuild. A pod restart empties the container list, so the whole stack must be recreated (images stay cached on `/dev/shm` only until the pod dies, so they are pulled again — ~1–2 min). `ldd kbox` of the release build shows only libc + ld-linux.

## 7. Suggested next steps
1. Get the browser past the GPU crash (§3.1); drive it through CDP (`:9222`, `/json/version`) or a tiny client container; log in as admin@local.test, open Market Inspection (BTC/USD), record network failures, screenshot.
2. Resolve the chart data path (§3.2): S3 stub for `ranked-daily-volume`, and decide Snowflake vs market-data-api for candles.
3. Fix the git situation (§5) and push kbox; update [halo-on-kbox.md](halo-on-kbox.md) with the fixes in §2 and the run recipe in §4.
4. Re-run the idle-connection test for the configmanager drops (§3.3) once the stack runs under browser load.
