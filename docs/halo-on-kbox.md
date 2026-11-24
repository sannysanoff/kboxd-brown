# HALO on kbox — methodology and status

Working notes for the effort to run the full HALO stack inside kbox (LKL
sandbox under OrbStack) rather than natively. Written 16 November 2026.

## Goal

Every service of HALO runs inside kbox, unmodified official images are used
wherever an image is needed, seed data and a user exist in postgres, and market
inspection shows a price chart. Nothing runs natively; kbox is repaired instead
of bypassed.

## What runs today

In pod `kbox-5699b59bb5-*`, image `kbox:v88` (or `v87` for the pre-revert state):

* `pgmain` — official `postgres:16`, data directory on the PVC at `/data/pgdata`,
  started as `gosu nobody postgres -D /pgdata -c unix_socket_directories=`.
* `redis` — official `redis:7-alpine`, started as
  `sh -c 'exec redis-server --save ""'` because the image's entrypoint calls
  `setpriv`, which kbox refuses on a second identity change.
* `kafka` — official `apache/kafka:3.7.0` in KRaft mode, reaches
  `Kafka Server started`.
* `configmanager` — `Started SolidusConfigurationManagerApplication in ~25 s`,
  Tomcat on 8078 and 8181. Needs a live Kafka, otherwise it never binds.
* `auth` — `Started AuthServiceApplication in ~20 s`, Tomcat on 8088 and 31622,
  `HikariPool-1 - Start completed`. Requires `AUTH_CLIENT_ENCRYPTION_HASH` and
  `PASSWORD_MASTER`/`PASSWORD_MASTER_BACKUP`, none of which have defaults in the
  local profile.
* `inspection` — `Started SolidusMarketInspectionApplication in ~20 s`, Tomcat
  on 8089 and 8234, when postgres accepts JDBC connections.
* `ui` — official `nginx:alpine` with the tardis build mounted at
  `/data/ui` and our config at `/etc/nginx/nginx.conf`; `GET /` returns the
  application HTML.

Database work done: schema inspected (`user_account`, `user_account_password`,
`user_account_hash`), and the seed user's password set to a known value
(`UPDATE 1`, verification `MARK_1`).

## kbox defects found and fixed

Each was confirmed by a measurement, not by reasoning about the source.

1. **Blocking loopback connect was never finished.** LKL returns `EINPROGRESS`
   although both ends are in the same kernel; the tracee then polls a host
   socketpair that cannot see LKL's handshake, so the connect hung. The daemon
   now polls the LKL socket for `POLLOUT` and reports success only when no
   `POLLERR`/`POLLHUP` is set. Self-connections went from 80–83% to 20/20.
   Commit `0000072`.
2. **`epoll_ctl` on an untracked descriptor answered `EBADF`.** Every postgres
   backend registers the client socket inherited from the postmaster, that
   number has no fd-table entry, so the backend died before serving a query.
   The symptom surfaced only as `HikariPool-1 - Exception during pool
   initialization` and Flyway `EOFException`. The call is continued to the host
   now, which returns `EBADF` itself when the descriptor is truly invalid.
   postgres logs zero `epoll_ctl` failures and market inspection starts.
   Commit `0000455`.

Earlier fixes that stay: teardown of the process group on container stop,
`fcntl` answered locally for descriptors kbox owns, `sendfile` returning
`ENOSYS` instead of a plausible count with no data, private procfs per
container, `signalfd4` and SysV IPC handlers, a shadow only for read-only
low-fd redirects.

## Defects open

1. **Attaching a shadow to every accepted connection breaks ingress to Java
   services.** With that change (`0000374`) `auth` and `configmanager` accept a
   connection and never answer, while `nginx` works; a plain `GET` to auth timed
   out. Reverting it (`0000a67`) made auth answer `HTTP/1.1 404` again on the
   same build. So the change is wrong in this form; the epoll fix does not need
   it.
2. **Login does not complete yet.** With auth reachable, `POST
   /api/v1/auth/login` still hangs. The likely reason in the last run was that
   `configmanager` was not up: the auth flow calls `system-login` on it. This is
   the next thing to measure, not to guess.
3. **The Docker shim cannot serve locally built images.**
   `docker run kbox-nfs-test/halo-ui:v1` returns `HTTP Error 401: Unauthorized`
   because the shim proxies to a registry and has no notion of local images.
   Workaround in use: official `nginx:alpine` plus bind mounts.
4. **`psql` from a separate container is unreliable.** Its first attempt on a
   fresh pod works, later ones fail with `server closed the connection
   unexpectedly` and `could not receive data from client: Bad file descriptor`
   in the postgres log. Seeding succeeded by restarting the pod and running the
   SQL as the first connection.
5. **The Debian `psql` wrapper does not resolve in kbox**
   (`pg_wrapper: 11 was not found in /usr/lib/postgresql/16/bin`). Use
   `/usr/lib/postgresql/16/bin/psql` or `--entrypoint`.

## Methodology that worked

* **Measure a distribution, never a single run.** The self-connect probe scores
  1/10 in one run and 10/10 in another on the same binary. Every conclusion
  drawn from one number was wrong.
* **Write probe results to a bind-mounted file** and read it from outside, or
  `docker exec` into the container. `/tmp/kboxd-logs/<name>.log` is not named by
  the id `docker run` prints, so grepping `<id>.log` silently reads another
  container's log and invents a phantom bug.
* **Trace in the daemon and read the trace literally.** The decisive findings
  came from two lines: `connect ret lkl_fd=… -> 0` and
  `epoll_ctl EBADF epfd=11 lkl_ep=-2 fd=15 lkl_fd=-1`. Add the trace where the
  branch is taken, and put it before any early return, or it will not fire.
* **Distinguish "connection refused" from "timeout" from "empty answer".**
  Refused means nothing listens, timeout means the listener never receives the
  connection, empty means the service answered badly. Each pointed at a
  different layer.
* **Revert to isolate.** The shadow regression was found by reverting one commit
  and re-measuring, not by reading the diff.
* **A fresh pod is part of the experiment.** Connection handling degrades as a
  pod ages, so a test that must succeed is run first after a pod restart.
* **Official images only where possible**, and when one needs a flag, change the
  command, not the image: `-c unix_socket_directories=`, `exec redis-server`,
  `LD_LIBRARY_PATH` for the Corretto image.

## Concerns

* kbox's container API shim is the least reliable part of the stack: it has gone
  silent (`docker ps` empty), mis-associated logs and ids, refused local images,
  and rejected `docker run` with arguments. Every one of these produced a false
  diagnosis before it was understood.
* Connection handling is not stable over the life of a pod, and the cause is not
  identified. Until it is, any test run has to be judged against a fresh pod.
* Nothing is pushed. All kbox work lives in local commits on `sannysanoff/kbox`
  (`0000455`, `0000a67`, `0000072`, `0000cdd`, `0000f8d`, `0000c39`, `00009b2`,
  `0000053`, `0000d0a`, `00007a2`) and needs a review pass before it goes
  anywhere.
* LKL runs one CPU; the HALO stack is nine JVMs on top of it. Even after every
  defect is fixed, this will be slow, and that is a property of the sandbox, not
  a bug.
* The screenshot still depends on a browser inside kbox. Public images with
  Chromium exist, but driving the login form needs automation, and that is new
  surface rather than a repair.
