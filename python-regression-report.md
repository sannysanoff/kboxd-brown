# CPython 3.12 regression suite under kbox

Environment: local OrbStack Kubernetes, namespace `kbox-python`. The two full
sweeps below ran on pod image `kbox-python/kbox:v22`; each later section names
the image and the LKL commit it was re-checked with (latest `v71`, LKL
`e7a0d32c9d`). The pod is unprivileged (uid 65534, all capability sets empty,
`Seccomp: 2`). Guest kernel `Linux 6.8.0-kbox aarch64` (LKL from
`sannysanoff/linux`).

Workload: CPython 3.12.16 `Lib/test`, merged over the image's stdlib and mounted
at `/usr/local/lib/python3.12`. Every module is run in its own container so one
hang costs one module:

```
python3 -m test -q --timeout 120 <module>
```

Two environments:

| Run | Command | Guest workdir / TMPDIR |
|---|---|---|
| internal filesystem | `docker run python:3.12-alpine` (LKL ext4 rootfs) | `/tmp` |
| mounted volume | same, plus `-v /data:/data` (pod disk, btrfs) | `/data/tmp` |

Baseline for classification: the same suite under plain Docker
(`python:3.12-alpine`, no kbox) — 28 modules, 8 failures. Anything that fails
there is environment, not kbox.

## Result

Two full sweeps of 438 modules each were run on the same binary
(`kbox-python/kbox:v22`), one on the guest's internal filesystem and one on the
pod's bind-mounted volume.

| | internal filesystem | mounted volume |
|---|---|---|
| modules PASS | 405 | 408 |
| modules FAIL | 32 | 29 |
| modules with no result | 1 WEDGED (`test_socket`) | 1 WEDGED (`test_socket`) |
| tests executed | 37,483 | 37,483 |
| tests failed | 152 | 132 |
| tests skipped | 1,349 | 1,277 |
| pass rate of executed | 99.59 % | 99.65 % |
| modules aborted by the 120 s per-test timeout | `test_asyncio`, `test_capi`, `test_logging`, `test_multiprocessing_forkserver`, `test_posix`, `test_ssl` | same six |

Modules that fail in either environment:

| module | internal fs | mounted volume | plain Docker |
|---|---|---|---|
| `test__locale` | FAIL | FAIL | PASS |
| `test_asyncio` | FAIL | FAIL | PASS |
| `test_c_locale_coercion` | FAIL | FAIL | FAIL |
| `test_capi` | FAIL | FAIL | FAIL |
| `test_ctypes` | FAIL | FAIL | FAIL |
| `test_curses` | FAIL | FAIL | PASS |
| `test_epoll` | FAIL | PASS | PASS |
| `test_import` | PASS | FAIL | PASS |
| `test_io` | FAIL | PASS | PASS |
| `test_largefile` | FAIL | PASS | PASS |
| `test_locale` | FAIL | FAIL | FAIL |
| `test_logging` | FAIL | FAIL | PASS |
| `test_multiprocessing_fork` | FAIL | FAIL | PASS |
| `test_multiprocessing_forkserver` | FAIL | FAIL | PASS |
| `test_multiprocessing_spawn` | FAIL | FAIL | PASS |
| `test_netrc` | PASS | FAIL | PASS |
| `test_os` | FAIL | FAIL | FAIL |
| `test_ossaudiodev` | FAIL | FAIL | FAIL |
| `test_pathlib` | FAIL | PASS | PASS |
| `test_posix` | FAIL | FAIL | PASS |
| `test_re` | FAIL | FAIL | FAIL |
| `test_smtpnet` | FAIL | FAIL | FAIL |
| `test_socket` | WEDGED | WEDGED | PASS |
| `test_socketserver` | FAIL | FAIL | PASS |
| `test_sqlite3` | FAIL | PASS | PASS |
| `test_ssl` | FAIL | FAIL | PASS |
| `test_strptime` | FAIL | FAIL | PASS |
| `test_subprocess` | FAIL | FAIL | PASS |
| `test_tarfile` | PASS | FAIL | PASS |
| `test_time` | FAIL | FAIL | PASS |
| `test_urllib2net` | FAIL | FAIL | PASS |
| `test_urllibnet` | FAIL | FAIL | PASS |
| `test_winsound` | FAIL | FAIL | PASS |
| `test_xmlrpc_net` | FAIL | FAIL | PASS |
| `test_zipfile` | FAIL | PASS | PASS |
| `test_zipfile64` | FAIL | FAIL | PASS |


### The launcher's stack overflow (`v72`)

The merged tree added fields to `struct kbox_fd_entry` (the recorded peer address
here, the fd-handling fields upstream), and that pushed two launcher frames past
the 8 MiB default stack. Only the release build showed it.

```
$ ./kbox --syscall-mode=seccomp --net -r py312f.ext4 -- /bin/echo hi
kbox: net: initialized (10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3)
Segmentation fault
```

The same command works in the debug build (default `-O0` plus sanitizers, prints
`hi`) and in the pod, whose daemon path calls a smaller callee. It dies with
either guest image, so the image is not the variable, and the build mode is.

gdb shows the fault at the first statement of the supervisor, with a corrupt
backtrace and garbage in the argument registers:

```
#0  kbox_run_supervisor_volumes (sysnrs=0xaaaaab634ae0 <SYSNRS_GENERIC>,
    command=0xffffffffff5f "/bin/echo", args=0xfffffffffd40, nargs=1,
    host_root=0x0, exec_memfd=11, verbose=0, root_identity=0,
    normalize=-2528, web=0xaaaaaaefbff0, host_binds=0xffffffa6e020,
    host_bind_count=281474792161536) at src/seccomp-supervisor.c:737
Backtrace stopped: previous frame identical to this frame (corrupt stack?)
```

Raising the limit fixes it, which names the mechanism:

| stack limit | result |
|---|---|
| `ulimit -s 8192` (default) | `Segmentation fault` |
| `ulimit -s 65536` | `hi`, clean exit |
| `ulimit -s unlimited` | `hi`, clean exit |

`-fstack-usage` at `-O2` gives the two frames that do not fit together:

| function | frame |
|---|---|
| `kbox_run_image` (with `run_trap_launch` inlined) | 5 682 992 B |
| `kbox_run_supervisor_volumes` | 5 143 664 B |

10.3 MiB of frames on an 8 MiB stack. The floor under both is
`struct kbox_fd_table`, which is an array of `struct kbox_fd_entry`
(`KBOX_FD_TABLE_MAX + KBOX_MID_FD_MAX + KBOX_LOW_FD_MAX` of them, 120 bytes
each, 4 718 616 B total) plus `struct kbox_supervisor_ctx` (424 776 B). Both were
locals; both live for the life of the process, so they now come from `calloc()`
in `kbox_run_supervisor_volumes`, `run_trap_launch` and `run_rewrite_launch`.

After the change the largest frame of the three is 963 584 B
(`kbox_run_image`), and the release build runs with the default stack:

```
$ ulimit -s; ./kbox --syscall-mode=seccomp --net -r py312f.ext4 -- /bin/echo hi
8192
hi
kbox: net: cleaned up
```

| check | result |
|---|---|
| `make check-unit` | 298 C tests, 26 python tests, all pass |
| local `test_socket` `test_ssl` `test_epoll` `test_io` `test_logging` `test_largefile` | 1 850 tests, 163 skipped, 1 failure |
| local `test_asyncio` | 2 577 tests, SUCCESS |

The one failure is `test_ssl.test_get_server_certificate_timeout`:
`ssl.get_server_certificate()` reached `getpeercert()` → `getpeername()` and got
`OSError: [Errno 107] Socket not connected` on a socket it had just connected.
Run alone the test passes 5 of 5, so it is the known `getpeername` /
`sock_established` area, not the stack change: the fix only moved two
allocations from the stack to the heap.

The daemon path still keeps the same pair on its container thread's stack
(`launch_and_supervise_proc`, 5 154 272 B). It fits today because it calls
`kbox_supervise_ctx` rather than the supervisor launcher, and it is left alone
because no failure has been observed there.

### The merged branch and the current LKL in the pod (`v71`)

`v71` is the first image built from the merged tree: kbox `84f2e09` (the local
descriptor and socket work merged with 12 upstream commits that bring the host
layer cache, per-container cgroups, host networking and their `sendfile`
changes) on top of LKL `e7a0d32c9d` (hostfs xattrs, hostfs tmpfiles and
unprivileged whiteouts, overlayfs `userxattr` whiteouts, hostfs `chown` through
`user.kbox.owner`). The LKL rebuild was required: the merged kbox mounts host
directories through `hostfs`, which the previous `liblkl.a` did not have.

One container per module, `python3 -m test -q --timeout 180`:

| module | tests run | skipped | duration | result |
|---|---|---|---|---|
| `test_ssl` | 188 | 16 | 20.7 s | SUCCESS |
| `test_epoll` | 10 | 0 | 0.13 s | SUCCESS |
| `test_socket` | 732 | 117 | 51.8 s | SUCCESS |
| `test_asyncio` | 2 577 | 54 | 1 min 19 s | SUCCESS |
| `test_largefile` | 16 | 6 | 0.04 s | SUCCESS |
| `test_io` | 644 | 18 | 12.9 s | SUCCESS |
| `test_logging` | 260 | 4 | 19.8 s | SUCCESS |
| `test_ssl` (repeat) | 188 | 16 | 20.7 s | SUCCESS |

4 615 tests executed, 231 skipped, 0 failed. Earlier these seven modules cost a
pod restart each (`test_socket` wedged the shim, `test_asyncio` and `test_ssl`
aborted by the per-test timeout); this is the first sweep in which all of them
complete in one pass.

Two defects from the open list do not reproduce:

- **`test_asyncio`, the sendfile wedge.** The module no longer sits in
  `_sock_sendfile_native_impl` for the whole budget: 2 577 tests finish in
  79-81 s. It is still flaky in the pod, at a much lower rate: 3 of 21
  full-module runs end at the 180 s per-test timeout. Two distinct stacks were
  captured:

  ```
  File "/usr/local/lib/python3.12/test/test_asyncio/test_unix_events.py", line 513 in run_loop
  File "/usr/local/lib/python3.12/test/test_asyncio/test_unix_events.py", line 528 in cleanup

  File "/usr/local/lib/python3.12/asyncio/unix_events.py", line 397 in _sock_sendfile_native_impl
  File "/usr/local/lib/python3.12/test/test_asyncio/test_unix_events.py", line 579 in test_sock_sendfile_cancel1
  ```

  The first waits for `connection_lost` from `proto.wait_closed()`, the second is
  inside the synchronous `os.sendfile` that `test_sock_sendfile_cancel1` calls
  before the event loop is running. Eight further full-module runs and 200
  repetitions of `SelectorEventLoopUnixSockSendfileTests` alone did not
  reproduce either, so neither is a property of that test class by itself. Row
  kept open, with the new rate.

- **`test_largefile`, `EFBIG` on the pod rootfs.** Same counts as the failing
  runs (`run=16 skipped=6`), now SUCCESS in three separate runs, and the whole
  pod log for the sweep contains no `writeback failed` and no `-27`:

  ```
  $ grep -c "writeback failed" kboxd.log        → 0
  $ grep -c "EFBIG\|: -27"     kboxd.log        → 0
  ```

  The mechanism is **not** isolated and is not claimed here. `EFBIG` comes from
  `inode_newsize_ok` (`fs/attr.c`) either through `rlimit(RLIMIT_FSIZE)` or
  through `s_maxbytes`, and both filesystems in the path declare
  `MAX_LFS_FILESIZE` in this tree (`fs/hostfs/hostfs_kern.c:1347`,
  `fs/overlayfs/super.c:1350`), so the limit that answered `-27` was attached to
  the task the copy-back ran on, not to the destination filesystem. What changed
  between `v70` and `v71` in that area is the LKL rebase and the upstream image
  and layer handling.

The pod log of the sweep also records these, none of which fails a test:

```
kbox: net: close drained lkl=15 after 5s, dropping to_lkl=160 to_sup=0
kbox: net: close drained lkl=16 after 5s, dropping to_lkl=576 to_sup=0
kbox: syscall pid=3280 nr=278 (getrandom) not returned after 5s; the guest waits
kbox: answer lost pid=18682 nr=222 (mmap): No such file or directory
kbox: answer lost pid=13277 nr=59 (pipe2): No such file or directory
```

- `close drained ... dropping` is the documented cap at `net-slirp.c:908`
  (`KBOX_CLOSE_DRAIN_NS`): when the bridge cannot hand the rest to LKL within
  5 s, the LKL socket is closed and the queued bytes are dropped. Two transfers
  lost 160 and 576 bytes this way. It is a data-loss path for a slow peer, not a
  defect of a test.
- `answer lost` is explained at `seccomp-supervisor.c:477`: `ENOENT` means the
  tracee died between the receive and the answer, `EBADF` means a thread exit
  invalidated the notification. The loop continues in both cases.
- `getrandom` stalled for 6 s once and then returned.

### Re-check of every previously failing module (`v71`)

One container per module on `v71`, `python3 -m test -q --timeout 180`, then a
plain `python:3.12-alpine` run of the same module with the same suite for
classification. Plain Docker is the baseline: a module that fails there is the
environment, not kbox.

| module | `v71` (tests / failed) | plain Docker | verdict |
|---|---|---|---|
| `test_epoll` | 10 / 0 | PASS | fixed |
| `test_import` | 104 / 0 | PASS | fixed |
| `test_io` | 644 / 0 | PASS | fixed |
| `test_largefile` | 16 / 0 | PASS | fixed |
| `test_logging` | 260 / 0 | PASS | fixed |
| `test_netrc` | 22 / 0 | PASS | fixed |
| `test_socket` | 732 / 0 | PASS | fixed |
| `test_ssl` | 188 / 0 | PASS | fixed |
| `test_tarfile` | 633 / 0 | PASS | fixed |
| `test_zipfile` | 344 / 0 | PASS | fixed |
| `test_asyncio` | 2 577 / 0 (rerun) | PASS | fixed at this rate, see the flake row |
| `test_time` | 62 / 1 | PASS | fixed afterwards, see below |
| `test__locale` | 6 / 86 | FAIL, 86 | environment: musl locale data |
| `test_posix` | 167 / 1 | FAIL, 1 | environment: musl `os.major(-1)` |
| `test_strptime` | 56 / 8 | FAIL, 8 | environment |
| `test_pathlib` | 609 / 3 | PASS | kbox: `Path.is_mount()` |
| `test_subprocess` | 341 / 5 | PASS | kbox: stdio redirection |
| `test_multiprocessing_fork` | 395 / 2 | PASS | kbox: fd transfer |
| `test_multiprocessing_spawn` | aborted | PASS | kbox: `dup()` answered `EBUSY`, then `SIGSEGV` |
| `test_multiprocessing_forkserver` | RUNBLOCKED, twice | PASS | kbox: wedges the shim |
| `test_sqlite3` | 474 / 1 | PASS | known: advisory locks are always granted |
| `test_concurrent_futures` | aborted | PASS | kbox: `SIGSEGV` in the parent |
| `test_socketserver` | 0, NO TESTS RAN | PASS | environment: no terminal |
| `test_zipfile64` | 0, NO TESTS RAN | PASS | environment: needs big memory |

`test__locale`, `test_posix` and `test_strptime` were listed as kbox defects in
the older tables; the baseline run says they fail without kbox too. They are
moved to the deviations section.

Two results need repeating rather than reading: `test_asyncio` was RUNBLOCKED in
the sweep and passed in 82 s when re-run alone, and
`test_multiprocessing_forkserver` was RUNBLOCKED twice. RUNBLOCKED means the
shim refused to start the container for 90 s, which is a wedged daemon, and the
forkserver module is the module that wedges it: after it runs, `docker run` does
not return until the pod is restarted.

The remaining kbox failures group into three areas, each with its own evidence:

- **Stdio redirection into a child.** `subprocess.Popen(..., stdout=filedes)`
  and the five related tests raise `OSError: [Errno 9] Bad file descriptor`
  from `_execute_child`.
- **Passing a descriptor to another process.** `test_fd_transfer` writes `b"foo"`
  through a descriptor received over SCM_RIGHTS and the file stays empty
  (`AssertionError: b'' != b'foo'`); the same shape fails for the >256 case.
  `test_multiprocessing_spawn` additionally answered `dup()` with `EBUSY`
  (`socket.fromfd` → `dup` in `resource_sharer.send`). The forkserver module
  stops in `multiprocessing.heap.Arena.__init__` with `OSError: [Errno 9] Bad
  file descriptor` from `mmap.mmap(self.fd, self.size)`; the arena's descriptor
  comes from `mkstemp` and `os.unlink`, so it is a kbox shadow file that is
  mapped after it lost its name.
- **`Path.is_mount()`** answers true for a regular file
  (`assertFalse((P / 'fileA').is_mount())` fails), three times: kbox resolves
  `lstat("fileA/..")` instead of failing with `ENOTDIR`, so the parent's inode
  differs from the file's and the path looks like a mount point.

### Writeback ordering and the stale copy size (`v70`)

The older open defect `test_io.test_threads_write` (a file 10 bytes short while
every write returned its full length, sizes seen by the readers going
190, 130, 130, 190, 30) does **not** reproduce on the current binary: 60 of 60
single-test runs and 20 of 20 full `test_io` runs pass. The later writeback
changes (pread instead of read, copy by extent, retry on EINTR, flush on thread
exit, copy on its own thread) had already removed the symptom.

The mechanism behind it was still in the code, and a trace shows it is live:

```
kbox: writeback size lkl_fd=1 queued=40 now=60
```

A copy-back is queued with the size the shadow had at that moment and runs on a
thread. A thread exit and a `close` of the same file each queue one, so two jobs
can overlap with different sizes, and the older job finishing last called
`ftruncate(lkl_fd, 40)` on a shadow that now holds 60 bytes. Fix: the copy takes
the shadow's current size when it starts. The shadow is the authority and only
the guest can shrink it, so its current size is the size the guest expects.

| check | result |
|---|---|
| `test_io` (whole module) | 644 tests, SUCCESS |
| `test_largefile` + `test_zipfile` | 360 tests, SUCCESS |
| `make check-unit` | 298 C tests and 12 python tests pass |
| stale sizes observed in one `test_io` run | 1 (`queued=40 now=60`) |

### Re-check in the pod after the readiness wait and the peer record (`v68`/`v69`)

`v66` left `test_epoll` as the only failing module. Two fixes closed it and the
last `test_ssl` failure; every module of the sweep now passes in the pod.

| defect | evidence | fix |
|---|---|---|
| a readiness call that arrived between a peer's write and the pump's next pass measured the bridge before the bytes were delivered | `test_epoll.test_control_and_wait` collected `[(11, 4), (12, 5)]` where `[(11, 5), (12, 5)]` was expected: with `EPOLLET` the readable edge that arrives one tick later is a separate event, and the test stops as soon as it has two | the pump publishes the completion of its passes (`g_pass_epoch`/`g_pass_done`), and `poll`, `ppoll`, `pselect6` and `epoll_wait` wait up to 5 ms for a quiet pass. The waiting thread holds no bridge lock and runs no LKL code, so the pump keeps making progress; a synchronous pump from the dispatcher had starved it and was rejected in `v66`. The wait is taken only when the call asks for readability: waiting on writability changed the answer, and `test_socket.SendfileUsingSendTest.testWithTimeoutTriggeredSend` then hit the peer's close instead of its own 10 ms send timeout (`BrokenPipeError`) |
| `getpeername` answered `ENOTCONN` for a socket the guest had just connected | `test_ssl.test_get_server_certificate_timeout` failed with `OSError: [Errno 107] Socket not connected` from `ssl.py` `_check_connected`. The test passes alone in the pod 40 of 40 times, so the trace had to be read, not the test. `ssl.SSLSocket._create()` calls `getpeername()` to decide whether the socket is connected; on `ENOTCONN` it sets `_connected = False`, skips the handshake, and the caller fails later at `getpeercert`. The guest's descriptor is a socketpair end, which the host reports writable at once, so `create_connection(timeout=...)` treats a non-blocking connect as done while LKL can still be in `SYN_SENT`, where `ENOTCONN` is the truthful answer for LKL and the wrong one for the guest | the fd entry records the peer sockaddr from `connect()`. `getpeername` asks LKL first, so a connection that really ended still answers `ENOTCONN` (a first version that always answered from the record broke `test_ssl.test_preauth_data_to_tls_client`, which needs `ENOTCONN` after a reset that carries data), and substitutes the recorded peer only while the connection was never seen established. `sock_established` is set by a successful `connect()`, by `getsockopt(SO_ERROR)` returning 0, or by a successful LKL `getpeername` |

Evidence for the peer record, from a guest run of `probe_peer.py`:

```
client peer ('127.0.0.1', 40085) matches: True
accepted peer ('127.0.0.1', 40152) matches client local: True
unconnected getpeername errno 107 ENOTCONN: True
nonblocking connect errno 115
nonblocking getpeername ('127.0.0.1', 40085)
rounds=300 bad=0          # 300 non-blocking connect -> getpeername in a row
test_ssl.TestPreHandshakeClose: 3/3 OK
```

| module | v66 pod | v68 pod | v69 pod |
|---|---|---|---|
| `test_epoll` | 10 tests, 1 failure | **10 tests, SUCCESS** | 10 tests, SUCCESS |
| `test_ssl` | 188 tests, SUCCESS | 188 tests, 1 failure | **188 tests, SUCCESS (3 runs)** |
| `test_socket` | 732 tests, SUCCESS | 732 tests, SUCCESS | 732 tests, SUCCESS |
| `test_asyncio` | 2 577 tests, SUCCESS | 2 577 tests, SUCCESS | 2 577 tests, SUCCESS |
| `test_largefile` | SUCCESS | SUCCESS | SUCCESS |
| `test_io` | SUCCESS | SUCCESS | SUCCESS |
| `test_logging` | SUCCESS | SUCCESS | SUCCESS |

Local run of the same binary: `test_socket`, `test_ssl`, `test_epoll`,
`test_io`, `test_logging` 1 834 tests SUCCESS; `test_asyncio` 2 577 tests, one
intermittent failure in `test_events` that passes 8 of 8 when run alone.

### Re-check in the pod after the vector-I/O EINTR fix (`v66`)

`v59` left two failures. One of them, `test_ssl`'s keylog pair, turned out to
be a lost write, and the other is a readiness race that two different fixes
failed to win.

| defect | evidence | fix |
|---|---|---|
| a `writev` on a file that lives in LKL lost the whole write when LKL answered `-EINTR` | the keylog header is written with `writev`, and the pod trace shows `kbofdt: iov done fd=32768 lkl=9 write=1 total=0 err=4` immediately followed by a read that copies 0 bytes. OpenSSL ignores the failed write, so the file stayed empty and `test_keylog_defaults` reported `0 != 1`. In the same run `kbox: syscall nr=63 (read) succeeded on a fresh LKL task after 3 EINTR; this container's task stays poisoned` | `dispatch_retryable_file_io()` listed `read`/`pread64`/`write`/`pwrite64` but not `readv`/`writev`/`preadv`/`pwritev`, so the retry-on-`EINTR` loop never ran for the vector forms. They are added; retrying is safe because `dispatch_iov_transfer()` reports `EINTR` only when it transferred nothing. After the fix the same trace reads `total=0 err=4` then `total=54 err=0` |

Diagnostics that found it (all gated by `KBOX_FD_TRACE`, off by default): the
virtual-FD call trace (`kbofdt: call fd=… nr=… (writev) …`), the open/lazy
shadow trace, and the vector-I/O result (`kbofdt: iov done fd=… total=… err=…`).

`test_epoll.test_control_and_wait` is the last failure, and it is a real race:
a bridged `send()` returns before the bridge has delivered the bytes to the
peer, so an edge-triggered poll that follows reports writability alone
(`[(11, 4), (12, 5)]` where `[(11, 5), (12, 5)]` is expected). Two fixes were
built and measured, and both are rejected:

| attempt | result |
|---|---|
| pump the whole bridge before every `poll`/`ppoll`/`pselect6`/`epoll_wait` | `test_epoll` passes, but the pump thread starves and the deferred `accept` path stops: `test_socket` timed out 3/3 and `test_asyncio` gained 13 failures |
| write into the tracee's socketpair, then flush and deliver once, inside `sendto` | `test_epoll` passes 10/10 and `test_socket`+`test_ssl` pass, but `test_asyncio` times out in `_sock_sendfile_native_impl` and `test_ssl` fails `test_get_server_certificate_timeout` |

Both were reverted; the reverted build is byte-identical to the one that
produced the table below (`sha256:de0f6ebc…`). The remaining work is to deliver
without holding the bridge lock on the dispatcher thread, for example by
letting the pump own the delivery and having the guest's readiness call wait
for one complete pass instead of performing it.

| module | v59 pod | v66 pod |
|---|---|---|
| `test_ssl` | 188 tests, 2 failures | **188 tests, SUCCESS, 16 skipped, 36 s** |
| `test_socket` | 732 tests, SUCCESS | 732 tests, SUCCESS, 117 skipped, 35 s |
| `test_asyncio` | 2 577 tests, SUCCESS | 2 577 tests, SUCCESS, 54 skipped, 75 s |
| `test_epoll` | 10 tests, 1 failure | 10 tests, 1 failure (`test_control_and_wait`) |
| `test_largefile` | SUCCESS | SUCCESS |
| `test_io` | SUCCESS | SUCCESS |
| `test_logging` | SUCCESS | SUCCESS, 260 tests |

### Re-check in the pod after the receive and data-loss fixes (`v59`)

`v53` left one `test_socket` failure that moved between runs, the four
`test_socket` `if_nameindex` errors, a `test_epoll` failure and two pod-only
`test_ssl` keylog failures. The moving `test_socket` failure and the wedging
daemon both came from the same two defects described below.

| defect | evidence | fix |
|---|---|---|
| a blocking `recvfrom` on a **bridged socket without an address buffer** was left to the host kernel | `test_ssl`'s `test_wrapped_unconnected` hung its whole module: `recvfrom` on a socket that was never connected, parked forever. The guest descriptor is a socketpair end, which the host considers connected | `stream_socket_unconnected()` is checked for both forms of the call and answers `ENOTCONN`, and every receive on a bridged socket now takes the same "try once, then park" path so that `SO_RCVTIMEO` is applied. Before, the timeout lived only on the LKL socket, so a plain `recv` on the socketpair ignored it (`test_socket.NetworkConnectionBehaviourTest.testOutsideTimeout`) |
| the pump **overwrote the buffer it had not yet delivered** | `probe_iv.py` (test_socket's interrupted-send pattern) sent **79 MB in 100 s to a peer that read nothing**: `pump_shadow_lkl_read()` read from the LKL socket into `to_supervisor_buf` even when the socketpair was full and the previous bytes were still there, so each pass discarded the last one. The sender never saw back-pressure, the alarm that should interrupt it was re-armed forever, and the same overwrite is what made a stream receive come back empty under load (`testRecvFromIntoBytearray`, `testRecvmsgLongAncillaryBuf`) | `pump_shadow_lkl_read()` flushes what is owed first and refuses to read again while `to_supervisor_len > 0`. Same probe after the fix: `interrupted after 4857 KiB in 3.52s`, and `test_socket.InterruptedSendTimeoutTest`/`InterruptedRecvTimeoutTest` pass 8/8 |
| a `ppoll`/`poll` notification arriving between a peer's write and the next pump tick reported writability alone | `test_epoll.test_control_and_wait` collected `[(11, 4), (12, 5)]` where `[(11, 5), (12, 5)]` was expected: with `EPOLLET` the readable edge that arrives one tick later is a separate event, and the test stops as soon as it has two | attempted and **reverted**: pumping the whole bridge from every readiness call starves the pump thread, and with it the deferred `accept` path (`test_socket` then timed out 3/3 and `test_asyncio` gained 13 failures). The remaining item is the opposite half of this race: a bridged `send` returns before the peer's descriptor is readable |

Diagnostics added while chasing the wedge (they stay, they cost nothing when
everything works):

* the bridge pump publishes its current step, and the supervisor's stall
  reporter prints `kbox: net: pump stuck in stage=… slot=… for …ms` once per
  stall;
* every LKL entry point records its syscall number, first argument and start
  time; a call in flight for more than 2 s prints
  `kbox: lkl: syscall nr=… a1=… in flight for …ms`
  (LKL runs all Linux code under one CPU lock, so this names the holder);
* `SIGUSR1` to the daemon prints the full state of every bridge
  (`kbox: net: dump slot=… lkl=… sp=… to_lkl=… to_sp=… lkl_poll=… guest_poll=…`).

| module | v53 pod | v59 pod |
|---|---|---|
| `test_socket` | 732 tests, 1 failure, 117 skipped | **732 tests, SUCCESS, 117 skipped, 46 s** |
| `test_ssl` | 188 tests, 2 failures | 188 tests, 2 failures (keylog, unchanged) |
| `test_asyncio` | 2 577 tests, SUCCESS | 2 577 tests, SUCCESS, 54 skipped, 74 s |
| `test_epoll` | 10 tests, 1 failure | 10 tests, 1 failure (`test_control_and_wait`, also reproduced on a local run) |
| `test_largefile` | SUCCESS | SUCCESS |
| `test_io` | SUCCESS | SUCCESS |
| `test_logging` | SUCCESS | SUCCESS, 260 tests |

The keylog failures were narrowed to the file, not the test: the same probe
reports `size after set: 54` and one header line in a plain container, in the
guest on a local run, and in the pod when it runs alone, but the full pod run
leaves `size=0` for `@test_<pid>_tmp<non-ascii>`. The write reaches a writeback
shadow that the later read does not find, and the file is created and empty.
That is the next defect to chase.

### Re-check in the pod after the sendfile, close and netlink fixes (`v53`)

`v46` left one `test_socket` failure and nine errors in the pod, four
`test_asyncio` failures, and `test_epoll` failing in the pod only. All of them
were real gaps; none of them needed a test change.

| defect | evidence in the pod | fix |
|---|---|---|
| `sendfile` into a bridged socket answered `ENXIO` (`OSError: [Errno 6]`) | `test_socket.SendfileUsingSendfileTest.testCount/testCountSmall/testCountWithOffset/testOffset`; `kbox: sendfile sv_fd fd=11 dup=-6 entry=... shadow_sp=-1 host_fd=-1` | kboxd ran under the runtime's `RuntimeDefault` seccomp profile, which denies `pidfd_getfd`; the `/proc/<pid>/fd/N` fallback cannot copy a socket. The container now runs with `seccompProfile: Unconfined` (the same as `--security-opt seccomp=unconfined` locally), and `sendfile` also falls back to the FD table's own supervisor descriptor |
| a 10 MB file written then read back came out empty (`setUpClass ... assert len(FILEDATA) == FILESIZE`) | `kbox: writeback failed: ftruncate lkl_fd=9 size=10485760: -27`; `truncate 4M` ok, `4M+1` → size 0 | LKL's `ftruncate` refuses to *grow* a file past 4 MiB in the pod while writes at the same offsets succeed. `kbox_lkl_ftruncate_safe()` extends by writing one zero byte at the last offset, which needs no truncate; used by writeback, path `truncate` and `ftruncate` |
| `sendfile` into a socket blocked the only dispatch thread, so the guest never got an answer (`test_asyncio` timed out, `close` reported "has not returned after 5s") | `kbox: sendfile write failed sv_out=19 ret=-11 errno=11` then no result at all | both write paths use a non-blocking write with a 100 ms budget and return a short count, which `sendfile(2)` allows; a first write that cannot proceed returns `EAGAIN`, never `0` |
| `testWithTimeoutTriggeredSend` did not see `SO_SNDTIMEO` | guest spun until the peer's close arrived as `ECONNRESET` | sendfile's output now goes into the tracee's *own* socketpair end instead of straight into the LKL socket, so its writability is the real back-pressure; Python's `poll+sendfile` loop then times out as it should |
| a socket closed while its write buffer still held data lost the tail | `kbox: net: drain lkl=4 gave up after 1999 iters pending=22321` and `retire ... why=deregister DROPS to_lkl=50900` | `close` no longer waits inside the dispatcher (the peer that must drain the data is often in the same container and needs the dispatcher): the bridge keeps the LKL socket, the pump finishes the transfer and half-closes it |
| writing to a socket whose peer had gone killed the whole daemon with `SIGPIPE` | `docker run` exit status 141, every container frozen | `SIGPIPE` is ignored in `main()` and socket writes use `MSG_NOSIGNAL`, so the guest sees `EPIPE` |
| `recv()`/`send()` on a socket that exists only inside LKL answered `EBADF` | `socket.if_nameindex()` → `ENOBUFS`, `sock.recv()` → `[Errno 9]`; on every ABI `recv` *is* `recvfrom` with no address, which was handed to the host | `recvfrom`/`sendto` without an address now go through LKL when the descriptor is not a bridged socketpair, and a blocking receive there parks like any other |
| `socket.if_nametoindex()`/`if_indextoname()` reported interfaces missing | `if_nameindex()` listed `sit0`, `if_nametoindex('sit0')` → ENODEV; musl does the lookup on an AF_UNIX socket, which is a host passthrough, so the *pod's* kernel answered | `SIOCGIFINDEX`/`SIOCGIFNAME` on a host-passthrough descriptor are answered by LKL |
| a truncated control message was reported as malformed | `/usr/local/lib/python3.12/test/test_socket.py:2889: RuntimeWarning: received malformed or improperly-truncated ancillary data` | `put_cmsg_guest()` now writes the truncated `cmsg_len` and copies exactly that many bytes, as the kernel's `put_cmsg()` does |
| `RTM_DELLINK`/`sendto` on a connected stream socket with an address | `testInterruptedSendtoTimeout` → `OSError: [Errno 106] Socket is connected`, and it could not be interrupted at all | POSIX ignores the address on a connected stream socket; the call is emulated against the descriptor the tracee actually holds, so a signal interrupts it like any other `send` |

| module | v46 pod | v53 pod |
|---|---|---|
| `test_socket` | 710 tests, 1 failure, 9 errors | **732 tests, 1 failure, 117 skipped, 47 s** |
| `test_asyncio` | 2 577 tests, 4 failures | **2 577 tests, SUCCESS, 56 skipped, 72 s** |
| `test_largefile` | 16 tests, SUCCESS | 16 tests, SUCCESS, 6 skipped |
| `test_epoll` | 10 tests, 1 failure | 10 tests, 1 failure (passes in `v52` and locally; timing-sensitive) |
| `test_ssl` | 188 tests, 2 failures | 188 tests, 2 failures (unchanged, see below) |

Locally with the same binary, in one daemon:

```
test_socket    run=732  SUCCESS  (skipped=119)
test_asyncio   run=2577 SUCCESS
test_ssl       run=188  SUCCESS
test_logging   run=260  SUCCESS
test_epoll     run=10   SUCCESS
test_io        run=644  SUCCESS
test_largefile run=16   SUCCESS
make check-unit: 298/298 C, 12/12 python
```

What is still not working, with the cause named:

* `test_ssl.TestSSLDebug.test_keylog_defaults` / `test_keylog_filename` (pod
  only, unchanged since `v42`): the keylog file exists but is empty
  (`AssertionError: 0 != 1`), while a plain container writes it. Both tests
  only read the file right after the SSL context created it.
* `test_epoll.test_control_and_wait` (pod only, intermittent): the guest's
  socket FD is a host socketpair end, and draining a socketpair always wakes
  `POLLOUT`, so an edge-triggered poll can return before the reverse direction
  has been delivered.
* `test_socket`'s single remaining pod failure moves between runs and passes in
  isolation and locally: one run reported
  `BufferIOTest.testRecvFromIntoBytearray` (3/3 OK on its own), the next
  `RecvmsgTCPTest.testRecvmsgLongAncillaryBuf` (`b''` where the peer's line was
  expected; the whole class runs 13/13 OK on its own). Both are stream receives
  that came back empty once under full-module load, so the remaining item is a
  bridge timing race on a stream receive, not a missing syscall.

Two defects that only *look* like kbox gaps, with the baseline that shows it:
in a plain `python:3.12-alpine` container on the same host,
`socket.if_nameindex()` and `socket.if_indextoname()` fail with `ENOBUFS` and
all four `if_nameindex`-related `test_socket` cases error out (verified again
this session). In the guest three of the four now pass.

### Where the pod-only wedge sits

**Current state.** On `v71` the wedge does not reproduce: `test_ssl` (188
tests), `test_socket` (732) and `test_asyncio` (2 577) all complete in the pod,
most runs in under a minute and a half (see the `v71` section). What is left is
the low-rate `test_asyncio` flake recorded there. The two causes below are kept
as the record of the wedge as it was.

The three modules that wedge the guest in the pod (`test_ssl`, `test_asyncio`,
`test_socket`) do not wedge it locally, in the same image and on the same
binary. `test_ssl` is the shortest reproduction.

**First cause, fixed.** The original stall was a writeback copy running inside
the dispatch thread:

```
seccomp notify syscall: pid=2321 nr=57 (close) a0=34816
kbox: close vfd=34816 lkl=9 host_fd=-2 shadow_sp=15 writeback=1
kbox: shadow writeback lkl_fd=9 shadow_size=5493
kbox: writeback truncate done lkl_fd=9 ret=0
kbox: writeback copy begin lkl_fd=9 size=5493        <- no further line
```

`ftruncate` returned, `pwrite` did not, and the tracee sat in wchan
`seccomp_filter` waiting for a notification answer that could never come. The
copy now runs on its own thread with a budget: a copy that outstays it is
abandoned, `close()` reports success, and the LKL descriptor is retired so the
abandoned call cannot write into a file that later receives the same number.
With that fix `test_ssl` no longer stops at `SSLObjectTests.test_distrusted_spki`
(where it used to hang) and instead runs roughly two hundred tests further.

**Second cause, fixed.** After the writeback change the module stopped later,
in `socket_helper.bind_port`, whose `bind(("localhost", 0))` needs
`getaddrinfo("localhost")`. Traced in the pod:

```
seccomp notify syscall: pid=2159 nr=63 (read) a0=32781 a1=... a2=1024
kbox: result pid=2159 nr=63 (read) -> errno 4          <- /etc/hosts
kbox: result pid=2159 nr=63 (read) -> errno 4          <- /etc/resolv.conf
seccomp notify syscall: pid=2159 nr=198 (socket) a0=2 a1=526338
seccomp notify syscall: pid=2159 nr=206 (sendto) a0=22 ... -> 27
seccomp notify syscall: pid=2159 nr=73 (ppoll) a0=... a1=2 ...
```

musl's resolver treats a failed `read` of `/etc/hosts` as "the name is not
listed" and falls back to DNS, whose reply never arrives, so the module died on
regrtest's 120 s timeout.

The read failure is LKL's, not a lost notification. Measured inside the failing
read:

```
kbox: lkl read fd=32768 lkl_fd=9 returned EINTR; pread(1,0)=-4 fstat=0 \
      mode=0100000 size=178791 other_open=10 other_read=-4
```

* a regular file; `fstat` succeeds, `read` and `pread` return `EINTR`;
* a freshly opened *other* file fails in the same request, so the failure is per
  container (per LKL task), not per descriptor;
* a fresh container in the same pod reads the same file 28 367 times with zero
  `EINTR`, so the shared engine is healthy;
* retries do not clear it: 8 attempts, then 5 000 with backoff, then 20 with
  250 ms pauses all end in `EINTR`;
* no host signal is pending (every daemon thread shows `SigPnd`/`ShdPnd` zero),
  a zero-timeout `rt_sigtimedwait` drains nothing, and replacing the LKL task's
  blocked set (which runs `recalc_sigpending()`) changes nothing.

LKL never resets a task's signal state, and `filemap_get_pages()` returns
`-EINTR` while a fatal signal is pending, so a single `SIGKILL` queued by the
LKL kernel -- the OOM killer on a failed allocation is the way in -- poisons that
task for good. kbox cannot clear it, so it stops using the task: the call is
re-run on a brand-new host thread, which LKL gives a fresh kernel task. Once
that works the container is marked poisoned and later file calls go straight
there. The log shows both halves:

```
kbox: syscall nr=63 (read) succeeded on a fresh LKL task after 3 EINTR; \
      this container's task stays poisoned
```

`test_ssl` then completes instead of timing out:

| | v42 pod |
|---|---|
| tests run | 188 |
| failures | 2 |
| skipped | 16 |
| duration | 32 s (regrtest limit is 120 s) |

### Re-check in the pod after ancillary-data support (`v46`)

The 76 `test_socket` failures in `v44` were dominated by one missing feature:
ancillary data on receives. All of it was absent, so `ancdata` was always empty.

| defect | fix |
|---|---|
| Datagram receives never returned `ancdata` (`IPV6_TCLASS`, `IPV6_HOPLIMIT`, `IP_TOS`) | The bridge pump now reads datagrams with `recvmsg` instead of `recvfrom`, keeps the control message per datagram, and the dispatcher copies it into the tracee's `msg_control` |
| Truncated cmsg buffers reported nothing | `put_cmsg_guest()` mirrors the kernel's `put_cmsg()`: a buffer too small for a `cmsghdr` yields no cmsg plus `MSG_CTRUNC`, a partially fitting cmsg is copied up to the limit, and `msg_controllen` reports the distance the cursor advanced |
| A datagram larger than the receive buffer lost `MSG_TRUNC` | The socketpair read asks the host for the true datagram size; when it exceeds the tracee's buffer the flag is reported and only the copied length is returned |
| `sendmsg` with no destination on an unconnected datagram socket succeeded | answered `EDESTADDRREQ`, as Linux does (the stand-in socketpair is always connected) |
| `sendfile` lost bytes after a short write | the source is rewound to the first byte that was not written (a 10 MB transfer lost 89 KB: `test_socket.SendfileUsingSendfileTest.testOffset`) |
| Stream sockets received IPv6 cmsgs they never asked for | the control-message path is limited to datagram sockets; the bridge only has per-datagram metadata for those |
| A live FD could resolve to another socket's stale entry | the host-FD mapping is only used when the number itself is absent or the inherited-FD placeholder |

| module | v44 pod | v46 pod |
|---|---|---|
| `test_socket` | 710 tests, 76 failures | **710 tests, 1 failure, 117 skipped, 56 s** |
| `test_asyncio` | 2 577 tests, 4 failures | 2 577 tests, 4 failures |
| `test_epoll` | 10 tests, 1 failure | 10 tests, 1 failure |

Locally, with the same binary:

```
test_socket.RecvmsgRFC3542AncillaryUDP6Test + RecvmsgInto... : 36 tests OK
test_socket.RecvmsgUDPTest/SendmsgUDPTest (+IPv6/UDPLITE/Into) : 58 tests OK
test_socket          run=732 failures=1 skipped=119
test_asyncio         run=2577 failures=1 skipped=54
test_ssl             run=188  SUCCESS
test_epoll           run=10   SUCCESS
test_logging         run=260  SUCCESS
test_io              run=644  SUCCESS
make check-unit: 298/298 C, 12/12 python
```

What still fails in `test_socket`, with the cause named:

* `SendfileUsingSendfileTest.testWithTimeoutTriggeredSend` (local): the test
  expects `SO_SNDTIMEO` to turn a stalled send into `TimeoutError`; the
  non-blocking sendfile returns a short count instead.
* `setUpClass (SendfileUsingSendTest / SendfileUsingSendfileTest)` (pod only):
  the class writes a 10 MB file and reads it back, and gets a shorter file --
  `assert len(cls.FILEDATA) == cls.FILESIZE`. This is a file writeback defect,
  the same area as the `test_largefile` `EFBIG` report, not a socket one.
* `testInterfaceNameIndex`, `testInvalidInterfaceIndexToName`,
  `test_getaddrinfo_ipv6_scopeid_symbolic`,
  `test_getnameinfo_ipv6_scopeid_symbolic`: `socket.if_nameindex()` fails with
  `OSError: [Errno 105] No buffer space available` -- the netlink dump overflows
  its socket buffer inside LKL.
* `TestUnixDomain.testBytesAddr` / `testStrAddr`: `bind()` on a path socket
  fails with `EADDRINUSE`.
* `testInterruptedSendtoTimeout`: a signal during `sendto` does not produce the
  expected interruption.
* `test_epoll.test_control_and_wait` (pod only, passes locally): unchanged, and
  bounded by the socketpair design described in the v44 section.
* `test_asyncio`: 4 failures, all in the sendfile tests
  (`test_sendfile_prevents_bare_write`, and one
  `test_sendfile_close_peer_in_the_middle_of_receiving` locally). A peer that
  closes while the bridge's guest-bound buffer is full is not noticed until the
  pump can write again, so the transport never observes the closure.

### Re-check in the pod after the socket-path fixes (`v44`)

Four defects were found and fixed after the poisoned-task fallback, all of them
in how a bridged socket is resolved and served:

1. **Resolution order.** `resolve_lkl_socket_entry()` looked the tracee FD number
   up first. The one-time inherited-FD scan registers every low FD as
   `SHADOW_ONLY`, and a socket injected later can reuse such a number, so the
   call was answered "host passthrough" while the FD really belonged to a
   virtual entry with an LKL twin. The host mapping now wins when it carries a
   real LKL socket.
2. **`sendmsg` with a destination.** On a bridged datagram socket Python sends
   `sendmsg(buffers, ancdata, flags, addr)`; the host saw an AF_INET sockaddr on
   the AF_UNIX socketpair and answered `EINVAL`, so nothing was sent and the
   receiver waited for a datagram that never left (`test_socket`'s
   `sendmsg`/`recvmsg` classes). The payload and control data now go into the
   LKL socket, which understands the address.
3. **Blocking `recvmsg` on a datagram socket** was served inside the dispatcher,
   which is the only thread that answers notifications: the guest's own sending
   thread could never run, so the datagram it was waiting for was never sent.
   `recvmsg` now attempts the receive without waiting, and a blocking socket
   parks the notification (`pending_recvmsgs`) for
   `kbox_dispatch_poll_pending`, exactly like `recvfrom`.
4. **`sendfile` into a socket** blocked the dispatcher for as long as the peer
   did not drain (the pump that frees space was not served), which wedged the
   guest with no answer at all. Both the host and the LKL write paths now use a
   non-blocking write with a 100 ms budget and return a short count, which
   `sendfile(2)` allows; a first write that cannot proceed returns `EAGAIN`, not
   zero (zero means end of file and made asyncio stop early).

Also: a datagram socket that LKL reports as `ECONNRESET` (an ICMP port
unreachable) is no longer torn down. The error is held per socket and reported
once to the guest's next receive, as Linux does; retiring the bridge left the
guest's end open with nobody feeding it, which was one of the wedges.

| module | v43 pod | v44 pod |
|---|---|---|
| `test_socket` | WEDGED, no result | **710 tests, 76 failures, 117 skipped, 65 s** |
| `test_asyncio` | timed out at 120 s | **2,577 tests, 4 failures, 56 skipped, 85 s** |
| `test_epoll` | 10 tests, 1 failure | 10 tests, 1 failure |

The same binary locally:

```
test_socket    run=732 failures=76 skipped=119  (completes; was WEDGED)
test_asyncio   run=2577 SUCCESS
test_ssl       run=188  SUCCESS
test_logging   run=260  SUCCESS
test_io        run=644  SUCCESS
test_zipfile   run=344  SUCCESS
test_epoll     run=10   SUCCESS
make check-unit: 298/298 C, 12/12 python
```

The four `test_asyncio` failures left in the pod are
`SendfileMixin.test_sendfile_prevents_bare_write`, which raises
`ConnectionError('Connection closed by peer')` from `drain()`.

`test_epoll.test_control_and_wait` still fails in the pod and passes locally:
both sockets are edge-triggered, and the pump drains the guest's own write
buffer asynchronously, which makes the host kernel wake `POLLOUT` before the
reverse-direction data has been delivered. A kernel that drains a socketpair
always wakes writers, so this cannot be avoided while the guest's socket FD is a
host socketpair end.

### Re-check in the pod after the poisoned-task fallback (`v42`/`v43`)

| module | before | after |
|---|---|---|
| `test_ssl` | WEDGED, no result | 188 tests, 2 failures, **21-36 s** |
| `test_logging` | aborted | 260 tests, SUCCESS, 21 s |
| `test_io` | FAIL (13) | 644 tests, SUCCESS, 14 s |
| `test_asyncio` | WEDGED, no result | still times out, now in `_sock_sendfile_native_impl` |
| `test_socket` | WEDGED, no result | still wedges, now in a blocking `recvmsg` (`testOddCmsgSize`) |

Both remaining modules now fail *later* and in named places, and the reporter
prints the stalled syscall:

```
kbox: syscall pid=17665 nr=212 (recvmsg) has not returned after 5s; the guest is waiting for it
```

The two `test_ssl` failures are `TestSSLDebug.test_keylog_defaults` and
`test_keylog_filename`, which read a keylog file that OpenSSL writes while
holding it open (`AssertionError: 0 != 1`, `0 != 6`). Both pass in isolation in
the pod (6 tests, `OK`), and after a full module run in the same container the
next command cannot even start (`/bin/sh: python3: Interrupted system call`), so
they are a symptom of the poisoned task, not a separate defect in the keylog
path: writes made before the task is detected as poisoned are lost.

### Re-check after the AF_UNIX datagram fix

`test_logging` used to abort with no result in both environments: its
`UnixDatagramHandler` test sent a datagram to a bound path, `sendto` answered
`ENOENT`, and the server thread waited forever. With the fix the module
completes. Three other modules that were aborted by timeouts also finish now,
measured locally on the same binary:

| module | before | after |
|---|---|---|
| `test_logging` | aborted, no result | 260 tests, SUCCESS |
| `test_ssl` | aborted, no result | 188 tests, 16 skipped, SUCCESS |
| `test_asyncio` | aborted, no result | 2,577 tests, 2 failures |
| `test_posix` | aborted, no result | 167 tests, 1 error + 1 failure (both environment) |

### Re-check after the fexecve and group-list fixes

`test_posix` is the module the two fixes above unblock. Before them it produced no
result at all: `test_fexecve` failed, its child never exited, and `regrtest` aborted
the whole module on the 120 s timeout. On `v25`:

| | internal filesystem | mounted volume |
|---|---|---|
| tests run | 167 | 167 |
| failures | 0 | 1 (`test_fchown`, host ownership on the mount) |
| errors | 1 (`test_makedev`, musl `major()`/`minor()`) | 1 (`test_makedev`) |
| `test_fexecve`, `test_setgroups`, `test_initgroups` | pass | pass |

### Re-check after the writeback fix

The sweeps above ran on `v22`. The next build (`v23`) adds the `EINTR`/short-write
retry in the shadow writeback. Only the modules that touch that path were re-run,
in both environments:

| module | internal (v22) | internal (v23) | mounted (v22) | mounted (v23) |
|---|---|---|---|---|
| `test_largefile` | FAIL | FAIL (`EFBIG`) | PASS | PASS |
| `test_io` | FAIL | PASS | PASS | PASS |
| `test_zipfile` | FAIL | FAIL | PASS | PASS |
| `test_tarfile` | PASS | PASS | FAIL | FAIL |
| `test_import` | PASS | PASS | FAIL | FAIL |
| `test_netrc` | PASS | PASS | FAIL | FAIL |
| `test_epoll` | FAIL | FAIL | PASS | FAIL |
| `test_os` | FAIL | FAIL | FAIL | FAIL |

The retry removes a silent truncation risk but changes no outcome here: the
`EFBIG` failure is not an interruption, and the two mounted-only failures are
identity, not writeback.

### How the numbers are counted

`regrtest` runs every test of a module; it does not stop at the first failure.
A module is aborted only when one test exceeds `--timeout 120`, and the driver
kills a module whose container exceeds 240 s. Test-level totals therefore come
from the `Total tests:` line of each module log and exclude the aborted modules,
which have no such line. Failures of subtest-based modules (for example
`test__locale`) can exceed the number of test methods, because each subtest is
counted separately.

## Fixes to kbox

Each row was reproduced first, then fixed, then re-verified. Evidence column
names the test that failed before the fix and passes after it.

### Process and descriptor lifecycle

| Fix | Evidence |
|---|---|
| The FD table (4.5 MiB) and the supervisor context (0.4 MiB) are heap-allocated in the three launchers instead of being locals, so the release build no longer runs its 8 MiB stack out before the supervisor's first statement | local `--net -r <image>` printed `Segmentation fault` before and `hi` after; frames 5 682 992 B → 963 584 B |
| `exit_group` deregisters writeback shadows; a plain thread `exit` only flushes them, so a threaded writer's buffered data survives | `test_io.test_threads_write` |
| `O_APPEND` opens share an active writeback shadow, so appended bytes survive the other descriptor's `close` | `test_io`, `test_cmd_line` |
| Writeback uses `pread` (never disturbs the shared file-description offset), copies sparse files by extent (`SEEK_DATA`/`SEEK_HOLE`), caps at 16 MiB | `test_largefile`, `test_io` |
| Writeback retries `ftruncate`/`pwrite` on `EINTR` and writes every byte of each chunk, instead of abandoning the copy-back at the first `-EINTR` or short write | `test_largefile`, `test_zipfile`, pod log `writeback failed: ...: -4` |
| Writes through a writable shared mapping are tracked, so `msync`/`ndbm` data is copied back | `test_dbm_ndbm` |
| `wait4`/`waitid` flush pending shadows and reap dead process tables (flush before `free`), with a deferred reap on the parent's next syscall | `test_faulthandler` crash-file tests |
| A failed `/proc` read no longer counts as proof of death for a process table | `test_concurrent_futures`, multiprocessing pools |
| `F_SETFD` on a real host descriptor continues to the kernel, which clears the descriptor's own close-on-exec bit | `test_faulthandler` fd tests |
| Unknown-but-open tracee descriptors are adopted instead of denied | SCM_RIGHTS pipe descriptors, `forkserver` pid write |

### Terminal

| Fix | Evidence |
|---|---|
| Terminal ioctls that need LKL state (`TIOCSCTTY` and friends) are forwarded; host-descriptor job-control ioctls continue | `test_pty`, `test_builtin` PtyTests |

### Sockets and network

| Fix | Evidence |
|---|---|
| Blocking datagram `recvfrom` is parked instead of blocking the single supervisor thread, and completed when data arrives | `test_asyncio` (2,577 tests, previously hung) |
| `MSG_OOB` on a shadow socket is delivered through LKL after flushing | `test_ftplib.abort` |
| A deferred `accept` is polled after every dispatch, and listeners are woken right after a guest `connect`, so a loopback connection reaches `client_connected_cb` in the same loop iteration | `test_asyncio.test_streams.test_unhandled_exception` |
| `epoll_wait`/`epoll_pwait` move data that LKL already holds into the shadow socketpair before waiting | `test_epoll.test_control_and_wait` |
| `bind` of an AF_UNIX path leaves a socket inode at the guest path on a bind mount as well as in the LKL rootfs | `test_stat.test_socket` |
| `sendto` to an AF_UNIX path goes through the supervisor, which can address the hashed host path the bound socket actually lives at; LKL answered `ENOENT` because the guest path is only an inode there | `test_logging.UnixDatagramHandlerTest` (whole module: 260 tests, from aborted to green) |

### Filesystem

| Fix | Evidence |
|---|---|
| `open("/proc/self/fd/N")` and `open("/dev/fd/N")` for a kbox virtual descriptor are served from the file kbox holds for it | `test_cmd_line_script.test_script_as_dev_fd` |
| `linkat` on a host-passthrough path uses the host kernel | musl `sem_open`, `multiprocessing.Lock`/`Queue` |
| File I/O on a container whose LKL task is poisoned is re-run on a fresh host thread, which gets a fresh LKL task; once a retry there succeeds the container is marked poisoned and every later file call goes straight there | The pod-only `EINTR` on every `read`/`pread` of that container (`test_ssl`, `test_asyncio`, `test_socket`) |
| `sendfile` prefers the host side of a descriptor the tracee really holds (a shadow memfd, or the guest end of a bridged socket) instead of its LKL twin | Writing into LKL past the bridge pump blocked forever in `test_asyncio`'s `_sock_sendfile_native_impl` |
| A writable shadow is copied back on its own thread with an 8 s budget; a copy that does not finish is abandoned, the guest's `close()` succeeds, and the LKL descriptor is retired so the abandoned call cannot write into a reused file | The pod-only wedge that consumed `test_ssl`, `test_asyncio` and `test_socket`: with the copy inline, one `pwrite` never returned and the guest waited for a notification answer forever |
| Kernel restart codes (`-ERESTART*`, 512..516) are retried, then reported to the guest as `EINTR` | A pod run surfaced `OSError: [Errno 512] No error information` from `connect()` in `test_ssl.test_subclass` |
| LKL file I/O that returns `EINTR` is retried, and a stale pending signal is dropped with a zero-timeout `rt_sigtimedwait` | `read()` of `/etc/hosts` fails with `EINTR` in the pod, which makes musl's resolver skip the hosts file and fall back to DNS |
| A reporter names any dispatch that has not returned after 5 s, and names it again when it comes back | Without it a stuck engine and a stuck guest look identical from outside |
| `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` (`fexecve`) on a kbox descriptor: the file is materialised as an exec image (shebang rewritten, `PT_INTERP` patched) and injected at the same descriptor number, instead of answering `EBADF` | `test_posix.test_fexecve` |
| `setgroups` stores the supplementary group list in the virtual credentials and `getgroups` reports it, instead of returning one hard-coded gid | `test_posix.test_setgroups`, `test_posix.test_initgroups` |
| `F_NOTIFY` (dnotify) is answered success: LKL is built without `CONFIG_DNOTIFY`, and no guest can observe the missing signal | `test_fcntl.test_fcntl_64_bit` |
| `execve` of a symlink that lives on a bind mount resolves the link target in guest space, so a link to `/usr/local/bin/python3` executes | `test_sysconfig.test_symlink`, `test_platform.test_architecture_via_symlink`, `test_site._pthFileTests` |
| Files created on a bind mount get the guest's umask applied, not the supervisor's | `test_pathlib.test_open_mode`, `test_pathlib.test_touch_mode` |
| A trailing slash survives path normalization, so `open("missing/", O_CREAT)` fails the way Linux fails it instead of creating a file named `missing` | `test_shutil.test_copyfile_nonexistent_dir` |

### Time

| Fix | Evidence |
|---|---|
| `clock_gettime`/`clock_getres` with an encoded CPU clock id (`time.pthread_getcpuclockid`) continue to the kernel instead of running in the supervisor, which is not the process that owns the thread and answered `EINVAL` | `test_time.test_pthread_getcpuclockid`; `test_time` 62 tests SUCCESS |

## Deviations that are not kbox defects

| Item | Why |
|---|---|
| `test_os` `fwalk` descriptor-number assertions | kbox allocates virtual descriptors from 32768 up, so "the next free descriptor is N+1" cannot hold |
| `test_sqlite3` lock-contention test | kbox treats POSIX advisory locks as always granted: LKL's `fcntl_setlk` dereferences lock state it does not have for host-backed files and crashes the daemon |
| `test_os.test_fpathconf` | musl's `fpathconf`/`pathconf` return values differ from glibc's |
| `test_import.test_unwritable_directory`, `test_shutil.test_copytree_retains_permissions` on the guest's internal filesystem | the guest runs as root; root may write into a directory whose mode denies it, and may not read a mode-000 file owned by the supervisor's uid. On the mounted volume these pass, because there the host identity applies (see open defects). |
| `test_curses`, `test_socketserver` "NO TESTS RAN" | no terminal environment inside the guest; the socketserver module skips every test when it cannot bind |
| `test_winsound` | Windows-only module |
| `test_urllibnet`, `test_urllib2net`, `test_smtpnet`, `test_xmlrpc_net` | require internet access from the guest |
| `test_import.test_unencodable_filename` on a Mac-hosted bind mount | the Mac host filesystem (APFS) rewrites a name with an invalid UTF-8 byte to U+FFFD, so the name the guest created is not the name the listing returns. Verified outside kbox: the same directory read from macOS shows `\xef\xbf\xbd`. The pod's `/data` is btrfs, which stores arbitrary bytes. |
| `test_capi` | `test_run_fileexflags` dies with `Fatal Python error: Segmentation fault` in plain Docker on the same image, at the same test and line (`test_run/test_run.py:78`), so the crash is CPython 3.12.16 on musl, not kbox |
| `test_c_locale_coercion`, `test_ctypes`, `test_locale`, `test_ossaudiodev`, `test_os`, `test_re` | fail in plain Docker with the same image (baseline) |
| `test__locale`, `test_strptime` | fail in plain `python:3.12-alpine` with the same suite (86 subtest failures and 8 respectively), so the cause is musl's locale data, not kbox. `test__locale` was listed as a kbox defect before the `v71` baseline run. |
| `test_posix.test_makedev` | `os.major(-1)` raises `OverflowError: can't convert negative int to unsigned` in plain `python:3.12-alpine` too: the musl build of CPython does not special-case `NODEV`. |
| `test_zipfile64` | NO TESTS RAN: the module needs more memory than the guest gives it, and plain Docker skips it as well. |

## Open defects

| Defect | Status |
|---|---|
| `test_subprocess` stdio redirection (5 of 341) | `subprocess.Popen(..., stdout=<filedes>)` and its siblings (`stdin=`, `stderr=`, `stdout=<fileobj>`, `check_output(input=...)`, `remapping_std_fds`) raise `OSError: [Errno 9] Bad file descriptor` from `_execute_child`. Plain `python:3.12-alpine` passes all 341, so the descriptor the child is told to `dup2` is not valid there. |
| `test_pathlib.test_is_mount` (3 of 609) | `Path('/').is_mount()` is false in all three path classes, so `stat("/")` and `stat("/..")` disagree in `st_dev`/`st_ino`. Plain Docker passes. |
| `test_multiprocessing_*` fd passing (2 in fork, aborted in spawn) | `test_fd_transfer` writes `b"foo"` through a descriptor received over SCM_RIGHTS and the file stays empty (`AssertionError: b'' != b'foo'`); the same shape fails for the >256 case. `test_multiprocessing_spawn` also answered `dup()` with `EBUSY` (`resource_sharer.send` → `socket.fromfd` → `dup`). Plain Docker passes both modules. |
| `test_multiprocessing_forkserver` hangs the module | The module never finishes: the container stays `Up` past the driver's 300 s limit, and that is what the later RUNBLOCKED entries mean -- the daemon starts one container at a time, so a hung guest blocks the queue. `docker rm -f` does clear it. The guest's own log names the stop: `multiprocessing.heap.Arena.__init__` -> `mmap.mmap(self.fd, self.size)` raises `OSError: [Errno 9] Bad file descriptor`. Plain Docker passes. |
| `test_concurrent_futures` spawn-class `SIGSEGV` | Isolated to `ProcessPoolSpawnProcessPoolExecutorTest`; fork and forkserver classes pass. The crash is in the parent during `popen_spawn_posix._launch` → `reduction.dump` → `DupFd` → `list.append`, and disappears under `PYTHONMALLOC=debug` and `PYTHONMALLOC=malloc`, which points at a small out-of-bounds write into pymalloc-managed memory. The writing syscall is not yet identified. |
| `test_asyncio` in the pod | Rate dropped from "2 of 3 runs spend the whole budget in one test" to 3 of 21 full-module runs ending at the 180 s per-test timeout, with two different stacks: `cleanup` → `proto.wait_closed()` waiting for `connection_lost`, and the synchronous `os.sendfile` inside `test_sock_sendfile_cancel1` (`_sock_sendfile_native_impl` line 397) not returning. Eight further full-module runs and 300 repetitions of `SelectorEventLoopUnixSockSendfileTests` alone did not reproduce either, so the trigger is load in the pod, not the class. See the `v71` section. |
| `test_epoll.test_control_and_wait` | Intermittent without the pod: 4 of 8 repeats of the module fail locally with `[(11, 4), (12, 5)] != [(11, 5), (12, 5)]`. Measured inside the running test: `epoll` reports `EPOLLIN` only for that descriptor, `select.poll()` reports `POLLIN` only (`{11: 4, 12: 5}`), the socket inode is unchanged since registration (no descriptor replacement), and `os.write(fd, b"Z")` on that very descriptor returns 1, so the socket is writable while readiness says it is not. A native AF_UNIX socket whose peer closed reports `POLLIN|POLLOUT|POLLERR|POLLHUP` (21), so a dead peer does not explain the mask either. The divergence is in kbox's readiness translation for shadow sockets, not in edge-triggered delivery. |
| ~~`test_io.test_threads_write` on the guest's own filesystem~~ | Closed: not reproducible (60 single-test and 20 module runs pass); the copy-back ordering defect behind it is fixed in `v70` (see the `v70` section) Historical evidence: with raw `os.write` as well as with Python's buffered layer: 4 of 40 repeats end 10 bytes short, and every write returned its full 10 bytes (`short_writes=0`). The descriptor itself is short, not just the file: after the threads join, `fstat(fd)`, `fstat(dup(fd))`, `pread(dup(fd), …)` and `stat(path)` all report 190 bytes, and one line is absent. The size recorded per writer is non-monotonic (for example 190, 130, 130, 190, 30 …), so the shared description is truncated while the writers run, and `test_io` also drives 20 thread exits, each of which runs a writeback of that shadow. Plain Docker passes 40 of 40. |
| `test_import.test_unwritable_directory`, `test_netrc` on the mounted volume only | Both pass on the guest's internal filesystem and fail on the bind mount. `netrc` reports `~/.netrc file owner (nobody, root) does not match current user`: the pod runs kboxd as uid 65534, so files the guest creates on the mount are owned by 65534 while the guest believes it is root, and the guest's own permission checks see the host identity. `test_import` creates a bytecode file in a mode-0555 directory, because the write lands in a shadow memfd that ignores the mount directory's mode. |
| ~~`test_largefile` on the pod's own rootfs (8 of 16 tests)~~ | Closed on `v71`: the same counts (`run=16 skipped=6`) are SUCCESS in three separate runs and the daemon log holds no `writeback failed` and no `-27`; the cause was not isolated, so the closed row claims only the measurement. Historical evidence: writeback answers `EFBIG`. The daemon log repeats `kbox: writeback failed: ftruncate lkl_fd=11 size=2500000001: -27` sixteen times per run, and the file therefore keeps size 0, so `os.stat(...).st_size`, `f.tell()` and `os.lseek(fd, 0, SEEK_END)` all read 0 and `f.read(1)` is empty. The guest filesystem accepted the same size from a direct `ftruncate`: inside the pod a guest truncating `/tmp/big`, `/data/tmp/big` and `/big` to 2,500,000,001 bytes succeeded (`size=2500000001`, `blocks=0`). The limit therefore applied to the descriptor writeback used, not to the filesystem. The same module passed on the pod's bind-mounted volume and on the local ext4 guest image, so the trigger was the container rootfs. |
| `test_zipfile.test_append_to_concatenated_zip_file` on the pod's own rootfs (1 of 344) | After writing a 20 MB prefix plus a zip file and reopening it for append, `ZipFile(...).namelist()` returns `[]` where the local ext4 guest and the pod's btrfs volume both return `['@test_6394_tmpæ']`. No writeback error is logged, so the read-back sees a file whose content does not match what was written. |
| `test_tarfile.test_parent_symlink` on the mounted volume (1 of 633) | The extraction filter must refuse an archive whose symlink escapes the destination. On the bind-mounted volume no `LinkOutsideDestinationError` is raised (`AssertionError: LinkOutsideDestinationError not raised`), while the same test passes on the guest's internal filesystem. The containment check compares resolved paths, so kbox's mount-path resolution makes an escaping link look contained. |
| ~~`test_ssl`, `test_asyncio`, `test_socket` in the pod~~ | Closed on `v71` except for the `test_asyncio` rate in its own row: `test_ssl` 188 tests SUCCESS (20.7 s, twice), `test_socket` 732 tests SUCCESS (51.8 s), `test_io` 644 and `test_logging` 260 SUCCESS. Historical evidence: `test_ssl` completed with 2 failures after the poisoned-LKL-task fallback, `test_asyncio` timed out inside `_sock_sendfile_native_impl`, and `test_socket` wedged in a blocking `recvmsg` for `test_socket.testOddCmsgSize` (`recvmsg has not returned after 5s`), which pointed at the bridge pump's backpressure: a guest socketpair end the pump did not drain stopped advertising `EPOLLOUT`, the same mechanism `test_epoll.test_control_and_wait` still fails on. |
| ~~`test_socket` wedges the shim in both environments~~ | Closed on `v71`: 732 tests finish in 51.8 s and the driver records PASS, not `WEDGED`. Historical evidence: the module produced no result in either `v22` sweep, the container stayed `running` past the 240 s limit, `docker rm -f` could not kill the guest, and while it was wedged the shim answered unrelated calls slowly. |
| A close that the pump cannot finish drops what it still holds | `net-slirp.c:908` caps the drain at `KBOX_CLOSE_DRAIN_NS` (5 s), then closes the LKL socket: two transfers in the `v71` sweep lost 160 and 576 bytes this way (`kbox: net: close drained lkl=15 after 5s, dropping to_lkl=160 to_sup=0`). No test fails on it, and the cap exists so a descriptor the supervisor still holds cannot pin a bridge slot and an LKL FD forever. |
| ~~`test_fexecve`~~ | Fixed: see the fix table. `test_posix.test_fexecve` passes on the internal filesystem and on the mounted volume. |

## Repro

```sh
# internal filesystem
KPF_HOOK=/tmp/kpf.sh \
SUITE_LIB=/Users/san/Fun/tmp/pysrc/syslib/python3.12 \
./scripts/run-cpython-suite-pod.sh /tmp/suite-pod 240

# mounted volume
KPF_HOOK=/tmp/kpf.sh \
SUITE_LIB=/Users/san/Fun/tmp/pysrc/syslib/python3.12 \
WORKDIR=/data/tmp GUEST_TMPDIR=/data/tmp \
./scripts/run-cpython-suite-pod.sh /tmp/suite-mnt 240
```

`/tmp/kpf.sh` re-establishes the port-forward to the newest pod. The driver runs
one container per module, kills it after 240 s, and writes
`<module>.log` plus `summary.txt`.
