1|1|1|1|1|1|1|1|1|# A container cannot talk to its own listener
2|2|2|2|2|2|2|2|2|
3|3|3|3|3|3|3|3|3|Inside a kbox container, connecting to a port that the *same container* is
4|4|4|4|4|4|4|4|4|listening on fails, whether the address used is `127.0.0.1` or the container's
5|5|5|5|5|5|5|5|5|own bridge IP. Connecting to another container by name or IP works.
6|6|6|6|6|6|6|6|6|
7|7|7|7|7|7|7|7|7|Evidence, all with `kbox:v62` and unmodified images:
8|8|8|8|8|8|8|8|8|
9|9|9|9|9|9|9|9|9|- `python:3-alpine` runs an HTTP server on `0.0.0.0:8099` and immediately asks
10|10|10|10|10|10|10|10|10|  it for `http://127.0.0.1:8099/` and `http://<own ip>:8099/`. Both fail, with
11|11|11|11|11|11|11|11|11|  `URLError [Errno 25] Not a tty` — a wrong errno, the same stale-errno pattern
12|12|12|12|12|12|12|12|12|  seen elsewhere in the dispatcher, so the message means less than the failure.
13|13|13|13|13|13|13|13|13|- `curlimages/curl` in one container reaches `http://auth:8088/` and
14|14|14|14|14|14|14|14|14|  `http://configmanager:8078/` in other containers without trouble.
15|15|15|15|15|15|15|15|15|
16|16|16|16|16|16|16|16|16|The consequence is not academic: the Solidus auth service answers a login by
17|17|17|17|17|17|17|17|17|verifying the password, then calling *itself* at
18|18|18|18|18|18|18|18|18|`http://auth:8088/api/v1/internal/auth/system-login` and
19|19|19|19|19|19|19|19|19|`…/get-external-auth-config`. That request never returns, so `POST
20|20|20|20|20|20|20|20|20|/api/v1/auth/login` hangs and the caller times out with no response at all.
21|21|21|21|21|21|21|21|21|Every other link in the chain is healthy — the configuration manager answers
22|22|22|22|22|22|22|22|22|the rule endpoint immediately with `401 {"message":"No auth token"}`, Kafka is
23|23|23|23|23|23|23|23|23|up, Postgres is up. Only the loop back into the same container is broken.
24|24|24|24|24|24|24|24|24|
25|25|25|25|25|25|25|25|25|## Where the loop happens
26|26|26|26|26|26|26|26|26|
27|27|27|27|27|27|27|27|27|`forward_connect()` hands the address to `kbox_lkl_connect()`, so the connect
28|28|28|28|28|28|28|28|28|is meant to run inside LKL. But a container's bridge IP is also an address the
29|29|29|29|29|29|29|29|29|*host* owns, and the daemon's own port forwarder (`port_accept_thread`) accepts
30|30|30|30|30|30|30|30|30|on the host side and then connects an LKL socket back to
31|31|31|31|31|31|31|31|31|`container_ip:container_port`. A connect whose destination is the container's
32|32|32|32|32|32|32|32|32|own address therefore has two possible paths, and the failing one is the path
33|33|33|33|33|33|33|33|33|that leaves LKL, reaches the daemon's forwarder, and is pumped straight back
34|34|34|34|34|34|34|34|34|into the same container. That round trip needs a second connection to be
35|35|35|35|35|35|35|35|35|serviced inside the same container while the first is still in flight.
36|36|36|36|36|36|36|36|36|
37|37|37|37|37|37|37|37|37|## Proposed fix
38|38|38|38|38|38|38|38|38|
39|39|39|39|39|39|39|39|39|Decide the path in `forward_connect()` from the destination: if the target is
40|40|40|40|40|40|40|40|40|the container's own address (or loopback, or any address assigned to the
41|41|41|41|41|41|41|41|41|container's own interface), make the connect entirely inside LKL and never
42|42|42|42|42|42|42|42|42|hand it to the host. The rule must be based on the destination, not on the
43|43|43|43|43|43|43|43|43|caller, because the same syscall is legitimate for both cases and the caller
44|44|44|44|44|44|44|44|44|has no way to tell them apart.
45|45|45|45|45|45|45|45|45|
46|46|46|46|46|46|46|46|46|Verification is already in place: the `python:3-alpine` self-connect probe
47|47|47|47|47|47|47|47|47|(one server, two connects — loopback and own IP) is the test to keep, and the
48|48|48|48|48|48|48|48|48|auth login endpoint is the end-to-end check.
49|49|49|49|49|49|49|49|
50|50|50|50|50|50|50|50|## The second self-connection loses its reply
51|51|51|51|51|51|51|51|
52|52|52|52|52|52|52|52|Reproduced with plain Python (`socketserver.ThreadingTCPServer` on `0.0.0.0`,
53|53|53|53|53|53|53|53|then three sequential connects to `127.0.0.1` from the same process):
54|54|54|54|54|54|54|54|
55|55|55|55|55|55|55|55|    self 1 ok b'HTTP/1.0 200'
56|56|56|56|56|56|56|56|    self 2 FAILED TimeoutError timed out
57|57|57|57|57|57|57|57|    self 3 FAILED TimeoutError timed out
58|58|58|58|58|58|58|58|
59|59|59|59|59|59|59|59|The server log shows three `GET / HTTP/1.0" 200` lines, so all three requests
60|60|60|60|60|60|60|60|were accepted and answered. The reply of the second and third never reaches the
61|61|61|61|61|61|61|61|client. The same shape shows up in a JVM: the inner call is served and logs its
62|62|62|62|62|62|62|62|last line, the outer request never returns.
63|63|63|63|63|63|63|63|
64|64|64|64|64|64|64|64|Where to look: `complete_accept_result()` attaches a *shadow* socket to the
65|65|65|65|65|65|65|65|accepted connection (`attach_shadow_socket`) when the listening entry has a
66|66|66|66|66|66|66|66|shadow and the net layer is active. Shadow-backed sockets have their data
67|67|67|67|67|67|67|67|pumped between the host socketpair and LKL by the port-forward path
68|68|68|68|68|68|68|68|(`tcp_pump_*`, created in `port_accept_thread`). A connection that never left
69|69|69|69|69|69|69|69|the container has no such pump, so a reply written on the shadow side has
70|70|70|70|70|70|70|70|nowhere to go. The first connection appears to work, the rest time out.
71|71|71|71|71|71|71|71|
72|72|72|72|72|72|72|72|A fix should make the accepted connection's data path unambiguous for a
73|73|73|73|73|73|73|73|self-connect: either always use the LKL socket directly for connections that
74|74|74|74|74|74|74|74|never left the container, or create the pump for them too.
75|75|75|75|75|75|75|
76|76|76|76|76|76|76|### Update: the stale slot
77|77|77|77|77|77|77|
78|78|78|78|78|78|78|`kbox_net_register_socket()` looks slots up by `lkl_fd` number, and the close
79|79|79|79|79|79|79|path only deregisters a descriptor it knows to be a network socket. LKL reuses
80|80|80|80|80|80|80|fd numbers immediately, so a stale slot kept answering for the *new*
81|81|81|81|81|81|81|connection and readiness went to a socketpair nobody held. Retiring any active
82|82|82|82|82|82|82|slot that still carries the same `lkl_fd` before reserving a new one changed
83|83|83|83|83|83|83|the probe from one success in three to three in four (the one that still fails
84|84|84|84|84|84|84|is the first request after the server starts).
85|85|85|85|85|85|
86|86|86|86|86|86|### Measured on the current image
87|87|87|87|87|87|
88|88|88|88|88|88|A probe that opens ten sequential self-connections in one process scored
89|89|89|89|89|89|**1/10**, and every attempt from the sixth onwards timed out -- so the failure
90|90|90|90|90|90|is not random noise but a state the daemon settles into. `MAX_SHADOW_SOCKETS` is
91|91|91|91|91|91|512, so running out of slots is not the cause.
92|92|92|92|92|92|
93|93|93|93|93|93|The listening socket's readiness is re-armed in the net layer's event loop
94|94|94|94|94|94|(`net-slirp.c`, the `sock->listening` branch): when `listen_notified` is clear
95|95|95|95|95|95|and LKL reports `POLLIN`, one byte is written to the shadow and the flag is
96|96|96|96|96|96|set; `complete_accept_result` drains that byte and calls
97|97|97|97|97|97|`kbox_net_clear_listening_notify`. Two things to check next, in this order:
98|98|98|98|98|98|
99|99|99|99|99|99|1. Whether the flag is actually cleared on every accept, or whether an accept
100|100|100|100|100|100|   that returns early (no shadow, `addr_ptr` error) leaves it set forever.
101|101|101|101|101|101|2. Whether the slot keeps its place in the poll set. The loop walks
102|102|102|102|102|102|   `shadow_base + si` and skips inactive slots; a slot that is retired and
103|103|103|103|103|103|   re-registered while the loop holds stale indices would stop waking the
104|104|104|104|104|104|   listener, which fits "works once, then never again".
105|105|105|105|105|105|
106|106|106|106|106|106|The probe is the acceptance criterion: ten out of ten, not one good login.
107|107|107|107|107|
108|108|108|108|108|Checked and ruled out: a deferred accept is not leaking. `defer_pending_accept`
109|109|109|109|109|fills `pending_accepts[]` (`KBOX_PENDING_ACCEPTS_MAX` is 64) and
110|110|110|110|110|`kbox_dispatch_poll_pending` does retire entries, keeping
111|111|111|111|111|`pending_accept_count` in step, so a full queue is not what stops the sixth
112|112|112|112|112|connection. What is left is the `listen_notified` re-arm and the poll-set slot
113|113|113|113|113|bookkeeping described above.
114|114|114|114|
115|115|115|115|### Distribution, not a single number
116|116|116|116|
117|117|117|117|Three runs of ten self-connections on the same image: 7/10, 10/10, 8/10 -- about
118|118|118|118|83% overall. With `KBOX_NET_TRACE` set on the daemon, the net layer's event loop
119|119|119|119|logs the listening socket on nearly every iteration as `notified=0 pr=0
120|120|120|120|revents=0`, i.e. the loop is awake and checking, and LKL simply reports nothing
121|121|121|121|pending at those moments. The loop's own poll timeout is capped at 100 ms and
122|122|122|122|the supervisor polls deferred accepts every 5 ms while any are outstanding
123|123|123|123|(`seccomp-supervisor.c`), so "the daemon was asleep" is not the explanation.
124|124|124|124|
125|125|125|125|That leaves the failure being a *lost* wakeup rather than a late one: the
126|126|126|126|connection sits in LKL's accept queue, the guest's waiting accept never
127|127|127|127|completes, and the client's `recv` times out after six seconds. Instrumentation
128|128|128|128|is in place (`KBOX_NET_TRACE=1` on the kboxd container); the next step is to log
129|129|129|129|the deferred-accept queue alongside it, so a failing connection shows whether
130|130|130|130|the accept was ever queued.
131|131|131|
132|132|132|### The accept is never deferred
133|133|133|
134|134|134|With `KBOX_NET_TRACE` on the daemon, a probe that lost two of ten connections
135|135|135|(ok=8, fails=[0,2]) produced no `accept deferred` and no `accept retry` line at
136|136|136|all. The guest server's `accept` therefore blocks inside LKL and never reaches
137|137|137|kbox's deferred-accept machinery, which means the readiness shim is not involved
138|138|138|in this failure: the connection completes at the client, the server's accept
139|139|139|does not wake, and the client's `recv` times out.
140|140|140|
141|141|141|That moves the defect from `dispatch-net.c` into LKL's own socket layer -- the
142|142|142|backlog accounting or the wakeup of a blocked accept. The shim's shadow sockets
143|143|143|stay as they are; the earlier 1/10 was a bad sample and nothing in the net layer
144|144|144|needs the epoll or shadow rework that was tried and reverted.
145|145|
146|146|### accept never reaches the shim at all
147|147|
148|148|Forcing every seccomp accept onto the deferred path (dropping the
149|149|`ctx->listener_fd >= 0` guard) changed nothing: 7/10, 9/10, 8/10, i.e. 80%
150|150|against 83% before. And not one `accept deferred` line was logged even then, so
151|151|the accept does not reach `forward_accept` on this path at all -- it is served
152|152|straight out of LKL, which is why the wakeup that goes missing is in native
153|153|kernel socket code and why every change made in `dispatch-net.c` was a no-op
154|154|against this probe. The change was reverted.
155|
156|### The connect was the timeout, and finishing it helps
157|
158|Per-attempt logging showed the two lost connections out of ten failing inside
159|`connect` itself, before the server ever saw them, while every accept in the
160|daemon succeeded. A loopback connect comes back `EINPROGRESS` even though both
161|ends are in this kernel, and the tracee's follow-up poll is on the host
162|socketpair, which knows nothing about LKL's handshake -- so the connect can look
163|hung forever.
164|
165|For a blocking socket the daemon now finishes the handshake itself (poll for
166|`POLLOUT`, accept it only when neither `POLLERR` nor `POLLHUP` is set) instead of
167|handing `EINPROGRESS` back. Two runs of ten: 9/10 and 9/10, against 80-83%
168|before, and every logged `connect ret` is 0. One connection in ten still fails
169|after a successful connect, so something in the read/write exchange remains --
170|that is the next trace, not the connect.

### Resolved: twenty out of twenty

The probe that writes its result to a bind-mounted file (so no log-reading
guesswork is involved) ran twenty sequential self-connections on the fixed
build: every one connected, sent, was accepted, was answered, and read the
reply, all within 0.0 s, `BAD 0 /20`. The listening path, the accept path and
the data path all appear in the log in order for each iteration.

The change that did it is finishing a blocking loopback connect in the daemon
rather than handing `EINPROGRESS` back to a tracee whose poll sits on a host
socketpair. The earlier accept, shadow and epoll theories were all wrong, and
the numbers that seemed to support them (1/10, then 7-9/10) were partly small
samples and partly a container-log path that does not exist -- `/tmp/kboxd-logs`
files are named by hash, not by the id `docker run` prints.
