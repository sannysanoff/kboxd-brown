# Docker-API gaps found running an agent in kbox

Defects found — and fixed — by driving a real compose stack (ClickHouse,
Kafka, Postgres, MinIO, Spring services) from an agent inside kbox. Each one
is invisible until a workload is big or talks to a cluster service, which is
why a small smoke test passes while the real stack does not.

## Exec arguments were capped at one page

`json_get_str_array` parsed every `Cmd` / `env` entry into a fixed 4096-byte
buffer, so any argument longer than 4095 bytes reached the guest truncated.
This is silent: the container starts, gets a argv whose last byte is cut
mid-token, and fails in a way that names nothing (a Python script truncated
inside a string literal reports "SyntaxError at line 95", pointing at innocent
source).

Reproduce without a workload: an argument of 10000 bytes arrives as 4095.

    docker run --rm alpine:3.20 sh -c 'printf %s "$1" | wc -c' q "$(python3 -c 'print("A"*10000)')"
    # 4095 before the fix, 10000 after

It also silently truncated every `env` value over 4 KiB, which is reachable
with a long token or a JSON credential.

Fixed by sizing the buffer to the literal (`daemon.c`, `json_get_str_array`).

## DNS forwarded to a hardcoded address

The embedded DNS server sent every query it could not answer from its own host
table to `10.0.2.3`, a qemu/slirp address that means nothing inside a pod. The
guest could resolve public names (that resolver happens to exist in some
setups) but never a ClusterDNS name, so a sibling service — the team Nexus, a
database, another compose service on the pod network — was unreachable by name
while the identical URL worked by IP.

Diagnosis is one command pair; reachability by IP with failure by name is the
signature:

    curl -o /dev/null -w '%{http_code}\n' http://<service-ip>:8081/    # 200
    curl -o /dev/null -w '%{http_code}\n' http://<service-name>:8081/  # 000

Fixed by reading the POD's `/etc/resolv.conf` at startup and trying each
nameserver in order (`kbox_daemon_read_resolvers`, `dns_forward_one`). The
constant remains only as a fallback when the file yields nothing. A pod's
resolv.conf is the authoritative list — it carries the cluster resolver and
the search domains, and it is what the workload is allowed to use.

## Why both were easy to miss

A container that starts and answers a trivial command looks healthy. Both bugs
only surface on argv over 4 KiB or on a cluster-service hostname, so a smoke
test ("does `sh -c echo` work") passes on a broken engine. The check worth
keeping is the pair above: a >4 KiB argument, and a ClusterDNS name reached by
name as well as by IP.
