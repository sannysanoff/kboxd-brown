# epoll and the guest's descriptor numbers

`forward_epoll_ctl_gated()` refuses with EBADF whenever either descriptor looks
guest-only. Postgres, once it gets past the nonblocking fcntl, registers its
client socket in an epoll set and dies on the refusal:

    FATAL: epoll_ctl() failed: Bad file descriptor

The refusal is wrong in both directions. The guest's number cannot be handed to
the host unchanged (the host has no such descriptor), and answering "success"
would leave `epoll_wait` asleep forever. The number has to be *translated*: a
guest socket already has a shadow socketpair that carries its readiness, and
that shadow is a real host descriptor.

## What the fix has to do

There is no helper for rewriting syscall arguments -- the dispatcher can only
release a call or answer it -- so the registration must be performed here:

1. Look up the target fd's entry. Its `shadow_sp` (or `host_fd`) is the host
   descriptor that signals readiness.
2. Copy both descriptors into the supervisor: `dup_tracee_fd(pid, shadow)` and
   `dup_tracee_fd(pid, epfd)`; the second is needed because the epoll set itself
   lives in the tracee.
3. Read the guest's `struct epoll_event` (12 bytes packed on this ABI) with
   `guest_mem_read`, and call `epoll_ctl(my_epfd, op, my_target, &event)`.
4. Close both duplicates and return 0, or `-errno` on failure.

`epoll_wait` needs no change: the tracee waits on its own epoll descriptor, and
events now arrive because the shadow of each registered socket was armed.

## Verification

The check that matters is the postgres log after a login attempt: no
`epoll_ctl() failed` and no backend teardown, and the login request returns a
token instead of `000`. The probe that isolates it is a container that opens a
socket, puts it in an epoll set and waits for readability.
