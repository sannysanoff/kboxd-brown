/* SPDX-License-Identifier: MIT */

#ifndef KBOX_NET_H
#define KBOX_NET_H

struct kbox_sysnrs;

int kbox_net_add_device(void);
int kbox_net_configure(const struct kbox_sysnrs *sysnrs);
int kbox_net_configure_ipv4(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str,
                            const char *mask_str,
                            const char *gw_str);
int kbox_net_add_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str);
int kbox_net_del_host_route(const struct kbox_sysnrs *sysnrs,
                            const char *ifname,
                            const char *ip_str);
void kbox_net_cleanup(void);
int kbox_net_is_active(void);
int kbox_net_register_socket(int lkl_fd, int supervisor_fd, int sock_type);
/* Pop the metadata of the oldest queued datagram: source address and the
 * ancillary data the LKL socket produced for it. */
int kbox_net_pop_dgram_meta(int lkl_fd,
                            void *addr_out,
                            unsigned int *addrlen_io,
                            void *ctl_out,
                            size_t *ctllen_io,
                            size_t ctl_cap,
                            int peek);
int kbox_net_pop_dgram_addr(int lkl_fd,
                            void *addr_out,
                            unsigned int *addrlen_io,
                            int peek);
void kbox_net_flush_socket(int lkl_fd);
/* Wait (bounded) until the pump has drained every bridge. A readiness call
 * uses this so the kernel sees the peer's bytes that a completed write already
 * put on the wire. Returns at once when the bridge is already quiet. */
void kbox_net_wait_until_quiet(int max_ms);
/* Note that the tracee wrote into a bridged socket, so the pump must deliver
 * it before a readiness call may report the bridge as drained. */
void kbox_net_mark_guest_write(void);
void kbox_net_notify_listeners(void);

/* Age of the current bridge-pump step in milliseconds (0 when it is idle).
 * `stage` and `slot` name the step, so a stall can be attributed. */
uint64_t kbox_net_pump_stage_age_ms(int *stage, int *slot);

/* Report (once) an ICMP-derived error the LKL datagram socket recorded. */
long kbox_net_pop_recv_error(int lkl_fd);
/* Peek or consume a fatal LKL stream recv error (e.g. ECONNREFUSED on a
 * non-blocking connect) that the pump thread read before the guest queried
 * SO_ERROR. */
int kbox_net_peek_lkl_error(int lkl_fd);
int kbox_net_take_lkl_error(int lkl_fd);
/* Detach a bridge from a closing tracee FD.
 *
 * Returns 1 when the bridge took ownership of the LKL socket because bytes the
 * tracee already wrote were still waiting for it; the caller must then NOT
 * close the LKL FD -- the pump flushes and closes it.
 */
int kbox_net_deregister_socket(int lkl_fd);
void kbox_net_set_listening(int lkl_fd);
void kbox_net_clear_listening_notify(int lkl_fd);

/* Print the state of every bridged socket (called on SIGUSR1). */
void kbox_net_dump_state(void);

#endif /* KBOX_NET_H */
