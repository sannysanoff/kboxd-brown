/* SPDX-License-Identifier: MIT */
#ifndef KBOX_DAEMON_H
#define KBOX_DAEMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "seccomp.h"
#include "syscall-nr.h"

#define KBOX_DAEMON_DEFAULT_SOCK "/tmp/kboxd.sock"
#define KBOX_DAEMON_DEFAULT_CONFIG_REL ".config/kbox-config.yaml"
#define KBOX_DAEMON_BRIDGE_NAME "br0"
#define KBOX_DAEMON_DEFAULT_START_IP "172.18.0.2"
#define KBOX_DAEMON_DEFAULT_GW_IP "172.18.0.1"
#define KBOX_DAEMON_HOST_MASK "255.255.255.255"
#define KBOX_DAEMON_DNS_PORT 53
#define KBOX_DAEMON_MAX_HOSTS 512
#define KBOX_DNS_UPSTREAM_MAX 4
#define KBOX_DAEMON_MAX_ALIAS 128
#define KBOX_DAEMON_DEFAULT_EPHEMERAL_ROOT "/tmp/.kboxd/ephemeral"

/* NFS-backed volumes (src/daemon-nfs.c). */
#define KBOX_NFS_MAX_MOUNTS 8
#define KBOX_NFS_NAME_MAX 64
#define KBOX_NFS_ROOT "/kbox-vol/nfs"
#define KBOX_NFS_SOURCE_MAX 256
#define KBOX_NFS_OPTIONS_MAX 224

struct kbox_nfs_mount {
    char handle[KBOX_NFS_NAME_MAX + 8]; /* literal "nfs://<name>" from config */
    char name[KBOX_NFS_NAME_MAX];       /* <name>, used in the LKL path */
    char source[KBOX_NFS_SOURCE_MAX];   /* "server:/export" */
    char options[KBOX_NFS_OPTIONS_MAX]; /* NFS mount options string */
    int mounted;
};

struct kbox_daemon_config {
    char start_ip[32];
    char gateway_ip[32];
    /* Upstream resolver for the embedded DNS server. Defaults are the pod's own
     * nameservers (read from /etc/resolv.conf at startup): a hardcoded address
     * cannot resolve cluster names, because the nameserver differs per cluster
     * and per pod. */
    char dns_upstream[KBOX_DNS_UPSTREAM_MAX][32];
    size_t dns_upstream_count;
    struct kbox_nfs_mount nfs[KBOX_NFS_MAX_MOUNTS];
    size_t nfs_count;
    /* Storage. Defaults are host-backed: image layers and each container's
     * overlay upper/work live in host directories, mounted into the guest by
     * the LKL hostfs driver, so a container's data lands on the pod filesystem
     * instead of in guest RAM and is not duplicated per container.
     *
     * images_hostfs mounts each image rootfs directly from the host instead of
     * copying it.
     * ephemeral_hostfs backs each container's upper/work dirs with a host
     * directory.
     *
     * Both need CONFIG_HOSTFS in the guest kernel and user.* xattrs on the host
     * filesystem (overlay whiteouts are stored as user.overlay.*). */
    int images_hostfs;
    int ephemeral_hostfs;
    char ephemeral_root[256];
    /* Where per-container stdout/stderr logs land. Configurable because a
     * container's log file is opened by the DAEMON, so a fixed /tmp path makes
     * every container of a second daemon fail in a directory it may not own. */
    char log_dir[256];
};

int kbox_daemon_load_config(const char *path, struct kbox_daemon_config *cfg);
void kbox_daemon_read_resolvers(struct kbox_daemon_config *cfg);
void kbox_daemon_set_config_path(const char *path);
int kbox_daemon_main(int argc, char **argv);
int kbox_daemon_run(const char *sock_path, const char *cmdline, int verbose);

/* Network subsystem (src/daemon-net.c). */
int kbox_daemon_net_init(const struct kbox_sysnrs *sysnrs,
                         const struct kbox_daemon_config *cfg,
                         int verbose);
void kbox_daemon_net_cleanup(void);
const char *kbox_daemon_net_gateway_ip(void);
int kbox_daemon_net_create_veth(const struct kbox_sysnrs *sysnrs,
                                const char *host_if,
                                const char *peer_if,
                                long peer_netns_fd,
                                const char *peer_ip);
int kbox_daemon_net_delete_link(const struct kbox_sysnrs *sysnrs,
                                const char *ifname,
                                const char *peer_ip);
int kbox_daemon_net_alloc_ip(char *buf, size_t len);
int kbox_daemon_dns_register(const char *name, const char *ip_str);
void kbox_daemon_dns_unregister_ip(const char *ip_str);
size_t kbox_daemon_dns_format_hosts(char *buf, size_t cap);
int kbox_daemon_port_add(const struct kbox_sysnrs *sysnrs,
                         const char *host_ip,
                         int host_port,
                         const char *container_ip,
                         int container_port);
void kbox_daemon_port_remove_ip(const char *container_ip);

/* True once SIGTERM/SIGINT has been seen; used by interruptible waits. */
int kbox_daemon_stopping(void);

/* mkdir -p inside LKL (daemon side, initial mount namespace). */
int lkl_mkdir_p_daemon(const struct kbox_sysnrs *sysnrs,
                       const char *path,
                       int mode);

/* NFS volumes (src/daemon-nfs.c). */
int kbox_nfs_split_source(const char *source,
                          char *name,
                          size_t name_size,
                          char *subpath,
                          size_t subpath_size);
int kbox_daemon_nfs_add(struct kbox_daemon_config *cfg,
                        const char *handle,
                        const char *key,
                        const char *value);
int kbox_daemon_nfs_mount_all(const struct kbox_sysnrs *sysnrs,
                              struct kbox_daemon_config *cfg,
                              int verbose);
int kbox_daemon_nfs_bind_container(const struct kbox_sysnrs *sysnrs,
                                   const struct kbox_daemon_config *cfg,
                                   const char *rootfs,
                                   const struct kbox_host_bind *binds,
                                   size_t bind_count,
                                   char *err,
                                   size_t err_size);
void kbox_daemon_nfs_unbind_container(const struct kbox_sysnrs *sysnrs,
                                      const char *rootfs,
                                      const struct kbox_host_bind *binds,
                                      size_t bind_count);

#endif /* KBOX_DAEMON_H */
