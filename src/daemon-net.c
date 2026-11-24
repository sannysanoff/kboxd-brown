/* SPDX-License-Identifier: MIT */
/* daemon-net.c - Multi-container bridge networking, DNS server, and port
 * forwarding inside a single LKL instance.
 *
 * All LKL network control-plane operations (bridge br0 setup, veth pair
 * creation/deletion) run on a dedicated root-netns thread whose LKL task stays
 * permanently in the initial root NET_NS.  Per-container worker threads enter
 * their own NET_NS via unshare(CLONE_NEWNET), open /proc/self/ns/net, and
 * request a veth pair whose peer ("eth0") is atomically placed in that netns.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/netfilter/nf_nat.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "daemon.h"
#include "lkl-wrap.h"
#include "net.h"

#define LKL_AF_NETLINK 16
#define LKL_SOCK_RAW 3
#define LKL_SOCK_STREAM 1
#define LKL_SOCK_DGRAM 2
#define LKL_SOCK_NONBLOCK 04000
#define LKL_SOL_SOCKET 1
#define LKL_SO_REUSEADDR 2
#define LKL_NR_IOCTL 29
#define LKL_SIOCGIFINDEX 0x8933
#define LKL_IFF_UP 0x1
#define LKL_SHUT_WR 1
#define LKL_SHUT_RDWR 2

#define UPSTREAM_DNS_IP "10.0.2.3"
#define MAX_PORT_FORWARDS 128
#define DNS_BUF_LEN 512

struct lkl_sockaddr_nl {
    unsigned short nl_family;
    unsigned short nl_pad;
    unsigned int nl_pid;
    unsigned int nl_groups;
};

struct lkl_ifreq_idx {
    char name[16];
    int ifindex;
    char pad[20];
};

struct dns_entry {
    int used;
    char name[KBOX_DAEMON_MAX_ALIAS];
    uint32_t ip_be; /* network byte order */
    char ip_str[32];
};

enum netns_op_type {
    NETNS_OP_CREATE_VETH = 1,
    NETNS_OP_DELETE_LINK = 2,
    NETNS_OP_STOP = 3,
};

struct netns_req {
    enum netns_op_type op;
    const struct kbox_sysnrs *sysnrs;
    char host_if[16];
    char peer_if[16];
    char peer_ip[32];
    long peer_netns_fd;
    int result;
    int done;
};

struct port_fwd_entry {
    int active;
    char host_ip[32];
    int host_port;
    char container_ip[32];
    int container_port;
    int listen_fd;
    int stop;
    pthread_t thread;
    const struct kbox_sysnrs *sysnrs;
};

struct tcp_pump_args {
    int host_fd;
    long lkl_fd;
    const struct kbox_sysnrs *sysnrs;
    volatile int *shutdown_flag;
    pthread_mutex_t *close_lock;
    int *refcount;
};

static const struct kbox_sysnrs *g_sysnrs;
static int g_verbose;
static volatile int g_running;
static int g_br0_ifindex = -1;

/* IP allocator under g_ip_lock: sequential /32 hosts starting at config
 * start_ip (default 172.18.0.2).
 */
static pthread_mutex_t g_ip_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_start_ip_host = (172U << 24) | (18U << 16) | 2U;
static uint32_t g_next_ip_host = (172U << 24) | (18U << 16) | 2U;
static uint32_t g_gw_ip_host = (172U << 24) | (18U << 16) | 1U;
static char g_bridge_ip[32] = KBOX_DAEMON_DEFAULT_GW_IP;

static void trim_ws(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\r' || s[len - 1] == '\n'))
        s[--len] = '\0';
    size_t off = 0;
    while (s[off] == ' ' || s[off] == '\t')
        off++;
    if (off > 0)
        memmove(s, s + off, len - off + 1);
}

static void unquote_val(char *s)
{
    trim_ws(s);
    size_t len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
                     (s[0] == '\'' && s[len - 1] == '\''))) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static int normalize_start_ip(const char *raw, char *out, size_t out_len)
{
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s", raw);
    char *slash = strchr(tmp, '/');
    if (slash)
        *slash = '\0';

    struct in_addr ina;
    if (inet_pton(AF_INET, tmp, &ina) == 1) {
        uint32_t h = ntohl(ina.s_addr);
        if ((h & 0xffffU) == 0)
            h |= 2U;
        else if ((h & 0xffU) == 0)
            h |= 2U;
        ina.s_addr = htonl(h);
        return inet_ntop(AF_INET, &ina, out, (socklen_t) out_len) ? 0 : -1;
    }

    /* Allow shorthand prefix such as "172.18" or "172.19". */
    char expanded[128];
    int dots = 0;
    for (const char *p = tmp; *p; p++) {
        if (*p == '.')
            dots++;
    }
    if (dots == 1)
        snprintf(expanded, sizeof(expanded), "%s.0.2", tmp);
    else if (dots == 2)
        snprintf(expanded, sizeof(expanded), "%s.2", tmp);
    else
        return -1;

    if (inet_pton(AF_INET, expanded, &ina) != 1)
        return -1;
    snprintf(out, out_len, "%s", expanded);
    return 0;
}

static void derive_default_gateway(const char *start_ip,
                                   char *gw_out,
                                   size_t gw_len)
{
    struct in_addr ina;
    if (inet_pton(AF_INET, start_ip, &ina) != 1) {
        snprintf(gw_out, gw_len, "%s", KBOX_DAEMON_DEFAULT_GW_IP);
        return;
    }
    uint32_t h = ntohl(ina.s_addr);
    uint32_t cand = (h & 0xffffff00U) | 1U;
    if (cand == h)
        cand = (h & 0xffffff00U) | 254U;
    ina.s_addr = htonl(cand);
    if (!inet_ntop(AF_INET, &ina, gw_out, (socklen_t) gw_len))
        snprintf(gw_out, gw_len, "%s", KBOX_DAEMON_DEFAULT_GW_IP);
}

int kbox_daemon_load_config(const char *path, struct kbox_daemon_config *cfg)
{
    if (!cfg)
        return -1;
    snprintf(cfg->start_ip, sizeof(cfg->start_ip), "%s",
             KBOX_DAEMON_DEFAULT_START_IP);
    cfg->gateway_ip[0] = '\0';
    memset(cfg->nfs, 0, sizeof(cfg->nfs));
    cfg->nfs_count = 0;
    cfg->images_hostfs = 1;
    cfg->ephemeral_hostfs = 1;
    cfg->log_dir[0] = '\0';
    snprintf(cfg->ephemeral_root, sizeof(cfg->ephemeral_root), "%s",
             KBOX_DAEMON_DEFAULT_EPHEMERAL_ROOT);

    char resolved[512];
    const char *eff = path;
    if (!eff || !*eff) {
        const char *envp = getenv("KBOX_CONFIG");
        if (envp && *envp)
            eff = envp;
    }
    if (!eff || !*eff) {
        const char *home = getenv("HOME");
        if (home && *home) {
            snprintf(resolved, sizeof(resolved), "%s/%s", home,
                     KBOX_DAEMON_DEFAULT_CONFIG_REL);
            eff = resolved;
        }
    }

    if (eff && *eff) {
        FILE *f = fopen(eff, "re");
        if (f) {
            char line[512];
            char section[64] = "";
            char subsection[160] = "";
            while (fgets(line, sizeof(line), f)) {
                char *hash = strchr(line, '#');
                if (hash)
                    *hash = '\0';
                int indented = (line[0] == ' ' || line[0] == '\t');
                trim_ws(line);
                if (!line[0])
                    continue;

                /* A quoted key may itself contain a colon, as the NFS mount
                 * handles do ("nfs://mounted_here":), so the generic
                 * key/value split below would cut it in the wrong place.
                 */
                if (line[0] == '"' || line[0] == '\'') {
                    char quote = line[0];
                    char *close = strchr(line + 1, quote);
                    if (close) {
                        char *rest = close + 1;
                        *close = '\0';
                        trim_ws(rest);
                        if (rest[0] == ':' && rest[1] == '\0') {
                            const char *qname = line + 1;
                            if (!indented) {
                                snprintf(section, sizeof(section), "%.63s",
                                         qname);
                                subsection[0] = '\0';
                            } else {
                                snprintf(subsection, sizeof(subsection),
                                         "%.159s", qname);
                            }
                            continue;
                        }
                    }
                }

                char *colon = strchr(line, ':');
                if (!colon)
                    continue;
                *colon = '\0';
                char *key = line;
                char *val = colon + 1;
                trim_ws(key);
                unquote_val(val);

                if (!indented && !val[0]) {
                    snprintf(section, sizeof(section), "%.63s", key);
                    subsection[0] = '\0';
                    continue;
                }
                if (!indented) {
                    section[0] = '\0';
                    subsection[0] = '\0';
                }

                if (strcmp(section, "mounts") == 0 && subsection[0]) {
                    if (kbox_daemon_nfs_add(cfg, subsection, key, val) < 0)
                        fprintf(stderr,
                                "kboxd: config: bad mount entry %s.%s\n",
                                subsection, key);
                    continue;
                }

                int in_storage = (strcmp(section, "storage") == 0);
                if (in_storage) {
                    /* storage:
                     *   images:         copy | hostfs
                     *   ephemeral:      tmpfs | hostfs
                     *   ephemeral_root: /tmp/.kboxd/ephemeral
                     */
                    if (strcmp(key, "images") == 0)
                        cfg->images_hostfs = (strcmp(val, "hostfs") == 0);
                    else if (strcmp(key, "ephemeral") == 0)
                        cfg->ephemeral_hostfs = (strcmp(val, "hostfs") == 0);
                    else if (strcmp(key, "ephemeral_root") == 0 ||
                             strcmp(key, "ephemeral-root") == 0)
                        snprintf(cfg->ephemeral_root,
                                 sizeof(cfg->ephemeral_root), "%s", val);
                    else if (strcmp(key, "log_dir") == 0 ||
                             strcmp(key, "log-dir") == 0)
                        snprintf(cfg->log_dir, sizeof(cfg->log_dir), "%s",
                                 val);
                    continue;
                }

                int in_net = (!section[0] || strcmp(section, "network") == 0);
                if (in_net && (strcmp(key, "start_ip") == 0 ||
                               strcmp(key, "start-ip") == 0)) {
                    char norm[32];
                    if (normalize_start_ip(val, norm, sizeof(norm)) == 0)
                        snprintf(cfg->start_ip, sizeof(cfg->start_ip), "%s",
                                 norm);
                } else if (in_net && (strcmp(key, "gateway") == 0 ||
                                      strcmp(key, "gateway_ip") == 0)) {
                    struct in_addr ina;
                    if (inet_pton(AF_INET, val, &ina) == 1)
                        snprintf(cfg->gateway_ip, sizeof(cfg->gateway_ip), "%s",
                                 val);
                }
            }
            fclose(f);
        }
    }

    if (!cfg->gateway_ip[0])
        derive_default_gateway(cfg->start_ip, cfg->gateway_ip,
                               sizeof(cfg->gateway_ip));
    return 0;
}

const char *kbox_daemon_net_gateway_ip(void)
{
    return g_bridge_ip;
}

/* Embedded DNS table. */
static pthread_mutex_t g_dns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dns_entry g_dns_entries[KBOX_DAEMON_MAX_HOSTS];
static pthread_t g_dns_thread;
static int g_dns_started;

/* Root-netns worker thread. */
static pthread_mutex_t g_netns_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_netns_req_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_netns_done_cv = PTHREAD_COND_INITIALIZER;
static struct netns_req *g_netns_pending;
static pthread_t g_netns_thread;
static int g_netns_started;

/* Port forwarding table. */
static pthread_mutex_t g_port_lock = PTHREAD_MUTEX_INITIALIZER;
static struct port_fwd_entry g_port_fwds[MAX_PORT_FORWARDS];

static int lkl_errno_or_ok(long r)
{
    return (r < 0) ? (int) r : 0;
}

/* Write a value into an LKL sysctl file. */
static void lkl_write_sysctl(const struct kbox_sysnrs *sysnrs,
                             const char *path,
                             const char *val)
{
    long fd =
        kbox_lkl_openat(sysnrs, AT_FDCWD_LINUX, path, 1 /* O_WRONLY */, 0);
    if (fd >= 0) {
        (void) kbox_lkl_write(sysnrs, fd, val, (long) strlen(val));
        (void) kbox_lkl_close(sysnrs, fd);
    }
}

/* Netlink attribute helpers. */

struct nl_buf {
    struct nlmsghdr nlh;
    struct ifinfomsg ifi;
    uint8_t buf[2048];
};

static struct rtattr *nl_tail(struct nl_buf *b)
{
    return (struct rtattr *) (((uint8_t *) b) + NLMSG_ALIGN(b->nlh.nlmsg_len));
}

static void nl_add_attr(struct nl_buf *b,
                        unsigned short type,
                        const void *data,
                        size_t len)
{
    struct rtattr *rta = nl_tail(b);
    size_t rta_len = RTA_LENGTH(len);

    if (NLMSG_ALIGN(b->nlh.nlmsg_len) + RTA_ALIGN(rta_len) > sizeof(*b))
        return;

    rta->rta_type = type;
    rta->rta_len = (unsigned short) rta_len;
    if (len > 0 && data)
        memcpy(RTA_DATA(rta), data, len);
    b->nlh.nlmsg_len =
        (unsigned int) (NLMSG_ALIGN(b->nlh.nlmsg_len) + RTA_ALIGN(rta_len));
}

static struct rtattr *nl_nest_begin(struct nl_buf *b, unsigned short type)
{
    struct rtattr *nest = nl_tail(b);
    nl_add_attr(b, type, NULL, 0);
    return nest;
}

static void nl_nest_end(struct nl_buf *b, struct rtattr *nest)
{
    nest->rta_len =
        (unsigned short) ((uint8_t *) nl_tail(b) - (uint8_t *) nest);
}

static void nl_add_ifinfo_stub(struct nl_buf *b, struct ifinfomsg **out)
{
    uint8_t *p = (uint8_t *) nl_tail(b);
    if (NLMSG_ALIGN(b->nlh.nlmsg_len) + NLMSG_ALIGN(sizeof(struct ifinfomsg)) >
        sizeof(*b))
        return;
    memset(p, 0, sizeof(struct ifinfomsg));
    *out = (struct ifinfomsg *) p;
    b->nlh.nlmsg_len = (unsigned int) (NLMSG_ALIGN(b->nlh.nlmsg_len) +
                                       NLMSG_ALIGN(sizeof(struct ifinfomsg)));
}

static int lkl_netlink_talk(const struct kbox_sysnrs *sysnrs,
                            struct nl_buf *req)
{
    long fd =
        lkl_syscall6(sysnrs->socket, LKL_AF_NETLINK, LKL_SOCK_RAW, 0, 0, 0, 0);
    if (fd < 0)
        return (int) fd;

    struct lkl_sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = LKL_AF_NETLINK;

    long r = kbox_lkl_bind(sysnrs, fd, &sa, sizeof(sa));
    if (r < 0) {
        kbox_lkl_close(sysnrs, fd);
        return (int) r;
    }

    r = kbox_lkl_sendto(sysnrs, fd, req, (long) req->nlh.nlmsg_len, 0, &sa,
                        sizeof(sa));
    if (r < 0) {
        kbox_lkl_close(sysnrs, fd);
        return (int) r;
    }

    uint8_t resp[4096];
    long n = kbox_lkl_recvfrom(sysnrs, fd, resp, sizeof(resp), 0, NULL, NULL);
    kbox_lkl_close(sysnrs, fd);
    if (n < 0)
        return (int) n;

    if ((size_t) n < sizeof(struct nlmsghdr))
        return -EPROTO;

    const struct nlmsghdr *nh = (const struct nlmsghdr *) resp;
    if (nh->nlmsg_type == NLMSG_ERROR &&
        (size_t) n >= NLMSG_HDRLEN + sizeof(struct nlmsgerr)) {
        const struct nlmsgerr *err =
            (const struct nlmsgerr *) (resp + NLMSG_HDRLEN);
        return err->error;
    }
    return 0;
}

static int lkl_get_ifindex(const struct kbox_sysnrs *sysnrs, const char *ifname)
{
    long sock = kbox_lkl_socket(sysnrs, 2 /* AF_INET */, LKL_SOCK_DGRAM, 0);
    if (sock < 0)
        return (int) sock;

    struct lkl_ifreq_idx ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.name, sizeof(ifr.name), "%s", ifname);

    long ret = lkl_syscall6(LKL_NR_IOCTL, sock, LKL_SIOCGIFINDEX, (long) &ifr,
                            0, 0, 0);
    kbox_lkl_close(sysnrs, sock);
    if (ret < 0)
        return (int) ret;
    return ifr.ifindex;
}

static int lkl_create_bridge(const struct kbox_sysnrs *sysnrs, const char *name)
{
    struct nl_buf req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;

    nl_add_attr(&req, IFLA_IFNAME, name, strlen(name) + 1);
    struct rtattr *li = nl_nest_begin(&req, IFLA_LINKINFO);
    nl_add_attr(&req, IFLA_INFO_KIND, "bridge", sizeof("bridge"));
    nl_nest_end(&req, li);

    int rc = lkl_netlink_talk(sysnrs, &req);
    if (rc == -EEXIST)
        rc = 0;
    return rc;
}

static int do_root_create_veth(const struct kbox_sysnrs *sysnrs,
                               const char *host_if,
                               const char *peer_if,
                               long peer_netns_fd,
                               const char *peer_ip)
{
    struct nl_buf req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq = 2;
    req.ifi.ifi_family = AF_UNSPEC;

    nl_add_attr(&req, IFLA_IFNAME, host_if, strlen(host_if) + 1);

    struct rtattr *li = nl_nest_begin(&req, IFLA_LINKINFO);
    nl_add_attr(&req, IFLA_INFO_KIND, "veth", sizeof("veth"));
    struct rtattr *ld = nl_nest_begin(&req, IFLA_INFO_DATA);
    struct rtattr *vp = nl_nest_begin(&req, VETH_INFO_PEER);
    struct ifinfomsg *peer_ifi = NULL;
    nl_add_ifinfo_stub(&req, &peer_ifi);
    if (peer_ifi)
        peer_ifi->ifi_family = AF_UNSPEC;
    nl_add_attr(&req, IFLA_IFNAME, peer_if, strlen(peer_if) + 1);
    int32_t nsfd32 = (int32_t) peer_netns_fd;
    nl_add_attr(&req, IFLA_NET_NS_FD, &nsfd32, sizeof(nsfd32));
    nl_nest_end(&req, vp);
    nl_nest_end(&req, ld);
    nl_nest_end(&req, li);

    int rc = lkl_netlink_talk(sysnrs, &req);
    if (rc < 0) {
        fprintf(stderr, "kboxd: netlink veth create (%s<->%s): %d (%s)\n",
                host_if, peer_if, rc, strerror(-rc));
        return rc;
    }

    int host_idx = lkl_get_ifindex(sysnrs, host_if);
    if (host_idx <= 0) {
        fprintf(stderr, "kboxd: cannot find ifindex for %s: %d\n", host_if,
                host_idx);
        return host_idx < 0 ? host_idx : -ENODEV;
    }

    /* Attach host_if to br0 and bring it UP. */
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_SETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 3;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = host_idx;
    req.ifi.ifi_change = LKL_IFF_UP;
    req.ifi.ifi_flags = LKL_IFF_UP;

    if (g_br0_ifindex > 0) {
        uint32_t master = (uint32_t) g_br0_ifindex;
        nl_add_attr(&req, IFLA_MASTER, &master, sizeof(master));
    }

    rc = lkl_netlink_talk(sysnrs, &req);
    if (rc < 0) {
        fprintf(stderr, "kboxd: netlink setlink (%s -> br0): %d (%s)\n",
                host_if, rc, strerror(-rc));
        return rc;
    }

    if (peer_ip && peer_ip[0] &&
        kbox_net_add_host_route(sysnrs, KBOX_DAEMON_BRIDGE_NAME, peer_ip) < 0) {
        fprintf(stderr, "kboxd: host route add (%s/32 dev %s) failed\n",
                peer_ip, KBOX_DAEMON_BRIDGE_NAME);
        return -EIO;
    }
    return 0;
}

static int do_root_delete_link(const struct kbox_sysnrs *sysnrs,
                               const char *ifname,
                               const char *peer_ip)
{
    if (peer_ip && peer_ip[0])
        kbox_net_del_host_route(sysnrs, KBOX_DAEMON_BRIDGE_NAME, peer_ip);

    int idx = lkl_get_ifindex(sysnrs, ifname);
    if (idx <= 0)
        return 0;

    struct nl_buf req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_DELLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 4;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = idx;

    return lkl_errno_or_ok(lkl_netlink_talk(sysnrs, &req));
}

/* Best-effort MASQUERADE rule so 172.18.0.0/16 can reach SLIRP eth0 if needed.
 * Uses IPT_SO_GET_INFO / IPT_SO_SET_REPLACE on LKL's nat table.
 */
static void setup_nat_masquerade(const struct kbox_sysnrs *sysnrs)
{
    long sock = kbox_lkl_socket(sysnrs, 2 /* AF_INET */, LKL_SOCK_DGRAM, 0);
    if (sock < 0)
        return;

    struct ipt_getinfo info;
    memset(&info, 0, sizeof(info));
    snprintf(info.name, sizeof(info.name), "nat");
    unsigned int ilen = sizeof(info);
    if (kbox_lkl_getsockopt(sysnrs, sock, IPPROTO_IP, IPT_SO_GET_INFO, &info,
                            &ilen) < 0) {
        kbox_lkl_close(sysnrs, sock);
        return;
    }

    size_t get_sz = sizeof(struct ipt_get_entries) + info.size;
    struct ipt_get_entries *cur = calloc(1, get_sz);
    if (!cur) {
        kbox_lkl_close(sysnrs, sock);
        return;
    }
    snprintf(cur->name, sizeof(cur->name), "nat");
    cur->size = info.size;
    unsigned int glen = (unsigned int) get_sz;
    if (kbox_lkl_getsockopt(sysnrs, sock, IPPROTO_IP, IPT_SO_GET_ENTRIES, cur,
                            &glen) < 0) {
        free(cur);
        kbox_lkl_close(sysnrs, sock);
        return;
    }

    /* Build single MASQUERADE rule in POSTROUTING before existing entries. */
    size_t target_sz = XT_ALIGN(sizeof(struct xt_entry_target) +
                                sizeof(struct nf_nat_ipv4_multi_range_compat));
    size_t rule_sz = sizeof(struct ipt_entry) + target_sz;
    size_t rep_sz = sizeof(struct ipt_replace) + rule_sz + info.size;
    struct ipt_replace *rep = calloc(1, rep_sz);
    if (!rep) {
        free(cur);
        kbox_lkl_close(sysnrs, sock);
        return;
    }

    snprintf(rep->name, sizeof(rep->name), "nat");
    rep->valid_hooks = info.valid_hooks;
    rep->num_entries = info.num_entries + 1;
    rep->size = info.size + (unsigned int) rule_sz;

    /* Find hook offset of NF_INET_POST_ROUTING (hook 4). */
    unsigned int post_off = info.hook_entry[4];
    for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
        rep->hook_entry[h] = info.hook_entry[h];
        rep->underflow[h] = info.underflow[h];
        if ((info.valid_hooks & (1U << h)) && h > 4) {
            rep->hook_entry[h] += (unsigned int) rule_sz;
            rep->underflow[h] += (unsigned int) rule_sz;
        }
        if (h == 4)
            rep->underflow[h] += (unsigned int) rule_sz;
    }

    uint8_t *dst = (uint8_t *) rep->entries;
    const uint8_t *src = (const uint8_t *) cur->entrytable;
    if (post_off > 0 && post_off <= info.size)
        memcpy(dst, src, post_off);

    struct ipt_entry *e = (struct ipt_entry *) (dst + post_off);
    snprintf(e->ip.outiface, sizeof(e->ip.outiface), "eth0");
    memset(e->ip.outiface_mask, 0xff, strlen("eth0") + 1);
    e->target_offset = sizeof(struct ipt_entry);
    e->next_offset = (uint16_t) rule_sz;

    struct xt_entry_target *t = (struct xt_entry_target *) (e + 1);
    t->u.user.target_size = (uint16_t) target_sz;
    snprintf(t->u.user.name, sizeof(t->u.user.name), "MASQUERADE");
    t->u.user.revision = 0;
    struct nf_nat_ipv4_multi_range_compat *mr =
        (struct nf_nat_ipv4_multi_range_compat *) t->data;
    mr->rangesize = 1;

    if (info.size > post_off)
        memcpy(dst + post_off + rule_sz, src + post_off, info.size - post_off);

    rep->num_counters = info.num_entries;
    struct xt_counters *ctrs =
        calloc(rep->num_counters > 0 ? rep->num_counters : 1,
               sizeof(struct xt_counters));
    rep->counters = ctrs;

    long rc = kbox_lkl_setsockopt(sysnrs, sock, IPPROTO_IP, IPT_SO_SET_REPLACE,
                                  rep, (long) rep_sz);
    if (rc < 0 && g_verbose)
        fprintf(stderr, "kboxd: nat MASQUERADE skipped (%ld)\n", rc);
    else if (g_verbose)
        fprintf(stderr, "kboxd: net: NAT MASQUERADE enabled (br0 -> eth0)\n");

    free(ctrs);
    free(rep);
    free(cur);
    kbox_lkl_close(sysnrs, sock);
}

static void *root_netns_worker(void *arg)
{
    (void) arg;
    for (;;) {
        pthread_mutex_lock(&g_netns_lock);
        while (!g_netns_pending)
            pthread_cond_wait(&g_netns_req_cv, &g_netns_lock);

        struct netns_req *r = g_netns_pending;
        g_netns_pending = NULL;
        pthread_mutex_unlock(&g_netns_lock);

        if (r->op == NETNS_OP_STOP) {
            pthread_mutex_lock(&g_netns_lock);
            r->done = 1;
            pthread_cond_broadcast(&g_netns_done_cv);
            pthread_mutex_unlock(&g_netns_lock);
            break;
        }

        int rc = -EINVAL;
        if (r->op == NETNS_OP_CREATE_VETH)
            rc = do_root_create_veth(r->sysnrs, r->host_if, r->peer_if,
                                     r->peer_netns_fd, r->peer_ip);
        else if (r->op == NETNS_OP_DELETE_LINK)
            rc = do_root_delete_link(r->sysnrs, r->host_if, r->peer_ip);

        pthread_mutex_lock(&g_netns_lock);
        r->result = rc;
        r->done = 1;
        pthread_cond_broadcast(&g_netns_done_cv);
        pthread_mutex_unlock(&g_netns_lock);
    }
    return NULL;
}

static int submit_netns_req(struct netns_req *r)
{
    pthread_mutex_lock(&g_netns_lock);
    while (g_netns_pending) {
        struct timespec ts = {0, 5 * 1000 * 1000};
        pthread_mutex_unlock(&g_netns_lock);
        nanosleep(&ts, NULL);
        pthread_mutex_lock(&g_netns_lock);
    }
    r->done = 0;
    g_netns_pending = r;
    pthread_cond_signal(&g_netns_req_cv);
    while (!r->done)
        pthread_cond_wait(&g_netns_done_cv, &g_netns_lock);
    int res = r->result;
    pthread_mutex_unlock(&g_netns_lock);
    return res;
}

int kbox_daemon_net_create_veth(const struct kbox_sysnrs *sysnrs,
                                const char *host_if,
                                const char *peer_if,
                                long peer_netns_fd,
                                const char *peer_ip)
{
    struct netns_req req;
    memset(&req, 0, sizeof(req));
    req.op = NETNS_OP_CREATE_VETH;
    req.sysnrs = sysnrs;
    snprintf(req.host_if, sizeof(req.host_if), "%s", host_if);
    snprintf(req.peer_if, sizeof(req.peer_if), "%s", peer_if);
    if (peer_ip)
        snprintf(req.peer_ip, sizeof(req.peer_ip), "%s", peer_ip);
    req.peer_netns_fd = peer_netns_fd;
    return submit_netns_req(&req);
}

int kbox_daemon_net_delete_link(const struct kbox_sysnrs *sysnrs,
                                const char *ifname,
                                const char *peer_ip)
{
    struct netns_req req;
    memset(&req, 0, sizeof(req));
    req.op = NETNS_OP_DELETE_LINK;
    req.sysnrs = sysnrs;
    snprintf(req.host_if, sizeof(req.host_if), "%s", ifname);
    if (peer_ip)
        snprintf(req.peer_ip, sizeof(req.peer_ip), "%s", peer_ip);
    return submit_netns_req(&req);
}

int kbox_daemon_net_alloc_ip(char *buf, size_t len)
{
    pthread_mutex_lock(&g_ip_lock);
    uint32_t ip = 0;
    for (int tries = 0; tries < 65536; tries++) {
        uint32_t cand = g_next_ip_host++;
        if (g_next_ip_host - g_start_ip_host > 65000U)
            g_next_ip_host = g_start_ip_host;
        uint32_t last = cand & 0xffU;
        if (last == 0U || last == 255U || cand == g_gw_ip_host)
            continue;
        ip = cand;
        break;
    }
    pthread_mutex_unlock(&g_ip_lock);

    if (!ip)
        return -1;

    struct in_addr ina;
    ina.s_addr = htonl(ip);
    return inet_ntop(AF_INET, &ina, buf, (socklen_t) len) ? 0 : -1;
}

int kbox_daemon_dns_register(const char *name, const char *ip_str)
{
    if (!name || !*name || !ip_str || !*ip_str)
        return -1;

    struct in_addr ina;
    if (inet_pton(AF_INET, ip_str, &ina) != 1)
        return -1;

    pthread_mutex_lock(&g_dns_lock);
    for (int i = 0; i < KBOX_DAEMON_MAX_HOSTS; i++) {
        if (g_dns_entries[i].used &&
            strcasecmp(g_dns_entries[i].name, name) == 0) {
            g_dns_entries[i].ip_be = ina.s_addr;
            snprintf(g_dns_entries[i].ip_str, sizeof(g_dns_entries[i].ip_str),
                     "%s", ip_str);
            pthread_mutex_unlock(&g_dns_lock);
            return 0;
        }
    }
    for (int i = 0; i < KBOX_DAEMON_MAX_HOSTS; i++) {
        if (!g_dns_entries[i].used) {
            g_dns_entries[i].used = 1;
            snprintf(g_dns_entries[i].name, sizeof(g_dns_entries[i].name), "%s",
                     name);
            g_dns_entries[i].ip_be = ina.s_addr;
            snprintf(g_dns_entries[i].ip_str, sizeof(g_dns_entries[i].ip_str),
                     "%s", ip_str);
            pthread_mutex_unlock(&g_dns_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_dns_lock);
    return -ENOSPC;
}

void kbox_daemon_dns_unregister_ip(const char *ip_str)
{
    if (!ip_str || !*ip_str)
        return;

    pthread_mutex_lock(&g_dns_lock);
    for (int i = 0; i < KBOX_DAEMON_MAX_HOSTS; i++) {
        if (g_dns_entries[i].used &&
            strcmp(g_dns_entries[i].ip_str, ip_str) == 0) {
            memset(&g_dns_entries[i], 0, sizeof(g_dns_entries[i]));
        }
    }
    pthread_mutex_unlock(&g_dns_lock);
}

size_t kbox_daemon_dns_format_hosts(char *buf, size_t cap)
{
    size_t pos = 0;
    int n = snprintf(buf, cap, "127.0.0.1 localhost\n::1 localhost\n");
    if (n > 0 && (size_t) n < cap)
        pos = (size_t) n;

    pthread_mutex_lock(&g_dns_lock);
    for (int i = 0; i < KBOX_DAEMON_MAX_HOSTS; i++) {
        if (!g_dns_entries[i].used)
            continue;
        n = snprintf(buf + pos, cap - pos, "%s %s\n", g_dns_entries[i].ip_str,
                     g_dns_entries[i].name);
        if (n <= 0 || pos + (size_t) n >= cap)
            break;
        pos += (size_t) n;
    }
    pthread_mutex_unlock(&g_dns_lock);
    return pos;
}

/* Parse DNS QNAME starting at off in pkt[0..pkt_len], writing dotted name.
 * Returns offset right after the terminating 0-label (pointing at QTYPE), or
 * -1.
 */
static int dns_parse_qname(const uint8_t *pkt,
                           size_t pkt_len,
                           size_t off,
                           char *out,
                           size_t out_cap)
{
    size_t out_pos = 0;
    while (off < pkt_len) {
        uint8_t llen = pkt[off++];
        if (llen == 0) {
            if (out_pos < out_cap)
                out[out_pos] = '\0';
            return (int) off;
        }
        if ((llen & 0xc0) != 0)
            return -1;
        if (off + llen > pkt_len)
            return -1;
        if (out_pos > 0) {
            if (out_pos + 1 >= out_cap)
                return -1;
            out[out_pos++] = '.';
        }
        if (out_pos + llen >= out_cap)
            return -1;
        memcpy(out + out_pos, pkt + off, llen);
        out_pos += llen;
        off += llen;
    }
    return -1;
}

static int dns_lookup_local(const char *qname, uint32_t *ip_be_out)
{
    char clean[KBOX_DAEMON_MAX_ALIAS];
    size_t len = strlen(qname);
    while (len > 0 && qname[len - 1] == '.')
        len--;
    if (len == 0 || len >= sizeof(clean))
        return 0;
    memcpy(clean, qname, len);
    clean[len] = '\0';

    pthread_mutex_lock(&g_dns_lock);
    for (int i = 0; i < KBOX_DAEMON_MAX_HOSTS; i++) {
        if (g_dns_entries[i].used &&
            strcasecmp(g_dns_entries[i].name, clean) == 0) {
            *ip_be_out = g_dns_entries[i].ip_be;
            pthread_mutex_unlock(&g_dns_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_dns_lock);
    return 0;
}

static int dns_forward_upstream(const struct kbox_sysnrs *sysnrs,
                                const uint8_t *query,
                                size_t qlen,
                                uint8_t *resp,
                                size_t resp_cap)
{
    long usock =
        kbox_lkl_socket(sysnrs, AF_INET, LKL_SOCK_DGRAM | LKL_SOCK_NONBLOCK, 0);
    if (usock < 0)
        return -1;

    struct sockaddr_in up;
    memset(&up, 0, sizeof(up));
    up.sin_family = AF_INET;
    up.sin_port = htons(KBOX_DAEMON_DNS_PORT);
    inet_pton(AF_INET, UPSTREAM_DNS_IP, &up.sin_addr);

    if (kbox_lkl_sendto(sysnrs, usock, query, (long) qlen, 0, &up, sizeof(up)) <
        0) {
        kbox_lkl_close(sysnrs, usock);
        return -1;
    }

    struct pollfd pfd = {.fd = (int) usock, .events = POLLIN, .revents = 0};
    struct timespec ts = {0, 400 * 1000 * 1000};
    long pr = lkl_syscall6(sysnrs->ppoll, (long) &pfd, 1, (long) &ts, 0, 8, 0);
    if (pr <= 0 || !(pfd.revents & POLLIN)) {
        kbox_lkl_close(sysnrs, usock);
        return -1;
    }

    long rn =
        kbox_lkl_recvfrom(sysnrs, usock, resp, (long) resp_cap, 0, NULL, NULL);
    kbox_lkl_close(sysnrs, usock);
    return (rn > 0) ? (int) rn : -1;
}

static void *dns_server_thread(void *arg)
{
    (void) arg;
    const struct kbox_sysnrs *sysnrs = g_sysnrs;

    long sock =
        kbox_lkl_socket(sysnrs, AF_INET, LKL_SOCK_DGRAM | LKL_SOCK_NONBLOCK, 0);
    if (sock < 0) {
        fprintf(stderr, "kboxd: dns socket failed: %ld\n", sock);
        return NULL;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(KBOX_DAEMON_DNS_PORT);
    inet_pton(AF_INET, g_bridge_ip, &bind_addr.sin_addr);

    if (kbox_lkl_bind(sysnrs, sock, &bind_addr, sizeof(bind_addr)) < 0) {
        /* Fallback to INADDR_ANY if bridge IP bind returned EADDRNOTAVAIL. */
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (kbox_lkl_bind(sysnrs, sock, &bind_addr, sizeof(bind_addr)) < 0) {
            fprintf(stderr, "kboxd: dns bind failed\n");
            kbox_lkl_close(sysnrs, sock);
            return NULL;
        }
    }

    if (g_verbose)
        fprintf(stderr, "kboxd: dns server listening on %s:%d\n", g_bridge_ip,
                KBOX_DAEMON_DNS_PORT);

    while (__atomic_load_n(&g_running, __ATOMIC_ACQUIRE)) {
        struct pollfd pfd = {.fd = (int) sock, .events = POLLIN, .revents = 0};
        struct timespec ts = {0, 50 * 1000 * 1000};
        long pr =
            lkl_syscall6(sysnrs->ppoll, (long) &pfd, 1, (long) &ts, 0, 8, 0);
        if (pr <= 0 || !(pfd.revents & POLLIN))
            continue;

        uint8_t pkt[DNS_BUF_LEN];
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        long n =
            kbox_lkl_recvfrom(sysnrs, sock, pkt, sizeof(pkt), 0, &cli, &clilen);
        if (n < 12)
            continue;

        uint16_t qdcount = (uint16_t) ((pkt[4] << 8) | pkt[5]);
        if (qdcount == 0)
            continue;

        char qname[KBOX_DAEMON_MAX_ALIAS];
        int qend = dns_parse_qname(pkt, (size_t) n, 12, qname, sizeof(qname));
        if (qend < 0 || qend + 4 > (int) n)
            continue;

        uint16_t qtype = (uint16_t) ((pkt[qend] << 8) | pkt[qend + 1]);
        uint16_t qclass = (uint16_t) ((pkt[qend + 2] << 8) | pkt[qend + 3]);

        uint32_t ip_be = 0;
        if (qclass == 1 && dns_lookup_local(qname, &ip_be)) {
            uint8_t resp[DNS_BUF_LEN];
            size_t rlen = (size_t) (qend + 4);
            memcpy(resp, pkt, rlen);
            /* QR=1, AA=1, RA=1, RCODE=0 (NOERROR). */
            resp[2] = (uint8_t) (0x84 | (pkt[2] & 0x01));
            resp[3] = 0x80;
            resp[4] = 0;
            resp[5] = 1;
            resp[8] = 0;
            resp[9] = 0;
            resp[10] = 0;
            resp[11] = 0;

            if ((qtype == 1 || qtype == 255) && rlen + 16 <= sizeof(resp)) {
                resp[6] = 0;
                resp[7] = 1;
                uint8_t ans[16] = {0xc0, 0x0c, /* pointer to offset 12 */
                                   0x00, 0x01, /* TYPE A */
                                   0x00, 0x01, /* CLASS IN */
                                   0x00, 0x00, 0x00, 0x05, /* TTL 5s */
                                   0x00, 0x04,             /* RDLENGTH 4 */
                                   0,    0,    0,    0};
                memcpy(ans + 12, &ip_be, 4);
                memcpy(resp + rlen, ans, 16);
                rlen += 16;
            } else {
                /* For AAAA (28) etc. on known local hosts: NOERROR empty answer
                 * so musl/glibc accepts the companion A answer immediately.
                 */
                resp[6] = 0;
                resp[7] = 0;
            }
            (void) kbox_lkl_sendto(sysnrs, sock, resp, (long) rlen, 0, &cli,
                                   (long) clilen);
            continue;
        }

        uint8_t uresp[DNS_BUF_LEN];
        int urn =
            dns_forward_upstream(sysnrs, pkt, (size_t) n, uresp, sizeof(uresp));
        if (urn > 0) {
            (void) kbox_lkl_sendto(sysnrs, sock, uresp, (long) urn, 0, &cli,
                                   (long) clilen);
        } else {
            uint8_t nxd[DNS_BUF_LEN];
            size_t rlen = (size_t) (qend + 4);
            memcpy(nxd, pkt, rlen);
            nxd[2] = (uint8_t) (0x81 | (pkt[2] & 0x01));
            nxd[3] = 0x83; /* RCODE=3 NXDOMAIN */
            nxd[6] = 0;
            nxd[7] = 0;
            nxd[8] = 0;
            nxd[9] = 0;
            nxd[10] = 0;
            nxd[11] = 0;
            (void) kbox_lkl_sendto(sysnrs, sock, nxd, (long) rlen, 0, &cli,
                                   (long) clilen);
        }
    }

    kbox_lkl_close(sysnrs, sock);
    return NULL;
}

/* Host port forwarding (host TCP -> LKL container TCP). */

static void tcp_pump_release(struct tcp_pump_args *a)
{
    pthread_mutex_lock(a->close_lock);
    int left = --(*a->refcount);
    pthread_mutex_unlock(a->close_lock);

    if (left == 0) {
        close(a->host_fd);
        kbox_lkl_close(a->sysnrs, a->lkl_fd);
        pthread_mutex_destroy(a->close_lock);
        free(a->close_lock);
        free((void *) a->shutdown_flag);
        free(a->refcount);
    }
    free(a);
}

static void tcp_pump_finish(struct tcp_pump_args *a)
{
    __atomic_store_n(a->shutdown_flag, 1, __ATOMIC_RELEASE);
    shutdown(a->host_fd, SHUT_RDWR);
    kbox_lkl_shutdown(a->sysnrs, a->lkl_fd, LKL_SHUT_RDWR);
    tcp_pump_release(a);
}

static void *pump_host_to_lkl(void *arg)
{
    struct tcp_pump_args *a = arg;
    uint8_t buf[32768];

    for (;;) {
        if (__atomic_load_n(a->shutdown_flag, __ATOMIC_ACQUIRE))
            break;
        ssize_t n = read(a->host_fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0) {
            /* Preserve server->host response stream on half-close (SHUT_WR). */
            kbox_lkl_shutdown(a->sysnrs, a->lkl_fd, LKL_SHUT_WR);
            tcp_pump_release(a);
            return NULL;
        }
        if (n < 0)
            break;

        size_t off = 0;
        while (off < (size_t) n) {
            long w = kbox_lkl_sendto(a->sysnrs, a->lkl_fd, buf + off,
                                     (long) ((size_t) n - off), 0, NULL, 0);
            if (w == -EINTR)
                continue;
            if (w <= 0)
                goto done;
            off += (size_t) w;
        }
    }
done:
    tcp_pump_finish(a);
    return NULL;
}

static void *pump_lkl_to_host(void *arg)
{
    struct tcp_pump_args *a = arg;
    uint8_t buf[32768];

    for (;;) {
        if (__atomic_load_n(a->shutdown_flag, __ATOMIC_ACQUIRE))
            break;
        long n = kbox_lkl_recvfrom(a->sysnrs, a->lkl_fd, buf, sizeof(buf), 0,
                                   NULL, NULL);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            break;

        size_t off = 0;
        while (off < (size_t) n) {
            ssize_t w = write(a->host_fd, buf + off, (size_t) n - off);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0)
                goto done;
            off += (size_t) w;
        }
    }
done:
    tcp_pump_finish(a);
    return NULL;
}

static void *port_accept_thread(void *arg)
{
    struct port_fwd_entry *pf = arg;

    while (!__atomic_load_n(&pf->stop, __ATOMIC_ACQUIRE) &&
           __atomic_load_n(&g_running, __ATOMIC_ACQUIRE)) {
        struct pollfd pfd = {
            .fd = pf->listen_fd,
            .events = POLLIN,
            .revents = 0,
        };
        int pr = poll(&pfd, 1, 100);
        if (pr <= 0 || !(pfd.revents & POLLIN))
            continue;

        int host_fd = accept4(pf->listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (host_fd < 0)
            continue;

        long lkl_fd = kbox_lkl_socket(pf->sysnrs, AF_INET, LKL_SOCK_STREAM, 0);
        if (lkl_fd < 0) {
            close(host_fd);
            continue;
        }

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons((uint16_t) pf->container_port);
        inet_pton(AF_INET, pf->container_ip, &dst.sin_addr);

        if (kbox_lkl_connect(pf->sysnrs, lkl_fd, &dst, sizeof(dst)) < 0) {
            kbox_lkl_close(pf->sysnrs, lkl_fd);
            close(host_fd);
            continue;
        }

        volatile int *shut = calloc(1, sizeof(int));
        int *refcount = malloc(sizeof(int));
        pthread_mutex_t *clock = malloc(sizeof(pthread_mutex_t));
        struct tcp_pump_args *a1 = malloc(sizeof(*a1));
        struct tcp_pump_args *a2 = malloc(sizeof(*a2));
        if (!shut || !refcount || !clock || !a1 || !a2) {
            free((void *) shut);
            free(refcount);
            free(clock);
            free(a1);
            free(a2);
            kbox_lkl_close(pf->sysnrs, lkl_fd);
            close(host_fd);
            continue;
        }

        *refcount = 2;
        pthread_mutex_init(clock, NULL);

        a1->host_fd = host_fd;
        a1->lkl_fd = lkl_fd;
        a1->sysnrs = pf->sysnrs;
        a1->shutdown_flag = shut;
        a1->close_lock = clock;
        a1->refcount = refcount;

        *a2 = *a1;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_t t1, t2;
        if (pthread_create(&t1, &attr, pump_host_to_lkl, a1) != 0) {
            pthread_attr_destroy(&attr);
            tcp_pump_finish(a1);
            tcp_pump_finish(a2);
            continue;
        }
        if (pthread_create(&t2, &attr, pump_lkl_to_host, a2) != 0) {
            pthread_attr_destroy(&attr);
            tcp_pump_finish(a2);
            continue;
        }
        pthread_attr_destroy(&attr);
    }
    return NULL;
}

int kbox_daemon_port_add(const struct kbox_sysnrs *sysnrs,
                         const char *host_ip,
                         int host_port,
                         const char *container_ip,
                         int container_port)
{
    if (host_port <= 0 || host_port > 65535 || container_port <= 0 ||
        container_port > 65535 || !container_ip)
        return -EINVAL;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t) host_port);
    const char *bind_ip = (host_ip && host_ip[0]) ? host_ip : "0.0.0.0";
    if (strcmp(bind_ip, "0.0.0.0") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        return -EINVAL;
    }

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0)
        return -errno;

    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(lfd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        int err = -errno;
        close(lfd);
        return err;
    }
    if (listen(lfd, 64) < 0) {
        int err = -errno;
        close(lfd);
        return err;
    }

    pthread_mutex_lock(&g_port_lock);
    struct port_fwd_entry *slot = NULL;
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (!g_port_fwds[i].active) {
            slot = &g_port_fwds[i];
            break;
        }
    }
    if (!slot) {
        pthread_mutex_unlock(&g_port_lock);
        close(lfd);
        return -ENOSPC;
    }

    memset(slot, 0, sizeof(*slot));
    slot->active = 1;
    snprintf(slot->host_ip, sizeof(slot->host_ip), "%s", bind_ip);
    slot->host_port = host_port;
    snprintf(slot->container_ip, sizeof(slot->container_ip), "%s",
             container_ip);
    slot->container_port = container_port;
    slot->listen_fd = lfd;
    slot->sysnrs = sysnrs;

    if (pthread_create(&slot->thread, NULL, port_accept_thread, slot) != 0) {
        slot->active = 0;
        pthread_mutex_unlock(&g_port_lock);
        close(lfd);
        return -EAGAIN;
    }
    pthread_mutex_unlock(&g_port_lock);

    if (g_verbose)
        fprintf(stderr, "kboxd: forwarding host %s:%d -> %s:%d\n", bind_ip,
                host_port, container_ip, container_port);
    return 0;
}

void kbox_daemon_port_remove_ip(const char *container_ip)
{
    if (!container_ip || !*container_ip)
        return;

    pthread_t to_join[MAX_PORT_FORWARDS];
    int nj = 0;

    pthread_mutex_lock(&g_port_lock);
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (g_port_fwds[i].active &&
            strcmp(g_port_fwds[i].container_ip, container_ip) == 0) {
            __atomic_store_n(&g_port_fwds[i].stop, 1, __ATOMIC_RELEASE);
            if (g_port_fwds[i].listen_fd >= 0) {
                shutdown(g_port_fwds[i].listen_fd, SHUT_RDWR);
                close(g_port_fwds[i].listen_fd);
                g_port_fwds[i].listen_fd = -1;
            }
            to_join[nj++] = g_port_fwds[i].thread;
            g_port_fwds[i].active = 0;
        }
    }
    pthread_mutex_unlock(&g_port_lock);

    for (int i = 0; i < nj; i++)
        pthread_join(to_join[i], NULL);
}

int kbox_daemon_net_init(const struct kbox_sysnrs *sysnrs,
                         const struct kbox_daemon_config *cfg,
                         int verbose)
{
    g_sysnrs = sysnrs;
    g_verbose = verbose;
    __atomic_store_n(&g_running, 1, __ATOMIC_RELEASE);

    const char *start_ip = (cfg && cfg->start_ip[0])
                               ? cfg->start_ip
                               : KBOX_DAEMON_DEFAULT_START_IP;
    const char *gw_ip = (cfg && cfg->gateway_ip[0]) ? cfg->gateway_ip
                                                    : KBOX_DAEMON_DEFAULT_GW_IP;

    struct in_addr sa, ga;
    if (inet_pton(AF_INET, start_ip, &sa) != 1)
        inet_pton(AF_INET, KBOX_DAEMON_DEFAULT_START_IP, &sa);
    if (inet_pton(AF_INET, gw_ip, &ga) != 1) {
        inet_pton(AF_INET, KBOX_DAEMON_DEFAULT_GW_IP, &ga);
        gw_ip = KBOX_DAEMON_DEFAULT_GW_IP;
    }
    pthread_mutex_lock(&g_ip_lock);
    g_start_ip_host = ntohl(sa.s_addr);
    g_next_ip_host = g_start_ip_host;
    g_gw_ip_host = ntohl(ga.s_addr);
    snprintf(g_bridge_ip, sizeof(g_bridge_ip), "%s", gw_ip);
    pthread_mutex_unlock(&g_ip_lock);

    /* Enable IPv4 forwarding and disable ICMP redirects in LKL root netns
     * so br0 <-> br0 routing between /32 containers works cleanly.
     */
    lkl_write_sysctl(sysnrs, "/proc/sys/net/ipv4/ip_forward", "1\n");
    lkl_write_sysctl(sysnrs, "/proc/sys/net/ipv4/conf/all/send_redirects",
                     "0\n");
    lkl_write_sysctl(sysnrs, "/proc/sys/net/ipv4/conf/default/send_redirects",
                     "0\n");

    int rc = lkl_create_bridge(sysnrs, KBOX_DAEMON_BRIDGE_NAME);
    if (rc < 0) {
        fprintf(stderr, "kboxd: failed to create %s: %d (%s)\n",
                KBOX_DAEMON_BRIDGE_NAME, rc, strerror(-rc));
        return -1;
    }

    if (kbox_net_configure_ipv4(sysnrs, KBOX_DAEMON_BRIDGE_NAME, g_bridge_ip,
                                KBOX_DAEMON_HOST_MASK, NULL) < 0) {
        fprintf(stderr, "kboxd: failed to configure %s\n",
                KBOX_DAEMON_BRIDGE_NAME);
        return -1;
    }

    g_br0_ifindex = lkl_get_ifindex(sysnrs, KBOX_DAEMON_BRIDGE_NAME);
    if (verbose)
        fprintf(stderr,
                "kboxd: bridge %s up (gw %s/32, start_ip %s, ifindex=%d)\n",
                KBOX_DAEMON_BRIDGE_NAME, g_bridge_ip, start_ip, g_br0_ifindex);

    setup_nat_masquerade(sysnrs);

    if (pthread_create(&g_netns_thread, NULL, root_netns_worker, NULL) != 0) {
        fprintf(stderr, "kboxd: failed to start root netns thread\n");
        return -1;
    }
    g_netns_started = 1;

    if (pthread_create(&g_dns_thread, NULL, dns_server_thread, NULL) != 0) {
        fprintf(stderr, "kboxd: failed to start DNS thread\n");
        return -1;
    }
    g_dns_started = 1;
    return 0;
}

void kbox_daemon_net_cleanup(void)
{
    __atomic_store_n(&g_running, 0, __ATOMIC_RELEASE);

    pthread_t to_join[MAX_PORT_FORWARDS];
    int nj = 0;
    pthread_mutex_lock(&g_port_lock);
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (g_port_fwds[i].active) {
            __atomic_store_n(&g_port_fwds[i].stop, 1, __ATOMIC_RELEASE);
            if (g_port_fwds[i].listen_fd >= 0) {
                shutdown(g_port_fwds[i].listen_fd, SHUT_RDWR);
                close(g_port_fwds[i].listen_fd);
                g_port_fwds[i].listen_fd = -1;
            }
            to_join[nj++] = g_port_fwds[i].thread;
            g_port_fwds[i].active = 0;
        }
    }
    pthread_mutex_unlock(&g_port_lock);
    for (int i = 0; i < nj; i++)
        pthread_join(to_join[i], NULL);

    if (g_dns_started) {
        pthread_join(g_dns_thread, NULL);
        g_dns_started = 0;
    }
    if (g_netns_started) {
        struct netns_req stop_req;
        memset(&stop_req, 0, sizeof(stop_req));
        stop_req.op = NETNS_OP_STOP;
        submit_netns_req(&stop_req);
        pthread_join(g_netns_thread, NULL);
        g_netns_started = 0;
    }
}
