#ifndef __HELPER_H__
#define __HELPER_H__

#include "heartbeat.h"
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../../xdp-tools/headers/xdp/xsk.h"
#include "../../xdp-tools/headers/xdp/libxdp.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* -------------------------------------------------------------------------
 * Common constants
 * ------------------------------------------------------------------------- */

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

/* Print a network-byte-order uint32_t as a.b.c.d (expands to 4 comma-separated args) */
#define FMT_IP(ip)                       \
    (unsigned)((ip) & 0xFF),             \
        (unsigned)(((ip) >> 8) & 0xFF),  \
        (unsigned)(((ip) >> 16) & 0xFF), \
        (unsigned)(((ip) >> 24) & 0xFF)

/* -------------------------------------------------------------------------
 * Common structs
 * ------------------------------------------------------------------------- */

struct config
{
    __u32 xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char *redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progsec[32];
    char src_mac[18];
    char dest_mac[18];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

struct xsk_umem_info
{
    struct xsk_umem *umem;
    void *buffer;
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
};

struct xsk_socket_info
{
    int id;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint32_t outstanding_tx;
    int is_input;
};

/* -------------------------------------------------------------------------
 * UMEM helpers
 * ------------------------------------------------------------------------- */

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
    r->cached_cons = *r->consumer + r->size;
    return r->cached_cons - r->cached_prod;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
    if (ret)
    {
        errno = -ret;
        free(umem);
        return NULL;
    }

    for (int i = 0; i < NUM_FRAMES; i++)
        umem->umem_frame_addr[i] = i * FRAME_SIZE;

    umem->umem_frame_free = NUM_FRAMES;
    umem->buffer = buffer;
    return umem;
}

static uint64_t alloc_umem_frame(struct xsk_umem_info *umem)
{
    if (umem->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    uint64_t frame = umem->umem_frame_addr[--umem->umem_frame_free];
    umem->umem_frame_addr[umem->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void free_umem_frame(struct xsk_umem_info *umem, uint64_t frame)
{
    assert(umem->umem_frame_free < NUM_FRAMES);
    umem->umem_frame_addr[umem->umem_frame_free++] = frame;
}

static uint64_t umem_free_frames(struct xsk_umem_info *umem)
{
    return umem->umem_frame_free;
}

/* -------------------------------------------------------------------------
 * Socket helpers
 * ------------------------------------------------------------------------- */

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
                                                    struct xsk_umem_info *umem)
{
    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;

    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = cfg->xdp_flags,
        .bind_flags = cfg->xsk_bind_flags,
    };

    int ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
                                        cfg->xsk_if_queue, umem->umem,
                                        &xsk_info->rx, &xsk_info->tx,
                                        &xsk_info->fq, &xsk_info->cq, &xsk_cfg);
    if (ret)
    {
        errno = -ret;
        free(xsk_info);
        return NULL;
    }

    return xsk_info;
}

/*
 * setup_fq – fill the receive fill-ring of xsk.
 * num_sockets: total sockets sharing this umem; the budget is divided evenly
 * so no socket starves the others.  Pass 1 when the socket owns the umem alone.
 */
static void setup_fq(struct xsk_socket_info *xsk, int num_sockets)
{
    uint32_t budget = XSK_RING_PROD__DEFAULT_NUM_DESCS / num_sockets;
    uint32_t idx;

    int ret = xsk_ring_prod__reserve(&xsk->fq, budget, &idx);
    if (ret != (int)budget)
        exit(EXIT_FAILURE);

    for (uint32_t i = 0; i < budget; i++)
        *xsk_ring_prod__fill_addr(&xsk->fq, idx++) = alloc_umem_frame(xsk->umem);

    xsk_ring_prod__submit(&xsk->fq, budget);
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    if (!xsk->outstanding_tx)
        return;

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    uint32_t idx_cq;
    unsigned int completed = xsk_ring_cons__peek(&xsk->cq,
                                                 XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                                 &idx_cq);
    if (completed > 0)
    {
        for (unsigned int i = 0; i < completed; i++)
            free_umem_frame(xsk->umem, *xsk_ring_cons__comp_addr(&xsk->cq, idx_cq++));
        xsk_ring_cons__release(&xsk->cq, completed);
        xsk->outstanding_tx -= completed;
    }
}

/* -------------------------------------------------------------------------
 * Checksum helpers
 * ------------------------------------------------------------------------- */

static inline __u16 ip_checksum(unsigned short *buf, int bufsz)
{
    unsigned long sum = 0;

    while (bufsz > 1)
    {
        sum += *buf++;
        bufsz -= 2;
    }
    if (bufsz == 1)
        sum += *(unsigned char *)buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static void compute_tcp_checksum(struct iphdr *ip, uint8_t *l4)
{
    uint32_t sum = 0;
    uint16_t tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);
    struct tcphdr *tcp = (struct tcphdr *)l4;

    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_len);

    tcp->check = 0;

    uint16_t *w = (uint16_t *)l4;
    while (tcp_len > 1)
    {
        sum += *w++;
        tcp_len -= 2;
    }
    if (tcp_len == 1)
        sum += *(uint8_t *)w;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    tcp->check = ~sum;
}

static void compute_udp_checksum(struct iphdr *ip, struct udphdr *udp)
{
    uint32_t sum = 0;
    uint16_t udp_len = ntohs(udp->len);

    udp->check = 0;

    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udp->len;

    uint16_t *w = (uint16_t *)udp;
    while (udp_len > 1)
    {
        sum += *w++;
        udp_len -= 2;
    }
    if (udp_len == 1)
        sum += *(uint8_t *)w;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    udp->check = ~sum;
    if (udp->check == 0)
        udp->check = 0xFFFF;
}

/* -------------------------------------------------------------------------
 * Misc helpers
 * ------------------------------------------------------------------------- */

static int get_iface_mac(const char *ifname, uint8_t mac[ETH_ALEN])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    if (ret < 0)
        return -1;

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}

/* Monotonic nanoseconds — same clock source as bpf_ktime_get_ns. */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * hash_4tuple_primary_eligible – select the primary firewall for a flow.
 * Skips dead firewalls and those still within their 30 s recovery grace period.
 * Returns -1 if all firewalls are down or recovering.
 *
 * Ports must be in host byte order (to match the XDP BPF hash).
 */
static inline int hash_4tuple_primary_eligible(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    int num_outputs, struct fw_state *states)
{
    uint32_t hash = src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port;
    uint64_t now = now_ns();
    for (int i = 0; i < num_outputs; i++)
    {
        int idx = (hash + i) % num_outputs;
        if (!states[idx].alive)
            continue;
        uint64_t rec = states[idx].recovery_ns;
        if (rec > 0 && (now - rec) < THIRTY_SEC_NS)
            continue;
        return idx;
    }
    return -1;
}

#endif /* __HELPER_H__ */
