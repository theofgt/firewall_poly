#ifndef XDP_HELPER_H
#define XDP_HELPER_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "heartbeat.h"

/* Number of firewall slots — must match NUM_OUTPUT_SOCKETS in userspace. */
#define NUM_OUTPUT_SOCKETS 4

/* -------------------------------------------------------------------------
 * Maps shared across XDP programs
 * ------------------------------------------------------------------------- */

/*
 * iface_to_fw_map – ifindex → firewall slot index (0-based).
 * Populated by controller and load_balancer at startup.
 * NOTE: fw_state_map / con_fw_state_map are NOT shared here; each component
 * (load balancer, controller) declares its own liveness map locally so that
 * each maintains independent liveness state derived from its own observations.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NUM_OUTPUT_SOCKETS * 2);
    __type(key, __u32);   /* ifindex */
    __type(value, __u32); /* firewall slot 0..NUM_OUTPUT_SOCKETS-1 */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} iface_to_fw_map SEC(".maps");

/* -------------------------------------------------------------------------
 * Shared helpers
 * ------------------------------------------------------------------------- */

/*
 * is_heartbeat_udp – true when the UDP datagram carries a heartbeat probe or
 * ACK (identified by HB_UDP_PORT and HB_MAGIC in the payload).
 */
static __always_inline bool
is_heartbeat_udp(struct udphdr *udp, void *data_end)
{
    if (bpf_ntohs(udp->dest) != HB_UDP_PORT &&
        bpf_ntohs(udp->source) != HB_UDP_PORT)
        return false;

    struct hb_payload *hb =
        (struct hb_payload *)((void *)udp + sizeof(struct udphdr));
    if ((void *)(hb + 1) > data_end)
        return false;

    return (bpf_ntohl(hb->magic) == HB_MAGIC);
}

/*
 * is_header_only – true when ip->tot_len equals exactly the IP header plus
 * the L4 header with no payload bytes.  The load_balancer sets tot_len to
 * this value on every non-primary (header-only) copy it sends.
 *
 * Called only after bounds-checking the L4 header.
 */
static __always_inline bool
is_header_only(struct iphdr *ip, __u8 protocol, void *l4)
{
    __u16 ip_tot = bpf_ntohs(ip->tot_len);
    __u16 ip_hdrlen = ip->ihl * 4;
    __u16 l4_hdrlen;

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        l4_hdrlen = tcp->doff * 4;
    }
    else /* UDP */
    {
        l4_hdrlen = sizeof(struct udphdr);
    }

    return (ip_tot == ip_hdrlen + l4_hdrlen);
}

/*
 * hash_4tuple – base flow hash on host-byte-order ports.
 * NOTE: ports must be passed as bpf_ntohs(port) to match the userspace hash
 * in load_balancer.c and controller.c.
 */
static __always_inline __u32
hash_4tuple(__u32 src_ip, __u32 dst_ip, __u16 src_port_h, __u16 dst_port_h)
{
    __u32 hash = src_ip ^ dst_ip ^ ((__u32)src_port_h << 16) ^ dst_port_h;
    return hash % NUM_OUTPUT_SOCKETS;
}

/*
 * get_fw_slot – translate an ifindex to its firewall slot via iface_to_fw_map.
 * Returns NUM_OUTPUT_SOCKETS (invalid sentinel) if not registered.
 */
static __always_inline __u32 get_fw_slot(__u32 ifindex)
{
    __u32 *slot = bpf_map_lookup_elem(&iface_to_fw_map, &ifindex);
    return slot ? *slot : NUM_OUTPUT_SOCKETS;
}

#endif /* XDP_HELPER_H */
