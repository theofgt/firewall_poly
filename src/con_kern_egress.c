
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include "flow.h"
#include "heartbeat.h"

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/*
 * tcp_hash_map – shared with con_kern_ingress via the same pin path.
 * Used here to evict the fast-path entry when the server sends a RST.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_hash_map SEC(".maps");

SEC("xdp")
int xsk_redir_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Handle TCP */
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /*
         * Traffic on this interface has src=server, dst=client; the
         * tcp_hash_map key uses the opposite (client→server) direction.
         */
        struct flow_key rev_key = {};
        rev_key.src_ip = ip->daddr;     /* client IP */
        rev_key.dst_ip = ip->saddr;     /* server IP */
        rev_key.src_port = tcp->dest;   /* client port (network order) */
        rev_key.dst_port = tcp->source; /* server port (network order) */

        __u64 *val = bpf_map_lookup_elem(&tcp_hash_map, &rev_key);
        if (val)
        {
            if (tcp->rst)
                /* Abrupt teardown: evict immediately. */
                bpf_map_delete_elem(&tcp_hash_map, &rev_key);
            else if (tcp->fin)
                /* Signal ingress that the server has sent its FIN.
                 * Ingress owns all eviction; it will delete the entry once
                 * it sees the client's response with CLIENT_FIN_BIT set. */
                *val |= TCP_HASH_SERVER_FIN_BIT;
        }

        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    /* Handle UDP */
    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
