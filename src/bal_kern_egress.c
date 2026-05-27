#include "XDP_helper.h"

/* -------------------------------------------------------------------------
 * Maps local to the load-balancer egress path
 * ------------------------------------------------------------------------- */

/*
 * fw_state_map – liveness + recovery state maintained by the load balancer.
 * Written by load_balancer.c heartbeat thread; read here for primary selection.
 * Pin name intentionally differs from con_fw_state_map so each component owns
 * its own independent view of firewall liveness.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NUM_OUTPUT_SOCKETS);
    __type(key, __u32);
    __type(value, struct fw_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fw_state_map SEC(".maps");

/*
 * hash_4tuple_primary_eligible – primary selection using the load balancer's
 * own fw_state_map.  Identical logic to the controller's version.
 */
static __always_inline __u32
hash_4tuple_primary_eligible(__u32 src_ip, __u32 dst_ip,
                             __u16 src_port_h, __u16 dst_port_h)
{
    __u32 base = hash_4tuple(src_ip, dst_ip, src_port_h, dst_port_h);
    __u64 now = bpf_ktime_get_ns();

    __u32 i;
    for (i = 0; i < NUM_OUTPUT_SOCKETS; i++)
    {
        __u32 candidate = (base + i) % NUM_OUTPUT_SOCKETS;
        struct fw_state *state = bpf_map_lookup_elem(&fw_state_map, &candidate);

        if (!state)
            return candidate;
        if (!state->alive)
            continue;
        if (state->recovery_ns > 0 && (now - state->recovery_ns) < THIRTY_SEC_NS)
            continue;

        return candidate;
    }
    return NUM_OUTPUT_SOCKETS;
}

/*
 * xsks_map – AF_XDP socket map; heartbeat packets are redirected here so
 * userspace can reflect the ACK.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/*
 * client_ifindex_map – single-entry array: key=0, value=client-facing ifindex
 * + dst MAC.  Populated by load_balancer at startup; used to bpf_redirect
 * return packets past the host routing table.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct iface_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_ifindex_map SEC(".maps");

/* get_client_info – look up client ifindex + dst MAC. */
static __always_inline struct iface_info *get_client_info(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&client_ifindex_map, &key);
}

/* -------------------------------------------------------------------------
 * XDP program
 * ------------------------------------------------------------------------- */

SEC("xdp")
int xsk_redir_egress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* ── IP ── */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only handle TCP and UDP; pass everything else to the stack */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    }
    else /* UDP */
    {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        /* ── Heartbeat: always redirect to userspace regardless of primary ── */
        if (is_heartbeat_udp(udp, data_end))
            return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);

        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    /* ── Determine which firewall index owns this ingress interface ── */
    __u32 my_fw_id = get_fw_slot(ctx->ingress_ifindex);
    if (my_fw_id == NUM_OUTPUT_SOCKETS)
        return XDP_PASS; /* interface not registered — pass unknown traffic */

    /* ── Determine which firewall should receive the full packet ── */
    __u32 primary = hash_4tuple_primary_eligible(ip->saddr, ip->daddr, src_port, dst_port);

    if (primary == NUM_OUTPUT_SOCKETS)
    {
        /* All firewalls are down */
        return XDP_DROP;
    }

    if (my_fw_id == primary)
    {
        /*
         * Primary interface: redirect the full return packet directly to the
         * client-facing interface (veth-lb-in), bypassing the kernel routing
         * stack.  XDP_PASS would deliver locally in the host-namespace topology
         * since all IPs are local — bpf_redirect pushes the frame onto the
         * TX of veth-lb-in so it arrives on veth-client.
         * Fall back to XDP_PASS if the map is not yet populated.
         */
        struct iface_info *cinfo = get_client_info();
        if (!cinfo || !cinfo->ifindex)
            return XDP_PASS;
        if (cinfo->dst_mac[0] | cinfo->dst_mac[1] | cinfo->dst_mac[2] |
            cinfo->dst_mac[3] | cinfo->dst_mac[4] | cinfo->dst_mac[5])
            __builtin_memcpy(eth->h_dest, cinfo->dst_mac, 6);
        else
        {
            eth->h_dest[0] = 0xff;
            eth->h_dest[1] = 0xff;
            eth->h_dest[2] = 0xff;
            eth->h_dest[3] = 0xff;
            eth->h_dest[4] = 0xff;
            eth->h_dest[5] = 0xff;
        }
        return bpf_redirect(cinfo->ifindex, 0);
    }

    /*
     * This interface is NOT the primary.
     * The controller sent a header-only copy to keep this firewall's
     * connection-state tables in sync.
     */
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";