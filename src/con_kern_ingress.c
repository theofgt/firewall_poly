
#include "XDP_helper.h"
#include "flow.h"

/* -------------------------------------------------------------------------
 * Maps local to the controller ingress path
 * ------------------------------------------------------------------------- */

/*
 * con_fw_state_map – liveness + recovery state maintained by the controller.
 * Written by controller.c based on heartbeat probes arriving through each
 * firewall path; independent from the load balancer's fw_state_map.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NUM_OUTPUT_SOCKETS);
    __type(key, __u32);
    __type(value, struct fw_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} con_fw_state_map SEC(".maps");

/*
 * hash_4tuple_primary_eligible – primary selection using the controller's own
 * con_fw_state_map.  Identical logic to the LB's version but reads the
 * controller's independently maintained liveness view.
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
        struct fw_state *state = bpf_map_lookup_elem(&con_fw_state_map, &candidate);

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

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_hash_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_hash_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct iface_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} output_ifindex_map SEC(".maps");

static __always_inline struct iface_info *get_output_info(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&output_ifindex_map, &key);
}

/* -------------------------------------------------------------------------
 * XDP program
 * ------------------------------------------------------------------------- */

SEC("xdp")
int xsk_redir_prog(struct xdp_md *ctx)
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

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 my_slot = get_fw_slot(ctx->ingress_ifindex);

    /* ── TCP ── */
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /* Ports in host byte order for consistent hashing with userspace */
        __u16 sport_h = bpf_ntohs(tcp->source);
        __u16 dport_h = bpf_ntohs(tcp->dest);

        struct flow_key key = {};
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;
        key.src_port = tcp->source; /* stored in network order */
        key.dst_port = tcp->dest;

        /*
         * Pure SYN: always route to userspace (controller) for a fresh
         * handshake, even if a fast-path entry already exists for this
         * 4-tuple. This handles the case where a client restarts and
         * reuses a source port before the 30 s LRU entry expires.
         */
        if (tcp->syn && !tcp->ack)
        {
            __u64 *stale = bpf_map_lookup_elem(&tcp_hash_map, &key);
            if (stale)
                bpf_map_delete_elem(&tcp_hash_map, &key);
            return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
        }

        __u64 now = bpf_ktime_get_ns();
        __u64 *val = bpf_map_lookup_elem(&tcp_hash_map, &key);

        if (val && (now - TCP_HASH_TS(*val) < THIRTY_SEC_NS * 4))
        {
            /* ── Established flow ── */

            __u32 primary = hash_4tuple_primary_eligible(ip->saddr, ip->daddr,
                                                         sport_h, dport_h);

            if (primary == NUM_OUTPUT_SOCKETS)
                return XDP_DROP; /* all firewalls down or recovering */

            if (my_slot == primary)
            {
                /*
                 * Primary interface: redirect the full packet directly to
                 * the server-side output interface, bypassing
                 * AF_XDP userspace for a zero-copy fast path.
                 * Fall back to XDP_PASS if the map is not yet populated.
                 *
                 * Two-bit teardown (bits 62-63 of the stored timestamp):
                 *  • CLIENT_FIN_BIT (63): set here when client sends FIN.
                 *  • SERVER_FIN_BIT (62): set by con_kern_egress when server sends FIN.
                 * Entry is evicted when both bits are set: either on the
                 * client's closing FIN (if server FIN came first) or on the
                 * client's final ACK (if client FIN came first).
                 */
                struct iface_info *oinfo = get_output_info();
                if (!oinfo || !oinfo->ifindex)
                    return XDP_PASS;

                if (tcp->rst)
                {
                    /* Abrupt teardown: evict immediately, then forward. */
                    bpf_map_delete_elem(&tcp_hash_map, &key);
                }
                else if (tcp->fin)
                {
                    if (*val & TCP_HASH_SERVER_FIN_BIT)
                        /* Server already sent FIN; this client FIN completes
                         * the exchange — evict now, then forward. */
                        bpf_map_delete_elem(&tcp_hash_map, &key);
                    else
                        /* Record client FIN; preserve SERVER_FIN_BIT if set. */
                        *val = (*val & TCP_HASH_SERVER_FIN_BIT) | now | TCP_HASH_CLIENT_FIN_BIT;
                }
                else if ((*val & TCP_HASH_FIN_BITS) == TCP_HASH_FIN_BITS)
                {
                    /* Both sides sent FIN; this is the client's final ACK - evict. */
                    bpf_map_delete_elem(&tcp_hash_map, &key);
                }
                else
                {
                    /* Normal data: refresh timestamp, preserve any FIN bits. */
                    *val = (*val & TCP_HASH_FIN_BITS) | now;
                }
                if (oinfo->dst_mac[0] | oinfo->dst_mac[1] | oinfo->dst_mac[2] |
                    oinfo->dst_mac[3] | oinfo->dst_mac[4] | oinfo->dst_mac[5])
                    __builtin_memcpy(eth->h_dest, oinfo->dst_mac, 6);
                else
                {
                    eth->h_dest[0] = 0xff;
                    eth->h_dest[1] = 0xff;
                    eth->h_dest[2] = 0xff;
                    eth->h_dest[3] = 0xff;
                    eth->h_dest[4] = 0xff;
                    eth->h_dest[5] = 0xff;
                }
                return bpf_redirect(oinfo->ifindex, 0);
            }

            /*
             * Non-primary interface: this is a header-only copy that the
             * controller return path sent to keep the firewall's state in sync.
             * Verify it really carries no payload before dropping, so we
             * don't accidentally discard a legitimate retransmit that arrived
             * on a different interface after a failover.
             */
            if (is_header_only(ip, IPPROTO_TCP, tcp))
                return XDP_DROP;

            /*
             * Full packet on a non-primary interface, may happen due to race condition
             */
            struct iface_info *oinfo = get_output_info();
            if (!oinfo || !oinfo->ifindex)
                return XDP_PASS;
            if (oinfo->dst_mac[0] | oinfo->dst_mac[1] | oinfo->dst_mac[2] |
                oinfo->dst_mac[3] | oinfo->dst_mac[4] | oinfo->dst_mac[5])
                __builtin_memcpy(eth->h_dest, oinfo->dst_mac, 6);
            else
            {
                eth->h_dest[0] = 0xff;
                eth->h_dest[1] = 0xff;
                eth->h_dest[2] = 0xff;
                eth->h_dest[3] = 0xff;
                eth->h_dest[4] = 0xff;
                eth->h_dest[5] = 0xff;
            }
            return bpf_redirect(oinfo->ifindex, 0);
        }

        /*
         * Non-established flow (new handshake or expired entry):
         * redirect to userspace (controller) for deduplication counting.
         */
        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    /* ── UDP ── */
    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        /* ── Heartbeat: always redirect to userspace ── */
        if (is_heartbeat_udp(udp, data_end))
            return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);

        __u16 sport_h = bpf_ntohs(udp->source);
        __u16 dport_h = bpf_ntohs(udp->dest);

        struct flow_key key = {};
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;
        key.src_port = udp->source;
        key.dst_port = udp->dest;

        __u64 now = bpf_ktime_get_ns();
        __u64 *val = bpf_map_lookup_elem(&udp_hash_map, &key);

        if (val && (now - *val < THIRTY_SEC_NS))
        {
            /* ── Established flow ── */
            *val = now;

            __u32 primary = hash_4tuple_primary_eligible(ip->saddr, ip->daddr,
                                                         sport_h, dport_h);

            if (primary == NUM_OUTPUT_SOCKETS)
                return XDP_DROP; /* all firewalls down or recovering */
                
            struct iface_info *oinfo = get_output_info();
            if (my_slot == primary)
            {
                if (!oinfo || !oinfo->ifindex)
                    return XDP_PASS;
                if (oinfo->dst_mac[0] | oinfo->dst_mac[1] | oinfo->dst_mac[2] |
                    oinfo->dst_mac[3] | oinfo->dst_mac[4] | oinfo->dst_mac[5])
                    __builtin_memcpy(eth->h_dest, oinfo->dst_mac, 6);
                else
                {
                    eth->h_dest[0] = 0xff;
                    eth->h_dest[1] = 0xff;
                    eth->h_dest[2] = 0xff;
                    eth->h_dest[3] = 0xff;
                    eth->h_dest[4] = 0xff;
                    eth->h_dest[5] = 0xff;
                }
                return bpf_redirect(oinfo->ifindex, 0);
            }

            if (is_header_only(ip, IPPROTO_UDP, udp))
                return XDP_DROP;
            /*
             * Full packet on a non-primary interface, may happen due to race condition
             */
            if (oinfo->dst_mac[0] | oinfo->dst_mac[1] | oinfo->dst_mac[2] |
                oinfo->dst_mac[3] | oinfo->dst_mac[4] | oinfo->dst_mac[5])
                __builtin_memcpy(eth->h_dest, oinfo->dst_mac, 6);
            else
            {
                eth->h_dest[0] = 0xff;
                eth->h_dest[1] = 0xff;
                eth->h_dest[2] = 0xff;
                eth->h_dest[3] = 0xff;
                eth->h_dest[4] = 0xff;
                eth->h_dest[5] = 0xff;
            }
            return bpf_redirect(oinfo->ifindex, 0);
        }

        /* Non-established UDP flow → userspace for deduplication */
        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
