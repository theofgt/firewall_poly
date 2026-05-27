#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_drop_map SEC(".maps");

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

        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    /* Handle UDP — drop when userspace signals pool pressure */
    if (ip->protocol == IPPROTO_UDP)
    {
        __u32 key = 0;
        __u32 *drop_flag = bpf_map_lookup_elem(&udp_drop_map, &key);
        if (drop_flag && *drop_flag)
            return XDP_DROP;
        return bpf_redirect_map(&xsks_map, ctx->ingress_ifindex, 0);
    }

    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";