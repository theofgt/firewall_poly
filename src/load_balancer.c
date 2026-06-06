#include <pthread.h>
#include "heartbeat.h"
#include "helper.h"

#define S_MAC "FF:FF:FF:FF:FF:FF"
#define D_MAC "FF:FF:FF:FF:FF:FF"

/*
 * When the shared UMEM pool drops below this threshold, UDP packet copies are
 * skipped so the remaining frames are reserved for TCP.  Sized for two full
 * RX batches across all output sockets (2 × 64 pkts × 4 FWs = 512 frames).
 */
#define UMEM_TCP_RESERVE 256

/* Per-firewall userspace mirror of the kernel fw_state_map */
static struct fw_state *fw_states = NULL; /* [num_output_sockets] */
static int fw_state_map_fd = -1;
static int num_firewalls = 0; /* == num_output_sockets */

static int udp_drop_map_fd = -1;
static bool udp_drop_active = false;

static void set_udp_drop(bool drop)
{
    if (udp_drop_map_fd < 0 || udp_drop_active == drop)
        return;
    __u32 key = 0, val = drop ? 1 : 0;
    bpf_map_update_elem(udp_drop_map_fd, &key, &val, BPF_ANY);
    udp_drop_active = drop;
    fprintf(stderr, "%s: UDP drop flag %s (pool pressure)\n",
            drop ? "WARN" : "INFO", drop ? "SET" : "CLEARED");
}

/* Sequence counters, one per firewall */
static uint32_t *hb_seq = NULL;

struct hb_thread_ctx
{
    struct xsk_socket_info **output_xsks;
    int num_outputs;
    struct xsk_umem_info *umem;
};

static struct hb_thread_ctx hb_ctx;

/* Prebuilt source/dest IPs for probe frames (network byte order) */
static uint32_t hb_src_ip_n;
static uint32_t hb_dst_ip_n;

/* Forward declarations */
static bool send_packet_to_output(struct xsk_socket_info *xsk_out, uint64_t addr, uint32_t len);
static inline bool fw_is_alive(int fw_id);

static bool global_exit;

/*
 * Per-output-socket MAC cache populated once at startup.
 * Index matches output_xsks[i].
 */
static uint8_t (*output_src_macs)[ETH_ALEN] = NULL; /* our MAC on each output iface  */
static uint8_t (*output_dst_macs)[ETH_ALEN] = NULL; /* next-hop MAC on each output iface */
static char **output_ifnames = NULL;                /* ifnames for each output socket */

/*
 * rewrite_and_forward_inplace - rewrites the original RX frame in-place
 * (no allocation, no copy) and hands it directly to the TX ring of the
 * primary output socket.  Returns true when the frame is enqueued - the
 * caller must NOT free the frame.  Returns false on TTL expiry or TX-ring
 * full; the caller is responsible for freeing the frame in that case.
 */
static bool rewrite_and_forward_inplace(struct xsk_socket_info *xsk_out, int out_idx,
                                        uint64_t rx_addr, uint32_t len)
{
    uint8_t *pkt = xsk_umem__get_data(xsk_out->umem->buffer, rx_addr);

    struct ethhdr *eth = (struct ethhdr *)pkt;
    memcpy(eth->h_source, output_src_macs[out_idx], ETH_ALEN);
    memcpy(eth->h_dest, output_dst_macs[out_idx], ETH_ALEN);

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    if (ip->ttl <= 1)
        return false; /* drop: TTL expired; caller frees frame */
    ip->ttl--;
    ip->check = 0;
    ip->check = ip_checksum((__u16 *)ip, ip->ihl * 4);

    uint8_t *l4 = pkt + sizeof(struct ethhdr) + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP)
        compute_tcp_checksum(ip, l4);
    else if (ip->protocol == IPPROTO_UDP)
        compute_udp_checksum(ip, (struct udphdr *)l4);

    if (!send_packet_to_output(xsk_out, rx_addr, len))
        return false; /* TX ring full; caller frees frame */

    return true; /* frame ownership transferred to TX ring */
}

/*
 * rewrite_and_forward_header_only - like rewrite_and_forward but truncates
 * the copy to headers only (Eth + IP + TCP/UDP header, no payload).
 * ip->tot_len is adjusted to match, and both IP and L4 checksums are
 * recomputed so the receiving firewall accepts the frame.
 */
static bool rewrite_and_forward_header_only(struct xsk_socket_info *xsk_out, int out_idx,
                                            uint8_t *pkt_data, uint32_t full_len)
{
    struct iphdr *src_ip = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
    uint8_t *src_l4 = pkt_data + sizeof(struct ethhdr) + src_ip->ihl * 4;

    /* Compute header-only length */
    uint32_t l4_hdr_len;
    if (src_ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)src_l4;
        l4_hdr_len = tcp->doff * 4;
    }
    else /* UDP */
    {
        l4_hdr_len = sizeof(struct udphdr);
    }

    uint32_t send_len = sizeof(struct ethhdr) + src_ip->ihl * 4 + l4_hdr_len;

    /* Never send more than we actually have */
    if (send_len > full_len)
        send_len = full_len;

    uint64_t dst_addr = alloc_umem_frame(xsk_out->umem);
    if (dst_addr == INVALID_UMEM_FRAME)
    {
        fprintf(stderr, "WARN: no umem frame (header-only) for output socket %d\n", out_idx);
        return false;
    }

    uint8_t *dst_pkt = xsk_umem__get_data(xsk_out->umem->buffer, dst_addr);
    memcpy(dst_pkt, pkt_data, send_len);

    /* ── Ethernet MACs ── */
    struct ethhdr *eth = (struct ethhdr *)dst_pkt;
    memcpy(eth->h_source, output_src_macs[out_idx], ETH_ALEN);
    memcpy(eth->h_dest, output_dst_macs[out_idx], ETH_ALEN);

    /* ── IP: adjust tot_len, decrement TTL, recompute checksum ── */
    struct iphdr *ip = (struct iphdr *)(dst_pkt + sizeof(struct ethhdr));
    if (ip->ttl <= 1)
    {
        free_umem_frame(xsk_out->umem, dst_addr);
        return false;
    }
    ip->ttl--;
    ip->tot_len = htons(send_len - sizeof(struct ethhdr));
    ip->check = 0;
    ip->check = ip_checksum((__u16 *)ip, ip->ihl * 4);

    /* ── L4: recompute checksum over the trimmed (header-only) segment ── */
    uint8_t *l4 = dst_pkt + sizeof(struct ethhdr) + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        tcp->check = 0;
        compute_tcp_checksum(ip, l4);
    }
    else
    {
        struct udphdr *udp = (struct udphdr *)l4;
        udp->len = htons(sizeof(struct udphdr));
        udp->check = 0;
        compute_udp_checksum(ip, udp);
    }

    if (!send_packet_to_output(xsk_out, dst_addr, send_len))
    {
        free_umem_frame(xsk_out->umem, dst_addr);
        return false;
    }
    return true;
}

/*
 * duplicate_to_all_outputs - forwards the packet to every alive firewall:
 *   • non-primary alive interfaces first: header-only copies (new frames)
 *   • primary last: reuses the original RX frame in-place (no allocation)
 *
 * Non-primary FWs are processed before the primary so the original frame
 * data is still intact when rewrite_and_forward_header_only reads it.
 *
 * Returns the number of sockets successfully enqueued.
 * *rx_frame_consumed is set to true when the primary reused rx_addr; the
 * caller must NOT free that frame in that case.
 */
static int duplicate_to_all_outputs(struct xsk_socket_info **output_xsks,
                                    int num_outputs,
                                    uint8_t *pkt_data, uint32_t len,
                                    uint64_t rx_addr,
                                    uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t src_port, uint16_t dst_port,
                                    bool is_tcp,
                                    bool *rx_frame_consumed)
{
    *rx_frame_consumed = false;

    /* Drop UDP when the pool is low — reserve remaining frames for TCP so the
     * iperf3 control connection (TCP) survives a saturating UDP data stream. */
    if (!is_tcp && umem_free_frames(output_xsks[0]->umem) <= UMEM_TCP_RESERVE)
        return 0;

    int primary = hash_4tuple_primary_eligible(src_ip, dst_ip, src_port, dst_port, num_outputs, fw_states);
    if (primary < 0)
    {
        fprintf(stderr, "WARN: all firewalls down or recovering, dropping packet\n");
        return 0;
    }

    int sent = 0;

    /* Non-primary FWs first — header-only copies into freshly allocated frames.
     * The original frame (pkt_data / rx_addr) is read-only here. */
    for (int i = 0; i < num_outputs; i++)
    {
        if (i == primary)
            continue;
        if (!fw_is_alive(i))
            continue;
        if (rewrite_and_forward_header_only(output_xsks[i], i, pkt_data, len))
            sent++;
        else
            fprintf(stderr, "WARN: failed to forward to output socket %d\n", i);
    }

    /* Primary last — rewrite the original RX frame in-place; no alloc needed. */
    if (rewrite_and_forward_inplace(output_xsks[primary], primary, rx_addr, len))
    {
        sent++;
        *rx_frame_consumed = true;
    }
    else
        fprintf(stderr, "WARN: failed to forward to output socket %d\n", primary);

    return sent;
}

/* Send packet to specific output socket */
static bool send_packet_to_output(struct xsk_socket_info *xsk_out, uint64_t addr, uint32_t len)
{
    int ret;
    uint32_t tx_idx;

    ret = xsk_ring_prod__reserve(&xsk_out->tx, 1, &tx_idx);
    if (ret != 1)
    {
        return false; /* TX ring full */
    }

    xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->len = len;
    xsk_ring_prod__submit(&xsk_out->tx, 1);
    xsk_out->outstanding_tx++;

    return true;
}

/* -----------------------------------------------------------------------
 * Heartbeat helpers – load_balancer side
 * ----------------------------------------------------------------------- */

/* Update both the userspace mirror and the kernel BPF map for firewall fw_id */
static void fw_set_state(uint8_t fw_id, uint8_t alive, uint64_t ts)
{
    if (fw_id >= num_firewalls)
        return;

    bool was_dead = !fw_states[fw_id].alive;

    fw_states[fw_id].alive = alive;
    fw_states[fw_id].last_seen_ns = ts;

    if (was_dead && alive)
    {
        fw_states[fw_id].recovery_ns = now_ns();
        printf("FW%u recovered: primary-ineligible for %llu s\n",
               fw_id, (unsigned long long)THIRTY_SEC_NS / 1000000000ULL);
    }
    else if (!alive)
        fw_states[fw_id].recovery_ns = 0;

    if (fw_state_map_fd >= 0)
    {
        __u32 key = fw_id;
        if (bpf_map_update_elem(fw_state_map_fd, &key, &fw_states[fw_id], BPF_ANY) != 0)
            fprintf(stderr, "WARN: fw_state_map update failed for fw %u: %s\n",
                    fw_id, strerror(errno));
    }
}

/* Build and transmit one HEARTBEAT_REQ frame out output socket fw_id */
static void send_heartbeat_req(struct xsk_socket_info *xsk_out, uint8_t fw_id)
{
    uint64_t frame_addr = alloc_umem_frame(xsk_out->umem);
    if (frame_addr == INVALID_UMEM_FRAME)
    {
        fprintf(stderr, "WARN: no umem frame for heartbeat to fw %u\n", fw_id);
        return;
    }

    uint8_t *pkt = xsk_umem__get_data(xsk_out->umem->buffer, frame_addr);
    memset(pkt, 0, HB_FRAME_LEN);

    /* Ethernet header – reuse the global MAC constants */
    struct ethhdr *eth = (struct ethhdr *)pkt;
    uint8_t s_mac[ETH_ALEN], d_mac[ETH_ALEN];
    sscanf(S_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &s_mac[0], &s_mac[1], &s_mac[2], &s_mac[3], &s_mac[4], &s_mac[5]);
    sscanf(D_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &d_mac[0], &d_mac[1], &d_mac[2], &d_mac[3], &d_mac[4], &d_mac[5]);
    memcpy(eth->h_source, s_mac, ETH_ALEN);
    memcpy(eth->h_dest, d_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    /* IP header */
    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = hb_src_ip_n;
    ip->daddr = hb_dst_ip_n;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + HB_PAYLOAD_LEN);
    ip->check = 0;
    ip->check = ip_checksum((__u16 *)ip, sizeof(struct iphdr));

    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(HB_UDP_PORT);
    udp->dest = htons(HB_UDP_PORT);
    udp->len = htons(sizeof(struct udphdr) + HB_PAYLOAD_LEN);
    udp->check = 0;

    /* Heartbeat payload */
    struct hb_payload *hb = (struct hb_payload *)(pkt + sizeof(struct ethhdr) +
                                                  sizeof(struct iphdr) +
                                                  sizeof(struct udphdr));
    hb->magic = htonl(HB_MAGIC);
    hb->type = HB_TYPE_REQ;
    hb->fw_id = fw_id;
    hb->seq = htonl(++hb_seq[fw_id]);
    hb->ts_ns = now_ns();

    compute_udp_checksum(ip, udp);

    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&xsk_out->tx, 1, &tx_idx) != 1)
    {
        fprintf(stderr, "WARN: TX ring full, dropping heartbeat to fw %u\n", fw_id);
        free_umem_frame(xsk_out->umem, frame_addr);
        return;
    }

    xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->addr = frame_addr;
    xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->len = HB_FRAME_LEN;
    xsk_ring_prod__submit(&xsk_out->tx, 1);
    xsk_out->outstanding_tx++;
    complete_tx(xsk_out);
}

/* Called by process_packet when an incoming frame looks like a heartbeat ACK */
static bool handle_heartbeat_ack(uint8_t *pkt, uint32_t len)
{
    if (len < HB_FRAME_LEN)
        return false;

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    if (ip->protocol != IPPROTO_UDP)
        return false;

    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + ip->ihl * 4);
    if (ntohs(udp->dest) != HB_UDP_PORT && ntohs(udp->source) != HB_UDP_PORT)
        return false;

    struct hb_payload *hb = (struct hb_payload *)((uint8_t *)udp + sizeof(struct udphdr));
    if (ntohl(hb->magic) != HB_MAGIC || hb->type != HB_TYPE_ACK)
        return false;

    uint8_t fw_id = hb->fw_id;
    uint64_t ts = now_ns();

    printf("HB ACK from fw %u seq %u rtt ~%lu us\n",
           fw_id, ntohl(hb->seq), (ts - hb->ts_ns) / 1000);

    /* Mark firewall alive and refresh kernel map */
    fw_states[fw_id].seq_last = ntohl(hb->seq);
    fw_set_state(fw_id, 1, ts);
    return true;
}

/* Sweep all firewalls: mark timed-out ones dead, send new probes */
static void heartbeat_tick(struct xsk_socket_info **output_xsks, int num_outputs)
{
    uint64_t ts = now_ns();

    for (int i = 0; i < num_outputs; i++)
    {
        /* Timeout check */
        if (fw_states[i].alive &&
            fw_states[i].last_seen_ns > 0 &&
            (ts - fw_states[i].last_seen_ns) > HEARTBEAT_TIMEOUT_NS)
        {
            printf("WARN: firewall %d timed out - marking DOWN\n", i);
            fw_set_state(i, 0, ts);
        }

        /* Send probe */
        send_heartbeat_req(output_xsks[i], (uint8_t)i);
    }
}

/* Background thread: fires heartbeat_tick every HEARTBEAT_INTERVAL_NS */
static void *heartbeat_thread(void *arg)
{
    struct hb_thread_ctx *ctx = (struct hb_thread_ctx *)arg;
    struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = HEARTBEAT_INTERVAL_NS,
    };

    while (!global_exit)
    {
        heartbeat_tick(ctx->output_xsks, ctx->num_outputs);
        nanosleep(&interval, NULL);
    }
    return NULL;
}

/* Return true if firewall fw_id is considered alive */
static inline bool fw_is_alive(int fw_id)
{
    return fw_id >= 0 && fw_id < num_firewalls && fw_states[fw_id].alive;
}

/*
 * Returns true when the original RX frame (addr) was consumed by the primary
 * TX ring — the caller must NOT free it.  Returns false in all other cases
 * (parse failure, no alive FWs, TTL expired, TX ring full) — caller frees it.
 */
static bool process_packet(struct xsk_socket_info *xsk, struct xsk_socket_info **output_xsks,
                           int num_output_sockets, uint64_t addr, uint32_t len)
{
    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    struct ethhdr *eth = (struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    if (ip->version != 4)
        return false;

    uint8_t *l4 = pkt + sizeof(struct ethhdr) + ip->ihl * 4;

    /* ── Heartbeat ACK interception ── */
    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)l4;
        if (ntohs(udp->dest) == HB_UDP_PORT || ntohs(udp->source) == HB_UDP_PORT)
        {
            handle_heartbeat_ack(pkt, len);
            return false; /* not forwarded; caller frees the frame */
        }
    }

    /* ── Extract 4-tuple for routing ── */
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;
    uint16_t src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)l4;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    }
    else
    {
        return false;
    }

    bool rx_frame_consumed = false;
    int sent = duplicate_to_all_outputs(output_xsks, num_output_sockets,
                                        pkt, len, addr,
                                        src_ip, dst_ip, src_port, dst_port,
                                        ip->protocol == IPPROTO_TCP,
                                        &rx_frame_consumed);
    if (sent == 0)
    {
        fprintf(stderr, "WARN: packet dropped - no alive output sockets\n");
        return false;
    }

    return rx_frame_consumed;
}

static void handle_receive_packets(struct xsk_socket_info *xsk, struct xsk_socket_info **output_xsks,
                                   int num_output_sockets)
{
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    /* Drain previous batch's TX completions first — returns frames to the
     * shared pool before we refill the fill ring and allocate for new TX. */
    for (int j = 0; j < num_output_sockets; j++)
        complete_tx(output_xsks[j]);

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    /* Refill the fill ring — cap at min(rcvd, pool_avail) so frames remain
     * available for TX allocation (rcvd × num_output_sockets frames needed). */
    uint32_t pool_avail = (uint32_t)umem_free_frames(xsk->umem);

    /* XDP-level UDP priority: signal the kernel to drop UDP when the pool is
     * low so the iperf3 TCP control channel always has frames available.
     * Clear with hysteresis (2× threshold) to avoid rapid toggling. */
    if (pool_avail <= UMEM_TCP_RESERVE)
        set_udp_drop(true);
    else if (pool_avail > 2 * UMEM_TCP_RESERVE)
        set_udp_drop(false);

    uint32_t want = rcvd < pool_avail ? rcvd : pool_avail;
    stock_frames = xsk_prod_nb_free(&xsk->fq, want);

    if (stock_frames > 0)
    {
        ret = xsk_ring_prod__reserve(&xsk->fq, stock_frames, &idx_fq);

        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->fq, stock_frames, &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) =
                alloc_umem_frame(xsk->umem);

        xsk_ring_prod__submit(&xsk->fq, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < rcvd; i++)
    {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        /* process_packet returns true when it reused addr for the primary TX ring.
         * In that case the frame is owned by the TX ring and must not be freed here;
         * complete_tx() will return it to the pool once the kernel drains it. */
        if (!process_packet(xsk, output_xsks, num_output_sockets, addr, len))
            free_umem_frame(xsk->umem, addr);
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);

    /* Complete TX on all output sockets */
    for (int j = 0; j < num_output_sockets; j++)
    {
        complete_tx(output_xsks[j]);
    }
}

static void rx_and_process(struct xsk_socket_info **input_xsks, int num_input_sockets,
                           struct xsk_socket_info **output_xsks, int num_output_sockets)
{
    struct pollfd *fds;
    int ret;

    fds = calloc(num_input_sockets, sizeof(*fds));
    if (!fds)
    {
        exit(-1);
    }

    for (int i = 0; i < num_input_sockets; i++)
    {
        fds[i].fd = xsk_socket__fd(input_xsks[i]->xsk);
        fds[i].events = POLLIN;
    }

    while (!global_exit)
    {
        ret = poll(fds, num_input_sockets, -1);
        if (ret <= 0)
            continue;

        for (int i = 0; i < num_input_sockets; i++)
        {
            if (fds[i].revents & POLLIN)
            {
                handle_receive_packets(input_xsks[i], output_xsks, num_output_sockets);
            }
        }
    }

    free(fds);
}

static void exit_application(int signal)
{
    (void)signal;
    global_exit = true;
}

int main(int argc, char **argv)
{
    int xsks_map_fd = -1;
    void *packet_buffer;
    uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct config *cfgs;
    struct xsk_umem_info *umem;
    struct xsk_socket_info **input_xsks;
    struct xsk_socket_info **output_xsks;
    int num_input_sockets, num_output_sockets, num_total_sockets, id;

    /* Global shutdown handler */
    signal(SIGINT, exit_application);

    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s <num_input_sockets> <input_ifname1> ... <input_ifnameN> <output_ifname1> ... <output_ifnameN>\n", argv[0]);
        fprintf(stderr, "Example: %s 2 eth0 eth1 eth2 eth3\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    num_input_sockets = atoi(argv[1]);
    int arg_idx = 2;

    if (argc < 2 + num_input_sockets + 1)
    {
        fprintf(stderr, "ERROR: Not enough arguments for input interfaces\n");
        exit(EXIT_FAILURE);
    }

    num_output_sockets = argc - 2 - num_input_sockets;

    if (num_output_sockets < 1)
    {
        fprintf(stderr, "ERROR: Need at least 1 output socket\n");
        exit(EXIT_FAILURE);
    }

    num_total_sockets = num_input_sockets + num_output_sockets;

    printf("Input sockets: %d, Output sockets: %d\n", num_input_sockets, num_output_sockets);

    input_xsks = calloc(num_input_sockets, sizeof(*input_xsks));
    output_xsks = calloc(num_output_sockets, sizeof(*output_xsks));
    cfgs = malloc(num_total_sockets * sizeof(struct config));

    if (!input_xsks || !output_xsks || !cfgs)
    {
        fprintf(stderr, "ERROR: Can't allocate memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/xsks_map");
    printf("xsks_map_fd: %d\n", xsks_map_fd);
    if (xsks_map_fd < 0)
    {
        fprintf(stderr, "ERROR: xsks_map not available \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* iface_to_fw_map: ifindex → firewall slot index, consumed by bal_kern_egress */
    int iface_to_fw_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/iface_to_fw_map");
    if (iface_to_fw_map_fd < 0)
        fprintf(stderr, "WARN: iface_to_fw_map not available (%s) - egress XDP filtering disabled\n",
                strerror(errno));

    /* client_ifindex_map: key=0 → client-facing ifindex (veth-lb-in).
     * Consumed by bal_kern_egress to bpf_redirect return packets to the client. */
    int client_ifindex_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/client_ifindex_map");
    if (client_ifindex_map_fd < 0)
        fprintf(stderr, "WARN: client_ifindex_map not available (%s) - return bpf_redirect disabled\n",
                strerror(errno));

    fw_state_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/fw_state_map");
    if (fw_state_map_fd < 0)
        fprintf(stderr, "WARN: fw_state_map not available (%s) - kernel state disabled\n",
                strerror(errno));

    udp_drop_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/udp_drop_map");
    if (udp_drop_map_fd < 0)
        fprintf(stderr, "WARN: udp_drop_map not available (%s) - XDP UDP priority disabled\n",
                strerror(errno));

    /* Allow unlimited locking of memory */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (posix_memalign(&packet_buffer,
                       getpagesize(),
                       packet_buffer_size))
    {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Initialize shared packet_buffer for umem usage */
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL)
    {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Configure input sockets */
    for (int i = 0; i < num_input_sockets; i++)
    {
        id = if_nametoindex(argv[arg_idx]);
        if (!id)
        {
            fprintf(stderr, "ERROR: input ifname does not exist: %s\n", argv[arg_idx]);
            exit(EXIT_FAILURE);
        }

        cfgs[i].ifindex = id;
        cfgs[i].xsk_if_queue = 0;
        cfgs[i].do_unload = false;
        strcpy(cfgs[i].progsec, "xdp");
        cfgs[i].ifname = argv[arg_idx];
        cfgs[i].xdp_flags = XDP_FLAGS_SKB_MODE;

        input_xsks[i] = xsk_configure_socket(&cfgs[i], umem);
        input_xsks[i]->id = i;
        input_xsks[i]->is_input = 1;

        if (input_xsks[i] == NULL)
        {
            fprintf(stderr, "ERROR: Can't setup AF_XDP input socket for %s \"%s\"\n", cfgs[i].ifname, strerror(errno));
            exit(EXIT_FAILURE);
        }

        setup_fq(input_xsks[i], 1);

        int xsk_fd = xsk_socket__fd(input_xsks[i]->xsk);
        if (bpf_map_update_elem(xsks_map_fd, &id, &xsk_fd, BPF_ANY) != 0)
        {
            fprintf(stderr, "ERROR: bpf_map_update_elem failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("Input socket %d configured: %s (ifindex=%d)\n", i, argv[arg_idx], id);
        arg_idx++;
    }

    /* Populate client_ifindex_map: the client-facing interface is the first
     * (and only) input socket — veth-lb-in.  bal_kern_egress uses this to
     * bpf_redirect return packets directly onto its TX, reaching veth-client. */
    if (client_ifindex_map_fd >= 0)
    {
        /* Resolve the peer MAC (veth-client) so bal_kern_egress can set the
         * correct Ethernet dst instead of using a broadcast fallback. */
        uint8_t cli_dst_mac[6] = {0};
        {
            char sysfs_path[256];
            snprintf(sysfs_path, sizeof(sysfs_path),
                     "/sys/class/net/%s/iflink", cfgs[0].ifname);
            FILE *fp = fopen(sysfs_path, "r");
            if (fp)
            {
                int peer_idx = -1;
                if (fscanf(fp, "%d", &peer_idx) == 1 && peer_idx > 0)
                {
                    char peer_name[IF_NAMESIZE] = {0};
                    if (if_indextoname(peer_idx, peer_name) &&
                        get_iface_mac(peer_name, cli_dst_mac) == 0)
                        printf("client dst MAC (peer %s): "
                               "%02x:%02x:%02x:%02x:%02x:%02x\n",
                               peer_name,
                               cli_dst_mac[0], cli_dst_mac[1], cli_dst_mac[2],
                               cli_dst_mac[3], cli_dst_mac[4], cli_dst_mac[5]);
                    else
                        fprintf(stderr, "WARN: can't resolve peer MAC for %s\n",
                                cfgs[0].ifname);
                }
                fclose(fp);
            }
            else
            {
                fprintf(stderr, "WARN: can't open %s\n", sysfs_path);
            }
        }

        struct iface_info cinfo = {};
        cinfo.ifindex = (__u32)cfgs[0].ifindex;
        memcpy(cinfo.dst_mac, cli_dst_mac, 6);
        __u32 key = 0;
        if (bpf_map_update_elem(client_ifindex_map_fd, &key, &cinfo, BPF_ANY) != 0)
            fprintf(stderr, "WARN: client_ifindex_map update failed: %s\n", strerror(errno));
        else
            printf("client_ifindex_map: ifindex=%u (%s) dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   cinfo.ifindex, cfgs[0].ifname,
                   cinfo.dst_mac[0], cinfo.dst_mac[1], cinfo.dst_mac[2],
                   cinfo.dst_mac[3], cinfo.dst_mac[4], cinfo.dst_mac[5]);
        close(client_ifindex_map_fd);
    }

    /* Configure output sockets */
    for (int i = 0; i < num_output_sockets; i++)
    {
        id = if_nametoindex(argv[arg_idx]);
        if (!id)
        {
            fprintf(stderr, "ERROR: output ifname does not exist: %s\n", argv[arg_idx]);
            exit(EXIT_FAILURE);
        }

        int cfg_idx = num_input_sockets + i;
        cfgs[cfg_idx].ifindex = id;
        cfgs[cfg_idx].xsk_if_queue = 0;
        cfgs[cfg_idx].do_unload = false;
        strcpy(cfgs[cfg_idx].progsec, "xdp");
        cfgs[cfg_idx].ifname = argv[arg_idx];
        cfgs[cfg_idx].xdp_flags = XDP_FLAGS_SKB_MODE;

        output_xsks[i] = xsk_configure_socket(&cfgs[cfg_idx], umem);
        output_xsks[i]->id = num_input_sockets + i;
        output_xsks[i]->is_input = 0;

        if (output_xsks[i] == NULL)
        {
            fprintf(stderr, "ERROR: Can't setup AF_XDP output socket for %s \"%s\"\n", cfgs[cfg_idx].ifname, strerror(errno));
            exit(EXIT_FAILURE);
        }

        int xsk_fd = xsk_socket__fd(output_xsks[i]->xsk);
        if (bpf_map_update_elem(xsks_map_fd, &id, &xsk_fd, BPF_ANY) != 0)
        {
            fprintf(stderr, "ERROR: bpf_map_update_elem failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Register ifindex → firewall slot for the egress XDP program */
        if (iface_to_fw_map_fd >= 0)
        {
            __u32 fw_slot = (__u32)i;
            if (bpf_map_update_elem(iface_to_fw_map_fd, &id, &fw_slot, BPF_ANY) != 0)
                fprintf(stderr, "WARN: iface_to_fw_map update failed for %s: %s\n",
                        argv[arg_idx], strerror(errno));
            else
                printf("iface_to_fw_map: ifindex %d -> fw slot %u\n", id, fw_slot);
        }

        printf("Output socket %d configured: %s (ifindex=%d)\n", i, argv[arg_idx], id);
        arg_idx++;
    }

    printf("%d input and %d output sockets configured\n", num_input_sockets, num_output_sockets);

    /* ── MAC address cache for output interfaces ──
     * Populate output_src_macs (our own MAC on each output link) here.
     * output_dst_macs (next-hop MAC) defaults to broadcast; in a real
     * deployment replace with ARP-resolved next-hop MACs or configure
     * them via environment / config file before launch.
     */
    output_src_macs = calloc(num_output_sockets, ETH_ALEN);
    output_dst_macs = calloc(num_output_sockets, ETH_ALEN);
    output_ifnames = calloc(num_output_sockets, sizeof(char *));
    if (!output_src_macs || !output_dst_macs || !output_ifnames)
    {
        fprintf(stderr, "ERROR: Can't allocate MAC cache\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_output_sockets; i++)
    {
        int cfg_idx = num_input_sockets + i;
        output_ifnames[i] = cfgs[cfg_idx].ifname;

        if (get_iface_mac(cfgs[cfg_idx].ifname, output_src_macs[i]) < 0)
        {
            fprintf(stderr, "WARN: can't get MAC for %s, using zeros: %s\n",
                    cfgs[cfg_idx].ifname, strerror(errno));
        }
        else
        {
            printf("Output %d (%s) src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   i, cfgs[cfg_idx].ifname,
                   output_src_macs[i][0], output_src_macs[i][1],
                   output_src_macs[i][2], output_src_macs[i][3],
                   output_src_macs[i][4], output_src_macs[i][5]);
        }

        /* Default dst MAC to broadcast until ARP resolution is available.
         * Replace with actual next-hop MAC for production use. */
        memset(output_dst_macs[i], 0xFF, ETH_ALEN);
    }

    /* ---- Heartbeat initialisation ---- */
    inet_pton(AF_INET, HB_SRC_IP, &hb_src_ip_n);
    inet_pton(AF_INET, HB_DST_IP, &hb_dst_ip_n);

    num_firewalls = num_output_sockets;
    fw_states = calloc(num_firewalls, sizeof(struct fw_state));
    hb_seq = calloc(num_firewalls, sizeof(uint32_t));
    if (!fw_states || !hb_seq)
    {
        fprintf(stderr, "ERROR: Can't allocate heartbeat state\n");
        exit(EXIT_FAILURE);
    }

    /* Mark all firewalls alive; last_seen_ns=0 means "no ACK yet", so the
     * heartbeat timeout check (which guards on last_seen_ns > 0) won't fire
     * until the first ACK is received from each firewall. */
    for (int i = 0; i < num_firewalls; i++)
        fw_set_state(i, 1, 0);

    hb_ctx.output_xsks = output_xsks;
    hb_ctx.num_outputs = num_output_sockets;
    hb_ctx.umem = umem;

    pthread_t hb_tid;
    if (pthread_create(&hb_tid, NULL, heartbeat_thread, &hb_ctx) != 0)
    {
        fprintf(stderr, "ERROR: pthread_create for heartbeat: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("Heartbeat thread started (interval=%llu ms, timeout=%llu ms)\n",
           (unsigned long long)HEARTBEAT_INTERVAL_NS / 1000000,
           (unsigned long long)HEARTBEAT_TIMEOUT_NS / 1000000);

    /* Main packet processing loop */
    rx_and_process(input_xsks, num_input_sockets, output_xsks, num_output_sockets);

    pthread_join(hb_tid, NULL);

    /* Cleanup */
    xsk_umem__delete(umem->umem);

    for (int i = 0; i < num_input_sockets; i++)
    {
        xsk_socket__delete(input_xsks[i]->xsk);
        xdp_multiprog__close(xdp_multiprog__get_from_ifindex(cfgs[i].ifindex));
    }

    for (int i = 0; i < num_output_sockets; i++)
    {
        int cfg_idx = num_input_sockets + i;
        xsk_socket__delete(output_xsks[i]->xsk);
        xdp_multiprog__close(xdp_multiprog__get_from_ifindex(cfgs[cfg_idx].ifindex));
    }

    free(input_xsks);
    free(output_xsks);
    free(cfgs);
    free(fw_states);
    free(hb_seq);
    free(output_src_macs);
    free(output_dst_macs);
    free(output_ifnames);

    return 0;
}
