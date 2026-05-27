
#include "helper.h"
#include "uthash.h"
#include "heartbeat.h"
#include "flow.h"

typedef enum
{
    NUL,
    SYN,
    SYNACK,
    ACK,
    FIN
} TCP_state;

typedef enum
{
    TCP,
    UDP
} TP;

static const char *state_name(TCP_state s)
{
    switch (s)
    {
    case NUL:
        return "NUL";
    case SYN:
        return "SYN";
    case SYNACK:
        return "SYNACK";
    case ACK:
        return "ACK";
    case FIN:
        return "FIN";
    default:
        return "?";
    }
}

struct hash_counter
{
    int id; /* key */
    time_t timestamp;
    uint64_t addr;
    uint32_t pkt_len; /* length of the saved frame */
    TCP_state *state;
    UT_hash_handle hh; /* makes this structure hashable */
};

#define STALE_ENTRY_SEC 5

static struct hash_counter *tcp_hash_counter = NULL;
static struct hash_counter *udp_hash_counter = NULL;

/* Userspace mirror: indexed by socket id / firewall index */
static struct fw_state *fw_states_mp = NULL;

static uint32_t hb_src_ip_n_mp;
static uint32_t hb_dst_ip_n_mp;

/* Global BPF map fds — opened once in main, used in process_packet */
static int tcp_map_fd = -1;
static int udp_map_fd = -1;
static int fw_state_map_fd_mp = -1;
static int num_fw_mp = 0;

/* Per-input-socket MAC cache (populated at startup via SIOCGIFHWADDR) */
static uint8_t (*input_src_macs)[ETH_ALEN] = NULL; /* our MAC on each input iface  */
static uint8_t (*input_dst_macs)[ETH_ALEN] = NULL; /* next-hop MAC on each input iface */

static bool global_exit;

/* Return true if firewall fw_id is considered alive */
static inline bool fw_is_alive(int fw_id)
{
    return fw_id >= 0 && fw_id < num_fw_mp && fw_states_mp[fw_id].alive;
}

/* Count how many firewalls are currently alive */
static inline int count_alive_fws(void)
{
    int n = 0;
    for (int i = 0; i < num_fw_mp; i++)
        if (fw_states_mp[i].alive)
            n++;
    return n;
}

/*
 * add_hash_count_udp – deduplicate a UDP packet arriving from one of the
 * firewall sockets.
 *
 * is_primary: true when this socket is the primary for this flow (has full
 *             payload); false when this is a header-only copy.
 * forward_len: set to the primary's packet length when returning != INVALID_UMEM_FRAME.
 *
 * Returns INVALID_UMEM_FRAME when not all copies have arrived yet.
 * Returns the primary's frame addr when all copies have arrived — caller must
 * TX that addr (complete_tx will free it via the completion queue).
 *
 * Frame ownership: non-primary copies are freed here; primary copy is saved
 * in s->addr and freed or handed to the caller when the trigger fires.
 */
static uint64_t add_hash_count_udp(int packet_id, uint64_t addr, uint32_t pkt_len,
                                   struct xsk_socket_info *xsk, bool is_primary,
                                   uint32_t *forward_len)
{
    struct hash_counter *s;
    HASH_FIND_INT(udp_hash_counter, &packet_id, s);

    if (s == NULL)
    {
        s = (struct hash_counter *)malloc(sizeof *s);
        s->id = packet_id;
        s->timestamp = time(NULL);
        s->state = (TCP_state *)calloc(num_fw_mp, sizeof(TCP_state));
        s->state[xsk->id] = SYN;
        HASH_ADD_INT(udp_hash_counter, id, s);

        if (is_primary)
        {
            s->addr = addr;
            s->pkt_len = pkt_len;
        }
        else
        {
            s->addr = INVALID_UMEM_FRAME;
            s->pkt_len = 0;
            free_umem_frame(xsk->umem, addr);
        }
        return INVALID_UMEM_FRAME;
    }

    if (s->state[xsk->id] != NUL)
    {
        /* Duplicate from the same socket — discard */
        free_umem_frame(xsk->umem, addr);
        return INVALID_UMEM_FRAME;
    }

    s->state[xsk->id] = SYN;

    if (is_primary)
    {
        /* Replace any previously saved frame with the primary's full-payload one */
        if (s->addr != INVALID_UMEM_FRAME)
            free_umem_frame(xsk->umem, s->addr);
        s->addr = addr;
        s->pkt_len = pkt_len;
    }
    else
    {
        /* Header-only non-primary copy — discard */
        free_umem_frame(xsk->umem, addr);
    }

    for (int i = 0; i < num_fw_mp; i++)
        if (fw_is_alive(i) && s->state[i] == NUL)
            return INVALID_UMEM_FRAME; /* still waiting for alive FW i */

    /* All alive firewalls confirmed: hand the primary's frame to the caller */
    uint64_t fwd_addr = s->addr;
    *forward_len = s->pkt_len;
    HASH_DEL(udp_hash_counter, s);
    free(s->state);
    free(s);
    return fwd_addr; /* INVALID_UMEM_FRAME if primary never arrived */
}

/* -----------------------------------------------------------------------
 * Heartbeat helpers
 * ----------------------------------------------------------------------- */
static void fw_set_state_mp(uint8_t fw_id, uint8_t alive, uint64_t ts)
{
    if (fw_id >= num_fw_mp || !fw_states_mp)
        return;

    bool was_dead = !fw_states_mp[fw_id].alive;

    fw_states_mp[fw_id].alive = alive;
    fw_states_mp[fw_id].last_seen_ns = ts;

    if (was_dead && alive)
        fw_states_mp[fw_id].recovery_ns = now_ns();
    else if (!alive)
        fw_states_mp[fw_id].recovery_ns = 0;

    if (fw_state_map_fd_mp >= 0)
    {
        __u32 key = fw_id;
        if (bpf_map_update_elem(fw_state_map_fd_mp, &key,
                                &fw_states_mp[fw_id], BPF_ANY) != 0)
            fprintf(stderr, "WARN: fw_state_map update failed for fw %u: %s\n",
                    fw_id, strerror(errno));
    }
}

/*
 * Detect an incoming HEARTBEAT_REQ on xsk, build a HEARTBEAT_ACK in-place,
 * and transmit it back out the same socket (same path = same firewall).
 * Returns true if the frame was a heartbeat and has been handled.
 */
static bool handle_heartbeat_req(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
{
    if (len < HB_FRAME_LEN)
        return false;

    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    if (ip->protocol != IPPROTO_UDP)
        return false;

    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
    if (ntohs(udp->dest) != HB_UDP_PORT && ntohs(udp->source) != HB_UDP_PORT)
        return false;

    struct hb_payload *hb = (struct hb_payload *)((uint8_t *)udp + sizeof(struct udphdr));
    if (ntohl(hb->magic) != HB_MAGIC || hb->type != HB_TYPE_REQ)
        return false;

    uint8_t fw_id = hb->fw_id;
    uint64_t ts = now_ns();

    printf("HB REQ from fw %u seq %u - reflecting ACK\n", fw_id, ntohl(hb->seq));

    fw_set_state_mp(fw_id, 1, ts);

    /* Flip the packet into an ACK: swap src/dst IPs, swap ports, change type */
    uint32_t tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->check = 0;

    /* Recompute IP checksum inline */
    ip->check = 0;
    uint32_t sum = 0;
    uint16_t *words = (uint16_t *)ip;
    int ihl_words = ip->ihl * 2; /* ihl is in 32-bit units; *2 gives 16-bit units */
    for (int i = 0; i < ihl_words; i++)
        sum += words[i];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = ~sum;

    uint16_t tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    hb->type = HB_TYPE_ACK;
    /* ts_ns carries the original sender timestamp so the LB can measure RTT */

    udp->check = 0;
    /* Recompute UDP checksum */
    uint32_t usum = 0;
    uint16_t udp_len = ntohs(udp->len);
    uint8_t *udata = (uint8_t *)udp;
    usum += (ip->saddr >> 16) & 0xFFFF;
    usum += ip->saddr & 0xFFFF;
    usum += (ip->daddr >> 16) & 0xFFFF;
    usum += ip->daddr & 0xFFFF;
    usum += htons(IPPROTO_UDP);
    usum += udp->len;
    uint16_t rem = udp_len;
    while (rem > 1)
    {
        usum += ((uint16_t)udata[0] << 8) | udata[1];
        udata += 2;
        rem -= 2;
    }
    if (rem == 1)
        usum += ((uint16_t)udata[0] << 8);
    while (usum >> 16)
        usum = (usum & 0xFFFF) + (usum >> 16);
    udp->check = ~usum;
    if (udp->check == 0)
        udp->check = 0xFFFF;

    /* Transmit ACK back out the same socket */
    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx) != 1)
    {
        fprintf(stderr, "WARN: TX ring full, dropping HB ACK for fw %u\n", fw_id);
        free_umem_frame(xsk->umem, addr);
        return true; /* still consumed */
    }

    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;
    complete_tx(xsk);
    return true;
}

/*
 * add_hash_count_tcp – deduplicate a TCP packet arriving from one of the
 * firewall sockets.
 *
 * is_primary: true when this socket received the full-payload copy from the LB.
 * pkt_len:    Ethernet frame length of this copy.
 * forward_len: set to the primary's packet length when returning != INVALID_UMEM_FRAME.
 *
 * Returns INVALID_UMEM_FRAME when not ready to forward.
 * Returns the primary's frame addr when all copies have confirmed the current
 * state — caller must TX that addr (complete_tx frees it via the CQ).
 *
 * Frame ownership: non-primary copies freed here; primary copy saved in
 * s->addr and handed to the caller on trigger.
 */
static uint64_t add_hash_count_tcp(int packet_id, uint64_t addr, uint32_t pkt_len,
                                   struct xsk_socket_info *xsk, TCP_state state,
                                   bool is_primary, uint32_t *forward_len)
{
    struct hash_counter *s;
    HASH_FIND_INT(tcp_hash_counter, &packet_id, s);

    if (s == NULL)
    {
        if (state != SYN)
        {
            free_umem_frame(xsk->umem, addr);
            return INVALID_UMEM_FRAME;
        }
        s = (struct hash_counter *)malloc(sizeof *s);
        s->id = packet_id;
        s->timestamp = time(NULL);
        s->state = (TCP_state *)calloc(num_fw_mp, sizeof(TCP_state));
        s->state[xsk->id] = SYN;
        HASH_ADD_INT(tcp_hash_counter, id, s);
        if (is_primary)
        {
            s->addr = addr;
            s->pkt_len = pkt_len;
        }
        else
        {
            s->addr = INVALID_UMEM_FRAME;
            s->pkt_len = 0;
            free_umem_frame(xsk->umem, addr);
        }
        return INVALID_UMEM_FRAME;
    }

    /*
     * If a fresh SYN arrives on a stale entry (previous handshake aborted
     * mid-flight — e.g. SYNACK was never received so the ACK-phase deletion
     * never ran), reset the entry so the new connection can start fresh.
     * Without this, every subsequent SYN for the same 4-tuple hits the
     * "unexpected jump" branch and is dropped forever.
     */
    if (state == SYN && s->state[xsk->id] != NUL)
    {
        if (s->addr != INVALID_UMEM_FRAME)
        {
            free_umem_frame(xsk->umem, s->addr);
            s->addr = INVALID_UMEM_FRAME;
            s->pkt_len = 0;
        }
        for (int k = 0; k < num_fw_mp; k++)
            s->state[k] = NUL;
    }

    /* Validate state progression */
    if (s->state[xsk->id] == state - 1)
    {
        s->state[xsk->id] = state;
    }
    else if (s->state[xsk->id] == state)
    {
        free_umem_frame(xsk->umem, addr); /* retransmit — silent drop */
        return INVALID_UMEM_FRAME;
    }
    else
    {
        free_umem_frame(xsk->umem, addr); /* unexpected jump — drop */
        return INVALID_UMEM_FRAME;
    }

    /* Track the primary's full-payload frame */
    if (is_primary)
    {
        if (s->addr != INVALID_UMEM_FRAME)
            free_umem_frame(xsk->umem, s->addr);
        s->addr = addr;
        s->pkt_len = pkt_len;
    }
    else
    {
        free_umem_frame(xsk->umem, addr);
    }

    /* Check whether all alive firewalls have reached this state */
    int alive_total = 0, alive_voted = 0;
    for (int i = 0; i < num_fw_mp; i++)
    {
        if (!fw_is_alive(i))
            continue;
        alive_total++;
        if (s->state[i] != state)
            return INVALID_UMEM_FRAME; /* this alive FW hasn't confirmed yet */
        alive_voted++;
    }

    /* All alive firewalls confirmed this state */
    uint64_t fwd_addr = s->addr;
    *forward_len = s->pkt_len;

    if (state == ACK)
    {
        HASH_DEL(tcp_hash_counter, s);
        free(s->state);
        free(s);
    }
    else
    {
        /* SYN confirmed — advance all per-socket states to SYNACK.
         * Reset s->addr so we don't double-free it during the ACK pass. */
        for (int k = 0; k < num_fw_mp; k++)
            s->state[k] = SYNACK;
        s->addr = INVALID_UMEM_FRAME;
        s->pkt_len = 0;
    }

    return fwd_addr;
}

static bool process_packet(struct xsk_socket_info *xsk, struct xsk_socket_info *xsk_out,
                           uint64_t addr, uint32_t len)
{
    bool send = false;
    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    struct ethhdr *eth = (struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return false;
    }

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    if (ip->version != 4)
    {
        return false;
    }

    /* ---- Heartbeat REQ interception (reflected back, not forwarded) ---- */
    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp_chk = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
        if (ntohs(udp_chk->dest) == HB_UDP_PORT || ntohs(udp_chk->source) == HB_UDP_PORT)
        {
            handle_heartbeat_req(xsk, addr, len);
            return true; /* frame ownership transferred to handle_heartbeat_req */
        }
    }

    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;
    uint16_t src_port = 0, dst_port = 0;

    uint8_t *payload = pkt + sizeof(struct ethhdr) + (ip->ihl * 4);
    int packet_id;
    if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)payload;
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
        packet_id = (src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port);

        /* Determine TCP state from flags */
        TCP_state tcp_state;
        if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK))
            tcp_state = SYN;
        else if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK))
            tcp_state = SYNACK;
        else if (tcp->th_flags & TH_ACK)
            tcp_state = ACK;
        else
            tcp_state = NUL;

        int tcp_primary = hash_4tuple_primary_eligible(src_ip, dst_ip, src_port, dst_port, num_fw_mp, fw_states_mp);
        bool tcp_is_primary = (tcp_primary >= 0 && xsk->id == tcp_primary);

        uint32_t tcp_fwd_len = len;
        uint64_t tcp_fwd_addr = add_hash_count_tcp(packet_id, addr, len, xsk,
                                                   tcp_state, tcp_is_primary,
                                                   &tcp_fwd_len);
        if (tcp_fwd_addr != INVALID_UMEM_FRAME)
        {
            addr = tcp_fwd_addr;
            len = tcp_fwd_len;
            send = true;
            /* After the full 3-way handshake is confirmed (all 4 ACK copies
             * seen), register the flow in tcp_hash_map so con_kern_ingress
             * can bpf_redirect subsequent data packets directly to the server
             * interface, bypassing AF_XDP userspace. */
            if (tcp_state == ACK && tcp_map_fd >= 0)
            {
                struct flow_key fk = {};
                fk.src_ip = src_ip;
                fk.dst_ip = dst_ip;
                fk.src_port = htons(src_port);
                fk.dst_port = htons(dst_port);
                uint64_t ts = now_ns();
                bpf_map_update_elem(tcp_map_fd, &fk, &ts, BPF_ANY);
            }
        }
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)payload;
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
        packet_id = (src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port);

        int primary_slot = hash_4tuple_primary_eligible(src_ip, dst_ip, src_port, dst_port, num_fw_mp, fw_states_mp);
        bool is_primary = (primary_slot >= 0 && xsk->id == primary_slot);

        uint32_t forward_len = len;
        uint64_t forward_addr = add_hash_count_udp(packet_id, addr, len, xsk,
                                                   is_primary, &forward_len);
        if (forward_addr != INVALID_UMEM_FRAME)
        {
            /* Update addr/len to use the primary's full-payload frame */
            addr = forward_addr;
            len = forward_len;
            send = true;
            /* Register flow in udp_hash_map so con_kern_ingress can
             * bpf_redirect repeat datagrams from the same 4-tuple directly. */
            if (udp_map_fd >= 0)
            {
                struct flow_key fk = {};
                fk.src_ip = src_ip;
                fk.dst_ip = dst_ip;
                fk.src_port = htons(src_port);
                fk.dst_port = htons(dst_port);
                uint64_t ts = now_ns();
                bpf_map_update_elem(udp_map_fd, &fk, &ts, BPF_ANY);
            }
        }
    }

    if (send)
    {
        /* Refresh pointers — addr/len may have been updated by UDP primary-copy fix */
        pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
        ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
        payload = pkt + sizeof(struct ethhdr) + ip->ihl * 4;

        /* ── Ethernet: rewrite MACs for the output (server-side) interface.
         * The output socket is xsk_out; its index in the input_src/dst_macs
         * arrays is num_fw_mp (last slot, populated in main).               */
        struct ethhdr *eth_out = (struct ethhdr *)pkt;
        memcpy(eth_out->h_source, input_src_macs[num_fw_mp], ETH_ALEN);
        memcpy(eth_out->h_dest, input_dst_macs[num_fw_mp], ETH_ALEN);

        /* ── IP: decrement TTL, then recompute IP checksum ── */
        if (ip->ttl <= 1)
        {
            free_umem_frame(xsk->umem, addr);
            return true;
        }

        ip->ttl--;
        ip->check = 0;
        ip->check = ip_checksum((__u16 *)ip, ip->ihl * 4);

        /* ── L4: recompute over updated IP header ── */
        if (ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)payload;
            tcp->check = 0;
            compute_tcp_checksum(ip, payload);
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)payload;
            udp->check = 0;
            compute_udp_checksum(ip, udp);
        }

        /* ── Enqueue on output socket ── */
        uint32_t tx_idx;
        if (xsk_ring_prod__reserve(&xsk_out->tx, 1, &tx_idx) != 1)
        {
            /* TX ring full — we own addr here; free it and return true so that
             * handle_receive_packets does not attempt a second free of the frame. */
            free_umem_frame(xsk->umem, addr);
            return true;
        }

        xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->addr = addr;
        xsk_ring_prod__tx_desc(&xsk_out->tx, tx_idx)->len = len;
        xsk_ring_prod__submit(&xsk_out->tx, 1);
        xsk_out->outstanding_tx++;
    }
    return true;
}

static void handle_receive_packets(struct xsk_socket_info *xsk, struct xsk_socket_info *xsk_out)
{
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;
    /* One-for-one refill: replace exactly the frames the kernel just consumed from fq.
     * Cap by actual pool availability to prevent INVALID_UMEM_FRAME from being
     * submitted to the kernel (which would permanently lose that fq slot). */
    {
        uint32_t pool_avail = (uint32_t)umem_free_frames(xsk->umem);
        uint32_t want = rcvd < pool_avail ? rcvd : pool_avail;
        stock_frames = xsk_prod_nb_free(&xsk->fq, want);

        if (stock_frames > 0)
        {
            ret = xsk_ring_prod__reserve(&xsk->fq, stock_frames, &idx_fq);
            while (ret != (int)stock_frames)
                ret = xsk_ring_prod__reserve(&xsk->fq, stock_frames, &idx_fq);

            for (i = 0; i < stock_frames; i++)
                *xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) =
                    alloc_umem_frame(xsk->umem);

            xsk_ring_prod__submit(&xsk->fq, stock_frames);
        }
    }

    /* Process received packets */
    for (i = 0; i < rcvd; i++)
    {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        if (!process_packet(xsk, xsk_out, addr, len))
            free_umem_frame(xsk->umem, addr);
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);

    complete_tx(xsk_out);
}

static void handle_return_packets(struct xsk_socket_info **xsks, int num_sockets)
{
    unsigned int rcvd, stock_frames, i, j;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;
    struct xsk_socket_info *output_xsk = xsks[num_sockets - 1];
    int num_input_sockets = num_sockets - 1;

    /* Drain previous batch's TX completions FIRST — returns FW-copy frames to the
     * shared pool before we refill fq and allocate new TX frames below.
     * Calling complete_tx here (after the previous batch's sendto kick) gives the
     * kernel the entire duration of the last call to complete those TX ops. */
    for (j = 0; j < (unsigned int)num_input_sockets; j++)
        complete_tx(xsks[j]);

    rcvd = xsk_ring_cons__peek(&output_xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    /* One-for-one refill: replace exactly the frames the kernel just consumed from the
     * output socket's fill queue.  Cap by actual pool availability to prevent
     * INVALID_UMEM_FRAME from being submitted to the kernel (frame leak). */
    {
        uint32_t pool_avail = (uint32_t)umem_free_frames(output_xsk->umem);
        uint32_t want = rcvd < pool_avail ? rcvd : pool_avail;
        stock_frames = xsk_prod_nb_free(&output_xsk->fq, want);
        if (stock_frames > 0)
        {
            ret = xsk_ring_prod__reserve(&output_xsk->fq, stock_frames, &idx_fq);
            while (ret != (int)stock_frames)
                ret = xsk_ring_prod__reserve(&output_xsk->fq, stock_frames, &idx_fq);
            for (i = 0; i < stock_frames; i++)
                *xsk_ring_prod__fill_addr(&output_xsk->fq, idx_fq++) =
                    alloc_umem_frame(output_xsk->umem);
            xsk_ring_prod__submit(&output_xsk->fq, stock_frames);
        }
    }

    for (i = 0; i < rcvd; i++)
    {
        uint64_t src_addr = xsk_ring_cons__rx_desc(&output_xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&output_xsk->rx, idx_rx++)->len;

        uint8_t *src_pkt = xsk_umem__get_data(output_xsk->umem->buffer, src_addr);

        /* ── Parse Ethernet / IP ── */
        struct ethhdr *src_eth = (struct ethhdr *)src_pkt;
        if (ntohs(src_eth->h_proto) != ETH_P_IP)
        {
            free_umem_frame(output_xsk->umem, src_addr);
            continue;
        }

        struct iphdr *src_ip = (struct iphdr *)(src_pkt + sizeof(struct ethhdr));
        if (src_ip->version != 4)
        {
            free_umem_frame(output_xsk->umem, src_addr);
            continue;
        }

        uint32_t sip = src_ip->saddr;
        uint32_t dip = src_ip->daddr;
        uint16_t sport = 0, dport = 0;
        uint8_t *payload = src_pkt + sizeof(struct ethhdr) + src_ip->ihl * 4;

        if (src_ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)payload;
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
        }
        else if (src_ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *)payload;
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
        }
        else
        {
            free_umem_frame(output_xsk->umem, src_addr);
            continue;
        }

        /* ── Select primary firewall (gets full packet) ── */
        int primary_idx = hash_4tuple_primary_eligible(sip, dip, sport, dport, num_input_sockets, fw_states_mp);
        if (primary_idx < 0)
        {
            fprintf(stderr, "[mp-ret] WARN: all firewalls down, dropping return packet\n");
            free_umem_frame(output_xsk->umem, src_addr);
            continue;
        }

        /* ── Compute header-only length ── */
        uint32_t l4_hdr_len;
        if (src_ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *)payload;
            l4_hdr_len = tcp->doff * 4;
        }
        else
        {
            l4_hdr_len = sizeof(struct udphdr);
        }
        uint32_t header_len = sizeof(struct ethhdr) + src_ip->ihl * 4 + l4_hdr_len;

        /* ── Non-primary copies first (header-only, allocate new frames) ── */
        for (j = 0; j < (unsigned int)num_input_sockets; j++)
        {
            if ((int)j == primary_idx)
                continue;
            if (!fw_is_alive(j))
                continue;

            uint64_t dst_addr = alloc_umem_frame(xsks[j]->umem);
            if (dst_addr == INVALID_UMEM_FRAME)
            {
                fprintf(stderr, "[mp-ret]   fw%d WARN: no free frames, dropping\n", j);
                continue;
            }

            uint8_t *dst_pkt = xsk_umem__get_data(xsks[j]->umem->buffer, dst_addr);
            memcpy(dst_pkt, src_pkt, header_len);

            /* ── Ethernet MACs for this input link ── */
            struct ethhdr *dst_eth = (struct ethhdr *)dst_pkt;
            memcpy(dst_eth->h_source, input_src_macs[j], ETH_ALEN);
            memcpy(dst_eth->h_dest, input_dst_macs[j], ETH_ALEN);

            /* ── IP: adjust tot_len, decrement TTL, recompute ── */
            struct iphdr *dst_ip = (struct iphdr *)(dst_pkt + sizeof(struct ethhdr));
            if (dst_ip->ttl <= 1)
            {
                free_umem_frame(xsks[j]->umem, dst_addr);
                continue;
            }
            dst_ip->ttl--;
            dst_ip->tot_len = htons(header_len - sizeof(struct ethhdr));
            dst_ip->check = 0;
            dst_ip->check = ip_checksum((__u16 *)dst_ip, dst_ip->ihl * 4);

            /* ── L4 checksum ── */
            uint8_t *dst_l4 = dst_pkt + sizeof(struct ethhdr) + dst_ip->ihl * 4;
            if (dst_ip->protocol == IPPROTO_TCP)
            {
                struct tcphdr *dst_tcp = (struct tcphdr *)dst_l4;
                dst_tcp->check = 0;
                compute_tcp_checksum(dst_ip, dst_l4);
            }
            else
            {
                struct udphdr *dst_udp = (struct udphdr *)dst_l4;
                dst_udp->len = htons(sizeof(struct udphdr));
                dst_udp->check = 0;
                compute_udp_checksum(dst_ip, dst_udp);
            }

            /* ── Enqueue on this input socket's TX ── */
            uint32_t tx_idx;
            ret = xsk_ring_prod__reserve(&xsks[j]->tx, 1, &tx_idx);
            if (ret != 1)
            {
                fprintf(stderr, "[mp-ret]   fw%d WARN: TX ring full, dropping\n", j);
                free_umem_frame(xsks[j]->umem, dst_addr);
                continue;
            }

            xsk_ring_prod__tx_desc(&xsks[j]->tx, tx_idx)->addr = dst_addr;
            xsk_ring_prod__tx_desc(&xsks[j]->tx, tx_idx)->len = header_len;
            xsk_ring_prod__submit(&xsks[j]->tx, 1);
            xsks[j]->outstanding_tx++;
        }

        /*  Primary copy: modify src frame in-place  */
        if (fw_is_alive(primary_idx))
        {

            if (src_ip->ttl <= 1)
            {
                free_umem_frame(output_xsk->umem, src_addr);
            }
            else
            {
                struct ethhdr *p_eth = (struct ethhdr *)src_pkt;
                memcpy(p_eth->h_source, input_src_macs[primary_idx], ETH_ALEN);
                memcpy(p_eth->h_dest, input_dst_macs[primary_idx], ETH_ALEN);

                src_ip->ttl--;
                src_ip->check = 0;
                src_ip->check = ip_checksum((__u16 *)src_ip, src_ip->ihl * 4);

                uint8_t *p_l4 = src_pkt + sizeof(struct ethhdr) + src_ip->ihl * 4;
                if (src_ip->protocol == IPPROTO_TCP)
                {
                    struct tcphdr *p_tcp = (struct tcphdr *)p_l4;
                    p_tcp->check = 0;
                    compute_tcp_checksum(src_ip, p_l4);
                }
                else
                {
                    struct udphdr *p_udp = (struct udphdr *)p_l4;
                    p_udp->check = 0;
                    compute_udp_checksum(src_ip, p_udp);
                }

                uint32_t tx_idx;
                ret = xsk_ring_prod__reserve(&xsks[primary_idx]->tx, 1, &tx_idx);
                if (ret != 1)
                {
                    fprintf(stderr, "[mp-ret]   fw%d WARN: TX ring full, dropping\n", primary_idx);
                    free_umem_frame(output_xsk->umem, src_addr);
                }
                else
                {
                    xsk_ring_prod__tx_desc(&xsks[primary_idx]->tx, tx_idx)->addr = src_addr;
                    xsk_ring_prod__tx_desc(&xsks[primary_idx]->tx, tx_idx)->len = len;
                    xsk_ring_prod__submit(&xsks[primary_idx]->tx, 1);
                    xsks[primary_idx]->outstanding_tx++;
                }
            }
        }
        else
        {
            free_umem_frame(output_xsk->umem, src_addr);
        }
    }

    xsk_ring_cons__release(&output_xsk->rx, rcvd);

    /* Kick current batch's TX submissions so the kernel processes them promptly.
     * Completions will be drained at the START of the next call (see above). */
    for (j = 0; j < (unsigned int)num_input_sockets; j++)
        if (xsks[j]->outstanding_tx)
            sendto(xsk_socket__fd(xsks[j]->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void evict_stale(struct hash_counter **table,
                        struct xsk_umem_info *umem, time_t now)
{
    struct hash_counter *s, *tmp;
    HASH_ITER(hh, *table, s, tmp)
    {
        if (now - s->timestamp > STALE_ENTRY_SEC)
        {
            if (s->addr != INVALID_UMEM_FRAME)
                free_umem_frame(umem, s->addr);
            free(s->state);
            HASH_DEL(*table, s);
            free(s);
        }
    }
}

static void rx_and_process(struct xsk_socket_info **xsks, int num_sockets)
{
    struct pollfd *fds;
    int ret;

    fds = calloc(num_sockets, sizeof(*fds));
    if (!fds)
    {
        exit(-1);
    }

    for (int i = 0; i < num_sockets; i++)
    {
        fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
        fds[i].events = POLLIN;
    }

    static time_t last_evict = 0;
    while (!global_exit)
    {

        ret = poll(fds, num_sockets, -1);

        /* Evict stale entries periodically */
        time_t now_sec = time(NULL);
        if (now_sec - last_evict < STALE_ENTRY_SEC)
        {
            evict_stale(&tcp_hash_counter, xsks[0]->umem, now_sec);
            evict_stale(&udp_hash_counter, xsks[0]->umem, now_sec);
            last_evict = now_sec;
        }

        if (ret <= 0)
            continue;

        for (int i = 0; i < num_sockets; i++)
        {
            if (
                fds[i].revents & POLLIN)
            {
                if (i != num_sockets - 1)
                {
                    handle_receive_packets(xsks[i], xsks[num_sockets - 1]);
                }
                else
                {
                    handle_return_packets(xsks, num_sockets);
                }
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
    struct xsk_socket_info **xsks;
    int num_sockets, id;

    /* Global shutdown handler */
    signal(SIGINT, exit_application);

    if (argc == 1)
    {
        fprintf(stderr, "no args\n");
        exit(EXIT_FAILURE);
    }

    num_sockets = argc - 1;

    xsks = calloc(num_sockets, sizeof(*xsks));

    if (!xsks)
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

    tcp_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/tcp_hash_map");
    printf("tcp_map_fd: %d\n", tcp_map_fd);
    if (tcp_map_fd < 0)
    {
        fprintf(stderr, "ERROR: tcp_map not available \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    udp_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/udp_hash_map");
    printf("udp_map_fd: %d\n", udp_map_fd);
    if (udp_map_fd < 0)
    {
        fprintf(stderr, "ERROR: udp_map not available \"%s\"\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fw_state_map_fd_mp = bpf_obj_get("/sys/fs/bpf/xsks_map/con_fw_state_map");
    if (fw_state_map_fd_mp < 0)
        fprintf(stderr, "WARN: con_fw_state_map not available (%s) – kernel state disabled\n",
                strerror(errno));

    /* iface_to_fw_map: ifindex → firewall slot index, consumed by con_kern_ingress */
    int iface_to_fw_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/iface_to_fw_map");
    if (iface_to_fw_map_fd < 0)
        fprintf(stderr, "WARN: iface_to_fw_map not available (%s) – ingress XDP slot lookup disabled\n",
                strerror(errno));

    /* output_ifindex_map: key=0 → output interface ifindex.
     * Written below (after sockets are opened); read by con_kern_ingress to
     * bpf_redirect established-flow primary packets directly to the server. */
    int output_ifindex_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map/output_ifindex_map");
    if (output_ifindex_map_fd < 0)
        fprintf(stderr, "WARN: output_ifindex_map not available (%s) – bpf_redirect shortcut disabled\n",
                strerror(errno));

    num_fw_mp = num_sockets - 1; /* exclude the single output socket */
    fw_states_mp = calloc(num_fw_mp, sizeof(struct fw_state));
    if (!fw_states_mp)
    {
        fprintf(stderr, "ERROR: Can't allocate heartbeat state\n");
        exit(EXIT_FAILURE);
    }
    /* Treat every firewall as alive at startup — matches the kernel XDP
     * startup-race protection (missing fw_state_map entry → alive). The
     * heartbeat will mark dead firewalls once probing begins. */
    for (int i = 0; i < num_fw_mp; i++)
        fw_states_mp[i].alive = 1;

    /* Initialize heartbeat IP addresses */
    inet_pton(AF_INET, HB_SRC_IP, &hb_src_ip_n_mp);
    inet_pton(AF_INET, HB_DST_IP, &hb_dst_ip_n_mp);

    /* Allow unlimited locking of memory, so all memory needed for packet
     * buffers can be locked.
     */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    cfgs = malloc(num_sockets * sizeof(struct config));
    if (!cfgs)
    {
        fprintf(stderr, "ERROR: Can't allocate config memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (posix_memalign(&packet_buffer,
                       getpagesize(), /* PAGE_SIZE aligned */
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

    for (int i = 0; i < num_sockets; i++)
    {
        id = if_nametoindex(argv[i + 1]);
        if (!id)
        {
            fprintf(stderr, "ifname does not exist");
            exit(EXIT_FAILURE);
        }

        cfgs[i].ifindex = id;
        cfgs[i].xsk_if_queue = 0;
        cfgs[i].do_unload = false;
        strcpy(cfgs[i].progsec, "xdp");
        cfgs[i].ifname = argv[i + 1];
        cfgs[i].xdp_flags = XDP_FLAGS_SKB_MODE;
        xsks[i] = xsk_configure_socket(&cfgs[i], umem);
        if (xsks[i] == NULL)
        {
            fprintf(stderr, "ERROR: Can't setup AF_XDP socket for %s \"%s\"\n", cfgs[i].ifname, strerror(errno));
            exit(EXIT_FAILURE);
        }
        xsks[i]->id = i;

        /* Divide fill-ring frames evenly across all sockets */
        setup_fq(xsks[i], num_sockets);

        int xsk_fd = xsk_socket__fd(xsks[i]->xsk);
        if (bpf_map_update_elem(xsks_map_fd, &id, &xsk_fd, BPF_ANY) != 0)
        {
            fprintf(stderr, "ERROR: bpf_map_update_elem failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* Register ifindex → firewall slot for the ingress XDP program.
         * The output socket (last entry, index num_fw_mp) is the server-side
         * interface and has no firewall slot — skip it. */
        if (iface_to_fw_map_fd >= 0 && i < num_fw_mp)
        {
            __u32 fw_slot = (__u32)i;
            if (bpf_map_update_elem(iface_to_fw_map_fd, &id, &fw_slot, BPF_ANY) != 0)
                fprintf(stderr, "WARN: iface_to_fw_map update failed for %s: %s\n",
                        cfgs[i].ifname, strerror(errno));
            else
                printf("iface_to_fw_map: ifindex %d -> fw slot %u (%s)\n",
                       id, fw_slot, cfgs[i].ifname);
        }
    }
    printf("%d sockets configured and added to xsks_map\n", num_sockets);

    /* ── MAC cache: num_sockets slots (0..num_fw_mp-1 = input, num_fw_mp = output) ──
     * input_src_macs[i] = our MAC on input iface i (toward firewall i)
     * input_dst_macs[i] = next-hop MAC on that link (default broadcast)
     * input_src_macs[num_fw_mp] = our MAC on the output (server-side) iface
     * input_dst_macs[num_fw_mp] = next-hop MAC on server side
     */
    input_src_macs = calloc(num_sockets, ETH_ALEN);
    input_dst_macs = calloc(num_sockets, ETH_ALEN);
    if (!input_src_macs || !input_dst_macs)
    {
        fprintf(stderr, "ERROR: Can't allocate MAC cache\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_sockets; i++)
    {
        if (get_iface_mac(cfgs[i].ifname, input_src_macs[i]) < 0)
            fprintf(stderr, "WARN: can't get MAC for %s: %s\n",
                    cfgs[i].ifname, strerror(errno));
        else
            printf("iface %s src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   cfgs[i].ifname,
                   input_src_macs[i][0], input_src_macs[i][1],
                   input_src_macs[i][2], input_src_macs[i][3],
                   input_src_macs[i][4], input_src_macs[i][5]);
        /* Default dst to broadcast; overridden below for the output interface */
        memset(input_dst_macs[i], 0xFF, ETH_ALEN);
    }

    /* Resolve the veth peer's MAC for the output (server-side) interface */
    {
        char sysfs_path[256];
        snprintf(sysfs_path, sizeof(sysfs_path),
                 "/sys/class/net/%s/iflink", cfgs[num_fw_mp].ifname);
        FILE *fp = fopen(sysfs_path, "r");
        if (fp)
        {
            int peer_idx = -1;
            if (fscanf(fp, "%d", &peer_idx) == 1 && peer_idx > 0)
            {
                char peer_name[IF_NAMESIZE] = {0};
                if (if_indextoname(peer_idx, peer_name) &&
                    get_iface_mac(peer_name, input_dst_macs[num_fw_mp]) == 0)
                    printf("output dst MAC (peer %s): "
                           "%02x:%02x:%02x:%02x:%02x:%02x\n",
                           peer_name,
                           input_dst_macs[num_fw_mp][0],
                           input_dst_macs[num_fw_mp][1],
                           input_dst_macs[num_fw_mp][2],
                           input_dst_macs[num_fw_mp][3],
                           input_dst_macs[num_fw_mp][4],
                           input_dst_macs[num_fw_mp][5]);
                else
                    fprintf(stderr, "WARN: can't resolve peer MAC for %s"
                                    " - using broadcast\n",
                            cfgs[num_fw_mp].ifname);
            }
            fclose(fp);
        }
        else
        {
            fprintf(stderr, "WARN: can't open %s to find output peer"
                            " - using broadcast\n",
                    sysfs_path);
        }
    }

    /* Populate output_ifindex_map now that input_dst_macs[num_fw_mp] is resolved. */
    if (output_ifindex_map_fd >= 0)
    {
        __u32 key = 0;
        struct iface_info oinfo = {};
        oinfo.ifindex = (__u32)cfgs[num_fw_mp].ifindex;
        memcpy(oinfo.dst_mac, input_dst_macs[num_fw_mp], 6);
        if (bpf_map_update_elem(output_ifindex_map_fd, &key, &oinfo, BPF_ANY) != 0)
            fprintf(stderr, "WARN: output_ifindex_map update failed: %s\n", strerror(errno));
        else
            printf("output_ifindex_map: ifindex=%u (%s) dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   oinfo.ifindex, cfgs[num_fw_mp].ifname,
                   oinfo.dst_mac[0], oinfo.dst_mac[1], oinfo.dst_mac[2],
                   oinfo.dst_mac[3], oinfo.dst_mac[4], oinfo.dst_mac[5]);
        close(output_ifindex_map_fd);
    }

    rx_and_process(xsks, num_sockets);

    /* Cleanup */
    xsk_umem__delete(xsks[0]->umem->umem);
    for (int i = 0; i < num_sockets; i++)
    {
        xsk_socket__delete(xsks[i]->xsk);
        xdp_multiprog__close(xdp_multiprog__get_from_ifindex(cfgs[i].ifindex));
        free(cfgs);
    }

    free(fw_states_mp);
    free(input_src_macs);
    free(input_dst_macs);

    return 0;
}
