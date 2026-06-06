#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/types.h>

/* -----------------------------------------------------------------------
 * Heartbeat protocol
 *
 * Topology:   [load_balancer] ←→ [firewall_N] ←→ [controller]
 *
 * The load_balancer sends a HEARTBEAT_REQ UDP frame out each output socket
 * (one socket = one firewall path) every HEARTBEAT_INTERVAL_NS nanoseconds.
 * The controller reflects it as a HEARTBEAT_ACK on the same path.
 * Both sides maintain a BPF hash map  (fw_state_map) keyed by firewall index
 * so the kernel-side XDP program can also consult liveness.
 *
 * Wire format (carried inside a raw UDP payload after IP/UDP headers):
 *   magic   : 4 bytes  (0xDEADBEEF)
 *   type    : 1 byte   (HEARTBEAT_REQ / HEARTBEAT_ACK)
 *   fw_id   : 1 byte   (firewall index, 0-based)
 *   seq     : 4 bytes  (sequence number, network byte order)
 *   ts_ns   : 8 bytes  (sender timestamp, host byte order)
 * ----------------------------------------------------------------------- */

#define HB_MAGIC 0xDEADBEEF
#define HB_TYPE_REQ 0x01
#define HB_TYPE_ACK 0x02

/* Probe IP/port identifiers – arbitrary reserved values */
#define HB_SRC_IP "169.254.0.1"
#define HB_DST_IP "169.254.0.2"
#define HB_UDP_PORT 9999

/* Timing */
#define HEARTBEAT_INTERVAL_NS (500ULL * 1000 * 1000)     /* 500 ms */
#define HEARTBEAT_TIMEOUT_NS (2ULL * 1000 * 1000 * 1000) /* 2 s → dead */

/* Grace period after a dead→alive transition during which the FW is
 * ineligible as primary (used by both LB and con_kern_ingress). */
#ifndef THIRTY_SEC_NS
#define THIRTY_SEC_NS (30ULL * 1000000000ULL)
#endif

/* Value stored in output_ifindex_map (controller) and client_ifindex_map (LB):
 * carries both the redirect target ifindex and the peer's Ethernet dst MAC. */
struct iface_info
{
    __u32 ifindex;
    __u8 dst_mac[6];
    __u8 pad[2]; /* explicit padding; must be zero-initialised by userspace */
};

/* Value stored in fw_state_map */
struct fw_state
{
    __u8 alive;         /* 1 = up, 0 = down                   */
    __u64 last_seen_ns; /* monotonic ns from bpf_ktime_get_ns */
    __u64 recovery_ns;  /* time of last dead→alive transition; 0 = never recovered */
    __u32 seq_last;     /* last sequence number seen           */
};

/* On-wire heartbeat payload (packed, no padding) */
struct __attribute__((packed)) hb_payload
{
    __u32 magic;
    __u8 type;
    __u8 fw_id;
    __u32 seq;
    __u64 ts_ns;
};

#define HB_PAYLOAD_LEN sizeof(struct hb_payload) /* 18 bytes */

/* Total probe frame size */
#define HB_FRAME_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                      sizeof(struct udphdr) + HB_PAYLOAD_LEN)

#endif /* HEARTBEAT_H */
