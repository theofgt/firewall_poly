#ifndef __FLOW_H__
#define __FLOW_H__

#include <linux/types.h>

struct flow_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/* Bits stored in the tcp_hash_map u64 value alongside the timestamp.
 * Bits 0-61 hold the nanosecond timestamp; bits 62-63 are FIN flags. */
#define TCP_HASH_CLIENT_FIN_BIT (1ULL << 63) /* set by ingress when client sends FIN */
#define TCP_HASH_SERVER_FIN_BIT (1ULL << 62) /* set by egress when server sends FIN */
#define TCP_HASH_FIN_BITS (TCP_HASH_CLIENT_FIN_BIT | TCP_HASH_SERVER_FIN_BIT)
#define TCP_HASH_TS(v) ((v) & ~TCP_HASH_FIN_BITS)

#endif /* __FLOW_H__ */