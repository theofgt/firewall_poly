#!/usr/bin/env bash
# docker/net_setup.sh
# Creates the full virtual topology in the host network namespace.
# Run once by the net-setup init container before anything else starts.
set -euo pipefail

log() { echo "[net-setup] $*"; }

# ── Helper: create veth pair, bring both ends up ─────────────────────────────
veth_pair() {
    local a="$1" b="$2"
    if ip link show "$a" &>/dev/null; then
        log "veth $a already exists, skipping"
        return
    fi
    ip link add "$a" type veth peer name "$b"
    ip link set "$a" up
    ip link set "$b" up
    # Disable GRO/LRO so XDP sees full-size frames unmodified
    ethtool -K "$a" gro off lro off 2>/dev/null || true
    ethtool -K "$b" gro off lro off 2>/dev/null || true
    log "created veth pair $a <-> $b"
}

# ── Topology ─────────────────────────────────────────────────────────────────
#
#  [client:veth-client] <-> [veth-lb-in:load_balancer]
#
#  [load_balancer:veth-lb-fw{N}] <-> [veth-fw{N}-lb:fw{N}]
#  [fw{N}:veth-fw{N}-mp]         <-> [veth-mp-fw{N}:controller]
#
#  [controller:veth-mp-out] <-> [veth-server:server]
#
# IP addressing:
#   10.0.0.0/30  – client  <-> load_balancer input
#   10.0.1.N/30  – load_balancer <-> fw{N}     (N=0-3, subnets /30)
#   10.0.2.N/30  – fw{N}  <-> controller input  (N=0-3)
#   10.0.5.0/30  – controller output <-> server

NUM_FW=4

# client ↔ load_balancer
veth_pair veth-client veth-lb-in
ip addr replace 10.0.0.1/30 dev veth-client   2>/dev/null || true
ip addr replace 10.0.0.2/30 dev veth-lb-in    2>/dev/null || true

# load_balancer ↔ fw{N}  and  fw{N} ↔ controller
for N in $(seq 0 $((NUM_FW - 1))); do
    SUBNET_LB=$((1 + N * 4))         # 10.0.1.{1,5,9,13}
    SUBNET_MP=$((1 + N * 4))         # 10.0.2.{1,5,9,13}

    veth_pair "veth-lb-fw${N}"  "veth-fw${N}-lb"
    ip addr replace "10.0.1.${SUBNET_LB}/30"   dev "veth-lb-fw${N}"  2>/dev/null || true
    ip addr replace "10.0.1.$((SUBNET_LB+1))/30" dev "veth-fw${N}-lb" 2>/dev/null || true

    veth_pair "veth-fw${N}-mp"  "veth-mp-fw${N}"
    ip addr replace "10.0.2.${SUBNET_MP}/30"   dev "veth-fw${N}-mp"  2>/dev/null || true
    ip addr replace "10.0.2.$((SUBNET_MP+1))/30" dev "veth-mp-fw${N}" 2>/dev/null || true
done

# controller ↔ server
veth_pair veth-mp-out veth-server
ip addr replace 10.0.5.1/30 dev veth-mp-out  2>/dev/null || true
ip addr replace 10.0.5.2/30 dev veth-server  2>/dev/null || true

# ── IP forwarding: needed for XDP_PASS established-flow kernel shortcut ───────
sysctl -w net.ipv4.ip_forward=1 || true

# ── Block kernel TCP RSTs so raw Scapy sockets aren't reset by the IP stack ──
# Without this, the kernel sees SYN/ACK arriving at local IPs with no matching
# socket and sends RSTs that tear down the Scapy-managed TCP state machines.
iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true
log "iptables: outgoing TCP RSTs suppressed"

# ── BPF filesystem ────────────────────────────────────────────────────────────
mount | grep -q "bpffs on /sys/fs/bpf" || mount -t bpf bpf /sys/fs/bpf
mkdir -p /sys/fs/bpf/xsks_map
log "BPF fs ready at /sys/fs/bpf/xsks_map"

# ── Routing: ensure traffic from client can find the server ──────────────────
ip route replace 10.0.5.0/30 via 10.0.0.2 dev veth-client 2>/dev/null || true

# Static ARP entries using the peer interface's actual MAC — the kernel rejects
# broadcast MACs (ff:ff:ff:ff:ff:ff) in the neighbor table; unicast MACs work.
ip neigh replace 10.0.0.2 \
    lladdr "$(cat /sys/class/net/veth-lb-in/address)" \
    nud permanent dev veth-client 2>/dev/null || true
ip neigh replace 10.0.5.1 \
    lladdr "$(cat /sys/class/net/veth-mp-out/address)" \
    nud permanent dev veth-server 2>/dev/null || true

log "Network topology ready:"
log "  client(10.0.0.1) <-> lb-in(10.0.0.2)"
for N in $(seq 0 $((NUM_FW - 1))); do
    log "  lb-fw${N} <-> fw${N}-lb  |  fw${N}-mp <-> mp-fw${N}"
done
log "  mp-out(10.0.5.1) <-> server(10.0.5.2)"

exit 0
