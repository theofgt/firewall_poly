#!/usr/bin/env bash
# docker/firewall_sim_entrypoint.sh
# Simulates a firewall: forwards all traffic from INGRESS to EGRESS.
# Optional DROP_RATE (0-100) injects packet loss to test heartbeat failover.
set -euo pipefail

FW_ID="${FW_ID:-0}"
INGRESS="${INGRESS:-veth-fw0-lb}"
EGRESS="${EGRESS:-veth-fw0-mp}"
DROP_RATE="${DROP_RATE:-0}"   # percent packet drop for failure simulation
ROLE="${ROLE:-firewall}"

log() { echo "[${ROLE}/${FW_ID}] $*"; }

# ── Client / server roles (for traffic generator containers) ─────────────────
if [ "$ROLE" = "client" ]; then
    IFACE="${IFACE:-veth-client}"
    TARGET_IP="${TARGET_IP:-10.0.5.2}"
    TCP_PORT="${TCP_PORT:-8080}"
    UDP_PORT="${UDP_PORT:-9090}"

    log "client starting on $IFACE, targeting $TARGET_IP"
    ip link set "$IFACE" up 2>/dev/null || true

    # Wait for server
    until ping -c1 -W1 "$TARGET_IP" &>/dev/null; do
        log "waiting for server at $TARGET_IP …"
        sleep 2
    done

    exec python3 /usr/local/bin/traffic_gen.py \
        --role client \
        --iface "$IFACE" \
        --target "$TARGET_IP" \
        --tcp-port "$TCP_PORT" \
        --udp-port "$UDP_PORT"
fi

if [ "$ROLE" = "server" ]; then
    IFACE="${IFACE:-veth-server}"
    LISTEN_IP="${LISTEN_IP:-10.0.5.2}"
    TCP_PORT="${TCP_PORT:-8080}"
    UDP_PORT="${UDP_PORT:-9090}"

    log "server listening on $IFACE ($LISTEN_IP)"
    ip link set "$IFACE" up 2>/dev/null || true

    exec python3 /usr/local/bin/traffic_gen.py \
        --role server \
        --iface "$IFACE" \
        --listen "$LISTEN_IP" \
        --tcp-port "$TCP_PORT" \
        --udp-port "$UDP_PORT"
fi

# ── Firewall bridge mode ──────────────────────────────────────────────────────
wait_iface() {
    local iface="$1" retries=30
    while ! ip link show "$iface" &>/dev/null; do
        retries=$((retries - 1))
        [ "$retries" -le 0 ] && { log "ERROR: $iface never appeared"; exit 1; }
        log "waiting for $iface …"
        sleep 1
    done
}

wait_iface "$INGRESS"
wait_iface "$EGRESS"

ip link set "$INGRESS" up
ip link set "$EGRESS"  up

log "firewall $FW_ID: $INGRESS → $EGRESS  (drop_rate=${DROP_RATE}%)"

# Use tc netem to simulate packet loss when DROP_RATE > 0
if [ "$DROP_RATE" -gt 0 ]; then
    log "injecting ${DROP_RATE}% packet loss on $INGRESS"
    tc qdisc replace dev "$INGRESS" root netem loss "${DROP_RATE}%"
fi

# Simple L2 bridge using ip link bridge
BRIDGE="br-fw${FW_ID}"
if ! ip link show "$BRIDGE" &>/dev/null; then
    ip link add name "$BRIDGE" type bridge
    ip link set "$INGRESS" master "$BRIDGE"
    ip link set "$EGRESS"  master "$BRIDGE"
    ip link set "$BRIDGE"  up
    log "bridge $BRIDGE created ($INGRESS <-> $EGRESS)"
fi

log "firewall $FW_ID running (bridge mode)"

# Keep the container alive; react to SIGTERM for clean shutdown
trap 'log "shutting down"; ip link del "$BRIDGE" 2>/dev/null; exit 0' SIGTERM SIGINT
while true; do sleep 10; done
