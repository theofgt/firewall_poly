#!/usr/bin/env bash
# docker/load_balancer_entrypoint.sh
set -euo pipefail

log() { echo "[load_balancer] $*"; }

INPUT_IFACES="${INPUT_IFACES:-veth-lb-in}"
OUTPUT_IFACES="${OUTPUT_IFACES:-veth-lb-fw0 veth-lb-fw1 veth-lb-fw2 veth-lb-fw3}"
BAL_INGRESS_OBJ="${BAL_INGRESS_OBJ:-/opt/xdp/bal_kern_ingress.o}"
BAL_EGRESS_OBJ="${BAL_EGRESS_OBJ:-/opt/xdp/bal_kern_egress.o}"
BPF_PIN_DIR="${BPF_PIN_DIR:-/sys/fs/bpf/xsks_map}"

wait_iface() {
    local iface="$1" retries=30
    while ! ip link show "$iface" &>/dev/null; do
        retries=$((retries - 1))
        [ "$retries" -le 0 ] && { log "ERROR: $iface never appeared"; exit 1; }
        log "waiting for $iface …"
        sleep 1
    done
    log "$iface is up"
}

for iface in $INPUT_IFACES $OUTPUT_IFACES; do
    wait_iface "$iface"
done

# ── Remove stale XDP programs and pinned maps from previous runs ─────────────
log "cleaning up stale XDP state"
for iface in $INPUT_IFACES $OUTPUT_IFACES; do
    xdp-loader unload "$iface" --all 2>/dev/null || true
done
rm -rf "$BPF_PIN_DIR"
mkdir -p "$BPF_PIN_DIR"

# ── Load XDP programs: ingress prog on input ifaces ──────────────────────────
for iface in $INPUT_IFACES; do
    log "loading bal_kern_ingress on $iface"
    xdp-loader load -m skb --pin-path "$BPF_PIN_DIR" "$iface" "$BAL_INGRESS_OBJ" || {
        log "WARN: xdp-loader failed for $iface (may already be loaded)"
    }
done

# ── Load XDP programs: egress prog on output ifaces ──────────────────────────
for iface in $OUTPUT_IFACES; do
    log "loading bal_kern_egress on $iface"
    xdp-loader load -m skb --pin-path "$BPF_PIN_DIR" "$iface" "$BAL_EGRESS_OBJ" || {
        log "WARN: xdp-loader failed for $iface (may already be loaded)"
    }
done

log "BPF maps pinned at $BPF_PIN_DIR:"
ls "$BPF_PIN_DIR" 2>/dev/null || true

# ── Build argument list for load_balancer binary ─────────────────────────────
NUM_INPUT=$(echo $INPUT_IFACES | wc -w)
ARGS="$NUM_INPUT $INPUT_IFACES $OUTPUT_IFACES"

log "starting: load_balancer $ARGS"
exec /usr/local/bin/load_balancer $ARGS
