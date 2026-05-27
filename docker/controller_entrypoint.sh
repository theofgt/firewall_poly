#!/usr/bin/env bash
# docker/controller_entrypoint.sh
set -euo pipefail

log() { echo "[controller] $*"; }

INPUT_IFACES="${INPUT_IFACES:-veth-mp-fw0 veth-mp-fw1 veth-mp-fw2 veth-mp-fw3}"
OUTPUT_IFACE="${OUTPUT_IFACE:-veth-mp-out}"
CON_INGRESS_OBJ="${CON_INGRESS_OBJ:-/opt/xdp/con_kern_ingress.o}"
CON_EGRESS_OBJ="${CON_EGRESS_OBJ:-/opt/xdp/con_kern_egress.o}"
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

for iface in $INPUT_IFACES $OUTPUT_IFACE; do
    wait_iface "$iface"
done

# ── Remove stale XDP programs from previous runs (don't wipe pin dir — LB owns it) ──
log "cleaning up stale XDP state"
for iface in $INPUT_IFACES $OUTPUT_IFACE; do
    xdp-loader unload "$iface" --all 2>/dev/null || true
done

mkdir -p "$BPF_PIN_DIR"

# ── Load XDP programs: ingress prog on firewall-facing input ifaces ───────────
for iface in $INPUT_IFACES; do
    log "loading con_kern_ingress on $iface"
    xdp-loader load -m skb --pin-path "$BPF_PIN_DIR" "$iface" "$CON_INGRESS_OBJ" || {
        log "WARN: xdp-loader failed for $iface (may already be loaded)"
    }
done

# ── Load XDP programs: egress prog on server-facing output iface ──────────────
log "loading con_kern_egress on $OUTPUT_IFACE"
xdp-loader load -m skb --pin-path "$BPF_PIN_DIR" "$OUTPUT_IFACE" "$CON_EGRESS_OBJ" || {
    log "WARN: xdp-loader failed for $OUTPUT_IFACE (may already be loaded)"
}

log "BPF maps pinned at $BPF_PIN_DIR:"
ls "$BPF_PIN_DIR" 2>/dev/null || true

# ── controller CLI: input ifaces then output iface ────────────────────────────
ARGS="$INPUT_IFACES $OUTPUT_IFACE"

log "starting: controller $ARGS"
exec /usr/local/bin/controller $ARGS
