#!/usr/bin/env python3
"""
traffic_gen.py
Full-duplex TCP + UDP traffic generator for the multipoly firewall-cluster pipeline.

Client: SYN → SYNACK → ACK → PSH+ACK (data) → wait PSH+ACK (echo) → FIN+ACK →
        wait FIN+ACK → final ACK
Server: SYNACK on SYN, echo data on PSH, FIN+ACK on FIN.
"""

import argparse
import queue
import struct
import sys
import threading
import time

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, Raw, ARP,
        sendp, sniff, srp, conf, get_if_hwaddr,
    )
except ImportError:
    print("scapy not available - install python3-scapy", file=sys.stderr)
    sys.exit(1)

# TCP flag bit masks
F_FIN     = 0x01
F_SYN     = 0x02
F_RST     = 0x04
F_PSH     = 0x08
F_ACK     = 0x10
F_SYN_ACK = F_SYN | F_ACK   # 0x12
F_PSH_ACK = F_PSH | F_ACK   # 0x18
F_FIN_ACK = F_FIN | F_ACK   # 0x11


def log(role, msg):
    print(f"[{time.strftime('%H:%M:%S')}][{role}] {msg}", flush=True)


def resolve_peer_mac(iface, peer_ip, retries=15):
    """ARP-resolve `peer_ip` on `iface`. Returns MAC string or None."""
    for attempt in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=peer_ip),
                iface=iface, timeout=1, verbose=False,
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        time.sleep(0.5)
    return None


def wait_pkt(q, flag_mask, timeout=5.0):
    """
    Dequeue packets until one with all bits in `flag_mask` set is found.
    Returns the matching packet, or None on timeout.
    Non-matching packets are discarded (they are from unexpected phases).
    """
    deadline = time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            return None
        try:
            pkt = q.get(timeout=min(left, 0.1))
            if pkt.haslayer(TCP) and (int(pkt[TCP].flags) & flag_mask) == flag_mask:
                return pkt
        except queue.Empty:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────

_cli_queues: dict = {}   # sport (int) → queue.Queue
_cli_lock   = threading.Lock()


def _cli_sniff(iface, server_ip):
    """Background thread: deliver server TCP packets to the right per-flow queue."""
    def cb(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        if pkt[IP].src != server_ip:
            return
        dport = pkt[TCP].dport          # server writes to client's ephemeral port
        with _cli_lock:
            q = _cli_queues.get(dport)
        if q:
            q.put(pkt)

    sniff(iface=iface,
          filter=f"ip and tcp and src host {server_ip}",
          prn=cb, store=False)


def run_client(args):
    role   = "client"
    src_ip = "10.0.0.1"
    my_mac = get_if_hwaddr(args.iface)

    log(role, f"ARP resolving gateway 10.0.0.2 on {args.iface} …")
    gw_mac = resolve_peer_mac(args.iface, "10.0.0.2") or "ff:ff:ff:ff:ff:ff"
    log(role, f"gateway MAC = {gw_mac}")

    threading.Thread(target=_cli_sniff, args=(args.iface, args.target),
                     daemon=True).start()

    def send_tcp(sport, seq, ack, flags, payload=b""):
        pkt = (Ether(src=my_mac, dst=gw_mac) /
               IP(src=src_ip, dst=args.target) /
               TCP(sport=sport, dport=args.tcp_port,
                   seq=seq, ack=ack, flags=flags))
        if payload:
            pkt /= Raw(load=payload)
        sendp(pkt, iface=args.iface, verbose=False)

    flow_id = 0
    while True:
        flow_id += 1
        sport   = 10000 + (flow_id % 50000)
        cli_isn = flow_id * 1000

        q = queue.Queue()
        with _cli_lock:
            _cli_queues[sport] = q

        try:
            log(role, f"── flow {flow_id}  sport={sport} ──")

            # ── SYN ──────────────────────────────────────────────────────────
            log(role, f"[1/6] flow {flow_id}: sending SYN  seq={cli_isn}")
            send_tcp(sport, seq=cli_isn, ack=0, flags=F_SYN)

            # ── Wait SYNACK ───────────────────────────────────────────────────
            synack = wait_pkt(q, F_SYN_ACK, timeout=5.0)
            if synack is None:
                log(role, f"[1/6] flow {flow_id}: SYNACK timeout - skipping flow")
                continue
            srv_isn = synack[TCP].seq
            cli_seq = cli_isn + 1       # SYN consumed 1 seq byte
            srv_seq = srv_isn + 1       # server's next byte (SYNACK SYN byte)
            log(role, f"[2/6] flow {flow_id}: got SYNACK  srv_isn={srv_isn:#010x}")

            # ── ACK (completes 3-way handshake) ───────────────────────────────
            log(role, f"[3/6] flow {flow_id}: sending ACK  (handshake complete)")
            send_tcp(sport, seq=cli_seq, ack=srv_seq, flags=F_ACK)
            time.sleep(0.05)

            # ── Data ──────────────────────────────────────────────────────────
            payload = f"HELLO-FLOW-{flow_id}".encode()
            log(role, f"[4/6] flow {flow_id}: sending data  {len(payload)}B: {payload}")
            send_tcp(sport, seq=cli_seq, ack=srv_seq, flags=F_PSH_ACK,
                     payload=payload)

            # ── Wait echo response ────────────────────────────────────────────
            resp = wait_pkt(q, F_PSH, timeout=5.0)
            if resp is not None:
                echo     = bytes(resp[TCP].payload) if resp[TCP].payload else b""
                cli_seq += len(payload)
                srv_seq += len(echo)
                send_tcp(sport, seq=cli_seq, ack=srv_seq, flags=F_ACK)
                log(role, f"[4/6] flow {flow_id}: echo received  {len(echo)}B: {echo[:60]}")
            else:
                log(role, f"[4/6] flow {flow_id}: echo TIMEOUT (no response from server)")
                cli_seq += len(payload)

            time.sleep(0.05)

            # ── FIN (client initiates close) ──────────────────────────────────
            log(role, f"[5/6] flow {flow_id}: sending FIN+ACK")
            send_tcp(sport, seq=cli_seq, ack=srv_seq, flags=F_FIN_ACK)

            # ── Wait server FIN+ACK ───────────────────────────────────────────
            fin_ack = wait_pkt(q, F_FIN_ACK, timeout=5.0)
            if fin_ack is not None:
                cli_seq    += 1
                srv_fin_seq = fin_ack[TCP].seq
                send_tcp(sport, seq=cli_seq, ack=srv_fin_seq + 1, flags=F_ACK)
                log(role, f"[6/6] flow {flow_id}: got server FIN+ACK, sent final ACK – CLOSED")
            else:
                log(role, f"[5/6] flow {flow_id}: server FIN+ACK TIMEOUT")

        finally:
            with _cli_lock:
                _cli_queues.pop(sport, None)

        # ── UDP datagram ──────────────────────────────────────────────────────
        udp_payload = struct.pack("!I", flow_id) + b"UDP-TEST"
        sendp(
            Ether(src=my_mac, dst=gw_mac) /
            IP(src=src_ip, dst=args.target) /
            UDP(sport=sport, dport=args.udp_port) /
            Raw(load=udp_payload),
            iface=args.iface, verbose=False,
        )
        log(role, f"[UDP ] flow {flow_id}: UDP datagram sent ({len(udp_payload)}B)")

        time.sleep(5.0)


# ─────────────────────────────────────────────────────────────────────────────
# Server
# ─────────────────────────────────────────────────────────────────────────────

class Server:
    def __init__(self, iface, listen_ip, tcp_port, udp_port):
        self.iface     = iface
        self.listen_ip = listen_ip
        self.tcp_port  = tcp_port
        self.udp_port  = udp_port
        self.my_mac    = get_if_hwaddr(iface)
        self.peer_mac  = None        # MAC of veth-mp-out; learned from ARP or first pkt
        self.flows     = {}          # (src_ip, sport) → flow state dict
        self.lock      = threading.Lock()
        self.pkt_count = 0
        self.dup_count = 0
        self.seen_udp  = set()

    def _send_tcp(self, dst_ip, sport, dport, seq, ack, flags, payload=b""):
        dst_mac = self.peer_mac or "ff:ff:ff:ff:ff:ff"
        pkt = (Ether(src=self.my_mac, dst=dst_mac) /
               IP(src=self.listen_ip, dst=dst_ip) /
               TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))
        if payload:
            pkt /= Raw(load=payload)
        sendp(pkt, iface=self.iface, verbose=False)

    def handle(self, pkt):
        if not (pkt.haslayer(Ether) and pkt.haslayer(IP)):
            return
        ip = pkt[IP]
        if ip.dst != self.listen_ip:
            return

        # Learn peer MAC from first arriving packet (MAC of veth-mp-out)
        if self.peer_mac is None:
            self.peer_mac = pkt[Ether].src
            log("server", f"peer MAC learned: {self.peer_mac}")

        if pkt.haslayer(TCP):
            self._tcp(ip, pkt[TCP])
        elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
            self._udp(ip, pkt[UDP], bytes(pkt[Raw]))

    def _tcp(self, ip, tcp):
        key   = (ip.src, tcp.sport)
        flags = int(tcp.flags)

        with self.lock:
            self.pkt_count += 1

            # RST: tear down any state
            if flags & F_RST:
                self.flows.pop(key, None)
                return

            # New SYN (no ACK)
            if (flags & F_SYN) and not (flags & F_ACK):
                srv_isn = 0x12345678
                self.flows[key] = {
                    'state':   'SYN_RCVD',
                    'cli_seq': tcp.seq + 1,
                    'srv_seq': srv_isn + 1,   # after SYNACK (SYN consumes 1)
                    'dport':   tcp.dport,
                }
                self._send_tcp(ip.src, sport=tcp.dport, dport=tcp.sport,
                               seq=srv_isn, ack=tcp.seq + 1, flags=F_SYN_ACK)
                log("server", f"SYNACK → {ip.src}:{tcp.sport}")
                return

            flow = self.flows.get(key)
            if flow is None:
                return

            state = flow['state']

            # SYN_RCVD → ESTABLISHED on ACK
            if state == 'SYN_RCVD' and (flags & F_ACK):
                flow['state'] = 'ESTABLISHED'
                state         = 'ESTABLISHED'
                log("server", f"established {ip.src}:{tcp.sport}")

            if state == 'ESTABLISHED':
                # Data packet
                if flags & F_PSH:
                    raw = bytes(tcp.payload) if tcp.payload else b""
                    if raw:
                        echo = b"ECHO:" + raw
                        flow['cli_seq'] = tcp.seq + len(raw)
                        self._send_tcp(ip.src,
                                       sport=flow['dport'], dport=tcp.sport,
                                       seq=flow['srv_seq'], ack=flow['cli_seq'],
                                       flags=F_PSH_ACK, payload=echo)
                        flow['srv_seq'] += len(echo)
                        log("server", f"echo {len(echo)}B → {ip.src}:{tcp.sport}")

                # FIN (may arrive alone or combined with data)
                if flags & F_FIN:
                    ack_val = tcp.seq + 1
                    self._send_tcp(ip.src,
                                   sport=flow['dport'], dport=tcp.sport,
                                   seq=flow['srv_seq'], ack=ack_val,
                                   flags=F_FIN_ACK)
                    log("server", f"FIN+ACK → {ip.src}:{tcp.sport}")
                    del self.flows[key]

    def _udp(self, ip, udp, raw):
        key = (ip.src, ip.dst, udp.sport, udp.dport, raw)
        with self.lock:
            self.pkt_count += 1
            if key in self.seen_udp:
                self.dup_count += 1
                log("server", f"!! DUP UDP {ip.src}:{udp.sport}")
            else:
                self.seen_udp.add(key)
                log("server", f"UDP {ip.src}:{udp.sport} len={len(raw)}")

    def stats(self):
        with self.lock:
            log("server",
                f"pkts={self.pkt_count}  dups={self.dup_count}  "
                f"dup_rate={self.dup_count / max(self.pkt_count, 1) * 100:.1f}%")


def run_server(args):
    srv = Server(args.iface, args.listen, args.tcp_port, args.udp_port)

    log("server", f"ARP resolving peer 10.0.5.1 on {args.iface} …")
    mac = resolve_peer_mac(args.iface, "10.0.5.1")
    if mac:
        srv.peer_mac = mac
        log("server", f"peer MAC = {mac}")
    else:
        log("server", "ARP failed - will learn MAC from first arriving packet")

    def _stats_loop():
        while True:
            time.sleep(10)
            srv.stats()

    threading.Thread(target=_stats_loop, daemon=True).start()

    log("server", f"listening on {args.iface} ({args.listen}) "
        f"tcp={args.tcp_port} udp={args.udp_port}")
    sniff(
        iface=args.iface,
        filter=(f"ip and "
                f"(tcp dst port {args.tcp_port} or udp dst port {args.udp_port})"),
        prn=srv.handle,
        store=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Multipoly pipeline traffic generator")
    p.add_argument("--role",     required=True, choices=["client", "server"])
    p.add_argument("--iface",    required=True)
    p.add_argument("--target",   default="10.0.5.2", help="client: server IP")
    p.add_argument("--listen",   default="10.0.5.2", help="server: listen IP")
    p.add_argument("--tcp-port", type=int, default=8080, dest="tcp_port")
    p.add_argument("--udp-port", type=int, default=9090, dest="udp_port")
    args = p.parse_args()

    if args.role == "client":
        run_client(args)
    else:
        run_server(args)


if __name__ == "__main__":
    main()
