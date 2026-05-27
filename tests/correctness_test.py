#!/usr/bin/env python3
"""
correctness_test.py
Correctness tests for the firewall-polymorphism pipeline.

The script runs as a privileged container (--network host) and acts as
both client (veth-client / 10.0.0.1) and server (veth-server / 10.0.5.2).
Stop the traffic-gen client and server containers before running this.

Usage:
    ./run_tests.sh

Available tests:
    tcp_dedup       Server receives each TCP packet at most once
    udp_dedup       Server receives each UDP datagram at most once
    session         Full SYN→data→echo→FIN cycle completes for every flow
    voting_fw0      With fw0 blackholed, nothing reaches the server
    voting_fw3      With fw3 blackholed, nothing reaches the server
    affinity        Full-payload copy of each 4-tuple seen on exactly one fw→mp interface
"""

import argparse
import queue
import subprocess
import sys
import threading
import time

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, Raw,
        conf, get_if_hwaddr, sendp, sniff, srp,
    )
    conf.verb = 0
except ImportError:
    print("scapy not available — install python3-scapy", file=sys.stderr)
    sys.exit(1)

# ── Topology constants ─────────────────────────────────────────────────────────
CLIENT_IFACE = "veth-client"
SERVER_IFACE = "veth-server"
CLIENT_IP    = "10.0.0.1"
LB_IP        = "10.0.0.2"   # load_balancer's client-side IP; ARP target for client
MP_IP        = "10.0.5.1"   # controller's server-side IP; ARP target for server
SERVER_IP    = "10.0.5.2"
TCP_PORT     = 8080
UDP_PORT     = 9090

# TCP flag bitmasks
F_FIN     = 0x01
F_SYN     = 0x02
F_RST     = 0x04
F_PSH     = 0x08
F_ACK     = 0x10
F_SYN_ACK = F_SYN | F_ACK
F_PSH_ACK = F_PSH | F_ACK
F_FIN_ACK = F_FIN | F_ACK

# ── Colour output ──────────────────────────────────────────────────────────────
_GREEN = "\033[32m"
_RED   = "\033[31m"
_RESET = "\033[0m"
PASS   = f"{_GREEN}PASS{_RESET}"
FAIL   = f"{_RED}FAIL{_RESET}"

_results: list[tuple[str, bool, str]] = []


def log(tag: str, msg: str) -> None:
    print(f"  [{tag}] {msg}", flush=True)


def record(name: str, ok: bool, detail: str = "") -> None:
    status = PASS if ok else FAIL
    suffix = f"  ({detail})" if detail else ""
    print(f"  {status}  {name}{suffix}", flush=True)
    _results.append((name, ok, detail))


# ── MAC resolution ─────────────────────────────────────────────────────────────

def resolve_mac(iface: str, ip: str, retries: int = 10) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "neigh", "show", ip, "dev", iface],
            text=True, stderr=subprocess.DEVNULL,
        )
        for token in out.split():
            if len(token) == 17 and token.count(":") == 5:
                return token
    except Exception:
        pass

    for _ in range(retries):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=iface, timeout=1, verbose=False,
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        time.sleep(0.5)
    log("warn", f"ARP for {ip} on {iface} failed — using broadcast")
    return "ff:ff:ff:ff:ff:ff"


# ── tc helpers ─────────────────────────────────────────────────────────────────

def _tc(*args: str) -> None:
    subprocess.run(["tc", *args], check=True, capture_output=True)


def blackhole_fw_to_mp(fw_id: int) -> None:
    """
    Drop all traffic on veth-fw{N}-mp EGRESS (the firewall-side of the
    fw→controller veth pair).
    Blocking egress on the FW side runs before the packet enters the veth
    pair, so it is not affected by any XDP program on the controller side.
    """
    iface = f"veth-fw{fw_id}-mp"
    try:
        _tc("qdisc", "del", "dev", iface, "root")
    except subprocess.CalledProcessError:
        pass
    _tc("qdisc", "add", "dev", iface, "root", "handle", "1:", "prio")
    _tc("filter", "add", "dev", iface, "parent", "1:",
        "matchall", "action", "drop")
    log("tc", f"blackholed {iface} egress (fw{fw_id} → controller path)")


def restore_fw_to_mp(fw_id: int) -> None:
    iface = f"veth-fw{fw_id}-mp"
    try:
        _tc("qdisc", "del", "dev", iface, "root")
    except subprocess.CalledProcessError:
        pass
    log("tc", f"restored {iface}")


# ── Embedded server (runs on veth-server) ─────────────────────────────────────

class EmbeddedServer:
    """
    Listens on SERVER_IFACE for TCP and UDP traffic destined to SERVER_IP.
    Responds to TCP handshakes and echoes data.  Tracks duplicate detection.
    """

    def __init__(self) -> None:
        self._lock        = threading.Lock()
        self.my_mac       = get_if_hwaddr(SERVER_IFACE)
        self.peer_mac: str | None = None      # learned from first arriving frame

        # dedup tracking
        self._seen_tcp: dict[tuple, int] = {}  # (src_ip, sport, seq, flags) → count
        self.tcp_dup_count   = 0
        self._seen_udp: dict[bytes, int] = {}  # payload → count
        self.udp_dup_count   = 0

        # per-flow state for TCP
        self._flows: dict[tuple, dict] = {}    # (src_ip, sport) → state
        self.completed_flows  = 0              # flows that went SYN→echo→FIN

        self._stop      = threading.Event()
        self._pkt_count = 0   # total unique TCP packets received (lock-protected)

    def tcp_packet_count(self) -> int:
        with self._lock:
            return self._pkt_count

    # ── sending helpers ──────────────────────────────────────────────────────

    def _dst_mac(self) -> str:
        return self.peer_mac or "ff:ff:ff:ff:ff:ff"

    def _send_tcp(self, dst_ip: str, sport: int, dport: int,
                  seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        p = (Ether(src=self.my_mac, dst=self._dst_mac()) /
             IP(src=SERVER_IP, dst=dst_ip) /
             TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags))
        if payload:
            p /= Raw(load=payload)
        sendp(p, iface=SERVER_IFACE, verbose=False)

    # ── packet handler ───────────────────────────────────────────────────────

    def handle(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        if ip.dst != SERVER_IP:
            return

        if self.peer_mac is None and pkt.haslayer(Ether):
            self.peer_mac = pkt[Ether].src

        if pkt.haslayer(TCP):
            self._handle_tcp(ip, pkt[TCP])
        elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
            self._handle_udp(bytes(pkt[Raw]))

    def _handle_tcp(self, ip, tcp) -> None:
        dup_key = (ip.src, tcp.sport, tcp.seq, int(tcp.flags))
        flags   = int(tcp.flags)
        fkey    = (ip.src, tcp.sport)

        with self._lock:
            cnt = self._seen_tcp.get(dup_key, 0)
            self._seen_tcp[dup_key] = cnt + 1
            if cnt > 0:
                self.tcp_dup_count += 1
                return   # ignore duplicate; state machine stays clean
            self._pkt_count += 1

            if flags & F_RST:
                self._flows.pop(fkey, None)
                return

            # New SYN
            if (flags & F_SYN) and not (flags & F_ACK):
                srv_isn = 0xABCD1234
                self._flows[fkey] = {
                    "state":   "SYN_RCVD",
                    "cli_seq": tcp.seq + 1,
                    "srv_seq": srv_isn + 1,
                    "dport":   tcp.dport,
                    "echo_ok": False,
                }
                self._send_tcp(ip.src, sport=tcp.dport, dport=tcp.sport,
                               seq=srv_isn, ack=tcp.seq + 1, flags=F_SYN_ACK)
                return

            flow = self._flows.get(fkey)
            if flow is None:
                return

            if flow["state"] == "SYN_RCVD" and (flags & F_ACK):
                flow["state"] = "ESTABLISHED"

            if flow["state"] == "ESTABLISHED":
                if flags & F_PSH:
                    raw = bytes(tcp.payload) if tcp.payload else b""
                    if raw:
                        echo = b"ECHO:" + raw
                        self._send_tcp(ip.src,
                                       sport=flow["dport"], dport=tcp.sport,
                                       seq=flow["srv_seq"],
                                       ack=flow["cli_seq"] + len(raw),
                                       flags=F_PSH_ACK, payload=echo)
                        flow["srv_seq"] += len(echo)
                        flow["cli_seq"] += len(raw)
                        flow["echo_ok"] = True

                if flags & F_FIN:
                    ack_val = tcp.seq + 1
                    self._send_tcp(ip.src,
                                   sport=flow["dport"], dport=tcp.sport,
                                   seq=flow["srv_seq"], ack=ack_val,
                                   flags=F_FIN_ACK)
                    if flow["echo_ok"]:
                        self.completed_flows += 1
                    self._flows.pop(fkey, None)

    def _handle_udp(self, payload: bytes) -> None:
        with self._lock:
            cnt = self._seen_udp.get(payload, 0)
            self._seen_udp[payload] = cnt + 1
            if cnt > 0:
                self.udp_dup_count += 1

    # ── lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        sniff(
            iface=SERVER_IFACE,
            filter=(f"ip and dst host {SERVER_IP} and "
                    f"(tcp dst port {TCP_PORT} or udp dst port {UDP_PORT})"),
            prn=self.handle,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def stop(self) -> None:
        self._stop.set()


# ── Client ─────────────────────────────────────────────────────────────────────

class Client:
    def __init__(self, gw_mac: str) -> None:
        self.my_mac  = get_if_hwaddr(CLIENT_IFACE)
        self.gw_mac  = gw_mac
        self._queues: dict[int, queue.Queue] = {}
        self._lock   = threading.Lock()
        self._start_sniffer()

    def _start_sniffer(self) -> None:
        def cb(pkt):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            if pkt[IP].src != SERVER_IP:
                return
            dport = pkt[TCP].dport
            with self._lock:
                q = self._queues.get(dport)
            if q:
                q.put(pkt)

        threading.Thread(
            target=lambda: sniff(
                iface=CLIENT_IFACE,
                filter=f"ip and src host {SERVER_IP} and tcp",
                prn=cb, store=False,
            ),
            daemon=True,
        ).start()

    def _send(self, sport: int, seq: int, ack: int,
              flags: int, payload: bytes = b"") -> None:
        p = (Ether(src=self.my_mac, dst=self.gw_mac) /
             IP(src=CLIENT_IP, dst=SERVER_IP) /
             TCP(sport=sport, dport=TCP_PORT, seq=seq, ack=ack, flags=flags))
        if payload:
            p /= Raw(load=payload)
        sendp(p, iface=CLIENT_IFACE, verbose=False)

    def send_udp(self, sport: int, payload: bytes) -> None:
        sendp(
            Ether(src=self.my_mac, dst=self.gw_mac) /
            IP(src=CLIENT_IP, dst=SERVER_IP) /
            UDP(sport=sport, dport=UDP_PORT) /
            Raw(load=payload),
            iface=CLIENT_IFACE, verbose=False,
        )

    def _wait(self, q: queue.Queue, flag_mask: int,
              timeout: float = 5.0):
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

    def run_flow(self, sport: int, payload: bytes = b"HELLO",
                 timeout: float = 5.0) -> tuple[bool, bool]:
        """
        Run a complete TCP flow: SYN → SYNACK → ACK → PSH → echo → FIN+ACK.
        Returns (got_echo, got_server_fin).
        """
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._queues[sport] = q

        try:
            isn = sport * 1000
            self._send(sport, isn, 0, F_SYN)

            sa = self._wait(q, F_SYN_ACK, timeout)
            if sa is None:
                return False, False
            srv_isn = sa[TCP].seq
            cli_seq = isn + 1
            srv_seq = srv_isn + 1

            self._send(sport, cli_seq, srv_seq, F_ACK)
            time.sleep(0.02)

            self._send(sport, cli_seq, srv_seq, F_PSH_ACK, payload)

            resp = self._wait(q, F_PSH, timeout)
            got_echo = resp is not None
            if got_echo:
                echo    = bytes(resp[TCP].payload) if resp[TCP].payload else b""
                cli_seq += len(payload)
                srv_seq += len(echo)
                self._send(sport, cli_seq, srv_seq, F_ACK)

            time.sleep(0.02)
            self._send(sport, cli_seq, srv_seq, F_FIN_ACK)

            fin = self._wait(q, F_FIN_ACK, timeout)
            got_fin = fin is not None
            if got_fin:
                self._send(sport, cli_seq + 1, fin[TCP].seq + 1, F_ACK)

            return got_echo, got_fin

        finally:
            time.sleep(0.05)
            with self._lock:
                self._queues.pop(sport, None)

    def send_syn_only(self, sport: int) -> None:
        """Send a single SYN with no expectation of a reply."""
        isn = sport * 1000
        self._send(sport, isn, 0, F_SYN)


# ── Individual tests ───────────────────────────────────────────────────────────

def test_tcp_dedup(client: Client, server: EmbeddedServer, n: int = 20) -> None:
    log("tcp_dedup", f"sending {n} TCP flows")
    before = server.tcp_dup_count

    for i in range(n):
        client.run_flow(20000 + i, payload=f"FLOW-{i}".encode())
        time.sleep(0.05)

    time.sleep(0.3)
    delta = server.tcp_dup_count - before
    record("tcp_dedup", delta == 0, f"dup_count={delta}")


def test_udp_dedup(client: Client, server: EmbeddedServer, n: int = 20) -> None:
    log("udp_dedup", f"sending {n} UDP datagrams")
    before = server.udp_dup_count

    for i in range(n):
        client.send_udp(30000 + i, f"UDP-UNIQUE-{i:04d}".encode())
        time.sleep(0.05)

    time.sleep(0.3)
    delta = server.udp_dup_count - before
    record("udp_dedup", delta == 0, f"dup_count={delta}")


def test_session_integrity(client: Client, server: EmbeddedServer,
                           n: int = 10) -> None:
    log("session", f"running {n} full TCP flows")
    echo_ok = fin_ok = 0

    for i in range(n):
        got_echo, got_fin = client.run_flow(40000 + i,
                                            payload=f"DATA-{i}".encode())
        echo_ok += int(got_echo)
        fin_ok  += int(got_fin)
        time.sleep(0.1)

    record("session_echo", echo_ok == n, f"{echo_ok}/{n} flows got echo")
    record("session_fin",  fin_ok  == n, f"{fin_ok}/{n} flows completed FIN")


def test_voting(client: Client, server: EmbeddedServer,
                fw_id: int, n: int = 4) -> None:
    """
    Blackhole fw{fw_id}→controller path.  No packet should reach the server
    because the vote threshold (all alive firewalls) is no longer reachable.

    The total blackhole window is kept short (~1 s) so the heartbeat timeout
    (typically several seconds) does not fire and lower the threshold before
    the test completes.  If your heartbeat timeout is configured below 1 s,
    reduce n or the inter-packet delay accordingly.
    """
    log(f"voting_fw{fw_id}", f"blackholing fw{fw_id}→mp, sending {n} SYNs")
    blackhole_fw_to_mp(fw_id)
    time.sleep(0.1)

    before = server.tcp_packet_count()

    for i in range(n):
        client.send_syn_only(50000 + fw_id * 100 + i)
        time.sleep(0.15)

    time.sleep(0.3)
    new_pkts = server.tcp_packet_count() - before

    restore_fw_to_mp(fw_id)
    time.sleep(1.0)   # let pipeline recover before next test

    record(f"voting_fw{fw_id}", new_pkts == 0,
           f"{new_pkts} packets reached server (expected 0)")


def test_flow_affinity(client: Client, n_flows: int = 8) -> None:
    """
    Each distinct 4-tuple must have its FULL-PAYLOAD copy on exactly one
    fw→mp interface.  Header-only copies on multiple interfaces are expected
    (the LB sends header-only voting copies to all non-primary firewalls).
    A violation means the LB sent a full-payload copy to more than one
    firewall, breaking the primary-selection invariant.
    """
    log("affinity", f"sniffing fw→mp interfaces during {n_flows} flows")
    full_payload: dict[tuple, set[str]] = {}
    seen_lock = threading.Lock()
    sniffers_ready = threading.Barrier(5)   # 4 sniffers + 1 main thread

    def make_sniffer(iface: str) -> None:
        def cb(pkt):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            tcp = pkt[TCP]
            payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
            if payload_len == 0:
                return  # header-only copy — expected on non-primary interfaces
            key = (pkt[IP].src, tcp.sport, pkt[IP].dst, tcp.dport)
            with seen_lock:
                full_payload.setdefault(key, set()).add(iface)

        sniffers_ready.wait()
        sniff(iface=iface, filter="tcp", prn=cb, store=False, timeout=7)

    for fw in range(4):
        threading.Thread(target=make_sniffer,
                         args=(f"veth-fw{fw}-mp",),
                         daemon=True).start()

    sniffers_ready.wait()   # release all sniffers simultaneously
    time.sleep(0.2)         # sniffer warm-up

    for i in range(n_flows):
        client.run_flow(60000 + i, payload=f"AFF-{i}".encode())
        time.sleep(0.2)

    time.sleep(1.5)         # let sniffers capture trailing packets

    violations = [
        (key, ifaces) for key, ifaces in full_payload.items()
        if len(ifaces) > 1
    ]
    for key, ifaces in violations:
        log("affinity", f"VIOLATION {key} on {sorted(ifaces)}")

    record("flow_affinity", len(violations) == 0,
           f"{len(violations)} 4-tuples with full payload on multiple interfaces")


# ── Entry point ────────────────────────────────────────────────────────────────

ALL_TESTS = {
    "tcp_dedup": "Server receives each TCP packet at most once",
    "udp_dedup": "Server receives each UDP datagram at most once",
    "session":   "Full SYN→data→echo→FIN cycle for every flow",
    "voting_fw0": "With fw0 blackholed, nothing reaches the server",
    "voting_fw3": "With fw3 blackholed, nothing reaches the server",
    "affinity":   "Full-payload copy of each 4-tuple on exactly one fw→mp interface",
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", metavar="NAME",
                    help="Run only this test (default: all)")
    ap.add_argument("--list", action="store_true",
                    help="List available tests and exit")
    args = ap.parse_args()

    if args.list:
        for name, desc in ALL_TESTS.items():
            print(f"  {name:15s}  {desc}")
        return

    if args.test and args.test not in ALL_TESTS:
        print(f"Unknown test: {args.test}", file=sys.stderr)
        print(f"Available: {', '.join(ALL_TESTS)}", file=sys.stderr)
        sys.exit(1)

    to_run = [args.test] if args.test else list(ALL_TESTS)

    print("=" * 64)
    print("  Firewall-Polymorphism Correctness Tests")
    print("=" * 64)

    log("setup", f"ARP resolving gateway {LB_IP} on {CLIENT_IFACE} …")
    gw_mac = resolve_mac(CLIENT_IFACE, LB_IP)
    log("setup", f"gateway MAC = {gw_mac}")

    log("setup", f"ARP resolving server-side peer {MP_IP} on {SERVER_IFACE} …")
    srv_peer_mac = resolve_mac(SERVER_IFACE, MP_IP)
    log("setup", f"server peer MAC = {srv_peer_mac}")

    server = EmbeddedServer()
    server.peer_mac = srv_peer_mac
    server.start()
    time.sleep(0.3)

    client = Client(gw_mac)
    time.sleep(0.3)

    dispatch = {
        "tcp_dedup":   lambda: test_tcp_dedup(client, server),
        "udp_dedup":   lambda: test_udp_dedup(client, server),
        "session":     lambda: test_session_integrity(client, server),
        "voting_fw0":  lambda: test_voting(client, server, fw_id=0),
        "voting_fw3":  lambda: test_voting(client, server, fw_id=3),
        "affinity":    lambda: test_flow_affinity(client),
    }

    for name in to_run:
        print(f"\n── {name} {'─' * (56 - len(name))}")
        try:
            dispatch[name]()
        except Exception as exc:
            record(name, False, f"exception: {exc}")

    server.stop()

    print("\n" + "=" * 64)
    passed = sum(1 for _, ok, _ in _results if ok)
    total  = len(_results)
    overall = PASS if passed == total else FAIL
    print(f"  {overall}  {passed}/{total} checks passed")
    print("=" * 64)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
