#!/usr/bin/env python3
"""
throughput_iperf3.py — iperf3 UDP forward-only throughput benchmark.

Full pipeline (4 FWs, all XDP programs loaded):
  veth-client → bal_kern_ingress → LB(AF_XDP, 4× UDP copies)
              → FW bridges → con_kern_ingress (fast-path to veth-mp-out) → veth-server

Baseline (no AF_XDP, no XDP programs, kernel routing lb-in→mp-out directly):
  veth-client (ns-iperf-client) → veth-lb-in → kernel IP fwd
              → veth-mp-out → veth-server (ns-iperf-server)

Metric: veth-mp-out tx_bytes delta / elapsed.

Run with sudo on the host (not inside a container):
    cd final/docker
    sudo python3 tests/throughput_iperf3.py [--duration 30] [--bandwidth 1G]
"""

import argparse
import json
import subprocess
import sys
import time

CLIENT_IFACE = "veth-client"
SERVER_IFACE = "veth-server"
MPOUT_IFACE  = "veth-mp-out"
CLIENT_IP    = "10.0.0.1"
SERVER_IP    = "10.0.5.2"
LB_IN_IFACE  = "veth-lb-in"
IPERF_PORT   = 5201
NUM_FW       = 4
NS_CLIENT    = "ns-iperf-client"
NS_SERVER    = "ns-iperf-server"

_CLIENT_MAC: str = ""
_SERVER_MAC: str = ""


def _read_tx_bytes(iface: str) -> int:
    with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f:
        return int(f.read().strip())


def _mac(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def _run(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, **kw)


def _nsrun(ns: str, *cmd) -> None:
    subprocess.run(["ip", "netns", "exec", ns] + list(cmd),
                   check=True, capture_output=True)


# ── Network namespace setup/teardown ───────────────────────────────────────────

def _setup_test_ns() -> None:
    global _CLIENT_MAC, _SERVER_MAC

    # Recover stale namespaces left by a previous interrupted run.
    existing = subprocess.run(["ip", "netns", "list"],
                              capture_output=True, text=True).stdout
    if NS_CLIENT in existing:
        subprocess.run(["ip", "netns", "exec", NS_CLIENT,
                        "ip", "link", "set", CLIENT_IFACE, "netns", "1"],
                       capture_output=True)
        subprocess.run(["ip", "netns", "del", NS_CLIENT], capture_output=True)
        subprocess.run(["ip", "link", "set", CLIENT_IFACE, "up"], capture_output=True)
    if NS_SERVER in existing:
        subprocess.run(["ip", "netns", "exec", NS_SERVER,
                        "ip", "link", "set", SERVER_IFACE, "netns", "1"],
                       capture_output=True)
        subprocess.run(["ip", "netns", "del", NS_SERVER], capture_output=True)
        subprocess.run(["ip", "link", "set", SERVER_IFACE, "up"], capture_output=True)

    _CLIENT_MAC = _mac(CLIENT_IFACE)
    _SERVER_MAC = _mac(SERVER_IFACE)
    lb_in_mac   = _mac(LB_IN_IFACE)
    mp_out_mac  = _mac(MPOUT_IFACE)

    subprocess.run(["ip", "addr", "replace", "10.0.5.1/30", "dev", MPOUT_IFACE],
                   check=True)

    # Docker sets FORWARD policy to DROP; these rules allow the baseline return path.
    subprocess.run(["iptables", "-I", "FORWARD",
                    "-i", LB_IN_IFACE, "-o", MPOUT_IFACE, "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-I", "FORWARD",
                    "-i", MPOUT_IFACE, "-o", LB_IN_IFACE, "-j", "ACCEPT"], check=True)

    subprocess.run(["ip", "neigh", "replace", CLIENT_IP,
                    "lladdr", _CLIENT_MAC, "nud", "permanent", "dev", LB_IN_IFACE],
                   check=True)

    subprocess.run(["ip", "netns", "add", NS_CLIENT], check=True)
    subprocess.run(["ip", "link", "set", CLIENT_IFACE, "netns", NS_CLIENT], check=True)
    _nsrun(NS_CLIENT, "ip", "link", "set", CLIENT_IFACE, "up")
    _nsrun(NS_CLIENT, "ip", "addr", "add", f"{CLIENT_IP}/30", "dev", CLIENT_IFACE)
    _nsrun(NS_CLIENT, "ip", "route", "add", "10.0.5.0/30", "via", "10.0.0.2")
    _nsrun(NS_CLIENT, "ip", "neigh", "replace", "10.0.0.2",
           "lladdr", lb_in_mac, "nud", "permanent", "dev", CLIENT_IFACE)

    subprocess.run(["ip", "netns", "add", NS_SERVER], check=True)
    subprocess.run(["ip", "link", "set", SERVER_IFACE, "netns", NS_SERVER], check=True)
    _nsrun(NS_SERVER, "ip", "link", "set", SERVER_IFACE, "up")
    _nsrun(NS_SERVER, "ip", "addr", "add", f"{SERVER_IP}/30", "dev", SERVER_IFACE)
    _nsrun(NS_SERVER, "ip", "route", "add", "10.0.0.0/30", "via", "10.0.5.1")
    _nsrun(NS_SERVER, "ip", "neigh", "replace", "10.0.5.1",
           "lladdr", mp_out_mac, "nud", "permanent", "dev", SERVER_IFACE)

    # Re-add connected route purged when veth-server left the host namespace.
    subprocess.run(["ip", "addr", "replace", "10.0.5.1/30", "dev", MPOUT_IFACE], check=True)
    subprocess.run(["ip", "route", "replace", "10.0.5.0/30", "dev", MPOUT_IFACE],
                   capture_output=True)
    print(f"  Test namespaces ready "
          f"({CLIENT_IFACE}→{NS_CLIENT}, {SERVER_IFACE}→{NS_SERVER})", flush=True)


def _teardown_test_ns() -> None:
    subprocess.run(["iptables", "-D", "FORWARD",
                    "-i", LB_IN_IFACE, "-o", MPOUT_IFACE, "-j", "ACCEPT"],
                   capture_output=True)
    subprocess.run(["iptables", "-D", "FORWARD",
                    "-i", MPOUT_IFACE, "-o", LB_IN_IFACE, "-j", "ACCEPT"],
                   capture_output=True)

    _nsrun(NS_SERVER, "ip", "link", "set", SERVER_IFACE, "netns", "1")
    subprocess.run(["ip", "link", "set", SERVER_IFACE, "up"], capture_output=True)
    subprocess.run(["ip", "addr", "replace", f"{SERVER_IP}/30", "dev", SERVER_IFACE],
                   capture_output=True)
    subprocess.run(["ip", "neigh", "replace", "10.0.5.1",
                    "lladdr", _mac(MPOUT_IFACE), "nud", "permanent",
                    "dev", SERVER_IFACE], capture_output=True)
    _run("ip", "netns", "del", NS_SERVER)

    _nsrun(NS_CLIENT, "ip", "link", "set", CLIENT_IFACE, "netns", "1")
    subprocess.run(["ip", "link", "set", CLIENT_IFACE, "up"], capture_output=True)
    subprocess.run(["ip", "addr", "replace", f"{CLIENT_IP}/30", "dev", CLIENT_IFACE],
                   capture_output=True)
    subprocess.run(["ip", "route", "replace", "10.0.5.0/30",
                    "via", "10.0.0.2", "dev", CLIENT_IFACE], capture_output=True)
    subprocess.run(["ip", "neigh", "replace", "10.0.0.2",
                    "lladdr", _mac(LB_IN_IFACE), "nud", "permanent",
                    "dev", CLIENT_IFACE], capture_output=True)
    subprocess.run(["ip", "neigh", "del", CLIENT_IP, "dev", LB_IN_IFACE],
                   capture_output=True)
    _run("ip", "netns", "del", NS_CLIENT)
    print("  Test namespaces torn down", flush=True)


# ── iperf3 helpers ─────────────────────────────────────────────────────────────

def _iperf3_server_bg() -> subprocess.Popen:
    _run("pkill", "-9", "iperf3")
    time.sleep(1.0)
    return subprocess.Popen(
        ["ip", "netns", "exec", NS_SERVER,
         "iperf3", "-s", "-B", SERVER_IP, "-p", str(IPERF_PORT), "--one-off"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )


def _iperf3_client(duration: int, bandwidth: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ip", "netns", "exec", NS_CLIENT,
         "iperf3", "-c", SERVER_IP, "-B", CLIENT_IP,
         "-p", str(IPERF_PORT),
         "-u", "-b", bandwidth,
         "-l", "1400",
         "-t", str(duration),
         "-J"],
        capture_output=True, text=True,
        timeout=duration + 60,
    )


# ── Measurement ────────────────────────────────────────────────────────────────

TCPDUMP_IFACES = [
    ("veth-lb-in",             [],                                    LB_IN_IFACE),
    ("veth-mp-out",            [],                                    MPOUT_IFACE),
    ("ns-client/veth-client",  ["ip", "netns", "exec", NS_CLIENT],   CLIENT_IFACE),
    ("ns-server/veth-server",  ["ip", "netns", "exec", NS_SERVER],   SERVER_IFACE),
]


def _start_tcpdumps() -> list:
    procs = []
    for label, prefix, iface in TCPDUMP_IFACES:
        cmd = prefix + ["tcpdump", "-n", "-v", "-l", "--immediate-mode",
                        "-i", iface, "tcp", "port", str(IPERF_PORT)]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        procs.append((label, p))
        print(f"  [tcpdump] capturing on {label}", flush=True)
    return procs


def _stop_print_tcpdumps(procs: list) -> None:
    for label, p in procs:
        try:
            p.terminate()
            out, _ = p.communicate(timeout=3)
        except Exception:
            out = ""
        print(f"\n  --- tcpdump {label} ---", flush=True)
        print((out or "  (no output)")[:4000], flush=True)


def measure_throughput(duration: int, bandwidth: str, debug: bool = False) -> float:
    """Return forward throughput in Mbps (veth-mp-out tx_bytes / elapsed)."""
    srv = _iperf3_server_bg()
    time.sleep(2.0)

    if srv.poll() is not None:
        srv_err = srv.stderr.read() if srv.stderr else b""
        print(f"  ERROR: iperf3 server exited immediately (rc={srv.returncode}): "
              f"{srv_err.decode(errors='replace').strip()[:200]}", file=sys.stderr)
        return 0.0

    td_procs  = _start_tcpdumps() if debug else []
    tx_before = _read_tx_bytes(MPOUT_IFACE)
    t_start   = time.time()
    elapsed   = float(duration)
    iperf_mbps = None

    try:
        r = _iperf3_client(duration, bandwidth)
        elapsed = time.time() - t_start
        if r.returncode == 0:
            try:
                bits = json.loads(r.stdout)["end"]["sum"]["bits_per_second"]
                iperf_mbps = bits / 1e6
            except (json.JSONDecodeError, KeyError):
                pass
        else:
            print(f"  WARN: iperf3 client exited {r.returncode}: "
                  f"{r.stderr.strip()[:200]}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t_start
        print("  WARN: iperf3 client timed out", file=sys.stderr)
        _run("pkill", "-9", "iperf3")

    try:
        srv.kill()
        srv.wait(timeout=5)
    except Exception:
        pass

    if debug:
        _stop_print_tcpdumps(td_procs)

    if srv.stderr:
        try:
            srv_err = srv.stderr.read().decode(errors="replace").strip()
            if srv_err:
                print(f"  iperf3 server stderr: {srv_err[:300]}", file=sys.stderr, flush=True)
        except Exception:
            pass

    fwd_mbps = (_read_tx_bytes(MPOUT_IFACE) - tx_before) * 8 / elapsed / 1e6
    if iperf_mbps is not None:
        print(f"      fwd_bytes={fwd_mbps:.1f} Mbps  "
              f"iperf3_sender={iperf_mbps:.1f} Mbps  "
              f"elapsed={elapsed:.1f} s", flush=True)
    else:
        print(f"      fwd_bytes={fwd_mbps:.1f} Mbps  "
              f"iperf3=n/a  elapsed={elapsed:.1f} s", flush=True)
    return fwd_mbps


# ── Baseline helpers ───────────────────────────────────────────────────────────

def _baseline_setup() -> None:
    """Stop LB+controller, unload all XDP, use direct kernel forwarding."""
    # Unload XDP via xdp-loader while containers are still alive so that the
    # libxdp dispatcher is removed cleanly.  ip-link xdpgeneric off can fail
    # silently when the container was SIGKILLed and left stale BPF state.
    lb_ifaces  = "veth-lb-in " + " ".join(f"veth-lb-fw{i}" for i in range(NUM_FW))
    con_ifaces = " ".join(f"veth-mp-fw{i}" for i in range(NUM_FW)) + " veth-mp-out"
    _run("docker", "exec", "load_balancer",
         "sh", "-c",
         f"for iface in {lb_ifaces}; do xdp-loader unload $iface --all 2>/dev/null || true; done")
    _run("docker", "exec", "controller",
         "sh", "-c",
         f"for iface in {con_ifaces}; do xdp-loader unload $iface --all 2>/dev/null || true; done")

    _run("docker", "compose", "stop", "load_balancer", "controller")
    time.sleep(1)   # allow AF_XDP sockets to close before kernel forwarding starts

    subprocess.run(["sysctl", "-qw", "net.ipv4.ip_forward=1"], capture_output=True)
    subprocess.run(["ip", "addr", "replace", "10.0.5.1/30", "dev", MPOUT_IFACE],
                   capture_output=True)
    subprocess.run(["ip", "route", "replace", "10.0.5.0/30", "dev", MPOUT_IFACE],
                   capture_output=True)
    subprocess.run(["ip", "neigh", "replace", SERVER_IP,
                    "lladdr", _SERVER_MAC, "nud", "permanent", "dev", MPOUT_IFACE],
                   capture_output=True)


def wait_lb_healthy(timeout: int = 90) -> None:
    print(f"  Waiting for load_balancer healthy (max {timeout} s) ...", flush=True)
    for _ in range(timeout):
        r = subprocess.run(
            ["docker", "inspect", "--format={{.State.Health.Status}}", "load_balancer"],
            capture_output=True, text=True)
        if r.stdout.strip() == "healthy":
            return
        time.sleep(1)
    sys.exit("ERROR: load_balancer did not become healthy within 90 s")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="iperf3 UDP forward-only throughput: 4-FW pipeline vs bare-metal baseline")
    ap.add_argument("--duration",  type=int, default=30,
                    help="iperf3 test duration in seconds (default: 30)")
    ap.add_argument("--bandwidth", default="1G",
                    help="iperf3 UDP target bandwidth, e.g. 100M, 1G, 10G (default: 1G)")
    ap.add_argument("--debug", action="store_true",
                    help="capture TCP port 5201 on four interfaces and print after each run")
    args = ap.parse_args()

    print("=== iperf3 UDP forward-only throughput benchmark ===")
    print(f"    duration  : {args.duration} s")
    print(f"    bandwidth : {args.bandwidth}")
    print()

    wait_lb_healthy()
    _run("docker", "compose", "stop", "client", "server")
    _setup_test_ns()

    try:
        print("[1/2] Full pipeline  (4 FWs, LB+controller+XDP) ...", flush=True)
        mbps_full = measure_throughput(args.duration, args.bandwidth, args.debug)

        print("[2/2] Baseline  (kernel IP forwarding, no XDP) ...", flush=True)
        _baseline_setup()
        mbps_base = measure_throughput(args.duration, args.bandwidth, args.debug)
        _run("ip", "neigh", "del", SERVER_IP, "dev", MPOUT_IFACE)

    finally:
        _teardown_test_ns()

    _run("docker", "compose", "up", "-d")

    ratio    = (mbps_full / mbps_base) if mbps_base else 0.0
    overhead = (1.0 - ratio) * 100.0
    sep = "=" * 60
    print()
    print(sep)
    print(f"  {'Baseline  (kernel IP forwarding, no XDP)':<40} {mbps_base:>8.1f}  Mbps")
    print(f"  {'Pipeline  (4-FW, LB+controller+XDP)':<40} {mbps_full:>8.1f}  Mbps")
    print(f"  {'Throughput ratio  (pipeline / baseline)':<40} {ratio:>9.3f}")
    print(f"  {'Polymorphism overhead':<40} {overhead:>8.1f}  %")
    print(sep)


if __name__ == "__main__":
    main()
