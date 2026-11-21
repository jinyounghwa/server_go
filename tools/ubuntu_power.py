#!/usr/bin/env python3
"""Wake, check status, or safely power off the remote Ubuntu PC from macOS.

Config via env vars or local git-ignored file (.ubuntu_power.env):
  UBUNTU_MAC=aa:bb:cc:dd:ee:ff
  UBUNTU_HOST=192.168.0.105
  UBUNTU_SSH=ubuntu
  UBUNTU_BCAST=192.168.0.255

Usage:
  python3 tools/ubuntu_power.py status
  python3 tools/ubuntu_power.py wake [--wait] [--timeout 60]
  python3 tools/ubuntu_power.py off
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_local_env():
    env_file = ROOT / ".ubuntu_power.env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def tcp_open(host: str, port: int = 22, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def send_wol(mac: str, bcast: str):
    clean = mac.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(clean) != 12:
        sys.exit(f"Invalid MAC address: {mac}")
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for addr in {bcast, "255.255.255.255"}:
            for port in (9, 7):
                try:
                    s.sendto(packet, (addr, port))
                except OSError:
                    pass


def cmd_status(args):
    up = tcp_open(args.host, 22)
    print(f"{args.ssh} ({args.host}): {'ONLINE' if up else 'OFFLINE'}")
    sys.exit(0 if up else 1)


def cmd_wake(args):
    if not args.mac:
        sys.exit("UBUNTU_MAC is not set (pass --mac or put UBUNTU_MAC=... in .ubuntu_power.env)")
    if tcp_open(args.host, 22, timeout=1.0):
        print(f"{args.ssh} ({args.host}) is already ONLINE.")
        return
    print(f"Sending Wake-on-LAN magic packet to {args.mac} via {args.bcast}...")
    for _ in range(3):
        send_wol(args.mac, args.bcast)
        time.sleep(0.2)
    if not args.wait:
        print("Magic packet sent.")
        return
    t0 = time.monotonic()
    deadline = t0 + args.timeout
    while time.monotonic() < deadline:
        if tcp_open(args.host, 22, timeout=1.5):
            print(f"{args.ssh} ({args.host}) is ONLINE! ({time.monotonic() - t0:.1f}s)")
            return
        time.sleep(1.5)
    print(f"Timed out after {args.timeout}s waiting for {args.host}:22.", file=sys.stderr)
    sys.exit(1)


def cmd_off(args):
    if not tcp_open(args.host, 22, timeout=1.5):
        print(f"{args.ssh} ({args.host}) is already OFFLINE.")
        return
    cmd = 'pkill -f "target/[r]elease/rocalcloud$" || true; (systemctl poweroff || sudo -n poweroff)'
    r = subprocess.run(["ssh", args.ssh, cmd])
    if r.returncode == 0:
        print(f"Poweroff command sent to {args.ssh}.")
    else:
        sys.exit(r.returncode)


def main():
    load_local_env()
    ap = argparse.ArgumentParser(description="Remote power control (WoL / SSH poweroff) for Ubuntu PC")
    ap.add_argument("--mac", default=os.environ.get("UBUNTU_MAC", ""))
    ap.add_argument("--host", default=os.environ.get("UBUNTU_HOST", "192.168.0.105"))
    ap.add_argument("--ssh", default=os.environ.get("UBUNTU_SSH", "ubuntu"))
    ap.add_argument("--bcast", default=os.environ.get("UBUNTU_BCAST", "192.168.0.255"))
    sub = ap.add_subparsers(dest="action", required=True)

    p_st = sub.add_parser("status", help="Check if Ubuntu SSH port is reachable")
    p_st.set_defaults(func=cmd_status)

    p_wk = sub.add_parser("wake", help="Send Wake-on-LAN magic packet")
    p_wk.add_argument("--wait", action="store_true", help="Wait until SSH port comes up")
    p_wk.add_argument("--timeout", type=int, default=45, help="Wait timeout in seconds")
    p_wk.set_defaults(func=cmd_wake)

    p_off = sub.add_parser("off", help="Safely shut down Ubuntu via SSH")
    p_off.set_defaults(func=cmd_off)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
