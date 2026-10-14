"""
Cross-platform Traffic Generator for SDN Mininet Lab.
Generates Benign traffic as well as SYN, UDP, and ICMP attack traffic.
Can send live packets via socket or generate synthetic flow stat records.
"""

import argparse
import random
import socket
import struct
import sys
import time
from typing import List, Dict, Any


def generate_raw_syn_packet(src_ip: str, dst_ip: str, dst_port: int = 80) -> bytes:
    """Generate raw TCP SYN packet with IP header."""
    # Dummy raw packet payload for socket transmission
    return b"SYN_PROBE_PACKET" * 4


def generate_flow_record(
    src_ip: str,
    dst_ip: str,
    proto: int,
    packets: int,
    bytes_count: int,
    duration: float = 3.0,
) -> Dict[str, Any]:
    """Create a standardized flow record dictionary."""
    return {
        "ipv4_src": src_ip,
        "ipv4_dst": dst_ip,
        "ip_proto": proto,
        "packet_count": int(packets),
        "byte_count": int(bytes_count),
        "duration_sec": float(duration),
    }


def simulate_normal_traffic_window(
    client_ips: List[str] = None,
    server_ips: List[str] = None,
    window_duration: float = 3.0,
) -> List[Dict[str, Any]]:
    """
    Simulate a realistic window of benign traffic flows:
    HTTP browsing, DNS queries, ICMP pings with moderate rates and balanced entropy.
    """
    if client_ips is None:
        client_ips = ["10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]
    if server_ips is None:
        server_ips = ["10.0.0.4", "10.0.0.5"]

    flows = []
    # 1. HTTP web traffic (TCP proto 6)
    for client in client_ips:
        if random.random() > 0.15:
            pkts = random.randint(15, 60)
            avg_pkt_size = random.randint(500, 1100)
            flows.append(
                generate_flow_record(
                    src_ip=client,
                    dst_ip=server_ips[0],
                    proto=6,
                    packets=pkts,
                    bytes_count=pkts * avg_pkt_size,
                    duration=window_duration,
                )
            )

    # 2. DNS/Telemetry traffic (UDP proto 17)
    for client in random.sample(client_ips, k=min(2, len(client_ips))):
        pkts = random.randint(5, 25)
        avg_pkt_size = random.randint(80, 250)
        flows.append(
            generate_flow_record(
                src_ip=client,
                dst_ip=server_ips[1],
                proto=17,
                packets=pkts,
                bytes_count=pkts * avg_pkt_size,
                duration=window_duration,
            )
        )

    # 3. Occasional ICMP ping (proto 1)
    if random.random() > 0.4:
        client = random.choice(client_ips)
        pkts = random.randint(2, 6)
        flows.append(
            generate_flow_record(
                src_ip=client,
                dst_ip=server_ips[0],
                proto=1,
                packets=pkts,
                bytes_count=pkts * 84,
                duration=window_duration,
            )
        )

    return flows


def simulate_attack_traffic_window(
    attack_type: str = "syn",
    victim_ip: str = "10.0.0.4",
    attacker_ips: List[str] = None,
    spoof_ips: bool = False,
    window_duration: float = 3.0,
    intensity: float = 1.0,
) -> List[Dict[str, Any]]:
    """
    Simulate a high-volume DDoS attack window:
    SYN flood, UDP flood, or ICMP flood.
    """
    if attacker_ips is None:
        attacker_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    flows = []
    # Include some benign background flows so realistic mixed state is modeled
    flows.extend(simulate_normal_traffic_window(window_duration=window_duration))

    proto_map = {"syn": 6, "udp": 17, "icmp": 1}
    proto = proto_map.get(attack_type.lower(), 6)

    # High packet rate flood
    base_packets = int(random.randint(3500, 7500) * intensity)

    if spoof_ips:
        # Spoofed attack with many distinct pseudo-random IPs targeting single victim
        num_spoofed = random.randint(15, 45)
        for _ in range(num_spoofed):
            src_ip = f"10.{random.randint(0, 2)}.{random.randint(0, 254)}.{random.randint(1, 254)}"
            pkts = max(10, base_packets // num_spoofed)
            pkt_size = 60 if proto == 6 else (100 if proto == 17 else 84)
            flows.append(
                generate_flow_record(
                    src_ip=src_ip,
                    dst_ip=victim_ip,
                    proto=proto,
                    packets=pkts,
                    bytes_count=pkts * pkt_size,
                    duration=window_duration,
                )
            )
    else:
        # Botnet with fixed attacker IP nodes
        for attacker in attacker_ips:
            pkts = int(base_packets / len(attacker_ips)) + random.randint(100, 400)
            pkt_size = 64 if proto == 6 else (256 if proto == 17 else 84)
            flows.append(
                generate_flow_record(
                    src_ip=attacker,
                    dst_ip=victim_ip,
                    proto=proto,
                    packets=pkts,
                    bytes_count=pkts * pkt_size,
                    duration=window_duration,
                )
            )

    return flows


def run_live_flood(attack_type: str, target: str, port: int, duration: float):
    """Simple user-space socket burst for testing without hping3."""
    end_time = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 256
    count = 0
    print(f"[LIVE] Starting {attack_type.upper()} socket burst towards {target}:{port} for {duration}s...")
    try:
        while time.time() < end_time:
            try:
                sock.sendto(payload, (target, port))
                count += 1
            except Exception:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"[LIVE] Completed socket burst. Sent ~{count} packets.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Traffic Generator")
    parser.add_argument("--type", choices=["normal", "syn", "udp", "icmp", "all"], default="normal")
    parser.add_argument("--target", default="10.0.0.4", help="Target IP")
    parser.add_argument("--port", type=int, default=80, help="Target Port")
    parser.add_argument("--duration", type=float, default=20.0, help="Duration in seconds")
    parser.add_argument("--live", action="store_true", help="Send live network packets")
    args = parser.parse_args()

    if args.live:
        run_live_flood(args.type, args.target, args.port, args.duration)
    else:
        print(f"[INFO] Simulation mode for {args.type} traffic generator. Use inside Mininet with --live or via bash scripts.")
