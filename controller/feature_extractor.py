"""
Feature Extractor Module for SDN DDoS Detection.

Extracts statistical and information-theoretic features from OpenFlow flow statistics.
Features computed:
  1. packet_rate: Packet arrival rate (packets/sec)
  2. byte_rate: Byte transfer rate (bytes/sec)
  3. packet_count_per_flow: Average packets per flow entry
  4. byte_count_per_flow: Average bytes per flow entry
  5. avg_duration_sec: Average duration of active flows (seconds)
  6. src_ip_entropy: Shannon entropy of source IP addresses
  7. dst_ip_entropy: Shannon entropy of destination IP addresses
  8. unique_src_per_dst: Ratio of unique source IPs to unique destination IPs
  9. tcp_ratio: Fraction of flows using TCP protocol
  10. udp_ratio: Fraction of flows using UDP protocol
  11. icmp_ratio: Fraction of flows using ICMP protocol
"""

import math
import time
from collections import Counter
from typing import List, Dict, Any, Tuple, Optional


class FeatureExtractor:
    """
    Extracts traffic features from OpenFlow flow statistics replies.
    Maintains historical state to compute accurate delta rates over time windows.
    """

    FEATURE_NAMES = [
        "packet_rate",
        "byte_rate",
        "packet_count_per_flow",
        "byte_count_per_flow",
        "avg_duration_sec",
        "src_ip_entropy",
        "dst_ip_entropy",
        "unique_src_per_dst",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
    ]

    def __init__(self, default_interval: float = 3.0):
        """
        Initialize FeatureExtractor.

        Args:
            default_interval: Default sampling interval in seconds if timestamps are unavailable.
        """
        self.default_interval = max(0.1, float(default_interval))
        self.prev_flow_records: Dict[Tuple, Dict[str, Any]] = {}
        self.prev_timestamp: Optional[float] = None

    @staticmethod
    def calculate_entropy(elements: List[Any]) -> float:
        """
        Calculate Shannon entropy for a list of discrete elements.
        H(X) = - sum(p_i * log2(p_i))

        Args:
            elements: List of values (e.g., IP addresses).

        Returns:
            Shannon entropy as float. Returns 0.0 if elements list is empty or uniform.
        """
        if not elements:
            return 0.0
        total_count = len(elements)
        if total_count <= 1:
            return 0.0
        counts = Counter(elements)
        entropy = 0.0
        for count in counts.values():
            p = count / total_count
            if p > 0:
                entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def normalize_flow_stat(stat: Any) -> Dict[str, Any]:
        """
        Normalize an OpenFlow flow stat object or dictionary into a standard dictionary.

        Args:
            stat: Ryu OFPFlowStats object or dictionary.

        Returns:
            Dictionary with keys: packet_count, byte_count, duration_sec,
            ipv4_src, ipv4_dst, ip_proto.
        """
        if isinstance(stat, dict):
            return {
                "packet_count": int(stat.get("packet_count", 0)),
                "byte_count": int(stat.get("byte_count", 0)),
                "duration_sec": float(stat.get("duration_sec", 0)) + float(stat.get("duration_nsec", 0)) / 1e9,
                "ipv4_src": stat.get("ipv4_src") or stat.get("src_ip", "0.0.0.0"),
                "ipv4_dst": stat.get("ipv4_dst") or stat.get("dst_ip", "0.0.0.0"),
                "ip_proto": int(stat.get("ip_proto", 0) or stat.get("protocol", 0)),
            }

        # Handle Ryu OFPFlowStats object
        packet_count = getattr(stat, "packet_count", 0)
        byte_count = getattr(stat, "byte_count", 0)
        duration_sec = getattr(stat, "duration_sec", 0)
        duration_nsec = getattr(stat, "duration_nsec", 0)
        total_duration = float(duration_sec) + (float(duration_nsec) / 1e9)

        match = getattr(stat, "match", {})
        ipv4_src = "0.0.0.0"
        ipv4_dst = "0.0.0.0"
        ip_proto = 0

        # Ryu match can be accessed via dict-like or ofproto methods
        if hasattr(match, "get"):
            ipv4_src = match.get("ipv4_src", "0.0.0.0")
            ipv4_dst = match.get("ipv4_dst", "0.0.0.0")
            ip_proto = match.get("ip_proto", 0)
        elif hasattr(match, "__getitem__"):
            try:
                ipv4_src = match["ipv4_src"]
            except KeyError:
                pass
            try:
                ipv4_dst = match["ipv4_dst"]
            except KeyError:
                pass
            try:
                ip_proto = match["ip_proto"]
            except KeyError:
                pass

        return {
            "packet_count": int(packet_count),
            "byte_count": int(byte_count),
            "duration_sec": total_duration,
            "ipv4_src": str(ipv4_src),
            "ipv4_dst": str(ipv4_dst),
            "ip_proto": int(ip_proto or 0),
        }

    def extract_features(
        self,
        flow_stats: List[Any],
        timestamp: Optional[float] = None,
        elapsed_time: Optional[float] = None,
    ) -> Dict[str, float]:
        """
        Extract numerical features from the current window of flow stats.

        Args:
            flow_stats: List of Ryu OFPFlowStats or standardized flow dictionaries.
            timestamp: Epoch timestamp of current sample. Defaults to time.time().
            elapsed_time: Explicit elapsed seconds since last sample.

        Returns:
            Dictionary mapping feature name to float value.
        """
        current_time = timestamp if timestamp is not None else time.time()

        if elapsed_time is not None and elapsed_time > 0:
            dt = float(elapsed_time)
        elif self.prev_timestamp is not None and current_time > self.prev_timestamp:
            dt = current_time - self.prev_timestamp
        else:
            dt = self.default_interval

        if not flow_stats:
            # Baseline empty state
            self.prev_timestamp = current_time
            return {name: 0.0 for name in self.FEATURE_NAMES}

        normalized_flows = [self.normalize_flow_stat(s) for s in flow_stats]

        # Aggregate raw values
        total_packets = sum(f["packet_count"] for f in normalized_flows)
        total_bytes = sum(f["byte_count"] for f in normalized_flows)
        total_duration = sum(f["duration_sec"] for f in normalized_flows)
        flow_count = len(normalized_flows)

        # Compute delta packet and byte rate
        current_records: Dict[Tuple, Dict[str, Any]] = {}
        delta_packets = 0
        delta_bytes = 0

        for f in normalized_flows:
            key = (f["ipv4_src"], f["ipv4_dst"], f["ip_proto"])
            current_records[key] = f

            if key in self.prev_flow_records:
                prev = self.prev_flow_records[key]
                p_diff = f["packet_count"] - prev["packet_count"]
                b_diff = f["byte_count"] - prev["byte_count"]
                # Guard against counter resets
                delta_packets += max(0, p_diff)
                delta_bytes += max(0, b_diff)
            else:
                delta_packets += f["packet_count"]
                delta_bytes += f["byte_count"]

        # If previous window was empty, estimate delta over default interval
        if not self.prev_flow_records:
            delta_packets = total_packets
            delta_bytes = total_bytes

        packet_rate = float(delta_packets) / dt
        byte_rate = float(delta_bytes) / dt

        # Per flow averages
        packet_count_per_flow = float(total_packets) / max(1, flow_count)
        byte_count_per_flow = float(total_bytes) / max(1, flow_count)
        avg_duration_sec = float(total_duration) / max(1, flow_count)

        # Source & Destination Entropy
        src_ips = [f["ipv4_src"] for f in normalized_flows if f["ipv4_src"] != "0.0.0.0"]
        dst_ips = [f["ipv4_dst"] for f in normalized_flows if f["ipv4_dst"] != "0.0.0.0"]

        src_ip_entropy = self.calculate_entropy(src_ips)
        dst_ip_entropy = self.calculate_entropy(dst_ips)

        # Unique sources per destination
        unique_src_count = len(set(src_ips))
        unique_dst_count = len(set(dst_ips))
        unique_src_per_dst = float(unique_src_count) / max(1.0, float(unique_dst_count))

        # Protocol Ratios (IP Proto: 6=TCP, 17=UDP, 1=ICMP)
        protocols = [f["ip_proto"] for f in normalized_flows]
        tcp_count = sum(1 for p in protocols if p == 6)
        udp_count = sum(1 for p in protocols if p == 17)
        icmp_count = sum(1 for p in protocols if p == 1)

        total_proto = max(1, len(protocols))
        tcp_ratio = float(tcp_count) / total_proto
        udp_ratio = float(udp_count) / total_proto
        icmp_ratio = float(icmp_count) / total_proto

        # Update historical state
        self.prev_flow_records = current_records
        self.prev_timestamp = current_time

        return {
            "packet_rate": round(packet_rate, 4),
            "byte_rate": round(byte_rate, 4),
            "packet_count_per_flow": round(packet_count_per_flow, 4),
            "byte_count_per_flow": round(byte_count_per_flow, 4),
            "avg_duration_sec": round(avg_duration_sec, 4),
            "src_ip_entropy": round(src_ip_entropy, 4),
            "dst_ip_entropy": round(dst_ip_entropy, 4),
            "unique_src_per_dst": round(unique_src_per_dst, 4),
            "tcp_ratio": round(tcp_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": round(icmp_ratio, 4),
        }

    def reset(self) -> None:
        """Reset historical state tracking."""
        self.prev_flow_records.clear()
        self.prev_timestamp = None
