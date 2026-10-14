"""
Unit tests for FeatureExtractor module.
"""

import math
import pytest
from controller.feature_extractor import FeatureExtractor


def test_entropy_empty_and_single():
    extractor = FeatureExtractor()
    assert extractor.calculate_entropy([]) == 0.0
    assert extractor.calculate_entropy(["10.0.0.1"]) == 0.0
    assert extractor.calculate_entropy(["10.0.0.1"] * 100) == 0.0


def test_entropy_distribution():
    extractor = FeatureExtractor()
    # 4 distinct items with equal probability: -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0
    items = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    entropy = extractor.calculate_entropy(items)
    assert math.isclose(entropy, 2.0, rel_tol=1e-5)


def test_extract_features_empty():
    extractor = FeatureExtractor()
    features = extractor.extract_features([])
    assert isinstance(features, dict)
    assert features["packet_rate"] == 0.0
    assert features["byte_rate"] == 0.0
    assert features["src_ip_entropy"] == 0.0


def test_extract_features_normal_traffic():
    extractor = FeatureExtractor(default_interval=3.0)
    flows = [
        {"ipv4_src": "10.0.0.6", "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 50, "byte_count": 35000, "duration_sec": 3.0},
        {"ipv4_src": "10.0.0.7", "ipv4_dst": "10.0.0.5", "ip_proto": 17, "packet_count": 30, "byte_count": 18000, "duration_sec": 2.5},
        {"ipv4_src": "10.0.0.8", "ipv4_dst": "10.0.0.4", "ip_proto": 1, "packet_count": 10, "byte_count": 840, "duration_sec": 1.0},
    ]

    features = extractor.extract_features(flows, elapsed_time=3.0)
    # Total packets: 90 / 3s = 30.0 pps
    assert math.isclose(features["packet_rate"], 30.0, rel_tol=1e-3)
    assert features["src_ip_entropy"] > 1.0
    assert features["tcp_ratio"] > 0.0
    assert features["udp_ratio"] > 0.0
    assert features["icmp_ratio"] > 0.0


def test_extract_features_syn_flood():
    extractor = FeatureExtractor(default_interval=3.0)
    # Single attacker flooding victim with TCP SYN packets
    flows = [
        {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 6000, "byte_count": 360000, "duration_sec": 3.0},
        {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 5500, "byte_count": 330000, "duration_sec": 3.0},
    ]
    features = extractor.extract_features(flows, elapsed_time=3.0)
    assert features["packet_rate"] >= 3000.0
    assert features["src_ip_entropy"] == 0.0  # Only one unique source IP
    assert features["dst_ip_entropy"] == 0.0  # Only one unique destination IP
    assert features["tcp_ratio"] == 1.0
    assert features["udp_ratio"] == 0.0


def test_delta_rate_calculation_over_windows():
    extractor = FeatureExtractor(default_interval=3.0)
    
    # Window 1
    flows_w1 = [
        {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 100, "byte_count": 10000, "duration_sec": 3.0}
    ]
    f1 = extractor.extract_features(flows_w1, timestamp=100.0, elapsed_time=3.0)
    assert f1["packet_rate"] == round(100.0 / 3.0, 4)

    # Window 2: cumulative packet count increased to 400 (delta = 300 packets)
    flows_w2 = [
        {"ipv4_src": "10.0.0.1", "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 400, "byte_count": 40000, "duration_sec": 6.0}
    ]
    f2 = extractor.extract_features(flows_w2, timestamp=103.0, elapsed_time=3.0)
    assert math.isclose(f2["packet_rate"], 100.0, rel_tol=1e-3)
