"""
Unit tests for DDoS Detection and Mitigation logic.
"""

import time
import pytest
from controller.ddos_controller import DDoSController


class MockDatapath:
    def __init__(self, dpid=1):
        self.id = dpid
        self.sent_messages = []

    def send_msg(self, msg):
        self.sent_messages.append(msg)


@pytest.fixture
def controller():
    ctrl = DDoSController()
    ctrl.datapaths[1] = MockDatapath(1)
    return ctrl


def test_classify_normal_traffic(controller):
    features = {
        "packet_rate": 35.0,
        "byte_rate": 25000.0,
        "packet_count_per_flow": 25.0,
        "byte_count_per_flow": 18000.0,
        "avg_duration_sec": 3.0,
        "src_ip_entropy": 1.95,
        "dst_ip_entropy": 1.2,
        "unique_src_per_dst": 2.0,
        "tcp_ratio": 0.5,
        "udp_ratio": 0.4,
        "icmp_ratio": 0.1,
    }
    is_attack, atk_type, conf = controller.classify_traffic(features)
    assert not is_attack
    assert atk_type == "Normal"


def test_classify_syn_flood_attack(controller):
    features = {
        "packet_rate": 4500.0,
        "byte_rate": 280000.0,
        "packet_count_per_flow": 4500.0,
        "byte_count_per_flow": 280000.0,
        "avg_duration_sec": 3.0,
        "src_ip_entropy": 0.0,
        "dst_ip_entropy": 0.0,
        "unique_src_per_dst": 1.0,
        "tcp_ratio": 1.0,
        "udp_ratio": 0.0,
        "icmp_ratio": 0.0,
    }
    is_attack, atk_type, conf = controller.classify_traffic(features)
    assert is_attack
    assert "SYN" in atk_type or "DDoS" in atk_type


def test_threshold_fallback_when_model_disabled(controller):
    # Temporarily disable ML model
    saved_model = controller.model
    controller.model = None

    try:
        # High rate exceeding threshold
        high_features = {
            "packet_rate": 2000.0,
            "byte_rate": 2000000.0,
            "tcp_ratio": 0.9,
            "udp_ratio": 0.0,
            "icmp_ratio": 0.0,
            "src_ip_entropy": 0.1,
            "dst_ip_entropy": 0.0,
            "unique_src_per_dst": 1.0,
        }
        is_attack, atk_type, conf = controller.classify_traffic(high_features)
        assert is_attack
        assert "Threshold Fallback" in atk_type
    finally:
        controller.model = saved_model


def test_whitelist_protection(controller):
    dp = controller.datapaths[1]
    # Whitelisted IP (e.g. 10.0.0.6 is in config whitelist)
    whitelist_ip = "10.0.0.6"
    assert whitelist_ip in controller.whitelist_ips

    mock_flows = [
        {"ipv4_src": whitelist_ip, "ipv4_dst": "10.0.0.4", "ip_proto": 6, "packet_count": 8000, "byte_count": 500000, "duration_sec": 3.0}
    ]
    features = controller.feature_extractor.extract_features(mock_flows)
    controller._mitigate_attack(dp, features, mock_flows, "SYN Flood")

    # Whitelisted IP must NOT be added to blocked_hosts
    assert whitelist_ip not in controller.blocked_hosts


def test_mitigation_and_auto_unblock(controller):
    dp = controller.datapaths[1]
    attacker_ip = "10.0.0.1"
    victim_ip = "10.0.0.4"

    mock_flows = [
        {"ipv4_src": attacker_ip, "ipv4_dst": victim_ip, "ip_proto": 6, "packet_count": 5000, "byte_count": 350000, "duration_sec": 3.0}
    ]
    features = controller.feature_extractor.extract_features(mock_flows)
    controller._mitigate_attack(dp, features, mock_flows, "TCP SYN Flood")

    assert attacker_ip in controller.blocked_hosts
    assert controller.blocked_hosts[attacker_ip]["victim"] == victim_ip

    # Test manual unblock
    success = controller.unblock_host_manually(attacker_ip)
    assert success
    assert attacker_ip not in controller.blocked_hosts

    # Test auto unblock expiration
    controller._mitigate_attack(dp, features, mock_flows, "TCP SYN Flood")
    assert attacker_ip in controller.blocked_hosts
    # Manually expire
    controller.blocked_hosts[attacker_ip]["expires_at"] = time.time() - 1.0
    controller._check_unblock_timeouts()
    assert attacker_ip not in controller.blocked_hosts
