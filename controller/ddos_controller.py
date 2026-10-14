"""
Ryu OpenFlow 1.3 SDN Controller for DDoS Detection and Automatic Mitigation.

Features:
  1. OpenFlow 1.3 L2 Learning Switch with MAC table learning.
  2. Periodic Flow and Port Stats polling via Ryu hub green threads.
  3. Feature extraction (rate, duration, entropy, fan-in, protocol ratio).
  4. Real-time ML Inference (Random Forest) with heuristic threshold fallback.
  5. Dynamic Mitigation: Installs high-priority OFPFlowMod DROP rules directly on Open vSwitch.
  6. Auto-unblock after hard timeout expiration.
  7. Whitelist enforcement for critical/legitimate IP addresses.
  8. JSON state synchronization with Web Monitoring Dashboard.
"""

import collections
import json
import logging
import os
import sys
import time
from typing import Dict, Any, List, Optional, Tuple

# Ensure project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import yaml

from controller.feature_extractor import FeatureExtractor

# Graceful import of Ryu modules with shim fallback for offline/test environments
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.lib import hub
    from ryu.lib.packet import ethernet, ipv4, packet
    from ryu.ofproto import ofproto_v1_3
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False

    class DummyApp:
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger("RyuAppFallback")
            if not self.logger.handlers:
                h = logging.StreamHandler(sys.stdout)
                h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
                self.logger.addHandler(h)
                self.logger.setLevel(logging.INFO)

    class app_manager:
        RyuApp = DummyApp

    class ofp_event:
        class EventOFPStateChange: pass
        class EventOFPSwitchFeatures: pass
        class EventOFPFlowStatsReply: pass
        class EventOFPPacketIn: pass

    class ofproto_v1_3:
        OFP_VERSION = 0x04

    def set_ev_cls(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

    CONFIG_DISPATCHER = "config"
    MAIN_DISPATCHER = "main"

    class hub:
        @staticmethod
        def spawn(func, *args, **kwargs):
            import threading
            t = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
            t.start()
            return t

        @staticmethod
        def sleep(seconds):
            time.sleep(seconds)


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from config.yaml."""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


class DDoSController(app_manager.RyuApp):
    """
    Ryu OpenFlow 1.3 Controller with DDoS Detection & Automated Mitigation.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)

        self.config = load_config()
        self.polling_interval = float(self.config.get("controller", {}).get("stat_polling_interval", 3.0))
        self.hard_timeout = int(self.config.get("mitigation", {}).get("hard_timeout", 30))
        self.idle_timeout = int(self.config.get("mitigation", {}).get("idle_timeout", 10))
        self.rule_priority = int(self.config.get("mitigation", {}).get("rule_priority", 65535))
        self.auto_unblock = bool(self.config.get("mitigation", {}).get("auto_unblock", True))
        self.whitelist_ips = set(self.config.get("mitigation", {}).get("whitelist_ips", ["10.0.0.254", "127.0.0.1"]))
        
        # Thresholds fallback
        self.thresh = self.config.get("detection", {}).get("thresholds", {
            "max_packet_rate": 1200.0,
            "max_byte_rate": 1500000.0,
            "min_src_entropy": 0.85,
            "max_flows_per_dest": 40,
            "syn_ratio_threshold": 0.70,
            "udp_ratio_threshold": 0.70,
            "icmp_ratio_threshold": 0.60,
        })

        # Feature Extractor
        self.feature_extractor = FeatureExtractor(default_interval=self.polling_interval)

        # Datapath and MAC learning tables
        self.datapaths: Dict[int, Any] = {}
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

        # Mitigation & Telemetry state
        self.blocked_hosts: Dict[str, Dict[str, Any]] = {}
        self.alert_history: List[Dict[str, Any]] = []
        self.traffic_history = collections.deque(maxlen=100)
        self.current_status = "NORMAL"
        self.latest_features: Dict[str, float] = {}

        # State storage file for dashboard communication
        self.state_file = "logs/controller_state.json"
        os.makedirs("logs", exist_ok=True)

        # Load ML Model
        self.model = None
        self.scaler = None
        self.feature_order = self.config.get("ml", {}).get("features", FeatureExtractor.FEATURE_NAMES)
        self._load_ml_model()

        # Start periodic telemetry thread
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.logger.info("[INIT] DDoS Controller initialized successfully. Polling interval: %.1fs", self.polling_interval)
        self._export_state()

    def _load_ml_model(self):
        """Load trained machine learning classifier and scaler."""
        model_path = self.config.get("detection", {}).get("model_path", "ml/models/model.pkl")
        scaler_path = self.config.get("detection", {}).get("scaler_path", "ml/models/scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.logger.info("[ML] Loaded ML model from %s and scaler from %s", model_path, scaler_path)
            except Exception as e:
                self.logger.warning("[ML-WARN] Failed to load model (%s). Reverting to threshold heuristic.", e)
                self.model = None
                self.scaler = None
        else:
            self.logger.warning("[ML-WARN] ML model/scaler files not found (%s). Running in threshold fallback mode.", model_path)

    def _export_state(self):
        """Export current controller state to JSON file for dashboard synchronization."""
        # Calculate remaining timeouts
        now = time.time()
        active_blocks = []
        for ip, info in list(self.blocked_hosts.items()):
            remaining = max(0, int(info["expires_at"] - now))
            active_blocks.append({
                "ip": ip,
                "victim": info.get("victim", "N/A"),
                "reason": info.get("reason", "DDoS Attack"),
                "blocked_at": info.get("blocked_at", now),
                "remaining_sec": remaining,
            })

        state = {
            "status": self.current_status,
            "polling_interval": self.polling_interval,
            "ml_active": self.model is not None,
            "blocked_count": len(active_blocks),
            "blocked_hosts": active_blocks,
            "latest_features": self.latest_features,
            "traffic_history": list(self.traffic_history),
            "recent_alerts": self.alert_history[-20:],
            "active_switches": list(self.datapaths.keys()),
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        try:
            temp_file = f"{self.state_file}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            os.replace(temp_file, self.state_file)
        except Exception:
            pass

    def _monitor_loop(self):
        """Periodic background thread to request stats and check unblock timeouts."""
        while True:
            hub.sleep(self.polling_interval)
            self._check_unblock_timeouts()
            for dp in list(self.datapaths.values()):
                self._send_flow_stats_request(dp)
                self._send_port_stats_request(dp)

    def _check_unblock_timeouts(self):
        """Clean up expired DROP rules and unblock legitimate hosts."""
        now = time.time()
        expired = [ip for ip, data in self.blocked_hosts.items() if now >= data.get("expires_at", 0)]
        for ip in expired:
            victim = self.blocked_hosts[ip].get("victim", "all")
            self.logger.info("[UNBLOCK] Timeout expired for %s (targeted %s). Removing block status.", ip, victim)
            del self.blocked_hosts[ip]
            self._record_alert(
                severity="INFO",
                title="Host Unblocked",
                message=f"Hard timeout expired. IP {ip} unblocked.",
                attacker_ip=ip,
            )

        if not self.blocked_hosts and self.current_status == "ATTACK":
            self.current_status = "NORMAL"
            self.logger.info("[STATUS] No active blocked hosts. System returned to NORMAL status.")

        self._export_state()

    def _send_flow_stats_request(self, datapath):
        """Send OFPFlowStatsRequest to datapath."""
        if not RYU_AVAILABLE:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _send_port_stats_request(self, datapath):
        """Send OFPPortStatsRequest to datapath."""
        if not RYU_AVAILABLE:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        """Track connected switches."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("[SWITCH] Datapath s%d connected.", datapath.id)
                self.datapaths[datapath.id] = datapath
        else:
            if datapath.id in self.datapaths:
                self.logger.info("[SWITCH] Datapath s%d disconnected.", datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow rule during switch connection."""
        if not RYU_AVAILABLE:
            return
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("[SWITCH] Switch s%d configured with table-miss flow rule.", datapath.id)

    def add_flow(
        self,
        datapath,
        priority: int,
        match: Any,
        actions: List[Any],
        idle_timeout: int = 0,
        hard_timeout: int = 0,
    ):
        """Install OpenFlow flow rule into switch table."""
        if not RYU_AVAILABLE:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def add_drop_rule(self, datapath, src_ip: str, dst_ip: str = None, hard_timeout: int = None):
        """
        Install high-priority DROP flow entry.
        Omits actions instruction list -> packets matching src/dst are discarded by hardware/OVS.
        """
        if not RYU_AVAILABLE:
            self.logger.info("[SIM-FLOWMOD] DROP rule for src=%s -> dst=%s installed (timeout=%ds)", src_ip, dst_ip, hard_timeout or self.hard_timeout)
            return

        timeout = hard_timeout or self.hard_timeout
        parser = datapath.ofproto_parser

        if dst_ip:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        else:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

        # Empty instructions = DROP
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=self.rule_priority,
            match=match,
            instructions=[],
            idle_timeout=0,
            hard_timeout=timeout,
        )
        datapath.send_msg(mod)
        self.logger.info("[MITIGATION] Switch s%d installed DROP rule for %s -> %s (hard_timeout=%ds)", datapath.id, src_ip, dst_ip or "*", timeout)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle periodic FlowStatsReply, extract features, and detect DDoS attacks."""
        datapath = ev.msg.datapath
        body = ev.msg.body

        # Filter out table-miss and controller-internal flows
        valid_flows = [
            f for f in body
            if hasattr(f, "priority") and f.priority > 0 and getattr(f, "packet_count", 0) > 0
        ]

        # Extract features
        features = self.feature_extractor.extract_features(valid_flows)
        self.latest_features = features

        # Classify interval
        is_attack, attack_type, confidence = self.classify_traffic(features)

        # Update telemetry history
        timestamp = time.strftime("%H:%M:%S")
        self.traffic_history.append({
            "timestamp": timestamp,
            "packet_rate": features.get("packet_rate", 0.0),
            "byte_rate": features.get("byte_rate", 0.0),
            "flow_count": len(valid_flows),
            "src_entropy": features.get("src_ip_entropy", 0.0),
            "dst_entropy": features.get("dst_ip_entropy", 0.0),
            "status": "ATTACK" if is_attack else "NORMAL",
            "attack_type": attack_type,
        })

        if is_attack:
            self.current_status = "ATTACK"
            self.logger.warning(
                "[ALERT-DDoS] Traffic classified as ATTACK (%s)! Rate: %.1f pps, Entropy: %.2f",
                attack_type, features.get("packet_rate", 0.0), features.get("src_ip_entropy", 0.0)
            )
            self._mitigate_attack(datapath, features, valid_flows, attack_type)
        else:
            if not self.blocked_hosts:
                self.current_status = "NORMAL"

        self._export_state()

    def classify_traffic(self, features: Dict[str, float]) -> Tuple[bool, str, float]:
        """
        Classify network status using Machine Learning or threshold fallback.

        Returns:
            Tuple of (is_attack: bool, attack_type: str, confidence: float)
        """
        packet_rate = features.get("packet_rate", 0.0)

        # 1. Use ML Classifier if loaded
        if self.model is not None and self.scaler is not None:
            try:
                feature_vector = [features.get(f, 0.0) for f in self.feature_order]
                scaled = self.scaler.transform([feature_vector])
                prediction = int(self.model.predict(scaled)[0])
                prob = float(self.model.predict_proba(scaled)[0][1]) if hasattr(self.model, "predict_proba") else 1.0

                if prediction == 1 and packet_rate > 100.0:
                    # Determine attack signature
                    if features.get("tcp_ratio", 0.0) > 0.6:
                        atk_type = "TCP SYN Flood"
                    elif features.get("udp_ratio", 0.0) > 0.6:
                        atk_type = "UDP Flood"
                    elif features.get("icmp_ratio", 0.0) > 0.5:
                        atk_type = "ICMP Flood"
                    else:
                        atk_type = "Multi-Vector DDoS"
                    return True, atk_type, prob
                return False, "Normal", 1.0 - prob
            except Exception as e:
                self.logger.error("[ML-ERR] Inference error: %s. Reverting to fallback.", e)

        # 2. Heuristic Threshold Fallback
        t = self.thresh
        if packet_rate > t["max_packet_rate"] or features.get("byte_rate", 0.0) > t["max_byte_rate"]:
            if features.get("tcp_ratio", 0.0) >= t["syn_ratio_threshold"]:
                return True, "TCP SYN Flood (Threshold Fallback)", 0.95
            if features.get("udp_ratio", 0.0) >= t["udp_ratio_threshold"]:
                return True, "UDP Flood (Threshold Fallback)", 0.95
            if features.get("icmp_ratio", 0.0) >= t["icmp_ratio_threshold"]:
                return True, "ICMP Flood (Threshold Fallback)", 0.95
            return True, "High Rate Anomaly (Threshold Fallback)", 0.90

        return False, "Normal", 0.99

    def _mitigate_attack(self, datapath, features, flow_stats, attack_type):
        """Identify offending attacker IP(s) and install DROP flow rules across switches."""
        # Normalize and inspect active flows to isolate culprit
        normalized = [self.feature_extractor.normalize_flow_stat(f) for f in flow_stats]
        
        # Sort flows by packet volume in descending order
        sorted_flows = sorted(normalized, key=lambda x: x["packet_count"], reverse=True)
        if not sorted_flows:
            return

        max_flow_pkts = sorted_flows[0]["packet_count"]
        # Heavy-hitter threshold: must have high packet volume (e.g., >= 300 pkts or >= 25% of peak)
        min_attack_pkts = max(300, int(max_flow_pkts * 0.25))

        blocked_count = 0
        now = time.time()

        for flow in sorted_flows:
            src_ip = flow["ipv4_src"]
            dst_ip = flow["ipv4_dst"]
            pkt_count = flow["packet_count"]

            # Filter invalid, whitelisted addresses, or sub-threshold benign flows
            if src_ip in ("0.0.0.0", "127.0.0.1") or src_ip in self.whitelist_ips:
                continue

            if pkt_count < min_attack_pkts:
                # Do not block benign clients that happen to be active during the attack
                continue

            # If already blocked, skip
            if src_ip in self.blocked_hosts:
                continue

            # Offending host confirmed
            expires_at = now + self.hard_timeout
            self.blocked_hosts[src_ip] = {
                "blocked_at": now,
                "expires_at": expires_at,
                "victim": dst_ip,
                "reason": attack_type,
                "packets": pkt_count,
            }

            self.logger.warning(
                "[MITIGATION] Blocking Malicious Attacker IP: %s (Packets: %d, Targeting: %s)",
                src_ip, pkt_count, dst_ip
            )

            # Push DROP rule to the reporting datapath and all active edge switches
            for dp in self.datapaths.values():
                self.add_drop_rule(dp, src_ip=src_ip, dst_ip=dst_ip, hard_timeout=self.hard_timeout)

            self._record_alert(
                severity="CRITICAL",
                title="DDoS Attack Mitigated",
                message=f"Attack vector '{attack_type}' detected ({pkt_count} pkts). Installed DROP rule for attacker {src_ip} targeting {dst_ip}.",
                attacker_ip=src_ip,
                target_ip=dst_ip,
            )

            blocked_count += 1
            if blocked_count >= 5:  # Block top culprits in this cycle
                break

    def unblock_host_manually(self, ip: str) -> bool:
        """Manually remove an IP from blocked list."""
        if ip in self.blocked_hosts:
            del self.blocked_hosts[ip]
            self.logger.info("[MANUAL-UNBLOCK] Host %s unblocked manually.", ip)
            self._record_alert("INFO", "Manual Unblock", f"Administrator unblocked {ip}.", attacker_ip=ip)
            self._export_state()
            return True
        return False

    def _record_alert(
        self,
        severity: str,
        title: str,
        message: str,
        attacker_ip: str = "N/A",
        target_ip: str = "N/A",
    ):
        """Append alert to audit history."""
        self.alert_history.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "title": title,
            "message": message,
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
        })
        if len(self.alert_history) > 100:
            self.alert_history.pop(0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Standard L2 Learning Switch forwarding logic."""
        if not RYU_AVAILABLE:
            return
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # Inspect IPv4 header if present
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            # Check if traffic originates from blocked host
            if src_ip in self.blocked_hosts:
                # Discard packet immediately
                return

        # Learn source MAC to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule if destination is known
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=15, hard_timeout=60)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)


def run_simulation_loop():
    """
    Simulation mode: Allows running controller logic, feature extraction,
    ML detection, and mitigation on non-Linux hosts or during automated testing.
    """
    print("[SIM] Starting DDoS Controller in Standalone Simulation Mode...")
    controller = DDoSController()
    
    # Simulate a lifecycle:
    # Phase 1: 3 normal intervals
    # Phase 2: 3 SYN attack intervals (triggering detection & DROP rule)
    # Phase 3: Mitigation active (dropped packets)
    # Phase 4: Auto-unblock
    from traffic.traffic_generator import simulate_normal_traffic_window, simulate_attack_traffic_window

    print("[SIM] Phase 1: Sending Benign Traffic Flows...")
    for i in range(3):
        flows = simulate_normal_traffic_window()
        features = controller.feature_extractor.extract_features(flows)
        controller.latest_features = features
        is_attack, atk_type, conf = controller.classify_traffic(features)
        controller.traffic_history.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "packet_rate": features["packet_rate"],
            "byte_rate": features["byte_rate"],
            "flow_count": len(flows),
            "status": "ATTACK" if is_attack else "NORMAL",
            "attack_type": atk_type,
        })
        print(f"  Interval {i+1}: pps={features['packet_rate']:.1f} status={controller.current_status}")
        controller._export_state()
        time.sleep(1)

    print("\n[SIM] Phase 2: Launching SYN Flood Attack (Attacker: 10.0.0.1 -> Victim: 10.0.0.4)...")
    for i in range(3):
        flows = simulate_attack_traffic_window(attack_type="syn", victim_ip="10.0.0.4", attacker_ips=["10.0.0.1"])
        features = controller.feature_extractor.extract_features(flows)
        controller.latest_features = features
        is_attack, atk_type, conf = controller.classify_traffic(features)
        
        class DummyDatapath:
            id = 1
        
        if is_attack:
            controller.current_status = "ATTACK"
            controller._mitigate_attack(DummyDatapath(), features, flows, atk_type)
        
        controller.traffic_history.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "packet_rate": features["packet_rate"],
            "byte_rate": features["byte_rate"],
            "flow_count": len(flows),
            "status": "ATTACK" if is_attack else "NORMAL",
            "attack_type": atk_type,
        })
        print(f"  Attack Interval {i+1}: pps={features['packet_rate']:.1f} status={controller.current_status} blocked={list(controller.blocked_hosts.keys())}")
        controller._export_state()
        time.sleep(1)

    print("\n[SIM] Phase 3: Mitigation Active. Attacker flows dropped at switch. Verifying state export...")
    print(f"  Blocked Hosts: {list(controller.blocked_hosts.keys())}")
    print(f"  Recent Alerts: {[a['title'] for a in controller.alert_history]}")
    controller._export_state()
    print("[SIM] State exported successfully to logs/controller_state.json")


if __name__ == "__main__":
    if "--simulate" in sys.argv or not RYU_AVAILABLE:
        run_simulation_loop()
    else:
        print("[INFO] Run with: ryu-manager controller/ddos_controller.py")
