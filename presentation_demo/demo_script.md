# Faculty Project Demonstration Script & Defense Guide

**Project:** SDN-Based DDoS Detection and Automatic Mitigation using Ryu Controller and Machine Learning  
**Presenter:** Project Lead / Candidate  
**Target Audience:** Project Review Committee / External Examiners / College Faculty  
**Total Demo Time:** 10 - 15 Minutes  

---

## 1. Setup Before Calling the Committee
1. Open three terminal windows (or tabs):
   - **Terminal 1**: System Startup / Controller / Mininet
   - **Terminal 2**: Traffic Generator (Attack Commands)
   - **Terminal 3**: Log monitoring / Test suite
2. Open your web browser to: `http://localhost:5000` (The Web Dashboard).
3. Ensure the dashboard shows: `Status: NORMAL`, `ML Engine: Active`, `Blocked Hosts: 0`.

---

## 2. Step-by-Step Live Demonstration

### Step 1: Explain the Topology & Architecture (2 Minutes)
- **What to say**:  
  *"Good morning respected committee members. Our project addresses DDoS security in next-generation networks using Software-Defined Networking. Here in Mininet, we have 4 OpenFlow 1.3 switches: a Core switch S1 connected to three edge switches: S2 for attackers, S3 for our protected Web and DNS servers, and S4 for legitimate clients. Traffic is monitored every 3 seconds by the Ryu controller."*
- **Action**: Point to the architecture diagram on the slide or dashboard.

---

### Step 2: Show Normal Benign Traffic (2 Minutes)
- **Command (Terminal 2 or Mininet CLI)**:
  ```bash
  # Inside Mininet CLI:
  mininet> h6 ./traffic/normal_traffic.sh 30 &
  mininet> h7 ping -c 4 10.0.0.4
  ```
  *(Or if demonstrating standalone / simulation mode: click "Benign Traffic Burst" on the dashboard toolbar).*
- **What to point out on screen**:
  - The dashboard packet rate hovers at a healthy baseline ($\approx 30 - 80\text{ pps}$).
  - Source IP entropy $H(\text{Src})$ is high ($\approx 1.8 - 2.0$), indicating diverse benign clients.
  - The Status Badge stays **GREEN (NORMAL)**.
  - Zero hosts are blocked. Normal web queries succeed.

---

### Step 3: Launch TCP SYN Flood Attack (3 Minutes)
- **Command (Terminal 2 or Mininet CLI)**:
  ```bash
  # Inside Mininet CLI:
  mininet> h1 ./traffic/attack_traffic.sh syn 10.0.0.4 20
  ```
  *(Or on dashboard: click "Simulate SYN Flood (10.0.0.1)").*
- **What to observe and explain**:
  1. **Traffic Surge**: The live chart immediately spikes from $50\text{ pps}$ to over $5,000\text{ pps}$.
  2. **Entropy Drop**: Destination entropy drops to $0.00$ because all traffic is targeted at $10.0.0.4$.
  3. **ML Classification**: Within one polling cycle ($\approx 3.2\text{s}$), the Random Forest model detects the anomaly with 100% confidence.
  4. **Dynamic Flow Rule**: The status banner turns **FLASHING RED ("DDoS ATTACK DETECTED")**.
  5. **Edge Mitigation**: Ryu injects an `OFPFlowMod` entry (`priority=65535, match: ipv4_src=10.0.0.1 -> ipv4_dst=10.0.0.4, instructions=[]`) into Switch S2.
  6. **Immediate Rate Drop**: In the next polling cycle, traffic rate plunges back to normal.
  7. **Table of Blocked Hosts**: IP `10.0.0.1` appears in the Blocked Table with a 30-second live countdown timer!
  8. **Audit Log**: A CRITICAL alert is logged with the timestamp and packet count.

---

### Step 4: Verify Benign Host Access During Attack (1 Minute)
- **Command (Terminal 2 or Mininet CLI)**:
  ```bash
  # Benign host h6 tries to reach victim server h4:
  mininet> h6 curl -s --connect-timeout 2 http://10.0.0.4/
  ```
- **What to explain**:
  *"Notice that legitimate host `h6` (`10.0.0.6`) can still access the server without any disruption. Our heavy-hitter algorithm only blocked the attacker `10.0.0.1`, preserving Quality of Service (QoS) for legitimate users."*

---

### Step 5: Test UDP and ICMP Floods (2 Minutes)
- **Command**:
  ```bash
  # Inside Mininet CLI:
  mininet> h2 ./traffic/attack_traffic.sh udp 10.0.0.5 15
  mininet> h3 ./traffic/attack_traffic.sh icmp 10.0.0.4 15
  ```
  *(Or on dashboard: click "Simulate UDP Flood" and "Simulate ICMP Flood").*
- **What to show**:
  - The system detects different protocols: Protocol Doughnut chart shows UDP and ICMP slices expanding.
  - The classifier correctly tags the attack signatures as "UDP Flood" and "ICMP Flood".
  - Attacker hosts `10.0.0.2` and `10.0.0.3` are dynamically quarantined.

---

### Step 6: Demonstrate Auto-Unblocking and Manual Override (1 Minute)
- **What to show**:
  - Watch the countdown timer reach 0 seconds. The controller automatically cleans the block state and logs `[INFO] Timeout expired. IP unblocked.`
  - Click the **"Unblock"** button on the UI for manual administrative override.

---

### Step 7: Run Automated Test Suite (1 Minute)
- **Command (Terminal 3)**:
  ```bash
  pytest tests/ -v
  ```
- **Result**:
  - 14 out of 14 unit tests pass in under 3 seconds, proving code quality, feature math correctness, and test coverage.

---

## 3. Anticipated Faculty Viva / Defense Questions & Answers

**Q1: Why did you choose Ryu instead of OpenDaylight or POX?**  
*Answer:* "Ryu is a pure Python OpenFlow 1.3 controller maintained by NTT. It provides native event-driven asynchronous threading (`eventlet` hubs), lightweight memory footprint, and full Python data science integration, allowing our scikit-learn models to execute in-memory with sub-millisecond inference latency."

**Q2: Why use Random Forest instead of Deep Learning (e.g., CNN or LSTM)?**  
*Answer:* "In SDN edge mitigation, inference latency is paramount. Random Forest achieves 100% accuracy on our statistical flow features with an inference latency of just $0.05\text{ ms}$ per sample, compared to tens of milliseconds for Deep Neural Networks. It requires negligible CPU overhead, preventing the controller itself from becoming a bottleneck during an attack."

**Q3: How does the switch drop packets without contacting the controller every time?**  
*Answer:* "We install a proactive `OFPFlowMod` entry with the highest priority ($65535$) directly into the Open vSwitch flow table with an empty instruction set (`instructions=[]`). Once installed, the switch hardware or Linux kernel datapath drops matching packets directly at line rate without generating any `Packet-In` events to the controller."

**Q4: How do you prevent attackers from spoofing legitimate IP addresses?**  
*Answer:* "When an attacker uses random IP spoofing (`--rand-source`), source IP entropy $H(\text{Src})$ spikes abnormally while destination entropy $H(\text{Dst})$ collapses to zero. The ML model detects this unique multi-feature signature. At the OpenFlow level, switch port-security can also cross-reference learned MAC and in-port mappings to drop forged source IPs at the physical port."

**Q5: What happens if the ML model file is corrupted or missing?**  
*Answer:* "Our controller includes an automatic heuristic fallback engine. If `model.pkl` is missing, the system falls back to configured statistical rate and entropy thresholds (`config.yaml`), ensuring uninterrupted fail-safe security."
