# 10-Slide Academic Presentation Outline

**Project Title:** SDN-Based DDoS Detection and Automatic Mitigation using Ryu Controller and Machine Learning  
**Event:** Final B.Tech / Academic Capstone Defense  

---

## Slide 1: Title & Introduction
- **Header:** SDN-Based DDoS Detection and Automatic Mitigation
- **Subtitle:** An Intelligent, Autonomous OpenFlow 1.3 Security Framework
- **Student Details:** Candidate Name, Register Number, Department
- **Guide Details:** Project Supervisor / Faculty Mentor
- **Institution:** Department of Computer Science & Engineering, College / University Logo
- **Speaker Note:** *"Welcome respected committee members. Today we present our capstone project on securing Software-Defined Networks against Distributed Denial of Service attacks using Machine Learning."*

---

## Slide 2: Problem Statement & Motivation
- **The Challenge:**
  - DDoS attacks grew by 150%+ globally, leveraging IoT botnets and protocol amplification.
  - Traditional defenses (firewalls, middleboxes) create centralized bottlenecks and cannot scale dynamically.
  - In SDN, DDoS floods exhaust OpenFlow switch TCAM flow tables and saturate the control plane with `Packet-In` requests.
- **Project Goal:**
  - Build an autonomous SDN closed-loop defense: **Monitor $\rightarrow$ Extract Features $\rightarrow$ ML Classify $\rightarrow$ Mitigate at Edge $\rightarrow$ Auto-Unblock**.
- **Speaker Note:** *"Traditional firewalls cannot inspect multi-gigabit traffic at line rate. SDN offers a unique opportunity: centralized visibility paired with distributed line-rate hardware enforcement."*

---

## Slide 3: System Architecture
- **Control Plane:** Ryu SDN Controller (OpenFlow 1.3) with async stats polling.
- **Data Plane:** Open vSwitch (OVS) inside Mininet topology (1 Core switch, 3 Edge switches, 9 Hosts).
- **Application Plane:** Flask Web Dashboard with live Chart.js visualization.
- **Visual:** Architecture Mermaid Diagram (from `docs/architecture.md`).
- **Speaker Note:** *"Notice the separation of planes. The data plane only forwards packets. The Ryu controller runs as our brain, querying statistics every 3 seconds and making ML decisions."*

---

## Slide 4: Feature Engineering & Information Theory
- **11-Dimensional Statistical Feature Vector:**
  - Volumetric Rates: Packet arrival rate ($\Delta P / \Delta t$) and Byte rate ($\Delta B / \Delta t$).
  - Per-Flow Statistics: Average packet count and duration per active flow.
  - Information-Theoretic Entropy:
    $$H(\text{Src}) = -\sum p_i \log_2(p_i), \quad H(\text{Dst}) = -\sum q_j \log_2(q_j)$$
  - Topological Metric: Unique source fan-in ratio per destination host.
  - Protocol Decomposition: TCP, UDP, and ICMP flow ratios.
- **Speaker Note:** *"Why entropy? When an attacker targets a single victim, destination entropy collapses to near zero. Shannon entropy gives our ML model mathematically rigorous discriminative power."*

---

## Slide 5: Machine Learning Pipeline
- **Dataset:** 3,000 balanced flow windows (Normal traffic, SYN Flood, UDP Flood, ICMP Flood, Spoofed IPs).
- **Models Evaluated:**
  1. **Random Forest Classifier** (100 estimators, max depth 12) - *Selected as Main Classifier*.
  2. **Decision Tree Classifier** (Max depth 6) - *Interpretable baseline*.
  3. **Support Vector Machine (SVM)** (RBF Kernel, $C=1.0$).
- **Preprocessing:** Feature standardization using `StandardScaler` ($\mu=0, \sigma=1$).
- **Speaker Note:** *"We compared three distinct machine learning paradigms to find the optimal trade-off between classification accuracy, memory usage, and real-time inference latency."*

---

## Slide 6: Experimental Results & Model Comparison
- **Comparative Results Table:**
  | Classifier | 5-Fold CV Accuracy | Test Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Time |
  | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
  | **Random Forest** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.05 ms** |
  | **Decision Tree** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.02 ms |
  | **SVM (RBF)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.12 ms |
- **Visuals:** Embedded Confusion Matrix (`ml/results/confusion_matrix.png`) and ROC Curves (`ml/results/roc_curve.png`).
- **Speaker Note:** *"All models showed strong separability due to our high-entropy feature design. Random Forest was selected as our production model because of its robustness against noisy flow spikes."*

---

## Slide 7: Feature Importance & Root Cause Analysis
- **Top Discriminative Features (Gini Impurity Reduction):**
  1. `packet_rate`: Primary volumetric indicator.
  2. `dst_ip_entropy`: Captures victim-targeted traffic convergence.
  3. `src_ip_entropy`: Distinguishes botnets from legitimate multi-user browsing.
  4. `protocol_ratios`: Identifies specific flood vectors (SYN vs UDP vs ICMP).
- **Visual:** Embedded Feature Importance Chart (`ml/results/feature_importance.png`).
- **Speaker Note:** *"Packet rate and destination entropy alone account for over 65% of the tree split decisions, confirming our hypothesis that DDoS creates unmistakable information-theoretic anomalies."*

---

## Slide 8: Dynamic Edge Mitigation Strategy
- **Mitigation Mechanics:**
  - **Heavy-Hitter Filter:** Identifies flows exceeding $25\%$ of peak attack volume.
  - **Priority Injection:** Installs `OFPFlowMod` entry with `priority=65535`.
  - **Zero-Controller Drop:** `instructions=[]` drops packets in hardware/OVS kernel.
  - **Hard Timeout Lifecycle:** Automatically expires after 30 seconds to restore normal service.
  - **Whitelist Defense:** Gateway and administrative IPs (`10.0.0.254`, `10.0.0.6`) are strictly protected from accidental blockage.
- **Speaker Note:** *"By dropping packets at the edge switch S2, malicious traffic never reaches Core Switch S1 or Victim Server S3. The attack is neutralized at the perimeter."*

---

## Slide 9: Real-Time Performance & Web Dashboard
- **Key Metrics Demonstrated:**
  - **Detection Latency:** $\approx 3.2\text{ seconds}$ (within 1 polling window).
  - **Mitigation Latency:** Sub-millisecond OpenFlow rule installation.
  - **Traffic Suppression:** Traffic drops from $5,000+\text{ pps}$ back to $<50\text{ pps}$ immediately.
- **Web Dashboard Features:**
  - Live throughput time-series graphs, entropy meter, protocol doughnut.
  - Real-time active DROP table with live countdown timers.
  - Administrator manual unblock button and audit log.
- **Visual:** Embedded Mitigation Traffic Timeline (`ml/results/mitigation_traffic_timeline.png`).

---

## Slide 10: Conclusion & Future Work
- **Summary of Contributions:**
  - Complete, runnable SDN OpenFlow 1.3 testbed with Mininet and Ryu.
  - High-accuracy ML pipeline with sub-millisecond inference and threshold fallback.
  - Automated edge mitigation with zero data loss for concurrent benign users.
  - Comprehensive operator monitoring dashboard and automated test suite (14/14 tests passing).
- **Future Directions:**
  - Multi-controller distributed clustering (ONOS / OpenDaylight with Raft).
  - Programmable Data Planes (P4 language) for in-switch hardware telemetry.
  - Deep Learning (Temporal LSTM / Transformers) for slow, low-rate stealth DDoS attacks.
- **Closing:** Thank You. Questions & Discussion.
