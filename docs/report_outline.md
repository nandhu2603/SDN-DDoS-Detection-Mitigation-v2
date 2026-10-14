# Academic Project Report Outline

**Project Title:** SDN-Based DDoS Detection and Automatic Mitigation using Ryu Controller and Machine Learning  
**Target Domain:** Computer Science & Engineering / Information Technology / Cyber Security  
**Academic Level:** Bachelor of Technology (B.Tech) / Master of Science (M.S.) Thesis  

---

## Table of Contents

### Certificate & Declaration
- Bonafide Certificate signed by Guide and Head of Department (HOD)
- Student Declaration of Original Work
- Acknowledgements & Abstract

---

### Chapter 1: Introduction
- **1.1 Background & Motivation**: Limitations of traditional perimeter defenses (firewalls, static ACLs) against volumetric and distributed denial-of-service (DDoS) attacks.
- **1.2 Introduction to Software-Defined Networking (SDN)**: Control plane and data plane decoupling, OpenFlow protocol standards, centralized network visibility.
- **1.3 Problem Statement**: Vulnerability of SDN switches and controllers to high-rate resource exhaustion (flow table overflows, CPU starvation).
- **1.4 Objectives of the Project**:
  - Implement a multi-switch OpenFlow 1.3 topology in Mininet.
  - Develop periodic asynchronous flow telemetry collection in Ryu.
  - Formulate statistical and information-theoretic features (packet rates, Shannon entropy, fan-in ratios).
  - Train and evaluate multiple machine learning classifiers (Random Forest, Decision Tree, SVM).
  - Automate rapid edge mitigation via dynamic `OFPFlowMod` DROP rules with auto-unblock.
  - Build a live web dashboard for network operators.
- **1.5 Organization of the Report**.

---

### Chapter 2: Literature Review & Related Work
- **2.1 Evolution of DDoS Attacks**: SYN Floods, UDP Amplification, ICMP Ping Floods, Spoofed IP botnets.
- **2.2 Existing Traditional Solutions**: Static Rate Limiting, Deep Packet Inspection (DPI) bottlenecks, Scrubbing centers.
- **2.3 SDN-Based Security Solutions**: Review of OpenFlow anomaly detection frameworks (NOX, POX, Floodlight, Ryu, ONOS).
- **2.4 Machine Learning in Network Intrusion Detection**: Review of SVM, Decision Trees, Ensemble Random Forests, and Deep Learning approaches.
- **2.5 Research Gap**: Need for lightweight, low-latency, real-time edge mitigation without controller saturation.

---

### Chapter 3: System Architecture & Mathematical Methodology
- **3.1 Architecture Overview**: Management Plane, Control Plane, and Data Plane interaction.
- **3.2 OpenFlow 1.3 Communication Protocol**:
  - Packet-In, Flow-Mod, Flow-Stats-Request, Flow-Stats-Reply.
- **3.3 Feature Engineering**:
  - Delta Rate Calculation ($\Delta P / \Delta t$, $\Delta B / \Delta t$).
  - Shannon Entropy of Source and Destination IP addresses ($H_{\text{src}}$, $H_{\text{dst}}$).
  - Unique source fan-in ratio and protocol decomposition.
- **3.4 Machine Learning Classifiers**:
  - Random Forest Classifier (Bootstrap aggregation, Gini impurity).
  - Decision Tree Classifier (Information Gain baseline).
  - Support Vector Machine with Radial Basis Function (RBF) Kernel.
- **3.5 Mitigation Strategy**:
  - Heavy-hitter isolation algorithm.
  - High-priority DROP flow rules (`priority=65535`, `instructions=[]`).
  - Timeout lifecycle management and whitelist defense.

---

### Chapter 4: Implementation Details
- **4.1 Network Topology Setup (`topology/custom_topo.py`)**:
  - 1 Controller, 4 Open vSwitch instances (1 Core, 3 Edge), 9 Hosts.
- **4.2 Ryu Controller Implementation (`controller/ddos_controller.py`)**:
  - L2 Learning Switch, hub-thread timer loop, OpenFlow message handlers.
- **4.3 Traffic Generation Suite (`traffic/`)**:
  - Benign traffic (HTTP, DNS, Ping) vs Attack traffic (`hping3`, Scapy, Python sockets).
- **4.4 Machine Learning Pipeline (`ml/`)**:
  - Dataset collection, normalization with `StandardScaler`, model persistence (`joblib`).
- **4.5 Real-Time Web Monitoring Dashboard (`dashboard/`)**:
  - Flask REST API, Chart.js time-series charts, table of active flow blocks, manual override.

---

### Chapter 5: Experimental Results & Performance Analysis
- **5.1 Dataset Characteristics**: 3,000 samples, class balance, protocol breakdown.
- **5.2 ML Model Comparison**:
  - Accuracy, Precision, Recall, F1-Score, and ROC-AUC table.
  - Confusion Matrix analysis for Random Forest.
  - Receiver Operating Characteristic (ROC) curve analysis.
  - Feature Importance ranking (Relative Gini Index).
- **5.3 Real-Time Detection Latency**:
  - Average time between attack onset and flow rule installation ($\approx 3.2\text{s}$).
- **5.4 Traffic Throughput Before and After Mitigation**:
  - Immediate packet drop at the edge switch; restoration of benign service.

---

### Chapter 6: Future Work
- **6.1 Multi-Controller & Distributed SDN**: High-availability clustering using Raft consensus.
- **6.2 P4 Programmable Data Planes**: In-switch line-rate feature extraction and mitigation without controller polling.
- **6.3 Deep Learning & Recurrent Neural Networks**: LSTM / GRU networks for temporal sequence anomaly detection.
- **6.4 Integration with Enterprise Controllers (ONOS, OpenDaylight)**.

---

### Chapter 7: Conclusion
- Summary of achievements, practical impact, and concluding remarks.

---

### References (IEEE Format)
- Relevant IEEE papers, ACM conference proceedings, and RFC standards (RFC 7426, RFC 7011).
