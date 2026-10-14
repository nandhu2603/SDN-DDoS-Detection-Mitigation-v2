# System Architecture: SDN-Based DDoS Detection and Automatic Mitigation

## 1. Executive Architecture Overview

Software-Defined Networking (SDN) decouples network intelligence (the **Control Plane**) from physical packet forwarding hardware (the **Data Plane**). In this project, the control plane is implemented using the **Ryu SDN Controller** running the **OpenFlow 1.3** protocol, while the data plane consists of **Open vSwitch (OVS)** virtual switches instantiated inside **Mininet**. 

A real-time Machine Learning (ML) inference engine analyzes aggregated flow and port telemetry collected every 3 seconds. When volumetric anomalies (SYN Flood, UDP Flood, or ICMP Flood) are identified, the controller autonomously synthesizes and pushes high-priority `OFPFlowMod` DROP rules directly to the edge switches. This blocks the malicious attack at the network periphery before it exhausts switch flow tables, controller bandwidth, or server resources.

---

## 2. End-to-End System Diagram

```mermaid
flowchart TD
    subgraph Management_Layer ["Management & Visualization Plane"]
        UI["Web Dashboard (Chart.js / HTML5)"]
        API["Flask REST API (:5000)"]
        UI <-->|HTTP GET/POST (JSON)| API
    end

    subgraph Control_Layer ["SDN Control Plane (Ryu Controller :6653)"]
        RYU["Ryu Core OpenFlow 1.3 App"]
        L2["L2 Learning Switch Engine"]
        POLL["Async Stats Poller (hub.spawn 3s)"]
        FEAT["Feature Extractor (Entropy & Rates)"]
        
        subgraph Detection_Engine ["Detection Engine"]
            ML["Random Forest Classifier (model.pkl)"]
            FALLBACK["Heuristic Threshold Engine"]
        end
        
        MIT["Mitigation Engine (FlowMod Manager)"]
        STATE["JSON State Synchronizer"]
        
        RYU --> L2
        POLL -->|OFPFlowStatsRequest| RYU
        RYU -->|OFPFlowStatsReply| FEAT
        FEAT -->|11-D Feature Vector| Detection_Engine
        Detection_Engine -->|ATTACK Detected| MIT
        MIT -->|OFPFlowMod DROP| RYU
        MIT -->|Log Alert / Block Host| STATE
        STATE -->|Export logs/controller_state.json| API
    end

    subgraph Data_Layer ["SDN Data Plane (Mininet / Open vSwitch)"]
        S1["Core Switch (s1)"]
        S2["Edge Switch 1 (s2 - Attackers)"]
        S3["Edge Switch 2 (s3 - Server Farm)"]
        S4["Edge Switch 3 (s4 - Benign Users)"]
        
        S1 <--> S2
        S1 <--> S3
        S1 <--> S4
        
        H1["Attacker h1\n10.0.0.1"] -->|SYN Flood| S2
        H2["Attacker h2\n10.0.0.2"] -->|UDP Flood| S2
        H3["Attacker h3\n10.0.0.3"] -->|ICMP Flood| S2
        
        S3 --> H4["Victim Web Server h4\n10.0.0.4:80"]
        S3 --> H5["Victim DNS Server h5\n10.0.0.5:53"]
        
        H6["Benign h6\n10.0.0.6"] -->|Legitimate Web| S4
        H7["Benign h7\n10.0.0.7"] -->|Legitimate DNS| S4
    end

    RYU <===>|OpenFlow 1.3 Control Channel| S1
    RYU <===>|OpenFlow 1.3 Control Channel| S2
    RYU <===>|OpenFlow 1.3 Control Channel| S3
    RYU <===>|OpenFlow 1.3 Control Channel| S4

    classDef normal fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef attack fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fef2f2;
    classDef safe fill:#064e3b,stroke:#22c55e,stroke-width:2px,color:#f0fdf4;
    
    class UI,API,RYU,L2,POLL,FEAT,ML,FALLBACK,MIT,STATE,S1,S2,S3,S4 normal;
    class H1,H2,H3 attack;
    class H4,H5,H6,H7 safe;
```

---

## 3. Mathematical Feature Formulation

The controller extracts an 11-dimensional feature vector $\mathbf{x} \in \mathbb{R}^{11}$ over sampling interval $\Delta t = 3.0\text{s}$:

1. **Packet Arrival Rate ($R_p$)**:
   $$\Delta P = \sum_{f \in \mathcal{F}_t} P(f) - \sum_{f \in \mathcal{F}_{t-\Delta t}} P(f), \quad R_p = \frac{\Delta P}{\Delta t}$$

2. **Byte Transfer Rate ($R_b$)**:
   $$\Delta B = \sum_{f \in \mathcal{F}_t} B(f) - \sum_{f \in \mathcal{F}_{t-\Delta t}} B(f), \quad R_b = \frac{\Delta B}{\Delta t}$$

3. **Packet Count per Active Flow**:
   $$\overline{P_f} = \frac{\sum_{f \in \mathcal{F}} P(f)}{|\mathcal{F}|}$$

4. **Byte Count per Active Flow**:
   $$\overline{B_f} = \frac{\sum_{f \in \mathcal{F}} B(f)}{|\mathcal{F}|}$$

5. **Average Flow Duration**:
   $$\overline{T_d} = \frac{1}{|\mathcal{F}|} \sum_{f \in \mathcal{F}} \text{duration}(f)$$

6. **Shannon Entropy of Source IP Addresses ($H_{\text{src}}$)**:
   Given $N$ packets observed with discrete source frequencies $p(s_i) = \frac{n(s_i)}{N}$:
   $$H_{\text{src}} = -\sum_{i=1}^{k} p(s_i) \log_2 p(s_i)$$
   *Under single/botnet attacks, $H_{\text{src}}$ drops sharply. Under random IP spoofing, $H_{\text{src}}$ spikes to maximum.*

7. **Shannon Entropy of Destination IP Addresses ($H_{\text{dst}}$)**:
   $$H_{\text{dst}} = -\sum_{j=1}^{m} q(d_j) \log_2 q(d_j)$$
   *During targeted DDoS floods, $H_{\text{dst}} \to 0$ because all attack traffic converges onto the victim ($10.0.0.4$).*

8. **Unique Source to Destination Fan-In Ratio**:
   $$\rho_{\text{fan}} = \frac{|\{s_i \in \text{Sources}\}|}{\max(1, |\{d_j \in \text{Destinations}\}|)}$$

9. **Protocol Ratios**:
   $$\text{Ratio}_{\text{TCP}} = \frac{N_{\text{TCP}}}{|\mathcal{F}|}, \quad \text{Ratio}_{\text{UDP}} = \frac{N_{\text{UDP}}}{|\mathcal{F}|}, \quad \text{Ratio}_{\text{ICMP}} = \frac{N_{\text{ICMP}}}{|\mathcal{F}|}$$

---

## 4. Mitigation Workflow & FlowMod Lifecycle

1. **Traffic Ingestion**: Hosts send packets; switches evaluate local OpenFlow pipeline tables.
2. **Periodic Polling**: Controller sends `OFPFlowStatsRequest` every $3$ seconds to all DPIDs.
3. **ML Inference**:
   $$\hat{y} = \text{RandomForestClassifier}(\text{StandardScaler}(\mathbf{x}))$$
4. **Offender Isolation**: The controller isolates heavy-hitter flows:
   $$\text{Attackers} = \{ s_i \mid P(s_i) \ge \max(300, 0.25 \times P_{\max}) \land s_i \notin \text{Whitelist} \}$$
5. **Flow Rule Injection**:
   - `Priority`: `65535` (maximum OpenFlow 1.3 priority, overriding normal L2 learning rules).
   - `Match`: `eth_type=0x0800, ipv4_src=AttackerIP, ipv4_dst=VictimIP`.
   - `Instructions`: `[]` (empty instruction set $\implies$ hardware DROP).
   - `Hard Timeout`: `30` seconds.
6. **Auto-Unblock**: Once the 30-second timer elapses, the OpenFlow switch purges the DROP rule, and normal communications can resume automatically.
