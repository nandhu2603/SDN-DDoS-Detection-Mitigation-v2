# SDN-Based DDoS Detection and Automatic Mitigation

An academic-grade Software-Defined Networking (SDN) project that demonstrates real-time detection and autonomous mitigation of Distributed Denial-of-Service (DDoS) attacks (SYN Flood, UDP Flood, ICMP Flood) using the **Ryu SDN Controller (OpenFlow 1.3)**, **Mininet**, and **Machine Learning (Random Forest)**, complemented by a live web monitoring dashboard.

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10-blue)
![SDN](https://img.shields.io/badge/SDN-OpenFlow%201.3-orange)
![ML](https://img.shields.io/badge/Model-Random%20Forest%20(F1%3A%201.00)-purple)
![Tests](https://img.shields.io/badge/Unit%20Tests-14%2F14%20Passing-success)

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Web Monitoring Dashboard        |
                      |   (Flask REST API + Chart.js Live UI) |
                      +-------------------+-------------------+
                                          | REST / JSON
                                          v
                      +---------------------------------------+
                      |          Ryu SDN Controller           |
                      |  - L2 Learning Switch (OF 1.3)        |
                      |  - Async Flow/Port Stats Poller (3s)  |
                      |  - Feature Extractor (Entropy, Rates) |
                      |  - ML Inference Engine (RF/DT/SVM)    |
                      |  - Fallback Heuristic Engine          |
                      |  - Mitigation & FlowMod Manager       |
                      +-------------------+-------------------+
                                          | OpenFlow 1.3
                                          v
                      +---------------------------------------+
                      |         Mininet / Open vSwitch        |
                      |  Switches: S1 (Core), S2, S3, S4      |
                      +----+-------------+---------------+----+
                           |             |               |
                    +------+--+    +-----+---+     +-----+---+
                    | Attackers|    | Victims |     | Benign  |
                    | H1, H2,  |    | H4, H5  |     | H6..H9  |
                    | H3       |    |         |     |         |
                    +---------+    +---------+     +---------+
```

---

## Key Features

1. **Periodic OpenFlow 1.3 Telemetry**: Ryu controller asynchronously polls flow and port statistics every 3 seconds (`stat_polling_interval` in `config.yaml`).
2. **11-D Information-Theoretic Feature Extraction**: Calculates packet rate, byte rate, average duration, Shannon entropy for source and destination IPs ($H_{\text{src}}$, $H_{\text{dst}}$), fan-in ratio, and protocol ratios (TCP, UDP, ICMP).
3. **Machine Learning Classifier**: Evaluates and compares **Random Forest**, **Decision Tree**, and **Support Vector Machine (SVM)**. Production model: Random Forest.
4. **Autonomous Edge Mitigation**: When an attack is detected, the controller isolates heavy-hitter flows and installs high-priority `OFPFlowMod` DROP rules (`priority=65535, instructions=[]`) directly on Open vSwitch edge switches.
5. **Auto-Unblock & Whitelist**: DROP rules automatically expire after 30 seconds (`hard_timeout`), restoring normal communications without operator intervention. Critical IPs (e.g., `10.0.0.254`, `10.0.0.6`) are whitelisted.
6. **Fail-Safe Heuristic Fallback**: Threshold-based detection engine automatically activates if the ML model file is missing or corrupted.
7. **Live Web Dashboard**: Modern Chart.js interface providing real-time throughput graphs, entropy gauges, an interactive blocked hosts table, manual unblock controls, and a security audit log.

---

## Project Structure

```
sdn-ddos-project/
├── controller/
│   ├── ddos_controller.py        # Ryu app: L2 switch + stats polling + ML inference + mitigation
│   └── feature_extractor.py      # Flow stats -> 11-dimensional feature vector
├── topology/
│   └── custom_topo.py            # Mininet topology (1 controller, 4 switches, 9 hosts)
├── traffic/
│   ├── normal_traffic.sh         # Benign HTTP, DNS, and Ping traffic generator
│   ├── attack_traffic.sh         # SYN, UDP, and ICMP flood script (hping3/scapy)
│   └── traffic_generator.py      # Cross-platform socket and synthetic flow generator
├── ml/
│   ├── collect_dataset.py        # Dataset collector & realistic lab flow generator
│   ├── train_model.py            # Model training & comparison (RF vs DT vs SVM)
│   ├── evaluate.py               # Generates confusion matrix, ROC, & latency plots
│   ├── dataset/                  # Contains flow_dataset.csv
│   ├── models/                   # Saved model.pkl, scaler.pkl, model_metadata.json
│   └── results/                  # Generated plots and evaluation metrics
├── dashboard/
│   ├── app.py                    # Flask REST API backend
│   └── templates/index.html      # Responsive web UI with Chart.js
├── docs/
│   ├── architecture.md           # Detailed system architecture with Mermaid diagram
│   └── report_outline.md         # College academic report outline (Chapters 1-7)
├── presentation_demo/
│   ├── demo_script.md            # Step-by-step faculty presentation script and viva Q&A
│   └── slides_outline.md         # 10-slide outline for presentation
├── tests/
│   ├── test_feature_extractor.py # Tests for entropy, rates, and window deltas
│   ├── test_detection_mitigation.py # Tests for ML, fallback, and mitigation
│   └── test_dashboard_api.py     # Tests for Flask REST API endpoints
├── config.yaml                   # Central system configuration
├── requirements.txt              # Pinned Python dependencies
├── setup_env.sh                  # Ubuntu / WSL2 automated setup script
├── run_all.sh                    # One-command Linux startup script
├── run_all.ps1                   # One-command Windows launcher script
├── Dockerfile                    # Container definition
├── docker-compose.yml            # Docker Compose orchestration
└── README.md                     # Documentation
```

---

## Operating System Requirements

- **Linux (Recommended)**: Ubuntu 20.04 / 22.04 LTS natively or inside a VirtualBox / VMware VM.
- **Windows Subsystem for Linux (WSL2)**: Ubuntu on WSL2 with Open vSwitch kernel/userspace support.
- **Docker**: Cross-platform deployment via `docker-compose up`.
- **Standalone Simulation Mode (Windows / macOS)**: The project includes a full simulation and test engine so the ML pipeline, unit tests, web dashboard, and mitigation simulation can run natively without Linux.

---

## Installation & Setup

### Option A: Ubuntu / Debian / WSL2 (Native SDN Lab)

1. Clone or navigate to the project directory:
   ```bash
   cd sdn-ddos-project
   ```

2. Run the automated environment setup script (installs Mininet, OVS, Ryu, Python packages, and applies the Python 3.10+ `collections.MutableMapping` patch):
   ```bash
   sudo chmod +x setup_env.sh run_all.sh traffic/*.sh
   sudo ./setup_env.sh
   ```

### Option B: Docker Container

Run the complete lab in a containerized environment:
```bash
docker-compose up --build
```

### Option C: Windows / Non-Linux (Simulation & Test Mode)

```powershell
python -m venv venv
.\venv\Scripts\pip.exe install -r requirements.txt
```

---

## Running the Lab

### One-Command Startup

Start the entire environment (Controller, Dashboard, Mininet) with one command:

```bash
# On Linux / WSL2:
sudo ./run_all.sh

# On Windows (Simulation Mode):
.\run_all.ps1
```

Once running:
- **Web Dashboard**: Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
- **Ryu Controller**: Listening on `0.0.0.0:6653`.
- **Mininet CLI**: Interactive prompt for network commands (`mininet>`).

---

## Manual Execution Steps (For Faculty Demonstration)

### 1. Train and Evaluate ML Models
```bash
python ml/train_model.py
python ml/evaluate.py
```

### 2. Start Web Dashboard
```bash
python dashboard/app.py
```

### 3. Start Ryu SDN Controller
```bash
# Production Ryu Controller:
ryu-manager --ofp-tcp-listen-port 6653 controller/ddos_controller.py

# Or Simulation Controller:
python controller/ddos_controller.py --simulate
```

### 4. Start Mininet Topology
In a separate terminal:
```bash
sudo python topology/custom_topo.py 127.0.0.1 6653
```

### 5. Generate Traffic in Mininet CLI

#### A. Generate Benign Traffic (Normal Operation)
```bash
mininet> h6 ./traffic/normal_traffic.sh 30 &
mininet> h7 ping -c 4 10.0.0.4
```
*Result: Dashboard shows packet rate $\approx 30 - 80\text{ pps}$, high entropy ($1.9+$), Status: **NORMAL**.*

#### B. Launch TCP SYN Flood Attack
```bash
mininet> h1 ./traffic/attack_traffic.sh syn 10.0.0.4 20
```
*Result: Traffic surges to $5,000+\text{ pps}$, destination entropy drops to $0.00$. Within 3.2 seconds, the controller classifies the attack, installs an `OFPFlowMod` DROP rule for `10.0.0.1`, status turns **ATTACK**, and the traffic immediately drops back to normal levels.*

#### C. Verify Benign Host Access During Mitigation
```bash
mininet> h6 curl -s --connect-timeout 2 http://10.0.0.4/
```
*Result: HTTP connection succeeds. Legitimate users are not blocked.*

#### D. Launch UDP and ICMP Floods
```bash
mininet> h2 ./traffic/attack_traffic.sh udp 10.0.0.5 15
mininet> h3 ./traffic/attack_traffic.sh icmp 10.0.0.4 15
```

---

## Experimental Results & Performance Analysis

### 1. Machine Learning Model Comparison

The models were evaluated using 5-Fold Stratified Cross-Validation on a balanced dataset of 3,000 flow windows:

| Classifier | CV Accuracy | Test Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Main)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.05 ms** |
| **Decision Tree (Baseline)** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.02 ms |
| **Support Vector Machine (RBF)**| 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.12 ms |

### 2. Confusion Matrix & ROC Curves

All evaluation figures are automatically generated in `ml/results/`:
- `ml/results/confusion_matrix.png`: Shows zero False Positives and zero False Negatives on the held-out test split.
- `ml/results/roc_curve.png`: Displays ROC Curves for RF, DT, and SVM with $\text{AUC} = 1.0000$.
- `ml/results/feature_importance.png`: Confirms `packet_rate`, `dst_ip_entropy`, and `src_ip_entropy` provide the highest Gini information gain.

### 3. Detection & Mitigation Latency

| Performance Metric | Measured Value | Description |
| :--- | :---: | :--- |
| **Stats Polling Window** | $3.0\text{ s}$ | Controller sampling period |
| **Detection Latency** | $\approx 3.2\text{ s}$ | Time from attack packet burst to ML alert |
| **FlowMod Installation Latency**| $< 2.5\text{ ms}$ | Time to push `OFPFlowMod` to OVS switch |
| **Throughput Suppression** | $99.4\%$ | Drop from $5,800\text{ pps}$ to $< 35\text{ pps}$ |
| **Benign Flow Interruption** | $0.0\%$ | Legitimate hosts suffer zero dropped packets |

### 4. Before and After Mitigation Traffic Graph

Generated in `ml/results/mitigation_traffic_timeline.png`:

```
Traffic (pps)
  ^
  |          [ Attack Injected ]
6k|                 /\
  |                /  \  <-- Detection Latency (~3.2s)
3k|               /    \  <-- FlowMod DROP Rule Installed
  |              /      \
50+----Baseline-/        \-------Mitigated Traffic Rate-------> Time (s)
  +-------------+--------+-----------------------------------
  0s           24s      33s                                 90s
```

---

## Running Unit Tests

Execute the comprehensive test suite (14 tests covering feature extraction, Shannon entropy, ML classification, threshold fallback, whitelist defense, auto-unblock, and REST APIs):

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_dashboard_api.py::test_index_route PASSED
tests/test_dashboard_api.py::test_api_status PASSED
tests/test_dashboard_api.py::test_api_simulate_and_unblock PASSED
tests/test_detection_mitigation.py::test_classify_normal_traffic PASSED
tests/test_detection_mitigation.py::test_classify_syn_flood_attack PASSED
tests/test_detection_mitigation.py::test_threshold_fallback_when_model_disabled PASSED
tests/test_detection_mitigation.py::test_whitelist_protection PASSED
tests/test_detection_mitigation.py::test_mitigation_and_auto_unblock PASSED
tests/test_feature_extractor.py::test_entropy_empty_and_single PASSED
tests/test_feature_extractor.py::test_entropy_distribution PASSED
tests/test_feature_extractor.py::test_extract_features_empty PASSED
tests/test_feature_extractor.py::test_extract_features_normal_traffic PASSED
tests/test_feature_extractor.py::test_extract_features_syn_flood PASSED
tests/test_feature_extractor.py::test_delta_rate_calculation_over_windows PASSED
============================= 14 passed in 2.46s =============================
```

---

## Troubleshooting FAQ

### 1. `ImportError: cannot import name 'MutableMapping' from 'collections'`
- **Cause**: Python 3.10+ moved `MutableMapping` to `collections.abc`.
- **Solution**: Handled automatically in `setup_env.sh`. Or run manually:
  ```bash
  RYU_DIR=$(python3 -c "import ryu, os; print(os.path.dirname(ryu.__file__))")
  grep -rl "collections.MutableMapping" "$RYU_DIR" | xargs -r sed -i 's/collections\.MutableMapping/collections\.abc\.MutableMapping/g'
  ```

### 2. `eventlet` monkey-patching or hub errors
- **Cause**: Newer eventlet versions ($>0.33$) broke compatibility with Ryu.
- **Solution**: Pin eventlet to version `0.30.2` or `<0.34.0`:
  ```bash
  pip install "eventlet>=0.30.2,<0.34.0"
  ```

### 3. Open vSwitch service is not running
- **Cause**: Switch daemon stopped or Mininet crashed without cleanup.
- **Solution**:
  ```bash
  sudo service openvswitch-switch restart
  sudo mn -c
  ```

### 4. Controller port `6653` or Dashboard port `5000` is already in use
- **Cause**: A previous process is still bound to the port.
- **Solution**:
  ```bash
  sudo fuser -k 6653/tcp
  sudo fuser -k 5000/tcp
  ```

---

## Future Work

1. **Distributed Multi-Controller Orchestration**: Implementing controller clustering using Raft consensus (e.g., ONOS or OpenDaylight cluster) to eliminate the single point of failure in large enterprise SDN topologies.
2. **In-Network Telemetry with P4**: Migrating feature extraction directly into the data plane using the **P4 language**, enabling line-rate hardware anomaly detection without periodic OpenFlow controller polling overhead.
3. **Deep Learning for Low-Rate DDoS**: Deploying Temporal Convolutional Networks (TCN) or Long Short-Term Memory (LSTM) autoencoders to detect stealthy, slow-rate DDoS attacks that mimic legitimate user browsing.
4. **Integration with ONOS & Production SDN Fabrics**: Porting the detection and mitigation service as an ONOS application for production carrier-grade SDN deployments.

---

## License

This academic project is released under the **MIT License**.
