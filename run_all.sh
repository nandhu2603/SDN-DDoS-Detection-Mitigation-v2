#!/usr/bin/env bash
# ==============================================================================
# One-Command Startup Script: SDN DDoS Detection & Automatic Mitigation Lab
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PROJECT_ROOT}"

echo "======================================================================"
echo "   SDN DDoS Detection & Mitigation System - One-Command Startup"
echo "   Tech: Ryu (OF 1.3) + Mininet + Random Forest ML + Flask Dashboard"
echo "======================================================================"

# 1. Environment Verification
echo "[STEP 1/5] Checking Python environment and dependencies..."
PYTHON_BIN=$(command -v python3 || command -v python)
if [ -z "$PYTHON_BIN" ]; then
    echo "[ERROR] Python 3.9+ is required but not found in PATH."
    exit 1
fi

# 2. Model Verification & Training
if [ ! -f "ml/models/model.pkl" ] || [ ! -f "ml/models/scaler.pkl" ]; then
    echo "[STEP 2/5] ML model not found. Generating dataset and training models..."
    $PYTHON_BIN ml/train_model.py
    $PYTHON_BIN ml/evaluate.py
else
    echo "[STEP 2/5] Trained ML model and scaler verified."
fi

# 3. Clean up old locks / state files
mkdir -p logs
rm -f logs/controller_state.json.tmp

# 4. Start Flask Web Dashboard
echo "[STEP 3/5] Starting Web Monitoring Dashboard (http://localhost:5000)..."
$PYTHON_BIN dashboard/app.py > logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "  -> Dashboard running with PID: ${DASHBOARD_PID}"

# 5. Start Ryu SDN Controller
echo "[STEP 4/5] Starting Ryu SDN Controller (OF 1.3 on port 6653)..."
if command -v ryu-manager >/dev/null 2>&1; then
    ryu-manager --ofp-tcp-listen-port 6653 controller/ddos_controller.py > logs/controller.log 2>&1 &
    CONTROLLER_PID=$!
    echo "  -> Ryu Controller running with PID: ${CONTROLLER_PID}"
else
    echo "  -> [NOTICE] ryu-manager not found in PATH. Starting controller in simulation mode..."
    $PYTHON_BIN controller/ddos_controller.py --simulate > logs/controller.log 2>&1 &
    CONTROLLER_PID=$!
    echo "  -> Controller Simulation running with PID: ${CONTROLLER_PID}"
fi

# Clean up trap on exit
cleanup() {
    echo ""
    echo "[INFO] Shutting down SDN services..."
    kill -9 $DASHBOARD_PID 2>/dev/null || true
    kill -9 $CONTROLLER_PID 2>/dev/null || true
    if command -v mn >/dev/null 2>&1; then
        sudo mn -c >/dev/null 2>&1 || true
    fi
    echo "[INFO] Clean shutdown complete."
}
trap cleanup EXIT INT TERM

# 6. Start Mininet Topology (if Linux / Mininet available)
echo "[STEP 5/5] Launching Network Topology..."
if command -v mn >/dev/null 2>&1 && [ "$EUID" -eq 0 ]; then
    echo "  -> Mininet detected with root privileges. Starting OpenFlow 1.3 topology..."
    python3 topology/custom_topo.py 127.0.0.1 6653
elif command -v mn >/dev/null 2>&1; then
    echo "  -> Mininet requires sudo. Launching with sudo:"
    sudo python3 topology/custom_topo.py 127.0.0.1 6653
else
    echo ""
    echo "======================================================================"
    echo " [DEMO READY] Dashboard and Controller are active!"
    echo "   - Web Dashboard: http://127.0.0.1:5000"
    echo "   - Ryu OFP Port : 127.0.0.1:6653"
    echo "   - Logs         : logs/dashboard.log, logs/controller.log"
    echo ""
    echo " To run traffic tests:"
    echo "   - On Mininet: h1 ./traffic/attack_traffic.sh syn 10.0.0.4 20"
    echo "   - Or use the interactive buttons on the Web Dashboard!"
    echo " Press [Ctrl+C] to stop all services."
    echo "======================================================================"
    wait
fi
