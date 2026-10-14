#!/usr/bin/env bash
# ==============================================================================
# Environment Setup Script for Ubuntu / Debian / WSL2
# Installs Mininet, Open vSwitch, Ryu SDN Controller, and Python Dependencies
# ==============================================================================

set -e

echo "======================================================================"
echo "   Setting up SDN DDoS Lab Environment (Linux / WSL2 / Ubuntu)"
echo "======================================================================"

# Require root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run setup_env.sh as root (e.g., sudo ./setup_env.sh)"
    exit 1
fi

echo "[1/5] Updating APT package repositories..."
apt-get update -y

echo "[2/5] Installing core networking and development packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    openvswitch-switch \
    mininet \
    hping3 \
    iperf \
    curl \
    net-tools \
    tcpdump \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev

echo "[3/5] Starting and enabling Open vSwitch service..."
service openvswitch-switch start || systemctl start openvswitch-switch || true
ovs-vsctl show || true

echo "[4/5] Installing Python libraries and handling Ryu/eventlet compatibility..."
python3 -m pip install --upgrade pip setuptools wheel

# Install eventlet pin compatible with Ryu
python3 -m pip install "eventlet>=0.30.2,<0.34.0"

# Install requirements
python3 -m pip install -r requirements.txt

# Patch Ryu for Python 3.10+ MutableMapping issue if present
echo "[5/5] Checking and patching Ryu Python 3.10+ compatibility..."
RYU_DIR=$(python3 -c "import ryu, os; print(os.path.dirname(ryu.__file__))" 2>/dev/null || true)
if [ -n "$RYU_DIR" ]; then
    echo "  Found Ryu installation at: ${RYU_DIR}"
    grep -rl "collections.MutableMapping" "${RYU_DIR}" 2>/dev/null | xargs -r sed -i 's/collections\.MutableMapping/collections\.abc\.MutableMapping/g' || true
    grep -rl "collections.Mapping" "${RYU_DIR}" 2>/dev/null | xargs -r sed -i 's/collections\.Mapping/collections\.abc\.Mapping/g' || true
    grep -rl "collections.Iterable" "${RYU_DIR}" 2>/dev/null | xargs -r sed -i 's/collections\.Iterable/collections\.abc\.Iterable/g' || true
    echo "  Ryu compatibility patch applied successfully."
fi

# Clean mininet state
mn -c >/dev/null 2>&1 || true

echo "======================================================================"
echo " [SUCCESS] SDN DDoS Lab environment is fully configured!"
echo "   - Mininet version: $(mn --version 2>/dev/null || echo 'Installed')"
echo "   - Ryu controller:  $(ryu-manager --version 2>/dev/null || echo 'Installed')"
echo "   - Open vSwitch:    $(ovs-vsctl --version | head -n 1)"
echo ""
echo " You can now start the entire lab with:"
echo "   sudo ./run_all.sh"
echo "======================================================================"
