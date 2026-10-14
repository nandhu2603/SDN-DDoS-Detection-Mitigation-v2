#!/usr/bin/env bash
# ==============================================================================
# Benign Traffic Generator for SDN Mininet Lab
# Simulates legitimate user activity: HTTP requests, ping probes, iperf streams
# ==============================================================================

VICTIM_WEB="10.0.0.4"
VICTIM_DNS="10.0.0.5"
DURATION=${1:-60} # Duration in seconds, default 60s

echo "=========================================================="
echo "[INFO] Starting Benign Traffic Generation (Duration: ${DURATION}s)"
echo "[INFO] Target Web Server: ${VICTIM_WEB}:80"
echo "[INFO] Target DNS/UDP Server: ${VICTIM_DNS}:53"
echo "=========================================================="

END_TIME=$((SECONDS + DURATION))

while [ $SECONDS -lt $END_TIME ]; do
    # 1. Benign Web Requests (simulating user browsing)
    echo "[BENIGN] Generating HTTP GET request to ${VICTIM_WEB}..."
    curl -s --connect-timeout 2 "http://${VICTIM_WEB}/" > /dev/null 2>&1 || true
    
    # 2. Benign ICMP ping echo probes
    echo "[BENIGN] Sending ICMP ping to ${VICTIM_WEB}..."
    ping -c 2 -W 1 "${VICTIM_WEB}" > /dev/null 2>&1 || true

    # 3. Benign small UDP transfers (e.g., DNS queries / telemetry)
    echo "[BENIGN] Sending benign UDP packet burst to ${VICTIM_DNS}..."
    if command -v nc >/dev/null 2>&1; then
        echo "benign_dns_query_payload" | nc -u -w1 "${VICTIM_DNS}" 53 > /dev/null 2>&1 || true
    fi

    # Random jitter between benign requests (0.5 to 2.0 seconds)
    SLEEP_TIME=$(awk -v min=0.5 -v max=2.0 'BEGIN{srand(); print min+rand()*(max-min)}')
    sleep "${SLEEP_TIME}"
done

echo "=========================================================="
echo "[INFO] Benign traffic generation completed successfully."
echo "=========================================================="
