#!/bin/bash
# Injects generated logs into the Wazuh agent container
# Usage: ./inject_logs.sh [log_file]

LOG_FILE=${1:-"logs/test.log"}
WAZUH_AGENT_CONTAINER="wazuh-agent"
WAZUH_LOG_PATH="/var/log/simulated_traffic.log"

echo "[*] Generating 10,000 test log lines..."
python simulation/log_generator.py --count 10000 --output $LOG_FILE --malicious-ratio 0.2

echo "[*] Copying log file into Wazuh agent container..."
docker cp $LOG_FILE $WAZUH_AGENT_CONTAINER:$WAZUH_LOG_PATH

echo "[*] Done. Wazuh agent is now monitoring $WAZUH_LOG_PATH"
echo "[*] Check Wazuh Dashboard for alerts at https://localhost"
