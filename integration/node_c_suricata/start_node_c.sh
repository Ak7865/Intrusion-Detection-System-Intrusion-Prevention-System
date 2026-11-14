#!/usr/bin/env bash
# =============================================================================
# start_node_c.sh  —  One-shot startup for Node C (Kali Linux VMware VM)
# Usage:    bash /mnt/hgfs/IPS-Project/integration/node_c_suricata/start_node_c.sh
# =============================================================================

set -e

TOKEN="e321ea0b804e0b76ae5f8db8f1cc2d25d3b14ba5479b5592f5a6c96d01e6103c"
IPS_API="http://192.168.56.1:8765/suricata"
FORWARDER="/mnt/hgfs/IPS-Project/integration/node_a_suricata/eve_forwarder.py"

echo "========================================"
echo "  IPS Node C — Suricata Eve Forwarder  "
echo "========================================"
echo "  Token  : ${TOKEN:0:16}... (truncated)"
echo "  API URL : $IPS_API"
echo "========================================"

TOKEN_FILE="$HOME/node-c.token"
echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "[ok] Token saved to $TOKEN_FILE"

export IPS_NODE_TOKEN="$TOKEN"
export IPS_API_URL="$IPS_API"

echo "[ok] Starting forwarder…"
python3 "$FORWARDER"

