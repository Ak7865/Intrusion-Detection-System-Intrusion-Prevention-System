#!/usr/bin/env bash
# =============================================================================
# start_node_a.sh  —  One-shot startup for Node A (Kali Linux VMware VM)
# Run from: /mnt/hgfs/IPS-Project/integration/node_a_suricata/
# Usage:    bash /mnt/hgfs/IPS-Project/integration/node_a_suricata/start_node_a.sh
# =============================================================================

set -e

TOKEN="f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61"
IPS_API="http://192.168.56.1:8765/suricata"
FORWARDER="/mnt/hgfs/IPS-Project/integration/node_a_suricata/eve_forwarder.py"

echo "========================================"
echo "  IPS Node A — Suricata Eve Forwarder  "
echo "========================================"
echo "  Token  : ${TOKEN:0:16}... (truncated)"
echo "  API URL : $IPS_API"
echo "  Script  : $FORWARDER"
echo "========================================"

# Save token to home dir (no sudo needed)
TOKEN_FILE="$HOME/node-a.token"
echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "[ok] Token saved to $TOKEN_FILE"

# Export env for forwarder
export IPS_NODE_TOKEN="$TOKEN"
export IPS_API_URL="$IPS_API"

echo "[ok] Starting forwarder…"
python3 "$FORWARDER"

