#!/usr/bin/env bash
# =============================================================================
# start_node_b.sh  —  One-shot startup for Node B (Kali Linux VMware VM)
# Usage:    bash /mnt/hgfs/IPS-Project/integration/node_b_suricata/start_node_b.sh
# =============================================================================

set -e

TOKEN="2233086f59c6a26313dffcc528250abd7f3deb5b9078cb84115cd0bb7ffac62b"
IPS_API="http://192.168.56.1:8765/suricata"
FORWARDER="/mnt/hgfs/IPS-Project/integration/node_a_suricata/eve_forwarder.py"

echo "========================================"
echo "  IPS Node B — Suricata Eve Forwarder  "
echo "========================================"
echo "  Token  : ${TOKEN:0:16}... (truncated)"
echo "  API URL : $IPS_API"
echo "========================================"

TOKEN_FILE="$HOME/node-b.token"
echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "[ok] Token saved to $TOKEN_FILE"

export IPS_NODE_TOKEN="$TOKEN"
export IPS_API_URL="$IPS_API"

echo "[ok] Starting forwarder…"
python3 "$FORWARDER"

