#!/usr/bin/env bash
# ================================================================
# IPS LAB STARTUP SCRIPT — works on Node A, B, and C
# Shared folder path: /mnt/hgfs/IPS-Project/start.sh
#
# USAGE (on any Kali VM terminal):
#   bash /mnt/hgfs/IPS-Project/start.sh
#
# This script will:
#   1. Detect which node this VM is (A, B, or C) by IP
#   2. Start Suricata on the detected interface
#   3. Start Juice Shop (Docker) if this is the VICTIM node
#   4. Start the Eve Forwarder with the correct token
# ================================================================

set -e

SHARED="/mnt/hgfs/IPS-Project"
IPS_API="http://192.168.56.1:8765/suricata"

# --- Node tokens (plaintext) ---
TOKEN_A="f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61"
TOKEN_B="2233086f59c6a26313dffcc528250abd7f3deb5b9078cb84115cd0bb7ffac62b"
TOKEN_C="e321ea0b804e0b76ae5f8db8f1cc2d25d3b14ba5479b5592f5a6c96d01e6103c"

# --- Detect this node's IP on the host-only network ---
MY_IP=$(ip addr show eth1 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
if [ -z "$MY_IP" ]; then
  MY_IP=$(ip addr show ens33 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
fi
if [ -z "$MY_IP" ]; then
  MY_IP=$(hostname -I | awk '{print $1}')
fi

echo "=================================================="
echo "  IPS Lab Node Startup"
echo "  Detected IP: $MY_IP"
echo "=================================================="

# --- Pick token and node label based on IP ---
case "$MY_IP" in
  192.168.56.128)
    NODE="A"
    TOKEN="$TOKEN_A"
    IS_VICTIM=false
    ;;
  192.168.56.129)
    NODE="B"
    TOKEN="$TOKEN_B"
    IS_VICTIM=true
    ;;
  192.168.56.130)
    NODE="C"
    TOKEN="$TOKEN_C"
    IS_VICTIM=false
    ;;
  *)
    echo "[warn] Unknown IP $MY_IP — defaulting to Node A token"
    NODE="A"
    TOKEN="$TOKEN_A"
    IS_VICTIM=false
    ;;
esac

echo "  Node    : $NODE"
echo "  Victim  : $IS_VICTIM"
echo "=================================================="

# --- STEP 1: Start Juice Shop if this is the victim node ---
if [ "$IS_VICTIM" = true ]; then
  echo ""
  echo "[1/3] Starting Juice Shop (victim target)..."
  if sudo docker ps 2>/dev/null | grep -q "3000"; then
    echo "      Juice Shop already running on port 3000."
  else
    sudo docker run -d -p 3000:3000 --name juice bkimminich/juice-shop 2>/dev/null \
      || sudo docker start juice 2>/dev/null \
      || echo "      [warn] Could not start Juice Shop. Start manually: sudo docker run -d -p 3000:3000 bkimminich/juice-shop"
    echo "      Waiting 30s for Juice Shop to boot..."
    sleep 30
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
      echo "      Juice Shop ready! http://$MY_IP:3000"
    else
      echo "      [warn] Juice Shop returned HTTP $HTTP_CODE — may still be starting"
    fi
  fi
else
  echo "[1/3] Skipping Juice Shop (not the victim node)"
fi

# --- STEP 2: Start Suricata ---
echo ""
echo "[2/3] Starting Suricata..."
if pgrep -x suricata > /dev/null 2>&1; then
  echo "      Suricata already running."
else
  IFACE="eth1"
  if ! ip link show "$IFACE" > /dev/null 2>&1; then
    IFACE=$(ip link | grep -v lo | awk -F: '/^[0-9]+:/{print $2}' | tr -d ' ' | head -1)
    echo "      eth1 not found, using interface: $IFACE"
  fi
  sudo suricata -c /etc/suricata/suricata.yaml -i "$IFACE" -D 2>/dev/null \
    && echo "      Suricata started on $IFACE (daemon mode)" \
    || {
      echo "      [warn] Daemon mode failed. Starting in background..."
      sudo suricata -c /etc/suricata/suricata.yaml -i "$IFACE" > /tmp/suricata.log 2>&1 &
      sleep 3
      echo "      Suricata launched. Logs: /tmp/suricata.log"
    }
fi

# --- STEP 3: Start Eve Forwarder ---
echo ""
echo "[3/3] Starting Eve Forwarder (Node $NODE -> $IPS_API)..."
export IPS_NODE_TOKEN="$TOKEN"
export IPS_API_URL="$IPS_API"

# Kill any existing stale forwarder instances
pkill -f eve_forwarder.py 2>/dev/null || true
sleep 1

echo ""
echo "=================================================="
echo "  All services started! Eve Forwarder running."
echo "  Admin Panel: http://192.168.56.1:3000"
echo "  API Health:  http://192.168.56.1:8765/api/health"
echo "=================================================="
echo ""

python3 "$SHARED/integration/node_a_suricata/eve_forwarder.py"

