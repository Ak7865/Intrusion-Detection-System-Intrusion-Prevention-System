#!/usr/bin/env bash
# ============================================================
# NODE A QUICK START — Double-click or just type:
#   bash /mnt/hgfs/IPS-Project/start_node_a.sh
# ============================================================
export IPS_NODE_TOKEN=f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61
export IPS_API_URL=http://192.168.56.1:8765/suricata
python3 /mnt/hgfs/IPS-Project/integration/node_a_suricata/eve_forwarder.py

