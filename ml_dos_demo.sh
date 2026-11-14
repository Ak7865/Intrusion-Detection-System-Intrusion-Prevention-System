#!/usr/bin/env bash
# ============================================================
# ML DoS/DDoS Detection Demo — values from real training data
# Features from CIC-IDS-2017 DoS/DDoS class (263,604 samples)
#
# Note: flow_duration is sent in SECONDS to the API.
#       server.py multiplies by 1,000,000 → microseconds internally.
#
# Usage: bash /mnt/hgfs/IPS-Project/ml_dos_demo.sh
# ============================================================

API=http://192.168.56.1:8765/flow
TOKEN=f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61
SRC_IP=192.168.56.128    # Node A (attacker)
DST_IP=192.168.56.129    # Node B (victim / Juice Shop)

echo "========================================"
echo "  ML Detection Demo — DoS/DDoS Pattern "
echo "  Source  : $SRC_IP"
echo "  Target  : $DST_IP:80"
echo "  Values  : from real CIC-IDS-2017 data"
echo "========================================"

# Real DoS/DDoS samples from training set (duration in seconds = µs / 1,000,000)
# dst_port  dur_s       fwd  bwd  fwd_len  bwd_len  byts_s   pkts_s  fwd_ps  bwd_ps  ratio sport
SAMPLES=(
  "80  8.645389   7   5   50    11601  1347.65  1.39   0.81  0.58  0  52101"
  "80  83.622166  6   6   364   11595  143.01   0.14   0.07  0.07  1  52102"
  "80  0.905997   4   0   24    0      26.49    4.42   4.42  0.0   0  52103"
  "80  1.234567   5   2   40    8000   520.0    5.68   3.0   2.68  0  52104"
  "80  3.100000   8   3   60    9500   700.0    3.55   2.58  0.97  0  52105"
)

for sample in "${SAMPLES[@]}"; do
  read -r DPORT DUR FWD BWD FLEN BLEN BYTS_S PKTS_S FWD_PS BWD_PS RATIO SPORT <<< "$sample"

  echo ""
  echo "  → dst=:$DPORT dur=${DUR}s fwd_pkts=$FWD byts_s=$BYTS_S"

  RESPONSE=$(curl -s -X POST "$API" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"src_ip\":\"$SRC_IP\",
      \"dst_ip\":\"$DST_IP\",
      \"src_port\":$SPORT,
      \"dst_port\":$DPORT,
      \"protocol\":\"tcp\",
      \"flow_duration\":$DUR,
      \"tot_fwd_pkts\":$FWD,
      \"tot_bwd_pkts\":$BWD,
      \"totlen_fwd_pkts\":$FLEN,
      \"totlen_bwd_pkts\":$BLEN,
      \"flow_byts_s\":$BYTS_S,
      \"flow_pkts_s\":$PKTS_S,
      \"fwd_pkts_s\":$FWD_PS,
      \"bwd_pkts_s\":$BWD_PS,
      \"down_up_ratio\":$RATIO
    }")

  echo "  Response: $RESPONSE"
  sleep 3
done

echo ""
echo "========================================"
echo "  Done! Admin Panel → Alerts → ML_MODEL"
echo "========================================"
