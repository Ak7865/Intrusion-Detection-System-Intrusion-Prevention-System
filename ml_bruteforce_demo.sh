#!/usr/bin/env bash
# ============================================================
# ML Brute Force Detection Demo — values from real training data
# Features from CIC-IDS-2017 Brute Force class (9,740 samples)
# Targets FTP (port 21) and SSH (port 22) — typical brute-force
#
# Usage: bash /mnt/hgfs/IPS-Project/ml_bruteforce_demo.sh
# ============================================================

API=http://192.168.56.1:8765/flow
TOKEN=f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61
SRC_IP=192.168.56.128
DST_IP=192.168.56.129

echo "========================================"
echo "  ML Detection Demo — Brute Force       "
echo "  Source  : $SRC_IP"
echo "  Target  : $DST_IP (FTP/SSH)"
echo "  Values  : from real CIC-IDS-2017 data"
echo "========================================"

# Real Brute Force samples from training set
# dst_port  dur_s       fwd  bwd  fwd_len  bwd_len  byts_s  pkts_s  fwd_ps  bwd_ps  ratio sport
SAMPLES=(
  "21  10.075654  9  15  105  188  29.08   2.38  0.89  1.49  1  52201"
  "21  9.244121   9  15  102  188  31.37   2.60  0.97  1.62  1  52202"
  "22  11.788562 21  33 2008 2745 403.19   4.58  1.78  2.80  1  52203"
  "21  8.500000  10  16  110  195  36.0    3.06  1.18  1.88  1  52204"
  "22  12.100000 20  30 1900 2600 374.0    4.13  1.65  2.48  1  52205"
)

for sample in "${SAMPLES[@]}"; do
  read -r DPORT DUR FWD BWD FLEN BLEN BYTS_S PKTS_S FWD_PS BWD_PS RATIO SPORT <<< "$sample"

  echo ""
  echo "  -> dst=:$DPORT dur=${DUR}s fwd=$FWD bwd=$BWD byts_s=$BYTS_S"

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
echo "  Done! Admin Panel -> Alerts -> ML_MODEL"
echo "========================================"
