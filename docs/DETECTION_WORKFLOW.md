# Detection Workflow

## Primary Detection: Suricata

```
Network Traffic
      │
      ▼
Network Interface (Linux Node A, eth1)
      │
      ▼
Suricata IDS (signature-based, 8.0.7)
      │ Matches ET rules
      ▼
EVE JSON (/var/log/suricata/eve.json)
      │ event_type: "alert"
      ▼
eve_forwarder.py (tails eve.json)
      │ POST /suricata
      │ Authorization: Bearer <NODE_A_TOKEN>
      ▼
Central IPS API (server.py, 192.168.56.1:8765)
      │
      ├── Validate token (SHA-256 hash check)
      ├── Filter non-alert events
      ├── Deduplicate (180s window, flow-id + signature-id)
      ├── Classify: INFORMATIONAL (ET INFO prefix) or REQUIRES_REVIEW
      ├── Build event (schema_version 1.0)
      │
      ▼
hyperledger_events.jsonl (append-only, thread-safe)
      │
      ▼
GET /api/events (Admin Panel proxy)
      │
      ▼
Admin Panel → Threats → Alerts
```

### Suricata Event Classification

| Suricata Category | classification_status | attack_detected |
|---|---|---|
| ET INFO … | INFORMATIONAL | false |
| Any other alert | REQUIRES_REVIEW | false |
| (None — ML only) | MODEL_PREDICTED | true |

**IMPORTANT:** Suricata alerts do NOT set `attack_detected: true` by default.
They are classified as requiring human review.

---

## Secondary Detection: Machine Learning

```
Network Traffic
      │
      ▼
Suricata inspection (above)
      │ No matching rule / No alert generated
      ▼
CICFlowMeter (Python, tools/cicflowmeter-python)
      │ Extracts 11 flow features
      ▼
Feature extraction:
  - Destination Port
  - Flow Duration (microseconds)
  - Total Fwd Packets
  - Total Backward Packets
  - Total Length of Fwd Packets
  - Total Length of Bwd Packets
  - Flow Bytes/s
  - Flow Packets/s
  - Fwd Packets/s
  - Bwd Packets/s
  - Down/Up Ratio
      │
      ▼
POST /flow (Central IPS API)
      │
      ├── Validate features (no negatives, no infinity, no NaN)
      ├── Binary ensemble prediction (RF + XGBoost, threshold 0.5)
      │     "Normal" → benign_no_event (no event written)
      │     "Attack" → continue
      ├── Multiclass prediction (RF + XGBoost label encoder)
      │     → attack_type: DoS/DDoS | Brute Force | Web Attack | etc.
      ├── Build ML event (attack_detected: true)
      │
      ▼
hyperledger_events.jsonl
      │
      ▼
Admin Panel → Threats → Alerts (detection: ML_MODEL)
```

### ML Models

| Model | File | Purpose |
|---|---|---|
| Binary Random Forest | ml/models/binary/binary_random_forest.joblib | Is it an attack? |
| Binary XGBoost | ml/models/binary/binary_xgboost.json | Is it an attack? |
| Multiclass Random Forest | ml/models/multiclass/multiclass_random_forest.joblib | What type? |
| Multiclass XGBoost | ml/models/multiclass/multiclass_xgboost.json | What type? |
| Label Encoder | ml/models/multiclass/multiclass_xgboost_label_encoder.joblib | Decode class index |

**Attack classes (multiclass):** Normal, Botnet, Brute Force, DoS/DDoS, Infiltration, PortScan, Web Attack, OTHER_RARE

### Feature Compatibility Warning

> `FEATURE_COMPATIBILITY = "NOT_VERIFIED"`

The 11 deployment features were selected from the CICIDS2017 dataset.
Live CICFlowMeter output must be verified to match these features exactly
(same calculation method, same scale, same units) before ML predictions
can be considered reliable.

The server explicitly reports `feature_compatibility: NOT_VERIFIED` in all API responses.

---

## Suricata–ML Correlation

If a Suricata alert has already been received for a flow, the ML pipeline
does NOT generate a duplicate event for that flow.

The deduplication cache stores alert keys by (node_id, src_ip, dst_ip, src_port, dst_port, protocol)
for 180 seconds.

---

## Blockchain Status

All events are stored in `runtime/events/hyperledger_events.jsonl`.
No Hyperledger Fabric network is connected.
`blockchain_status` is reported as `PENDING_NOT_SUBMITTED`.

