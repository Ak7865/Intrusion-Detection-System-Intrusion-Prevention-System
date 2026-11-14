# ML Detection Documentation

## Overview

The ML detection pipeline uses an ensemble of Random Forest and XGBoost models
trained on the CICIDS2017 dataset to classify network flows as benign or attack.

## Models

### Binary Classification (Attack vs Normal)

| Model         | File                                           | Accuracy       |
| ------------- | ---------------------------------------------- | -------------- |
| Random Forest | `ml/models/binary/binary_random_forest.joblib` | See reports    |
| XGBoost       | `ml/models/binary/binary_xgboost.json`         | See reports    |
| **Ensemble**  | RF + XGB averaged                              | Threshold: 0.5 |

The ensemble averages the attack probability from both models.
If the ensemble probability ≥ 0.5, the flow is classified as an attack.

### Multiclass Classification (Attack Type)

| Model         | File                                                           |
| ------------- | -------------------------------------------------------------- |
| Random Forest | `ml/models/multiclass/multiclass_random_forest.joblib`         |
| XGBoost       | `ml/models/multiclass/multiclass_xgboost.json`                 |
| Label Encoder | `ml/models/multiclass/multiclass_xgboost_label_encoder.joblib` |

Attack classes: `Normal`, `Botnet`, `Brute Force`, `DoS/DDoS`,
`Infiltration`, `PortScan`, `Web Attack`, `OTHER_RARE`

## Feature Schema

The models use 11 features from the CICIDS2017 deployment feature set:

| #   | Feature Name                | Unit         | Notes                                                     |
| --- | --------------------------- | ------------ | --------------------------------------------------------- |
| 1   | Destination Port            | integer      |                                                           |
| 2   | Flow Duration               | microseconds | CICFlowMeter outputs seconds; server converts × 1,000,000 |
| 3   | Total Fwd Packets           | count        |                                                           |
| 4   | Total Backward Packets      | count        |                                                           |
| 5   | Total Length of Fwd Packets | bytes        |                                                           |
| 6   | Total Length of Bwd Packets | bytes        |                                                           |
| 7   | Flow Bytes/s                | bytes/s      |                                                           |
| 8   | Flow Packets/s              | packets/s    |                                                           |
| 9   | Fwd Packets/s               | packets/s    |                                                           |
| 10  | Bwd Packets/s               | packets/s    |                                                           |
| 11  | Down/Up Ratio               | ratio        |                                                           |

**Feature compatibility:** `NOT_VERIFIED`

The live CICFlowMeter feature extraction has not been experimentally verified
to match the training dataset feature calculations. All ML predictions carry
this uncertainty warning.

## POST /flow Request Format

```json
{
  "src_ip": "192.168.56.129",
  "dst_ip": "192.168.56.1",
  "src_port": 54321,
  "dst_port": 8765,
  "protocol": "tcp",
  "timestamp": "2026-11-14T17:30:00Z",
  "flow_id": "optional-flow-id",
  "flow_duration": 1.5,
  "tot_fwd_pkts": 10,
  "tot_bwd_pkts": 8,
  "totlen_fwd_pkts": 1500,
  "totlen_bwd_pkts": 800,
  "flow_byts_s": 1533.33,
  "flow_pkts_s": 12.0,
  "fwd_pkts_s": 6.67,
  "bwd_pkts_s": 5.33,
  "down_up_ratio": 0.8
}
```

## Validation Rules

Before prediction:

- All features must be finite (no `inf`, `-inf`, `nan`)
- All features must be non-negative (≥ 0)
- Destination Port must be a valid integer

Invalid flows are rejected with HTTP 400.

## Confidence Score

The `ensemble_confidence` field in events represents the raw ensemble attack
probability (average of RF and XGBoost attack probabilities).

This is NOT a calibrated confidence score. It should not be interpreted as a
percentage certainty.

## CICFlowMeter Integration

### Python CICFlowMeter (tools/cicflowmeter-python)

The CICFlowMeter Python implementation is installed in `.venv/`.

To capture and submit flows on Linux Node A:

```bash
# Capture on interface eth1, submit flows every 30 seconds
python3 -m cicflowmeter -i eth1 -c /tmp/flows.csv
# Then parse flows.csv and POST each row to /flow
```

### Manual Flow Submission Script

A helper script for submitting CICFlowMeter CSV output:

```python
import csv, json, urllib.request

TOKEN = open('/etc/ips/node-a.token').read().strip()
API = 'http://192.168.56.1:8765/flow'

with open('/tmp/flows.csv') as f:
    for row in csv.DictReader(f):
        payload = {
            'src_ip': row['Src IP'],
            'dst_ip': row['Dst IP'],
            'src_port': int(row['Src Port']),
            'dst_port': int(row['Dst Port']),
            'protocol': row['Protocol'],
            'flow_duration': float(row['Flow Duration']) / 1_000_000,  # μs → s
            'tot_fwd_pkts': int(row['Tot Fwd Pkts']),
            'tot_bwd_pkts': int(row['Tot Bwd Pkts']),
            'totlen_fwd_pkts': float(row['TotLen Fwd Pkts']),
            'totlen_bwd_pkts': float(row['TotLen Bwd Pkts']),
            'flow_byts_s': float(row['Flow Byts/s']),
            'flow_pkts_s': float(row['Flow Pkts/s']),
            'fwd_pkts_s': float(row['Fwd Pkts/s']),
            'bwd_pkts_s': float(row['Bwd Pkts/s']),
            'down_up_ratio': float(row['Down/Up Ratio']),
        }
        req = urllib.request.Request(API, json.dumps(payload).encode(),
                                     headers={'Authorization': f'Bearer {TOKEN}',
                                              'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as r:
            print(r.read().decode())
```

## Model Reports

Detailed model performance metrics are in `ml/reports/`:

- `ml/reports/binary/binary_random_forest_metrics.json`
- `ml/reports/binary/binary_xgboost_metrics.json`
- `ml/reports/binary/ensemble/binary_soft_voting_ensemble_metrics.json`
- `ml/reports/multiclass/multiclass_random_forest_metrics.json`
- `ml/reports/multiclass/multiclass_xgboost_metrics.json`
- `ml/reports/multiclass/model_selection/multiclass_model_selection_report.md`
