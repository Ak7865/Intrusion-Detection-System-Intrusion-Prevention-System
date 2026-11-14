# API Documentation

## Central IPS API — server.py

**Base URL:** `http://192.168.56.1:8765`

---

## Authentication

Endpoints that accept detection data require a node Bearer token:

```
Authorization: Bearer <node_token>
```

The token is hashed with SHA-256 and compared against `IPS_NODE_TOKEN_HASHES` in the `.env` file.

---

## Endpoints

### GET /health

Returns API and model status. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "models_loaded": true,
  "feature_compatibility": "NOT_VERIFIED",
  "service_role": "CENTRAL_ML_API",
  "node_authentication": "CONFIGURED",
  "event_file": "..."
}
```

---

### GET /api/health

Extended health check for Admin Panel integration.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-11-14T17:30:00Z",
  "models_loaded": true,
  "event_file_exists": true,
  "blockchain_status": "PENDING_NOT_SUBMITTED"
}
```

---

### GET /api/stats

Returns dashboard statistics computed from `hyperledger_events.jsonl`.

**Response:**
```json
{
  "total_events": 42,
  "suricata_detections": 30,
  "ml_detections": 12,
  "informational_alerts": 5,
  "events_requiring_review": 15,
  "attack_events": 10,
  "active_nodes": 1,
  "recent_events": [...]
}
```

---

### GET /api/events

Returns paginated events from the JSONL file (most recent first).

**Query Parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number |
| `page_size` | int | 50 | Events per page (max 200) |
| `detection_method` | string | "" | Filter: `SURICATA` or `ML_MODEL` |

**Response:**
```json
{
  "total": 42,
  "page": 1,
  "page_size": 50,
  "events": [...]
}
```

---

### GET /api/nodes

Returns connected node information.

**Response:**
```json
{
  "nodes": [
    {
      "node_id": "NODE_A",
      "status": "online",
      "last_heartbeat": "2026-11-14T17:30:00Z",
      "first_seen": "2026-11-14T16:00:00Z",
      "role": "sensor"
    }
  ],
  "total": 1
}
```

---

### POST /suricata

Accepts a Suricata EVE JSON alert event. Requires authentication.

**Request body:** Raw Suricata EVE JSON object (event_type must be "alert")

**Response:**
```json
{"status": "suricata_event_written", "event_id": "evt-..."}
```

---

### POST /flow

Accepts CICFlowMeter flow features for ML prediction. Requires authentication.

**Request body:**
```json
{
  "src_ip": "192.168.56.129",
  "dst_ip": "192.168.56.1",
  "src_port": 54321,
  "dst_port": 8765,
  "protocol": "tcp",
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

**Response (benign):**
```json
{"status": "benign_no_event", "prediction": "Normal"}
```

**Response (attack):**
```json
{
  "status": "attack_event_written",
  "event_id": "evt-...",
  "ml_prediction_id": "ml-pred-...",
  "feature_compatibility": "NOT_VERIFIED",
  "warning": "ML output is experimental..."
}
```

---

## Event Schema (hyperledger_events.jsonl)

Each line is a valid JSON object with this schema:

```json
{
  "schema_version": "1.0",
  "event_id": "evt-<uuid>",
  "event_type": "INTRUSION_DETECTION",
  "timestamp": "<ISO 8601>",
  "organisation": {
    "organisation_id": "ORG_A",
    "organisation_name": "Organisation A",
    "node_id": "NODE_A"
  },
  "detection": {
    "detection_source": "SURICATA | ML_MODEL",
    "attack_detected": true,
    "classification_status": "REQUIRES_REVIEW | INFORMATIONAL | MODEL_PREDICTED",
    "classification_basis": "...",
    "attack_type": "...",
    "suricata": { ... },
    "machine_learning": { ... }
  },
  "network": {
    "source_ip": "...",
    "source_port": 12345,
    "destination_ip": "...",
    "destination_port": 80,
    "protocol": "TCP"
  },
  "response": {
    "recommended_action": "REVIEW_AND_CONSIDER_BLOCK",
    "actual_block_status": "NOT_EXECUTED"
  },
  "evidence": { ... }
}
```

## Admin Panel Proxy

The Next.js Admin Panel proxies API calls through:

```
/api/ips/<path> → <IPS_API_URL>/api/<path>
```

This avoids exposing the backend URL and node tokens to the browser.

