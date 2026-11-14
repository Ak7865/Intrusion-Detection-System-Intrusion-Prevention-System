# System Architecture

## Overview

This project implements a **Decentralized, Self-Learning Intrusion Prevention System** with three independent applications.

```
┌─────────────────────┐     Network Traffic     ┌──────────────────────────┐
│  Attack Simulator   │ ──────────────────────► │   Detection System       │
│  (Windows EXE)      │                          │                          │
│                     │                          │  ┌──────────────────┐   │
│  Modes:             │                          │  │  Suricata IDS    │   │
│  - Normal Traffic   │                          │  │  (Linux Node A)  │   │
│  - SQL Injection    │                          │  └────────┬─────────┘   │
│  - Brute Force      │                          │           │ EVE JSON     │
│  - DoS / HiVol      │                          │  ┌────────▼─────────┐   │
└─────────────────────┘                          │  │  eve_forwarder   │   │
                                                 │  └────────┬─────────┘   │
                                                 │           │ POST         │
                                                 │  ┌────────▼─────────┐   │
                                                 │  │  Central IPS API │   │
                                                 │  │  (server.py)     │   │
                                                 │  │  192.168.56.1    │   │
                                                 │  │  :8765           │   │
                                                 │  └────────┬─────────┘   │
                                                 │           │              │
                                                 │  ┌────────▼─────────┐   │
                                                 │  │ ML Pipeline      │   │
                                                 │  │ (RF + XGBoost)   │   │
                                                 │  └────────┬─────────┘   │
                                                 │           │              │
                                                 │  ┌────────▼─────────┐   │
                                                 │  │hyperledger_      │   │
                                                 │  │events.jsonl      │   │
                                                 └──┴────────┬──────────┘  │
                                                             │
                                                 ┌───────────▼─────────────┐
                                                 │   Admin Panel           │
                                                 │   (Next.js k-ra3p-ui)   │
                                                 │   Port 3001             │
                                                 └─────────────────────────┘
```

## Network Topology (Lab)

| Host | IP | Role |
|---|---|---|
| Windows Host | 192.168.56.1 | Central IPS API, ML models |
| Linux VM (Node A) | 192.168.56.128 | Suricata, CICFlowMeter |
| Target App (Juice Shop) | 192.168.56.129:3000 | Test target |

## Component Responsibilities

### Application 1: Attack Simulator (`attack_simulator/`)
- Standalone GUI desktop application
- Generates controlled test traffic only
- Does NOT write to JSONL event file
- Does NOT interact with the IPS API directly
- Restricted to private lab IP addresses

### Application 2: Detection Backend (`integration/`)
- **Suricata**: Signature-based detection (Linux Node A)
- **eve_forwarder.py**: Tails Suricata EVE JSON → POST to central API
- **server.py**: Central IPS API — receives Suricata events, runs ML inference
- **CICFlowMeter**: Flow feature extraction → POST /flow to central API
- Writes all events to `runtime/events/hyperledger_events.jsonl`

### Application 3: Admin Panel (`k-ra3p-ui/`)
- Next.js 14 web application
- Reads live data from Central IPS API via `/api/ips/*` proxy routes
- Displays real events, stats, and node information
- No hardcoded fake data

## Data Flow

```
Traffic → Network Interface
       → Suricata → EVE JSON → eve_forwarder.py → POST /suricata → server.py
       → CICFlowMeter → Flow Features → POST /flow → server.py → ML models
                                                                 ↓
                                                    hyperledger_events.jsonl
                                                                 ↓
                                                     GET /api/events
                                                                 ↓
                                                        Admin Panel
```

## Security Architecture

- Node authentication via pre-shared token hashes (SHA-256)
- Tokens stored in `.env` file, never in source code
- Admin Panel uses Next.js API proxy routes (tokens not exposed to browser)
- Attack Simulator only permits private IPv4 targets

## Blockchain Status

`hyperledger_events.jsonl` is the event storage file.
No live Hyperledger Fabric network is configured.
All `blockchain_status` fields are reported as `PENDING_NOT_SUBMITTED`.

