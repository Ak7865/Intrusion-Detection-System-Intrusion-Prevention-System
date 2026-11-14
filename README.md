# 🛡️ Decentralized Self-Learning Intrusion Prevention System

### Using Machine Learning and Blockchain

> **IPS Project** — A three-application system: Attack Simulator, ML+Suricata Detection Backend, and an Admin Panel, built for a decentralized lab environment using VMware, Python, and Next.js.

---

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WINDOWS HOST (192.168.56.1)              │
│                                                             │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │  Attack Simulator │    │   Admin Panel (Next.js)      │  │
│  │  (IPS_Attack_     │    │   http://localhost:3000       │  │
│  │   Simulator.exe)  │    │   - Live alerts              │  │
│  │  Modes:           │    │   - Node approval UI         │  │
│  │  · Normal Traffic │    │   - Blocked IPs              │  │
│  │  · SQL Injection  │    │   - ML/Suricata events       │  │
│  │  · Brute Force    │    └──────────────┬───────────────┘  │
│  │  · DoS            │                   │ polls /api/ips/  │
│  └────────┬──────────┘    ┌──────────────▼───────────────┐  │
│           │ HTTP traffic   │  Central IPS API (server.py) │  │
│           │               │  http://192.168.56.1:8765     │  │
│           │               │  Endpoints:                  │  │
│           │               │  · POST /suricata (node events)│ │
│           │               │  · POST /flow (ML features)  │  │
│           │               │  · GET  /api/events          │  │
│           │               │  · GET  /api/stats           │  │
│           │               │  · GET  /api/nodes           │  │
│           │               │  · POST /api/block /unblock  │  │
│           │               │  · POST /api/nodes/approve   │  │
│           │               └──────────────┬───────────────┘  │
└───────────┼──────────────────────────────┼──────────────────┘
            │                              │
            ▼                              ▼
┌────────────────────┐         ┌─────────────────────────────┐
│ Node B (Victim)    │         │  runtime/events/            │
│ 192.168.56.129     │         │  hyperledger_events.jsonl   │
│ · Juice Shop :3000 │         │  (append-only event log)    │
│ · Suricata eth1    │         │                             │
│ · eve_forwarder.py │──POST──▶│  ◀─────── BLOCKCHAIN ──────▶│
└────────────────────┘ /suricata│  TEAMMATE INTEGRATION POINT│
                                └─────────────────────────────┘
┌────────────────────┐
│ Node A (Attacker)  │
│ 192.168.56.128     │
│ · Suricata eth1    │──POST──▶ Central IPS API
│ · eve_forwarder.py │ /suricata
└────────────────────┘
```

---

## 📁 Repository Structure

```
IPS-Project/
├── README.md                          # This file
├── start.sh                           # 🚀 ONE-CMD startup for any Kali node
├── ml_dos_demo.sh                     # ML DoS detection demo script
├── ml_bruteforce_demo.sh              # ML Brute Force detection demo script
├── START_ALL_WINDOWS.bat              # 🖱️ Windows: start API + Admin Panel
├── START_IPS_SERVER.bat               # Windows: start API server only
├── START_ADMIN_PANEL.bat              # Windows: start Admin Panel only
│
├── attack_simulator/                  # 🎯 Application 1: Attack Simulator
│   ├── app.py                         # Main GUI entry point
│   ├── gui/                           # CustomTkinter UI components
│   ├── modules/simulators.py          # Traffic simulation logic
│   ├── config/simulator_config.json   # Authorized targets & settings
│   ├── simulator.spec                 # PyInstaller build spec
│   ├── build.bat                      # Build EXE script
│   └── dist/IPS_Attack_Simulator.exe  # ← Built EXE (not in git)
│
├── integration/
│   ├── node_a_suricata/
│   │   ├── eve_forwarder.py           # 📡 Suricata EVE → IPS API forwarder
│   │   └── start_node_a.sh            # Node A specific startup
│   ├── node_b_suricata/
│   │   └── start_node_b.sh            # Node B startup
│   ├── node_c_suricata/
│   │   └── start_node_c.sh            # Node C startup
│   └── windows_ml_service/
│       ├── server.py                  # 🧠 Central IPS API + ML inference
│       ├── suricata_rule_generator.py # Rule gen + BLOCKCHAIN STUB
│       └── .env                       # Node token hashes (not in git)
│
├── k-ra3p-ui/k-ra3p-ui/              # 🖥️ Application 3: Admin Panel
│   ├── app/(app)/
│   │   ├── dashboard/page.tsx         # Live stats
│   │   ├── threats/alerts/page.tsx    # Live alerts + Block IP button
│   │   ├── threats/blocked/page.tsx   # Blocked IPs management
│   │   ├── network/nodes/page.tsx     # Node registry + Approve/Reject
│   │   ├── network/traffic/page.tsx   # ML flow events
│   │   └── audit/page.tsx             # Full event log + Clear button
│   ├── lib/api.ts                     # TypeScript API client
│   └── .env.local                     # IPS_API_URL config
│
├── ml/
│   └── models/                        # Trained ML models (in git - small)
│       ├── binary/                    # Binary classifier (Attack/Normal)
│       └── multiclass/                # Attack category classifier
│
├── src/                               # ML training scripts
├── datasets/                          # Training data (NOT in git - too large)
├── runtime/
│   └── events/
│       ├── .gitkeep                   # Keeps folder in git
│       └── hyperledger_events.jsonl   # Event log (NOT in git)
├── config/                            # Suricata and system configs
├── docs/                              # Additional documentation
└── tools/                             # CICFlowMeter and other tools
```

---

## 🚀 Quick Start

### Windows (run first)

```bat
rem Double-click this file:
START_ALL_WINDOWS.bat
```

Opens two terminals: IPS API (port 8765) + Admin Panel (port 3000). Browser opens automatically.

### Kali Linux Nodes (run after Windows services are up)

```bash
# On EVERY node — auto-detects which node it is:
bash /mnt/hgfs/IPS-Project/start.sh
```

### Attack Simulator (Windows)

```
attack_simulator\dist\IPS_Attack_Simulator.exe
```

---

## 🎯 Application 1: Attack Simulator (Windows EXE)

**Location:** `attack_simulator/`  
**Built EXE:** `attack_simulator/dist/IPS_Attack_Simulator.exe`

### Build from source

```bat
cd attack_simulator
pip install -r requirements.txt
build.bat
```

### Simulation Modes

| Mode              | Target             | Detected By   | Purpose                   |
| ----------------- | ------------------ | ------------- | ------------------------- |
| Normal Traffic    | Juice Shop :3000   | Nothing       | Verify no false positives |
| SQL Injection     | Juice Shop /search | **Suricata**  | Signature detection test  |
| Brute Force       | Juice Shop /login  | ML + Suricata | Auth attack detection     |
| DoS / High-Volume | Any lab server     | **ML Model**  | Flow anomaly detection    |

> **Security:** Only RFC 1918 private IPs are permitted as targets. The simulator enforces this in `is_authorised_target()`.

---

## 🔍 Application 2: Detection System

### Suricata (on each Kali node)

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1
```

EVE JSON output: `/var/log/suricata/eve.json`

### Eve Forwarder (on each Kali node)

```bash
export IPS_NODE_TOKEN=<plaintext_token>
export IPS_API_URL=http://192.168.56.1:8765/suricata
python3 /mnt/hgfs/IPS-Project/integration/node_a_suricata/eve_forwarder.py
```

### Central IPS API (Windows)

```powershell
Set-Location d:\IPS-Lab\Shared\IPS-Project
.\.venv\Scripts\python.exe integration\windows_ml_service\server.py
```

### ML Models

- **Binary classifier:** Random Forest + XGBoost ensemble (`ml/models/binary/`)
- **Multiclass classifier:** Identifies DoS/DDoS, Brute Force, Botnet, Web Attack, etc.
- **Training data:** CIC-IDS-2017 (11 flow features from CICFlowMeter)
- **Accuracy:** ~99.6% on training distribution

---

## 🖥️ Application 3: Admin Panel

**URL:** http://localhost:3000  
**Tech:** Next.js 14, TypeScript, React

### Pages

| Page        | URL                | Description                                 |
| ----------- | ------------------ | ------------------------------------------- |
| Dashboard   | `/dashboard`       | Live event counts, ML vs Suricata breakdown |
| Alerts      | `/threats/alerts`  | Live events with Block IP button            |
| Blocked IPs | `/threats/blocked` | IP blocking management                      |
| Nodes       | `/network/nodes`   | Node registry with Approve/Reject           |
| Traffic     | `/network/traffic` | ML flow events                              |
| Audit Log   | `/audit`           | Full JSONL event history + Clear button     |

---

## 🔐 Node Approval Workflow

The system implements **unanimous consent** for node onboarding:

| Scenario      | Behavior                                                     |
| ------------- | ------------------------------------------------------------ |
| 0 nodes exist | First node → **AUTO-APPROVED** (no peers to approve)         |
| 1 node exists | Second node → **PENDING** (needs 1 approval)                 |
| 2 nodes exist | Third node → **PENDING** (needs 2 approvals — both existing) |

### Approval via Admin Panel

1. Node connects → appears in **Nodes** page with `PENDING` badge
2. Admin clicks **✓ Approve** for each pending node
3. When all required approvals are collected → node becomes **APPROVED**

### Via API

```bash
curl -X POST http://192.168.56.1:8765/api/nodes/approve \
  -H "Content-Type: application/json" \
  -d '{"node_id": "NODE_B", "approved_by": "ADMIN"}'
```

---

## ⛓️ Blockchain Integration (Teammate)

> **This section is for the teammate implementing Hyperledger Fabric.**

### Integration Point

The stub function is in `integration/windows_ml_service/suricata_rule_generator.py`:

```python
def blockchain_sync(event: dict, suricata_rule: str | None, trigger: str) -> None:
    # IMPLEMENT THIS — currently a stub
    pass
```

And called from `server.py`:

```python
def _blockchain_sync_placeholder(event: dict, trigger: str) -> None:
    # Calls suricata_rule_generator.blockchain_sync(...)
    pass
```

### Detection Flow: Suricata Detected

```
Suricata alert → eve_forwarder → POST /suricata
    → server.py writes event to hyperledger_events.jsonl  ✅
    → _blockchain_sync_placeholder(event, "SURICATA_DETECTED")
         ↓ TEAMMATE IMPLEMENTS:
         → Submit event to Hyperledger Fabric channel
         → All nodes sync their ledger from Fabric
         → Each node's hyperledger_events.jsonl updated via sync
```

### Detection Flow: ML Detected (new Suricata rule generated)

```
CICFlowMeter flow → POST /flow
    → ML model predicts attack
    → server.py writes event to hyperledger_events.jsonl  ✅
    → _blockchain_sync_placeholder(event, "ML_DETECTED_NEW_RULE")
         ↓ TEAMMATE IMPLEMENTS:
         1. Generate Suricata rule (see suricata_rule_generator.generate_rule())
         2. Push rule to THIS node's /etc/suricata/rules/ips-ml-generated.rules
         3. Reload THIS node's Suricata (suricata_rule_generator.reload_suricata())
         4. Submit (event + rule) to Hyperledger Fabric
         5. All connected nodes receive the new rule from Fabric
         6. Each node:
              a. Writes rule to their Suricata rules file
              b. Reloads their Suricata
              c. Appends synced event to their hyperledger_events.jsonl
         → Now ALL nodes detect this attack via Suricata (not just ML)
```

### Key Files for Teammate

| File                                                        | Purpose                                      |
| ----------------------------------------------------------- | -------------------------------------------- |
| `integration/windows_ml_service/suricata_rule_generator.py` | Rule generation + `blockchain_sync()` stub   |
| `integration/windows_ml_service/server.py`                  | `_blockchain_sync_placeholder()` call sites  |
| `runtime/events/hyperledger_events.jsonl`                   | The local ledger (append-only JSONL)         |
| `/etc/suricata/rules/ips-ml-generated.rules`                | Auto-generated Suricata rules (on each node) |

---

## 🌐 API Reference

| Method | Path                 | Auth         | Description                                                         |
| ------ | -------------------- | ------------ | ------------------------------------------------------------------- |
| GET    | `/api/health`        | None         | Server health + model status                                        |
| GET    | `/api/stats`         | None         | Event counts and dashboard data                                     |
| GET    | `/api/events`        | None         | Paginated events (`?page=1&page_size=25&detection_method=SURICATA`) |
| GET    | `/api/nodes`         | None         | Node registry with approval status                                  |
| GET    | `/api/blocked`       | None         | List of blocked IPs                                                 |
| POST   | `/suricata`          | Bearer token | Submit Suricata alert event                                         |
| POST   | `/flow`              | Bearer token | Submit CICFlowMeter flow for ML scoring                             |
| POST   | `/api/block`         | None (admin) | Block an IP (`{ip, reason, duration_minutes}`)                      |
| POST   | `/api/unblock`       | None (admin) | Unblock an IP (`{ip}`)                                              |
| POST   | `/api/nodes/approve` | None (admin) | Approve a pending node (`{node_id}`)                                |
| POST   | `/api/nodes/reject`  | None (admin) | Reject a pending node (`{node_id}`)                                 |
| POST   | `/api/events/clear`  | None (admin) | Clear all events (testing only)                                     |

---

## 🔑 Node Token Setup

Each node authenticates to the central API using a pre-shared bearer token.

Tokens are **hashed (SHA-256)** in `integration/windows_ml_service/.env`:

```
IPS_NODE_TOKEN_HASHES={"NODE_A":"<sha256>","NODE_B":"<sha256>","NODE_C":"<sha256>"}
```

Plaintext tokens are stored on each Kali node (never committed to git):

```bash
# On each Kali VM:
export IPS_NODE_TOKEN=<plaintext_token>
# OR save to file:
echo "<token>" > ~/node-a.token
export IPS_NODE_TOKEN_FILE=~/node-a.token
```

> **To regenerate tokens:** Run `python -c "import secrets; print(secrets.token_hex(32))"` for each node. Update `.env` with the SHA-256 hash of each token.

---

## 🧪 Testing Guide

### Clear test events (before demo)

1. Admin Panel → Audit Log → click **"🗑 Clear All Events (Testing Only)"**
2. Or via API: `curl -X POST http://192.168.56.1:8765/api/events/clear`

### Full simulation sequence

| Step | Action                               | Expected Result                 |
| ---- | ------------------------------------ | ------------------------------- |
| 1    | Simulator: **Normal Traffic**        | No new alerts                   |
| 2    | Simulator: **SQL Injection**         | Suricata alerts in Admin Panel  |
| 3    | Node A: `bash ml_bruteforce_demo.sh` | ML_MODEL alert: Brute Force     |
| 4    | Node A: `bash ml_dos_demo.sh`        | ML_MODEL alert: DoS/DDoS        |
| 5    | Simulator: **Brute Force**           | Suricata alert (login attempts) |

---

## 🛠️ Tech Stack

| Component          | Technology                               |
| ------------------ | ---------------------------------------- |
| Attack Simulator   | Python, CustomTkinter, PyInstaller       |
| Detection Backend  | Python, scikit-learn, XGBoost, joblib    |
| IDS Engine         | Suricata 8.0.7                           |
| Central API        | Python `http.server`, threading          |
| Admin Panel        | Next.js 14, React, TypeScript            |
| Event Storage      | JSONL (append-only)                      |
| Blockchain         | Hyperledger Fabric _(teammate)_          |
| Network Features   | CICFlowMeter (11 flow features)          |
| Training Data      | CIC-IDS-2017                             |
| Lab Infrastructure | VMware Workstation, Host-only networking |
