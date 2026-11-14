# IPS Project — Demo Guide

## Demo Overview

This guide walks through a live demonstration of the complete IPS pipeline:

- Attack Simulator → Network Traffic → Suricata/ML Detection → Admin Panel

**Expected demo time:** 15–20 minutes

---

## Prerequisites (Before Demo)

Ensure all three applications are running:

| App              | Location     | Command                                                             |
| ---------------- | ------------ | ------------------------------------------------------------------- |
| Central IPS API  | Windows host | `.venv\Scripts\python.exe integration\windows_ml_service\server.py` |
| Admin Panel      | Windows host | `cd k-ra3p-ui\k-ra3p-ui && npm run dev`                             |
| Suricata         | Linux Node A | `sudo suricata -c /etc/suricata/suricata.yaml -i eth1`              |
| EVE Forwarder    | Linux Node A | `python3 integration/node_a_suricata/eve_forwarder.py`              |
| Attack Simulator | Windows host | `attack_simulator\dist\IPS_Attack_Simulator.exe`                    |

---

## Demo Sequence

### Step 1: Show the Admin Panel (baseline)

1. Open **http://localhost:3000** in a browser
2. Sign up or sign in (uses local browser storage)
3. Navigate to **Dashboard** — shows real event counts from JSONL file
4. Navigate to **Threats → Alerts** — shows real Suricata events paginated
5. Navigate to **Network → Nodes** — shows any connected nodes

> Point out: all data comes from `runtime/events/hyperledger_events.jsonl` via the Central IPS API — no hardcoded values.

---

### Step 2: Normal Traffic Simulation

1. Launch the Attack Simulator
2. Set Target IP: `192.168.56.129`, Port: `3000`
3. Select **Normal Traffic** mode
4. Set Duration: `30s`, Rate: `2.0`
5. Confirm Source IP is detected
6. Click **▶ Start**
7. Watch the log — HTTP 200/304 responses should appear
8. After completion, check Admin Panel Dashboard — no new attack events expected

> Demonstrates: benign traffic does NOT trigger false attack events.

---

### Step 3: SQL Injection Simulation

1. Select **SQL Injection** mode
2. Duration: `30s`, Rate: `0.5`
3. Click **▶ Start**
4. Watch log — requests with SQL payloads in search params
5. Wait ~15 seconds then refresh Admin Panel → **Threats → Alerts**
6. New events with `attack_type` containing "SQL" or Suricata category should appear

> Demonstrates: Suricata signature detection → EVE forwarder → Central API → Admin Panel.

---

### Step 4: Brute Force Simulation

1. Select **Brute Force** mode
2. Set Max attempts: `10`, Delay: `2.0s`
3. Click **▶ Start**
4. Simulator tries up to 10 passwords against `/rest/user/login`
5. Watch Admin Panel — Suricata may detect HTTP brute-force patterns

> Demonstrates: controlled attempt-limited authentication testing.

---

### Step 5: DoS / High-Volume Traffic

1. Select **DoS / High-Volume** mode
2. Duration: `30s`, Rate: `5.0`
3. Click **▶ Start**
4. High-frequency requests hit the target
5. If CICFlowMeter is running and ML pipeline is active, flow features are posted to `/flow`
6. If ML predicts an attack, event appears in Admin Panel with `detection_source: ML_MODEL`

> Demonstrates: ML-based detection path (secondary to Suricata).

---

### Step 6: Pause and Stop Controls

1. During any simulation, click **⏸ Pause**
2. Requests stop — log shows `[CTRL] Paused`
3. Click **▶ Resume** — requests restart
4. Click **⏹ Stop** — simulation ends immediately

---

### Step 7: Application Independence

1. Close the Attack Simulator — Admin Panel continues to show events
2. Close the Admin Panel — detection backend continues to run and write events
3. Reopen Admin Panel — events are still there (append-only JSONL)

---

## Key Points to Highlight

| Point                  | Evidence                                     |
| ---------------------- | -------------------------------------------- |
| Real detection data    | 10,243+ Suricata events in JSONL             |
| No hardcoded stats     | Dashboard reads from API in real-time        |
| Separation of concerns | 3 independent apps, different ports          |
| Authorisation check    | Simulator rejects non-private IPs            |
| No fake blocking       | Blocked IPs page clearly states NOT_EXECUTED |
| No false blockchain    | Status shown as PENDING_NOT_SUBMITTED        |
| Deduplication          | Same alert not written twice (180s cache)    |

---

## Troubleshooting

| Problem                                 | Solution                                               |
| --------------------------------------- | ------------------------------------------------------ |
| Admin Panel shows "Backend unreachable" | Start `server.py`, check port 8765                     |
| No events in Alerts page                | Check `runtime/events/hyperledger_events.jsonl` exists |
| Simulator rejects IP                    | Target must be a private RFC 1918 address              |
| Suricata events not appearing           | Check `eve_forwarder.py` is running on Linux Node A    |
| Node not showing in Nodes page          | Node must POST at least one event to appear            |
