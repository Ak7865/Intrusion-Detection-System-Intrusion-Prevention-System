# Build & Startup Instructions

## Prerequisites

### Windows Host (Central API + Admin Panel)
- Python 3.10+ (project uses 3.13 venv at `.venv/`)
- Node.js 18+ and pnpm or npm
- All ML dependencies installed in `.venv/`

### Linux Node A (Suricata)
- Suricata 8.0+
- Python 3.10+

---

## 1. Start the Central IPS API (Windows)

```powershell
cd d:\IPS-Lab\Shared\IPS-Project
.\.venv\Scripts\python.exe integration\windows_ml_service\server.py
```

Expected output:
```
Starting IPS ML API on 0.0.0.0:8765
Project root: D:\IPS-Lab\Shared\IPS-Project
Event JSONL: D:\IPS-Lab\Shared\IPS-Project\runtime\events\hyperledger_events.jsonl
WARNING: CICFlowMeter feature compatibility is NOT VERIFIED; firewall blocking is not implemented.
```

**Verify:** `curl http://localhost:8765/health`

---

## 2. Start the Admin Panel (Windows)

```powershell
cd d:\IPS-Lab\Shared\IPS-Project\k-ra3p-ui\k-ra3p-ui
npm install       # First time only
npm run dev
```

The panel will be available at **http://localhost:3001**

> **Port 3001 is used** to avoid conflict with Juice Shop which runs on port 3000.
> The `PORT=3001` setting is already set in `.env.local`.

> **Note:** The Admin Panel proxies all backend requests through `/api/ips/*` to the Central IPS API.
> If the API is on a different host, set `IPS_API_URL` environment variable before starting:
> ```powershell
> $env:IPS_API_URL = "http://192.168.56.1:8765"
> npm run dev
> ```

---

## 3. Start Suricata on Linux Node A

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth1
```

---

## 4. Start the EVE Forwarder on Linux Node A

```bash
export IPS_API_URL=http://192.168.56.1:8765/suricata
export IPS_NODE_TOKEN_FILE=/etc/ips/node-a.token
python3 /path/to/integration/node_a_suricata/eve_forwarder.py
```

---

## 5. Run the Attack Simulator

### From Source (requires `.venv` with customtkinter):
```powershell
cd d:\IPS-Lab\Shared\IPS-Project
.\.venv\Scripts\pip install customtkinter
.\.venv\Scripts\python.exe attack_simulator\app.py
```

### As Windows EXE (after build):
```powershell
dist\IPS_Attack_Simulator.exe
```

### Build the EXE:
```powershell
cd attack_simulator
pip install pyinstaller customtkinter requests pillow
pyinstaller simulator.spec --clean --noconfirm
# Output: attack_simulator\dist\IPS_Attack_Simulator.exe
```

---

## 6. CICFlowMeter Flow Submission

To submit flow features from CICFlowMeter to the ML endpoint:

```bash
# After CICFlowMeter generates flow CSV, post each row:
curl -X POST http://192.168.56.1:8765/flow \
  -H "Authorization: Bearer <NODE_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IPS_API_HOST` | `0.0.0.0` | Central API listen address |
| `IPS_API_PORT` | `8765` | Central API port |
| `IPS_PROJECT_ROOT` | Auto-detected | Project root path |
| `IPS_EVENT_DIR` | `runtime/events` | Event JSONL directory |
| `IPS_NODE_TOKEN_HASHES` | From `.env` | SHA-256 hashes of node tokens |
| `IPS_API_URL` | `http://192.168.56.1:8765` | Backend URL for Admin Panel |

---

## Startup Order (For Demo)

1. Start Central IPS API (Windows)
2. Verify: `GET /health` returns `{"status": "ok"}`
3. Start Admin Panel (port 3001)
4. Start Suricata on Linux Node A
5. Start EVE Forwarder on Linux Node A
6. Run Attack Simulator (`dist/IPS_Attack_Simulator.exe`)
7. Watch events appear in Admin Panel → Alerts page

---

## 7. Quick Verification Tests

### Test 1 — API health check
```powershell
# Windows PowerShell (while server.py is running)
Invoke-WebRequest http://localhost:8765/api/health | Select-Object -ExpandProperty Content
```
Expected: `{"status":"ok","models_loaded":true,...}`

### Test 2 — Events API
```powershell
Invoke-WebRequest "http://localhost:8765/api/events?page=1&page_size=5" | Select-Object -ExpandProperty Content
```
Expected: JSON with `total`, `events` array.

### Test 3 — Stats API
```powershell
Invoke-WebRequest http://localhost:8765/api/stats | Select-Object -ExpandProperty Content
```
Expected: `total_events`, `suricata_detections`, etc.

### Test 4 — Suricata end-to-end (after Node A is live)
On Linux Node A:
```bash
# Generate a SQL injection attempt that Suricata will detect
curl "http://192.168.56.129:3000/rest/products/search?q=1' OR 1=1--"
```
Watch `eve_forwarder.py` log — it should print:
```
Forwarded alert: ET WEB_SERVER SQL Injection Attempt...
```
Then go to Admin Panel → **Alerts** — the event should appear within 20 seconds.

### Test 5 — ML end-to-end (after Node A is live)
On Linux Node A, after CICFlowMeter processes traffic, it POSTs to `/flow`.
Or manually simulate a suspicious flow:
```bash
curl -X POST http://192.168.56.1:8765/flow \
  -H "Authorization: Bearer $(cat /etc/ips/node-a.token)" \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"192.168.56.129","dst_ip":"192.168.56.1","src_port":54321,"dst_port":80,"protocol":"tcp","flow_duration":0.001,"tot_fwd_pkts":5000,"tot_bwd_pkts":0,"totlen_fwd_pkts":250000,"totlen_bwd_pkts":0,"flow_byts_s":999999999,"flow_pkts_s":5000000,"fwd_pkts_s":5000000,"bwd_pkts_s":0,"down_up_ratio":0}'
```
If the ML model predicts Attack, Admin Panel → **Alerts** will show an ML_MODEL event.

