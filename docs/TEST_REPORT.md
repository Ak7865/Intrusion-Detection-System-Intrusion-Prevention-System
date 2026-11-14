# IPS Project — Integration Test Report

**Date:** 2026-11-14  
**Tester:** Automated verification  
**JSONL Event File:** `runtime/events/hyperledger_events.jsonl`

---

## Test 1: Event File Integrity

| Check | Result | Detail |
|---|---|---|
| File exists | ✅ PASS | 13.9 MB |
| Total lines | ✅ PASS | 10,243 |
| All lines valid JSON | ✅ PASS | 10,243 / 10,243 |
| Unique event IDs | ✅ PASS | 0 duplicates |
| Detection source | ✅ PASS | SURICATA: 10,243 |
| Network fields present | ✅ PASS | source_ip, dest_ip, ports verified |

---

## Test 2: Central IPS API — New Endpoints

| Endpoint | Test | Result | Detail |
|---|---|---|---|
| `_build_stats()` | Reads JSONL, computes all stats | ✅ PASS | total=10243, suricata=10243 |
| `_read_events_page()` | Returns paginated events | ✅ PASS | total=10243, page=3 events |
| `_update_node_heartbeat()` | Registers NODE_A | ✅ PASS | Registry populated |
| `GET /api/stats` | Returns stats JSON | ✅ PASS (logic) | Requires running server |
| `GET /api/events` | Returns paginated events | ✅ PASS (logic) | Requires running server |
| `GET /api/nodes` | Returns node list | ✅ PASS (logic) | Requires running server |
| `GET /api/health` | Returns health | ✅ PASS (logic) | Requires running server |

---

## Test 3: Python Syntax Checks

| File | Result |
|---|---|
| `integration/windows_ml_service/server.py` | ✅ PASS |
| `attack_simulator/app.py` | ✅ PASS |
| `attack_simulator/modules/simulators.py` | ✅ PASS |
| `attack_simulator/gui/__init__.py` | ✅ PASS |
| `attack_simulator/gui/theme.py` | ✅ PASS |
| `attack_simulator/gui/log_panel.py` | ✅ PASS |
| `attack_simulator/gui/counter_bar.py` | ✅ PASS |
| `attack_simulator/gui/config_panel.py` | ✅ PASS |
| `attack_simulator/gui/control_bar.py` | ✅ PASS |

---

## Test 4: Admin Panel TypeScript Build

| Check | Result | Detail |
|---|---|---|
| `tsc --noEmit` | ✅ PASS | Zero TypeScript errors |
| `npm install` | ✅ PASS | All dependencies installed |
| New API route exists | ✅ PASS | `app/api/ips/[...path]/route.ts` |
| Dashboard page updated | ✅ PASS | Real API calls, no hardcoded data |
| Alerts page created | ✅ PASS | Real paginated events |
| Nodes page created | ✅ PASS | Real node registry |
| Blocked IPs page updated | ✅ PASS | Honest NOT_EXECUTED status |
| `lib/api.ts` created | ✅ PASS | Shared types + fetch helpers |

---

## Test 5: Windows EXE Build

| Check | Result | Detail |
|---|---|---|
| PyInstaller build | ✅ PASS | Build completed successfully |
| Output file | ✅ PASS | `attack_simulator/dist/IPS_Attack_Simulator.exe` |
| File size | ✅ PASS | ~22 MB (standalone, no Python required) |
| customtkinter 6.0.0 | ✅ INSTALLED | Dark theme GUI available |
| GUI fallback | ✅ PASS | Falls back to standard tkinter if CTK missing |

---

## Test 6: Authorization Check (Simulator)

| Test | Result |
|---|---|
| Private IP 192.168.56.129 | ✅ AUTHORISED |
| Private IP 10.0.0.1 | ✅ AUTHORISED |
| Private IP 172.16.0.1 | ✅ AUTHORISED |
| Loopback 127.0.0.1 | ✅ AUTHORISED |
| Public IP 8.8.8.8 | ❌ REJECTED (by design) |
| Public IP 1.1.1.1 | ❌ REJECTED (by design) |

---

## Test 7: Application Separation

| Check | Result |
|---|---|
| Simulator has no JSONL write code | ✅ VERIFIED |
| Simulator does not import server.py | ✅ VERIFIED |
| Admin Panel is a separate Next.js app | ✅ VERIFIED |
| Admin Panel uses proxy routes (no direct backend calls from browser) | ✅ VERIFIED |
| Backend tokens not exposed to frontend JS | ✅ VERIFIED |

---

## Pending Verification (Requires Live Lab)

| Test | Status | Requirement |
|---|---|---|
| Suricata alert → EVE → forwarder → API → JSONL | NOT VERIFIED in CI | Needs Linux Node A + Suricata running |
| CICFlowMeter → /flow → ML prediction | NOT VERIFIED in CI | Needs live traffic capture |
| Admin Panel loading in browser | NOT VERIFIED in CI | Needs `npm run dev` |
| Attack Simulator GUI display | NOT VERIFIED in CI | Needs desktop display |
| EXE launches independently | NOT VERIFIED in CI | Needs Windows desktop |

---

## Known Limitations

1. **CICFlowMeter feature compatibility**: `NOT_VERIFIED` — live features vs training features not experimentally matched
2. **No firewall blocking**: `actual_block_status: NOT_EXECUTED` on all events
3. **No Hyperledger Fabric**: `blockchain_status: PENDING_NOT_SUBMITTED` — JSONL only
4. **Legacy event schema**: 10,243 real events predate `classification_status` field — shown as `null`
5. **Node join approval UI**: display only; no approve/reject API endpoint implemented
6. **ML detection requires Suricata correlation first**: if Suricata already cached a flow, ML event is suppressed

