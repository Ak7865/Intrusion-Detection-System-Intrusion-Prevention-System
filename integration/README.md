# Phase 1 IPS Runtime Integration (starter package)

## Components
- `windows_ml_service/server.py`: Windows-hosted inference API. Loads existing binary RF/XGBoost, multiclass RF/XGBoost, and XGBoost label encoder. Does not train or overwrite models.
- `node_a_suricata/eve_forwarder.py`: tails Suricata EVE JSON and forwards alert records.
- `bots/traffic_bot.py`: controlled HTTP normal, SQLi-shaped, login-guessing, and low-rate load traffic.
- `runtime/events/hyperledger_events.jsonl`: generated JSONL records ready for a Hyperledger adapter.

## Critical model-input limitation
The runtime adapter converts Python CICFlowMeter `flow_duration` from seconds to microseconds. However, the inspected Python CICFlowMeter currently reports forward/backward total lengths and Flow Bytes/s using full network-layer packet bytes, while the Java reference inspected for CICIDS-style features accumulates TCP/UDP payload bytes. Therefore model predictions from this initial integration are **experimental and not validated for deployment accuracy**. Every ML event records `feature_profile=UNVERIFIED_CICFLOWMETER_COMPATIBILITY`. Do not treat this as validated detection until feature parity is tested against the dataset's exact generator/version.

## Windows setup
Run from project root in PowerShell:
```powershell
$env:IPS_PROJECT_ROOT = (Get-Location).Path
$env:IPS_API_HOST = "0.0.0.0"
$env:IPS_API_PORT = "8765"
.\.venv\Scripts\python.exe .\integration\windows_ml_service\server.py
```
Check:
```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```
Allow inbound TCP 8765 on the host-only interface in Windows Firewall if Kali nodes cannot connect.

## Node A (Kali)
Install/use Python 3 and set:
```bash
export IPS_API_URL="http://192.168.56.1:8765/suricata"
export SURICATA_EVE="/var/log/suricata/eve.json"
sudo -E python3 integration/node_a_suricata/eve_forwarder.py
```
Confirm Suricata is configured to write `alert` events to EVE JSON. This forwarder only forwards alert events; it does not configure Suricata rules or enable packet capture.

## CICFlowMeter flow forwarding
Use the existing CICFlowMeter HTTP output mode with:
`http://192.168.56.1:8765/flow`
Example CLI options depend on the checked-in CLI version; inspect `python -m cicflowmeter --help` before running. Do not run live capture until Suricata and the API are confirmed healthy. The current flow-session code has concurrency/flush concerns identified during review; validate offline PCAP first.

## Bots (run from a machine that can reach Node B)
```bash
python bots/traffic_bot.py --mode normal --duration 60 --rate 1
python bots/traffic_bot.py --mode sqli --duration 30 --rate 1
python bots/traffic_bot.py --mode bruteforce --duration 30 --rate 1
python bots/traffic_bot.py --mode dos --duration 15 --rate 3
```
All traffic is directed to the controlled lab app by default. The SQLi and brute-force endpoints are examples; adapt them to the app's actual routes. The load mode is capped at 5 requests/second and is not a DDoS simulator.

## Event schema
Events contain event_id, attack_id, organisation metadata, source/destination, detection source, Suricata evidence or ML prediction evidence, block_ip_addresses, recommended_action, and actual_block_status. `actual_block_status` remains `NOT_EXECUTED`; no firewall action is performed.

## Hyperledger
The JSONL file is an integration handoff, not a blockchain transaction. A Fabric client/chaincode adapter still needs your Fabric network details, channel, chaincode name, identity/wallet and transaction function schema. Do not invent these values.

## Important routing note
This starter correlates a Suricata alert to a flow by 5-tuple in a short in-memory cache. If a matching alert is present when the flow arrives, it skips ML. It is not a durable correlation service and should be hardened before a formal experiment.
