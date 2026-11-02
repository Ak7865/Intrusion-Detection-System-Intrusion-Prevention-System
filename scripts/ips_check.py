#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

BASE = "/mnt/hgfs/IPS-Project"
TRAFFIC_LOG = f"{BASE}/logs/demo-traffic.jsonl"
OUT = f"{BASE}/logs"

SID_BY_IP = {
    "192.168.56.128": 1000002,
    "192.168.56.129": 1000003,
    "192.168.56.130": 1000001,
}
IST = timezone(timedelta(hours=5, minutes=30))

if len(sys.argv) != 2 or sys.argv[1] not in SID_BY_IP:
    sys.exit("Usage: ips-check SENDER_IP")

sender_ip = sys.argv[1]
interfaces = json.loads(subprocess.check_output(
    ["ip", "-j", "-4", "addr", "show"], text=True
))
local_ips = {
    a["local"]
    for i in interfaces
    for a in i.get("addr_info", [])
    if a.get("family") == "inet"
}
receivers = local_ips.intersection(SID_BY_IP)

if len(receivers) != 1:
    sys.exit("Could not identify this receiver VM.")

receiver_ip = next(iter(receivers))
if sender_ip == receiver_ip:
    sys.exit("Sender and receiver must be different.")

# Find the newest successful request for this exact direction.
request = None
with open(TRAFFIC_LOG, encoding="utf-8") as f:
    for line in f:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get("sender_ip") == sender_ip
            and item.get("receiver_ip") == receiver_ip
            and item.get("status") == "request_sent"):
            request = item

if request is None:
    sys.exit("No successful demo request found for this direction.")

run_start = datetime.fromisoformat(request["timestamp"].replace("Z", "+00:00"))
run_id = request.get("run_id", "legacy-no-run-id")
sid = SID_BY_IP[receiver_ip]
eve = "/var/log/suricata/eve.json"
events = []

with open(eve, encoding="utf-8") as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        a = e.get("alert", {})
        if (e.get("event_type") != "alert"
            or a.get("signature_id") != sid
            or e.get("src_ip") != sender_ip
            or e.get("dest_ip") != receiver_ip):
            continue

        ts = e.get("timestamp")
        if not ts:
            continue
        try:
            event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue

        if event_time < run_start - timedelta(seconds=3):
            continue

        events.append({
            "run_id": run_id,
            "request_timestamp_ist": run_start.astimezone(IST).isoformat(),
            "timestamp": event_time.astimezone(IST).isoformat(),
            "source": e.get("src_ip"),
            "destination": e.get("dest_ip"),
            "signature_id": sid,
            "signature": a.get("signature"),
            "action": a.get("action"),
            "http_url": e.get("http", {}).get("url"),
        })

os.makedirs(OUT, exist_ok=True)
stamp = datetime.now(IST).strftime("%Y%m%d-%H%M%S")
path = f"{OUT}/detection-{sender_ip}-to-{receiver_ip}-{stamp}.jsonl"

with open(path, "w", encoding="utf-8") as f:
    for event in events:
        f.write(json.dumps(event) + "\n")

print(f"Receiver: {receiver_ip}")
print(f"Sender: {sender_ip}")
print(f"Run ID: {run_id}")
print(f"Matching alerts since request: {len(events)}")
print(f"Evidence: {path}")
if events:
    print("\nLatest matching alert:")
    print(json.dumps(events[-1], indent=2))
else:
    print("No matching alert found after the request timestamp.")
    print("Check that the receiver's Suricata service was running during the request.")
