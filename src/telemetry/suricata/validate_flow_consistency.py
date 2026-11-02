import json
from pathlib import Path

EVE_FILE = Path("logs/kali-http-test-eve.json")
PARSED_FILE = Path("logs/parsed-flow-node-a.jsonl")

FIELDS = [
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "ip_version",
    "protocol",
    "packets_toserver",
    "packets_toclient",
    "bytes_toserver",
    "bytes_toclient",
    "start",
    "end",
    "state",
    "reason",
]

original = {}
normalized = {}

with EVE_FILE.open("r", encoding="utf-8-sig") as file:
    for line in file:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") == "flow":
            original[event["flow_id"]] = event

with PARSED_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        if line.strip():
            record = json.loads(line)
            normalized[record["flow_id"]] = record

matched = 0
missing = 0
mismatches = 0

for flow_id, record in normalized.items():

    event = original.get(flow_id)

    if event is None:
        missing += 1
        continue

    flow = event["flow"]

    expected = {
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "ip_version": event.get("ip_v"),
        "protocol": event.get("proto"),
        "packets_toserver": flow.get("pkts_toserver", 0),
        "packets_toclient": flow.get("pkts_toclient", 0),
        "bytes_toserver": flow.get("bytes_toserver", 0),
        "bytes_toclient": flow.get("bytes_toclient", 0),
        "start": flow.get("start"),
        "end": flow.get("end"),
        "state": flow.get("state"),
        "reason": flow.get("reason"),
    }

    differences = [
        field for field in FIELDS
        if record.get(field) != expected[field]
    ]

    if differences:
        mismatches += 1

        if mismatches <= 5:
            print(f"Mismatch: flow_id={flow_id}")
            print("Fields:", differences)
    else:
        matched += 1

print("\n========== FLOW CONSISTENCY REPORT ==========")
print(f"Original flow events : {len(original)}")
print(f"Parsed flow records  : {len(normalized)}")
print(f"Matched records      : {matched}")
print(f"Missing source events: {missing}")
print(f"Mismatched records   : {mismatches}")

if missing == 0 and mismatches == 0 and matched == len(normalized):
    print("\nRESULT: PARSER CONSISTENCY PASSED")
else:
    print("\nRESULT: INVESTIGATION REQUIRED")