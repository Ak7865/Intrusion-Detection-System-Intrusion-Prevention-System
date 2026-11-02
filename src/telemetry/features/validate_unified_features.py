import json
import math
from pathlib import Path

INPUT_FILE = Path("logs/unified-features-node-a.jsonl")

required_network_features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Down/Up Ratio",
]

required_http_features = [
    "http_method",
    "http_status_code",
    "http_response_length",
    "url_length",
    "url_path_depth",
    "url_query_length",
    "url_has_query",
    "user_agent_length",
    "content_type",
    "hostname_length",
]

valid_records = 0
failed_records = 0
missing_fields = 0
invalid_values = 0

with INPUT_FILE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        try:
            record = json.loads(line)

            network = record["network_features"]
            http = record["http_features"]

            for field in required_network_features:
                if field not in network:
                    missing_fields += 1
                elif not isinstance(network[field], (int, float)):
                    invalid_values += 1
                elif not math.isfinite(network[field]):
                    invalid_values += 1

            for field in required_http_features:
                if field not in http:
                    missing_fields += 1

            valid_records += 1

        except (json.JSONDecodeError, KeyError, TypeError):
            failed_records += 1

print("\n========== DATASET VALIDATION ==========")
print(f"Records processed : {valid_records}")
print(f"Failed records    : {failed_records}")
print(f"Missing fields    : {missing_fields}")
print(f"Invalid values    : {invalid_values}")

if not any([failed_records, missing_fields, invalid_values]):
    print("\nRESULT: STRUCTURAL VALIDATION PASSED")
else:
    print("\nRESULT: VALIDATION ISSUES FOUND")