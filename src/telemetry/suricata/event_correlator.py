import json
from pathlib import Path
from typing import Any


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

SENSOR_ID = "node-a"

HTTP_INPUT = Path("logs/parsed-http-node-a.jsonl")
FLOW_INPUT = Path("logs/parsed-flow-node-a.jsonl")

OUTPUT_FILE = Path("logs/combined-http-flow-node-a.jsonl")


# --------------------------------------------------
# JSONL READER
# --------------------------------------------------

def load_jsonl(file_path: Path) -> list[dict[str, Any]]:
    """Load JSON objects from a JSONL file."""

    if not file_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {file_path}"
        )

    records = []
    malformed = 0

    with file_path.open("r", encoding="utf-8-sig") as file:

        for line in file:

            if not line.strip():
                continue

            try:
                record = json.loads(line)

                if isinstance(record, dict):
                    records.append(record)

            except json.JSONDecodeError:
                malformed += 1

    if malformed:
        print(
            f"Warning: {malformed} malformed lines "
            f"found in {file_path}"
        )

    return records


# --------------------------------------------------
# FLOW ID INDEX
# --------------------------------------------------

def build_flow_index(
    flow_events: list[dict[str, Any]]
) -> dict[tuple[str, int], dict[str, Any]]:

    """
    Build an index using sensor_id and flow_id.

    A flow_id is local to its Suricata sensor.
    """

    flow_index = {}

    for flow in flow_events:

        flow_id = flow.get("flow_id")

        if flow_id is None:
            continue

        key = (SENSOR_ID, flow_id)

        if key in flow_index:
            print(
                f"Warning: Duplicate flow_id detected: {flow_id}"
            )
            continue

        flow_index[key] = flow

    return flow_index


# --------------------------------------------------
# NETWORK TUPLE VALIDATION
# --------------------------------------------------

def validate_network_tuple(
    http: dict[str, Any],
    flow: dict[str, Any]
) -> bool:

    """
    Verify that HTTP and flow events describe
    the same network connection.
    """

    fields = [
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port"
    ]

    for field in fields:

        if http.get(field) != flow.get(field):
            return False

    return True


# --------------------------------------------------
# EVENT CORRELATION
# --------------------------------------------------

def correlate_events(
    http_events: list[dict[str, Any]],
    flow_index: dict[tuple[str, int], dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, int]]:

    """
    Correlate HTTP transactions with their flow events.

    Each HTTP transaction produces one combined record
    when its corresponding flow event is available.
    """

    combined_events = []

    unmatched_http = 0
    inconsistent_events = 0
    matched_events = 0

    for http in http_events:

        flow_id = http.get("flow_id")

        key = (SENSOR_ID, flow_id)

        flow = flow_index.get(key)

        # No corresponding flow event
        if flow is None:
            unmatched_http += 1
            continue

        # Validate network tuple
        if not validate_network_tuple(http, flow):
            inconsistent_events += 1
            continue

        combined_record = {

            "sensor_id": SENSOR_ID,

            "flow_id": flow_id,

            "timestamp": http.get("timestamp"),

            "network": {
                "src_ip": http.get("src_ip"),
                "src_port": http.get("src_port"),
                "dest_ip": http.get("dest_ip"),
                "dest_port": http.get("dest_port"),
                "protocol": http.get("protocol"),
                "interface": flow.get("interface"),
                "ip_version": flow.get("ip_version")
            },

            "http": {
                "hostname": http.get("hostname"),
                "url": http.get("url"),
                "method": http.get("method"),
                "user_agent": http.get("user_agent"),
                "http_version": http.get("http_version"),
                "status_code": http.get("status_code"),
                "response_length": http.get("response_length"),
                "content_type": http.get("content_type")
            },

            "flow": {
                "packets_toserver": flow.get(
                    "packets_toserver"
                ),

                "packets_toclient": flow.get(
                    "packets_toclient"
                ),

                "bytes_toserver": flow.get(
                    "bytes_toserver"
                ),

                "bytes_toclient": flow.get(
                    "bytes_toclient"
                ),

                "total_packets": flow.get("total_packets"),
                "total_bytes": flow.get("total_bytes"),

                "start": flow.get("start"),
                "end": flow.get("end"),

                "duration_seconds": flow.get(
                    "duration_seconds"
                ),

                "age_seconds": flow.get("age_seconds"),
                "state": flow.get("state"),
                "reason": flow.get("reason"),
                "alerted": flow.get("alerted")
            }
        }

        combined_events.append(combined_record)
        matched_events += 1

    statistics = {
        "http_events": len(http_events),
        "flow_events": len(flow_index),
        "matched_events": matched_events,
        "unmatched_http_events": unmatched_http,
        "inconsistent_events": inconsistent_events
    }

    return combined_events, statistics


# --------------------------------------------------
# SAVE CORRELATED TELEMETRY
# --------------------------------------------------

def save_jsonl(
    records: list[dict[str, Any]],
    output_path: Path
) -> None:

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        for record in records:

            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                ) + "\n"
            )

    print(f"\nCombined telemetry saved: {output_path}")
    print(f"Records saved: {len(records)}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    print("=" * 50)
    print("       SURICATA EVENT CORRELATOR")
    print("=" * 50)

    try:

        # Load normalized telemetry
        http_events = load_jsonl(HTTP_INPUT)
        flow_events = load_jsonl(FLOW_INPUT)

        print("\nInput files loaded successfully.")

        # Build flow index
        flow_index = build_flow_index(flow_events)

        # Correlate HTTP and flow events
        combined_events, statistics = correlate_events(
            http_events,
            flow_index
        )

        # Display statistics
        print("\n========== CORRELATION SUMMARY ==========")

        for name, value in statistics.items():
            print(f"{name.replace('_', ' ').title():30}: {value}")

        # Save results
        save_jsonl(
            combined_events,
            OUTPUT_FILE
        )

        # Display one sample
        if combined_events:

            print("\n========== SAMPLE CORRELATED EVENT ==========")

            print(
                json.dumps(
                    combined_events[0],
                    indent=2
                )
            )

    except (FileNotFoundError, PermissionError, OSError) as error:

        print(f"\nError: {error}")


if __name__ == "__main__":
    main()