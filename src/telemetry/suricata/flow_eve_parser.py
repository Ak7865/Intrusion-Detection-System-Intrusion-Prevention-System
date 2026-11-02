
import json
from pathlib import Path
from typing import Any


def parse_flow_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extract normalized network-flow telemetry
    from a Suricata EVE flow event.
    """

    if event.get("event_type") != "flow":
        return None

    flow = event.get("flow")

    if not isinstance(flow, dict):
        return None

    start = flow.get("start")
    end = flow.get("end")

    duration_seconds = None

    # Calculate duration using the actual timestamps.
    if start and end:
        try:
            from datetime import datetime

            start_time = datetime.strptime(
                start, "%Y-%m-%dT%H:%M:%S.%f%z"
            )

            end_time = datetime.strptime(
                end, "%Y-%m-%dT%H:%M:%S.%f%z"
            )

            duration_seconds = max(
                0.0,
                (end_time - start_time).total_seconds()
            )

        except ValueError:
            duration_seconds = None

    packets_toserver = flow.get("pkts_toserver", 0)
    packets_toclient = flow.get("pkts_toclient", 0)

    bytes_toserver = flow.get("bytes_toserver", 0)
    bytes_toclient = flow.get("bytes_toclient", 0)

    total_packets = packets_toserver + packets_toclient
    total_bytes = bytes_toserver + bytes_toclient

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),

        # Sensor information
        "interface": event.get("in_iface"),

        # Network information
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "ip_version": event.get("ip_v"),
        "protocol": event.get("proto"),
        "app_protocol": event.get("app_proto"),

        # Flow statistics
        "packets_toserver": packets_toserver,
        "packets_toclient": packets_toclient,
        "bytes_toserver": bytes_toserver,
        "bytes_toclient": bytes_toclient,
        "total_packets": total_packets,
        "total_bytes": total_bytes,

        # Timing
        "start": start,
        "end": end,
        "duration_seconds": duration_seconds,
        "age_seconds": flow.get("age"),

        # Flow status
        "state": flow.get("state"),
        "reason": flow.get("reason"),
        "alerted": flow.get("alerted"),
    }


def parse_flow_file(
    file_path: str | Path
) -> list[dict[str, Any]]:

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"EVE file not found: {file_path}"
        )

    results = []
    malformed_lines = 0
    total_lines = 0

    with file_path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:

        for line in file:
            total_lines += 1

            if not line.strip():
                continue

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                malformed_lines += 1
                continue

            if not isinstance(event, dict):
                continue

            parsed = parse_flow_event(event)

            if parsed is not None:
                results.append(parsed)

    print("\n========== FLOW EVE SUMMARY ==========")
    print(f"Total lines processed : {total_lines}")
    print(f"Flow events extracted : {len(results)}")
    print(f"Malformed JSON lines  : {malformed_lines}")

    return results


def save_flow_events(
    events: list[dict[str, Any]],
    output_path: str | Path
) -> None:

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        for event in events:
            file.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

    print(f"\nFlow telemetry saved to: {output_path}")
    print(f"Records written: {len(events)}")


def main():

    print("======================================")
    print("       SURICATA FLOW EVE PARSER")
    print("======================================")

    eve_path = input(
        "\nEnter Suricata eve.json path: "
    ).strip().strip('"')

    if not eve_path:
        print("Error: No input path provided.")
        return

    try:
        events = parse_flow_file(eve_path)

        print("\n========== LATEST 3 FLOW EVENTS ==========")

        for event in events[-3:]:
            print(json.dumps(event, indent=2))

        save_flow_events(
            events,
            "logs/parsed-flow-node-a.jsonl"
        )

    except (FileNotFoundError, ValueError, PermissionError) as error:
        print(f"\nError: {error}")

    except OSError as error:
        print(f"\nFile operation failed: {error}")


if __name__ == "__main__":
    main()
