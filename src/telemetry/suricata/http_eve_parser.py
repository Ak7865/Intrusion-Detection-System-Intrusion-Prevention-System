
import json
from pathlib import Path
from typing import Any


def parse_http_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """
    Extract normalized HTTP telemetry from a Suricata EVE event.

    Returns None if the event is not an HTTP event.
    """

    if event.get("event_type") != "http":
        return None

    http = event.get("http")

    if not isinstance(http, dict):
        return None

    return {
        "timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),

        # Network information
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "protocol": event.get("proto"),

        # Application information
        "app_protocol": "http",
        "hostname": http.get("hostname"),
        "url": http.get("url"),
        "method": http.get("http_method"),
        "user_agent": http.get("http_user_agent"),
        "http_version": http.get("protocol"),

        # HTTP response information
        "status_code": http.get("status"),
        "response_length": http.get("length"),
        "content_type": http.get("http_content_type"),
    }


def parse_eve_file(file_path: str | Path) -> list[dict[str, Any]]:
    """
    Read Suricata eve.json and extract HTTP events.

    Malformed JSON lines and non-HTTP events are skipped.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Suricata EVE file not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"The supplied path is not a file: {file_path}"
        )

    results = []
    malformed_lines = 0
    total_lines = 0

    with file_path.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

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

            parsed_event = parse_http_event(event)

            if parsed_event is not None:
                results.append(parsed_event)

    print("\n========== EVE FILE SUMMARY ==========")
    print(f"Total lines processed : {total_lines}")
    print(f"HTTP events extracted : {len(results)}")
    print(f"Malformed JSON lines  : {malformed_lines}")

    return results


def save_events(
    events: list[dict[str, Any]],
    output_path: str | Path
) -> None:
    """
    Save normalized HTTP telemetry in JSON Lines format.

    Each line represents one HTTP transaction.
    """

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

    print(f"\nParsed telemetry saved to: {output_path}")
    print(f"Records written: {len(events)}")


def display_events(
    events: list[dict[str, Any]],
    limit: int = 5
) -> None:
    """
    Display the latest extracted HTTP events.
    """

    if not events:
        print("\nNo HTTP events found.")
        return

    print(f"\n========== LATEST {min(limit, len(events))} HTTP EVENTS ==========")

    for event in events[-limit:]:
        print(json.dumps(event, indent=2))


def main() -> None:

    print("======================================")
    print("       SURICATA HTTP EVE PARSER")
    print("======================================")

    eve_path = input(
        "\nEnter Suricata eve.json path: "
    ).strip().strip('"')

    if not eve_path:
        print("Error: No input file path provided.")
        return

    try:
        # Extract HTTP telemetry
        events = parse_eve_file(eve_path)

        # Display extracted events
        display_events(events, limit=5)

        # Save normalized telemetry
        output_path = Path(
            "logs/parsed-http-node-a.jsonl"
        )

        save_events(events, output_path)

    except (FileNotFoundError, ValueError, PermissionError) as error:
        print(f"\nError: {error}")

    except OSError as error:
        print(f"\nFile operation failed: {error}")


if __name__ == "__main__":
    main()

