
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


# =========================================================
# FEATURE CONFIGURATION
# =========================================================

HTTP_FEATURE_VERSION = "1.0"

HTTP_FEATURES = [
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


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def safe_text(value: Any) -> str:
    """Convert a value into a safe string."""

    if value is None:
        return ""

    return str(value).strip()


def safe_number(value: Any) -> float | None:
    """Convert a value into a finite number."""

    try:
        number = float(value)

        if number >= 0 and number != float("inf"):
            return number

    except (TypeError, ValueError):
        pass

    return None


def extract_url_components(url: str) -> dict[str, Any]:
    """Extract basic URL characteristics."""

    if not url:
        return {
            "url_length": 0,
            "url_path_depth": 0,
            "url_query_length": 0,
            "url_has_query": 0,
        }

    parsed = urlsplit(url)

    path = parsed.path or "/"

    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    return {
        "url_length": len(url),
        "url_path_depth": len(path_segments),
        "url_query_length": len(parsed.query),
        "url_has_query": int(bool(parsed.query)),
    }


# =========================================================
# HTTP FEATURE EXTRACTION
# =========================================================

def extract_http_features(
    event: dict[str, Any]
) -> dict[str, Any]:

    """
    Extract application-layer HTTP features.

    These features are independent of the CIC-IDS2017
    network-flow feature schema.
    """

    method = safe_text(event.get("method")).upper()

    user_agent = safe_text(event.get("user_agent"))

    content_type = safe_text(
        event.get("content_type")
    ).lower()

    hostname = safe_text(event.get("hostname"))

    url = safe_text(event.get("url"))

    status_code = safe_number(
        event.get("status_code")
    )

    response_length = safe_number(
        event.get("response_length")
    )

    # URL characteristics
    url_features = extract_url_components(url)

    features = {
        "http_method": method or None,

        "http_status_code": status_code,

        "http_response_length": response_length,

        **url_features,

        "user_agent_length": len(user_agent),

        "content_type": content_type or None,

        "hostname_length": len(hostname),
    }

    return features


# =========================================================
# FEATURE VALIDATION
# =========================================================

def validate_http_features(
    features: dict[str, Any]
) -> tuple[bool, list[str]]:

    errors = []

    for feature in HTTP_FEATURES:

        if feature not in features:
            errors.append(
                f"Missing feature: {feature}"
            )

    numeric_features = [
        "http_status_code",
        "http_response_length",
        "url_length",
        "url_path_depth",
        "url_query_length",
        "url_has_query",
        "user_agent_length",
        "hostname_length",
    ]

    for feature in numeric_features:

        value = features.get(feature)

        if value is not None:

            if not isinstance(value, (int, float)):
                errors.append(
                    f"Invalid numeric feature: {feature}"
                )

            elif value < 0:
                errors.append(
                    f"Negative feature value: {feature}"
                )

    return len(errors) == 0, errors


# =========================================================
# JSONL READER
# =========================================================

def load_http_events(
    file_path: str | Path
) -> list[dict[str, Any]]:

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {file_path}"
        )

    events = []

    with file_path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:

        for line in file:

            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if isinstance(event, dict):
                    events.append(event)

            except json.JSONDecodeError:
                continue

    return events


# =========================================================
# SAVE FEATURES
# =========================================================

def save_http_features(
    records: list[dict[str, Any]],
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

        for record in records:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                ) + "\n"
            )

    print(f"\nHTTP features saved: {output_path}")
    print(f"Records written: {len(records)}")


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 50)
    print("       HTTP APPLICATION FEATURE EXTRACTOR")
    print("=" * 50)

    input_path = Path(
        "logs/parsed-http-node-a.jsonl"
    )

    output_path = Path(
        "logs/http-features-node-a.jsonl"
    )

    try:

        events = load_http_events(input_path)

        extracted_records = []

        invalid_records = 0

        for event in events:

            features = extract_http_features(event)

            valid, errors = validate_http_features(
                features
            )

            if not valid:
                invalid_records += 1
                continue

            record = {
                "sensor_id": "node-a",
                "flow_id": event.get("flow_id"),
                "timestamp": event.get("timestamp"),
                "features": features,
            }

            extracted_records.append(record)

        print("\n========== EXTRACTION SUMMARY ==========")

        print(f"Input HTTP events : {len(events)}")

        print(
            f"Valid records     : {len(extracted_records)}"
        )

        print(
            f"Invalid records   : {invalid_records}"
        )

        save_http_features(
            extracted_records,
            output_path
        )

        if extracted_records:

            print("\n========== SAMPLE HTTP FEATURES ==========")

            print(
                json.dumps(
                    extracted_records[0],
                    indent=2
                )
            )

    except (FileNotFoundError, PermissionError, OSError) as error:

        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
