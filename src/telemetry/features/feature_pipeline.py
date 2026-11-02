
import json
from pathlib import Path
from typing import Any

from src.telemetry.features.flow_features import (
    extract_flow_features,
    validate_features as validate_flow_features,
    RUNTIME_FEATURES,
    FEATURE_VERSION,
)

from src.telemetry.features.http_features import (
    extract_http_features,
    validate_http_features,
)


# =========================================================
# CONFIGURATION
# =========================================================

SENSOR_ID = "node-a"

INPUT_FILE = Path(
    "logs/combined-http-flow-node-a.jsonl"
)

OUTPUT_FILE = Path(
    "logs/unified-features-node-a.jsonl"
)


# =========================================================
# INPUT READER
# =========================================================

def load_jsonl(
    file_path: Path
) -> list[dict[str, Any]]:
    """Load records from a JSONL file."""

    if not file_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {file_path}"
        )

    records = []
    malformed = 0

    with file_path.open(
        "r",
        encoding="utf-8-sig"
    ) as file:

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
            f"Warning: {malformed} malformed input lines."
        )

    return records


# =========================================================
# FLOW INPUT MAPPING
# =========================================================

def prepare_flow_input(
    record: dict[str, Any]
) -> dict[str, Any]:
    """
    Convert nested combined telemetry into the
    flat structure expected by flow_features.py.
    """

    network = record.get("network", {})
    flow = record.get("flow", {})

    return {
        "dest_port": network.get("dest_port"),

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

        "duration_seconds": flow.get(
            "duration_seconds"
        ),
    }


# =========================================================
# HTTP INPUT MAPPING
# =========================================================

def prepare_http_input(
    record: dict[str, Any]
) -> dict[str, Any]:
    """
    Convert nested combined telemetry into the
    flat structure expected by http_features.py.
    """

    http = record.get("http", {})

    return {
        "hostname": http.get("hostname"),
        "url": http.get("url"),
        "method": http.get("method"),
        "user_agent": http.get("user_agent"),
        "http_version": http.get("http_version"),
        "status_code": http.get("status_code"),
        "response_length": http.get(
            "response_length"
        ),
        "content_type": http.get("content_type"),
    }


# =========================================================
# UNIFIED FEATURE EXTRACTION
# =========================================================

def extract_unified_features(
    record: dict[str, Any]
) -> dict[str, Any]:
    """
    Extract network-flow and HTTP features separately
    and preserve their common telemetry identifiers.
    """

    flow_input = prepare_flow_input(record)
    http_input = prepare_http_input(record)

    flow_features = extract_flow_features(
        flow_input
    )

    http_features = extract_http_features(
        http_input
    )

    flow_valid, flow_errors = validate_flow_features(
        flow_features
    )

    http_valid, http_errors = validate_http_features(
        http_features
    )

    errors = flow_errors + http_errors

    if not flow_valid or not http_valid:
        raise ValueError(
            "; ".join(errors)
        )

    return {
        "schema_version": "1.0",

        "sensor_id": record.get(
            "sensor_id",
            SENSOR_ID
        ),

        "flow_id": record.get("flow_id"),

        "timestamp": record.get("timestamp"),

        "network_features": flow_features,

        "http_features": http_features,

        "metadata": {
            "flow_feature_schema": FEATURE_VERSION,
            "flow_feature_order": RUNTIME_FEATURES,
            "http_feature_schema": "1.0",
            "direction_mapping": (
                "Provisional: toserver/toclient mapped "
                "to forward/backward."
            ),
        },
    }


# =========================================================
# SAVE OUTPUT
# =========================================================

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

    print(
        f"\nUnified features saved: {output_path}"
    )

    print(
        f"Records written: {len(records)}"
    )


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 55)
    print("          UNIFIED FEATURE EXTRACTION PIPELINE")
    print("=" * 55)

    try:

        # Load correlated telemetry
        records = load_jsonl(INPUT_FILE)

        extracted_records = []
        failed_records = 0

        # Extract both feature groups
        for record in records:

            try:

                unified = extract_unified_features(
                    record
                )

                extracted_records.append(unified)

            except (ValueError, TypeError, KeyError) as error:

                failed_records += 1

                print(
                    f"Feature extraction failed for "
                    f"flow_id={record.get('flow_id')}: {error}"
                )

        # Summary
        print("\n========== PIPELINE SUMMARY ==========")

        print(
            f"Input records       : {len(records)}"
        )

        print(
            f"Successful records  : {len(extracted_records)}"
        )

        print(
            f"Failed records      : {failed_records}"
        )

        # Save results
        save_jsonl(
            extracted_records,
            OUTPUT_FILE
        )

        # Display sample
        if extracted_records:

            print(
                "\n========== SAMPLE UNIFIED FEATURES =========="
            )

            print(
                json.dumps(
                    extracted_records[0],
                    indent=2
                )
            )

    except (FileNotFoundError, PermissionError, OSError) as error:

        print(f"\nPipeline error: {error}")


if __name__ == "__main__":
    main()


