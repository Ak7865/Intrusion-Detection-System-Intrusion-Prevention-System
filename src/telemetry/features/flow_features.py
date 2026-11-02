from typing import Any
import math

# =========================================================
# FEATURE CONFIGURATION
# =========================================================

FEATURE_VERSION = "1.0"

RUNTIME_FEATURES = [
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


# =========================================================
# VALIDATION
# =========================================================

def safe_number(value: Any, default: float = 0.0) -> float:
    """Convert a value to a finite float."""

    try:
        number = float(value)

        if math.isfinite(number):
            return number

    except (TypeError, ValueError):
        pass

    return default


def safe_rate(value: float, duration: float) -> float:
    """Calculate a rate without dividing by zero."""

    if duration <= 0:
        return 0.0

    return value / duration


# =========================================================
# FLOW FEATURE EXTRACTION
# =========================================================

def extract_flow_features(
    flow: dict[str, Any]
) -> dict[str, float]:

    """
    Extract the provisional 11-feature runtime schema
    from normalized Suricata flow telemetry.

    IMPORTANT:
    Directional mapping is provisional and must be
    validated against CIC-IDS2017 before model inference.
    """

    # -----------------------------------------------------
    # Network information
    # -----------------------------------------------------

    destination_port = safe_number(
        flow.get("dest_port")
    )

    # -----------------------------------------------------
    # Directional packet statistics
    # -----------------------------------------------------

    forward_packets = safe_number(
        flow.get("packets_toserver")
    )

    backward_packets = safe_number(
        flow.get("packets_toclient")
    )

    forward_bytes = safe_number(
        flow.get("bytes_toserver")
    )

    backward_bytes = safe_number(
        flow.get("bytes_toclient")
    )

    # -----------------------------------------------------
    # Flow duration
    # -----------------------------------------------------

    duration_seconds = safe_number(
        flow.get("duration_seconds")
    )

    # CIC-IDS2017 Flow Duration is represented in
    # microseconds in the dataset.
    duration_microseconds = duration_seconds * 1_000_000

    # -----------------------------------------------------
    # Rate calculations
    # -----------------------------------------------------

    total_bytes = forward_bytes + backward_bytes

    total_packets = forward_packets + backward_packets

    flow_bytes_per_second = safe_rate(
        total_bytes,
        duration_seconds
    )

    flow_packets_per_second = safe_rate(
        total_packets,
        duration_seconds
    )

    forward_packets_per_second = safe_rate(
        forward_packets,
        duration_seconds
    )

    backward_packets_per_second = safe_rate(
        backward_packets,
        duration_seconds
    )

    # -----------------------------------------------------
    # Down / Up ratio
    # -----------------------------------------------------

    if forward_packets > 0:
        down_up_ratio = backward_packets / forward_packets
    else:
        down_up_ratio = 0.0

    # -----------------------------------------------------
    # Final feature vector
    # -----------------------------------------------------

    features = {

        "Destination Port": destination_port,

        "Flow Duration": duration_microseconds,

        "Total Fwd Packets": forward_packets,

        "Total Backward Packets": backward_packets,

        "Total Length of Fwd Packets": forward_bytes,

        "Total Length of Bwd Packets": backward_bytes,

        "Flow Bytes/s": flow_bytes_per_second,

        "Flow Packets/s": flow_packets_per_second,

        "Fwd Packets/s": forward_packets_per_second,

        "Bwd Packets/s": backward_packets_per_second,

        "Down/Up Ratio": down_up_ratio,
    }

    return features


# =========================================================
# FEATURE VALIDATION
# =========================================================

def validate_features(
    features: dict[str, float]
) -> tuple[bool, list[str]]:

    errors = []

    # Check feature completeness
    for feature in RUNTIME_FEATURES:

        if feature not in features:
            errors.append(
                f"Missing feature: {feature}"
            )

    # Check numerical validity
    for name, value in features.items():

        if not math.isfinite(value):
            errors.append(
                f"Non-finite value in {name}"
            )

        if value < 0:
            errors.append(
                f"Negative value in {name}"
            )

    return len(errors) == 0, errors


# =========================================================
# FEATURE VECTOR
# =========================================================

def to_feature_vector(
    features: dict[str, float]
) -> list[float]:

    """
    Return features in the exact training schema order.
    """

    return [
        features[name]
        for name in RUNTIME_FEATURES
    ]


# =========================================================
# MAIN TEST
# =========================================================

if __name__ == "__main__":

    sample_flow = {

        "dest_port": 8080,

        "packets_toserver": 5,
        "packets_toclient": 5,

        "bytes_toserver": 443,
        "bytes_toclient": 983,

        "duration_seconds": 0.214345,
    }

    extracted = extract_flow_features(sample_flow)

    valid, errors = validate_features(extracted)

    print("\n========== FLOW FEATURES ==========")

    for name, value in extracted.items():
        print(f"{name:35}: {value}")

    print("\n========== VALIDATION ==========")
    print("Valid:", valid)

    if errors:
        for error in errors:
            print(error)

    print("\n========== FEATURE VECTOR ==========")

    print(to_feature_vector(extracted))

