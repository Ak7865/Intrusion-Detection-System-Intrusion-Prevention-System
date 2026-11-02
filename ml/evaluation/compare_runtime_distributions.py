import json
import pandas as pd
import numpy as np

from pathlib import Path

TRAIN_FILE = Path(
    "datasets/processed/splits/train.csv"
)

RUNTIME_FILE = Path(
    "logs/unified-features-node-a.jsonl"
)

FEATURES = [
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

# --------------------------------------------------
# Load CIC-IDS2017 training data
# --------------------------------------------------

print("Loading CIC-IDS2017 training data...")

train = pd.read_csv(
    TRAIN_FILE,
    usecols=FEATURES
)

# --------------------------------------------------
# Load Suricata runtime features
# --------------------------------------------------

print("Loading Suricata runtime features...")

runtime_records = []

with RUNTIME_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        record = json.loads(line)

        runtime_records.append(
            record["network_features"]
        )

runtime = pd.DataFrame(runtime_records)

# --------------------------------------------------
# Compare distributions
# --------------------------------------------------

for feature in FEATURES:

    train_values = pd.to_numeric(
        train[feature],
        errors="coerce"
    ).replace([np.inf, -np.inf], np.nan).dropna()

    runtime_values = pd.to_numeric(
        runtime[feature],
        errors="coerce"
    ).replace([np.inf, -np.inf], np.nan).dropna()

    print("\n" + "=" * 65)
    print(feature)
    print("=" * 65)

    print("\nCIC-IDS2017:")
    print(
        train_values.describe(
            percentiles=[0.50, 0.95]
        ).to_string()
    )

    print("\nSURICATA RUNTIME:")
    print(
        runtime_values.describe(
            percentiles=[0.50, 0.95]
        ).to_string()
    )

    print(
        "\nTraining zero percentage:",
        round((train_values == 0).mean() * 100, 2),
        "%"
    )

    print(
        "Runtime zero percentage:",
        round((runtime_values == 0).mean() * 100, 2),
        "%"
    )

print("\nDISTRIBUTION COMPARISON COMPLETED.")