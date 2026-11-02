import pandas as pd
from pathlib import Path

DATASET_DIR = Path(
    "datasets/raw/CIC-IDS2017/MachineLearningCVE"
)

TARGETS = [
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Packet Length Mean",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
]

for file in DATASET_DIR.glob("*.csv"):

    print(f"\nFILE: {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=100_000,
        encoding_errors="replace"
    ):

        chunk.columns = chunk.columns.str.strip()

        labels = (
            chunk["Label"]
            .astype(str)
            .str.strip()
            .str.replace("�", "-", regex=False)
        )

        for target in TARGETS:

            subset = chunk[labels == target]

            if subset.empty:
                continue

            print(f"\nATTACK: {target}")
            print(f"Records in this chunk: {len(subset)}")

            print(
                subset[FEATURES]
                .describe()
                .round(3)
                .to_string()
            )

            print("\nZero-value percentages:")

            zero_percent = (
                subset[FEATURES]
                .eq(0)
                .mean()
                .mul(100)
                .round(2)
            )

            print(zero_percent.to_string())