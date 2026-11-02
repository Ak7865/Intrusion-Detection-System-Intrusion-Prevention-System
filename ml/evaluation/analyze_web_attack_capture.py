from pathlib import Path
import pandas as pd

DATASET_DIR = Path(
    "datasets/raw/CIC-IDS2017/MachineLearningCVE"
)

TARGETS = [
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

for file in DATASET_DIR.glob("*.csv"):

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

            attack = chunk[labels == target]

            if attack.empty:
                continue

            zero_bytes = (
                attack["Total Length of Fwd Packets"].eq(0)
                & attack["Total Length of Bwd Packets"].eq(0)
            )

            print("\n" + "=" * 65)
            print("CAPTURE:", file.name)
            print("ATTACK:", target)
            print("Total records:", len(attack))
            print("Both directions have zero bytes:", zero_bytes.sum())
            print(
                "Percentage:",
                round(zero_bytes.mean() * 100, 2),
                "%"
            )

            print("\nFlow duration distribution:")
            print(
                attack["Flow Duration"]
                .describe()
                .round(2)
                .to_string()
            )

            print("\nPacket count distribution:")
            print(
                attack[
                    ["Total Fwd Packets", "Total Backward Packets"]
                ]
                .describe()
                .round(2)
                .to_string()
            )