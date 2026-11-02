
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd


# =====================================================
# CONFIGURATION
# =====================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_DIR = (
    PROJECT_ROOT
    / "datasets"
    / "raw"
    / "CIC-IDS2017"
    / "MachineLearningCVE"
)

CHUNK_SIZE = 100_000
OUTPUT_DIR = PROJECT_ROOT / "experiments" / "ml"

# =====================================================
# INSPECTION FUNCTION
# =====================================================

def inspect_dataset():

    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATASET_DIR}"
        )

    total_rows = 0
    total_missing = 0
    total_infinite = 0

    label_counts = Counter()
    file_statistics = []

    reference_columns = None
    feature_columns = None

    print("=" * 75)
    print("CIC-IDS2017 DATASET INSPECTION")
    print("=" * 75)

    print(f"Dataset directory: {DATASET_DIR}")
    print(f"CSV files found: {len(csv_files)}")

    # =================================================
    # PROCESS EACH CSV
    # =================================================

    for file in csv_files:

        print(f"\nProcessing: {file.name}")

        file_rows = 0

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):

            # Normalize column whitespace
            chunk.columns = chunk.columns.str.strip()

            if reference_columns is None:
                reference_columns = list(chunk.columns)

                feature_columns = [
                    col for col in chunk.columns
                    if col.lower() != "label"
                ]

            elif list(chunk.columns) != reference_columns:
                raise ValueError(
                    f"Inconsistent columns in {file.name}"
                )

            # Identify label column
            label_column = next(
                (
                    col for col in chunk.columns
                    if col.lower() == "label"
                ),
                None
            )

            if label_column is None:
                raise ValueError(
                    f"Label column missing in {file.name}"
                )

            # Count records
            rows = len(chunk)

            file_rows += rows
            total_rows += rows

            # Label distribution
            labels = (
                chunk[label_column]
                .astype("string")
                .str.strip()
            )

            label_counts.update(
                labels.value_counts().to_dict()
            )

            # Missing values
            total_missing += int(
                chunk.isna().sum().sum()
            )

            # Infinite values
            numeric = chunk.select_dtypes(
                include=[np.number]
            )

            total_infinite += int(
                np.isinf(numeric.to_numpy()).sum()
            )

        file_statistics.append({
            "file": file.name,
            "rows": file_rows,
            "size_mb": round(
                file.stat().st_size / (1024 ** 2), 2
            )
        })

        print(f"Records: {file_rows:,}")

    # =================================================
    # SUMMARY
    # =================================================

    print("\n" + "=" * 75)
    print("DATASET SUMMARY")
    print("=" * 75)

    print(f"Total CSV files: {len(csv_files)}")
    print(f"Total records: {total_rows:,}")
    print(f"Feature columns: {len(feature_columns)}")
    print(f"Missing values: {total_missing:,}")
    print(f"Infinite values: {total_infinite:,}")

    print("\nLABEL DISTRIBUTION")
    print("-" * 75)

    label_summary = []

    for label, count in label_counts.most_common():

        percentage = count / total_rows * 100

        print(
            f"{label:<35}"
            f"{count:>15,}"
            f"{percentage:>12.2f}%"
        )

        label_summary.append({
            "label": label,
            "records": count,
            "percentage": round(percentage, 4)
        })

    # =================================================
    # SAVE REPORTS
    # =================================================

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(file_statistics).to_csv(
        OUTPUT_DIR / "dataset_file_statistics.csv",
        index=False
    )

    pd.DataFrame(label_summary).to_csv(
        OUTPUT_DIR / "dataset_label_distribution.csv",
        index=False
    )

    pd.DataFrame({
        "feature": feature_columns
    }).to_csv(
        OUTPUT_DIR / "dataset_features.csv",
        index=False
    )

    print("\nReports saved in:")
    print(OUTPUT_DIR)

    print("\nDataset inspection completed successfully.")


# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":
    inspect_dataset()

