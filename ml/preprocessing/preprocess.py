
from pathlib import Path

import numpy as np
import pandas as pd

from ml.preprocessing.feature_schema import (
    RUNTIME_FEATURES,
    TARGET_COLUMN,
)

# =====================================================
# CONFIGURATION
# =====================================================

ROOT = Path(__file__).resolve().parents[2]

SOURCE_DIR = (
    ROOT / "datasets" / "raw" /
    "CIC-IDS2017" / "MachineLearningCVE"
)

OUTPUT_DIR = ROOT / "datasets" / "processed"

OUTPUT_FILE = OUTPUT_DIR / "cicids2017_runtime_features.csv"

CHUNK_SIZE = 100_000

# =====================================================
# LABEL NORMALIZATION
# =====================================================

def normalize_label(label):

    label = str(label).strip()

    replacements = {
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack � XSS": "Web Attack - XSS",
        "Web Attack � Sql Injection": "Web Attack - SQL Injection",
    }

    return replacements.get(label, label)


# =====================================================
# PREPROCESSING
# =====================================================

def preprocess_dataset():

    files = sorted(SOURCE_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError("CIC-IDS2017 CSV files not found.")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    total_rows = 0
    total_invalid_rows = 0

    print("=" * 65)
    print("CIC-IDS2017 PREPROCESSING")
    print("=" * 65)

    for file in files:

        print(f"\nProcessing: {file.name}")

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
            encoding="utf-8"
        ):

            chunk.columns = chunk.columns.str.strip()

            # Normalize label column
            label_col = next(
                (
                    col for col in chunk.columns
                    if col.lower() == TARGET_COLUMN.lower()
                ),
                None
            )

            if label_col is None:
                raise ValueError("Label column not found.")

            # Validate feature schema
            missing_features = [
                feature for feature in RUNTIME_FEATURES
                if feature not in chunk.columns
            ]

            if missing_features:
                raise ValueError(
                    f"Missing features: {missing_features}"
                )

            # Select features and target
            data = chunk[RUNTIME_FEATURES + [label_col]].copy()

            data.rename(
                columns={label_col: TARGET_COLUMN},
                inplace=True
            )

            # Normalize labels
            data[TARGET_COLUMN] = (
                data[TARGET_COLUMN]
                .astype("string")
                .str.strip()
                .map(normalize_label)
            )

            # Convert features to numeric
            for feature in RUNTIME_FEATURES:

                data[feature] = pd.to_numeric(
                    data[feature],
                    errors="coerce"
                )

            # Replace infinite values
            data.replace(
                [np.inf, -np.inf],
                np.nan,
                inplace=True
            )

            # Remove records with invalid labels
            valid_labels = (
                data[TARGET_COLUMN].notna()
                & data[TARGET_COLUMN].ne("")
            )

            total_invalid_rows += int((~valid_labels).sum())

            data = data.loc[valid_labels].copy()

            # Drop rows with missing values in selected features.
            # We will evaluate the impact before choosing imputation.
            before = len(data)

            data.dropna(
                subset=RUNTIME_FEATURES,
                inplace=True
            )

            total_invalid_rows += before - len(data)

            # Save processed chunk
            if not data.empty:

                data.to_csv(
                    OUTPUT_FILE,
                    mode="a",
                    index=False,
                    header=not OUTPUT_FILE.exists()
                )

                total_rows += len(data)

        print(f"Processed records so far: {total_rows:,}")

    print("\n" + "=" * 65)
    print("PREPROCESSING COMPLETED")
    print("=" * 65)

    print(f"Valid records: {total_rows:,}")
    print(f"Discarded invalid records: {total_invalid_rows:,}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    preprocess_dataset()

