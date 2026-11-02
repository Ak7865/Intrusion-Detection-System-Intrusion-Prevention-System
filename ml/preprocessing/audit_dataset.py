
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

DATASET_DIR = (
    ROOT / "datasets" / "raw" /
    "CIC-IDS2017" / "MachineLearningCVE"
)

OUTPUT_DIR = ROOT / "experiments" / "ml"

CHUNK_SIZE = 100_000


def audit_dataset():

    files = sorted(DATASET_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError("Dataset files not found.")

    missing_counts = Counter()
    infinite_counts = Counter()
    dtypes = {}
    labels = Counter()

    total_rows = 0
    total_numeric_columns = 0

    for file in files:

        print(f"\nAuditing: {file.name}")

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ):

            chunk.columns = chunk.columns.str.strip()

            total_rows += len(chunk)

            for col in chunk.columns:

                current_dtype = str(chunk[col].dtype)

                if col not in dtypes:
                    dtypes[col] = current_dtype

                elif dtypes[col] != current_dtype:
                    dtypes[col] = "MIXED"

                missing_counts[col] += int(
                    chunk[col].isna().sum()
                )

            label_col = next(
                (
                    c for c in chunk.columns
                    if c.lower() == "label"
                ),
                None
            )

            if label_col:
                values = (
                    chunk[label_col]
                    .astype("string")
                    .str.strip()
                )

                labels.update(
                    values.value_counts().to_dict()
                )

            numeric = chunk.select_dtypes(
                include=[np.number]
            )

            if numeric.shape[1]:

                total_numeric_columns = numeric.shape[1]

                values = numeric.to_numpy(
                    dtype=np.float64,
                    na_value=np.nan
                )

                for index, col in enumerate(numeric.columns):

                    infinite_counts[col] += int(
                        np.isinf(values[:, index]).sum()
                    )

    # -----------------------------------------
    # QUALITY REPORT
    # -----------------------------------------

    all_columns = sorted(
        set(dtypes) |
        set(missing_counts) |
        set(infinite_counts)
    )

    quality_rows = []

    for col in all_columns:

        quality_rows.append({
            "feature": col,
            "dtype": dtypes.get(col),
            "missing_values": missing_counts[col],
            "infinite_values": infinite_counts[col]
        })

    quality_df = pd.DataFrame(quality_rows)

    quality_df = quality_df.sort_values(
        by=["missing_values", "infinite_values"],
        ascending=False
    )

    # -----------------------------------------
    # LABEL REPORT
    # -----------------------------------------

    label_rows = []

    for label, count in labels.most_common():

        label_rows.append({
            "label": repr(label),
            "records": count,
            "percentage": round(
                count / total_rows * 100, 5
            )
        })

    label_df = pd.DataFrame(label_rows)

    # -----------------------------------------
    # SAVE REPORTS
    # -----------------------------------------

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    quality_df.to_csv(
        OUTPUT_DIR / "dataset_quality_report.csv",
        index=False
    )

    label_df.to_csv(
        OUTPUT_DIR / "dataset_raw_labels_audit.csv",
        index=False
    )

    print("\n" + "=" * 65)
    print("DETAILED DATASET AUDIT")
    print("=" * 65)

    print(f"Total records: {total_rows:,}")
    print(f"Columns: {len(all_columns)}")
    print(f"Numeric columns in final chunk: {total_numeric_columns}")

    print("\nFEATURES WITH MISSING OR INFINITE VALUES")

    print(
        quality_df[
            (quality_df["missing_values"] > 0) |
            (quality_df["infinite_values"] > 0)
        ].to_string(index=False)
    )

    print("\nRAW LABEL REPRESENTATIONS")

    print(label_df.to_string(index=False))

    print("\nReports saved to:", OUTPUT_DIR)


if __name__ == "__main__":
    audit_dataset()

