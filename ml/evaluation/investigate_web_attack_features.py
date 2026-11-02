from pathlib import Path

import numpy as np
import pandas as pd

DATASET_DIR = Path("datasets/raw/CIC-IDS2017/MachineLearningCVE")

TARGET_LABELS = [
    "BENIGN",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

CHUNK_SIZE = 100_000
BENIGN_SAMPLE_SIZE = 50_000

samples = {label: [] for label in TARGET_LABELS}

print("Investigating original CIC-IDS2017 features...")

for file in DATASET_DIR.glob("*.csv"):

    print(f"\nReading: {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        encoding_errors="replace"
    ):

        chunk.columns = chunk.columns.str.strip()
        chunk["Label"] = chunk["Label"].astype(str).str.strip()

        # Normalize web attack labels
        chunk["Label"] = chunk["Label"].str.replace(
            "�", "-", regex=False
        )

        for label in TARGET_LABELS:

            subset = chunk[chunk["Label"] == label]

            if subset.empty:
                continue

            if label == "BENIGN":

                remaining = (
                    BENIGN_SAMPLE_SIZE - sum(
                        len(x) for x in samples[label]
                    )
                )

                if remaining > 0:
                    samples[label].append(
                        subset.sample(
                            n=min(remaining, len(subset)),
                            random_state=42
                        )
                    )

            else:
                samples[label].append(subset)


# Combine samples
frames = {}

for label, parts in samples.items():

    if parts:
        frames[label] = pd.concat(
            parts,
            ignore_index=True
        )

    print(f"{label}: {len(frames.get(label, [])):,} records")


# Identify numeric features
numeric_features = [
    col for col in frames["BENIGN"].columns
    if col != "Label"
    and pd.api.types.is_numeric_dtype(frames["BENIGN"][col])
]

results = []

for feature in numeric_features:

    benign = pd.to_numeric(
        frames["BENIGN"][feature],
        errors="coerce"
    ).replace([np.inf, -np.inf], np.nan).dropna()

    for attack_label in TARGET_LABELS[1:]:

        attack = pd.to_numeric(
            frames[attack_label][feature],
            errors="coerce"
        ).replace([np.inf, -np.inf], np.nan).dropna()

        if benign.empty or attack.empty:
            continue

        benign_median = benign.median()
        attack_median = attack.median()

        results.append({
            "Attack": attack_label,
            "Feature": feature,
            "Benign_Median": benign_median,
            "Attack_Median": attack_median,
            "Benign_IQR": (
                benign.quantile(0.75) - benign.quantile(0.25)
            ),
            "Attack_IQR": (
                attack.quantile(0.75) - attack.quantile(0.25)
            ),
            "Benign_Nonzero_Percent": (
                benign.ne(0).mean() * 100
            ),
            "Attack_Nonzero_Percent": (
                attack.ne(0).mean() * 100
            ),
        })


report = pd.DataFrame(results)

output_dir = Path("experiments/ml/feature_investigation")
output_dir.mkdir(parents=True, exist_ok=True)

output_file = output_dir / "web_attack_feature_comparison.csv"

report.to_csv(output_file, index=False)

print("\nInvestigation completed.")
print(f"Numeric features examined: {len(numeric_features)}")
print(f"Report saved: {output_file}")