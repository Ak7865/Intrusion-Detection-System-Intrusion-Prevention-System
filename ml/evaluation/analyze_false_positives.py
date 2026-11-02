from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.preprocessing.feature_schema import RUNTIME_FEATURES


# --------------------------------------------------
# PATHS AND CONFIGURATION
# --------------------------------------------------

MODEL_PATH = Path("ml/models/random_forest_pilot.joblib")
VALIDATION_PATH = Path("datasets/processed/splits/validation.csv")
OUTPUT_DIR = Path("experiments/ml/false_positive_analysis")

TARGET_CLASSES = [
    "Bot",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# LOAD MODEL AND VALIDATION DATA
# --------------------------------------------------

print("Loading trained model...")

model = joblib.load(MODEL_PATH)

print("Loading validation dataset...")

df = pd.read_csv(VALIDATION_PATH)

X = df[RUNTIME_FEATURES].astype(np.float32)
y_true = df["Label"].astype(str)

print(f"Validation records: {len(df):,}")

print("\nGenerating predictions...")

y_pred = model.predict(X)

df["Predicted"] = y_pred
df["Actual"] = y_true


# --------------------------------------------------
# FALSE POSITIVE ANALYSIS
# --------------------------------------------------

all_summaries = []

for target in TARGET_CLASSES:

    print("\n" + "=" * 65)
    print(f"ANALYSIS: BENIGN vs {target}")
    print("=" * 65)

    # Correctly classified benign records
    benign_correct = df[
        (df["Actual"] == "BENIGN") &
        (df["Predicted"] == "BENIGN")
    ]

    # Benign records incorrectly classified as target
    benign_false_positive = df[
        (df["Actual"] == "BENIGN") &
        (df["Predicted"] == target)
    ]

    # Correctly classified target attack records
    attack_correct = df[
        (df["Actual"] == target) &
        (df["Predicted"] == target)
    ]

    # Target attacks missed or classified as another class
    attack_missed = df[
        (df["Actual"] == target) &
        (df["Predicted"] != target)
    ]

    print(f"Correct BENIGN:       {len(benign_correct):,}")
    print(f"BENIGN -> {target}: {len(benign_false_positive):,}")
    print(f"Correct {target}: {len(attack_correct):,}")
    print(f"Missed {target}:   {len(attack_missed):,}")

    groups = {
        "BENIGN_CORRECT": benign_correct,
        "BENIGN_FALSE_POSITIVE": benign_false_positive,
        "ATTACK_CORRECT": attack_correct,
        "ATTACK_MISSED": attack_missed,
    }

    # Feature distribution comparison
    for group_name, group_df in groups.items():

        if group_df.empty:
            continue

        for feature in RUNTIME_FEATURES:

            values = group_df[feature].replace(
                [np.inf, -np.inf], np.nan
            ).dropna()

            if values.empty:
                continue

            all_summaries.append({
                "Target_Class": target,
                "Group": group_name,
                "Feature": feature,
                "Count": len(values),
                "Mean": values.mean(),
                "Median": values.median(),
                "P25": values.quantile(0.25),
                "P75": values.quantile(0.75),
            })


# --------------------------------------------------
# SAVE RESULTS
# --------------------------------------------------

summary_df = pd.DataFrame(all_summaries)

output_file = OUTPUT_DIR / "feature_distribution_comparison.csv"

summary_df.to_csv(output_file, index=False)

print("\n" + "=" * 65)
print("ANALYSIS COMPLETED")
print("=" * 65)

print(f"Report saved to: {output_file}")