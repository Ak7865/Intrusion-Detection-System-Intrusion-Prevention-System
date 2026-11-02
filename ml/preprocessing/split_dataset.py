import json
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.model_selection import StratifiedGroupKFold

# =========================================================
# CONFIGURATION
# =========================================================

INPUT_FILE = Path(
    "datasets/processed/cicids2017_clean.csv"
)

OUTPUT_DIR = Path(
    "datasets/processed/splits"
)

RANDOM_STATE = 42

# =========================================================
# LOAD DATASET
# =========================================================

print("=" * 65)
print("GROUP-AWARE DATASET SPLITTING")
print("=" * 65)

df = pd.read_csv(INPUT_FILE)

print("\nLoaded records:", len(df))

X = df.drop(columns=["Label"])
y = df["Label"]

# =========================================================
# CREATE GROUP IDENTIFIERS
# =========================================================

print("\nGenerating feature group identifiers...")

groups = pd.util.hash_pandas_object(
    X,
    index=False
).to_numpy()

print("Unique feature groups:", len(np.unique(groups)))

# =========================================================
# FIRST SPLIT: TRAIN+VALIDATION / TEST
# =========================================================

print("\nCreating first group-aware split...")

splitter_1 = StratifiedGroupKFold(
    n_splits=7,
    shuffle=True,
    random_state=RANDOM_STATE
)

train_val_idx, test_idx = next(
    splitter_1.split(X, y, groups)
)

# =========================================================
# SECOND SPLIT: TRAIN / VALIDATION
# =========================================================

print("Creating second group-aware split...")

X_train_val = X.iloc[train_val_idx]
y_train_val = y.iloc[train_val_idx]

groups_train_val = groups[train_val_idx]

splitter_2 = StratifiedGroupKFold(
    n_splits=6,
    shuffle=True,
    random_state=RANDOM_STATE
)

train_relative_idx, val_relative_idx = next(
    splitter_2.split(
        X_train_val,
        y_train_val,
        groups_train_val
    )
)

train_idx = train_val_idx[train_relative_idx]
val_idx = train_val_idx[val_relative_idx]

# =========================================================
# CREATE PARTITIONS
# =========================================================

train_df = df.iloc[train_idx].copy()
val_df = df.iloc[val_idx].copy()
test_df = df.iloc[test_idx].copy()

# =========================================================
# VERIFY GROUP ISOLATION
# =========================================================

train_groups = set(groups[train_idx])
val_groups = set(groups[val_idx])
test_groups = set(groups[test_idx])

assert train_groups.isdisjoint(val_groups)
assert train_groups.isdisjoint(test_groups)
assert val_groups.isdisjoint(test_groups)

# =========================================================
# SAVE DATASETS
# =========================================================

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

train_df.to_csv(OUTPUT_DIR / "train.csv", index=False)
val_df.to_csv(OUTPUT_DIR / "validation.csv", index=False)
test_df.to_csv(OUTPUT_DIR / "test.csv", index=False)

# =========================================================
# GENERATE CLASS DISTRIBUTION REPORT
# =========================================================

partitions = {
    "train": train_df,
    "validation": val_df,
    "test": test_df,
}

report = {}

for name, partition in partitions.items():

    report[name] = {
        "records": len(partition),
        "unique_groups": int(
            groups[
                partition.index.to_numpy()
            ].size
        ),
        "class_distribution": {
            str(label): int(count)
            for label, count in
            partition["Label"].value_counts().items()
        },
    }

    print(f"\n{name.upper()}")

    print("Records:", len(partition))

    print("\nClass distribution:")

    print(
        partition["Label"]
        .value_counts()
        .to_string()
    )

with open(
    OUTPUT_DIR / "split_report.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(report, file, indent=4)

# =========================================================
# FINAL SUMMARY
# =========================================================

total = len(df)

print("\n" + "=" * 65)
print("SPLITTING COMPLETED")
print("=" * 65)

for name, partition in partitions.items():

    percentage = len(partition) / total * 100

    print(
        f"{name.upper():12} "
        f"{len(partition):>10,} "
        f"({percentage:.2f}%)"
    )

print("\nGroup leakage: NONE DETECTED")

print("\nOutput directory:", OUTPUT_DIR)