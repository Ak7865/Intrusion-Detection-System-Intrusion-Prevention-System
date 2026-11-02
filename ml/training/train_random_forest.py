import time
import json
import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    classification_report,
)

# =====================================================
# CONFIGURATION
# =====================================================

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VAL_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("ml/models")
REPORT_DIR = Path("experiments/ml")

PILOT_SIZE = 50_000
RANDOM_STATE = 42

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

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

# =====================================================
# LOAD DATA
# =====================================================

print("=" * 65)
print("RANDOM FOREST PILOT TRAINING")
print("=" * 65)

print("\nLoading training data...")

train_df = pd.read_csv(
    TRAIN_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

print("Available training records:", len(train_df))

# Stratified pilot sample
pilot_df = (
    train_df.groupby("Label", group_keys=False)
    .sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    )
)

pilot_df = (
    pilot_df.groupby("Label", group_keys=False)
    .head(PILOT_SIZE)
)

print("Pilot records:", len(pilot_df))

del train_df

# =====================================================
# PREPARE TRAINING DATA
# =====================================================

X_train = pilot_df[FEATURES].to_numpy(dtype=np.float32)
y_train = pilot_df["Label"].to_numpy()

del pilot_df

# =====================================================
# LOAD VALIDATION DATA
# =====================================================

print("\nLoading validation data...")

val_df = pd.read_csv(
    VAL_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

X_val = val_df[FEATURES].to_numpy(dtype=np.float32)
y_val = val_df["Label"].to_numpy()

del val_df

# =====================================================
# TRAIN RANDOM FOREST
# =====================================================

model = RandomForestClassifier(
    n_estimators=30,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features="sqrt",
    max_samples=0.5,
    class_weight="balanced_subsample",
    n_jobs=2,
    random_state=RANDOM_STATE,
)

print("\nStarting Random Forest training...")

start_time = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start_time

print(f"\nTraining completed in {training_time:.2f} seconds")

# =====================================================
# VALIDATION
# =====================================================

print("\nRunning validation...")

predictions = model.predict(X_val)

metrics = {
    "accuracy": float(
        accuracy_score(y_val, predictions)
    ),
    "balanced_accuracy": float(
        balanced_accuracy_score(y_val, predictions)
    ),
    "macro_f1": float(
        f1_score(
            y_val,
            predictions,
            average="macro",
            zero_division=0,
        )
    ),
    "weighted_f1": float(
        f1_score(
            y_val,
            predictions,
            average="weighted",
            zero_division=0,
        )
    ),
    "training_time_seconds": training_time,
    "pilot_training_records": len(X_train),
    "validation_records": len(X_val),
}

print("\nVALIDATION METRICS")

for name, value in metrics.items():
    print(f"{name}: {value}")

print("\nCLASSIFICATION REPORT")

report = classification_report(
    y_val,
    predictions,
    zero_division=0,
)

print(report)

# =====================================================
# SAVE MODEL AND REPORT
# =====================================================

model_path = MODEL_DIR / "random_forest_pilot.joblib"

joblib.dump(model, model_path, compress=1)

with open(
    REPORT_DIR / "random_forest_pilot_metrics.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(metrics, file, indent=4)

with open(
    REPORT_DIR / "random_forest_pilot_classification_report.txt",
    "w",
    encoding="utf-8",
) as file:
    file.write(report)

print("\nModel saved:", model_path)

print("\nPilot experiment completed.")