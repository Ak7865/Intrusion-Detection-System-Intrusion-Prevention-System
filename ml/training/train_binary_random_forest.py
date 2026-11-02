import time
import json
import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
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

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VAL_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("ml/models")
REPORT_DIR = Path("experiments/ml")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42

print("=" * 65)
print("BINARY RANDOM FOREST EXPERIMENT")
print("=" * 65)

# --------------------------------------------------
# Load training data
# --------------------------------------------------

print("\nLoading training data...")

train_df = pd.read_csv(
    TRAIN_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

# Convert labels to binary
train_df["Target"] = (
    train_df["Label"] != "BENIGN"
).astype(np.uint8)

# Stratified pilot sample
pilot_df = (
    train_df.groupby("Target", group_keys=False)
    .sample(
        n=min(100000, train_df["Target"].value_counts().min()),
        random_state=RANDOM_STATE,
    )
)

print("Pilot records:", len(pilot_df))
print("\nTraining class distribution:")
print(pilot_df["Target"].value_counts().to_string())

X_train = pilot_df[FEATURES].to_numpy(dtype=np.float32)
y_train = pilot_df["Target"].to_numpy()

del train_df, pilot_df

# --------------------------------------------------
# Load validation data
# --------------------------------------------------

print("\nLoading validation data...")

val_df = pd.read_csv(
    VAL_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

y_val = (
    val_df["Label"] != "BENIGN"
).astype(np.uint8).to_numpy()

X_val = val_df[FEATURES].to_numpy(dtype=np.float32)

del val_df

# --------------------------------------------------
# Train model
# --------------------------------------------------

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

print("\nTraining binary classifier...")

start = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start

print(f"Training time: {training_time:.2f} seconds")

# --------------------------------------------------
# Evaluate
# --------------------------------------------------

predictions = model.predict(X_val)

metrics = {
    "accuracy": float(accuracy_score(y_val, predictions)),
    "precision": float(
        precision_score(y_val, predictions, zero_division=0)
    ),
    "recall": float(
        recall_score(y_val, predictions, zero_division=0)
    ),
    "f1": float(
        f1_score(y_val, predictions, zero_division=0)
    ),
    "training_time_seconds": training_time,
    "training_records": len(X_train),
    "validation_records": len(X_val),
}

print("\nBINARY VALIDATION METRICS")

for key, value in metrics.items():
    print(f"{key}: {value}")

print("\nCONFUSION MATRIX")
print(confusion_matrix(y_val, predictions))

print("\nCLASSIFICATION REPORT")
print(
    classification_report(
        y_val,
        predictions,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    )
)

# --------------------------------------------------
# Save
# --------------------------------------------------

joblib.dump(
    model,
    MODEL_DIR / "random_forest_binary_pilot.joblib",
    compress=1,
)

with open(
    REPORT_DIR / "random_forest_binary_metrics.json",
    "w",
    encoding="utf-8",
) as file:
    json.dump(metrics, file, indent=4)

print("\nBinary experiment completed.")
