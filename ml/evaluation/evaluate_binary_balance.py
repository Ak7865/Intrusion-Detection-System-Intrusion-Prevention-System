import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
    confusion_matrix,
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

VAL_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

MODEL_FILE = Path(
    "ml/models/random_forest_binary_pilot.joblib"
)

RANDOM_STATE = 42

print("=" * 65)
print("BINARY MODEL: NATURAL VS BALANCED VALIDATION")
print("=" * 65)

# Load validation data
df = pd.read_csv(
    VAL_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

df["Target"] = (
    df["Label"] != "BENIGN"
).astype(np.uint8)

# Load model
model = joblib.load(MODEL_FILE)

# --------------------------------------------------
# 1. Natural validation
# --------------------------------------------------

print("\n[1] NATURAL VALIDATION")

X_natural = df[FEATURES].to_numpy(dtype=np.float32)
y_natural = df["Target"].to_numpy()

pred_natural = model.predict(X_natural)

# --------------------------------------------------
# 2. Balanced validation
# --------------------------------------------------

print("\n[2] BALANCED VALIDATION")

balanced_df = (
    df.groupby("Target", group_keys=False)
    .sample(
        n=int(df["Target"].value_counts().min()),
        random_state=RANDOM_STATE,
    )
)

X_balanced = balanced_df[FEATURES].to_numpy(
    dtype=np.float32
)

y_balanced = balanced_df["Target"].to_numpy()

pred_balanced = model.predict(X_balanced)

# --------------------------------------------------
# 3. Evaluation function
# --------------------------------------------------

def evaluate(name, actual, predicted):

    tn, fp, fn, tp = confusion_matrix(
        actual,
        predicted,
        labels=[0, 1],
    ).ravel()

    print(f"\n{name}")

    print("Records:", len(actual))

    print("Accuracy:", accuracy_score(actual, predicted))

    print(
        "Balanced Accuracy:",
        balanced_accuracy_score(actual, predicted),
    )

    print(
        "Precision:",
        precision_score(actual, predicted, zero_division=0),
    )

    print(
        "Recall:",
        recall_score(actual, predicted, zero_division=0),
    )

    print(
        "F1:",
        f1_score(actual, predicted, zero_division=0),
    )

    print("FPR:", fp / (fp + tn))

    print("FNR:", fn / (fn + tp))

    print("\nConfusion Matrix:")
    print([[tn, fp], [fn, tp]])


evaluate(
    "NATURAL VALIDATION RESULTS",
    y_natural,
    pred_natural,
)

evaluate(
    "BALANCED VALIDATION RESULTS",
    y_balanced,
    pred_balanced,
)

print("\nEvaluation completed.")