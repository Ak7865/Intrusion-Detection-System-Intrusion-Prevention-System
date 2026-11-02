import joblib
import pandas as pd
import numpy as np

from pathlib import Path
from sklearn.metrics import (
    confusion_matrix,
    ConfusionMatrixDisplay,
    classification_report,
)

import matplotlib.pyplot as plt

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

VAL_FILE = Path("datasets/processed/splits/validation.csv")
MODEL_FILE = Path("ml/models/random_forest_pilot.joblib")

OUTPUT_DIR = Path("experiments/ml")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading validation dataset...")

df = pd.read_csv(
    VAL_FILE,
    usecols=FEATURES + ["Label"],
    dtype={feature: np.float32 for feature in FEATURES},
)

X_val = df[FEATURES].to_numpy(dtype=np.float32)
y_val = df["Label"].to_numpy()

print("Loading trained model...")

model = joblib.load(MODEL_FILE)

print("Generating predictions...")

predictions = model.predict(X_val)

labels = sorted(set(y_val) | set(predictions))

# Confusion matrix
cm = confusion_matrix(
    y_val,
    predictions,
    labels=labels,
)

cm_df = pd.DataFrame(
    cm,
    index=labels,
    columns=labels,
)

cm_df.to_csv(
    OUTPUT_DIR / "random_forest_confusion_matrix.csv"
)

# Classification report
report = classification_report(
    y_val,
    predictions,
    labels=labels,
    zero_division=0,
)

(OUTPUT_DIR / "random_forest_detailed_report.txt").write_text(
    report,
    encoding="utf-8",
)

# Confusion matrix visualization
fig, ax = plt.subplots(figsize=(16, 13))

display = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=labels,
)

display.plot(
    ax=ax,
    xticks_rotation=90,
    cmap="Blues",
    colorbar=False,
)

plt.title("Random Forest Pilot - Confusion Matrix")
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "random_forest_confusion_matrix.png",
    dpi=200,
)

plt.close()

# Most common incorrect predictions
errors = pd.DataFrame({
    "Actual": y_val,
    "Predicted": predictions,
})

errors = errors[
    errors["Actual"] != errors["Predicted"]
]

print("\nMOST COMMON MISCLASSIFICATIONS")

print(
    errors.groupby(["Actual", "Predicted"])
    .size()
    .sort_values(ascending=False)
    .head(20)
    .to_string()
)

print("\nEvaluation completed.")

print("Confusion matrix:", OUTPUT_DIR)