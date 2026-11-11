from pathlib import Path
import json
import time
import gc
import joblib
import numpy as np
import pandas as pd

from datetime import datetime, timezone
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

ROOT = Path(__file__).resolve().parents[2]

TRAIN_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/train.csv"
TEST_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/test.csv"

MODEL_DIR = ROOT / "ml/models/binary"
REPORT_DIR = ROOT / "ml/reports/binary"

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
    "Down/Up Ratio"
]

TARGET = "binary_label"
EXPECTED_TRAIN_ROWS = 2_211_962
EXPECTED_TEST_ROWS = 552_991
RANDOM_STATE = 42


def load_dataset(path):
    dtype_map = {feature: "float32" for feature in FEATURES}
    dtype_map["Destination Port"] = "uint16"
    dtype_map[TARGET] = "category"

    df = pd.read_csv(
        path,
        usecols=FEATURES + [TARGET],
        dtype=dtype_map
    )

    if df.isna().any().any():
        raise ValueError(f"Missing values found in {path}")

    X = df[FEATURES]
    y = df[TARGET].astype(str)

    return X, y


def calculate_class_rates(y_true, y_pred):
    labels = ["Normal", "Attack"]
    matrix = confusion_matrix(y_true, y_pred, labels=labels)

    tn, fp, fn, tp = matrix.ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return matrix, fpr, fnr


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODEL_DIR / "binary_random_forest.joblib"
    report_path = REPORT_DIR / "binary_random_forest_metrics.json"

    if model_path.exists() or report_path.exists():
        raise FileExistsError(
            "Model or report already exists. Refusing to overwrite."
        )

    print("=" * 65)
    print("BINARY RANDOM FOREST TRAINING")
    print("=" * 65)

    print("\nLoading complete training dataset...")
    X_train, y_train = load_dataset(TRAIN_PATH)

    print("Training rows:", len(X_train))

    if len(X_train) != EXPECTED_TRAIN_ROWS:
        raise ValueError("Unexpected training row count.")

    print("\nLoading complete test dataset...")
    X_test, y_test = load_dataset(TEST_PATH)

    print("Testing rows:", len(X_test))

    if len(X_test) != EXPECTED_TEST_ROWS:
        raise ValueError("Unexpected test row count.")

    if list(X_train.columns) != FEATURES:
        raise ValueError("Training feature order mismatch.")

    if list(X_test.columns) != FEATURES:
        raise ValueError("Test feature order mismatch.")

    print("\nTraining class distribution:")
    print(y_train.value_counts().to_string())

    print("\nInitializing Random Forest...")

    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=12,
        min_samples_leaf=10,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=2,
        verbose=1
    )

    print("\nStarting model training...")
    training_start = time.perf_counter()

    model.fit(X_train, y_train)

    training_time = time.perf_counter() - training_start

    print("\nTraining completed.")
    print("Training time (seconds):", round(training_time, 3))

    print("\nStarting test inference...")
    inference_start = time.perf_counter()

    y_pred = model.predict(X_test)

    inference_time = time.perf_counter() - inference_start

    inference_ms_per_flow = (
        inference_time / len(X_test)
    ) * 1000

    print("Inference time (seconds):", round(inference_time, 3))
    print(
        "Inference latency (ms/flow):",
        round(inference_ms_per_flow, 6)
    )

    print("\nCalculating evaluation metrics...")

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test, y_pred,
        pos_label="Attack",
        zero_division=0
    )

    recall = recall_score(
        y_test, y_pred,
        pos_label="Attack",
        zero_division=0
    )

    f1 = f1_score(
        y_test, y_pred,
        pos_label="Attack",
        zero_division=0
    )

    matrix, fpr, fnr = calculate_class_rates(y_test, y_pred)

    report = classification_report(
        y_test,
        y_pred,
        labels=["Normal", "Attack"],
        output_dict=True,
        zero_division=0
    )

    print("\nCONFUSION MATRIX")
    print("Labels: Normal, Attack")
    print(matrix)

    print("\nBINARY ATTACK METRICS")
    print("Accuracy:", round(accuracy, 6))
    print("Attack precision:", round(precision, 6))
    print("Attack recall:", round(recall, 6))
    print("Attack F1-score:", round(f1, 6))
    print("False-positive rate:", round(fpr, 6))
    print("False-negative rate:", round(fnr, 6))

    print("\nCLASSIFICATION REPORT")
    print(classification_report(
        y_test,
        y_pred,
        labels=["Normal", "Attack"],
        zero_division=0
    ))

    print("\nSaving trained model...")
    joblib.dump(model, model_path, compress=3)

    metrics = {
        "experiment": "Binary Random Forest",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "RandomForestClassifier",
        "configuration": {
            "n_estimators": 50,
            "max_depth": 12,
            "min_samples_leaf": 10,
            "class_weight": "balanced_subsample",
            "random_state": RANDOM_STATE,
            "n_jobs": 2
        },
        "features": FEATURES,
        "target": TARGET,
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "training_time_seconds": training_time,
        "inference_time_seconds": inference_time,
        "inference_latency_ms_per_flow": inference_ms_per_flow,
        "accuracy": accuracy,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": {
            "labels": ["Normal", "Attack"],
            "matrix": matrix.tolist()
        },
        "classification_report": report,
        "model_file": str(model_path.relative_to(ROOT))
    }

    report_path.write_text(
        json.dumps(metrics, indent=4),
        encoding="utf-8"
    )

    print("\nModel saved:", model_path)
    print("Metrics saved:", report_path)

    print("\nBINARY RANDOM FOREST EXPERIMENT COMPLETED.")

    del X_train, y_train, X_test, y_test, y_pred
    gc.collect()


if __name__ == "__main__":
    main()

