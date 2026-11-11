from pathlib import Path
from datetime import datetime, timezone
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support
)


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

TRAIN_PATH = (
    ROOT / "datasets/splits/cicids2017_v2/multiclass/train.csv"
)

TEST_PATH = (
    ROOT / "datasets/splits/cicids2017_v2/multiclass/test.csv"
)

MODEL_DIR = ROOT / "ml/models/multiclass"
REPORT_DIR = ROOT / "ml/reports/multiclass"

MODEL_PATH = (
    MODEL_DIR / "multiclass_random_forest.joblib"
)

REPORT_PATH = (
    REPORT_DIR / "multiclass_random_forest_metrics.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

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

TARGET = "multiclass_label"

EXPECTED_TRAIN_ROWS = 2_211_941
EXPECTED_TEST_ROWS = 552_985

RANDOM_STATE = 42

N_ESTIMATORS = 100
MAX_DEPTH = 16
MIN_SAMPLES_LEAF = 5
N_JOBS = 2


# ============================================================
# MAIN
# ============================================================

def main():

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Prevent accidental overwriting of previous results.

    if MODEL_PATH.exists():
        raise FileExistsError(
            f"Model already exists: {MODEL_PATH}"
        )

    if REPORT_PATH.exists():
        raise FileExistsError(
            f"Report already exists: {REPORT_PATH}"
        )

    print("=" * 65)
    print("MULTICLASS RANDOM FOREST TRAINING")
    print("=" * 65)


    # ========================================================
    # LOAD TRAINING DATA
    # ========================================================

    print("\nLoading training dataset...")

    train_df = pd.read_csv(TRAIN_PATH)

    if len(train_df) != EXPECTED_TRAIN_ROWS:
        raise ValueError(
            f"Expected {EXPECTED_TRAIN_ROWS} training records, "
            f"found {len(train_df)}."
        )

    X_train = train_df[FEATURES]
    y_train = train_df[TARGET]

    print("Training records:", len(X_train))
    print("Training features:", len(FEATURES))

    print("\nTraining class distribution:")
    print(y_train.value_counts())


    # ========================================================
    # LOAD TEST DATA
    # ========================================================

    print("\nLoading test dataset...")

    test_df = pd.read_csv(TEST_PATH)

    if len(test_df) != EXPECTED_TEST_ROWS:
        raise ValueError(
            f"Expected {EXPECTED_TEST_ROWS} test records, "
            f"found {len(test_df)}."
        )

    X_test = test_df[FEATURES]
    y_test = test_df[TARGET]

    print("Test records:", len(X_test))

    print("\nTest class distribution:")
    print(y_test.value_counts())


    # ========================================================
    # DATA VALIDATION
    # ========================================================

    print("\nValidating datasets...")

    if X_train.isna().any().any():
        raise ValueError("Missing values found in training features.")

    if X_test.isna().any().any():
        raise ValueError("Missing values found in test features.")

    if not np.isfinite(X_train.to_numpy()).all():
        raise ValueError("Infinite values found in training features.")

    if not np.isfinite(X_test.to_numpy()).all():
        raise ValueError("Infinite values found in test features.")

    if not (X_train >= 0).all().all():
        raise ValueError("Negative values found in training features.")

    if not (X_test >= 0).all().all():
        raise ValueError("Negative values found in test features.")

    if set(y_train.unique()) != set(y_test.unique()):
        raise ValueError(
            "Training and test class sets do not match."
        )

    print("Dataset validation passed.")


    # ========================================================
    # RELEASE DATAFRAME MEMORY
    # ========================================================

    del train_df
    del test_df

    gc.collect()


    # ========================================================
    # RANDOM FOREST MODEL
    # ========================================================

    print("\nInitializing Random Forest...")

    model = RandomForestClassifier(

        n_estimators=N_ESTIMATORS,

        max_depth=MAX_DEPTH,

        min_samples_leaf=MIN_SAMPLES_LEAF,

        class_weight="balanced",

        random_state=RANDOM_STATE,

        n_jobs=N_JOBS,

        verbose=1
    )


    # ========================================================
    # TRAINING
    # ========================================================

    print("\nStarting model training...")

    training_start = time.perf_counter()

    model.fit(
        X_train,
        y_train
    )

    training_time = (
        time.perf_counter() - training_start
    )

    print("\nTraining completed.")

    print(
        "Training time:",
        round(training_time, 3),
        "seconds"
    )


    # ========================================================
    # SAVE MODEL
    # ========================================================

    print("\nSaving trained model...")

    joblib.dump(
        model,
        MODEL_PATH,
        compress=3
    )

    print("Model saved:", MODEL_PATH)


    # ========================================================
    # INFERENCE BENCHMARK
    # ========================================================

    print("\nStarting inference benchmark...")

    inference_start = time.perf_counter()

    y_pred = model.predict(X_test)

    inference_time = (
        time.perf_counter() - inference_start
    )

    inference_latency = (
        inference_time / len(X_test)
    ) * 1000

    throughput = (
        len(X_test) / inference_time
    )

    print(
        "Inference time:",
        round(inference_time, 4),
        "seconds"
    )

    print(
        "Latency:",
        round(inference_latency, 6),
        "ms/flow"
    )

    print(
        "Throughput:",
        round(throughput, 2),
        "flows/second"
    )


    # ========================================================
    # EVALUATION
    # ========================================================

    print("\nEvaluating model...")

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision_macro, recall_macro, f1_macro, _ = (
        precision_recall_fscore_support(
            y_test,
            y_pred,
            average="macro",
            zero_division=0
        )
    )

    precision_weighted, recall_weighted, f1_weighted, _ = (
        precision_recall_fscore_support(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0
        )
    )

    labels = list(model.classes_)

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    report = classification_report(
        y_test,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0
    )


    # ========================================================
    # BUILD METRICS REPORT
    # ========================================================

    metrics = {

        "experiment": "Multiclass Random Forest",

        "created_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "dataset": "CIC-IDS2017",

        "training_records": EXPECTED_TRAIN_ROWS,

        "test_records": EXPECTED_TEST_ROWS,

        "features": FEATURES,

        "target": TARGET,

        "classes": labels,

        "model_parameters": {

            "algorithm": "RandomForestClassifier",

            "n_estimators": N_ESTIMATORS,

            "max_depth": MAX_DEPTH,

            "min_samples_leaf": MIN_SAMPLES_LEAF,

            "class_weight": "balanced",

            "random_state": RANDOM_STATE,

            "n_jobs": N_JOBS
        },

        "training_time_seconds": training_time,

        "inference_time_seconds": inference_time,

        "inference_latency_ms_per_flow": inference_latency,

        "throughput_flows_per_second": throughput,

        "accuracy": accuracy,

        "macro_precision": precision_macro,

        "macro_recall": recall_macro,

        "macro_f1": f1_macro,

        "weighted_precision": precision_weighted,

        "weighted_recall": recall_weighted,

        "weighted_f1": f1_weighted,

        "confusion_matrix": {

            "labels": labels,

            "matrix": cm.tolist()
        },

        "classification_report": report
    }


    # ========================================================
    # SAVE REPORT
    # ========================================================

    REPORT_PATH.write_text(
        json.dumps(metrics, indent=4),
        encoding="utf-8"
    )


    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\n" + "=" * 65)

    print("MULTICLASS RANDOM FOREST RESULTS")

    print("=" * 65)

    print(f"Accuracy:          {accuracy:.6f}")

    print(f"Macro Precision:   {precision_macro:.6f}")

    print(f"Macro Recall:      {recall_macro:.6f}")

    print(f"Macro F1-score:    {f1_macro:.6f}")

    print(f"Weighted F1-score: {f1_weighted:.6f}")


    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            labels=labels,
            zero_division=0
        )
    )


    print("\nConfusion Matrix:")

    print(cm)


    print("\nModel saved:", MODEL_PATH)

    print("Metrics saved:", REPORT_PATH)

    print("\nMULTICLASS RANDOM FOREST TRAINING COMPLETED.")


if __name__ == "__main__":

    main()
