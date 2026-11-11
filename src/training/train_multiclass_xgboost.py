from pathlib import Path
from datetime import datetime, timezone
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd

from xgboost import XGBClassifier

from sklearn.preprocessing import LabelEncoder
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
    MODEL_DIR / "multiclass_xgboost.json"
)

ENCODER_PATH = (
    MODEL_DIR / "multiclass_xgboost_label_encoder.joblib"
)

REPORT_PATH = (
    REPORT_DIR / "multiclass_xgboost_metrics.json"
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

N_ESTIMATORS = 200
MAX_DEPTH = 8
LEARNING_RATE = 0.1

SUBSAMPLE = 0.8
COLSAMPLE_BYTREE = 0.8

MAX_BIN = 256
N_JOBS = 2


# ============================================================
# MAIN
# ============================================================

def main():

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Prevent accidental overwriting.

    for path in [MODEL_PATH, ENCODER_PATH, REPORT_PATH]:

        if path.exists():
            raise FileExistsError(
                f"Output already exists: {path}"
            )

    print("=" * 65)
    print("MULTICLASS XGBOOST TRAINING")
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

    X_train = train_df[FEATURES].copy()
    y_train_text = train_df[TARGET].copy()

    print("Training records:", len(X_train))
    print("Training features:", len(FEATURES))

    print("\nTraining class distribution:")
    print(y_train_text.value_counts())


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

    X_test = test_df[FEATURES].copy()
    y_test_text = test_df[TARGET].copy()

    print("Test records:", len(X_test))

    print("\nTest class distribution:")
    print(y_test_text.value_counts())


    # ========================================================
    # DATA VALIDATION
    # ========================================================

    print("\nValidating datasets...")

    if list(X_train.columns) != FEATURES:
        raise ValueError("Training feature order mismatch.")

    if list(X_test.columns) != FEATURES:
        raise ValueError("Test feature order mismatch.")

    if X_train.isna().any().any():
        raise ValueError("Missing values in training features.")

    if X_test.isna().any().any():
        raise ValueError("Missing values in test features.")

    if not np.isfinite(X_train.to_numpy()).all():
        raise ValueError("Infinite values in training features.")

    if not np.isfinite(X_test.to_numpy()).all():
        raise ValueError("Infinite values in test features.")

    if not (X_train >= 0).all().all():
        raise ValueError("Negative values in training features.")

    if not (X_test >= 0).all().all():
        raise ValueError("Negative values in test features.")

    if set(y_train_text.unique()) != set(y_test_text.unique()):
        raise ValueError(
            "Training and test class sets do not match."
        )

    print("Dataset validation passed.")


    # ========================================================
    # LABEL ENCODING
    # ========================================================

    print("\nEncoding multiclass labels...")

    label_encoder = LabelEncoder()

    y_train = label_encoder.fit_transform(
        y_train_text
    )

    y_test = label_encoder.transform(
        y_test_text
    )

    class_names = label_encoder.classes_.tolist()

    num_classes = len(class_names)

    print("Number of classes:", num_classes)

    print("Class mapping:")

    for index, class_name in enumerate(class_names):
        print(f"{index}: {class_name}")


    # ========================================================
    # RELEASE ORIGINAL DATAFRAME MEMORY
    # ========================================================

    del train_df
    del test_df

    del y_train_text
    del y_test_text

    gc.collect()


    # ========================================================
    # INITIALIZE XGBOOST
    # ========================================================

    print("\nInitializing XGBoost...")

    model = XGBClassifier(

        objective="multi:softprob",

        num_class=num_classes,

        eval_metric="mlogloss",

        n_estimators=N_ESTIMATORS,

        max_depth=MAX_DEPTH,

        learning_rate=LEARNING_RATE,

        subsample=SUBSAMPLE,

        colsample_bytree=COLSAMPLE_BYTREE,

        tree_method="hist",

        max_bin=MAX_BIN,

        random_state=RANDOM_STATE,

        n_jobs=N_JOBS,

        verbosity=1
    )


    # ========================================================
    # TRAINING
    # ========================================================

    print("\nStarting XGBoost training...")

    training_start = time.perf_counter()

    model.fit(
        X_train,
        y_train,
        verbose=True
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
    # SAVE MODEL AND LABEL ENCODER
    # ========================================================

    print("\nSaving XGBoost model...")

    model.save_model(
        str(MODEL_PATH)
    )

    joblib.dump(
        label_encoder,
        ENCODER_PATH
    )

    print("Model saved:", MODEL_PATH)

    print("Label encoder saved:", ENCODER_PATH)


    # ========================================================
    # INFERENCE BENCHMARK
    # ========================================================

    print("\nStarting inference benchmark...")

    # Warm-up, excluded from timing.

    warmup_size = min(1000, len(X_test))

    model.predict(
        X_test.iloc[:warmup_size]
    )

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

    print("\nEvaluating XGBoost...")

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    (
        precision_macro,
        recall_macro,
        f1_macro,
        _
    ) = precision_recall_fscore_support(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    (
        precision_weighted,
        recall_weighted,
        f1_weighted,
        _
    ) = precision_recall_fscore_support(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    labels = list(range(num_classes))

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    class_report = classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )


    # ========================================================
    # BUILD METRICS REPORT
    # ========================================================

    metrics = {

        "experiment": "Multiclass XGBoost",

        "created_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "dataset": "CIC-IDS2017",

        "training_records": EXPECTED_TRAIN_ROWS,

        "test_records": EXPECTED_TEST_ROWS,

        "features": FEATURES,

        "target": TARGET,

        "classes": class_names,

        "class_mapping": {
            str(index): class_name
            for index, class_name in enumerate(class_names)
        },

        "class_weighting": "None (unweighted baseline)",

        "model_parameters": {

            "algorithm": "XGBClassifier",

            "objective": "multi:softprob",

            "num_class": num_classes,

            "eval_metric": "mlogloss",

            "n_estimators": N_ESTIMATORS,

            "max_depth": MAX_DEPTH,

            "learning_rate": LEARNING_RATE,

            "subsample": SUBSAMPLE,

            "colsample_bytree": COLSAMPLE_BYTREE,

            "tree_method": "hist",

            "max_bin": MAX_BIN,

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

            "labels": class_names,

            "matrix": cm.tolist()
        },

        "classification_report": class_report
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

    print("MULTICLASS XGBOOST RESULTS")

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
            target_names=class_names,
            zero_division=0
        )
    )


    print("\nConfusion Matrix:")

    print(cm)


    print("\nModel saved:", MODEL_PATH)

    print("Encoder saved:", ENCODER_PATH)

    print("Metrics saved:", REPORT_PATH)

    print("\nMULTICLASS XGBOOST TRAINING COMPLETED.")


    del X_train
    del X_test
    del y_train
    del y_test
    del y_pred
    del model
    del label_encoder

    gc.collect()


if __name__ == "__main__":

    main()
