from pathlib import Path
from datetime import datetime, timezone
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd

from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

ROOT = Path(__file__).resolve().parents[2]

TEST_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/test.csv"

RF_PATH = ROOT / "ml/models/binary/binary_random_forest.joblib"
XGB_PATH = ROOT / "ml/models/binary/binary_xgboost.json"

OUTPUT_DIR = ROOT / "ml/reports/binary/ensemble"
REPORT_PATH = OUTPUT_DIR / "binary_soft_voting_ensemble_metrics.json"

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
EXPECTED_TEST_ROWS = 552_991
CHUNK_SIZE = 50_000
RF_WEIGHT = 0.5
XGB_WEIGHT = 0.5
THRESHOLD = 0.5


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if REPORT_PATH.exists():
        raise FileExistsError(
            f"Report already exists. Refusing to overwrite: {REPORT_PATH}"
        )

    for path in [TEST_PATH, RF_PATH, XGB_PATH]:
        if not path.exists():
            raise FileNotFoundError(path)

    print("=" * 65)
    print("BINARY RF + XGBOOST SOFT-VOTING ENSEMBLE")
    print("=" * 65)

    print("\nLoading trained Random Forest...")
    rf_model = joblib.load(RF_PATH)

    print("Loading trained XGBoost...")
    xgb_model = XGBClassifier()
    xgb_model.load_model(XGB_PATH)

    if list(rf_model.feature_names_in_) != FEATURES:
        raise ValueError("Random Forest feature order mismatch.")

    if list(xgb_model.feature_names_in_) != FEATURES:
        raise ValueError("XGBoost feature order mismatch.")

    rf_attack_index = list(rf_model.classes_).index("Attack")
    xgb_attack_index = list(xgb_model.classes_).index(1)

    dtype_map = {feature: "float32" for feature in FEATURES}
    dtype_map["Destination Port"] = "uint16"
    dtype_map[TARGET] = "category"

    y_true_parts = []
    y_pred_parts = []

    total_rows = 0
    inference_start = time.perf_counter()

    print("\nProcessing test data in chunks...")

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            TEST_PATH,
            usecols=FEATURES + [TARGET],
            dtype=dtype_map,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):
        if chunk.isna().any().any():
            raise ValueError(
                f"Missing values found in test chunk {chunk_number}."
            )

        X_chunk = chunk[FEATURES]
        y_chunk = chunk[TARGET].astype(str)

        if list(X_chunk.columns) != FEATURES:
            raise ValueError("Test feature order mismatch.")

        rf_probabilities = rf_model.predict_proba(X_chunk)
        xgb_probabilities = xgb_model.predict_proba(X_chunk)

        rf_attack_probability = rf_probabilities[:, rf_attack_index]
        xgb_attack_probability = xgb_probabilities[:, xgb_attack_index]

        ensemble_probability = (
            RF_WEIGHT * rf_attack_probability
            + XGB_WEIGHT * xgb_attack_probability
        )

        predictions = np.where(
            ensemble_probability >= THRESHOLD,
            "Attack",
            "Normal"
        )

        y_true_parts.append(y_chunk.to_numpy())
        y_pred_parts.append(predictions)

        total_rows += len(chunk)

        print(
            f"Chunk {chunk_number}: "
            f"{len(chunk):,} rows processed "
            f"(total: {total_rows:,})"
        )

        del chunk, X_chunk, y_chunk
        del rf_probabilities, xgb_probabilities
        del ensemble_probability, predictions

    inference_time = time.perf_counter() - inference_start

    if total_rows != EXPECTED_TEST_ROWS:
        raise ValueError(
            f"Expected {EXPECTED_TEST_ROWS} test rows, got {total_rows}."
        )

    y_true = np.concatenate(y_true_parts)
    y_pred = np.concatenate(y_pred_parts)

    inference_latency = (inference_time / total_rows) * 1000

    labels = ["Normal", "Attack"]
    matrix = confusion_matrix(y_true, y_pred, labels=labels)

    tn, fp, fn, tp = matrix.ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(
        y_true, y_pred, pos_label="Attack", zero_division=0
    )
    recall = recall_score(
        y_true, y_pred, pos_label="Attack", zero_division=0
    )
    f1 = f1_score(
        y_true, y_pred, pos_label="Attack", zero_division=0
    )

    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0
    )

    print("\n" + "=" * 65)
    print("ENSEMBLE EVALUATION RESULTS")
    print("=" * 65)

    print("\nConfusion matrix (Normal, Attack):")
    print(matrix)

    print("\nClassification report:")
    print(classification_report(
        y_true, y_pred, labels=labels, zero_division=0
    ))

    print("Accuracy:", round(accuracy, 6))
    print("Attack precision:", round(precision, 6))
    print("Attack recall:", round(recall, 6))
    print("Attack F1-score:", round(f1, 6))
    print("False-positive rate:", round(fpr, 6))
    print("False-negative rate:", round(fnr, 6))
    print("Inference time (seconds):", round(inference_time, 3))
    print("Inference latency (ms/flow):", round(inference_latency, 6))

    metrics = {
        "experiment": "Binary RF + XGBoost Soft Voting Ensemble",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "Equal-weight probability averaging",
        "configuration": {
            "random_forest_weight": RF_WEIGHT,
            "xgboost_weight": XGB_WEIGHT,
            "attack_probability_threshold": THRESHOLD,
            "chunk_size": CHUNK_SIZE
        },
        "features": FEATURES,
        "target": TARGET,
        "testing_records": total_rows,
        "inference_time_seconds": inference_time,
        "inference_latency_ms_per_flow": inference_latency,
        "accuracy": accuracy,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.tolist()
        },
        "classification_report": report,
        "component_models": [
            str(RF_PATH.relative_to(ROOT)),
            str(XGB_PATH.relative_to(ROOT))
        ]
    }

    REPORT_PATH.write_text(
        json.dumps(metrics, indent=4),
        encoding="utf-8"
    )

    print("\nMetrics saved:", REPORT_PATH)
    print("\nENSEMBLE EVALUATION COMPLETED.")

    del y_true_parts, y_pred_parts, y_true, y_pred
    del rf_model, xgb_model
    gc.collect()


if __name__ == "__main__":
    main()
