from pathlib import Path
from datetime import datetime, timezone
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

TEST_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/test.csv"

RF_PATH = ROOT / "ml/models/binary/binary_random_forest.joblib"
XGB_PATH = ROOT / "ml/models/binary/binary_xgboost.json"

OUTPUT_DIR = ROOT / "ml/reports/binary/inference_benchmark"

REPORT_PATH = OUTPUT_DIR / "binary_inference_benchmark_v2.json"


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

TARGET = "binary_label"

EXPECTED_TEST_ROWS = 552_991

CHUNK_SIZE = 50_000

RF_WEIGHT = 0.5
XGB_WEIGHT = 0.5

THRESHOLD = 0.5

WARMUP_ROWS = 1_000


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if REPORT_PATH.exists():
        raise FileExistsError(
            f"Benchmark report already exists: {REPORT_PATH}"
        )

    for path in [TEST_PATH, RF_PATH, XGB_PATH]:

        if not path.exists():
            raise FileNotFoundError(path)

    print("=" * 65)
    print("STANDARDIZED BINARY INFERENCE BENCHMARK V2")
    print("=" * 65)


    # ========================================================
    # LOAD MODELS
    # ========================================================

    print("\nLoading Random Forest...")

    rf_model = joblib.load(RF_PATH)

    print("Loading XGBoost...")

    xgb_model = XGBClassifier()

    xgb_model.load_model(XGB_PATH)


    # ========================================================
    # FEATURE VALIDATION
    # ========================================================

    if list(rf_model.feature_names_in_) != FEATURES:

        raise ValueError(
            "Random Forest feature order mismatch."
        )

    if list(xgb_model.feature_names_in_) != FEATURES:

        raise ValueError(
            "XGBoost feature order mismatch."
        )


    rf_attack_index = list(
        rf_model.classes_
    ).index("Attack")

    xgb_attack_index = list(
        xgb_model.classes_
    ).index(1)


    # ========================================================
    # CSV CONFIGURATION
    # ========================================================

    dtype_map = {
        feature: "float32"
        for feature in FEATURES
    }

    dtype_map["Destination Port"] = "uint16"

    dtype_map[TARGET] = "category"


    # ========================================================
    # WARM-UP
    # ========================================================

    print("\nPreparing inference warm-up...")

    first_chunk = next(
        pd.read_csv(
            TEST_PATH,
            usecols=FEATURES + [TARGET],
            dtype=dtype_map,
            chunksize=CHUNK_SIZE
        )
    )

    X_warmup = first_chunk[FEATURES].iloc[:WARMUP_ROWS]

    if X_warmup.isna().any().any():

        raise ValueError(
            "Missing values in warm-up data."
        )


    # Random Forest warm-up

    rf_model.predict_proba(X_warmup)


    # XGBoost warm-up

    xgb_model.predict_proba(X_warmup)


    # Ensemble warm-up

    rf_prob = rf_model.predict_proba(
        X_warmup
    )[:, rf_attack_index]

    xgb_prob = xgb_model.predict_proba(
        X_warmup
    )[:, xgb_attack_index]


    ensemble_prob = (
        RF_WEIGHT * rf_prob
        + XGB_WEIGHT * xgb_prob
    )

    np.where(
        ensemble_prob >= THRESHOLD,
        "Attack",
        "Normal"
    )

    print(
        "Warm-up completed. Warm-up time excluded."
    )

    del first_chunk
    del X_warmup

    del rf_prob
    del xgb_prob
    del ensemble_prob

    gc.collect()


    # ========================================================
    # INFERENCE TIMERS
    # ========================================================

    elapsed = {

        "random_forest": 0.0,

        "xgboost": 0.0,

        "ensemble": 0.0
    }

    total_rows = 0


    # ========================================================
    # START BENCHMARK
    # ========================================================

    print("\nStarting standardized benchmark...")

    print("Chunk size:", CHUNK_SIZE)

    benchmark_start = time.perf_counter()


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
                f"Missing values in chunk {chunk_number}."
            )

        X_chunk = chunk[FEATURES]


        # ====================================================
        # 1. RANDOM FOREST INFERENCE
        # ====================================================

        start = time.perf_counter()

        rf_probabilities = rf_model.predict_proba(
            X_chunk
        )

        rf_attack_probability = (
            rf_probabilities[:, rf_attack_index]
        )

        rf_predictions = np.where(
            rf_attack_probability >= THRESHOLD,
            "Attack",
            "Normal"
        )

        elapsed["random_forest"] += (
            time.perf_counter() - start
        )


        # ====================================================
        # 2. XGBOOST INFERENCE
        # ====================================================

        start = time.perf_counter()

        xgb_probabilities = xgb_model.predict_proba(
            X_chunk
        )

        xgb_attack_probability = (
            xgb_probabilities[:, xgb_attack_index]
        )

        xgb_predictions = np.where(
            xgb_attack_probability >= THRESHOLD,
            "Attack",
            "Normal"
        )

        elapsed["xgboost"] += (
            time.perf_counter() - start
        )


        # ====================================================
        # 3. COMPLETE ENSEMBLE INFERENCE
        # ====================================================

        start = time.perf_counter()

        # Both component model predictions

        ensemble_rf_probabilities = (
            rf_model.predict_proba(X_chunk)
        )

        ensemble_xgb_probabilities = (
            xgb_model.predict_proba(X_chunk)
        )

        ensemble_rf_attack = (
            ensemble_rf_probabilities[:, rf_attack_index]
        )

        ensemble_xgb_attack = (
            ensemble_xgb_probabilities[:, xgb_attack_index]
        )


        # Probability averaging

        ensemble_probability = (
            RF_WEIGHT * ensemble_rf_attack
            + XGB_WEIGHT * ensemble_xgb_attack
        )


        # Final binary classification

        ensemble_predictions = np.where(
            ensemble_probability >= THRESHOLD,
            "Attack",
            "Normal"
        )

        elapsed["ensemble"] += (
            time.perf_counter() - start
        )


        # ====================================================
        # PROGRESS
        # ====================================================

        total_rows += len(chunk)

        print(
            f"Chunk {chunk_number}: "
            f"{total_rows:,}/{EXPECTED_TEST_ROWS:,} records"
        )


        # ====================================================
        # MEMORY CLEANUP
        # ====================================================

        del chunk
        del X_chunk

        del rf_probabilities
        del xgb_probabilities

        del rf_attack_probability
        del xgb_attack_probability

        del rf_predictions
        del xgb_predictions

        del ensemble_rf_probabilities
        del ensemble_xgb_probabilities

        del ensemble_rf_attack
        del ensemble_xgb_attack

        del ensemble_probability
        del ensemble_predictions


    # ========================================================
    # BENCHMARK COMPLETION
    # ========================================================

    benchmark_wall_time = (
        time.perf_counter() - benchmark_start
    )

    if total_rows != EXPECTED_TEST_ROWS:

        raise ValueError(
            f"Expected {EXPECTED_TEST_ROWS} records, "
            f"processed {total_rows}."
        )


    # ========================================================
    # CALCULATE PERFORMANCE METRICS
    # ========================================================

    results = {}

    for model_name, inference_time in elapsed.items():

        results[model_name] = {

            "inference_time_seconds": inference_time,

            "latency_ms_per_flow": (
                inference_time / total_rows
            ) * 1000,

            "throughput_flows_per_second": (
                total_rows / inference_time
            )
        }


    # ========================================================
    # REPORT
    # ========================================================

    report = {

        "experiment": (
            "Standardized Binary Inference Benchmark V2"
        ),

        "created_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "test_records": total_rows,

        "chunk_size": CHUNK_SIZE,

        "warmup_records": WARMUP_ROWS,

        "timing_scope": (
            "Prediction computation only. CSV reading, "
            "model loading, and warm-up are excluded."
        ),

        "prediction_method": (
            "Individual models use predict_proba followed "
            "by threshold classification. The ensemble "
            "includes both component model predictions, "
            "probability averaging, and threshold classification."
        ),

        "ensemble_configuration": {

            "random_forest_weight": RF_WEIGHT,

            "xgboost_weight": XGB_WEIGHT,

            "attack_probability_threshold": THRESHOLD
        },

        "benchmark_wall_time_seconds": (
            benchmark_wall_time
        ),

        "results": results
    }


    REPORT_PATH.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )


    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\n" + "=" * 65)

    print("STANDARDIZED BENCHMARK V2 RESULTS")

    print("=" * 65)


    for model_name, metrics in results.items():

        print(f"\n{model_name.upper()}")

        print(
            "Inference time:",
            round(
                metrics["inference_time_seconds"],
                4
            ),
            "seconds"
        )

        print(
            "Latency:",
            round(
                metrics["latency_ms_per_flow"],
                6
            ),
            "ms/flow"
        )

        print(
            "Throughput:",
            round(
                metrics["throughput_flows_per_second"],
                2
            ),
            "flows/second"
        )


    print("\nReport saved:", REPORT_PATH)

    print("\nBENCHMARK V2 COMPLETED.")


    del rf_model
    del xgb_model

    gc.collect()


if __name__ == "__main__":

    main()
