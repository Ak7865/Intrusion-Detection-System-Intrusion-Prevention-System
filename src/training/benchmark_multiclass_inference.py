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

TEST_PATH = (
    ROOT / "datasets/splits/cicids2017_v2/"
    "multiclass/test.csv"
)

RF_PATH = (
    ROOT / "ml/models/multiclass/"
    "multiclass_random_forest.joblib"
)

XGB_PATH = (
    ROOT / "ml/models/multiclass/"
    "multiclass_xgboost.json"
)

ENCODER_PATH = (
    ROOT / "ml/models/multiclass/"
    "multiclass_xgboost_label_encoder.joblib"
)

OUTPUT_DIR = (
    ROOT / "ml/reports/multiclass/"
    "inference_benchmark"
)

REPORT_PATH = (
    OUTPUT_DIR / "multiclass_inference_benchmark_v1.json"
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

EXPECTED_TEST_ROWS = 552_985

CHUNK_SIZE = 50_000

WARMUP_ROWS = 1_000

EXPECTED_CLASSES = 8


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if REPORT_PATH.exists():

        raise FileExistsError(
            f"Benchmark report already exists: {REPORT_PATH}"
        )

    required_files = [
        TEST_PATH,
        RF_PATH,
        XGB_PATH,
        ENCODER_PATH
    ]

    for path in required_files:

        if not path.exists():

            raise FileNotFoundError(path)

    print("=" * 70)

    print("STANDARDIZED MULTICLASS INFERENCE BENCHMARK V1")

    print("=" * 70)


    # ========================================================
    # LOAD MODELS
    # ========================================================

    print("\nLoading Random Forest...")

    rf_model = joblib.load(RF_PATH)

    print("Loading XGBoost...")

    xgb_model = XGBClassifier()

    xgb_model.load_model(XGB_PATH)

    print("Loading XGBoost label encoder...")

    label_encoder = joblib.load(ENCODER_PATH)


    # ========================================================
    # VALIDATE FEATURES
    # ========================================================

    print("\nValidating model features...")

    if list(rf_model.feature_names_in_) != FEATURES:

        raise ValueError(
            "Random Forest feature order mismatch."
        )

    if list(xgb_model.feature_names_in_) != FEATURES:

        raise ValueError(
            "XGBoost feature order mismatch."
        )


    # ========================================================
    # VALIDATE CLASS ORDER
    # ========================================================

    rf_classes = list(rf_model.classes_)

    xgb_classes = list(label_encoder.classes_)

    if len(rf_classes) != EXPECTED_CLASSES:

        raise ValueError(
            "Unexpected Random Forest class count."
        )

    if len(xgb_classes) != EXPECTED_CLASSES:

        raise ValueError(
            "Unexpected XGBoost class count."
        )

    if rf_classes != xgb_classes:

        raise ValueError(
            "Random Forest and XGBoost class order mismatch."
        )

    if xgb_model.n_classes_ != EXPECTED_CLASSES:

        raise ValueError(
            "Unexpected XGBoost model class count."
        )

    print("Feature validation passed.")

    print("Class validation passed.")

    print("Classes:", rf_classes)


    # ========================================================
    # CSV DATA TYPES
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

    print("\nPreparing warm-up data...")

    first_chunk = next(

        pd.read_csv(
            TEST_PATH,
            usecols=FEATURES + [TARGET],
            dtype=dtype_map,
            chunksize=CHUNK_SIZE
        )

    )

    X_warmup = first_chunk[FEATURES].iloc[:WARMUP_ROWS]

    if len(X_warmup) != WARMUP_ROWS:

        raise ValueError(
            "Insufficient warm-up records."
        )

    if X_warmup.isna().any().any():

        raise ValueError(
            "Missing values in warm-up data."
        )


    # Random Forest warm-up

    rf_probabilities = rf_model.predict_proba(
        X_warmup
    )

    np.argmax(
        rf_probabilities,
        axis=1
    )


    # XGBoost warm-up

    xgb_probabilities = xgb_model.predict_proba(
        X_warmup
    )

    np.argmax(
        xgb_probabilities,
        axis=1
    )


    print(
        "Warm-up completed. Warm-up time excluded."
    )

    del first_chunk
    del X_warmup

    del rf_probabilities
    del xgb_probabilities

    gc.collect()


    # ========================================================
    # TIMING INITIALIZATION
    # ========================================================

    elapsed = {

        "random_forest": 0.0,

        "xgboost": 0.0
    }

    total_rows = 0

    chunk_count = 0


    # ========================================================
    # START BENCHMARK
    # ========================================================

    print("\nStarting standardized benchmark...")

    print("Test records:", EXPECTED_TEST_ROWS)

    print("Chunk size:", CHUNK_SIZE)

    print("Warm-up records:", WARMUP_ROWS)

    print("Execution order: Alternating by chunk")


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

        if chunk[FEATURES].isna().any().any():

            raise ValueError(
                f"Missing feature values in chunk {chunk_number}."
            )

        X_chunk = chunk[FEATURES]


        # ====================================================
        # ALTERNATE EXECUTION ORDER
        # ====================================================

        if chunk_number % 2 == 1:

            execution_order = [
                "random_forest",
                "xgboost"
            ]

        else:

            execution_order = [
                "xgboost",
                "random_forest"
            ]


        for model_name in execution_order:

            start = time.perf_counter()


            # ================================================
            # RANDOM FOREST
            # ================================================

            if model_name == "random_forest":

                probabilities = rf_model.predict_proba(
                    X_chunk
                )

                predictions = np.argmax(
                    probabilities,
                    axis=1
                )


            # ================================================
            # XGBOOST
            # ================================================

            else:

                probabilities = xgb_model.predict_proba(
                    X_chunk
                )

                predictions = np.argmax(
                    probabilities,
                    axis=1
                )


            elapsed[model_name] += (
                time.perf_counter() - start
            )


            del probabilities
            del predictions


        # ====================================================
        # PROGRESS
        # ====================================================

        total_rows += len(chunk)

        chunk_count += 1

        print(
            f"Chunk {chunk_number}: "
            f"{total_rows:,}/{EXPECTED_TEST_ROWS:,} records"
        )


        # ====================================================
        # MEMORY CLEANUP
        # ====================================================

        del chunk
        del X_chunk

        gc.collect()


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
    # CALCULATE METRICS
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
    # CREATE REPORT
    # ========================================================

    report = {

        "experiment": (
            "Standardized Multiclass Inference Benchmark V1"
        ),

        "created_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "test_records": total_rows,

        "number_of_classes": EXPECTED_CLASSES,

        "classes": [
            str(name)
            for name in rf_classes
        ],

        "features": FEATURES,

        "chunk_size": CHUNK_SIZE,

        "number_of_chunks": chunk_count,

        "warmup_records_per_model": WARMUP_ROWS,

        "execution_order": (
            "Alternating model execution order by chunk."
        ),

        "prediction_method": (
            "predict_proba followed by argmax "
            "for multiclass classification."
        ),

        "timing_scope": (
            "Prediction computation and argmax only. "
            "CSV reading, model loading, warm-up, "
            "and garbage collection are excluded."
        ),

        "benchmark_wall_time_seconds": (
            benchmark_wall_time
        ),

        "results": results
    }


    REPORT_PATH.write_text(

        json.dumps(
            report,
            indent=4
        ),

        encoding="utf-8"
    )


    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\n" + "=" * 70)

    print("STANDARDIZED MULTICLASS BENCHMARK RESULTS")

    print("=" * 70)


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


    print(
        "\nBenchmark wall time:",
        round(benchmark_wall_time, 3),
        "seconds"
    )

    print("\nReport saved:", REPORT_PATH)

    print("\nSTANDARDIZED MULTICLASS BENCHMARK COMPLETED.")


    del rf_model
    del xgb_model
    del label_encoder

    gc.collect()


if __name__ == "__main__":

    main()