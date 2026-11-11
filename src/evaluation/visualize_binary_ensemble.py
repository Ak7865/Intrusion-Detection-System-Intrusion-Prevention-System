from pathlib import Path
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns

from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

RF_MODEL_PATH = ROOT / "ml/models/binary/binary_random_forest.joblib"
XGB_MODEL_PATH = ROOT / "ml/models/binary/binary_xgboost.json"

ENSEMBLE_METRICS_PATH = (
    ROOT / "ml/reports/binary/ensemble/"
    "binary_soft_voting_ensemble_metrics.json"
)

RF_METRICS_PATH = ROOT / "ml/reports/binary/binary_random_forest_metrics.json"
XGB_METRICS_PATH = ROOT / "ml/reports/binary/binary_xgboost_metrics.json"

TEST_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/test.csv"

OUTPUT_DIR = ROOT / "ml/reports/binary/ensemble/figures"
CATEGORY_REPORT = (
    ROOT / "ml/reports/binary/ensemble/"
    "ensemble_attack_category_metrics.json"
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
    "Down/Up Ratio"
]

TARGET = "binary_label"
CATEGORY_COLUMN = "multiclass_label"

CHUNK_SIZE = 50000
EXPECTED_TEST_ROWS = 552991

RF_WEIGHT = 0.5
XGB_WEIGHT = 0.5
THRESHOLD = 0.5

ATTACK_CATEGORIES = [
    "DoS/DDoS",
    "PortScan",
    "Brute Force",
    "Web Attack",
    "Botnet",
    "Infiltration",
    "OTHER_RARE"
]


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def plot_confusion_matrix(metrics):
    matrix = np.array(metrics["confusion_matrix"]["matrix"])
    labels = metrics["confusion_matrix"]["labels"]

    plt.figure(figsize=(8, 6))

    sns.heatmap(
        matrix,
        annot=True,
        fmt=",d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels
    )

    plt.title("Binary RF + XGBoost Ensemble - Confusion Matrix")
    plt.xlabel("Predicted Class")
    plt.ylabel("Actual Class")
    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "ensemble_confusion_matrix.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def plot_performance_metrics(metrics):
    values = {
        "Accuracy": metrics["accuracy"] * 100,
        "Precision": metrics["attack_precision"] * 100,
        "Recall": metrics["attack_recall"] * 100,
        "F1-score": metrics["attack_f1_score"] * 100,
        "False-positive rate": metrics["false_positive_rate"] * 100,
        "False-negative rate": metrics["false_negative_rate"] * 100
    }

    plt.figure(figsize=(11, 6))

    bars = plt.bar(values.keys(), values.values())

    plt.title("Binary RF + XGBoost Ensemble - Performance Metrics")
    plt.ylabel("Percentage (%)")
    plt.ylim(0, 105)
    plt.xticks(rotation=20, ha="right")

    for bar, value in zip(bars, values.values()):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"{value:.3f}%",
            ha="center",
            fontsize=8
        )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "ensemble_performance_metrics.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def plot_model_inference_comparison(rf_metrics, xgb_metrics, ensemble_metrics):
    names = ["Random Forest", "XGBoost", "Ensemble"]

    inference_times = [
        rf_metrics["inference_time_seconds"],
        xgb_metrics["inference_time_seconds"],
        ensemble_metrics["inference_time_seconds"]
    ]

    latencies = [
        rf_metrics["inference_latency_ms_per_flow"],
        xgb_metrics["inference_latency_ms_per_flow"],
        ensemble_metrics["inference_latency_ms_per_flow"]
    ]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    bars = axes[0].bar(names, inference_times)
    axes[0].set_title("Test Inference Time Comparison")
    axes[0].set_ylabel("Time (seconds)")

    for bar, value in zip(bars, inference_times):
        axes[0].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.3f}s",
            ha="center",
            va="bottom"
        )

    bars = axes[1].bar(names, latencies)
    axes[1].set_title("Average Inference Latency Comparison")
    axes[1].set_ylabel("Milliseconds per flow")

    for bar, value in zip(bars, latencies):
        axes[1].text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.6f}",
            ha="center",
            va="bottom",
            fontsize=8
        )

    for ax in axes:
        ax.tick_params(axis="x", rotation=15)

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "ensemble_model_inference_comparison.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def calculate_attack_category_metrics():
    print("\nLoading trained models for category analysis...")

    rf_model = joblib.load(RF_MODEL_PATH)

    xgb_model = XGBClassifier()
    xgb_model.load_model(XGB_MODEL_PATH)

    if list(rf_model.feature_names_in_) != FEATURES:
        raise ValueError("Random Forest feature order mismatch.")

    if list(xgb_model.feature_names_in_) != FEATURES:
        raise ValueError("XGBoost feature order mismatch.")

    rf_attack_index = list(rf_model.classes_).index("Attack")
    xgb_attack_index = list(xgb_model.classes_).index(1)

    categories = {
        category: {
            "total": 0,
            "detected": 0,
            "missed": 0,
            "false_positive": 0,
            "true_negative": 0
        }
        for category in ATTACK_CATEGORIES
    }

    columns = FEATURES + [TARGET, CATEGORY_COLUMN]

    dtype_map = {
        feature: "float32"
        for feature in FEATURES
    }

    dtype_map["Destination Port"] = "uint16"
    dtype_map[TARGET] = "category"
    dtype_map[CATEGORY_COLUMN] = "category"

    total_rows = 0
    start_time = time.perf_counter()

    print("\nRunning ensemble inference on complete test set...")

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            TEST_PATH,
            usecols=columns,
            dtype=dtype_map,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):
        if chunk[columns].isna().any().any():
            raise ValueError(
                f"Missing values found in test chunk {chunk_number}."
            )

        X = chunk[FEATURES]

        rf_probabilities = rf_model.predict_proba(X)
        xgb_probabilities = xgb_model.predict_proba(X)

        ensemble_probability = (
            RF_WEIGHT * rf_probabilities[:, rf_attack_index]
            + XGB_WEIGHT * xgb_probabilities[:, xgb_attack_index]
        )

        predicted_positive = ensemble_probability >= THRESHOLD

        actual_categories = chunk[CATEGORY_COLUMN].astype(str)

        for category in ATTACK_CATEGORIES:
            actual_positive = (
                actual_categories == category
            ).to_numpy()

            stats = categories[category]

            stats["total"] += int(actual_positive.sum())

            stats["detected"] += int(
                (actual_positive & predicted_positive).sum()
            )

            stats["missed"] += int(
                (actual_positive & ~predicted_positive).sum()
            )

            stats["false_positive"] += int(
                (~actual_positive & predicted_positive).sum()
            )

            stats["true_negative"] += int(
                (~actual_positive & ~predicted_positive).sum()
            )

        total_rows += len(chunk)

        print(
            f"Chunk {chunk_number}: "
            f"{total_rows:,}/{EXPECTED_TEST_ROWS:,} records processed."
        )

        del chunk, X, rf_probabilities, xgb_probabilities
        del ensemble_probability, predicted_positive, actual_categories
        gc.collect()

    analysis_time = time.perf_counter() - start_time

    if total_rows != EXPECTED_TEST_ROWS:
        raise ValueError(
            f"Expected {EXPECTED_TEST_ROWS} rows, got {total_rows}."
        )

    results = {}

    for category, stats in categories.items():
        tp = stats["detected"]
        fn = stats["missed"]
        fp = stats["false_positive"]
        tn = stats["true_negative"]

        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0

        results[category] = {
            "test_records": stats["total"],
            "detected_as_attack": tp,
            "missed_as_normal": fn,
            "one_vs_rest_false_positives": fp,
            "one_vs_rest_true_negatives": tn,
            "recall": recall,
            "false_negative_rate": fnr,
            "one_vs_rest_false_positive_rate": fpr
        }

    output = {
        "experiment": "Binary RF + XGBoost Soft Voting Ensemble",
        "analysis": "Attack-category detection using ensemble binary predictions",
        "test_records_processed": total_rows,
        "analysis_inference_time_seconds": analysis_time,
        "configuration": {
            "random_forest_weight": RF_WEIGHT,
            "xgboost_weight": XGB_WEIGHT,
            "attack_probability_threshold": THRESHOLD
        },
        "category_metrics": results,
        "interpretation": (
            "Recall and false-negative rate measure how well each "
            "attack category is detected as Attack. One-vs-rest "
            "false-positive rate treats all other categories, "
            "including other attacks, as negatives. This is binary "
            "attack detection, not multiclass attack-family classification."
        )
    }

    CATEGORY_REPORT.write_text(
        json.dumps(output, indent=4),
        encoding="utf-8"
    )

    print("\nENSEMBLE ATTACK CATEGORY METRICS")

    for category, stats in results.items():
        print(
            f"{category}: "
            f"records={stats['test_records']}, "
            f"recall={stats['recall']:.6f}, "
            f"FNR={stats['false_negative_rate']:.6f}"
        )

    print("\nCategory analysis time:", round(analysis_time, 3), "seconds")

    del rf_model, xgb_model
    gc.collect()

    return results


def plot_attack_categories(results):
    labels = list(results.keys())

    recall_values = [
        results[label]["recall"] * 100
        for label in labels
    ]

    fnr_values = [
        results[label]["false_negative_rate"] * 100
        for label in labels
    ]

    positions = np.arange(len(labels))
    width = 0.38

    plt.figure(figsize=(12, 7))

    plt.bar(
        positions - width / 2,
        recall_values,
        width,
        label="Recall"
    )

    plt.bar(
        positions + width / 2,
        fnr_values,
        width,
        label="False-negative rate"
    )

    plt.xticks(
        positions,
        labels,
        rotation=25,
        ha="right"
    )

    plt.ylabel("Percentage (%)")
    plt.title(
        "Binary RF + XGBoost Ensemble - Attack Category Detection"
    )

    plt.legend()
    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "ensemble_attack_category_analysis.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("BINARY ENSEMBLE EVALUATION VISUALIZATION")
    print("=" * 65)

    ensemble_metrics = load_json(ENSEMBLE_METRICS_PATH)
    rf_metrics = load_json(RF_METRICS_PATH)
    xgb_metrics = load_json(XGB_METRICS_PATH)

    print("\nGenerating ensemble confusion matrix...")
    plot_confusion_matrix(ensemble_metrics)

    print("Generating ensemble performance chart...")
    plot_performance_metrics(ensemble_metrics)

    print("Generating model inference comparison...")
    plot_model_inference_comparison(
        rf_metrics,
        xgb_metrics,
        ensemble_metrics
    )

    category_results = calculate_attack_category_metrics()

    print("\nGenerating attack-category chart...")
    plot_attack_categories(category_results)

    print("\nENSEMBLE VISUALIZATION COMPLETED")

    print("\nOutput directory:", OUTPUT_DIR)

    for file in sorted(OUTPUT_DIR.glob("*.png")):
        print(
            file.name,
            "-",
            round(file.stat().st_size / 1024, 2),
            "KB"
        )

    print("\nCategory report:", CATEGORY_REPORT)


if __name__ == "__main__":
    main()
