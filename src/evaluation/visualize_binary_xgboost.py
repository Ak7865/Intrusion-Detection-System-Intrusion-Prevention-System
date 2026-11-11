from pathlib import Path
import json
import time
import gc

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns

from xgboost import XGBClassifier


ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = ROOT / "ml/models/binary/binary_xgboost.json"
METRICS_PATH = ROOT / "ml/reports/binary/binary_xgboost_metrics.json"
TEST_PATH = ROOT / "datasets/splits/cicids2017_v2/binary/test.csv"

OUTPUT_DIR = ROOT / "ml/reports/binary/xgboost/figures"
CATEGORY_REPORT = ROOT / "ml/reports/binary/xgboost/attack_category_metrics.json"

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

ATTACK_CATEGORIES = [
    "DoS/DDoS",
    "PortScan",
    "Brute Force",
    "Web Attack",
    "Botnet",
    "Infiltration",
    "OTHER_RARE"
]


def load_metrics():
    if not METRICS_PATH.exists():
        raise FileNotFoundError(METRICS_PATH)

    with METRICS_PATH.open("r", encoding="utf-8") as file:
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

    plt.title("Binary XGBoost - Confusion Matrix")
    plt.xlabel("Predicted Class")
    plt.ylabel("Actual Class")
    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "xgboost_confusion_matrix.png",
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

    plt.title("Binary XGBoost - Performance Metrics")
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
        OUTPUT_DIR / "xgboost_performance_metrics.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def plot_training_inference_time(metrics):
    training = metrics["training_time_seconds"]
    inference = metrics["inference_time_seconds"]
    latency = metrics["inference_latency_ms_per_flow"]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    axes[0].bar(
        ["Training", "Test inference"],
        [training, inference]
    )

    axes[0].set_title("XGBoost Training and Inference Time")
    axes[0].set_ylabel("Time (seconds)")

    axes[0].text(
        0, training, f"{training:.2f}s",
        ha="center", va="bottom"
    )

    axes[0].text(
        1, inference, f"{inference:.2f}s",
        ha="center", va="bottom"
    )

    axes[1].bar(
        ["Average inference latency"],
        [latency]
    )

    axes[1].set_title("XGBoost Inference Latency")
    axes[1].set_ylabel("Milliseconds per flow")

    axes[1].text(
        0, latency, f"{latency:.6f} ms",
        ha="center", va="bottom"
    )

    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "xgboost_training_inference_time.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def calculate_attack_category_metrics():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(MODEL_PATH)

    print("\nLoading saved XGBoost model...")

    model = XGBClassifier()
    model.load_model(MODEL_PATH)

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

    total_rows = 0
    start_time = time.perf_counter()

    columns = FEATURES + [TARGET, CATEGORY_COLUMN]

    dtype_map = {
        feature: "float32"
        for feature in FEATURES
    }

    dtype_map["Destination Port"] = "uint16"
    dtype_map[TARGET] = "category"
    dtype_map[CATEGORY_COLUMN] = "category"

    print("Running chunked inference on the complete test set...")

    for chunk in pd.read_csv(
        TEST_PATH,
        usecols=columns,
        dtype=dtype_map,
        chunksize=CHUNK_SIZE
    ):

        X = chunk[FEATURES]

        if chunk[columns].isna().any().any():
            raise ValueError("Missing values found in test chunk.")

        predictions = model.predict(X)

        actual_categories = chunk[CATEGORY_COLUMN].astype(str)
        predicted_positive = predictions == 1

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

        print(f"Processed {total_rows:,} test records...")

        del chunk, X, predictions, actual_categories
        gc.collect()

    inference_analysis_time = time.perf_counter() - start_time

    if total_rows != 552991:
        raise ValueError(
            f"Unexpected test row count: {total_rows}"
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
        "experiment": "Binary XGBoost",
        "analysis": "Attack-category detection using binary predictions",
        "test_records_processed": total_rows,
        "analysis_inference_time_seconds": inference_analysis_time,
        "category_metrics": results,
        "interpretation": (
            "Recall and false-negative rate measure how well each "
            "attack category is detected as Attack. One-vs-rest "
            "false-positive rate treats all other categories, "
            "including other attacks, as negatives."
        )
    }

    CATEGORY_REPORT.write_text(
        json.dumps(output, indent=4),
        encoding="utf-8"
    )

    print("\nXGBOOST ATTACK CATEGORY METRICS")

    for category, stats in results.items():
        print(
            f"{category}: "
            f"records={stats['test_records']}, "
            f"recall={stats['recall']:.6f}, "
            f"FNR={stats['false_negative_rate']:.6f}"
        )

    print(
        "\nCategory analysis inference time:",
        round(inference_analysis_time, 3),
        "seconds"
    )

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
        "Binary XGBoost - Individual Attack Category Detection"
    )

    plt.legend()
    plt.tight_layout()

    plt.savefig(
        OUTPUT_DIR / "xgboost_attack_category_analysis.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 65)
    print("BINARY XGBOOST EVALUATION VISUALIZATION")
    print("=" * 65)

    metrics = load_metrics()

    print("\nGenerating confusion matrix...")
    plot_confusion_matrix(metrics)

    print("Generating performance metrics chart...")
    plot_performance_metrics(metrics)

    print("Generating training and inference time chart...")
    plot_training_inference_time(metrics)

    category_results = calculate_attack_category_metrics()

    print("\nGenerating attack-category chart...")
    plot_attack_categories(category_results)

    print("\nXGBOOST VISUALIZATION COMPLETED")
    print("Output directory:", OUTPUT_DIR)

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
