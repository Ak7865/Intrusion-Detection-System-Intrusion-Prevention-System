from pathlib import Path
import json

import matplotlib.pyplot as plt


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

REPORT_PATH = (
    ROOT
    / "ml/reports/multiclass/inference_benchmark/"
    "multiclass_inference_benchmark_v1.json"
)

OUTPUT_DIR = (
    ROOT
    / "ml/reports/multiclass/inference_benchmark/figures"
)


# ============================================================
# LOAD BENCHMARK REPORT
# ============================================================

def load_report():

    if not REPORT_PATH.exists():
        raise FileNotFoundError(REPORT_PATH)

    with open(REPORT_PATH, "r", encoding="utf-8") as file:
        report = json.load(file)

    required_models = [
        "random_forest",
        "xgboost"
    ]

    for model in required_models:

        if model not in report["results"]:
            raise ValueError(
                f"Missing benchmark results for {model}"
            )

    return report


# ============================================================
# SAVE FIGURE
# ============================================================

def save_figure(filename):

    output_path = OUTPUT_DIR / filename

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("Saved:", output_path)


# ============================================================
# MODEL LABELS
# ============================================================

MODEL_LABELS = [
    "Random Forest",
    "XGBoost"
]


# ============================================================
# 1. INFERENCE TIME COMPARISON
# ============================================================

def plot_inference_time(report):

    rf = report["results"]["random_forest"]
    xgb = report["results"]["xgboost"]

    values = [
        rf["inference_time_seconds"],
        xgb["inference_time_seconds"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        MODEL_LABELS,
        values
    )

    ax.set_ylabel("Inference time (seconds)")

    ax.set_title(
        "Multiclass Model Inference Time Comparison"
    )

    ax.bar_label(
        bars,
        fmt="%.4f s",
        padding=4
    )

    save_figure(
        "multiclass_inference_time_comparison.png"
    )


# ============================================================
# 2. LATENCY COMPARISON
# ============================================================

def plot_latency(report):

    rf = report["results"]["random_forest"]
    xgb = report["results"]["xgboost"]

    values = [
        rf["latency_ms_per_flow"],
        xgb["latency_ms_per_flow"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        MODEL_LABELS,
        values
    )

    ax.set_ylabel("Latency (milliseconds per flow)")

    ax.set_title(
        "Multiclass Model Inference Latency Comparison"
    )

    ax.bar_label(
        bars,
        fmt="%.6f ms",
        padding=4
    )

    save_figure(
        "multiclass_inference_latency_comparison.png"
    )


# ============================================================
# 3. THROUGHPUT COMPARISON
# ============================================================

def plot_throughput(report):

    rf = report["results"]["random_forest"]
    xgb = report["results"]["xgboost"]

    values = [
        rf["throughput_flows_per_second"],
        xgb["throughput_flows_per_second"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        MODEL_LABELS,
        values
    )

    ax.set_ylabel("Flows per second")

    ax.set_title(
        "Multiclass Model Inference Throughput Comparison"
    )

    ax.bar_label(
        bars,
        fmt="%.2f",
        padding=4
    )

    save_figure(
        "multiclass_inference_throughput_comparison.png"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 65)
    print("MULTICLASS BENCHMARK VISUALIZATION")
    print("=" * 65)

    report = load_report()

    print("\nBenchmark report loaded successfully.")

    print(
        "Test records:",
        f"{report['test_records']:,}"
    )

    print("\nGenerating comparison figures...")

    plot_inference_time(report)

    plot_latency(report)

    plot_throughput(report)

    print("\n" + "=" * 65)
    print("MULTICLASS BENCHMARK VISUALIZATION COMPLETED")
    print("=" * 65)

    print("\nOutput directory:", OUTPUT_DIR)


if __name__ == "__main__":

    main()
