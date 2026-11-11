from pathlib import Path
import json

import numpy as np
import matplotlib.pyplot as plt


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RF_REPORT = (
    ROOT / "ml/reports/multiclass/"
    "multiclass_random_forest_metrics.json"
)

XGB_REPORT = (
    ROOT / "ml/reports/multiclass/"
    "multiclass_xgboost_metrics.json"
)

BASE_OUTPUT = (
    ROOT / "ml/reports/multiclass/figures"
)

RF_OUTPUT = BASE_OUTPUT / "random_forest"
XGB_OUTPUT = BASE_OUTPUT / "xgboost"
COMPARISON_OUTPUT = BASE_OUTPUT / "comparison"


# ============================================================
# CONFIGURATION
# ============================================================

METRIC_KEYS = [
    "accuracy",
    "macro_precision",
    "macro_recall",
    "macro_f1",
    "weighted_f1"
]

METRIC_LABELS = [
    "Accuracy",
    "Macro Precision",
    "Macro Recall",
    "Macro F1",
    "Weighted F1"
]


# ============================================================
# DIRECTORY INITIALIZATION
# ============================================================

def create_directories():

    for directory in [
        RF_OUTPUT,
        XGB_OUTPUT,
        COMPARISON_OUTPUT
    ]:
        directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD REPORTS
# ============================================================

def load_report(path):

    if not path.exists():
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# VALIDATE REPORTS
# ============================================================

def validate_reports(rf, xgb):

    checks = [
        ("features", "Feature lists"),
        ("classes", "Class lists"),
        ("test_records", "Test record counts"),
        ("target", "Target columns")
    ]

    for key, description in checks:

        if rf[key] != xgb[key]:
            raise ValueError(
                f"{description} do not match."
            )

    print("Report compatibility validation passed.")


# ============================================================
# SAVE FIGURE
# ============================================================

def save_figure(output_dir, filename):

    output_path = output_dir / filename

    plt.tight_layout()

    plt.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("Saved:", output_path)


# ============================================================
# 1. CONFUSION MATRIX
# ============================================================

def plot_confusion_matrix(report, output_dir, model_name, prefix):

    labels = report["confusion_matrix"]["labels"]

    matrix = np.array(
        report["confusion_matrix"]["matrix"]
    )

    fig, ax = plt.subplots(figsize=(11, 9))

    im = ax.imshow(
        matrix,
        interpolation="nearest",
        cmap="Blues"
    )

    fig.colorbar(
        im,
        ax=ax,
        label="Number of records"
    )

    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        xlabel="Predicted class",
        ylabel="Actual class",
        title=f"{model_name} - Multiclass Confusion Matrix"
    )

    plt.setp(
        ax.get_xticklabels(),
        rotation=35,
        ha="right",
        rotation_mode="anchor"
    )


    for i in range(matrix.shape[0]):

        for j in range(matrix.shape[1]):

            cell_color = im.cmap(im.norm(matrix[i, j]))
            luminance = (
                0.299 * cell_color[0] +
                0.587 * cell_color[1] +
                0.114 * cell_color[2]
            )
            
            ax.text(
                j,
                i,
                f"{matrix[i, j]:,}",
                ha="center",
                va="center",
                fontsize=8,
                color="black" if luminance > 0.5 else "white"
            )

    save_figure(
        output_dir,
        f"{prefix}_confusion_matrix.png"
    )


# ============================================================
# 2. OVERALL PERFORMANCE METRICS
# ============================================================

def plot_performance_metrics(report, output_dir, model_name, prefix):

    values = [
        report[key] * 100
        for key in METRIC_KEYS
    ]

    fig, ax = plt.subplots(figsize=(10, 6))

    bars = ax.bar(
        METRIC_LABELS,
        values
    )

    ax.set_ylabel("Score (%)")

    ax.set_title(
        f"{model_name} - Overall Performance Metrics"
    )

    ax.set_ylim(0, 110)

    ax.bar_label(
        bars,
        fmt="%.2f%%",
        padding=3
    )

    plt.xticks(
        rotation=20,
        ha="right"
    )

    save_figure(
        output_dir,
        f"{prefix}_performance_metrics.png"
    )


# ============================================================
# 3. PER-CLASS METRICS
# ============================================================

def plot_per_class_metric(
    report,
    output_dir,
    model_name,
    prefix,
    metric_key,
    metric_label
):

    classes = report["classes"]

    class_report = report["classification_report"]

    values = [
        class_report[name][metric_key] * 100
        for name in classes
    ]

    fig, ax = plt.subplots(figsize=(12, 7))

    bars = ax.bar(
        classes,
        values
    )

    ax.set_ylabel(f"{metric_label} (%)")

    ax.set_title(
        f"{model_name} - Per-Class {metric_label}"
    )

    ax.set_ylim(0, 110)

    ax.bar_label(
        bars,
        fmt="%.2f%%",
        padding=3,
        fontsize=8
    )

    plt.xticks(
        rotation=30,
        ha="right"
    )

    save_figure(
        output_dir,
        f"{prefix}_per_class_{metric_key}.png"
    )


# ============================================================
# 4. TRAINING AND INFERENCE TIME
# ============================================================

def plot_execution_time(
    report,
    output_dir,
    model_name,
    prefix
):

    names = [
        "Training",
        "Inference"
    ]

    values = [
        report["training_time_seconds"],
        report["inference_time_seconds"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        names,
        values
    )

    ax.set_ylabel("Time (seconds)")

    ax.set_title(
        f"{model_name} - Training and Inference Time"
    )

    ax.bar_label(
        bars,
        fmt="%.3f s",
        padding=3
    )

    save_figure(
        output_dir,
        f"{prefix}_training_inference_time.png"
    )


# ============================================================
# 5. INFERENCE LATENCY AND THROUGHPUT
# ============================================================

def plot_inference_performance(
    report,
    output_dir,
    model_name,
    prefix
):

    latency = report["inference_latency_ms_per_flow"]

    throughput = report["throughput_flows_per_second"]

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(11, 5)
    )

    bars1 = axes[0].bar(
        ["Latency"],
        [latency]
    )

    axes[0].set_ylabel("Milliseconds per flow")

    axes[0].set_title("Inference Latency")

    axes[0].bar_label(
        bars1,
        fmt="%.6f ms",
        padding=3
    )

    bars2 = axes[1].bar(
        ["Throughput"],
        [throughput]
    )

    axes[1].set_ylabel("Flows per second")

    axes[1].set_title("Inference Throughput")

    axes[1].bar_label(
        bars2,
        fmt="%.2f",
        padding=3
    )

    fig.suptitle(
        f"{model_name} - Inference Performance"
    )

    save_figure(
        output_dir,
        f"{prefix}_inference_performance.png"
    )


# ============================================================
# GENERATE INDIVIDUAL MODEL FIGURES
# ============================================================

def generate_individual_figures(
    report,
    output_dir,
    model_name,
    prefix
):

    print("\nGenerating", model_name, "figures...")

    plot_confusion_matrix(
        report,
        output_dir,
        model_name,
        prefix
    )

    plot_performance_metrics(
        report,
        output_dir,
        model_name,
        prefix
    )

    for metric_key, metric_label in [
        ("precision", "Precision"),
        ("recall", "Recall"),
        ("f1-score", "F1-score")
    ]:

        plot_per_class_metric(
            report,
            output_dir,
            model_name,
            prefix,
            metric_key,
            metric_label
        )

    plot_execution_time(
        report,
        output_dir,
        model_name,
        prefix
    )

    plot_inference_performance(
        report,
        output_dir,
        model_name,
        prefix
    )


# ============================================================
# 6. OVERALL MODEL COMPARISON
# ============================================================

def plot_overall_comparison(rf, xgb):

    rf_values = [
        rf[key] * 100
        for key in METRIC_KEYS
    ]

    xgb_values = [
        xgb[key] * 100
        for key in METRIC_KEYS
    ]

    x = np.arange(len(METRIC_KEYS))

    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 6))

    bars1 = ax.bar(
        x - width / 2,
        rf_values,
        width,
        label="Random Forest"
    )

    bars2 = ax.bar(
        x + width / 2,
        xgb_values,
        width,
        label="XGBoost"
    )

    ax.set_ylabel("Score (%)")

    ax.set_title(
        "Multiclass Random Forest vs XGBoost - Overall Comparison"
    )

    ax.set_xticks(x)

    ax.set_xticklabels(METRIC_LABELS)

    ax.set_ylim(0, 110)

    ax.legend()

    ax.bar_label(
        bars1,
        fmt="%.2f",
        padding=3,
        fontsize=8
    )

    ax.bar_label(
        bars2,
        fmt="%.2f",
        padding=3,
        fontsize=8
    )

    save_figure(
        COMPARISON_OUTPUT,
        "overall_performance_comparison.png"
    )


# ============================================================
# 7. PER-CLASS METRIC COMPARISON
# ============================================================

def plot_per_class_comparison(rf, xgb):

    classes = rf["classes"]

    rf_report = rf["classification_report"]

    xgb_report = xgb["classification_report"]

    for metric_key, metric_label in [
        ("precision", "Precision"),
        ("recall", "Recall"),
        ("f1-score", "F1-score")
    ]:

        rf_values = [
            rf_report[name][metric_key] * 100
            for name in classes
        ]

        xgb_values = [
            xgb_report[name][metric_key] * 100
            for name in classes
        ]

        x = np.arange(len(classes))

        width = 0.35

        fig, ax = plt.subplots(figsize=(13, 7))

        bars1 = ax.bar(
            x - width / 2,
            rf_values,
            width,
            label="Random Forest"
        )

        bars2 = ax.bar(
            x + width / 2,
            xgb_values,
            width,
            label="XGBoost"
        )

        ax.set_ylabel(f"{metric_label} (%)")

        ax.set_title(
            f"Random Forest vs XGBoost - Per-Class {metric_label}"
        )

        ax.set_xticks(x)

        ax.set_xticklabels(
            classes,
            rotation=30,
            ha="right"
        )

        ax.set_ylim(0, 110)

        ax.legend()

        save_figure(
            COMPARISON_OUTPUT,
            f"per_class_{metric_key}_comparison.png"
        )


# ============================================================
# 8. TRAINING TIME COMPARISON
# ============================================================

def plot_training_time_comparison(rf, xgb):

    names = [
        "Random Forest",
        "XGBoost"
    ]

    values = [
        rf["training_time_seconds"],
        xgb["training_time_seconds"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        names,
        values
    )

    ax.set_ylabel("Training time (seconds)")

    ax.set_title(
        "Multiclass Model Training Time Comparison"
    )

    ax.bar_label(
        bars,
        fmt="%.3f s",
        padding=3
    )

    save_figure(
        COMPARISON_OUTPUT,
        "training_time_comparison.png"
    )


# ============================================================
# 9. INFERENCE TIME COMPARISON
# ============================================================

def plot_inference_time_comparison(rf, xgb):

    names = [
        "Random Forest",
        "XGBoost"
    ]

    inference_times = [
        rf["inference_time_seconds"],
        xgb["inference_time_seconds"]
    ]

    latencies = [
        rf["inference_latency_ms_per_flow"],
        xgb["inference_latency_ms_per_flow"]
    ]

    fig, axes = plt.subplots(
        1,
        2,
        figsize=(11, 5)
    )

    bars1 = axes[0].bar(
        names,
        inference_times
    )

    axes[0].set_ylabel("Seconds")

    axes[0].set_title("Total Inference Time")

    axes[0].bar_label(
        bars1,
        fmt="%.3f s",
        padding=3
    )

    bars2 = axes[1].bar(
        names,
        latencies
    )

    axes[1].set_ylabel("Milliseconds per flow")

    axes[1].set_title("Inference Latency")

    axes[1].bar_label(
        bars2,
        fmt="%.6f ms",
        padding=3
    )

    save_figure(
        COMPARISON_OUTPUT,
        "inference_time_comparison.png"
    )


# ============================================================
# 10. THROUGHPUT COMPARISON
# ============================================================

def plot_throughput_comparison(rf, xgb):

    names = [
        "Random Forest",
        "XGBoost"
    ]

    values = [
        rf["throughput_flows_per_second"],
        xgb["throughput_flows_per_second"]
    ]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(
        names,
        values
    )

    ax.set_ylabel("Flows per second")

    ax.set_title(
        "Multiclass Model Throughput Comparison"
    )

    ax.bar_label(
        bars,
        fmt="%.2f",
        padding=3
    )

    save_figure(
        COMPARISON_OUTPUT,
        "inference_throughput_comparison.png"
    )


# ============================================================
# 11. ATTACK CATEGORY RECALL COMPARISON
# ============================================================

def plot_attack_recall_comparison(rf, xgb):

    classes = [
        name
        for name in rf["classes"]
        if name != "Normal"
    ]

    rf_report = rf["classification_report"]

    xgb_report = xgb["classification_report"]

    rf_values = [
        rf_report[name]["recall"] * 100
        for name in classes
    ]

    xgb_values = [
        xgb_report[name]["recall"] * 100
        for name in classes
    ]

    x = np.arange(len(classes))

    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))

    bars1 = ax.bar(
        x - width / 2,
        rf_values,
        width,
        label="Random Forest"
    )

    bars2 = ax.bar(
        x + width / 2,
        xgb_values,
        width,
        label="XGBoost"
    )

    ax.set_ylabel("Recall (%)")

    ax.set_title(
        "Attack Category Recall Comparison"
    )

    ax.set_xticks(x)

    ax.set_xticklabels(
        classes,
        rotation=30,
        ha="right"
    )

    ax.set_ylim(0, 110)

    ax.legend()

    save_figure(
        COMPARISON_OUTPUT,
        "attack_category_recall_comparison.png"
    )


# ============================================================
# 12. SAVE COMPARISON JSON
# ============================================================

def save_comparison_summary(rf, xgb):

    metrics = [
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "weighted_f1",
        "training_time_seconds",
        "inference_time_seconds",
        "inference_latency_ms_per_flow",
        "throughput_flows_per_second"
    ]

    summary = {

        "experiment": "Multiclass Model Comparison",

        "test_records": rf["test_records"],

        "features": rf["features"],

        "classes": rf["classes"],

        "models": {

            "random_forest": {},

            "xgboost": {}

        }

    }

    for metric in metrics:

        summary["models"]["random_forest"][metric] = (
            rf[metric]
        )

        summary["models"]["xgboost"][metric] = (
            xgb[metric]
        )

    output_path = (
        COMPARISON_OUTPUT /
        "multiclass_model_comparison.json"
    )

    output_path.write_text(
        json.dumps(summary, indent=4),
        encoding="utf-8"
    )

    print("Saved:", output_path)


# ============================================================
# MAIN
# ============================================================

def main():

    create_directories()

    print("=" * 65)

    print("MULTICLASS MODEL VISUALIZATION")

    print("=" * 65)

    rf = load_report(RF_REPORT)

    xgb = load_report(XGB_REPORT)

    validate_reports(rf, xgb)


    # Individual Random Forest figures

    generate_individual_figures(
        rf,
        RF_OUTPUT,
        "Random Forest",
        "random_forest"
    )


    # Individual XGBoost figures

    generate_individual_figures(
        xgb,
        XGB_OUTPUT,
        "XGBoost",
        "xgboost"
    )


    # Comparative figures

    print("\nGenerating comparative figures...")

    plot_overall_comparison(rf, xgb)

    plot_per_class_comparison(rf, xgb)

    plot_training_time_comparison(rf, xgb)

    plot_inference_time_comparison(rf, xgb)

    plot_throughput_comparison(rf, xgb)

    plot_attack_recall_comparison(rf, xgb)


    # Comparison report

    save_comparison_summary(rf, xgb)


    print("\n" + "=" * 65)

    print("MULTICLASS VISUALIZATION COMPLETED")

    print("=" * 65)

    print("\nRandom Forest figures:", RF_OUTPUT)

    print("XGBoost figures:", XGB_OUTPUT)

    print("Comparison figures:", COMPARISON_OUTPUT)


if __name__ == "__main__":

    main()
