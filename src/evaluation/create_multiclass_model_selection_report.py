from pathlib import Path
import json
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]

RF_PATH = ROOT / "ml/reports/multiclass/multiclass_random_forest_metrics.json"
XGB_PATH = ROOT / "ml/reports/multiclass/multiclass_xgboost_metrics.json"
BENCHMARK_PATH = (
    ROOT
    / "ml/reports/multiclass/inference_benchmark/"
    "multiclass_inference_benchmark_v1.json"
)

OUTPUT_DIR = ROOT / "ml/reports/multiclass/model_selection"

JSON_OUTPUT = OUTPUT_DIR / "multiclass_model_selection_report.json"
MD_OUTPUT = OUTPUT_DIR / "multiclass_model_selection_report.md"


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Required report not found: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def pct(value):
    return round(value * 100, 4)


def build_report(rf, xgb, benchmark):

    rf_bench = benchmark["results"]["random_forest"]
    xgb_bench = benchmark["results"]["xgboost"]

    classes = rf["classes"]

    comparison = {
        "accuracy": {
            "random_forest": pct(rf["accuracy"]),
            "xgboost": pct(xgb["accuracy"]),
            "unit": "%"
        },
        "macro_precision": {
            "random_forest": pct(rf["macro_precision"]),
            "xgboost": pct(xgb["macro_precision"]),
            "unit": "%"
        },
        "macro_recall": {
            "random_forest": pct(rf["macro_recall"]),
            "xgboost": pct(xgb["macro_recall"]),
            "unit": "%"
        },
        "macro_f1": {
            "random_forest": pct(rf["macro_f1"]),
            "xgboost": pct(xgb["macro_f1"]),
            "unit": "%"
        },
        "weighted_f1": {
            "random_forest": pct(rf["weighted_f1"]),
            "xgboost": pct(xgb["weighted_f1"]),
            "unit": "%"
        },
        "training_time_seconds": {
            "random_forest": rf["training_time_seconds"],
            "xgboost": xgb["training_time_seconds"],
            "unit": "seconds"
        },
        "standardized_inference_time_seconds": {
            "random_forest": rf_bench["inference_time_seconds"],
            "xgboost": xgb_bench["inference_time_seconds"],
            "unit": "seconds"
        },
        "standardized_latency_ms_per_flow": {
            "random_forest": rf_bench["latency_ms_per_flow"],
            "xgboost": xgb_bench["latency_ms_per_flow"],
            "unit": "milliseconds/flow"
        },
        "standardized_throughput_flows_per_second": {
            "random_forest": rf_bench["throughput_flows_per_second"],
            "xgboost": xgb_bench["throughput_flows_per_second"],
            "unit": "flows/second"
        }
    }

    per_class = {}

    for label in classes:
        rf_metrics = rf["classification_report"][label]
        xgb_metrics = xgb["classification_report"][label]

        per_class[label] = {
            "support": int(rf_metrics["support"]),
            "random_forest": {
                "precision": pct(rf_metrics["precision"]),
                "recall": pct(rf_metrics["recall"]),
                "f1": pct(rf_metrics["f1-score"])
            },
            "xgboost": {
                "precision": pct(xgb_metrics["precision"]),
                "recall": pct(xgb_metrics["recall"]),
                "f1": pct(xgb_metrics["f1-score"])
            }
        }

    return {
        "report_name": "Multiclass Model Selection Report",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": "CIC-IDS2017",
        "test_records": benchmark["test_records"],
        "training_records": rf["training_records"],
        "number_of_features": len(rf["features"]),
        "features": rf["features"],
        "classes": classes,
        "comparison": comparison,
        "per_class_performance": per_class,
        "benchmark_methodology": {
            "benchmark_name": benchmark["experiment"],
            "benchmark_version": "V1",
            "test_records": benchmark["test_records"],
            "chunk_size": benchmark["chunk_size"],
            "number_of_chunks": benchmark["number_of_chunks"],
            "warmup_records_per_model": benchmark[
                "warmup_records_per_model"
            ],
            "prediction_method": benchmark["prediction_method"],
            "timing_scope": benchmark["timing_scope"],
            "execution_order": benchmark["execution_order"],
            "repeated_runs": False
        },
        "findings": [
            "XGBoost achieved higher accuracy, macro precision, "
            "macro F1, and weighted F1.",
            "Random Forest achieved higher macro recall.",
            "Random Forest had higher standardized inference throughput "
            "and lower standardized latency.",
            "Random Forest showed low precision for Botnet and Web Attack.",
            "XGBoost showed low recall for Botnet and Web Attack.",
            "Infiltration and OTHER_RARE have very small test supports."
        ],
        "limitations": [
            "The dataset is highly class-imbalanced.",
            "Infiltration has only 8 test records.",
            "OTHER_RARE has only 2 test records.",
            "Minority-class metrics are not reliable estimates "
            "of generalized performance at these support levels.",
            "The standardized inference benchmark contains one measured pass.",
            "Benchmark results measure prediction computation and argmax, "
            "not complete end-to-end IPS processing latency.",
            "Results are specific to the selected CIC-IDS2017 split "
            "and the 11 deployment features."
        ],
        "selection_recommendation": {
            "status": "PROVISIONAL_NO_UNCONDITIONAL_WINNER",
            "random_forest": (
                "Consider when inference throughput and attack-family "
                "recall are priorities, but investigate its false positives."
            ),
            "xgboost": (
                "Consider when precision and overall classification "
                "performance are priorities, but investigate missed "
                "Botnet and Web Attack samples."
            ),
            "decision": (
                "Do not finalize the Phase 1 multiclass model yet. "
                "Evaluate class-specific error costs, improve minority-class "
                "performance, and validate using controlled lab traffic."
            )
        }
    }


def generate_markdown(report):

    comparison = report["comparison"]
    per_class = report["per_class_performance"]

    lines = [
        "# Multiclass Model Selection Report",
        "",
        f"**Dataset:** {report['dataset']}",
        f"**Training records:** {report['training_records']:,}",
        f"**Test records:** {report['test_records']:,}",
        f"**Features:** {report['number_of_features']}",
        f"**Classes:** {len(report['classes'])}",
        "",
        "## 1. Overall Performance Comparison",
        "",
        "| Metric | Random Forest | XGBoost |",
        "|---|---:|---:|"
    ]

    metric_labels = {
        "accuracy": "Accuracy (%)",
        "macro_precision": "Macro precision (%)",
        "macro_recall": "Macro recall (%)",
        "macro_f1": "Macro F1 (%)",
        "weighted_f1": "Weighted F1 (%)",
        "training_time_seconds": "Training time (s)",
        "standardized_inference_time_seconds":
            "Standardized inference time (s)",
        "standardized_latency_ms_per_flow":
            "Standardized latency (ms/flow)",
        "standardized_throughput_flows_per_second":
            "Standardized throughput (flows/s)"
    }

    for key, label in metric_labels.items():
        values = comparison[key]
        lines.append(
            f"| {label} | {values['random_forest']:.4f} "
            f"| {values['xgboost']:.4f} |"
        )

    lines.extend([
        "",
        "## 2. Per-Class Performance",
        "",
        "| Class | Support | RF Precision | RF Recall | RF F1 "
        "| XGB Precision | XGB Recall | XGB F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"
    ])

    for label, values in per_class.items():

        rf_metrics = values["random_forest"]
        xgb_metrics = values["xgboost"]

        lines.append(
            f"| {label} | {values['support']} "
            f"| {rf_metrics['precision']:.2f}% "
            f"| {rf_metrics['recall']:.2f}% "
            f"| {rf_metrics['f1']:.2f}% "
            f"| {xgb_metrics['precision']:.2f}% "
            f"| {xgb_metrics['recall']:.2f}% "
            f"| {xgb_metrics['f1']:.2f}% |"
        )

    lines.extend([
        "",
        "## 3. Key Findings",
        ""
    ])

    for finding in report["findings"]:
        lines.append(f"- {finding}")

    lines.extend([
        "",
        "## 4. Benchmark Methodology",
        "",
        f"- Benchmark: {report['benchmark_methodology']['benchmark_name']}",
        f"- Chunk size: {report['benchmark_methodology']['chunk_size']:,}",
        f"- Number of chunks: "
        f"{report['benchmark_methodology']['number_of_chunks']}",
        f"- Warm-up records per model: "
        f"{report['benchmark_methodology']['warmup_records_per_model']:,}",
        f"- Prediction method: "
        f"{report['benchmark_methodology']['prediction_method']}",
        f"- Timing scope: "
        f"{report['benchmark_methodology']['timing_scope']}",
        "- Only one measured benchmark pass was performed.",
        "",
        "## 5. Limitations",
        ""
    ])

    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    recommendation = report["selection_recommendation"]

    lines.extend([
        "",
        "## 6. Model Selection Recommendation",
        "",
        f"**Status:** `{recommendation['status']}`",
        "",
        f"- **Random Forest:** {recommendation['random_forest']}",
        f"- **XGBoost:** {recommendation['xgboost']}",
        "",
        recommendation["decision"],
        "",
        "## 7. Conclusion",
        "",
        "The experiment demonstrates a trade-off between classification "
        "performance and inference efficiency. XGBoost provides stronger "
        "overall accuracy and precision, while Random Forest provides "
        "higher macro recall and substantially higher inference throughput. "
        "However, both models exhibit weaknesses on minority attack classes. "
        "A final deployment decision requires further class-specific "
        "evaluation and validation against controlled lab traffic.",
        ""
    ])

    return "\n".join(lines)


def main():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading multiclass evaluation reports...")

    rf = load_json(RF_PATH)
    xgb = load_json(XGB_PATH)
    benchmark = load_json(BENCHMARK_PATH)

    if rf["classes"] != xgb["classes"]:
        raise ValueError("Random Forest and XGBoost class lists differ.")

    if rf["features"] != xgb["features"]:
        raise ValueError("Random Forest and XGBoost feature lists differ.")

    if rf["test_records"] != xgb["test_records"]:
        raise ValueError("Model test record counts differ.")

    if rf["test_records"] != benchmark["test_records"]:
        raise ValueError("Benchmark test record count differs.")

    print("Source report validation passed.")

    report = build_report(rf, xgb, benchmark)

    with open(JSON_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    markdown = generate_markdown(report)

    with open(MD_OUTPUT, "w", encoding="utf-8") as file:
        file.write(markdown)

    print("\nReport generation completed.")
    print("JSON:", JSON_OUTPUT)
    print("Markdown:", MD_OUTPUT)


if __name__ == "__main__":
    main()
