"""
Generate additional diagrams from the ACTUAL fitted Random Forest models
and the actual validation CSV for an existing retraining run.

Run from project root:
python .\ml\evaluation\generate_actual_model_diagrams.py --run 20261103_130257

No model is retrained or overwritten. The script loads the saved .joblib
models, computes predictions on validation.csv, and writes PNG diagrams
inside that experiment's figures/actual_model/ directory.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
)

ROOT = Path(__file__).resolve().parents[2]
VAL_FILE = ROOT / "datasets/processed/splits/validation.csv"

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
    "Down/Up Ratio",
]

MODEL_NAMES = [
    "A_baseline_imbalanced",
    "B_balanced_undersampled",
    "C_class_weighted",
]


def save_confusion_matrices(y_true, model, name, out_dir):
    pred = model.predict(X_VAL)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])

    # Raw counts
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(cm, display_labels=["BENIGN", "ATTACK"])
    disp.plot(ax=ax, cmap="Blues", values_format=",", colorbar=False)
    ax.set_title(f"{name}: actual validation confusion matrix (counts)")
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_confusion_counts.png", bbox_inches="tight")
    plt.close(fig)

    # Row-normalized: recall per actual class
    row_sums = cm.sum(axis=1, keepdims=True)
    normalized = np.divide(cm, row_sums, out=np.zeros_like(cm, dtype=float),
                           where=row_sums != 0)
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(normalized, display_labels=["BENIGN", "ATTACK"])
    disp.plot(ax=ax, cmap="Blues", values_format=".2%", colorbar=False)
    ax.set_title(f"{name}: row-normalized validation confusion matrix")
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_confusion_normalized.png", bbox_inches="tight")
    plt.close(fig)
    return pred, cm


def plot_per_class(y_true, pred, name, out_dir):
    report = classification_report(
        y_true, pred, labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        output_dict=True, zero_division=0
    )
    labels = ["BENIGN", "ATTACK"]
    metric_names = ["precision", "recall", "f1-score"]
    x = np.arange(len(labels))
    width = 0.24

    fig, ax = plt.subplots(figsize=(8, 5))
    for idx, metric in enumerate(metric_names):
        vals = [report[label][metric] for label in labels]
        ax.bar(x + (idx - 1) * width, vals, width, label=metric)
        for xpos, val in zip(x + (idx - 1) * width, vals):
            ax.text(xpos, val + 0.004, f"{val:.4f}",
                    ha="center", va="bottom", fontsize=8, rotation=90)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Score")
    ax.set_title(f"{name}: per-class validation performance")
    ax.legend()
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_per_class_metrics.png", bbox_inches="tight")
    plt.close(fig)

    pd.DataFrame(report).T.to_csv(out_dir / f"{name}_classification_report.csv")


def plot_tree_count_curve(y_true, model, name, out_dir):
    """
    Reconstruct predictions from prefixes of the already-fitted forest.
    This is not a new fit: it evaluates the first N fitted trees.
    """
    trees = model.estimators_
    positive_probability_sum = np.zeros(len(y_true), dtype=np.float64)
    checkpoints = sorted(set([1, 2, 5, 10, 15, 20, 25, len(trees)]))
    checkpoints = [n for n in checkpoints if n <= len(trees)]
    records = []

    for index, tree in enumerate(trees, start=1):
        tree_prob = tree.predict_proba(X_VAL)
        # Find the probability column for class 1 robustly.
        class_one_index = list(tree.classes_).index(1)
        positive_probability_sum += tree_prob[:, class_one_index]

        if index in checkpoints:
            probability = positive_probability_sum / index
            prediction = (probability >= 0.5).astype(np.uint8)
            records.append({
                "trees": index,
                "accuracy": accuracy_score(y_true, prediction),
                "precision": precision_score(y_true, prediction, zero_division=0),
                "recall": recall_score(y_true, prediction, zero_division=0),
                "f1_score": f1_score(y_true, prediction, zero_division=0),
                "balanced_accuracy": balanced_accuracy_score(y_true, prediction),
            })

    curve = pd.DataFrame(records)
    curve.to_csv(out_dir / f"{name}_tree_count_metrics.csv", index=False)

    fig, ax = plt.subplots(figsize=(8, 5))
    for metric in ["accuracy", "precision", "recall", "f1_score", "balanced_accuracy"]:
        ax.plot(curve["trees"], curve[metric], marker="o", label=metric)
    ax.set_xlabel("Number of fitted trees included")
    ax.set_ylabel("Validation score")
    ax.set_ylim(0.95, 1.005)
    ax.set_title(f"{name}: validation performance by fitted tree count")
    ax.legend()
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}_tree_count_performance.png", bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True,
                        help="Timestamp suffix, e.g. 20261103_130257")
    args = parser.parse_args()

    run_dir = ROOT / "experiments" / "ml" / f"retraining_{args.run}"
    model_dir = run_dir / "models"
    out_dir = run_dir / "figures" / "actual_model"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not VAL_FILE.exists():
        raise FileNotFoundError(VAL_FILE)

    print("Loading validation data...")
    val = pd.read_csv(
        VAL_FILE,
        usecols=FEATURES + ["Label"],
        dtype={feature: np.float32 for feature in FEATURES},
    )
    y_val = (val["Label"] != "BENIGN").astype(np.uint8).to_numpy()

    global X_VAL
    X_VAL = val[FEATURES].to_numpy(dtype=np.float32)
    del val

    summary = []
    for name in MODEL_NAMES:
        model_path = model_dir / f"{name}.joblib"
        if not model_path.exists():
            raise FileNotFoundError(model_path)

        print(f"\nLoading actual fitted model: {model_path.name}")
        model = joblib.load(model_path)
        if model.n_features_in_ != len(FEATURES):
            raise ValueError(f"{name}: expected {len(FEATURES)} features, "
                             f"found {model.n_features_in_}")

        pred, cm = save_confusion_matrices(y_val, model, name, out_dir)
        plot_per_class(y_val, pred, name, out_dir)
        plot_tree_count_curve(y_val, model, name, out_dir)

        importance = pd.Series(
            model.feature_importances_, index=FEATURES
        ).sort_values()
        fig, ax = plt.subplots(figsize=(8, 5.5))
        importance.plot(kind="barh", ax=ax)
        ax.set_xlabel("Mean decrease in impurity")
        ax.set_title(f"{name}: feature importance from fitted model")
        ax.grid(axis="x", alpha=0.2)
        fig.tight_layout()
        fig.savefig(out_dir / f"{name}_feature_importance.png", bbox_inches="tight")
        plt.close(fig)
        importance.rename("importance").to_csv(
            out_dir / f"{name}_feature_importance.csv"
        )

        tn, fp, fn, tp = cm.ravel()
        summary.append({
            "model": name,
            "trees": model.n_estimators,
            "max_depth_config": model.max_depth,
            "validation_records": len(y_val),
            "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
        })
        del model

    pd.DataFrame(summary).to_csv(out_dir / "actual_model_summary.csv", index=False)
    print("\nCompleted. All diagrams are based on the saved fitted models and")
    print("the original validation partition. No test data was used.")
    print("Output:", out_dir)


if __name__ == "__main__":
    main()
