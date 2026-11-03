"""
Binary Random Forest retraining and report-figure generation.

Run from the project root:
    python ml/training/retrain_binary_report.py

This script:
- Keeps the deployed pilot model untouched.
- Compares an imbalanced baseline, an undersampled balanced model,
  and a class-weighted model.
- Uses the existing train/validation/test partitions.
- Uses validation only for model comparison. It does NOT evaluate the test set.
- Saves models, metrics, classification reports, and PNG figures in a
  timestamped experiments/ml/retraining_* directory.

Random Forest has no learning_rate parameter. n_estimators is the tree count.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score,
)

ROOT = Path(__file__).resolve().parents[2]
TRAIN_FILE = ROOT / "datasets/processed/splits/train.csv"
VAL_FILE = ROOT / "datasets/processed/splits/validation.csv"
TEST_FILE = ROOT / "datasets/processed/splits/test.csv"
CLEAN_FILE = ROOT / "datasets/processed/cicids2017_clean.csv"

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

RANDOM_STATE = 42
SAMPLE_SIZE = 200_000
BALANCED_PER_CLASS = 100_000

# Conservative configuration for the available 12 GB RAM / 2-core CPU.
RF_CONFIG = {
    "n_estimators": 30,
    "max_depth": 15,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "max_samples": 0.5,
    "n_jobs": 2,
    "random_state": RANDOM_STATE,
}

RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR = ROOT / "experiments" / "ml" / f"retraining_{RUN_ID}"
MODEL_DIR = OUT_DIR / "models"
FIG_DIR = OUT_DIR / "figures"
MODEL_DIR.mkdir(parents=True, exist_ok=False)
FIG_DIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 140,
    "savefig.dpi": 180,
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 10,
})


def require_files() -> None:
    for path in (TRAIN_FILE, VAL_FILE, TEST_FILE, CLEAN_FILE):
        if not path.exists():
            raise FileNotFoundError(f"Required dataset file not found: {path}")


def load_partition(path: Path, include_features: bool = True):
    columns = FEATURES + ["Label"] if include_features else ["Label"]
    dtype = {feature: np.float32 for feature in FEATURES} if include_features else None
    frame = pd.read_csv(path, usecols=columns, dtype=dtype)
    frame["Target"] = (frame["Label"] != "BENIGN").astype(np.uint8)
    return frame


def binary_counts(frame: pd.DataFrame) -> dict:
    counts = frame["Target"].value_counts().to_dict()
    return {
        "BENIGN": int(counts.get(0, 0)),
        "ATTACK": int(counts.get(1, 0)),
    }


def save_class_distribution(clean_counts, train_counts, baseline_counts, balanced_counts):
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.6))
    panels = [
        ("Full cleaned dataset", clean_counts),
        ("Original training sample", baseline_counts),
        ("Balanced training sample", balanced_counts),
    ]
    for ax, (title, counts) in zip(axes, panels):
        names = ["BENIGN", "ATTACK"]
        values = [counts["BENIGN"], counts["ATTACK"]]
        bars = ax.bar(names, values)
        ax.set_title(title)
        ax.set_ylabel("Records")
        ax.ticklabel_format(axis="y", style="plain")
        total = sum(values)
        for bar, value in zip(bars, values):
            pct = 100 * value / total if total else 0
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{value:,}\n({pct:.1f}%)",
                ha="center", va="bottom", fontsize=8
            )
        ax.grid(axis="y", alpha=0.2)
    fig.suptitle("Binary class distribution before and after balancing", fontsize=14)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "class_distribution_before_after.png", bbox_inches="tight")
    plt.close(fig)


def save_split_chart():
    split_counts = {
        "Training": sum(binary_counts(load_partition(TRAIN_FILE, False)).values()),
        "Validation": sum(binary_counts(load_partition(VAL_FILE, False)).values()),
        "Test": sum(binary_counts(load_partition(TEST_FILE, False)).values()),
    }
    total = sum(split_counts.values())
    labels = list(split_counts.keys())
    values = list(split_counts.values())
    percentages = [v / total * 100 for v in values]

    fig, ax = plt.subplots(figsize=(8, 4.8))
    bars = ax.bar(labels, percentages)
    ax.set_ylabel("Dataset share (%)")
    ax.set_ylim(0, max(percentages) * 1.22)
    ax.set_title("Train / validation / test split")
    for bar, count, pct in zip(bars, values, percentages):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                f"{pct:.2f}%\n({count:,})", ha="center", va="bottom")
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "dataset_split_ratio.png", bbox_inches="tight")
    plt.close(fig)
    return split_counts


def plot_confusion(name, actual, predicted):
    cm = confusion_matrix(actual, predicted, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(5.5, 4.7))
    image = ax.imshow(cm, interpolation="nearest")
    ax.figure.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    ax.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=["BENIGN", "ATTACK"],
        yticklabels=["BENIGN", "ATTACK"],
        ylabel="Actual class",
        xlabel="Predicted class",
        title=f"{name} — confusion matrix",
    )
    threshold = cm.max() / 2 if cm.size else 0
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > threshold else "black",
                    fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(FIG_DIR / f"confusion_matrix_{name.lower().replace(' ', '_')}.png",
                bbox_inches="tight")
    plt.close(fig)
    return cm


def evaluate_model(name, model, X_val, y_val):
    predictions = model.predict(X_val)
    probabilities = model.predict_proba(X_val)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_val, predictions, labels=[0, 1]).ravel()
    metrics = {
        "model": name,
        "accuracy": float(accuracy_score(y_val, predictions)),
        "precision": float(precision_score(y_val, predictions, zero_division=0)),
        "recall": float(recall_score(y_val, predictions, zero_division=0)),
        "f1_score": float(f1_score(y_val, predictions, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_val, predictions)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "roc_auc": float(roc_auc_score(y_val, probabilities)),
        "average_precision": float(average_precision_score(y_val, probabilities)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "validation_records": int(len(y_val)),
    }

    cm = plot_confusion(name, y_val, predictions)
    report = classification_report(
        y_val, predictions,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        digits=5,
        zero_division=0,
    )
    (OUT_DIR / f"classification_report_{name.lower().replace(' ', '_')}.txt").write_text(
        report, encoding="utf-8"
    )

    fpr, tpr, _ = roc_curve(y_val, probabilities)
    precision, recall, _ = precision_recall_curve(y_val, probabilities)
    return metrics, fpr, tpr, precision, recall


def main():
    require_files()
    print("=" * 72)
    print("BINARY RANDOM FOREST RETRAINING + REPORT FIGURES")
    print("=" * 72)
    print("Output:", OUT_DIR)
    print("Model configuration:", RF_CONFIG)

    # Read only 11 model features and labels from training/validation.
    train_df = load_partition(TRAIN_FILE, True)
    val_df = load_partition(VAL_FILE, True)

    print(f"\nTraining partition rows: {len(train_df):,}")
    print(f"Validation rows: {len(val_df):,}")

    # Convert labels to binary.
    train_counts_full = binary_counts(train_df)
    if train_counts_full["ATTACK"] < BALANCED_PER_CLASS:
        balanced_n = train_counts_full["ATTACK"]
    else:
        balanced_n = BALANCED_PER_CLASS

    # A: random sample preserving natural class proportions approximately.
    baseline_df = train_df.sample(
        n=min(SAMPLE_SIZE, len(train_df)),
        random_state=RANDOM_STATE,
    ).copy()

    # B: training-only random undersampling to equal class counts.
    benign_sample = train_df.loc[train_df["Target"] == 0].sample(
        n=balanced_n, random_state=RANDOM_STATE
    )
    attack_sample = train_df.loc[train_df["Target"] == 1].sample(
        n=balanced_n, random_state=RANDOM_STATE
    )
    balanced_df = pd.concat([benign_sample, attack_sample], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    # C: same naturally distributed sample as A, with class weighting.
    weighted_df = baseline_df.copy()

    clean_labels = pd.read_csv(CLEAN_FILE, usecols=["Label"])
    clean_labels["Target"] = (clean_labels["Label"] != "BENIGN").astype(np.uint8)
    clean_counts = binary_counts(clean_labels)
    del clean_labels

    baseline_counts = binary_counts(baseline_df)
    balanced_counts = binary_counts(balanced_df)

    save_class_distribution(
        clean_counts, train_counts_full, baseline_counts, balanced_counts
    )
    split_counts = save_split_chart()

    y_val = val_df["Target"].to_numpy(dtype=np.uint8)
    X_val = val_df[FEATURES].to_numpy(dtype=np.float32)

    experiments = [
        ("A_baseline_imbalanced", baseline_df, None),
        ("B_balanced_undersampled", balanced_df, None),
        ("C_class_weighted", weighted_df, "balanced"),
    ]

    results = []
    curves = []
    best_name = None
    best_model = None
    best_f1 = -1.0

    for name, sample_df, class_weight in experiments:
        print(f"\n--- Training {name} ---")
        print("Training records:", f"{len(sample_df):,}")
        print("Training class counts:", binary_counts(sample_df))

        X_train = sample_df[FEATURES].to_numpy(dtype=np.float32)
        y_train = sample_df["Target"].to_numpy(dtype=np.uint8)

        config = dict(RF_CONFIG)
        config["class_weight"] = class_weight
        model = RandomForestClassifier(**config)

        started = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - started

        model_path = MODEL_DIR / f"{name}.joblib"
        joblib.dump(model, model_path, compress=1)

        metrics, fpr, tpr, precision, recall = evaluate_model(
            name, model, X_val, y_val
        )
        metrics["training_records"] = int(len(y_train))
        metrics["training_time_seconds"] = round(elapsed, 3)
        metrics["class_weight"] = class_weight if class_weight else "none"
        metrics["model_file"] = str(model_path.relative_to(ROOT))
        results.append(metrics)
        curves.append((name, fpr, tpr, precision, recall))

        print("Validation:", {
            key: round(metrics[key], 5)
            for key in ("accuracy", "precision", "recall", "f1_score",
                        "balanced_accuracy", "false_positive_rate", "roc_auc")
        })
        print(f"Training time: {elapsed:.1f} seconds")

        if metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_name = name
            best_model = model

        del X_train, y_train, model, sample_df

    # Combined ROC and precision-recall curves.
    fig, ax = plt.subplots(figsize=(7, 5.5))
    for name, fpr, tpr, _, _ in curves:
        score = next(r["roc_auc"] for r in results if r["model"] == name)
        ax.plot(fpr, tpr, label=f"{name} (AUC={score:.4f})")
    ax.plot([0, 1], [0, 1], linestyle="--", linewidth=1, label="Random baseline")
    ax.set(xlabel="False positive rate", ylabel="True positive rate",
           title="ROC curve comparison")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "roc_curve_comparison.png", bbox_inches="tight")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 5.5))
    for name, _, _, precision, recall in curves:
        ap = next(r["average_precision"] for r in results if r["model"] == name)
        ax.plot(recall, precision, label=f"{name} (AP={ap:.4f})")
    ax.set(xlabel="Recall", ylabel="Precision",
           title="Precision–recall curve comparison")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "precision_recall_comparison.png", bbox_inches="tight")
    plt.close(fig)

    # Metric comparison chart.
    metrics_df = pd.DataFrame(results)
    metrics_df.to_csv(OUT_DIR / "model_comparison_metrics.csv", index=False)

    plot_metrics = ["accuracy", "precision", "recall", "f1_score", "balanced_accuracy"]
    ax = metrics_df.set_index("model")[plot_metrics].plot(
        kind="bar", figsize=(10, 5.5), ylim=(0, 1), rot=12
    )
    ax.set_ylabel("Score")
    ax.set_title("Validation metric comparison")
    ax.grid(axis="y", alpha=0.2)
    ax.legend(loc="lower right", fontsize=8)
    fig = ax.get_figure()
    fig.tight_layout()
    fig.savefig(FIG_DIR / "validation_metric_comparison.png", bbox_inches="tight")
    plt.close(fig)

    # Feature importance from the validation-F1-leading candidate.
    importances = pd.Series(best_model.feature_importances_, index=FEATURES).sort_values()
    fig, ax = plt.subplots(figsize=(8, 5.5))
    importances.plot(kind="barh", ax=ax)
    ax.set_xlabel("Mean decrease in impurity")
    ax.set_title(f"Feature importance — validation F1 leader: {best_name}")
    ax.grid(axis="x", alpha=0.2)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "best_candidate_feature_importance.png", bbox_inches="tight")
    plt.close(fig)

    # Record experiment details and explicit caveats.
    summary = {
        "run_id": RUN_ID,
        "dataset": "CIC-IDS2017 cleaned",
        "features": FEATURES,
        "class_mapping": {"0": "BENIGN", "1": "ATTACK"},
        "full_cleaned_class_counts": clean_counts,
        "full_training_partition_class_counts": train_counts_full,
        "baseline_sample_class_counts": baseline_counts,
        "balanced_sample_class_counts": balanced_counts,
        "split_counts": split_counts,
        "split_percentages": {
            key: round(value / sum(split_counts.values()) * 100, 4)
            for key, value in split_counts.items()
        },
        "random_forest_configuration": RF_CONFIG,
        "learning_rate": "Not applicable: Random Forest is not a gradient-based learning algorithm.",
        "tree_count": RF_CONFIG["n_estimators"],
        "selection_rule": "Highest validation F1-score; inspect precision, recall and FPR before selection.",
        "validation_f1_leader": best_name,
        "test_set_evaluated": False,
        "test_set_policy": "Untouched; reserve for final evaluation after candidate selection.",
        "results": results,
        "limitations": [
            "This is a 200,000-row pilot comparison, not full-training-partition fitting.",
            "Validation data retains its natural class distribution.",
            "Random undersampling discards some BENIGN training examples.",
            "Feature-hash split isolation is not a temporal/scenario-based holdout.",
            "Validation metrics are not final test metrics.",
        ],
    }
    (OUT_DIR / "experiment_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    print("\n" + "=" * 72)
    print("EXPERIMENT COMPLETE")
    print("=" * 72)
    print("Validation F1 leader:", best_name)
    print("Models:", MODEL_DIR)
    print("Metrics:", OUT_DIR / "model_comparison_metrics.csv")
    print("Figures:", FIG_DIR)
    print("\nGenerated figures:")
    for path in sorted(FIG_DIR.glob("*.png")):
        print(" -", path.name)
    print("\nIMPORTANT: The test set was not evaluated.")
    print("The deployed pilot model was not modified.")


if __name__ == "__main__":
    main()
