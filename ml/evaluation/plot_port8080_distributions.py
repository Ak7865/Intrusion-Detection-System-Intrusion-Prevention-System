import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from pathlib import Path

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
RUNTIME_FILE = Path("logs/unified-features-node-a.jsonl")

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Down/Up Ratio",
]

LOG_FEATURES = [
    feature for feature in FEATURES
    if feature != "Down/Up Ratio"
]

OUTPUT_DIR = Path("reports/port8080_distributions")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading training data...")

training = pd.read_csv(TRAIN_FILE)

training = training[
    training["Destination Port"] == 8080
].copy()

print("Training records:", len(training))

print("Loading runtime data...")

runtime = pd.read_json(RUNTIME_FILE, lines=True)

runtime_features = pd.DataFrame(
    runtime["network_features"].tolist()
)

print("Runtime records:", len(runtime_features))

for feature in FEATURES:

    train_values = pd.to_numeric(
        training[feature], errors="coerce"
    ).dropna()

    runtime_values = pd.to_numeric(
        runtime_features[feature], errors="coerce"
    ).dropna()

    if feature in LOG_FEATURES:
        train_values = np.log1p(train_values)
        runtime_values = np.log1p(runtime_values)
        x_label = f"log1p({feature})"
    else:
        x_label = feature

    combined = np.concatenate([
        train_values.to_numpy(),
        runtime_values.to_numpy()
    ])

    bins = np.linspace(
        combined.min(),
        combined.max(),
        41
    )

    plt.figure(figsize=(10, 5))

    plt.hist(
        train_values,
        bins=bins,
        density=True,
        alpha=0.6,
        label="CIC-IDS2017 Port 8080"
    )

    plt.hist(
        runtime_values,
        bins=bins,
        density=True,
        alpha=0.6,
        label="Suricata Runtime"
    )

    plt.title(f"Normalized Distribution: {feature}")
    plt.xlabel(x_label)
    plt.ylabel("Probability Density")
    plt.legend()
    plt.tight_layout()

    filename = feature.replace("/", "_").replace(" ", "_")

    plt.savefig(
        OUTPUT_DIR / f"{filename}_normalized.png",
        dpi=150
    )

    plt.close()

    print("Generated:", filename)

print("\nNormalized comparison completed.")
print("Output:", OUTPUT_DIR)