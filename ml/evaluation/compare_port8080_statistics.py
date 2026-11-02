import pandas as pd
import numpy as np

from pathlib import Path
from scipy.stats import ks_2samp

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

print("Loading CIC-IDS2017 data...")

training = pd.read_csv(TRAIN_FILE)

training = training[
    training["Destination Port"] == 8080
].copy()

print("Loading Suricata runtime data...")

runtime = pd.read_json(RUNTIME_FILE, lines=True)

runtime_features = pd.DataFrame(
    runtime["network_features"].tolist()
)

results = []

for feature in FEATURES:

    train = pd.to_numeric(
        training[feature], errors="coerce"
    ).to_numpy(dtype=float)

    live = pd.to_numeric(
        runtime_features[feature], errors="coerce"
    ).to_numpy(dtype=float)

    train = train[np.isfinite(train)]
    live = live[np.isfinite(live)]

    if feature != "Down/Up Ratio":
        train = np.log1p(train)
        live = np.log1p(live)

    ks = ks_2samp(train, live)

    results.append({
        "Feature": feature,
        "Training_Median": np.median(train),
        "Runtime_Median": np.median(live),
        "Training_Q25": np.percentile(train, 25),
        "Training_Q75": np.percentile(train, 75),
        "Runtime_Q25": np.percentile(live, 25),
        "Runtime_Q75": np.percentile(live, 75),
        "KS_Statistic": ks.statistic,
        "KS_P_Value": ks.pvalue,
        "Training_Count": len(train),
        "Runtime_Count": len(live),
    })

report = pd.DataFrame(results)

output = Path("reports/port8080_statistics.csv")
output.parent.mkdir(parents=True, exist_ok=True)

report.to_csv(output, index=False)

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

print("\n========== DISTRIBUTION COMPARISON ==========")
print(report.round(5).to_string(index=False))

print("\nReport saved:", output)