import pandas as pd
import numpy as np

from pathlib import Path

INPUT = Path(
    "experiments/ml/feature_investigation/"
    "web_attack_feature_comparison.csv"
)

df = pd.read_csv(INPUT)

selected_features = [
    "Flow Bytes/s",
    "Max Packet Length",
    "Average Packet Size",
    "Packet Length Mean",
    "Total Length of Fwd Packets",
    "Avg Fwd Segment Size",
    "Fwd Packet Length Max",
    "Subflow Fwd Bytes",
    "Total Length of Bwd Packets",
    "Bwd Packet Length Max",
]

df = df[df["Feature"].isin(selected_features)]

print("\nZERO-VALUE INVESTIGATION")
print("=" * 75)

for attack in [
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]:

    subset = df[df["Attack"] == attack]

    print(f"\n{attack}")
    print("-" * 75)

    for _, row in subset.iterrows():

        benign_nonzero = row["Benign_Nonzero_Percent"]
        attack_nonzero = row["Attack_Nonzero_Percent"]

        print(
            f"{row['Feature']:<35} "
            f"BENIGN non-zero: {benign_nonzero:8.3f}% | "
            f"ATTACK non-zero: {attack_nonzero:8.3f}%"
        )