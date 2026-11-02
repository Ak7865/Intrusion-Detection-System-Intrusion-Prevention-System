import pandas as pd
from pathlib import Path

TRAIN_FILE = Path("datasets/processed/splits/train.csv")

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

print("Loading CIC-IDS2017 training data...")

df = pd.read_csv(
    TRAIN_FILE,
    usecols=FEATURES
)

matching = df[df["Destination Port"] == 8080].copy()

print("\n========== PORT 8080 ANALYSIS ==========")
print("Total training records:", len(df))
print("Port 8080 records:", len(matching))

if matching.empty:
    print("\nNo records found for destination port 8080.")
else:
    print("\n========== FEATURE DISTRIBUTION ==========")

    for feature in FEATURES[1:]:
        print(f"\n{feature}")
        print("Median:", matching[feature].median())
        print("Mean:", matching[feature].mean())
        print("Minimum:", matching[feature].min())
        print("Maximum:", matching[feature].max())

    print("\n========== CLASS DISTRIBUTION ==========")

    labels = pd.read_csv(
        TRAIN_FILE,
        usecols=["Destination Port", "Label"]
    )

    labels = labels[labels["Destination Port"] == 8080]

    print(labels["Label"].value_counts())

print("\nAnalysis completed.")