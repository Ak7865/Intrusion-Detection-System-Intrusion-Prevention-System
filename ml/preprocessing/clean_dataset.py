import pandas as pd

INPUT_FILE = (
    "datasets/processed/"
    "cicids2017_runtime_features.csv"
)

OUTPUT_FILE = (
    "datasets/processed/"
    "cicids2017_clean.csv"
)

print("=" * 60)
print("CREATING CLEAN EXPERIMENTAL DATASET")
print("=" * 60)

df = pd.read_csv(INPUT_FILE)

original_count = len(df)

# Features that cannot legitimately be negative
non_negative_features = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
]

# Identify invalid records
invalid_mask = (
    df[non_negative_features] < 0
).any(axis=1)

invalid_count = int(invalid_mask.sum())

# Remove invalid records
clean_df = df.loc[~invalid_mask].copy()

# Preserve original records and labels otherwise
clean_df.to_csv(OUTPUT_FILE, index=False)

print("\nOriginal records:", original_count)
print("Invalid records removed:", invalid_count)
print("Remaining records:", len(clean_df))

print("\nFinal class distribution:")
print(clean_df["Label"].value_counts().to_string())

print("\nOutput:", OUTPUT_FILE)

print("\nCleaning completed.")