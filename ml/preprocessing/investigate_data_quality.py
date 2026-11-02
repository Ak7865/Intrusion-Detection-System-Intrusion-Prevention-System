import pandas as pd

DATASET = "datasets/processed/cicids2017_runtime_features.csv"

print("=" * 65)
print("PROCESSED DATASET QUALITY INVESTIGATION")
print("=" * 65)

df = pd.read_csv(DATASET)

X = df.drop(columns=["Label"])

# --------------------------------------------------
# 1. Identify duplicate feature groups
# --------------------------------------------------

print("\n[1] DUPLICATE INVESTIGATION")

hashes = pd.util.hash_pandas_object(X, index=False)

duplicate_data = pd.DataFrame({
    "hash": hashes,
    "label": df["Label"]
})

group_sizes = duplicate_data.groupby("hash").size()

duplicate_hashes = group_sizes[group_sizes > 1].index

duplicate_groups = duplicate_data[
    duplicate_data["hash"].isin(duplicate_hashes)
]

label_counts = duplicate_groups.groupby("hash")["label"].nunique()

conflicting_hashes = label_counts[label_counts > 1].index

print("Duplicate groups:", len(duplicate_hashes))

print(
    "Duplicate rows:",
    int(group_sizes[group_sizes > 1].sum())
)

print(
    "Groups with conflicting labels:",
    len(conflicting_hashes)
)

print(
    "Rows in conflicting groups:",
    int(
        duplicate_groups["hash"]
        .isin(conflicting_hashes)
        .sum()
    )
)

# --------------------------------------------------
# 2. Investigate negative values
# --------------------------------------------------

print("\n[2] NEGATIVE VALUE INVESTIGATION")

negative_mask = X.lt(0).any(axis=1)

negative_records = df.loc[negative_mask]

print("Total records with negative features:", len(negative_records))

print("\nNegative records by class:")
print(negative_records["Label"].value_counts().to_string())

print("\nNegative feature values by class:")

for feature in X.columns:
    mask = X[feature] < 0

    if mask.any():
        print(f"\n{feature}")
        print(
            df.loc[mask, "Label"]
            .value_counts()
            .to_string()
        )

# --------------------------------------------------
# 3. Display representative invalid records
# --------------------------------------------------

print("\n[3] SAMPLE NEGATIVE RECORDS")

print(
    negative_records.head(10).to_string(index=False)
)

print("\n" + "=" * 65)
print("INVESTIGATION COMPLETED")
print("=" * 65)