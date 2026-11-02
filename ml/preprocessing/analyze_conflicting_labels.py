import pandas as pd

DATASET = "datasets/processed/cicids2017_runtime_features.csv"

df = pd.read_csv(DATASET)

X = df.drop(columns=["Label"])

# Generate feature fingerprints
df["_hash"] = pd.util.hash_pandas_object(
    X,
    index=False
)

# Identify groups with multiple labels
label_groups = (
    df.groupby("_hash")["Label"]
    .agg(lambda labels: tuple(sorted(labels.unique())))
)

conflicting_groups = label_groups[
    label_groups.map(len) > 1
]

conflict_hashes = conflicting_groups.index

conflict_rows = df[
    df["_hash"].isin(conflict_hashes)
]

print("=" * 65)
print("CONFLICTING LABEL ANALYSIS")
print("=" * 65)

print("\nTotal conflicting groups:", len(conflicting_groups))

print("\nConflicting label combinations:")

print(
    conflicting_groups.value_counts()
    .head(30)
    .to_string()
)

print("\nClass distribution inside conflicting groups:")

print(
    conflict_rows["Label"]
    .value_counts()
    .to_string()
)

print("\nSample conflicting records:")

for fingerprint in conflicting_groups.index[:5]:

    group = conflict_rows[
        conflict_rows["_hash"] == fingerprint
    ]

    print("\nLabels:", group["Label"].unique())

    print(
        group.drop(columns=["_hash"])
        .to_string(index=False)
    )

print("\n" + "=" * 65)
print("ANALYSIS COMPLETED")
print("=" * 65)