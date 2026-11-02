import pandas as pd

DATASET = "datasets/processed/cicids2017_clean.csv"

df = pd.read_csv(DATASET)

features = df.drop(columns=["Label"])

df["_group"] = pd.util.hash_pandas_object(
    features,
    index=False
)

summary = (
    df.groupby("Label")
    .agg(
        records=("Label", "size"),
        unique_feature_groups=("_group", "nunique")
    )
    .sort_values("records", ascending=False)
)

print("=" * 65)
print("CLASS SUPPORT AND INDEPENDENT FEATURE GROUPS")
print("=" * 65)

print(summary.to_string())

print("\nTotal records:", len(df))
print("Total unique feature groups:", df["_group"].nunique())

print("\nClasses with fewer than 10 unique feature groups:")

print(
    summary[
        summary["unique_feature_groups"] < 10
    ].to_string()
)