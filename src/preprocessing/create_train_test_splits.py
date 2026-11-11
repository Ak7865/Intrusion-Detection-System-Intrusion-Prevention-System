import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold


ROOT = Path(__file__).resolve().parents[2]

SOURCE_ROOT = ROOT / "datasets/processed/cicids2017_v2/conflict_free"
OUTPUT_ROOT = ROOT / "datasets/splits/cicids2017_v2"

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

CONFIG = {
    "binary": {
        "source": SOURCE_ROOT / "binary/cicids2017_v2_binary_conflict_free.csv",
        "target": "binary_label",
        "expected_rows": 2_764_953,
        "expected_groups": 2_234_120,
    },
    "multiclass": {
        "source": SOURCE_ROOT / "multiclass/cicids2017_v2_multiclass_conflict_free.csv",
        "target": "multiclass_label",
        "expected_rows": 2_764_926,
        "expected_groups": 2_234_113,
    },
}

N_SPLITS = 5
SELECTED_FOLD = 1
RANDOM_STATE = 42


def main():
    print("=" * 70)
    print("CIC-IDS2017 V2 TRAIN/TEST SPLIT GENERATOR")
    print("=" * 70)
    print("Validation split: DISABLED")
    print("Training: approximately 80%")
    print("Testing: approximately 20%")

    if not OUTPUT_ROOT.is_dir():
        raise FileNotFoundError(f"Output directory missing: {OUTPUT_ROOT}")

    output_files = [
        OUTPUT_ROOT / "binary/train.csv",
        OUTPUT_ROOT / "binary/test.csv",
        OUTPUT_ROOT / "multiclass/train.csv",
        OUTPUT_ROOT / "multiclass/test.csv",
        OUTPUT_ROOT / "split_audit.json",
    ]

    existing = [str(p) for p in output_files if p.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite existing files:\n" + "\n".join(existing)
        )

    audit = {
        "project": "CIC-IDS2017 V2",
        "method": "StratifiedGroupKFold",
        "n_splits": N_SPLITS,
        "selected_fold": SELECTED_FOLD,
        "shuffle": True,
        "random_state": RANDOM_STATE,
        "train_test_ratio": "80:20 approximately",
        "validation_split": False,
        "features": FEATURES,
        "datasets": {},
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }

    with tempfile.TemporaryDirectory(
        prefix="cicids2017_split_",
        dir=OUTPUT_ROOT
    ) as temp_name:

        staging = Path(temp_name)

        for name, config in CONFIG.items():
            print(f"\n{'=' * 65}")
            print(f"PROCESSING: {name.upper()}")
            print("=" * 65)

            source = config["source"]
            target = config["target"]

            if not source.is_file():
                raise FileNotFoundError(source)

            df = pd.read_csv(source)

            if len(df) != config["expected_rows"]:
                raise ValueError(f"{name}: unexpected record count")

            # Identical feature vectors receive the same group identifier.
            groups = pd.util.hash_pandas_object(
                df[FEATURES],
                index=False
            )

            unique_groups = int(groups.nunique())

            if unique_groups != config["expected_groups"]:
                raise ValueError(
                    f"{name}: expected {config['expected_groups']:,} "
                    f"groups, found {unique_groups:,}"
                )

            splitter = StratifiedGroupKFold(
                n_splits=N_SPLITS,
                shuffle=True,
                random_state=RANDOM_STATE,
            )

            # Select the first fold only.
            train_idx, test_idx = next(
                splitter.split(df[FEATURES], df[target], groups)
            )

            train_df = df.iloc[train_idx]
            test_df = df.iloc[test_idx]

            train_groups = set(groups.iloc[train_idx])
            test_groups = set(groups.iloc[test_idx])
            overlap = train_groups.intersection(test_groups)

            if overlap:
                raise ValueError(
                    f"{name}: feature-group leakage detected: {len(overlap)}"
                )

            all_classes = set(df[target].unique())
            train_classes = set(train_df[target].unique())
            test_classes = set(test_df[target].unique())

            if train_classes != all_classes or test_classes != all_classes:
                raise ValueError(f"{name}: class missing from train or test")

            print(f"Total records: {len(df):,}")
            print(f"Unique feature groups: {unique_groups:,}")
            print(f"Training records: {len(train_df):,}")
            print(f"Testing records: {len(test_df):,}")
            print(f"Test percentage: {len(test_df) / len(df) * 100:.2f}%")
            print(f"Feature-group overlap: {len(overlap)}")
            print("Training classes:", len(train_classes))
            print("Testing classes:", len(test_classes))

            print("\nTest class distribution:")
            print(test_df[target].value_counts().sort_index().to_string())

            train_path = staging / f"{name}_train.csv"
            test_path = staging / f"{name}_test.csv"

            train_df.to_csv(train_path, index=False)
            test_df.to_csv(test_path, index=False)

            audit["datasets"][name] = {
                "source": str(source.relative_to(ROOT)),
                "target_column": target,
                "total_records": len(df),
                "unique_feature_groups": unique_groups,
                "training_records": len(train_df),
                "testing_records": len(test_df),
                "training_percentage": round(len(train_df) / len(df) * 100, 4),
                "testing_percentage": round(len(test_df) / len(df) * 100, 4),
                "feature_group_overlap": len(overlap),
                "missing_training_classes": sorted(all_classes - train_classes),
                "missing_testing_classes": sorted(all_classes - test_classes),
                "training_class_distribution": {
                    str(k): int(v)
                    for k, v in train_df[target].value_counts().items()
                },
                "testing_class_distribution": {
                    str(k): int(v)
                    for k, v in test_df[target].value_counts().items()
                },
                "validation": "PASS",
            }

            print(f"\n{name.upper()} SPLIT: PASS")

        audit["overall_validation"] = "PASS"

        audit_path = staging / "split_audit.json"
        audit_path.write_text(
            json.dumps(audit, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )

        print("\nPublishing train/test files...")

        destinations = {
            "binary_train.csv": OUTPUT_ROOT / "binary/train.csv",
            "binary_test.csv": OUTPUT_ROOT / "binary/test.csv",
            "multiclass_train.csv": OUTPUT_ROOT / "multiclass/train.csv",
            "multiclass_test.csv": OUTPUT_ROOT / "multiclass/test.csv",
            "split_audit.json": OUTPUT_ROOT / "split_audit.json",
        }

        staged = {
            "binary_train.csv": staging / "binary_train.csv",
            "binary_test.csv": staging / "binary_test.csv",
            "multiclass_train.csv": staging / "multiclass_train.csv",
            "multiclass_test.csv": staging / "multiclass_test.csv",
            "split_audit.json": audit_path,
        }

        for filename, destination in destinations.items():
            if destination.exists():
                raise FileExistsError(destination)
            staged[filename].replace(destination)
            print(f"Created: {destination.relative_to(ROOT)}")

    print("\n" + "=" * 70)
    print("TRAIN/TEST SPLIT GENERATION COMPLETED")
    print("Validation split: NOT CREATED")
    print("Group leakage: NONE")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)
