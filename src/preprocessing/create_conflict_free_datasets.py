import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

SOURCE = (
    ROOT / "datasets/processed/cicids2017_v2/deployment/"
    "cicids2017_v2_deployment.csv"
)

OUTPUT_ROOT = ROOT / "datasets/processed/cicids2017_v2/conflict_free"

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

EXPECTED_TOTAL = 2_827_761
EXPECTED_BINARY_CONFLICTS = 62_808
EXPECTED_MULTICLASS_CONFLICTS = 62_835

OUTPUTS = {
    "binary": (
        OUTPUT_ROOT / "binary/cicids2017_v2_binary_conflict_free.csv"
    ),
    "multiclass": (
        OUTPUT_ROOT / "multiclass/cicids2017_v2_multiclass_conflict_free.csv"
    ),
    "binary_quarantine": (
        OUTPUT_ROOT / "quarantine/cicids2017_v2_binary_conflicts.csv"
    ),
    "multiclass_quarantine": (
        OUTPUT_ROOT / "quarantine/cicids2017_v2_multiclass_conflicts.csv"
    ),
    "audit": OUTPUT_ROOT / "conflict_free_audit.json",
}


def main():
    print("=" * 70)
    print("CIC-IDS2017 V2 CONFLICT-FREE DATASET GENERATOR")
    print("=" * 70)

    if not SOURCE.is_file():
        raise FileNotFoundError(f"Source dataset not found: {SOURCE}")

    existing = [str(p) for p in OUTPUTS.values() if p.exists()]
    if existing:
        raise FileExistsError(
            "Refusing to overwrite existing outputs:\n" +
            "\n".join(existing)
        )

    required_dirs = [
        OUTPUT_ROOT / "binary",
        OUTPUT_ROOT / "multiclass",
        OUTPUT_ROOT / "quarantine",
    ]

    for directory in required_dirs:
        if not directory.is_dir():
            raise FileNotFoundError(
                f"Expected output directory does not exist: {directory}"
            )

    print("\nLoading deployment dataset...")
    columns = FEATURES + [
        "original_label",
        "multiclass_label",
        "binary_label",
        "source_file",
        "source_row",
    ]

    df = pd.read_csv(SOURCE, usecols=columns)

    total = len(df)
    print(f"Records loaded: {total:,}")

    if total != EXPECTED_TOTAL:
        raise ValueError(
            f"Unexpected source row count: {total:,}; "
            f"expected {EXPECTED_TOTAL:,}"
        )

    if df[columns].isnull().any().any():
        raise ValueError("Unexpected missing values found in source data.")

    print("\nIdentifying binary label conflicts...")
    binary_conflict = (
        df.groupby(FEATURES, sort=False, dropna=False)["binary_label"]
        .transform("nunique") > 1
    )

    print("Identifying multiclass label conflicts...")
    multiclass_conflict = (
        df.groupby(FEATURES, sort=False, dropna=False)["multiclass_label"]
        .transform("nunique") > 1
    )

    binary_conflict_count = int(binary_conflict.sum())
    multiclass_conflict_count = int(multiclass_conflict.sum())

    if binary_conflict_count != EXPECTED_BINARY_CONFLICTS:
        raise ValueError(
            f"Binary conflict count mismatch: {binary_conflict_count:,}"
        )

    if multiclass_conflict_count != EXPECTED_MULTICLASS_CONFLICTS:
        raise ValueError(
            f"Multiclass conflict count mismatch: "
            f"{multiclass_conflict_count:,}"
        )

    binary_clean = df.loc[~binary_conflict, columns].copy()
    multiclass_clean = df.loc[~multiclass_conflict, columns].copy()

    binary_quarantine = df.loc[binary_conflict, columns].copy()
    multiclass_quarantine = df.loc[multiclass_conflict, columns].copy()

    print("\nValidating output counts...")
    expected_counts = {
        "binary_clean": 2_764_953,
        "multiclass_clean": 2_764_926,
        "binary_quarantine": EXPECTED_BINARY_CONFLICTS,
        "multiclass_quarantine": EXPECTED_MULTICLASS_CONFLICTS,
    }

    actual_counts = {
        "binary_clean": len(binary_clean),
        "multiclass_clean": len(multiclass_clean),
        "binary_quarantine": len(binary_quarantine),
        "multiclass_quarantine": len(multiclass_quarantine),
    }

    for name, expected in expected_counts.items():
        actual = actual_counts[name]
        print(f"{name}: {actual:,} (expected {expected:,})")
        if actual != expected:
            raise ValueError(f"Record count validation failed: {name}")

    # Confirm that each retained feature vector has only one target label.
    for name, frame, label in [
        ("binary", binary_clean, "binary_label"),
        ("multiclass", multiclass_clean, "multiclass_label"),
    ]:
        remaining_conflicts = (
            frame.groupby(FEATURES, sort=False, dropna=False)[label]
            .nunique()
            .gt(1)
            .sum()
        )
        if remaining_conflicts:
            raise ValueError(
                f"{name} output still contains conflicting feature vectors."
            )

    audit = {
        "project": "CIC-IDS2017 V2",
        "operation": "Conflict-free dataset generation",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(SOURCE.relative_to(ROOT)),
        "features": FEATURES,
        "policy": {
            "binary": "Exclude feature vectors with multiple binary labels.",
            "multiclass": "Exclude feature vectors with multiple multiclass labels.",
            "consistent_duplicates": "Retain all records.",
            "majority_voting": False,
            "original_source_modified": False,
        },
        "record_counts": {
            "source_total": total,
            **actual_counts,
        },
        "class_distributions": {
            "binary_clean": {
                str(k): int(v)
                for k, v in binary_clean["binary_label"].value_counts().items()
            },
            "multiclass_clean": {
                str(k): int(v)
                for k, v in multiclass_clean["multiclass_label"].value_counts().items()
            },
        },
        "validation": {
            "source_count_matches": True,
            "conflict_counts_match": True,
            "output_counts_match": True,
            "remaining_binary_conflicts": 0,
            "remaining_multiclass_conflicts": 0,
        },
    }

    print("\nPreparing output files in a temporary staging directory...")

    with tempfile.TemporaryDirectory(
        prefix="cicids2017_conflict_free_",
        dir=OUTPUT_ROOT
    ) as temp_name:

        staging = Path(temp_name)

        staged_files = {
            "binary": staging / OUTPUTS["binary"].name,
            "multiclass": staging / OUTPUTS["multiclass"].name,
            "binary_quarantine": staging / OUTPUTS["binary_quarantine"].name,
            "multiclass_quarantine": staging / OUTPUTS["multiclass_quarantine"].name,
            "audit": staging / OUTPUTS["audit"].name,
        }

        binary_clean.to_csv(staged_files["binary"], index=False)
        multiclass_clean.to_csv(staged_files["multiclass"], index=False)
        binary_quarantine.to_csv(staged_files["binary_quarantine"], index=False)
        multiclass_quarantine.to_csv(staged_files["multiclass_quarantine"], index=False)

        staged_files["audit"].write_text(
            json.dumps(audit, indent=4, ensure_ascii=False),
            encoding="utf-8"
        )

        print("\nPublishing validated files...")

        for key, staged_path in staged_files.items():
            destination = OUTPUTS[key]
            if destination.exists():
                raise FileExistsError(
                    f"Output appeared during processing: {destination}"
                )
            staged_path.replace(destination)
            print(f"Created: {destination.relative_to(ROOT)}")

    print("\n" + "=" * 70)
    print("CONFLICT-FREE DATASET GENERATION COMPLETED")
    print("=" * 70)
    print(json.dumps(actual_counts, indent=4))
    print(f"\nAudit report: {OUTPUTS['audit']}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)
