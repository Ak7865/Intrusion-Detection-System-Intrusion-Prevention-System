from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config" / "cicids2017_v2.json"


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_chunk(chunk):
    chunk.columns = [str(column).strip() for column in chunk.columns]

    duplicate = "Fwd Header Length.1"

    if duplicate in chunk.columns:
        chunk = chunk.drop(columns=[duplicate])

    if len(chunk.columns) != len(set(chunk.columns)):
        raise ValueError("Duplicate columns remain after normalization.")

    return chunk


def get_exclusion_reasons(numeric, features):
    missing = numeric.isna()

    infinite = pd.DataFrame(
        np.isinf(numeric.to_numpy(dtype=float)),
        columns=features,
        index=numeric.index,
    )

    negative = numeric.lt(0)

    invalid = missing | infinite | negative

    reasons = []

    for index in numeric.index:
        row_reasons = []

        for feature in features:
            if missing.at[index, feature]:
                row_reasons.append(f"{feature}:missing")

            if infinite.at[index, feature]:
                row_reasons.append(f"{feature}:infinite")

            if negative.at[index, feature]:
                row_reasons.append(f"{feature}:negative")

        reasons.append(";".join(row_reasons))

    return invalid.any(axis=1), reasons


def process(dry_run=True):
    config = load_config()

    raw_folder = ROOT / config["paths"]["raw"]
    output_folder = ROOT / config["paths"]["processed"]
    quarantine_folder = ROOT / config["paths"]["quarantine"]

    features = config["features"]["deployment"]
    label_mapping = config["labels"]["multiclass"]
    chunk_size = config["preprocessing"]["chunk_size"]

    files = sorted(raw_folder.glob("*.csv"))

    if len(files) != config["raw_data"]["expected_files"]:
        raise RuntimeError(
            f"Expected {config['raw_data']['expected_files']} CSV files; "
            f"found {len(files)}."
        )

    if not dry_run:
        destinations = [
            output_folder / "deployment" / "cicids2017_v2_deployment.csv",
            output_folder / "binary" / "cicids2017_v2_binary.csv",
            output_folder / "multiclass" / "cicids2017_v2_multiclass.csv",
            quarantine_folder / "deployment_invalid_records.csv",
            output_folder / "deployment" / "preprocessing_audit.json",
        ]

        existing = [path for path in destinations if path.exists()]

        if existing:
            raise FileExistsError(
                "Output files already exist. Refusing to overwrite:\n"
                + "\n".join(str(path) for path in existing)
            )

    total_rows = 0
    valid_rows = 0
    invalid_rows = 0

    original_label_counts = Counter()
    multiclass_counts = Counter()
    binary_counts = Counter()
    exclusion_counts = Counter()
    file_counts = Counter()

    output_written = {
        "deployment": False,
        "binary": False,
        "multiclass": False,
        "quarantine": False,
    }

    print("=" * 75)
    print("CIC-IDS2017 V2 PREPROCESSING")
    print("MODE:", "DRY RUN" if dry_run else "FULL BUILD")
    print("=" * 75)

    for file in files:
        print(f"\nProcessing: {file.name}")

        source_offset = 0

        for chunk in pd.read_csv(
            file,
            encoding=config["preprocessing"]["encoding"],
            chunksize=chunk_size,
            low_memory=False,
        ):

            chunk = normalize_chunk(chunk)

            if "Label" not in chunk.columns:
                raise ValueError(f"Label column missing in {file.name}")

            if not set(features).issubset(chunk.columns):
                raise ValueError(f"Deployment features missing in {file.name}")

            original_labels = chunk["Label"].astype(str).str.strip()

            unmapped = set(original_labels.unique()) - set(label_mapping)

            if unmapped:
                raise ValueError(
                    f"Unmapped labels in {file.name}: {sorted(unmapped)}"
                )

            raw_features = chunk[features]

            numeric = raw_features.apply(
                pd.to_numeric,
                errors="coerce",
            )

            conversion_errors = (
                numeric.isna()
                & raw_features.notna()
            )

            if conversion_errors.any().any():
                raise ValueError(
                    f"Unexpected numeric conversion error in {file.name}"
                )

            invalid_mask, reasons = get_exclusion_reasons(
                numeric,
                features,
            )

            source_rows = np.arange(
                source_offset,
                source_offset + len(chunk),
            )

            source_offset += len(chunk)
            total_rows += len(chunk)

            original_label_counts.update(original_labels.value_counts().to_dict())

            mapped_labels = original_labels.map(label_mapping)

            normal_mask = mapped_labels.eq("Normal")

            binary_labels = np.where(normal_mask, "Normal", "Attack")

            multiclass_counts.update(mapped_labels.value_counts().to_dict())
            binary_counts.update(pd.Series(binary_labels).value_counts().to_dict())

            valid_mask = ~invalid_mask

            valid_count = int(valid_mask.sum())
            invalid_count = int(invalid_mask.sum())

            valid_rows += valid_count
            invalid_rows += invalid_count

            file_counts[file.name] += invalid_count

            for reason in np.array(reasons)[invalid_mask.to_numpy()]:
                exclusion_counts.update(reason.split(";"))

            if dry_run:
                continue

            if valid_count:
                valid_features = numeric.loc[valid_mask, features].copy()

                metadata = pd.DataFrame({
                    "original_label": original_labels.loc[valid_mask],
                    "multiclass_label": mapped_labels.loc[valid_mask],
                    "binary_label": binary_labels[valid_mask.to_numpy()],
                    "source_file": file.name,
                    "source_row": source_rows[valid_mask.to_numpy()],
                }, index=valid_features.index)

                deployment = pd.concat(
                    [valid_features, metadata],
                    axis=1,
                )

                binary = pd.concat(
                    [
                        valid_features,
                        metadata[
                            ["binary_label", "original_label",
                             "source_file", "source_row"]
                        ],
                    ],
                    axis=1,
                )

                multiclass = pd.concat(
                    [
                        valid_features,
                        metadata[
                            ["multiclass_label", "original_label",
                             "source_file", "source_row"]
                        ],
                    ],
                    axis=1,
                )

                outputs = [
                    (
                        deployment,
                        output_folder / "deployment" /
                        "cicids2017_v2_deployment.csv",
                        "deployment",
                    ),
                    (
                        binary,
                        output_folder / "binary" /
                        "cicids2017_v2_binary.csv",
                        "binary",
                    ),
                    (
                        multiclass,
                        output_folder / "multiclass" /
                        "cicids2017_v2_multiclass.csv",
                        "multiclass",
                    ),
                ]

                for dataframe, path, name in outputs:
                    path.parent.mkdir(parents=True, exist_ok=True)

                    dataframe.to_csv(
                        path,
                        mode="a",
                        header=not output_written[name],
                        index=False,
                    )

                    output_written[name] = True

            if invalid_count:
                quarantine = chunk.loc[invalid_mask].copy()

                quarantine["source_file"] = file.name
                quarantine["source_row"] = source_rows[invalid_mask.to_numpy()]
                quarantine["exclusion_reason"] = np.array(reasons)[
                    invalid_mask.to_numpy()
                ]

                path = quarantine_folder / "deployment_invalid_records.csv"
                path.parent.mkdir(parents=True, exist_ok=True)

                quarantine.to_csv(
                    path,
                    mode="a",
                    header=not output_written["quarantine"],
                    index=False,
                )

                output_written["quarantine"] = True

        print(
            f"Completed: {file.name} | "
            f"Rows: {source_offset:,} | "
            f"Invalid: {file_counts[file.name]:,}"
        )

    report = {
        "mode": "dry_run" if dry_run else "full_build",
        "raw_records": total_rows,
        "valid_deployment_records": valid_rows,
        "quarantined_records": invalid_rows,
        "original_label_distribution": dict(original_label_counts),
        "multiclass_distribution": dict(multiclass_counts),
        "binary_distribution": dict(binary_counts),
        "exclusion_reasons": dict(exclusion_counts),
        "quarantine_by_source_file": dict(file_counts),
        "outputs_written": output_written,
    }

    print("\n" + "=" * 75)
    print("PREPROCESSING SUMMARY")
    print("=" * 75)
    print(json.dumps(report, indent=4, ensure_ascii=False))

    if dry_run:
        print("\nDRY RUN: No datasets or reports were written.")

        expected = config["expected_audit"]

        if total_rows != expected["raw_records"]:
            raise RuntimeError("Raw record count differs from expected audit.")

        if invalid_rows != expected["deployment_invalid_records"]:
            raise RuntimeError("Invalid record count differs from expected audit.")

        if valid_rows != expected["deployment_valid_records"]:
            raise RuntimeError("Valid record count differs from expected audit.")

        print("\nAUDIT VALIDATION: PASS")

    else:
        report_path = (
            output_folder / "deployment" / "preprocessing_audit.json"
        )

        report_path.parent.mkdir(parents=True, exist_ok=True)

        with report_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, ensure_ascii=False)

        print("\nFULL BUILD COMPLETED.")
        print("Audit report:", report_path)


def main():
    parser = argparse.ArgumentParser(
        description="CIC-IDS2017 v2 preprocessing pipeline"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Audit all raw records without writing datasets.",
    )

    parser.add_argument(
        "--build",
        action="store_true",
        help="Generate deployment, binary, multiclass and quarantine CSVs.",
    )

    args = parser.parse_args()

    if args.dry_run == args.build:
        parser.error("Specify exactly one of --dry-run or --build.")

    process(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
