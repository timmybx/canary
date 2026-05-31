#!/usr/bin/env python3
"""
collect_canary_results.py

Collects all useful metrics, results, and analysis files from a CANARY
output directory tree into a single zip file for sharing/analysis.

Grabs per-model:
  - metrics.json          (model performance, train/test counts, feature importance)
  - precision_at_k.json   (operational precision@k analysis)
  - pr_curve.json         (precision-recall curve data)
  - feature_columns.json  (feature list used for training)
  - feature_selection.json (H3 feature selection results, if present)
  - test_predictions.csv  (ranked test predictions for case study)

Skips:
  - model.joblib / *.pkl  (large binary model files)
  - *.jsonl               (large raw data files)
  - Any file > 5 MB       (safety net)

Also grabs any top-level summary files (e.g. ablation summaries).

Usage:
  python collect_canary_results.py
  python collect_canary_results.py --models-dir /path/to/models --output results.zip
"""

import argparse
import zipfile
from pathlib import Path

# Files to collect from each model output directory
PER_MODEL_FILES = [
    "metrics.json",
    "precision_at_k.json",
    "pr_curve.json",
    "feature_columns.json",
    "feature_selection.json",
    "test_predictions.csv",
]

# Extensions to always skip regardless of filename
SKIP_EXTENSIONS = {".joblib", ".pkl", ".pickle", ".jsonl", ".parquet", ".feather"}

# Max file size to include (5 MB safety net)
MAX_FILE_BYTES = 5 * 1024 * 1024


def collect(models_dir: Path, output_zip: Path) -> None:
    if not models_dir.exists():
        print(f"ERROR: models directory not found: {models_dir}")
        return

    collected = []
    skipped_large = []
    skipped_binary = []

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # ── Per-model files ───────────────────────────────────────────────────
        model_dirs = sorted(
            [d for d in models_dir.iterdir() if d.is_dir()],
            key=lambda d: d.name,
        )

        if not model_dirs:
            print(f"WARNING: No subdirectories found in {models_dir}")
        else:
            print(f"Found {len(model_dirs)} model directories in {models_dir}")

        for model_dir in model_dirs:
            for filename in PER_MODEL_FILES:
                fpath = model_dir / filename
                if not fpath.exists():
                    continue
                size = fpath.stat().st_size
                if size > MAX_FILE_BYTES:
                    skipped_large.append(str(fpath))
                    continue
                arcname = f"models/{model_dir.name}/{filename}"
                zf.write(fpath, arcname)
                collected.append(arcname)

        # ── Top-level JSON/CSV summary files in models_dir ───────────────────
        for fpath in sorted(models_dir.glob("*.json")):
            if fpath.stat().st_size > MAX_FILE_BYTES:
                skipped_large.append(str(fpath))
                continue
            arcname = f"models/{fpath.name}"
            zf.write(fpath, arcname)
            collected.append(arcname)

        for fpath in sorted(models_dir.glob("*.csv")):
            if fpath.stat().st_size > MAX_FILE_BYTES:
                skipped_large.append(str(fpath))
                continue
            arcname = f"models/{fpath.name}"
            zf.write(fpath, arcname)
            collected.append(arcname)

    # ── Report ────────────────────────────────────────────────────────────────
    print(f"\nCollected {len(collected)} files into {output_zip}")
    print(f"Zip size: {output_zip.stat().st_size / 1024:.1f} KB")

    if collected:
        print("\nIncluded files:")
        for f in collected:
            print(f"  {f}")

    if skipped_large:
        print(f"\nSkipped {len(skipped_large)} oversized files (> 5 MB):")
        for f in skipped_large:
            print(f"  {f}")

    if skipped_binary:
        print(f"\nSkipped {len(skipped_binary)} binary files:")
        for f in skipped_binary:
            print(f"  {f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect CANARY results for sharing")
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path("models"),
        help="Path to your CANARY models/outputs directory (default: ./models)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("canary_results.zip"),
        help="Output zip filename (default: canary_results.zip)",
    )
    args = parser.parse_args()

    print(f"Collecting results from: {args.models_dir.resolve()}")
    print(f"Output zip: {args.output.resolve()}")
    print()

    collect(args.models_dir, args.output)


if __name__ == "__main__":
    main()
