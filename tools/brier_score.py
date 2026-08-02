"""
tools/brier_score.py
====================
Brier score and base-rate skill score from saved test predictions.

The Brier score is the mean squared error between predicted probabilities
and binary outcomes: BS = mean((y_prob - y_true)^2). Lower is better; 0 is
perfect. Because squared errors on rare events are small, a raw Brier score
looks deceptively good at CANARY's ~1.9% base rate, so this tool also
reports the base-rate reference (a "climatology" model that predicts the
test-set base rate for every observation, BS_ref = mean((base - y_true)^2))
and the Brier skill score, BSS = 1 - BS / BS_ref. A positive skill score
means the model's probabilities carry information beyond always predicting
the base rate; this is a necessary (not sufficient) condition for the
scores to be interpretable as probabilities.

This is the preliminary calibration check reported in praxis Section 4.7.
Formal calibration (reliability analysis, ECE, threshold justification)
remains future work; see also the ``calibration`` figure in
``tools/make_figures.py``.

Usage
-----
    # Default: headline and deployed interpretation models
    docker compose run --rm canary python tools/brier_score.py

    # Any model directories (uses <dir>/test_predictions.csv)
    python tools/brier_score.py data/processed/models/xgb_6m_*_time

    # JSON artifact
    python tools/brier_score.py --json data/processed/results/brier_scores.json

Output
------
    Console table: n, positives, base rate, Brier score, base-rate
    reference, and skill score per model. Optional JSON (``--json``).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

DEFAULT_MODELS = [
    "data/processed/models/xgb_6m_advisory_swh_time",
    "data/processed/models/xgb_6m_full_cleaned_time",
]


def load_predictions(path: str) -> list[tuple[float, int]]:
    """Return (y_prob, y_true) pairs from a predictions CSV or model dir."""
    if os.path.isdir(path):
        path = os.path.join(path, "test_predictions.csv")
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or not {"y_prob", "y_true"} <= set(reader.fieldnames):
            raise SystemExit(f"{path}: expected columns y_prob and y_true")
        return [(float(r["y_prob"]), int(r["y_true"])) for r in reader]


def brier(pairs: list[tuple[float, int]]) -> dict:
    n = len(pairs)
    positives = sum(y for _, y in pairs)
    base = positives / n
    bs = sum((p - y) ** 2 for p, y in pairs) / n
    bs_ref = sum((base - y) ** 2 for _, y in pairs) / n
    return {
        "n": n,
        "positives": positives,
        "base_rate": base,
        "brier_score": bs,
        "brier_reference": bs_ref,
        "brier_skill_score": 1.0 - bs / bs_ref if bs_ref > 0 else float("nan"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[3])
    ap.add_argument(
        "paths",
        nargs="*",
        default=DEFAULT_MODELS,
        help="model directories or prediction CSVs (default: headline and full models)",
    )
    ap.add_argument("--json", help="write results to this JSON file")
    args = ap.parse_args()

    results = {}
    header = f"{'model':<36} {'n':>6} {'pos':>5} {'base':>7} {'Brier':>8} {'ref':>8} {'skill':>7}"
    print(header)
    print("-" * len(header))
    for path in args.paths:
        name = os.path.basename(os.path.normpath(path)).replace("test_predictions.csv", "")
        r = brier(load_predictions(path))
        results[name] = r
        print(
            f"{name:<36} {r['n']:>6} {r['positives']:>5} {r['base_rate']:>7.4f} "
            f"{r['brier_score']:>8.4f} {r['brier_reference']:>8.4f} {r['brier_skill_score']:>+7.3f}"
        )

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"Saved: {args.json}")


if __name__ == "__main__":
    sys.exit(main())
