"""
tools/dedup_precision.py
=========================
Component-level deduplicated precision-at-k from saved test predictions.

Evaluation rankings in CANARY are over component-month observations, so a
single high-risk component can occupy several top-k positions (one row per
test month). This tool recomputes precision-at-k after deduplicating the
ranking to one row per component (each component's highest-scored test
observation), which is the operationally meaningful triage view: "of the k
distinct components ranked riskiest, what fraction received an advisory in
the prediction window."

Works on any saved predictions file with columns:
    <id column>, month, y_true, y_prob
The id column is auto-detected (``plugin_id`` or ``package_id``) or can be
set with ``--id-col``.

Usage
-----
    # One or more prediction files
    python tools/dedup_precision.py data/processed/models/xgb_6m_full_cleaned_time/test.csv

    # Model directories (uses <dir>/test_predictions.csv)
    python tools/dedup_precision.py data/processed/models/xgb_6m_*_time

    # Custom k values and JSON output
    python tools/dedup_precision.py --k 10 25 50 100 --json out.json <paths...>

Output
------
    Console table: row-level P@k, distinct components in the row-level
    top k, and deduplicated P@k, per input and k.
    Optional JSON file with the same values (``--json``).
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

ID_COLUMN_CANDIDATES = ("plugin_id", "package_id")
DEFAULT_K = (10, 25, 50)


def _load_predictions(path: Path, id_col: str | None) -> tuple[str, list[dict[str, Any]]]:
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        if id_col is None:
            for candidate in ID_COLUMN_CANDIDATES:
                if candidate in fieldnames:
                    id_col = candidate
                    break
        if id_col is None or id_col not in fieldnames:
            raise ValueError(
                f"{path}: could not find id column "
                f"(looked for {ID_COLUMN_CANDIDATES}, use --id-col)"
            )
        rows = [
            {
                "id": r[id_col],
                "y_true": int(r["y_true"]),
                "y_prob": float(r["y_prob"]),
            }
            for r in reader
        ]
    return id_col, rows


def _ranked(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda r: r["y_prob"], reverse=True)


def _row_precision_at_k(ranked: list[dict[str, Any]], k: int) -> float:
    top = ranked[:k]
    return sum(r["y_true"] for r in top) / k if len(top) >= k else float("nan")


def _distinct_in_top_k(ranked: list[dict[str, Any]], k: int) -> int:
    return len({r["id"] for r in ranked[:k]})


def _dedup_precision_at_k(ranked: list[dict[str, Any]], k: int) -> float:
    seen: set[str] = set()
    best: list[dict[str, Any]] = []
    for r in ranked:
        if r["id"] not in seen:
            seen.add(r["id"])
            best.append(r)
            if len(best) == k:
                break
    return sum(r["y_true"] for r in best) / k if len(best) >= k else float("nan")


def _resolve_paths(raw_paths: list[str]) -> list[Path]:
    paths: list[Path] = []
    for raw in raw_paths:
        p = Path(raw)
        if p.is_dir():
            p = p / "test_predictions.csv"
        if not p.exists():
            raise FileNotFoundError(f"Predictions file not found: {p}")
        paths.append(p)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Component-level deduplicated precision-at-k from saved test predictions."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="test_predictions.csv file(s) or model directories containing one",
    )
    parser.add_argument(
        "--k",
        type=int,
        nargs="+",
        default=list(DEFAULT_K),
        help=f"k values (default: {' '.join(str(k) for k in DEFAULT_K)})",
    )
    parser.add_argument("--id-col", default=None, help="component id column name")
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    results: list[dict[str, Any]] = []
    header = f"{'source':<36} {'k':>4} {'row P@k':>9} {'distinct':>9} {'dedup P@k':>10}"
    print(header)
    print("-" * len(header))

    for path in _resolve_paths(args.paths):
        label = path.parent.name if path.name == "test_predictions.csv" else path.name
        id_col, rows = _load_predictions(path, args.id_col)
        ranked = _ranked(rows)
        n_components = len({r["id"] for r in rows})
        entry: dict[str, Any] = {
            "source": str(path),
            "id_column": id_col,
            "n_rows": len(rows),
            "n_components": n_components,
        }
        for k in args.k:
            row_p = _row_precision_at_k(ranked, k)
            distinct = _distinct_in_top_k(ranked, k)
            dedup_p = _dedup_precision_at_k(ranked, k)
            entry[f"row_p_at_{k}"] = round(row_p, 4)
            entry[f"distinct_in_top_{k}"] = distinct
            entry[f"dedup_p_at_{k}"] = round(dedup_p, 4)
            print(f"{label:<36} {k:>4} {row_p:>9.3f} {distinct:>9d} {dedup_p:>10.3f}")
        print(f"  ({len(rows)} rows, {n_components} components, id column: {id_col})")
        results.append(entry)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
