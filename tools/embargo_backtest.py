"""
tools/embargo_backtest.py
=========================
Label-embargo backtest for the official reporting configuration.

Motivation (praxis Section 4.4.3 caveat): six-month labels look forward, so
the labels of the final training months (roughly 2024-12 through 2025-04)
are determined by advisory events that also fall in the test outcome window.
A deployed model standing at the test prediction date could not have used
those labels, because they had not yet matured. This script measures how
much of the reported performance depends on that overlap.

No relabeling is needed. Labels are computed from advisory publication
dates, so for any observation month whose full six-month window closed
before an embargo date, the truncated advisory feed and the full feed
produce identical labels. Cutting the feed therefore reduces to dropping
the training rows whose labels were not yet mature — a training-cutoff
filter over the existing labeled dataset.

Three runs on identical test rows (observation months 2025-05 and 2025-06,
the official test set):

    full     train obs 2018-01 .. 2025-04   the official configuration,
                                            retrained here as a same-code-path
                                            reference point
    overlap  train obs 2018-01 .. 2024-11   drops only rows whose label
                                            windows overlap the test outcome
                                            window (2025-06 onward)
    embargo  train obs 2018-01 .. 2024-05   additionally requires every
                                            training label to have matured by
                                            2024-11-30 (the advisory-feed
                                            embargo date from the design
                                            notes) — what a model trained on
                                            2024-12-01 could have known

Comparing full vs overlap isolates the shared-outcome effect; overlap vs
embargo adds the stricter maturity requirement plus six fewer months of
data. Nothing in data/processed/models/ is touched; outputs go to
data/processed/results/embargo_backtest/.

A fourth, deployment-realistic run is available with --as-of YYYY-MM: keep
every training observation, but rebuild its label as it was knowable at
that date — 1 if an advisory fell in the observation's six-month window
AND was published in a month strictly before --as-of; 0 otherwise. A
recent observation whose window has not fully elapsed is labeled with what
is known so far (a censored "no advisory yet" counts as 0), which is
exactly what a deployed system retraining on that date would have. For the
official test set the natural choice is --as-of 2025-06: labels as known
on June 1, 2025, the prediction date of the first test month. Advisories
published during the test outcome window never enter training labels.
Labels are rebuilt positionally from advisory_count_this_month (the same
mechanism as canary.build.monthly_labels), and rows whose windows closed
before the as-of date are verified to reproduce their stored labels.

Uses the exact feature columns of the saved official model
(xgb_6m_advisory_swh_no_window_time/feature_columns.json), the same
registry estimator (xgboost), and the same imputation scheme as
canary.train.baseline (advisory_* zero-fill, all else median, medians fit
on each run's own training rows).

Usage
-----
    docker compose run --rm canary python tools/embargo_backtest.py

    # Custom cutoffs (last training month, inclusive), model dir, or paths
    python tools/embargo_backtest.py --cutoffs 2024-05 2024-11 \
        --model-dir data/processed/models/xgb_6m_advisory_swh_no_window_time

    # Deployment-realistic run: all training rows, labels as knowable June 1 2025
    python tools/embargo_backtest.py --skip-full --cutoffs --as-of 2025-06

Output
------
    Console comparison table (AP, ROC-AUC, row-level and deduplicated
    P@k) and data/processed/results/embargo_backtest/embargo_backtest.json,
    plus per-run test_predictions.csv files compatible with
    tools/dedup_precision.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import numpy as np  # noqa: E402  # pyright: ignore[reportMissingImports]
from sklearn.compose import (  # noqa: E402  # pyright: ignore[reportMissingModuleSource]
    ColumnTransformer,
)
from sklearn.impute import SimpleImputer  # noqa: E402  # pyright: ignore[reportMissingModuleSource]
from sklearn.metrics import (  # noqa: E402  # pyright: ignore[reportMissingModuleSource]
    average_precision_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline  # noqa: E402  # pyright: ignore[reportMissingModuleSource]

from canary.train.baseline import (  # noqa: E402
    _load_jsonl,
    _month_to_sortable,
    _parse_month_value,
    _rows_to_matrix,
    _write_predictions_csv,
)
from canary.train.registry import get_model  # noqa: E402

DEFAULT_MODEL_DIR = "data/processed/models/xgb_6m_advisory_swh_no_window_time"
DEFAULT_IN_PATH = "data/processed/features/plugins.monthly.labeled.advisory_swh.jsonl"
TARGET_COL = "label_advisory_within_6m"
TEST_START = "2025-05"
K_VALUES = (10, 25, 50, 100)
HORIZON_MONTHS = 6


def _advisory_this_month(row: dict[str, Any]) -> bool:
    """Same indicator resolution as canary.build.monthly_labels."""
    for key in ("had_advisory_this_month", "has_advisory_this_month", "advisory_this_month"):
        if key in row:
            return bool(row[key])
    if "advisory_count_this_month" in row:
        try:
            return int(row["advisory_count_this_month"]) > 0
        except (TypeError, ValueError):
            return False
    raise KeyError("Row is missing an advisory-this-month indicator; cannot relabel as-of.")


def _relabel_as_of(
    all_rows: list[dict[str, Any]],
    train_rows: list[dict[str, Any]],
    as_of: str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Rebuild each training row's label as it was knowable at *as_of*.

    Label = 1 if any of the observation's next-six calendar months both
    (a) contains an advisory and (b) is strictly before *as_of*; else 0
    (a censored not-yet-positive window counts as 0, as it would in
    deployment). Positional over the dense monthly grid, mirroring
    canary.build.monthly_labels. Returns relabeled copies of train_rows
    plus stats, and verifies that fully-matured windows reproduce their
    stored labels.
    """
    as_of_key = _month_to_sortable(as_of)
    by_plugin: dict[str, list[dict[str, Any]]] = {}
    for r in all_rows:
        by_plugin.setdefault(str(r.get("plugin_id") or ""), []).append(r)

    advisory_months: dict[str, set[tuple[int, int]]] = {}
    for pid, rows in by_plugin.items():
        advisory_months[pid] = {
            _month_to_sortable(_parse_month_value(r)) for r in rows if _advisory_this_month(r)
        }

    stats = {"flipped_1_to_0": 0, "matured_mismatch": 0, "relabeled_positive": 0}
    out: list[dict[str, Any]] = []
    for r in train_rows:
        pid = str(r.get("plugin_id") or "")
        window = [_month_to_sortable(_add_months(_parse_month_value(r), i)) for i in range(1, 7)]
        knowable = [w for w in window if w < as_of_key]
        label = int(any(w in advisory_months.get(pid, set()) for w in knowable))
        stored = r.get(TARGET_COL)
        if len(knowable) == 6 and stored is not None and int(stored) != label:
            stats["matured_mismatch"] += 1
        if stored is not None and int(stored) == 1 and label == 0:
            stats["flipped_1_to_0"] += 1
        if label == 1:
            stats["relabeled_positive"] += 1
        nr = dict(r)
        nr[TARGET_COL] = label
        out.append(nr)
    return out, stats


def _add_months(month: str, n: int) -> str:
    year, mon = _month_to_sortable(month)
    mon += n
    year += (mon - 1) // 12
    mon = ((mon - 1) % 12) + 1
    return f"{year:04d}-{mon:02d}"


def _precision_at_k(ranked_truth: list[int], k: int) -> float | None:
    if len(ranked_truth) < k:
        return None
    return sum(ranked_truth[:k]) / k


def _dedup_ranked_truth(
    rows: list[dict[str, Any]], y_true: np.ndarray, y_prob: np.ndarray
) -> list[int]:
    """One entry per plugin: its highest-scored test observation's truth.

    Same convention as tools/dedup_precision.py.
    """
    order = np.argsort(-y_prob, kind="stable")
    seen: set[str] = set()
    truths: list[int] = []
    for i in order:
        pid = str(rows[int(i)].get("plugin_id") or "")
        if pid in seen:
            continue
        seen.add(pid)
        truths.append(int(y_true[int(i)]))
    return truths


def _build_pipeline(feature_cols: list[str], estimator: Any) -> Pipeline:
    """Imputation exactly as canary.train.baseline.train_model."""
    advisory_cols = [c for c in feature_cols if c.startswith(("advisory_", "advisories_"))]
    other_cols = [c for c in feature_cols if not c.startswith(("advisory_", "advisories_"))]
    transformers = []
    if advisory_cols:
        zero_imputer = SimpleImputer(strategy="constant", fill_value=0.0)
        transformers.append(("impute_advisory_zero", zero_imputer, advisory_cols))
    if other_cols:
        transformers.append(("impute_median", SimpleImputer(strategy="median"), other_cols))
    imputer = ColumnTransformer(transformers=transformers, remainder="drop")
    return Pipeline(steps=[("impute", imputer), ("model", estimator)])


def _run_one(
    *,
    label: str,
    train_rows: list[dict[str, Any]],
    test_rows: list[dict[str, Any]],
    feature_cols: list[str],
    model_name: str,
    out_dir: Path,
) -> dict[str, Any]:
    X_train = _rows_to_matrix(train_rows, feature_cols)
    X_test = _rows_to_matrix(test_rows, feature_cols)
    y_train = np.array([int(r[TARGET_COL]) for r in train_rows], dtype=int)
    y_test = np.array([int(r[TARGET_COL]) for r in test_rows], dtype=int)

    pipeline = _build_pipeline(feature_cols, get_model(model_name))
    pipeline.fit(X_train, y_train)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    train_months = [_parse_month_value(r) for r in train_rows]
    row_order = np.argsort(-y_prob, kind="stable")
    row_truth = [int(y_test[int(i)]) for i in row_order]
    dedup_truth = _dedup_ranked_truth(test_rows, y_test, y_prob)

    result: dict[str, Any] = {
        "run": label,
        "model_name": model_name,
        "train_first_month": min(train_months),
        "train_last_month": max(train_months),
        "labels_mature_by": _add_months(max(train_months), HORIZON_MONTHS),
        "train_row_count": int(len(train_rows)),
        "train_positive_count": int(y_train.sum()),
        "test_row_count": int(len(test_rows)),
        "test_positive_count": int(y_test.sum()),
        "average_precision": float(average_precision_score(y_test, y_prob)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "precision_at_k_rows": {str(k): _precision_at_k(row_truth, k) for k in K_VALUES},
        "precision_at_k_dedup": {str(k): _precision_at_k(dedup_truth, k) for k in K_VALUES},
    }

    run_dir = out_dir / label
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_predictions_csv(
        path=run_dir / "test_predictions.csv", rows=test_rows, y_true=y_test, y_prob=y_prob
    )
    return result


def _sanity_check_test_rows(test_rows: list[dict[str, Any]], model_dir: Path) -> tuple[bool, str]:
    """Compare (plugin, month, y_true) against the saved official predictions."""
    import csv

    saved_path = model_dir / "test_predictions.csv"
    if not saved_path.exists():
        return False, f"no saved predictions at {saved_path} (skipping check)"
    saved: dict[tuple[str, str], int] = {}
    with saved_path.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            saved[(r["plugin_id"], r["month"])] = int(r["y_true"])
    ours = {
        (str(r.get("plugin_id") or ""), _parse_month_value(r)): int(r[TARGET_COL])
        for r in test_rows
    }
    if saved == ours:
        return True, f"test rows match saved official predictions ({len(ours):,} rows)"
    only_saved = len(set(saved) - set(ours))
    only_ours = len(set(ours) - set(saved))
    diff_truth = sum(1 for key in set(saved) & set(ours) if saved[key] != ours[key])
    return False, (
        f"MISMATCH vs saved official predictions: {only_saved} rows only in saved, "
        f"{only_ours} only in this run, {diff_truth} label disagreements"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--in-path", default=DEFAULT_IN_PATH, help="labeled dataset (jsonl)")
    parser.add_argument(
        "--model-dir",
        default=DEFAULT_MODEL_DIR,
        help="saved official model dir (feature_columns.json + reference predictions)",
    )
    parser.add_argument("--model", default="xgboost", help="registry model name")
    parser.add_argument("--test-start", default=TEST_START, help="first test month (YYYY-MM)")
    parser.add_argument(
        "--test-end",
        default=None,
        metavar="YYYY-MM",
        help="last test month, inclusive (default: all labeled months from --test-start on). "
        "Use with earlier --test-start/--cutoffs to repeat the protocol in an earlier era, "
        "e.g. --test-start 2024-05 --test-end 2024-06 --cutoffs 2023-11 2023-05",
    )
    parser.add_argument(
        "--cutoffs",
        nargs="*",
        default=["2024-11", "2024-05"],
        metavar="YYYY-MM",
        help="last training month (inclusive) for each embargoed run; pass with no values "
        "to skip the cutoff runs",
    )
    parser.add_argument(
        "--as-of",
        default=None,
        metavar="YYYY-MM",
        help="deployment-realistic run: keep ALL training observations, relabel each with "
        "what was knowable at this date (advisories in months strictly before it). "
        "For the official test set, 2025-06 = labels as known June 1, 2025.",
    )
    parser.add_argument(
        "--skip-full",
        action="store_true",
        help="skip the full-training reference run (use saved metrics instead)",
    )
    parser.add_argument(
        "--out-dir",
        default="data/processed/results/embargo_backtest",
        help="output directory (kept outside data/processed/models/)",
    )
    args = parser.parse_args()

    model_dir = Path(args.model_dir)
    feature_cols = json.loads((model_dir / "feature_columns.json").read_text(encoding="utf-8"))
    print(f"Feature columns: {len(feature_cols)} (from {model_dir.name})")

    print(f"Loading {args.in_path} …")
    rows = _load_jsonl(args.in_path)
    usable = [r for r in rows if r.get(TARGET_COL) is not None]
    usable.sort(
        key=lambda r: (_month_to_sortable(_parse_month_value(r)), str(r.get("plugin_id", "")))
    )
    print(f"Usable rows (non-null {TARGET_COL}): {len(usable):,}")

    test_start_key = _month_to_sortable(args.test_start)
    test_rows = [r for r in usable if _month_to_sortable(_parse_month_value(r)) >= test_start_key]
    if args.test_end:
        test_end_key = _month_to_sortable(args.test_end)
        test_rows = [
            r for r in test_rows if _month_to_sortable(_parse_month_value(r)) <= test_end_key
        ]
    all_train = [r for r in usable if _month_to_sortable(_parse_month_value(r)) < test_start_key]
    if not test_rows:
        print("No test rows in the requested window.")
        return 1

    if args.test_start == TEST_START and args.test_end in (None, "2025-06"):
        ok, msg = _sanity_check_test_rows(test_rows, model_dir)
        print(("OK: " if ok else "WARNING: ") + msg)
    else:
        msg = "skipped (non-default test window)"
        print(f"Sanity check vs saved official predictions: {msg}")
    test_months = sorted({_parse_month_value(r) for r in test_rows})
    print(f"Test window: {test_months[0]} .. {test_months[-1]} ({len(test_rows):,} rows)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []

    saved_metrics_path = model_dir / "metrics.json"
    saved_metrics = (
        json.loads(saved_metrics_path.read_text(encoding="utf-8"))
        if saved_metrics_path.exists()
        else {}
    )
    if saved_metrics:
        results.append(
            {
                "run": "official_saved",
                "model_name": saved_metrics.get("model_name"),
                "train_last_month": "2025-04",
                "train_row_count": saved_metrics.get("train_row_count"),
                "train_positive_count": saved_metrics.get("train_positive_count"),
                "average_precision": saved_metrics.get("average_precision"),
                "roc_auc": saved_metrics.get("roc_auc"),
                "precision_at_k_rows": {
                    str(k): saved_metrics.get("ranking_metrics", {}).get(f"precision_at_{k}")
                    for k in K_VALUES
                },
                "note": "read from saved metrics.json, not retrained",
            }
        )

    runs: list[tuple[str, list[dict[str, Any]]]] = []
    if not args.skip_full:
        runs.append(("full", all_train))
    for cutoff in sorted(args.cutoffs, reverse=True):
        cutoff_key = _month_to_sortable(cutoff)
        runs.append(
            (
                f"cutoff_{cutoff}",
                [r for r in all_train if _month_to_sortable(_parse_month_value(r)) <= cutoff_key],
            )
        )
    if args.as_of:
        relabeled, stats = _relabel_as_of(rows, all_train, args.as_of)
        print(
            f"\nAs-of {args.as_of} relabel: {stats['relabeled_positive']:,} positives "
            f"({stats['flipped_1_to_0']:,} stored positives not yet knowable, now 0)"
        )
        if stats["matured_mismatch"]:
            print(
                f"WARNING: {stats['matured_mismatch']} fully-matured rows disagree with "
                "stored labels — investigate before trusting this run."
            )
        runs.append((f"asof_{args.as_of}", relabeled))

    for label, train_rows in runs:
        if not train_rows:
            print(f"Skipping {label}: no training rows.")
            continue
        print(
            f"\nTraining run '{label}': {len(train_rows):,} rows "
            f"({_parse_month_value(train_rows[0])} .. {_parse_month_value(train_rows[-1])}) …"
        )
        result = _run_one(
            label=label,
            train_rows=train_rows,
            test_rows=test_rows,
            feature_cols=feature_cols,
            model_name=args.model,
            out_dir=out_dir,
        )
        results.append(result)
        print(
            f"  AP={result['average_precision']:.4f}  ROC={result['roc_auc']:.4f}  "
            f"dedup P@25={result['precision_at_k_dedup']['25']}"
        )

    # ── Comparison table ────────────────────────────────────────────────────
    def _fmt(v: Any, pct: bool = False) -> str:
        if v is None:
            return "   —"
        return f"{v * 100:5.1f}%" if pct else f"{v:.4f}"

    print("\n" + "=" * 100)
    header = (
        f"{'run':<18} {'train thru':>10} {'rows':>9} {'pos':>6} {'AP':>8} {'ROC':>8}"
        f" {'P@25 row':>9} {'P@25 dd':>8} {'P@50 dd':>8}"
    )
    print(header)
    print("-" * 100)
    for r in results:
        pk_rows = r.get("precision_at_k_rows") or {}
        pk_dd = r.get("precision_at_k_dedup") or {}
        print(
            f"{r['run']:<18} {r.get('train_last_month', '?'):>10} "
            f"{(r.get('train_row_count') or 0):>9,} {(r.get('train_positive_count') or 0):>6,} "
            f"{_fmt(r.get('average_precision')):>8} {_fmt(r.get('roc_auc')):>8} "
            f"{_fmt(pk_rows.get('25'), pct=True):>9} {_fmt(pk_dd.get('25'), pct=True):>8} "
            f"{_fmt(pk_dd.get('50'), pct=True):>8}"
        )
    print("=" * 100)

    payload = {
        "description": "Label-embargo backtest: official config retrained with "
        "training-month cutoffs; identical test rows.",
        "input_path": args.in_path,
        "model_dir": str(model_dir),
        "target_col": TARGET_COL,
        "test_start_month": args.test_start,
        "test_end_month": args.test_end,
        "test_row_sanity_check": msg,
        "runs": results,
    }
    out_json = out_dir / "embargo_backtest.json"
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"\nWrote {out_json}")
    print("Per-run predictions are compatible with tools/dedup_precision.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
