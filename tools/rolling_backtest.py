"""
tools/rolling_backtest.py
=========================
Rolling-origin (expanding-window) backtest with the label embargo applied
at every fold.

Why
---
The official evaluation scores one two-month window (observation months
2025-05 and 2025-06: 4,106 rows, 77 positives). Any honest number measured
there carries a wide confidence interval, and iterating features or
hyperparameters against that single window invites overfitting to its
77 positives. A rolling backtest re-runs the same protocol at many
cutoffs — train on everything before month t, score a fixed-width window
starting at t, slide t forward — so a claim like "ROC-AUC 0.6 under the
honest protocol" rests on hundreds of positives across several eras
rather than one.

Each fold is a plain `canary.train.baseline.train_model` call with
    test_start_month  = t
    test_end_month    = t + test_months - 1
    label_as_of_month = t + 1        (deployment-realistic embargo; the
                                      month after the fold's test start —
                                      advisories through month t are known
                                      on t's scoring date and never enter a
                                      test label window)
unless --no-embargo is given, in which case the fold trains on the stored
(leaky) labels — useful for a side-by-side "leaky vs honest" curve.

Folds are not independent (training sets nest, and with --step smaller
than --test-months the test windows overlap), so the across-fold CI is
descriptive, not a formal test. When test windows do NOT overlap
(--step >= --test-months) the tool also pools every fold's test
predictions and reports pooled AP / ROC-AUC, which is the single most
defensible summary number.

Usage
-----
    docker compose run --rm canary python tools/rolling_backtest.py \\
        --in-path data/processed/features/plugins.monthly.labeled.advisory_only.jsonl \\
        --model xgboost --start 2023-05 --end 2025-05 --step 2 --test-months 2

    # Same folds without the embargo, for comparison
    docker compose run --rm canary python tools/rolling_backtest.py ... --no-embargo \\
        --out-dir data/processed/results/rolling_backtest/advisory_only_xgb_leaky

Output
------
    <out-dir>/fold_<YYYY-MM>/        the usual train_model artifacts per fold
    <out-dir>/rolling_backtest.json  per-fold metrics + summary (mean, sd,
                                     descriptive 95% CI, min/max, pooled
                                     metrics when windows do not overlap)
    Console table of the same.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sklearn.base import clone  # noqa: E402  # pyright: ignore[reportMissingModuleSource]
from sklearn.metrics import (  # noqa: E402  # pyright: ignore[reportMissingModuleSource]
    average_precision_score,
    roc_auc_score,
)

from canary.train.baseline import (  # noqa: E402
    _add_months,
    _load_jsonl,
    _validate_month,
    deployment_as_of_month,
    train_model,
)
from canary.train.registry import get_model  # noqa: E402

DEFAULT_IN_PATH = "data/processed/features/plugins.monthly.labeled.advisory_swh.jsonl"
DEFAULT_OUT_DIR = "data/processed/results/rolling_backtest"
TARGET_COL = "label_advisory_within_6m"


def _fmt_month(key: tuple[int, int]) -> str:
    return f"{key[0]:04d}-{key[1]:02d}"


def fold_months(start: str, end: str, step: int) -> list[str]:
    """Test-start months from *start* through *end* (inclusive) every *step* months."""
    if step < 1:
        raise ValueError("step must be >= 1")
    cur = _validate_month(start, name="start")
    end_key = _validate_month(end, name="end")
    if cur > end_key:
        raise ValueError(f"start {start!r} is after end {end!r}")
    out: list[str] = []
    while cur <= end_key:
        out.append(_fmt_month(cur))
        cur = _add_months(cur, step)
    return out


def _mean_sd(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, None
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    return mean, math.sqrt(var)


def summarize(fold_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Across-fold summary for the metrics train_model reports per fold."""
    summary: dict[str, Any] = {"fold_count": len(fold_results)}
    for key in ("roc_auc", "average_precision", "ap_lift_over_base_rate", "precision_at_25"):
        values = [float(r[key]) for r in fold_results if r.get(key) is not None]
        mean, sd = _mean_sd(values)
        entry: dict[str, Any] = {
            "n": len(values),
            "mean": mean,
            "sd": sd,
            "min": min(values) if values else None,
            "max": max(values) if values else None,
        }
        if mean is not None and sd is not None and len(values) >= 2:
            half = 1.96 * sd / math.sqrt(len(values))
            entry["ci95_descriptive"] = [mean - half, mean + half]
        summary[key] = entry
    summary["total_test_positives"] = sum(int(r["test_positive_count"]) for r in fold_results)
    summary["total_test_rows"] = sum(int(r["test_row_count"]) for r in fold_results)
    return summary


def _read_predictions(path: Path) -> tuple[list[int], list[float]]:
    y_true: list[int] = []
    y_prob: list[float] = []
    with path.open("r", encoding="utf-8", newline="") as f:
        for rec in csv.DictReader(f):
            y_true.append(int(rec["y_true"]))
            y_prob.append(float(rec["y_prob"]))
    return y_true, y_prob


def pooled_metrics(fold_dirs: list[Path]) -> dict[str, Any] | None:
    """AP / ROC-AUC over the concatenation of every fold's test predictions."""
    y_true: list[int] = []
    y_prob: list[float] = []
    for fold_dir in fold_dirs:
        t, p = _read_predictions(fold_dir / "test_predictions.csv")
        y_true.extend(t)
        y_prob.extend(p)
    if not y_true or len(set(y_true)) < 2:
        return None
    n_pos = sum(y_true)
    base_rate = n_pos / len(y_true)
    ap = float(average_precision_score(y_true, y_prob))
    return {
        "n_rows": len(y_true),
        "n_positive": n_pos,
        "base_rate": base_rate,
        "average_precision": ap,
        "ap_lift_over_base_rate": ap / base_rate if base_rate > 0 else None,
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
    }


def run_rolling_backtest(
    *,
    in_path: str | Path,
    model_name: str,
    out_dir: str | Path,
    start: str,
    end: str,
    step: int = 1,
    test_months: int = 2,
    target_col: str = TARGET_COL,
    embargo: bool = True,
    split_strategy: str = "time",
    include_window_features: bool = False,
    include_prefixes: tuple[str, ...] | None = None,
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
    rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run every fold and write <out_dir>/rolling_backtest.json. Returns its content."""
    if test_months < 1:
        raise ValueError("test_months must be >= 1")
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if rows is None:
        rows = _load_jsonl(in_path)

    folds = fold_months(start, end, step)
    fold_results: list[dict[str, Any]] = []
    fold_dirs: list[Path] = []
    for test_start in folds:
        start_key = _validate_month(test_start, name="fold")
        test_end = _fmt_month(_add_months(start_key, test_months - 1))
        as_of = deployment_as_of_month(test_start) if embargo else None
        fold_dir = out_path / f"fold_{test_start}"

        # Fresh estimator per fold: registry entries are shared module-level
        # objects and Pipeline.fit() fits them in place.
        metrics = train_model(
            estimator=clone(get_model(model_name)),  # pyright: ignore[reportArgumentType]
            model_name=model_name,
            in_path=in_path,
            target_col=target_col,
            out_dir=fold_dir,
            test_start_month=test_start,
            test_end_month=test_end,
            label_as_of_month=as_of,
            include_prefixes=include_prefixes,
            include_window_features=include_window_features,
            split_strategy=split_strategy,
            group_col=group_col,
            test_fraction=test_fraction,
            random_seed=random_seed,
            rows=rows,
        )
        n_test = int(metrics["test_row_count"])
        n_pos = int(metrics["test_positive_count"])
        base_rate = n_pos / n_test if n_test else 0.0
        ap = metrics.get("average_precision")
        lift = (ap / base_rate) if ap is not None and base_rate else None
        fold_results.append(
            {
                "test_start_month": test_start,
                "test_end_month": test_end,
                "label_as_of_month": as_of,
                "train_row_count": metrics["train_row_count"],
                "train_positive_count": metrics["train_positive_count"],
                "test_row_count": n_test,
                "test_positive_count": n_pos,
                "base_rate": base_rate,
                "roc_auc": metrics.get("roc_auc"),
                "average_precision": ap,
                "ap_lift_over_base_rate": lift,
                "precision_at_25": metrics.get("ranking_metrics", {}).get("precision_at_25"),
                "label_as_of_stats": metrics.get("label_as_of_stats"),
                "out_dir": str(fold_dir),
            }
        )
        fold_dirs.append(fold_dir)
        _print_fold(fold_results[-1])

    windows_overlap = step < test_months
    result: dict[str, Any] = {
        "in_path": str(in_path),
        "model_name": model_name,
        "target_col": target_col,
        "split_strategy": split_strategy,
        "embargo": embargo,
        "start": start,
        "end": end,
        "step_months": step,
        "test_months": test_months,
        "include_window_features": include_window_features,
        "include_prefixes": list(include_prefixes) if include_prefixes else None,
        "folds": fold_results,
        "summary": summarize(fold_results),
        "test_windows_overlap": windows_overlap,
        "pooled": None if windows_overlap else pooled_metrics(fold_dirs),
    }
    (out_path / "rolling_backtest.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    _print_summary(result)
    return result


def _fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.{digits}f}"


def _print_fold(r: dict[str, Any]) -> None:
    print(
        f"  fold {r['test_start_month']}..{r['test_end_month']}"
        f"  as-of {r['label_as_of_month'] or '-'}"
        f"  pos {r['test_positive_count']}/{r['test_row_count']}"
        f"  AP {_fmt(r['average_precision'])}"
        f"  (x{_fmt(r['ap_lift_over_base_rate'], 1)} base)"
        f"  ROC {_fmt(r['roc_auc'], 3)}"
        f"  P@25 {_fmt(r['precision_at_25'], 2)}"
    )


def _print_summary(result: dict[str, Any]) -> None:
    s = result["summary"]
    label = "embargoed" if result["embargo"] else "stored (leaky) labels"
    print()
    prefixes = result.get("include_prefixes")
    prefix_note = f" — features: {','.join(prefixes)}" if prefixes else ""
    print(
        f"Rolling backtest — {result['model_name']} — {label} — "
        f"{s['fold_count']} folds{prefix_note}"
    )
    print(f"  total test rows {s['total_test_rows']:,}, positives {s['total_test_positives']:,}")
    for key, name in (
        ("roc_auc", "ROC-AUC"),
        ("average_precision", "AP"),
        ("ap_lift_over_base_rate", "AP lift"),
        ("precision_at_25", "P@25"),
    ):
        e = s[key]
        ci = e.get("ci95_descriptive")
        ci_s = f"  CI95 [{_fmt(ci[0])}, {_fmt(ci[1])}]" if ci else ""
        print(
            f"  {name:<8} mean {_fmt(e['mean'])}  sd {_fmt(e['sd'])}"
            f"  min {_fmt(e['min'])}  max {_fmt(e['max'])}{ci_s}"
        )
    pooled = result.get("pooled")
    if pooled:
        print(
            f"  pooled   AP {_fmt(pooled['average_precision'])}"
            f" (x{_fmt(pooled['ap_lift_over_base_rate'], 1)} base rate"
            f" {_fmt(pooled['base_rate'])})  ROC-AUC {_fmt(pooled['roc_auc'], 3)}"
            f"  over {pooled['n_rows']:,} rows / {pooled['n_positive']:,} positives"
        )
    elif result["test_windows_overlap"]:
        print("  pooled   skipped (test windows overlap; use --step >= --test-months)")


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--in-path", default=DEFAULT_IN_PATH, help="labeled dataset (jsonl)")
    parser.add_argument("--model", default="xgboost", help="registry model name")
    parser.add_argument("--target-col", default=TARGET_COL)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--start", required=True, metavar="YYYY-MM", help="first fold test start")
    parser.add_argument("--end", required=True, metavar="YYYY-MM", help="last fold test start")
    parser.add_argument("--step", type=int, default=1, help="months between fold starts")
    parser.add_argument("--test-months", type=int, default=2, help="test window width (months)")
    parser.add_argument(
        "--no-embargo",
        action="store_true",
        help="train each fold on the stored labels (leaky) instead of as-of relabeled ones",
    )
    parser.add_argument("--split-strategy", choices=["time", "group_time"], default="time")
    parser.add_argument("--include-window-features", action="store_true")
    parser.add_argument("--include-prefixes", default="")
    parser.add_argument("--group-col", default="plugin_id")
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--random-seed", type=int, default=42)
    args = parser.parse_args()

    include_prefixes: tuple[str, ...] | None = None
    if args.include_prefixes:
        include_prefixes = tuple(p.strip() for p in args.include_prefixes.split(",") if p.strip())

    run_rolling_backtest(
        in_path=args.in_path,
        model_name=args.model,
        out_dir=args.out_dir,
        start=args.start,
        end=args.end,
        step=args.step,
        test_months=args.test_months,
        target_col=args.target_col,
        embargo=not args.no_embargo,
        split_strategy=args.split_strategy,
        include_window_features=args.include_window_features,
        include_prefixes=include_prefixes,
        group_col=args.group_col,
        test_fraction=args.test_fraction,
        random_seed=args.random_seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
