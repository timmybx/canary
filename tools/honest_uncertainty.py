"""
tools/honest_uncertainty.py
===========================
Uncertainty and calibration for the honest-layer results, from recorded
predictions only.

Nothing is retrained and no recorded number changes. For each rolling-backtest
run directory the tool concatenates every ``fold_*/test_predictions.csv``
(the pooled test set the praxis reports on) and computes:

Uncertainty
    A cluster bootstrap over plugins: plugins are resampled with replacement
    and every one of a resampled plugin's test rows comes with it, so the
    dependence between a plugin's months is respected. Each resample gives a
    pooled ROC-AUC, average precision and AP lift over the base rate; the
    2.5th and 97.5th percentiles over resamples are the 95% interval. The
    point estimate is the recorded pooled value (recomputed here and checked
    against ``rolling_backtest.json``).

Calibration
    Brier score, base-rate reference and Brier skill score (as in
    ``tools/brier_score.py``); expected calibration error (ECE) over
    quantile bins of the predicted score, so each bin holds the same number
    of rows; and the reliability table (per bin: mean predicted score,
    observed positive rate, count) that ``tools/make_figures.py
    --only honest_reliability`` draws.

ROC-AUC is computed by the rank statistic (Mann-Whitney U with tie
correction) and AP by the step-wise precision-recall integral, both in
NumPy, so the tool runs outside the container as well as inside it.

Usage
-----
    # the praxis runs (development champion, runner-up, baseline; the three
    # out-of-time runs), 2,000 resamples
    docker compose run --rm canary python tools/honest_uncertainty.py

    # any run directories
    python tools/honest_uncertainty.py \
        data/processed/results/rolling_backtest/oot_champion --resamples 5000

Output
------
    Console table per run; JSON at data/processed/results/honest_uncertainty.json
    (override with --json). Deterministic for a given --seed.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

ROLLING_ROOT = Path("data/processed/results/rolling_backtest")
DEFAULT_RUNS = [
    "ghclock_ghdyn_logistic",
    "ghclock_installs_xgb",
    "ghclock_only_logistic",
    "oot_champion",
    "oot_runnerup",
    "oot_ghclock_logistic",
]
OUT_JSON = Path("data/processed/results/honest_uncertainty.json")


# ---------------------------------------------------------------------------
# metrics (NumPy only)
# ---------------------------------------------------------------------------


def roc_auc(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> float:
    """ROC-AUC as the probability a random positive outranks a random negative
    (ties count one half), with optional row weights (used by the bootstrap,
    where a weight is how many times a plugin was drawn)."""
    if w is None:
        w = np.ones_like(y)
    uniq, inv = np.unique(s, return_inverse=True)
    pos_w = np.bincount(inv, weights=w * y, minlength=len(uniq))
    neg_w = np.bincount(inv, weights=w * (1 - y), minlength=len(uniq))
    total_pos, total_neg = pos_w.sum(), neg_w.sum()
    if total_pos == 0 or total_neg == 0:
        return float("nan")
    neg_below = np.cumsum(neg_w) - neg_w  # negatives with a strictly lower score
    u = float((pos_w * (neg_below + 0.5 * neg_w)).sum())
    return u / float(total_pos * total_neg)


def average_precision(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> float:
    """Average precision as the step-wise precision-recall integral with one
    step per distinct score (scikit-learn's definition, so tied scores are
    evaluated together), with optional row weights."""
    if w is None:
        w = np.ones_like(y)
    keep = w > 0
    y, s, w = y[keep], s[keep], w[keep]
    uniq, inv = np.unique(-s, return_inverse=True)  # groups in descending score order
    tp_g = np.bincount(inv, weights=w * y, minlength=len(uniq))
    n_g = np.bincount(inv, weights=w, minlength=len(uniq))
    total_pos = tp_g.sum()
    if total_pos == 0:
        return float("nan")
    precision = np.cumsum(tp_g) / np.cumsum(n_g)
    return float((precision * tp_g).sum() / total_pos)


def pooled_metrics(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> dict[str, float]:
    if w is None:
        w = np.ones_like(y)
    base = float((w * y).sum() / w.sum())
    ap = average_precision(y, s, w)
    return {
        "roc_auc": roc_auc(y, s, w),
        "average_precision": ap,
        "ap_lift_over_base_rate": ap / base if base > 0 else float("nan"),
        "base_rate": base,
    }


def calibration(y: np.ndarray, s: np.ndarray, n_bins: int = 10) -> dict:
    base = float(y.mean())
    brier = float(np.mean((s - y) ** 2))
    brier_ref = float(np.mean((base - y) ** 2))
    skill = 1.0 - brier / brier_ref if brier_ref > 0 else float("nan")
    # quantile bins on the score: equal-count bins, so the rare positives are
    # not all crowded into one sparse upper bin
    edges = np.quantile(s, np.linspace(0, 1, n_bins + 1))
    edges[0], edges[-1] = -np.inf, np.inf
    idx = np.clip(np.searchsorted(edges, s, side="right") - 1, 0, n_bins - 1)
    bins = []
    ece = 0.0
    for b in range(n_bins):
        m = idx == b
        if not m.any():
            continue
        mean_pred = float(s[m].mean())
        obs = float(y[m].mean())
        count = int(m.sum())
        ece += abs(mean_pred - obs) * count / len(y)
        bins.append(
            {
                "bin": b,
                "score_low": float(s[m].min()),
                "score_high": float(s[m].max()),
                "mean_predicted": mean_pred,
                "observed_rate": obs,
                "count": count,
                "positives": int(y[m].sum()),
            }
        )
    return {
        "brier": brier,
        "brier_base_rate_reference": brier_ref,
        "brier_skill_score": skill,
        "ece_quantile_bins": float(ece),
        "n_bins": n_bins,
        "mean_predicted": float(s.mean()),
        "observed_rate": base,
        "reliability_bins": bins,
    }


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------


def load_pooled(run_dir: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, list[str]]:
    plugins: list[str] = []
    ys: list[int] = []
    ss: list[float] = []
    folds = sorted(p for p in run_dir.glob("fold_*") if p.is_dir())
    if not folds:
        raise FileNotFoundError(f"no fold_* directories under {run_dir}")
    for fold in folds:
        path = fold / "test_predictions.csv"
        with path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                plugins.append(row["plugin_id"])
                ys.append(int(float(row["y_true"])))
                ss.append(float(row["y_prob"]))
    uniq, inv = np.unique(np.array(plugins), return_inverse=True)
    return np.array(ys, dtype=float), np.array(ss, dtype=float), inv, [f.name for f in folds]


def recorded_pooled(run_dir: Path) -> dict | None:
    path = run_dir / "rolling_backtest.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("pooled") or data.get("pooled_metrics")


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------


def cluster_bootstrap(
    y: np.ndarray,
    s: np.ndarray,
    cluster: np.ndarray,
    resamples: int,
    seed: int,
) -> dict[str, dict[str, float]]:
    """Resample plugins with replacement. A plugin drawn k times contributes
    every one of its rows with weight k, which is the same as duplicating the
    rows k times. Returns percentile intervals per metric."""
    rng = np.random.default_rng(seed)
    n_clusters = int(cluster.max()) + 1
    draws: dict[str, list[float]] = {
        "roc_auc": [],
        "average_precision": [],
        "ap_lift_over_base_rate": [],
    }
    for _ in range(resamples):
        chosen = rng.integers(0, n_clusters, size=n_clusters)
        counts = np.bincount(chosen, minlength=n_clusters).astype(float)
        w = counts[cluster]
        if (w * y).sum() == 0 or (w * (1 - y)).sum() == 0:
            continue
        m = pooled_metrics(y, s, w)
        for k in draws:
            draws[k].append(m[k])
    out = {}
    for k, v in draws.items():
        arr = np.array(v)
        out[k] = {
            "ci95_low": float(np.percentile(arr, 2.5)),
            "ci95_high": float(np.percentile(arr, 97.5)),
            "bootstrap_mean": float(arr.mean()),
            "bootstrap_sd": float(arr.std(ddof=1)),
            "n_resamples": int(len(arr)),
        }
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def analyse(run_dir: Path, resamples: int, seed: int, n_bins: int) -> dict:
    y, s, cluster, folds = load_pooled(run_dir)
    point = pooled_metrics(y, s)
    rec = recorded_pooled(run_dir)
    check = None
    if rec:
        check = {
            k: {
                "recorded": float(rec[k]),
                "recomputed": point[k],
                "abs_diff": abs(float(rec[k]) - point[k]),
            }
            for k in ("roc_auc", "average_precision")
            if k in rec
        }
    boot = cluster_bootstrap(y, s, cluster, resamples, seed)
    cal = calibration(y, s, n_bins)
    return {
        "run": run_dir.name,
        "folds": folds,
        "n_rows": int(len(y)),
        "n_positive": int(y.sum()),
        "n_plugins": int(cluster.max()) + 1,
        "point": point,
        "recorded_check": check,
        "bootstrap": boot,
        "calibration": cal,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[3])
    ap.add_argument(
        "runs", nargs="*", help="rolling-backtest run directories (default: the praxis runs)"
    )
    ap.add_argument("--rolling-root", default=str(ROLLING_ROOT))
    ap.add_argument("--resamples", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--bins", type=int, default=10, help="quantile bins for ECE and the reliability table"
    )
    ap.add_argument("--json", default=str(OUT_JSON))
    args = ap.parse_args()

    root = Path(args.rolling_root)
    run_dirs = [Path(r) if Path(r).exists() else root / r for r in (args.runs or DEFAULT_RUNS)]
    results = []
    header = (
        f"{'run':28s} {'rows':>7s} {'pos':>5s} {'ROC':>6s} {'95% CI':>15s} {'AP':>7s} "
        f"{'lift':>6s} {'95% CI':>13s} {'Brier skill':>11s} {'ECE':>7s}"
    )
    print(header)
    for d in run_dirs:
        try:
            r = analyse(d, args.resamples, args.seed, args.bins)
        except FileNotFoundError as exc:
            print(f"SKIP {d.name}: {exc}")
            continue
        results.append(r)
        b = r["bootstrap"]
        p = r["point"]
        c = r["calibration"]
        roc_ci = b["roc_auc"]
        lift_ci = b["ap_lift_over_base_rate"]
        print(
            f"{r['run']:28s} {r['n_rows']:7d} {r['n_positive']:5d} "
            f"{p['roc_auc']:6.3f} [{roc_ci['ci95_low']:.3f}, {roc_ci['ci95_high']:.3f}] "
            f"{p['average_precision']:7.4f} {p['ap_lift_over_base_rate']:6.2f} "
            f"[{lift_ci['ci95_low']:.2f}, {lift_ci['ci95_high']:.2f}] "
            f"{c['brier_skill_score']:11.4f} {c['ece_quantile_bins']:7.4f}"
        )
        if r["recorded_check"]:
            worst = max(v["abs_diff"] for v in r["recorded_check"].values())
            if worst > 1e-6:
                print(
                    "  WARNING: recomputed pooled metrics differ from "
                    f"rolling_backtest.json by up to {worst:.2e}"
                )
    out = Path(args.json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"resamples": args.resamples, "seed": args.seed, "bins": args.bins, "runs": results},
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
