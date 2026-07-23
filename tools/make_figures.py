"""
tools/make_figures.py
======================
Generate praxis/defense figures from saved pipeline artifacts.

No retraining and no new experiments: every figure is derived from files the
pipeline and analysis tools have already written. Requires matplotlib (dev
dependency).

Figures
-------
    h1_forest.png          Odds ratios with 95% CIs for the H1 marginal test
                           (from data/processed/results/h1_odds.json)
    precision_coverage.png Component-level precision and coverage vs review
                           size k (from <model>/test_predictions.csv)
    h3_retention.png       Average precision vs feature subset size
                           (from <model>/feature_selection.json)
    calibration.png        Reliability diagram of predicted probabilities
                           (from <model>/test_predictions.csv)
    shap_importance.png    Top features by mean |SHAP|
                           (from <model>/feature_selection.json)

Usage
-----
    # inside the container (all figures)
    python tools/make_figures.py

    # a subset, custom output directory
    python tools/make_figures.py --only h1_forest h3_retention --out-dir /tmp/figs

Defaults follow the praxis: the precision/coverage and calibration figures use
the Advisory+SWH time-split model (Table 4-4); the H3 retention figure uses the
full no-window model (Section 4.6); SHAP importance uses the full cleaned model.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib  # pyright: ignore[reportMissingImports]

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # pyright: ignore[reportMissingImports]  # noqa: E402

H1_JSON = "data/processed/results/h1_odds.json"
SIMPSON_JSON = "data/processed/results/simpson_stratified.json"
PC_MODEL = "data/processed/models/xgb_6m_advisory_swh_time"
H3_MODEL = "data/processed/models/xgb_6m_full_no_time_time"
SHAP_MODEL = "data/processed/models/xgb_6m_full_cleaned_time"
OUT_DIR = "data/processed/figures"
K_MARKS = (10, 25, 50, 100)

FACTOR_LABELS = {
    "releases": "Releases stale\n(>= 12 months)",
    "team": "Small team\n(<= 2 humans, 6 mo)",
    "either": "Either\n(H1 disjunction)",
    "commits": "Commits stale\n(>= 365 days)",
}


def _dedup_ranking(model_dir: str | Path) -> list[bool]:
    """Component-level ranking: per-plugin best row, ordered by probability."""
    rows: list[tuple[str, float, bool]] = []
    with (Path(model_dir) / "test_predictions.csv").open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["plugin_id"], float(r["y_prob"]), int(r["y_true"]) == 1))
    rows.sort(key=lambda x: (-x[1], x[0]))
    seen: set[str] = set()
    labels: list[bool] = []
    for pid, _, y in rows:
        if pid not in seen:
            seen.add(pid)
            labels.append(y)
    return labels


def fig_h1_forest(out: Path, h1_json: str) -> None:
    entries = [e for e in json.loads(Path(h1_json).read_text()) if e.get("window") == "train"]
    names, ors, lows, highs = [], [], [], []
    for e in entries:
        key = next((k for k in FACTOR_LABELS if e["factor"].startswith(k)), None)
        if key is None or "odds_ratio" not in e:
            continue
        names.append(FACTOR_LABELS[key])
        ors.append(e["odds_ratio"])
        lows.append(e["ci_low"])
        highs.append(e["ci_high"])
    ys = range(len(names))[::-1]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    for y, o, lo, hi in zip(ys, ors, lows, highs, strict=True):
        ax.plot([lo, hi], [y, y], color="#1f4e79", linewidth=2)
        ax.plot(o, y, "o", color="#1f4e79", markersize=7)
        ax.annotate(
            f"{o:.2f}", (o, y), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=9
        )
    ax.axvline(1.0, color="gray", linewidth=1, label="No association (OR = 1.0)")
    ax.axvline(
        1.5, color="#c00000", linewidth=1.2, linestyle="--", label="H1 criterion (OR >= 1.5)"
    )
    ax.set_xscale("log")
    ax.set_xticks([0.25, 0.5, 1.0, 1.5, 2.0])
    ax.set_xticklabels(["0.25", "0.5", "1.0", "1.5", "2.0"])
    ax.minorticks_off()
    ax.set_ylim(-0.6, len(names) - 0.2)
    ax.legend(loc="lower right", fontsize=8, framealpha=1.0)
    ax.set_yticks(list(ys))
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Odds ratio for advisory within 6 months (log scale, train window)")
    ax.set_title("H1 marginal test: every factor is significantly below 1.0")
    fig.tight_layout()
    fig.savefig(out / "h1_forest.png")
    plt.close(fig)


def fig_precision_coverage(out: Path, model_dir: str) -> None:
    labels = _dedup_ranking(model_dir)
    total_pos = sum(labels)
    kmax = max(K_MARKS) + 25
    ks = range(1, min(kmax, len(labels)) + 1)
    cum = 0
    prec, cov = [], []
    for k in ks:
        cum += labels[k - 1]
        prec.append(cum / k)
        cov.append(cum / total_pos if total_pos else 0.0)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(list(ks), prec, color="#1f4e79", linewidth=2, label="Precision@k")
    ax.plot(list(ks), cov, color="#c55a11", linewidth=2, label="Coverage of advisory plugins")
    for km in K_MARKS:
        if km <= len(labels):
            ax.axvline(km, color="gray", linewidth=0.6, linestyle=":")
            ax.annotate(
                f"k={km}\nP={prec[km - 1]:.2f}\ncov={cov[km - 1]:.0%}",
                (km, prec[km - 1]),
                textcoords="offset points",
                xytext=(6, 10),
                fontsize=8,
            )
    ax.set_xlabel("Review size k (distinct plugins)")
    ax.set_ylabel("Proportion")
    ax.set_ylim(0, 1.18)
    ax.set_title(f"Precision/coverage tradeoff, component level ({Path(model_dir).name})")
    ax.legend(loc="lower center", fontsize=9, framealpha=1.0)
    fig.tight_layout()
    fig.savefig(out / "precision_coverage.png")
    plt.close(fig)


def fig_h3_retention(out: Path, model_dir: str) -> None:
    j = json.loads((Path(model_dir) / "feature_selection.json").read_text())
    full_ap = j["full_model_average_precision"]
    sizes, aps = [], []
    for s in j.get("subset_results", []):
        size = s.get("actual_feature_count") or s.get("requested_size")
        ap = s.get("average_precision")
        if size is not None and ap is not None:
            sizes.append(int(size))
            aps.append(float(ap))
    order = sorted(range(len(sizes)), key=lambda i: sizes[i])
    sizes = [sizes[i] for i in order]
    aps = [aps[i] for i in order]
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(sizes, aps, "o-", color="#1f4e79", linewidth=2)
    ax.axhline(
        full_ap,
        color="gray",
        linewidth=1,
        label=f"Full model ({j['full_model_feature_count']} features), AP {full_ap:.3f}",
    )
    ax.axhline(
        0.9 * full_ap,
        color="#c00000",
        linewidth=1.2,
        linestyle="--",
        label="H3 criterion (90% of full model)",
    )
    for x, y in zip(sizes, aps, strict=True):
        ax.annotate(
            f"{y / full_ap:.0%}",
            (x, y),
            textcoords="offset points",
            xytext=(0, 9),
            ha="center",
            fontsize=8,
        )
    ax.set_xlabel("Feature subset size (top-n by mean |SHAP|)")
    ax.set_ylabel("Average precision on future data")
    ax.set_title(f"H3: retention vs subset size ({Path(model_dir).name})")
    ax.legend(loc="lower right", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "h3_retention.png")
    plt.close(fig)


def fig_calibration(out: Path, model_dir: str, n_bins: int = 10) -> None:
    probs, ys = [], []
    with (Path(model_dir) / "test_predictions.csv").open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            probs.append(float(r["y_prob"]))
            ys.append(int(r["y_true"]))
    bins: list[list[int]] = [[0, 0] for _ in range(n_bins)]  # [count, positives]
    sums = [0.0] * n_bins
    for p, y in zip(probs, ys, strict=True):
        b = min(int(p * n_bins), n_bins - 1)
        bins[b][0] += 1
        bins[b][1] += y
        sums[b] += p
    xs, obs, counts = [], [], []
    for b in range(n_bins):
        if bins[b][0]:
            xs.append(sums[b] / bins[b][0])
            obs.append(bins[b][1] / bins[b][0])
            counts.append(bins[b][0])
    fig, ax = plt.subplots(figsize=(5.6, 5.2))
    ax.plot([0, 1], [0, 1], color="gray", linewidth=1, linestyle="--", label="Perfect calibration")
    ax.plot(xs, obs, "o-", color="#1f4e79", linewidth=1.5, label="Model")
    for x, o, c in zip(xs, obs, counts, strict=True):
        ax.annotate(
            f"n={c}", (x, o), textcoords="offset points", xytext=(6, -10), fontsize=7, color="gray"
        )
    ax.set_xlabel("Mean predicted probability (bin)")
    ax.set_ylabel("Observed advisory frequency")
    ax.set_title(f"Reliability diagram ({Path(model_dir).name})")
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "calibration.png")
    plt.close(fig)


def fig_shap_importance(out: Path, model_dir: str, top_n: int = 15) -> None:
    j = json.loads((Path(model_dir) / "feature_selection.json").read_text())
    ranking = j.get("feature_ranking", [])[:top_n]
    names = [e["feature"] for e in ranking][::-1]
    vals = [e["mean_abs_shap"] for e in ranking][::-1]
    fig, ax = plt.subplots(figsize=(7, 0.32 * top_n + 1.4))
    ax.barh(range(len(names)), vals, color="#1f4e79")
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlabel("Mean |SHAP| (global importance)")
    ax.set_title(f"Top {top_n} features by SHAP importance ({Path(model_dir).name})")
    fig.tight_layout()
    fig.savefig(out / "shap_importance.png")
    plt.close(fig)


STRATUM_TITLES = {
    "none": "No observed activity",
    "lower": "Lower activity",
    "higher": "Higher activity",
    "pooled": "All pooled",
}


def fig_simpson(out: Path, simpson_json: str) -> None:
    j = json.loads(Path(simpson_json).read_text())
    groups = [*j["strata"], j["pooled"]]
    groups = [g for g in groups if "error" not in g]
    xs = list(range(len(groups)))
    xs = [x + (0.6 if groups[i]["stratum"] == "pooled" else 0.0) for i, x in enumerate(xs)]
    width = 0.36
    fig, ax = plt.subplots(figsize=(7.4, 4.4))
    for i, (x, g) in enumerate(zip(xs, groups, strict=True)):
        fresh = g["unexposed_rate"]
        stale = g["exposed_rate"]
        ax.bar(
            x - width / 2,
            fresh,
            width,
            color="#0F6E56",
            label="Recently maintained" if i == 0 else None,
        )
        ax.bar(x + width / 2, stale, width, color="#D85A30", label="Stale" if i == 0 else None)
        for dx, v in ((-width / 2, fresh), (width / 2, stale)):
            ax.annotate(
                f"{v:.2%}",
                (x + dx, v),
                textcoords="offset points",
                xytext=(0, 3),
                ha="center",
                fontsize=8,
            )
        rr = g.get("rate_ratio")
        if rr is not None:
            ax.annotate(
                f"stale/fresh = {rr:g}x",
                (x, max(fresh, stale)),
                textcoords="offset points",
                xytext=(0, 16),
                ha="center",
                fontsize=9,
                fontweight="bold",
                color="#993C1D" if rr > 1 else "#185FA5",
            )
    if any(g["stratum"] == "pooled" for g in groups):
        ax.axvline(xs[-1] - 0.85, color="gray", linewidth=0.8, linestyle="--")
    ax.set_xticks(xs)
    ax.set_xticklabels(
        [f"{STRATUM_TITLES.get(g['stratum'], g['stratum'])}\nn = {g['n']:,}" for g in groups],
        fontsize=9,
    )
    ax.set_ylabel("Advisory rate (6 month window)")
    ymax = max(max(g["unexposed_rate"], g["exposed_rate"]) for g in groups)
    ax.set_ylim(0, ymax * 1.35)
    ax.set_title(f"Staleness vs advisory rate by attention stratum ({j['window']} window)")
    ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "simpson.png")
    plt.close(fig)


FIGURES = {
    "simpson": lambda out, a: fig_simpson(out, a.simpson_json),
    "h1_forest": lambda out, a: fig_h1_forest(out, a.h1_json),
    "precision_coverage": lambda out, a: fig_precision_coverage(out, a.pc_model),
    "h3_retention": lambda out, a: fig_h3_retention(out, a.h3_model),
    "calibration": lambda out, a: fig_calibration(out, a.pc_model),
    "shap_importance": lambda out, a: fig_shap_importance(out, a.shap_model),
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate praxis figures from saved artifacts.")
    parser.add_argument("--out-dir", default=OUT_DIR)
    parser.add_argument("--h1-json", default=H1_JSON)
    parser.add_argument("--simpson-json", default=SIMPSON_JSON)
    parser.add_argument(
        "--pc-model", default=PC_MODEL, help="model dir for precision/coverage and calibration"
    )
    parser.add_argument("--h3-model", default=H3_MODEL, help="model dir for the H3 retention curve")
    parser.add_argument(
        "--shap-model", default=SHAP_MODEL, help="model dir for the SHAP importance chart"
    )
    parser.add_argument("--dpi", type=int, default=300)
    parser.add_argument("--only", nargs="+", choices=sorted(FIGURES), default=None)
    args = parser.parse_args()

    plt.rcParams["savefig.dpi"] = args.dpi
    plt.rcParams["font.size"] = 10
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    wanted = args.only or sorted(FIGURES)
    for name in wanted:
        try:
            FIGURES[name](out, args)
            print(f"wrote {out / name}.png")
        except FileNotFoundError as exc:
            print(f"SKIP {name}: missing input ({exc})")


if __name__ == "__main__":
    main()
