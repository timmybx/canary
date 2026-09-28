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
    fold_timeline.png      Per fold ROC-AUC of the declared configurations across
                           the embargoed development folds and the pre registered
                           holdout folds (from <run>/rolling_backtest.json)
    honest_shap.png        Mean |SHAP| per feature over the embargoed folds of the
                           runner up, development beside holdout, clocks coloured
                           by the logistic twin's coefficient sign (from
                           <run>/fold_*/metrics.json)

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
ROLLING_ROOT = "data/processed/results/rolling_backtest"
# (label, development run, out of time run, colour) for the fold timeline.
TIMELINE_SERIES = (
    (
        "Clocks + contributor dynamics, logistic (champion)",
        "ghclock_ghdyn_logistic",
        "oot_champion",
        "#b03a7a",
    ),
    (
        "Clocks + install base, XGBoost (runner up)",
        "ghclock_installs_xgb",
        "oot_runnerup",
        "#1f3b73",
    ),
    (
        "Clocks alone, logistic (baseline)",
        "ghclock_only_logistic",
        "oot_ghclock_logistic",
        "#3d8f6b",
    ),
)
H2_CRITERION = 0.55
# Honest SHAP figure: the tree model whose folds carry mean |SHAP|, its holdout
# run, and the logistic run of the same configuration that supplies signs.
HONEST_SHAP_DEV = "ghclock_installs_xgb"
HONEST_SHAP_OOT = "oot_runnerup"
HONEST_SHAP_LOGISTIC = "ghclock_installs_logistic"
FEATURE_LABELS = {
    "installs_months_of_data": "Install base: months of data",
    "installs_growth_12m": "Install base: 12 month growth",
    "installs_growth_3m": "Install base: 3 month growth",
    "installs_count": "Install count",
    "installs_log10_count": "Install count (log10)",
    "installs_pct": "Share of all Jenkins installs",
    "installs_rank_pct": "Install rank (percentile)",
    "installs_rank_delta_12m": "Install rank change, 12 months",
    "installs_peak_ratio": "Installs, ratio to own peak",
    "installs_has_data": "Has install data",
    "ghclock_days_since_human_push": "Days since last human push",
    "ghclock_days_since_any_push": "Days since any push (bots included)",
    "ghclock_days_since_release": "Days since last release",
    "ghclock_days_since_pr_opened": "Days since last pull request opened",
    "ghclock_days_since_pr_merged": "Days since last pull request merged",
    "ghclock_days_since_pr_review": "Days since last pull request review",
    "ghclock_days_since_issue_opened": "Days since last issue opened",
    "ghclock_days_since_tag_create": "Days since last tag",
    "ghclock_has_events": "Has any GitHub Archive events",
}
K_MARKS = (10, 25, 50, 100)

FACTOR_LABELS = {
    "releases": "Releases stale\n(>= 12 months)",
    "team": "Small team\n(<= 2 humans, 6 mo)",
    "either": "Either\n(H1 disjunction)",
    "commits": "Commits stale\n(>= 365 days)",
    "weekend": "Any weekend commits\n(fraction > 0)",
    "late night": "Any late night commits\n(fraction > 0)",
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
    fig, ax = plt.subplots(figsize=(7, 4.0))
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
    ax.set_xlim(0.22, 2.3)
    ax.minorticks_off()
    ax.set_ylim(-0.7, len(names) - 0.2)
    ax.legend(loc="lower left", fontsize=8, framealpha=1.0)
    ax.set_yticks(list(ys))
    ax.set_yticklabels(names, fontsize=9)
    ax.set_xlabel("Odds ratio for advisory within 6 months (log scale, train window)")
    ax.set_title("Marginal odds ratios: H1 factors and supplementary signals", fontsize=11)
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


SHAP_CONSISTENCY_JSON = "data/processed/results/shap_consistency.json"

FAMILY_COLORS = {
    "Advisory History": "#1f4e79",
    "Software Heritage": "#0F6E56",
    "GitHub Archive": "#BA7517",
}


def fig_shap_consistency(out: Path, src: str, top_n: int = 8) -> None:
    """Diverging feature-importance chart: risk increasing vs risk decreasing."""
    j = json.loads(Path(src).read_text())
    min_models = max(3, j.get("n_models_used", 25) // 6)
    inc = [r for r in j["increasing"] if r["models"] >= min_models][:top_n]
    dec = [r for r in j["decreasing"] if r["models"] >= min_models][:top_n]
    rows = [(r, -1) for r in reversed(dec)] + [(r, 1) for r in reversed(inc)]
    fig, ax = plt.subplots(figsize=(8.0, 0.30 * len(rows) + 1.6))
    for i, (r, sign) in enumerate(rows):
        color = FAMILY_COLORS.get(r["family"], "#888780")
        ax.barh(i, sign * r["avg_shap"], height=0.7, color=color, alpha=1.0 if sign > 0 else 0.55)
        ax.annotate(
            f"{r['avg_shap']:.3f} ({r['models']}/25)",
            (sign * r["avg_shap"], i),
            textcoords="offset points",
            xytext=(5 if sign > 0 else -5, 0),
            ha="left" if sign > 0 else "right",
            va="center",
            fontsize=7.5,
        )
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r["feature"] for r, _ in rows], fontsize=8)
    ax.axvline(0, color="#5F5E5A", linewidth=1)
    lim = max(r["avg_shap"] for r, _ in rows) * 1.45
    ax.set_xlim(-lim, lim)
    ax.set_xticks([t for t in ax.get_xticks() if abs(t) <= lim])
    ax.set_xticklabels([f"{abs(t):.1f}" for t in ax.get_xticks()], fontsize=8)
    ax.set_xlabel("Mean |SHAP| across 25 time split models (risk decrease <-- | --> risk increase)")
    ax.set_title(
        f"Feature importance by SHAP consistency across "
        f"{j.get('n_models_used', 25)} time split models"
    )
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in FAMILY_COLORS.values()]
    ax.legend(handles, list(FAMILY_COLORS), loc="lower right", fontsize=8, framealpha=1.0)
    fig.tight_layout()
    fig.savefig(out / "shap_consistency.png")
    plt.close(fig)


SHAP_SINGLE_JSON = "data/processed/results/shap_single_model.json"


def fig_shap_single(out: Path, src: str, top_n: int = 16) -> None:
    """Diverging importance chart for one model; direction by value correlation."""
    j = json.loads(Path(src).read_text())
    feats = j["features"][:top_n]
    inc = [f for f in feats if f["direction"] == "increasing"]
    dec = [f for f in feats if f["direction"] == "decreasing"]
    rows = [(f, -1) for f in reversed(dec)] + [(f, 1) for f in reversed(inc)]
    fig, ax = plt.subplots(figsize=(8.0, 0.30 * len(rows) + 1.7))
    for i, (f, sign) in enumerate(rows):
        color = FAMILY_COLORS.get(f["family"], "#888780")
        ax.barh(
            i,
            sign * f["mean_abs_shap"],
            height=0.7,
            color=color,
            alpha=0.45 if f.get("direction_weak") else 1.0,
        )
        weak = ", weak" if f.get("direction_weak") else ""
        ax.annotate(
            f"{f['mean_abs_shap']:.3f} (r={f['value_shap_corr']:+.2f}{weak})",
            (sign * f["mean_abs_shap"], i),
            textcoords="offset points",
            xytext=(5 if sign > 0 else -5, 0),
            ha="left" if sign > 0 else "right",
            va="center",
            fontsize=7.5,
        )
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f["feature"] for f, _ in rows], fontsize=8)
    ax.axvline(0, color="#5F5E5A", linewidth=1)
    lim = max(f["mean_abs_shap"] for f, _ in rows) * 1.55
    ax.set_xlim(-lim, lim)
    ticks = [t for t in ax.get_xticks() if abs(t) <= lim]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{abs(t):.1f}" for t in ticks], fontsize=8)
    ax.set_xlabel("Mean |SHAP|  (high value lowers risk <-- | --> high value raises risk)")
    ax.set_title(f"Top {len(rows)} features by SHAP importance ({j['model']})", fontsize=12)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in FAMILY_COLORS.values()]
    ax.legend(handles, list(FAMILY_COLORS), loc="lower right", fontsize=8, framealpha=1.0)
    fig.tight_layout()
    fig.savefig(out / "shap_single.png")
    plt.close(fig)


def fig_shap_profiles(out: Path, src: str, n_feats: int = 4) -> None:
    """Small-multiples dependence profiles: mean SHAP per value quintile.

    Panels are limited to the top recency ("staleness clock") features by
    importance: these carry the liveness-cliff pattern the text discusses,
    and a 2x2 grid stays readable at print size (advisor guidance, Aug 2026).
    """
    j = json.loads(Path(src).read_text())
    feats = [f for f in j["features"] if f.get("bin_profile") and "_since_" in f["feature"]][
        :n_feats
    ]
    if not feats:
        print("SKIP shap_profiles: no bin_profile data (rerun shap_single_model.py)")
        return
    ncols = 2  # advisor guidance (Aug 2026): max two panels across for print readability
    nrows = (len(feats) + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(7.0, 2.15 * nrows + 0.5), squeeze=False)
    for idx, f in enumerate(feats):
        ax = axes[idx // ncols][idx % ncols]
        prof = f["bin_profile"]
        xs = list(range(len(prof)))
        ys = [b["mean_shap"] for b in prof]
        color = FAMILY_COLORS.get(f["family"], "#888780")
        ax.axhline(0, color="#B4B2A9", linewidth=0.8)
        ax.plot(xs, ys, "o-", color=color, linewidth=1.8, markersize=5)
        ax.set_title(f["feature"], fontsize=10)
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{b['value_lo']:g}\n-{b['value_hi']:g}" for b in prof], fontsize=8)
        ax.tick_params(axis="y", labelsize=8)
        shape = f.get("bin_shape") or ""
        # keep the annotation off the curve: top-left unless the profile starts high
        starts_high = ys[0] > (min(ys) + max(ys)) / 2
        xy, va = ((0.03, 0.06), "bottom") if starts_high else ((0.03, 0.94), "top")
        ax.annotate(
            f"r={f['value_shap_corr']:+.2f}  {shape}",
            xy,
            xycoords="axes fraction",
            fontsize=8.5,
            va=va,
        )
    for idx in range(len(feats), nrows * ncols):
        axes[idx // ncols][idx % ncols].axis("off")
    fig.suptitle(f"SHAP dependence profiles by value quintile ({j['model']})", fontsize=12)
    fig.supylabel("Mean SHAP in bin", fontsize=10)
    fig.tight_layout(rect=(0.04, 0, 1, 0.965))
    fig.savefig(out / "shap_profiles.png")
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


def _fold_points(rolling_root: Path, run: str) -> list[tuple[str, float]]:
    payload = json.loads((rolling_root / run / "rolling_backtest.json").read_text(encoding="utf-8"))
    return [(str(f["test_start_month"]), float(f["roc_auc"])) for f in payload["folds"]]


def fig_fold_timeline(out: Path, rolling_root: str) -> None:
    """Per fold ROC-AUC, development sweep then holdout, for the declared configurations."""
    root = Path(rolling_root)
    series = [
        (label, _fold_points(root, dev), _fold_points(root, oot), colour)
        for label, dev, oot, colour in TIMELINE_SERIES
    ]
    months = sorted({m for _, dev, oot, _ in series for m, _ in dev + oot})
    x = {m: i for i, m in enumerate(months)}
    first_holdout = min(m for _, _, oot, _ in series for m, _ in oot)
    boundary = x[first_holdout] - 0.5
    fig, ax = plt.subplots(figsize=(7.0, 3.6))
    ax.axvspan(boundary, len(months) - 0.5, color="#e9f3ee", zorder=0)
    ax.axvline(boundary, color="#3d8f6b", linestyle="--", linewidth=1)
    ax.text(boundary + 0.15, 0.845, "pre registered holdout", fontsize=8, color="#2a6b4d", va="top")
    ax.text(
        boundary - 0.15, 0.845, "development sweep", fontsize=8, color="#555", va="top", ha="right"
    )
    ax.axhline(H2_CRITERION, color="#c00000", linestyle="--", linewidth=1)
    ax.text(
        0.1, H2_CRITERION + 0.006, f"H2 criterion {H2_CRITERION:.2f}", fontsize=8, color="#c00000"
    )
    ax.axhline(0.5, color="#888", linestyle=":", linewidth=1)
    ax.text(0.1, 0.506, "chance 0.50", fontsize=8, color="#666")
    for label, dev, oot, colour in series:
        pts = dev + oot
        ax.plot(
            [x[m] for m, _ in pts],
            [v for _, v in pts],
            color=colour,
            linewidth=1.6,
            marker="o",
            markersize=3.5,
            label=label,
        )
        ax.plot(
            [x[m] for m, _ in oot],
            [v for _, v in oot],
            color=colour,
            linestyle="none",
            marker="o",
            markersize=6,
        )
    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(months, rotation=45, ha="right", fontsize=7.5)
    ax.set_ylim(0.44, 0.86)
    ax.set_ylabel("ROC-AUC per fold", fontsize=9)
    ax.set_xlabel("Fold test start month (two month test windows)", fontsize=9)
    ax.tick_params(axis="y", labelsize=8)
    ax.grid(axis="y", color="#e6e8ef", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(fontsize=7.5, loc="upper left", frameon=False)
    fig.tight_layout()
    fig.savefig(out / "fold_timeline.png")
    plt.close(fig)


def _fold_shap(rolling_root: Path, run: str) -> dict[str, list[float]]:
    """Per feature list of mean |SHAP| across a run's fold metrics."""
    values: dict[str, list[float]] = {}
    fold_files = sorted((rolling_root / run).glob("fold_*/metrics.json"))
    if not fold_files:
        raise FileNotFoundError(f"no fold_*/metrics.json under {rolling_root / run}")
    for path in fold_files:
        metrics = json.loads(path.read_text(encoding="utf-8"))
        for key in ("top_positive_features", "top_negative_features"):
            for entry in metrics.get(key, []):
                if entry.get("mean_abs_shap") is not None:
                    values.setdefault(entry["feature"], []).append(float(entry["mean_abs_shap"]))
    return values


def _fold_signs(rolling_root: Path, run: str) -> dict[str, int]:
    """+1 / -1 when a logistic run's coefficient sign agrees in every fold, else 0."""
    counts: dict[str, list[int]] = {}
    for path in sorted((rolling_root / run).glob("fold_*/metrics.json")):
        metrics = json.loads(path.read_text(encoding="utf-8"))
        for key in ("top_positive_features", "top_negative_features"):
            for entry in metrics.get(key, []):
                coef = entry.get("coefficient")
                if coef is None:
                    continue
                pos_neg = counts.setdefault(entry["feature"], [0, 0])
                pos_neg[0 if coef > 0 else 1] += 1
    signs: dict[str, int] = {}
    for feature, (pos, neg) in counts.items():
        signs[feature] = 1 if neg == 0 else (-1 if pos == 0 else 0)
    return signs


def fig_honest_shap(out: Path, rolling_root: str) -> None:
    """Mean |SHAP| over embargoed folds for the runner up, development beside holdout."""
    root = Path(rolling_root)
    dev = _fold_shap(root, HONEST_SHAP_DEV)
    oot = _fold_shap(root, HONEST_SHAP_OOT)
    signs = _fold_signs(root, HONEST_SHAP_LOGISTIC)
    feats = [
        f for f in sorted(dev, key=lambda f: -sum(dev[f]) / len(dev[f])) if f != "installs_has_data"
    ]
    navy, magenta, grey, green = "#1f3b73", "#b03a7a", "#8a8fa3", "#3d8f6b"

    def colour(feature: str) -> str:
        if not feature.startswith("ghclock_"):
            return navy
        return {-1: magenta, 1: green}.get(signs.get(feature, 0), grey)

    fig, axes = plt.subplots(
        1, 2, figsize=(7.0, 5.0), sharey=True, gridspec_kw={"width_ratios": [1.1, 1]}
    )
    ys = list(range(len(feats)))[::-1]
    panels = (
        (axes[0], dev, f"{len(next(iter(dev.values())))} embargoed development folds"),
        (axes[1], oot, f"{len(next(iter(oot.values())))} pre registered holdout folds"),
    )
    for ax, data, title in panels:
        for y, feature in zip(ys, feats, strict=True):
            vals = data.get(feature, [])
            if not vals:
                continue
            ax.barh(y, sum(vals) / len(vals), color=colour(feature), height=0.62)
            ax.plot([min(vals), max(vals)], [y, y], color="#333333", linewidth=0.9)
            ax.plot([min(vals), max(vals)], [y, y], "|", color="#333333", markersize=5)
        ax.set_title(title, fontsize=9.5)
        ax.tick_params(axis="x", labelsize=8)
        ax.grid(axis="x", color="#e6e8ef", linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
    axes[0].set_yticks(ys)
    axes[0].set_yticklabels([FEATURE_LABELS.get(f, f) for f in feats], fontsize=8)
    fig.supxlabel(
        "Mean |SHAP| in each fold: bar = mean over folds, whisker = range across folds",
        fontsize=8.5,
        y=0.115,
    )
    from matplotlib.patches import Patch  # pyright: ignore[reportMissingImports]

    handles = [
        Patch(color=magenta, label="Clock, negative coefficient: more recent raises risk"),
        Patch(color=green, label="Clock, positive coefficient: larger value raises risk"),
        Patch(color=grey, label="Clock, coefficient sign not stable across folds"),
        Patch(color=navy, label="Install base family (direction not read from tree SHAP)"),
    ]
    fig.legend(
        handles=handles,
        loc="lower center",
        ncol=2,
        fontsize=7.5,
        frameon=False,
        bbox_to_anchor=(0.5, 0.0),
    )
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(out / "honest_shap.png")
    plt.close(fig)


FIGURES = {
    "shap_profiles": lambda out, a: fig_shap_profiles(out, a.shap_single_json),
    "shap_single": lambda out, a: fig_shap_single(out, a.shap_single_json),
    "shap_consistency": lambda out, a: fig_shap_consistency(out, a.shap_consistency_json),
    "simpson": lambda out, a: fig_simpson(out, a.simpson_json),
    "h1_forest": lambda out, a: fig_h1_forest(out, a.h1_json),
    "precision_coverage": lambda out, a: fig_precision_coverage(out, a.pc_model),
    "h3_retention": lambda out, a: fig_h3_retention(out, a.h3_model),
    "calibration": lambda out, a: fig_calibration(out, a.pc_model),
    "shap_importance": lambda out, a: fig_shap_importance(out, a.shap_model),
    "fold_timeline": lambda out, a: fig_fold_timeline(out, a.rolling_root),
    "honest_shap": lambda out, a: fig_honest_shap(out, a.rolling_root),
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate praxis figures from saved artifacts.")
    parser.add_argument("--out-dir", default=OUT_DIR)
    parser.add_argument("--h1-json", default=H1_JSON)
    parser.add_argument("--simpson-json", default=SIMPSON_JSON)
    parser.add_argument("--shap-consistency-json", default=SHAP_CONSISTENCY_JSON)
    parser.add_argument("--shap-single-json", default=SHAP_SINGLE_JSON)
    parser.add_argument(
        "--pc-model", default=PC_MODEL, help="model dir for precision/coverage and calibration"
    )
    parser.add_argument("--h3-model", default=H3_MODEL, help="model dir for the H3 retention curve")
    parser.add_argument(
        "--shap-model", default=SHAP_MODEL, help="model dir for the SHAP importance chart"
    )
    parser.add_argument(
        "--rolling-root", default=ROLLING_ROOT, help="rolling backtest results root"
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
