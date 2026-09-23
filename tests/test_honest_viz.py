"""Behavior tests for the Honest-tab charts: curve math, run pairing, rendering."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import canary.webapp as webapp
from canary.web import charts, honest_viz
from canary.web.ui import _render_honest_tab


def _write_fold(run_dir: Path, month: str, rows: list[tuple[str, int, float]]) -> None:
    d = run_dir / f"fold_{month}"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "test_predictions.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["plugin_id", "month", "y_true", "y_prob"])
        w.writeheader()
        for pid, y, p in rows:
            w.writerow({"plugin_id": pid, "month": month, "y_true": y, "y_prob": p})


def _rolling_payload(
    *, embargo: bool, prefixes: list[str] | None, model: str, folds: list[tuple[str, float, int]]
) -> dict[str, Any]:
    fold_dicts = [
        {"test_start_month": m, "test_end_month": m, "roc_auc": roc, "test_positive_count": pos}
        for m, roc, pos in folds
    ]
    mean = sum(f[1] for f in folds) / len(folds)
    return {
        "model_name": model,
        "embargo": embargo,
        "include_prefixes": prefixes,
        "in_path": "data/processed/features/plugins.monthly.labeled.jsonl",
        "folds": fold_dicts,
        "summary": {"fold_count": len(folds), "roc_auc": {"mean": mean}},
        "pooled": {
            "roc_auc": mean,
            "average_precision": 0.03,
            "ap_lift_over_base_rate": 2.0,
            "n_positive": sum(f[2] for f in folds),
        },
    }


# ---------------------------------------------------------------------------
# Curve math
# ---------------------------------------------------------------------------


def test_gain_and_roc_on_a_perfect_ranking() -> None:
    rows = [(1, 0.9), (1, 0.8)] + [(0, 0.1)] * 18
    gain = honest_viz.gain_curve(rows)
    roc = honest_viz.roc_curve(rows)
    assert gain is not None and roc is not None
    # Two positives sit at the top of twenty rows: the top 10% captures all of them.
    captured = dict(zip(gain["fractions"], gain["captured"], strict=True))
    assert captured[0.10] == 1.0
    assert captured[0.05] == 0.5
    assert roc["auc"] == 1.0


def test_roc_advances_tied_scores_together_and_matches_rank_auc() -> None:
    # One positive tied with one negative at the top: AUC must be 0.5 for that
    # pair, not 1.0 (which sweeping ties one row at a time would report).
    rows = [(1, 0.9), (0, 0.9), (0, 0.1)]
    roc = honest_viz.roc_curve(rows)
    assert roc is not None
    assert roc["auc"] == 0.75
    assert roc["fpr"][1] == 0.5 and roc["tpr"][1] == 1.0


def test_curves_are_undefined_without_both_classes() -> None:
    assert honest_viz.gain_curve([(0, 0.2), (0, 0.4)]) is None
    assert honest_viz.roc_curve([(1, 0.2), (1, 0.4)]) is None
    assert honest_viz.roc_curve([]) is None


def test_load_curves_pools_folds_and_caches_on_file_signature(tmp_path: Path) -> None:
    run_dir = tmp_path / "oot_run"
    _write_fold(run_dir, "2025-07", [("a", 1, 0.9), ("b", 0, 0.1)] * 5)
    _write_fold(run_dir, "2025-09", [("c", 0, 0.7), ("d", 1, 0.3)] * 5)
    first = honest_viz.load_curves(run_dir)
    assert first is not None
    assert [f["month"] for f in first["folds"]] == ["2025-07", "2025-09"]
    assert first["n_rows"] == 20 and first["n_positive"] == 10
    assert first["folds"][0]["roc_auc"] == 1.0 and first["folds"][1]["roc_auc"] == 0.0
    assert first["pooled"]["gain"] is not None
    # Same files -> same cached object; a rewritten fold -> recomputed.
    assert honest_viz.load_curves(run_dir) is first
    _write_fold(run_dir, "2025-09", [("c", 1, 0.7), ("d", 0, 0.3)] * 5)
    second = honest_viz.load_curves(run_dir)
    assert second is not first
    assert second is not None and second["folds"][1]["roc_auc"] == 1.0
    assert honest_viz.load_curves(tmp_path / "missing") is None
    assert honest_viz.load_curves(tmp_path) is None  # no fold_* directories


# ---------------------------------------------------------------------------
# Timeline and leakage pairing
# ---------------------------------------------------------------------------


def test_timeline_pairs_development_and_oot_runs_by_configuration() -> None:
    dev = _rolling_payload(
        embargo=True,
        prefixes=["ghclock_"],
        model="logistic",
        folds=[("2023-05", 0.7, 100), ("2023-07", 0.6, 90)],
    )
    oot = _rolling_payload(
        embargo=True, prefixes=["ghclock_"], model="logistic", folds=[("2025-07", 0.65, 40)]
    )
    other_dev = _rolling_payload(
        embargo=True, prefixes=["advhist_"], model="xgboost", folds=[("2023-05", 0.45, 100)]
    )
    leaky = _rolling_payload(
        embargo=False, prefixes=["ghclock_"], model="logistic", folds=[("2025-07", 0.9, 40)]
    )
    sens = dict(oot, run_name="oot_asof")
    for name, run, kind, sensitivity in (
        ("ghclock_only_logistic", dev, "development", False),
        ("oot_ghclock", oot, "out_of_time", False),
        ("advhist_xgb", other_dev, "development", False),
        ("oot_ghclock_leaky", leaky, "out_of_time", False),
        ("oot_asof", sens, "out_of_time", True),
    ):
        run.update(run_name=name, window_kind=kind, sensitivity=sensitivity)

    series = honest_viz.timeline_series([dev, oot, other_dev, leaky, sens])

    # Only the configuration that has an out-of-time run becomes a series, and
    # its points run development first, then holdout, in month order.
    assert len(series) == 1
    assert series[0]["run_names"] == ["ghclock_only_logistic", "oot_ghclock"]
    assert [p["month"] for p in series[0]["points"]] == ["2023-05", "2023-07", "2025-07"]
    assert [p["window"] for p in series[0]["points"]][-1] == "out_of_time"

    # With no out-of-time runs at all, the best development configuration is shown alone.
    alone = honest_viz.timeline_series([dev, other_dev])
    assert [s["run_names"] for s in alone] == [["ghclock_only_logistic"]]


def test_rolling_leakage_pairs_need_an_embargoed_sibling(tmp_path: Path) -> None:
    root = tmp_path / "rolling"
    honest = _rolling_payload(
        embargo=True, prefixes=["advisory_"], model="xgboost", folds=[("2023-05", 0.55, 50)]
    )
    leaky = _rolling_payload(
        embargo=False, prefixes=["advisory_"], model="xgboost", folds=[("2023-05", 0.60, 50)]
    )
    for name, payload in (
        ("advisory_only_xgb", honest),
        ("advisory_only_xgb_leaky", leaky),
        ("orphan_leaky", leaky),
    ):
        (root / name).mkdir(parents=True)
        (root / name / "rolling_backtest.json").write_text(json.dumps(payload), encoding="utf-8")

    pairs = honest_viz.rolling_leakage_pairs(root, "PyPI")

    assert [p["run_name"] for p in pairs] == ["advisory_only_xgb"]
    assert pairs[0]["ecosystem"] == "PyPI" and pairs[0]["layer"] == "rolling"
    assert pairs[0]["stored"]["roc_auc"] == 0.60 and pairs[0]["embargoed"]["roc_auc"] == 0.55
    assert honest_viz.rolling_leakage_pairs(tmp_path / "nowhere", "PyPI") == []


def test_time_split_pairs_use_listed_stems_and_derive_lift(tmp_path: Path) -> None:
    models = tmp_path / "models"
    stored = {
        "roc_auc": 0.93,
        "average_precision": 0.58,
        "test_positive_count": 77,
        "test_row_count": 4106,
        "model_name": "xgboost",
    }
    embargoed = dict(stored, roc_auc=0.48, average_precision=0.019, label_as_of_month="2025-06")
    for name, payload in (("official", stored), ("official_embargo", embargoed), ("other", stored)):
        (models / name).mkdir(parents=True)
        (models / name / "metrics.json").write_text(json.dumps(payload), encoding="utf-8")

    pairs = honest_viz.time_split_leakage_pairs(
        models, {"official": "Official config", "missing": "Not there"}, "Jenkins"
    )

    assert len(pairs) == 1
    assert pairs[0]["label"] == "Official config" and pairs[0]["layer"] == "time split"
    assert round(pairs[0]["stored"]["ap_lift"], 1) == round(0.58 / (77 / 4106), 1)
    assert pairs[0]["embargoed"]["n_positive"] == 77


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_svg_charts_escape_labels_and_draw_reference_lines() -> None:
    timeline = charts.svg_timeline(
        [
            {
                "label": "a <b> & c",
                "points": [
                    {"month": "2025-05", "roc_auc": 0.6, "positives": 3, "window": "development"},
                    {"month": "2025-07", "roc_auc": 0.7, "positives": 4, "window": "out_of_time"},
                ],
            }
        ],
        criterion=0.55,
        boundary_month="2025-06",
    )
    assert "<b>" not in timeline and "a &lt;b&gt; &amp; c" in timeline
    assert "pre-registered criterion 0.55" in timeline and "pre-registered holdout" in timeline
    assert timeline.count("<circle") == 2

    bars = charts.svg_paired_bars(
        [{"label": "x", "stored": 0.9, "embargoed": None}], metric_label="ROC-AUC", chance=0.5
    )
    assert bars.count("<rect") == 3  # two legend swatches + one bar (None draws nothing)
    assert "chance 0.50" in bars
    assert charts.svg_paired_bars([], metric_label="ROC-AUC") == ""
    assert charts.svg_gain([{"label": "x", "fractions": [], "captured": []}]) == ""
    assert charts.svg_roc([]) == ""


def test_honest_tab_renders_charts_when_viz_is_supplied_and_tables_without() -> None:
    dev = _rolling_payload(
        embargo=True,
        prefixes=["ghclock_"],
        model="logistic",
        folds=[("2023-05", 0.7, 100), ("2023-07", 0.6, 90)],
    )
    oot = _rolling_payload(
        embargo=True, prefixes=["ghclock_"], model="logistic", folds=[("2025-07", 0.65, 40)]
    )
    dev.update(run_name="ghclock_only_logistic", window_kind="development", sensitivity=False)
    oot.update(run_name="oot_ghclock", window_kind="out_of_time", sensitivity=False)
    runs = [dev, oot]

    plain = _render_honest_tab(runs)
    assert "<svg" not in plain and "All rolling backtest runs" in plain

    rows = [(1, 0.9), (0, 0.2), (0, 0.1)]
    viz = {
        "timeline": honest_viz.timeline_series(runs),
        "criterion": 0.55,
        "boundary_month": "2025-06",
        "curves": [
            {
                "run": oot,
                "curves": {
                    "run_name": "oot_ghclock",
                    "n_rows": 3,
                    "n_positive": 1,
                    "base_rate": 1 / 3,
                    "pooled": {"gain": honest_viz.gain_curve(rows), "roc_auc": 1.0},
                    "folds": [
                        {
                            "month": "2025-07",
                            "n_rows": 3,
                            "n_positive": 1,
                            "roc_auc": 1.0,
                            "roc": honest_viz.roc_curve(rows),
                            "gain": honest_viz.gain_curve(rows),
                        }
                    ],
                },
            }
        ],
        "pairs": [
            {
                "ecosystem": "Jenkins",
                "layer": "rolling",
                "run_name": "r",
                "folds": 13,
                "include_prefixes": ["ghclock_"],
                "model_name": "logistic",
                "stored": {"roc_auc": 0.7, "average_precision": 0.05, "n_positive": 10},
                "embargoed": {"roc_auc": 0.6, "average_precision": 0.03, "n_positive": 10},
            }
        ],
    }
    rich = _render_honest_tab(runs, viz=viz)
    assert rich.count("<svg") == 5  # two leakage charts, timeline, gain, ROC
    assert "The turning point" in rich and "Every fold, one criterion" in rich
    assert "Activity-recency clocks · Logistic Regression" in rich
    # The gain headline is computed from the curve, not hard-coded.
    assert "would have caught 100% of the advisories that followed" in rich
    assert "(by fold: 100%)" in rich


def test_load_honest_viz_reads_oot_curves_and_pairs(tmp_path: Path, monkeypatch: Any) -> None:
    rolling = tmp_path / "rolling"
    pypi = tmp_path / "pypi"
    models = tmp_path / "models"
    for root in (rolling, pypi, models):
        root.mkdir()
    oot = _rolling_payload(
        embargo=True, prefixes=["ghclock_"], model="logistic", folds=[("2025-07", 0.65, 5)]
    )
    (rolling / "oot_run").mkdir()
    (rolling / "oot_run" / "rolling_backtest.json").write_text(json.dumps(oot), encoding="utf-8")
    _write_fold(rolling / "oot_run", "2025-07", [("a", 1, 0.9), ("b", 0, 0.1)] * 5)
    monkeypatch.setattr(webapp, "ROLLING_RESULTS_ROOT", rolling)
    monkeypatch.setattr(webapp, "PYPI_ROLLING_RESULTS_ROOT", pypi)
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", models)

    runs = webapp._load_rolling_backtests()
    viz = webapp._load_honest_viz(runs)

    assert viz["boundary_month"] == webapp.OOT_BOUNDARY_MONTH
    assert viz["criterion"] == webapp.H2_ROC_CRITERION
    assert [c["run"]["run_name"] for c in viz["curves"]] == ["oot_run"]
    assert viz["curves"][0]["curves"]["pooled"]["roc_auc"] == 1.0
    assert viz["pairs"] == []
    page = webapp.render_page({"active_tab": "honest"})
    assert "Advisories caught vs plugins reviewed" in page


# ---------------------------------------------------------------------------
# Ranked index: plugin track record and per-fold top-N
# ---------------------------------------------------------------------------


def test_ranked_index_ranks_within_month_and_tracks_a_plugin(tmp_path: Path) -> None:
    dev = tmp_path / "dev"
    oot = tmp_path / "oot"
    _write_fold(dev, "2025-05", [("a", 0, 0.9), ("b", 1, 0.5), ("c", 0, 0.1)])
    _write_fold(oot, "2025-07", [("a", 1, 0.2), ("b", 0, 0.8), ("c", 0, 0.7)])
    index = honest_viz.ranked_index([dev, oot, tmp_path / "missing"])
    assert index is not None

    track = honest_viz.plugin_track(index, "a")
    assert [(r["month"], r["rank"], r["n"]) for r in track] == [
        ("2025-05", 1, 3),
        ("2025-07", 3, 3),
    ]
    assert track[0]["percentile"] == 100.0 and track[1]["percentile"] == 0.0
    assert track[1]["fold"] == "2025-07" and track[1]["run_name"] == "oot"
    assert honest_viz.plugin_track(index, "nobody") == []
    assert honest_viz.ranked_index([tmp_path / "missing"]) is None


def test_fold_top_n_keeps_each_plugin_once_with_its_best_month(tmp_path: Path) -> None:
    run = tmp_path / "oot"
    _write_fold(
        run,
        "2025-11",
        [("a", 0, 0.9), ("b", 0, 0.3)]  # November
        + [("a", 1, 0.6), ("b", 0, 0.8)],  # December (rows carry their own month below)
    )
    # Give the second pair a December month so the fold has two months.
    path = run / "fold_2025-11" / "test_predictions.csv"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[3] = lines[3].replace("2025-11", "2025-12")
    lines[4] = lines[4].replace("2025-11", "2025-12")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    index = honest_viz.ranked_index([run])
    assert index is not None
    top = honest_viz.fold_top_n(index, "2025-11", n_top=25)

    # "a" is kept once, at its November score, but its December label counts.
    assert [(r["plugin_id"], r["month"], r["y_prob"], r["y_true"]) for r in top] == [
        ("a", "2025-11", 0.9, 1),
        ("b", "2025-12", 0.8, 0),
    ]
    assert [r["rank"] for r in top] == [1, 2]
    assert honest_viz.fold_top_n(index, "2099-01") == []


def test_plugin_track_and_honest_case_study_loaders(tmp_path: Path, monkeypatch: Any) -> None:
    rolling = tmp_path / "rolling"
    advisories = tmp_path / "advisories"
    rolling.mkdir()
    advisories.mkdir()
    dev = _rolling_payload(
        embargo=True, prefixes=["ghclock_"], model="logistic", folds=[("2025-05", 0.7, 1)]
    )
    oot = _rolling_payload(
        embargo=True, prefixes=["ghclock_"], model="logistic", folds=[("2025-07", 0.65, 1)]
    )
    oot["folds"][0].update(test_row_count=3, label_as_of_month="2025-08", test_end_month="2025-08")
    for name, payload in (("dev_run", dev), ("oot_run", oot)):
        (rolling / name).mkdir()
        (rolling / name / "rolling_backtest.json").write_text(json.dumps(payload), encoding="utf-8")
    _write_fold(rolling / "dev_run", "2025-05", [("a", 0, 0.9), ("b", 0, 0.5), ("c", 0, 0.1)])
    _write_fold(rolling / "oot_run", "2025-07", [("a", 1, 0.9), ("b", 0, 0.5), ("c", 0, 0.1)])
    (advisories / "a.advisories.real.jsonl").write_text(
        json.dumps(
            {
                "published_date": "2025-09-03",
                "url": "https://example.test/adv",
                "security_warning_ids": ["SECURITY-1"],
                "severity_summary": {"max_severity_label": "medium", "max_cvss_base_score": 5.0},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(webapp, "ROLLING_RESULTS_ROOT", rolling)
    monkeypatch.setattr(webapp, "ADVISORY_DATA_ROOT", advisories)

    track = webapp._load_plugin_track("a")
    assert track is not None
    assert track["run_names"] == ["dev_run", "oot_run"]
    assert [r["window"] for r in track["rows"]] == ["development", "out_of_time"]
    assert track["rows"][1]["adv_id"] == "SECURITY-1"
    assert track["n_positive"] == 1 and track["holdout_mean_percentile"] == 100.0
    assert webapp._load_plugin_track("nobody") is None

    view = webapp._load_honest_case_study({"oot_run": "not-a-run"})
    assert view is not None
    assert view["run"]["run_name"] == "oot_run"  # unknown names fall back to the first run
    fold = view["folds"][0]
    assert fold["fold"] == "2025-07" and fold["base_rate"] == 1 / 3
    assert [r["plugin_id"] for r in fold["confirmed_rows"]] == ["a"]
    assert fold["confirmed_rows"][0]["adv_date"] == "2025-09-03"
    assert [r["plugin_id"] for r in fold["unconfirmed_rows"]] == ["b", "c"]

    # The Case-study tab shows the holdout view by default and the plugin's
    # score page carries its track record.
    page = webapp.render_page({"active_tab": "casestudy", "model_out_dir": "", "oot_run": ""})
    assert "Top-25 per holdout fold vs. what followed" in page and "SECURITY-1" in page
    score_result = {
        "plugin": "a",
        "ml": None,
        "reasons": [],
        "features": {},
        "pretty_features": "{}",
        "pretty_json": "{}",
    }
    page = webapp.render_page({"active_tab": "score", "plugin": "a"}, score_result=score_result)
    assert "Where a ranked before each window" in page and "top 0.00%" in page


def test_svg_plugin_track_marks_hits_and_holdout() -> None:
    rows = [
        {"month": "2025-05", "percentile": 80.0, "rank": 2, "n": 5, "y_true": 0, "y_prob": 0.4},
        {"month": "2025-07", "percentile": 100.0, "rank": 1, "n": 5, "y_true": 1, "y_prob": 0.9},
    ]
    svg = charts.svg_plugin_track(rows, boundary_month="2025-06")
    assert svg.count("<circle") == 4  # two points + two legend swatches
    assert "out-of-time holdout" in svg and "advisory followed within 180 days" in svg
    assert charts.svg_plugin_track([], boundary_month="2025-06") == ""
