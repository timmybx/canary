"""Behavior tests for the Honest-evaluation tab (rolling backtest results)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import canary.webapp as webapp
from canary.web.ui import _honest_run_label, _render_honest_tab


def _run_payload(
    *,
    embargo: bool = True,
    pooled_roc: float | None = 0.62,
    prefixes: list[str] | None = None,
    model: str = "logistic",
    fold_month: str = "2024-05",
) -> dict[str, Any]:
    return {
        "model_name": model,
        "embargo": embargo,
        "include_prefixes": prefixes,
        "folds": [
            {
                "test_start_month": fold_month,
                "test_end_month": "2024-06",
                "label_as_of_month": "2024-06" if embargo else None,
                "test_row_count": 4106,
                "test_positive_count": 23,
                "roc_auc": 0.61,
                "average_precision": 0.03,
                "ap_lift_over_base_rate": 2.1,
            }
        ],
        "summary": {
            "fold_count": 1,
            "total_test_rows": 4106,
            "total_test_positives": 23,
            "roc_auc": {"mean": 0.61, "sd": None, "min": 0.61, "max": 0.61},
            "average_precision": {"mean": 0.03, "sd": None, "min": 0.03, "max": 0.03},
            "ap_lift_over_base_rate": {"mean": 2.1, "sd": None, "min": 2.1, "max": 2.1},
            "precision_at_25": {"mean": 0.04, "sd": None, "min": 0.04, "max": 0.04},
        },
        "test_windows_overlap": False,
        "pooled": (
            None
            if pooled_roc is None
            else {
                "n_rows": 4106,
                "n_positive": 23,
                "base_rate": 0.0056,
                "average_precision": 0.025,
                "ap_lift_over_base_rate": 1.8,
                "roc_auc": pooled_roc,
            }
        ),
    }


def _write_run(root: Path, name: str, payload: dict[str, Any]) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "rolling_backtest.json").write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture()
def results_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "rolling_backtest"
    root.mkdir()
    monkeypatch.setattr(webapp, "ROLLING_RESULTS_ROOT", root)
    return root


# ---------------------------------------------------------------------------
# _load_rolling_backtests
# ---------------------------------------------------------------------------


def test_loader_orders_embargoed_first_then_by_pooled_roc(results_root: Path) -> None:
    _write_run(results_root, "leaky_run", _run_payload(embargo=False, pooled_roc=0.70))
    _write_run(results_root, "weak_honest", _run_payload(pooled_roc=0.43, prefixes=["advhist_"]))
    _write_run(results_root, "champion", _run_payload(pooled_roc=0.62, prefixes=["ghclock_"]))
    runs = webapp._load_rolling_backtests()
    assert [r["run_name"] for r in runs] == ["champion", "weak_honest", "leaky_run"]


def test_loader_skips_invalid_and_broken_entries(results_root: Path) -> None:
    _write_run(results_root, "good", _run_payload())
    _write_run(results_root, "bad_INVALID_partial_data", _run_payload())
    # integrity-gate reruns reproduce a frozen run bit-for-bit and would show as duplicates
    _write_run(results_root, "good_rebuilt", _run_payload())
    _write_run(results_root, "good_rebuilt_102m", _run_payload())
    broken = results_root / "broken"
    broken.mkdir()
    (broken / "rolling_backtest.json").write_text("{not json", encoding="utf-8")
    (results_root / "no_payload").mkdir()
    # valid JSON that is not a rolling-backtest payload (no summary dict) is skipped too
    foreign = results_root / "foreign"
    foreign.mkdir()
    (foreign / "rolling_backtest.json").write_text("[1, 2, 3]", encoding="utf-8")
    runs = webapp._load_rolling_backtests()
    assert [r["run_name"] for r in runs] == ["good"]


def test_loader_handles_missing_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webapp, "ROLLING_RESULTS_ROOT", tmp_path / "nope")
    assert webapp._load_rolling_backtests() == []


# ---------------------------------------------------------------------------
# _render_honest_tab
# ---------------------------------------------------------------------------


def test_run_label_from_prefixes() -> None:
    assert _honest_run_label({"include_prefixes": ["ghclock_", "advhist_"]}) == "ghclock, advhist"
    assert _honest_run_label({"include_prefixes": None}) == "all features in dataset"


def test_render_honest_tab_champion_and_protocol_pills() -> None:
    runs = [
        {**_run_payload(pooled_roc=0.62, prefixes=["ghclock_"]), "run_name": "champ"},
        {**_run_payload(embargo=False, pooled_roc=0.70), "run_name": "leaky"},
    ]
    html = _render_honest_tab(runs)
    assert "Best embargoed development result" in html
    assert "ghclock" in html
    assert "0.620" in html  # pooled ROC of the embargoed champion, not the leaky 0.70
    assert html.count("embargoed</span>") == 1
    assert html.count("stored labels</span>") == 1
    assert "Per-fold detail" in html


def test_render_honest_tab_empty_state() -> None:
    html = _render_honest_tab([])
    assert "No rolling backtest results found" in html


def test_honest_tab_route_renders(results_root: Path) -> None:
    _write_run(results_root, "champion", _run_payload(prefixes=["ghclock_"]))
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "QUERY_STRING": "tab=honest",
        "wsgi.input": None,
    }
    body = b"".join(webapp.app(environ, start_response)).decode("utf-8")
    assert captured["status"] == "200 OK"
    assert 'data-tab-panel="honest"' in body
    assert "Honest evaluation" in body
    assert "ghclock" in body


# ---------------------------------------------------------------------------
# Feature-family / model tooltips on the honest tab
# ---------------------------------------------------------------------------


def test_every_enrichment_family_has_a_plain_language_tip() -> None:
    from canary.build.enrich_monthly import ALL_FAMILIES
    from canary.web.ui import _HONEST_FAMILY_TIPS

    missing = [f for f in ALL_FAMILIES if f not in _HONEST_FAMILY_TIPS]
    assert not missing, f"families without a honest-tab description: {missing}"
    for key, (name, tip) in _HONEST_FAMILY_TIPS.items():
        assert name and tip.startswith(f"{key}_ — "), key


def test_run_label_html_names_families_with_tooltips() -> None:
    from canary.web.ui import _honest_run_label_html

    html = _honest_run_label_html({"include_prefixes": ["ghclock_", "ghdyn_"]})
    assert "Activity-recency clocks" in html
    assert "Contributor dynamics" in html
    assert html.count('class="tip tip--below"') == 2
    assert 'data-tip="ghclock_ — nine day-resolution clocks' in html
    # unknown prefixes degrade to the raw name rather than failing
    assert "<code>mystery</code>" in _honest_run_label_html({"include_prefixes": ["mystery_"]})
    # no filter -> explains that the whole input file was used
    html = _honest_run_label_html(
        {"include_prefixes": None, "in_path": "a/b/plugins.monthly.labeled.advisory_only.jsonl"}
    )
    assert "all features in dataset" in html
    assert "plugins.monthly.labeled.advisory_only.jsonl" in html


def test_render_honest_tab_has_tooltips_and_legend() -> None:
    runs = [
        {
            **_run_payload(pooled_roc=0.62, prefixes=["ghclock_"], model="logistic"),
            "run_name": "champ",
        },
        {
            **_run_payload(pooled_roc=0.60, prefixes=["ghclock_", "installs_"], model="xgboost"),
            "run_name": "pair",
        },
    ]
    html = _render_honest_tab(runs)
    # champion card + table row both carry the family tooltip; model names carry theirs
    assert html.count("Activity-recency clocks") == 4  # legend, champion card, 2 table rows
    assert "Install base" in html
    assert 'data-tip="Logistic regression:' in html
    assert 'data-tip="XGBoost gradient-boosted trees:' in html
    # legend lists every family for readers without hover
    assert "What the feature-set names mean" in html
    assert "<code style='font-size:.8rem'>swhdelta_</code>" in html
    # the plain-text label helper is unchanged
    assert _honest_run_label(runs[1]) == "ghclock, installs"


def test_render_honest_tab_metric_tips_and_model_badges() -> None:
    runs = [
        {**_run_payload(pooled_roc=0.62, prefixes=["ghclock_"], model="xgboost"), "run_name": "x"},
        {**_run_payload(pooled_roc=0.60, prefixes=["ghclock_"], model="lightgbm"), "run_name": "l"},
        {**_run_payload(pooled_roc=0.58, prefixes=["ghclock_"], model="logistic"), "run_name": "g"},
    ]
    html = _render_honest_tab(runs)
    # the ML tab's model badges, wrapped in a hover description
    assert '<span class="model-badge model-badge--xgb">XGBoost</span>' in html
    assert '<span class="model-badge model-badge--lgb">LightGBM</span>' in html
    assert '<span class="model-badge ">Logistic Regression</span>' in html
    assert 'tip--plain" data-tip="XGBoost gradient-boosted trees:' in html
    # metric tooltips on the champion card, the run table and the per-fold table
    for label in (
        "Pooled ROC-AUC",
        "Pooled AP",
        "AP lift",
        "Fold ROC mean (range)",
        "Folds",
        "Positives",
        "Protocol",
        "Test window",
        "Labels as-of",
    ):
        assert f">{label}</span>" in html, label
    assert html.count('data-tip="ROC-AUC computed once over the concatenated') >= 2


def test_render_honest_tab_degenerate_runs_do_not_crash() -> None:
    """Inputs the tool can genuinely produce must render, not raise.

    Overlapping test windows (``--step`` < ``--test-months``) make the tool write
    ``pooled: null``; a model name outside the registry descriptions gets a plain
    badge; a run without folds gets no per-fold table; and a directory holding only
    stored-label runs has no champion card.
    """
    overlapping = {
        **_run_payload(embargo=False, pooled_roc=None, prefixes=["ghclock_"], model="extra_trees"),
        "run_name": "overlap",
        "test_windows_overlap": True,
    }
    overlapping["folds"] = []
    html = _render_honest_tab([overlapping])
    assert "Best embargoed result" not in html
    assert "Per-fold detail" not in html
    assert html.count("—") >= 3  # pooled ROC, AP and lift are all unknown
    assert "EXTRA_TREES" in html  # model badge without a description
    assert html.count("stored labels</span>") == 1


# ---------------------------------------------------------------------------
# Out-of-time window classification (docs/panel_extension_protocol.md)
# ---------------------------------------------------------------------------


def test_loader_classifies_windows_and_orders_development_before_oot(results_root: Path) -> None:
    _write_run(
        results_root,
        "oot_champ",
        _run_payload(pooled_roc=0.67, prefixes=["ghclock_"], fold_month="2025-07"),
    )
    _write_run(results_root, "dev_champ", _run_payload(pooled_roc=0.64, prefixes=["ghclock_"]))
    _write_run(results_root, "dev_champ_asof", _run_payload(pooled_roc=0.65, prefixes=["ghclock_"]))
    curve = _run_payload(pooled_roc=0.66, prefixes=["ghclock_"])
    curve["folds"] = curve["folds"] + [{**curve["folds"][0], "test_start_month": "2025-11"}]
    _write_run(results_root, "curve", curve)
    runs = webapp._load_rolling_backtests()
    by_name = {r["run_name"]: r for r in runs}
    assert by_name["dev_champ"]["window_kind"] == "development"
    assert by_name["oot_champ"]["window_kind"] == "out_of_time"
    assert by_name["curve"]["window_kind"] == "mixed"
    assert by_name["dev_champ_asof"]["sensitivity"] is True
    assert by_name["dev_champ"]["sensitivity"] is False
    # a higher out-of-time or sensitivity ROC never outranks the development sweep
    assert [r["run_name"] for r in runs] == ["dev_champ", "dev_champ_asof", "oot_champ", "curve"]
    assert webapp._rolling_window_kind({"folds": []}) == "development"


def test_render_honest_tab_oot_card_and_window_pills() -> None:
    dev = {
        **_run_payload(pooled_roc=0.638, prefixes=["ghclock_", "ghdyn_"]),
        "run_name": "dev",
        "window_kind": "development",
        "sensitivity": False,
    }
    oot = {
        **_run_payload(pooled_roc=0.670, prefixes=["ghclock_", "ghdyn_"], fold_month="2025-07"),
        "run_name": "oot_champion",
        "window_kind": "out_of_time",
        "sensitivity": False,
    }
    asof = {
        **_run_payload(pooled_roc=0.668, prefixes=["ghclock_", "ghdyn_"], fold_month="2025-07"),
        "run_name": "oot_champion_asof",
        "window_kind": "out_of_time",
        "sensitivity": True,
    }
    html = _render_honest_tab([dev, oot, asof])
    # champion card is the development sweep, not the higher out-of-time number
    champ = html.split("Pre-registered out-of-time result")[0]
    assert "Best embargoed development result" in champ
    assert "0.638" in champ and "0.670" not in champ
    # the out-of-time card pairs the OOT number with its development reference
    card = html.split("Pre-registered out-of-time result")[1].split("All rolling backtest runs")[0]
    assert "0.670" in card and "0.638" in card
    assert "oot_champion_asof" not in card  # sensitivity runs stay out of the primary card
    # window pills in the run table
    assert html.count("<span class='pill pill--good'>out-of-time</span>") == 2
    assert html.count("<span class='pill pill--muted'>development</span>") == 1
    assert html.count("<span class='pill pill--warn'>sensitivity</span>") == 1


def test_render_honest_tab_explains_every_pill_and_header() -> None:
    dev = {
        **_run_payload(pooled_roc=0.638, prefixes=["ghclock_"]),
        "run_name": "dev",
        "window_kind": "development",
        "sensitivity": False,
    }
    leaky = {
        **_run_payload(embargo=False, pooled_roc=0.70, prefixes=["ghclock_"]),
        "run_name": "leaky",
        "window_kind": "development",
        "sensitivity": False,
    }
    oot = {
        **_run_payload(pooled_roc=0.670, prefixes=["ghclock_"], fold_month="2025-07"),
        "run_name": "oot",
        "window_kind": "out_of_time",
        "sensitivity": False,
    }
    asof = {
        **_run_payload(pooled_roc=0.668, prefixes=["ghclock_"], fold_month="2025-07"),
        "run_name": "oot_asof",
        "window_kind": "out_of_time",
        "sensitivity": True,
    }
    curve = {
        **_run_payload(pooled_roc=0.648, prefixes=["ghclock_"]),
        "run_name": "curve",
        "window_kind": "mixed",
        "sensitivity": False,
    }
    html = _render_honest_tab([dev, leaky, oot, asof, curve])
    # every status pill carries a hover description
    for tip_start in (
        "At every fold the training labels were rebuilt",
        "The historical labels as saved",
        "Every fold&#x27;s test window lies at or before",  # escaped inside the attribute
        "Every fold&#x27;s test window lies after",
        "One rolling curve that crosses",
        "The same configuration re-run with one corrected",
    ):
        assert f'data-tip="{tip_start}' in html, tip_start
    # column headers that are not self-explanatory
    for key in (
        "Feature set",
        "Model",
        "Development ROC-AUC",
        "Out-of-time ROC-AUC",
        "Positives / rows",
    ):
        assert f">{key}</span>" in html, key
