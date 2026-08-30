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
) -> dict[str, Any]:
    return {
        "model_name": model,
        "embargo": embargo,
        "include_prefixes": prefixes,
        "folds": [
            {
                "test_start_month": "2024-05",
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
    broken = results_root / "broken"
    broken.mkdir()
    (broken / "rolling_backtest.json").write_text("{not json", encoding="utf-8")
    (results_root / "no_payload").mkdir()
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
    assert "Best embargoed result" in html
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
