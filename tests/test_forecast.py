"""Behavior tests for the latest-forecast tool and the Score tab's forecast card."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np  # pyright: ignore[reportMissingImports]
import pandas as pd  # pyright: ignore[reportMissingModuleSource]
import pytest
from sklearn.compose import ColumnTransformer  # pyright: ignore[reportMissingModuleSource]
from sklearn.impute import SimpleImputer  # pyright: ignore[reportMissingModuleSource]
from sklearn.linear_model import LogisticRegression  # pyright: ignore[reportMissingModuleSource]
from sklearn.pipeline import Pipeline  # pyright: ignore[reportMissingModuleSource]

import canary.webapp as webapp
from canary.train import forecast as fc

COLS = ["ghclock_a", "ghdyn_b"]


def _write_fold_model(run_dir: Path, fold: str = "2025-11") -> Path:
    import joblib  # pyright: ignore[reportMissingImports]

    fold_dir = run_dir / f"fold_{fold}"
    fold_dir.mkdir(parents=True)
    X = pd.DataFrame([[1.0, 0.0], [0.0, 1.0], [2.0, 2.0], [0.5, 0.2]], columns=COLS)
    y = np.array([1, 0, 1, 0])
    imputer = ColumnTransformer(
        [("impute_median", SimpleImputer(strategy="median"), COLS)], remainder="drop"
    )
    pipe = Pipeline([("impute", imputer), ("model", LogisticRegression())]).fit(X, y)
    joblib.dump(pipe, fold_dir / "model.joblib")
    (fold_dir / "feature_columns.json").write_text(json.dumps(COLS), encoding="utf-8")
    (fold_dir / "metrics.json").write_text(
        json.dumps(
            {
                "model_name": "logistic",
                "include_prefixes": ["ghclock_", "ghdyn_"],
                "train_start_month": "2023-01",
                "test_start_month": fold,
                "label_as_of_month": "2025-12",
            }
        ),
        encoding="utf-8",
    )
    return fold_dir


def _write_panel(path: Path) -> None:
    rows = [
        {"plugin_id": "a", "month": "2026-05", "ghclock_a": 1.0, "ghdyn_b": 0.0},
        {"plugin_id": "a", "month": "2026-06", "ghclock_a": 2.0, "ghdyn_b": 2.0},
        {"plugin_id": "b", "month": "2026-06", "ghclock_a": None, "ghdyn_b": 1.0},
        {"plugin_id": "c", "month": "2026-06", "ghclock_a": 0.0, "ghdyn_b": 0.0},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_forecast_scores_newest_month_and_ranks_plugins(tmp_path: Path) -> None:
    run_dir = tmp_path / "oot_champion"
    fold_dir = _write_fold_model(run_dir)
    panel = tmp_path / "panel.jsonl"
    _write_panel(panel)
    (run_dir / "rolling_backtest.json").write_text(json.dumps({"in_path": str(panel)}))

    assert fc.run_in_path(fold_dir) == str(panel)
    assert fc.panel_months(panel) == ["2026-05", "2026-06"]

    out = fc.forecast_month(fold_dir, panel)
    assert out["month"] == "2026-06" and out["n_plugins"] == 3
    assert out["run_name"] == "oot_champion" and out["fold"] == "2025-11"
    assert out["train_end_month"] == "2025-11" and out["label_as_of_month"] == "2025-12"
    ranks = {pid: e["rank"] for pid, e in out["scores"].items()}
    assert ranks == {"a": 1, "b": 2, "c": 3}
    assert out["scores"]["a"]["percentile"] == 100.0 and out["scores"]["c"]["percentile"] == 0.0
    # Linear drivers are coefficient × imputed value, largest first; the raw value rides along.
    top = out["scores"]["a"]["drivers"][0]
    assert top["feature"] in COLS and top["value"] == 2.0
    # The missing value in "b" is imputed for scoring but reported as None.
    assert any(d["value"] is None for d in out["scores"]["b"]["drivers"])

    # An explicit earlier month works; an unknown month is refused.
    assert fc.forecast_month(fold_dir, panel, "2026-05")["n_plugins"] == 1
    with pytest.raises(ValueError, match="not in"):
        fc.forecast_month(fold_dir, panel, "2030-01")

    out_path = tmp_path / "out" / "latest_forecast.json"
    fc.write_forecast(out, out_path)
    assert json.loads(out_path.read_text(encoding="utf-8"))["month"] == "2026-06"


def test_score_tab_shows_forecast_card_from_the_forecast_file(
    tmp_path: Path, monkeypatch: Any
) -> None:
    forecast_path = tmp_path / "latest_forecast.json"
    monkeypatch.setattr(webapp, "LATEST_FORECAST_PATH", forecast_path)
    monkeypatch.setattr(webapp, "ROLLING_RESULTS_ROOT", tmp_path / "none")
    score_result = {
        "plugin": "git-client",
        "ml": None,
        "reasons": ["Recent commit activity suggests maintenance."],
        "features": {},
        "pretty_features": "{}",
        "pretty_json": "{}",
    }

    # No file yet: the card says how to make one.
    assert webapp._load_plugin_forecast("git-client") is None
    page = webapp.render_page(
        {"active_tab": "score", "plugin": "git-client"}, score_result=score_result
    )
    assert "no forecast file has been generated yet" in page
    assert "Heuristic · not validated" in page
    assert "ML model (optional)" not in page

    forecast_path.write_text(
        json.dumps(
            {
                "month": "2026-06",
                "run_name": "oot_champion",
                "fold": "2025-11",
                "model_name": "logistic",
                "include_prefixes": ["ghclock_", "ghdyn_"],
                "train_end_month": "2025-11",
                "label_as_of_month": "2025-12",
                "n_plugins": 2053,
                "scores": {
                    "git-client": {
                        "prob": 0.81,
                        "rank": 11,
                        "n": 2053,
                        "percentile": 99.5,
                        "drivers": [
                            {"feature": "ghdyn_active_actors_12m", "contribution": 1.2, "value": 7}
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    entry = webapp._load_plugin_forecast("git-client")
    assert entry is not None and entry["rank"] == 11 and entry["month"] == "2026-06"
    assert webapp._load_plugin_forecast("nobody") is None

    page = webapp.render_page(
        {"active_tab": "score", "plugin": "git-client"}, score_result=score_result
    )
    assert "CANARY forecast · as of 2026-06" in page
    assert "11 of 2,053" in page and "top 0.50%" in page
    assert "ghdyn_active_actors_12m" in page
    # A plugin outside the forecast month gets the "not available" card, not an error.
    page = webapp.render_page(
        {"active_tab": "score", "plugin": "nobody"},
        score_result=dict(score_result, plugin="nobody"),
    )
    assert "No forecast entry for" in page
