"""
Behavior tests for canary.train.feature_selection.

Consolidates test_feature_selection_gaps.py + test_feature_selection_more.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import canary.train.feature_selection as fs
from canary.train.feature_selection import (
    _WINDOW_FEATURES,
    DEFAULT_SUBSET_SIZES,
    compute_shap_global_importance,
    run_feature_selection,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_pipeline(model_step: object, imputer_step: object | None = None) -> MagicMock:
    """Build a minimal mock sklearn Pipeline without auto-creating named_steps."""
    pipeline = MagicMock(spec=[])
    named_steps: dict[str, object] = {"model": model_step}
    if imputer_step is not None:
        named_steps["impute"] = imputer_step
    pipeline.named_steps = named_steps
    return pipeline


def _make_X_test(n_rows: int = 10, n_cols: int = 5) -> object:
    X = MagicMock(spec=[])
    X.values = np.zeros((n_rows, n_cols))
    X.shape = (n_rows, n_cols)
    return X


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    def test_default_subset_sizes_is_tuple(self) -> None:
        assert isinstance(DEFAULT_SUBSET_SIZES, tuple)

    def test_default_subset_sizes_all_positive_ints(self) -> None:
        assert all(isinstance(s, int) and s > 0 for s in DEFAULT_SUBSET_SIZES)

    def test_default_subset_sizes_are_sorted(self) -> None:
        assert list(DEFAULT_SUBSET_SIZES) == sorted(DEFAULT_SUBSET_SIZES)

    def test_window_features_is_frozenset(self) -> None:
        assert isinstance(_WINDOW_FEATURES, frozenset)

    def test_window_features_contains_expected_keys(self) -> None:
        assert "window_index" in _WINDOW_FEATURES
        assert "window_month" in _WINDOW_FEATURES
        assert "window_year" in _WINDOW_FEATURES


# ---------------------------------------------------------------------------
# compute_shap_global_importance — Random Forest fast path (MDI)
# ---------------------------------------------------------------------------


class TestComputeShapGlobalImportanceRFPath:
    def _make_rf_model(self, n_features: int = 5) -> MagicMock:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "RandomForestClassifier"
        model.feature_importances_ = np.array([0.3, 0.2, 0.25, 0.15, 0.1][:n_features])
        return model

    def test_rf_returns_ranked_list(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5)),
            _make_X_test(10, 5),
            ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
        )
        assert isinstance(result, list)
        assert len(result) == 5

    def test_rf_result_is_sorted_descending(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5)),
            _make_X_test(10, 5),
            ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
        )
        scores = [r["mean_abs_shap"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_rf_result_has_required_keys(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5)),
            _make_X_test(10, 5),
            ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
        )
        for entry in result:
            assert "feature" in entry
            assert "mean_abs_shap" in entry
            assert "rank" in entry

    def test_rf_rank_starts_at_one(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5)),
            _make_X_test(10, 5),
            ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
        )
        assert result[0]["rank"] == 1
        assert result[-1]["rank"] == len(result)

    def test_rf_window_features_excluded(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5)),
            _make_X_test(10, 5),
            ["feat_a", "window_index", "feat_c", "window_month", "feat_e"],
        )
        returned_features = {r["feature"] for r in result}
        assert "window_index" not in returned_features
        assert "window_month" not in returned_features
        assert len(result) == 3

    def test_rf_with_imputer_step(self) -> None:
        imputer = MagicMock()
        imputer.transform.return_value = np.zeros((10, 5))
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(5), imputer_step=imputer),
            _make_X_test(10, 5),
            ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
        )
        imputer.transform.assert_called_once()
        assert len(result) == 5

    def test_rf_all_window_features_returns_empty(self) -> None:
        result = compute_shap_global_importance(
            _make_pipeline(self._make_rf_model(3)),
            _make_X_test(10, 3),
            ["window_index", "window_month", "window_year"],
        )
        assert result == []


# ---------------------------------------------------------------------------
# compute_shap_global_importance — SHAP success paths
# ---------------------------------------------------------------------------


def test_compute_shap_global_importance_tree_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeTreeExplainer:
        def __init__(self, model: object) -> None:
            pass

        def shap_values(self, X: np.ndarray) -> list[np.ndarray]:
            return [np.zeros_like(X), np.array([[0.1, -0.5, 0.0], [0.3, -0.1, 0.2]])]

    model = MagicMock(spec=[])
    type(model).__name__ = "XGBClassifier"
    monkeypatch.setitem(sys.modules, "shap", SimpleNamespace(TreeExplainer=FakeTreeExplainer))

    result = compute_shap_global_importance(
        _make_pipeline(model),
        SimpleNamespace(values=np.zeros((2, 3))),
        ["small", "big", "window_year"],
    )
    assert [r["feature"] for r in result] == ["big", "small"]
    assert result[0]["rank"] == 1


def test_compute_shap_global_importance_linear_inner_pipeline_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeLinearExplainer:
        def __init__(self, model, background, feature_perturbation) -> None:
            pass

        def shap_values(self, X: np.ndarray) -> np.ndarray:
            return np.array([[0.2, 0.4, 0.1], [0.2, 0.0, 0.5]])

    clf = LogisticRegression()
    clf.coef_ = np.array([[0.1, 0.2, 0.3]])
    inner = Pipeline([("scale", StandardScaler()), ("clf", clf)])
    inner.named_steps["scale"].fit(np.zeros((2, 3)))
    monkeypatch.setitem(sys.modules, "shap", SimpleNamespace(LinearExplainer=FakeLinearExplainer))

    result = compute_shap_global_importance(
        _make_pipeline(inner),
        SimpleNamespace(values=np.ones((2, 3))),
        ["a", "b", "c"],
    )
    assert [r["feature"] for r in result] == ["c", "a", "b"]


# ---------------------------------------------------------------------------
# compute_shap_global_importance — SHAP fallback path
# ---------------------------------------------------------------------------


class TestComputeShapFallbackPath:
    def test_fallback_to_feature_importances_when_shap_fails(self) -> None:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "XGBClassifier"
        model.feature_importances_ = np.array([0.4, 0.3, 0.2, 0.05, 0.05])

        with patch("shap.TreeExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(
                _make_pipeline(model),
                _make_X_test(10, 5),
                ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
            )
        assert len(result) == 5
        assert result[0]["feature"] == "feat_a"

    def test_fallback_to_coef_when_no_feature_importances(self) -> None:
        model = MagicMock(spec=["coef_"])
        type(model).__name__ = "LogisticRegression"
        model.coef_ = np.array([[0.1, 0.8, 0.3, 0.05, 0.6]])

        with patch("shap.LinearExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(
                _make_pipeline(model),
                _make_X_test(10, 5),
                ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"],
            )
        assert len(result) == 5
        assert result[0]["feature"] == "feat_b"

    def test_last_resort_uniform_importance(self) -> None:
        model = MagicMock(spec=[])
        type(model).__name__ = "SomeUnknownModel"

        with patch("shap.TreeExplainer", side_effect=ImportError("no shap")):
            result = compute_shap_global_importance(
                _make_pipeline(model),
                _make_X_test(10, 3),
                ["feat_a", "feat_b", "feat_c"],
            )
        assert len(result) == 3
        assert all(r["mean_abs_shap"] == 1.0 for r in result)

    def test_fallback_window_features_still_excluded(self) -> None:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "XGBClassifier"
        model.feature_importances_ = np.array([0.4, 0.3, 0.2, 0.05, 0.05])

        with patch("shap.TreeExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(
                _make_pipeline(model),
                _make_X_test(10, 5),
                ["feat_a", "window_index", "feat_c", "window_year", "feat_e"],
            )
        returned_features = {r["feature"] for r in result}
        assert "window_index" not in returned_features
        assert "window_year" not in returned_features
        assert len(result) == 3


# ---------------------------------------------------------------------------
# run_feature_selection
# ---------------------------------------------------------------------------


def test_run_feature_selection_missing_model_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Run 'canary train baseline' first"):
        run_feature_selection(model_dir=tmp_path, in_path=tmp_path / "missing.jsonl")


def test_run_feature_selection_records_success_failure_and_full_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "model.joblib").write_text("placeholder", encoding="utf-8")
    (model_dir / "feature_columns.json").write_text(
        json.dumps(["feat_a", "feat_b", "window_index"]), encoding="utf-8"
    )
    (model_dir / "metrics.json").write_text(
        json.dumps({"model_name": "dummy", "average_precision": 0.5}), encoding="utf-8"
    )

    pipeline = _make_pipeline(DummyClassifier(strategy="prior"))
    rows = [
        {"plugin_id": "p1", "month": "2025-01", "label_advisory_within_6m": 0, "feat_a": 1},
        {"plugin_id": "p2", "month": "2025-02", "label_advisory_within_6m": 1, "feat_b": 2},
    ]

    monkeypatch.setattr(fs.joblib, "load", lambda _path: pipeline)
    monkeypatch.setattr(fs, "_load_jsonl", lambda _path: rows)
    monkeypatch.setattr(fs, "_parse_month_value", lambda r: r["month"])
    monkeypatch.setattr(fs, "_month_to_sortable", lambda m: m)
    monkeypatch.setattr(fs, "_split_rows", lambda usable, **_kw: (usable[:1], usable[1:], None))
    monkeypatch.setattr(
        fs,
        "_rows_to_matrix",
        lambda test_rows, cols: SimpleNamespace(values=np.zeros((1, len(cols)))),
    )
    monkeypatch.setattr(
        fs,
        "compute_shap_global_importance",
        lambda *_args: [
            {"feature": "feat_a", "mean_abs_shap": 0.9, "rank": 1},
            {"feature": "feat_b", "mean_abs_shap": 0.1, "rank": 2},
        ],
    )
    monkeypatch.setattr(
        fs,
        "_select_feature_columns",
        lambda _rows, target_col: ["feat_a", "feat_b"],
    )

    calls: list[set[str]] = []

    def fake_train_model(**kwargs: object) -> dict[str, object]:
        calls.append(set(kwargs["extra_exclude"]))  # type: ignore[arg-type]
        if len(calls) == 1:
            return {"average_precision": 0.46, "roc_auc": 0.7, "feature_count": 1}
        raise RuntimeError("intentional subset failure")

    monkeypatch.setattr(fs, "train_model", fake_train_model)

    result = run_feature_selection(
        model_dir=model_dir,
        in_path=tmp_path / "data.jsonl",
        subset_sizes=(1, 2),
    )

    assert result["h3_satisfied"] is True
    assert result["h3_smallest_qualifying_subset"]["label"] == "top_1"
    assert result["subset_results"][0]["meets_h3_threshold"] is True
    assert result["subset_results"][1]["error"] == "intentional subset failure"
    assert result["subset_results"][-1]["subset_label"] == "full"
    assert calls[0] == {"feat_b"}
    assert (model_dir / "feature_selection.json").exists()


def test_run_feature_selection_random_forest_skips_subset_retraining(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_dir = tmp_path / "rf_model"
    model_dir.mkdir()
    (model_dir / "model.joblib").write_text("placeholder", encoding="utf-8")
    (model_dir / "feature_columns.json").write_text(json.dumps(["feat_a"]), encoding="utf-8")
    (model_dir / "metrics.json").write_text(
        json.dumps({"model_name": "random_forest", "average_precision": 0.25}), encoding="utf-8"
    )

    class RandomForestClassifier:
        feature_importances_ = np.array([1.0])

    pipeline = _make_pipeline(RandomForestClassifier())

    monkeypatch.setattr(fs.joblib, "load", lambda _path: pipeline)
    monkeypatch.setattr(
        fs,
        "_load_jsonl",
        lambda _path: [{"plugin_id": "p", "month": "2025-01", "label_advisory_within_6m": 0}],
    )
    monkeypatch.setattr(fs, "_parse_month_value", lambda r: r["month"])
    monkeypatch.setattr(fs, "_month_to_sortable", lambda m: m)
    monkeypatch.setattr(fs, "_split_rows", lambda usable, **_kw: ([], usable, None))
    monkeypatch.setattr(
        fs, "_rows_to_matrix", lambda *_args: SimpleNamespace(values=np.zeros((1, 1)))
    )
    monkeypatch.setattr(
        fs,
        "compute_shap_global_importance",
        lambda *_args: [{"feature": "feat_a", "mean_abs_shap": 1.0, "rank": 1}],
    )
    monkeypatch.setattr(fs, "_select_feature_columns", lambda *_args, **_kw: ["feat_a"])
    monkeypatch.setattr(
        fs,
        "train_model",
        lambda **_kw: pytest.fail("RF subsets should be skipped"),
    )

    result = run_feature_selection(model_dir=model_dir, in_path=tmp_path / "data.jsonl")
    assert [r["subset_label"] for r in result["subset_results"]] == ["full"]
    assert result["h3_satisfied"] is False
