"""
Tests for canary/train/feature_selection.py

Focuses on the pure-logic paths in compute_shap_global_importance:
  - Random Forest fast path (feature_importances_)
  - Fallback path when SHAP fails
  - Window feature exclusion
  - Constant / module-level values

These tests avoid needing real SHAP, real model files, or real data.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np

from canary.train.feature_selection import (
    _WINDOW_FEATURES,
    DEFAULT_SUBSET_SIZES,
    compute_shap_global_importance,
)

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
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(model_step: object, imputer_step: object | None = None) -> MagicMock:
    """Build a minimal mock sklearn Pipeline without auto-creating named_steps."""
    pipeline = MagicMock(spec=[])  # spec=[] prevents auto-attribute creation
    named_steps: dict[str, object] = {"model": model_step}
    if imputer_step is not None:
        named_steps["impute"] = imputer_step
    pipeline.named_steps = named_steps
    return pipeline


def _make_X_test(n_rows: int = 10, n_cols: int = 5) -> object:
    """Return a minimal mock DataFrame with real numpy values."""
    X = MagicMock(spec=[])
    X.values = np.zeros((n_rows, n_cols))
    X.shape = (n_rows, n_cols)
    return X


# ---------------------------------------------------------------------------
# compute_shap_global_importance — Random Forest fast path
# ---------------------------------------------------------------------------


class TestComputeShapGlobalImportanceRFPath:
    """Random Forest takes the feature_importances_ (MDI) fast path."""

    def _make_rf_model(self, n_features: int = 5) -> MagicMock:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "RandomForestClassifier"
        model.feature_importances_ = np.array([0.3, 0.2, 0.25, 0.15, 0.1][:n_features])
        return model

    def test_rf_returns_ranked_list(self) -> None:
        model = self._make_rf_model(5)
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        assert isinstance(result, list)
        assert len(result) == 5

    def test_rf_result_is_sorted_descending(self) -> None:
        model = self._make_rf_model(5)
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        scores = [r["mean_abs_shap"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_rf_result_has_required_keys(self) -> None:
        model = self._make_rf_model(5)
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        for entry in result:
            assert "feature" in entry
            assert "mean_abs_shap" in entry
            assert "rank" in entry

    def test_rf_rank_starts_at_one(self) -> None:
        model = self._make_rf_model(5)
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        assert result[0]["rank"] == 1
        assert result[-1]["rank"] == len(result)

    def test_rf_window_features_excluded(self) -> None:
        model = self._make_rf_model(5)
        pipeline = _make_pipeline(model)
        # Include a window feature in the list
        feature_cols = ["feat_a", "window_index", "feat_c", "window_month", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        returned_features = {r["feature"] for r in result}
        assert "window_index" not in returned_features
        assert "window_month" not in returned_features
        assert len(result) == 3  # only 3 non-window features

    def test_rf_with_imputer_step(self) -> None:
        model = self._make_rf_model(5)
        imputer = MagicMock()
        imputer.transform.return_value = np.zeros((10, 5))
        pipeline = _make_pipeline(model, imputer_step=imputer)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        imputer.transform.assert_called_once()
        assert len(result) == 5

    def test_rf_all_window_features_returns_empty(self) -> None:
        model = self._make_rf_model(3)
        pipeline = _make_pipeline(model)
        feature_cols = ["window_index", "window_month", "window_year"]
        X_test = _make_X_test(10, 3)

        result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        assert result == []


# ---------------------------------------------------------------------------
# compute_shap_global_importance — SHAP fallback path
# ---------------------------------------------------------------------------


class TestComputeShapFallbackPath:
    """When SHAP fails, falls back to feature_importances_ or coef_."""

    def test_fallback_to_feature_importances_when_shap_fails(self) -> None:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "XGBClassifier"
        model.feature_importances_ = np.array([0.4, 0.3, 0.2, 0.05, 0.05])
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        with patch("shap.TreeExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        assert len(result) == 5
        assert result[0]["feature"] == "feat_a"  # highest importance

    def test_fallback_to_coef_when_no_feature_importances(self) -> None:
        model = MagicMock(spec=["coef_"])
        type(model).__name__ = "LogisticRegression"
        model.coef_ = np.array([[0.1, 0.8, 0.3, 0.05, 0.6]])
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c", "feat_d", "feat_e"]
        X_test = _make_X_test(10, 5)

        with patch("shap.LinearExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        assert len(result) == 5
        assert result[0]["feature"] == "feat_b"  # highest |coef_|

    def test_last_resort_uniform_importance(self) -> None:
        model = MagicMock(spec=[])  # no feature_importances_ or coef_
        type(model).__name__ = "SomeUnknownModel"
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "feat_b", "feat_c"]
        X_test = _make_X_test(10, 3)

        with patch("shap.TreeExplainer", side_effect=ImportError("no shap")):
            result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        # All features should have equal uniform importance
        assert len(result) == 3
        scores = [r["mean_abs_shap"] for r in result]
        assert all(s == 1.0 for s in scores)

    def test_fallback_window_features_still_excluded(self) -> None:
        model = MagicMock(spec=["feature_importances_"])
        type(model).__name__ = "XGBClassifier"
        model.feature_importances_ = np.array([0.4, 0.3, 0.2, 0.05, 0.05])
        pipeline = _make_pipeline(model)
        feature_cols = ["feat_a", "window_index", "feat_c", "window_year", "feat_e"]
        X_test = _make_X_test(10, 5)

        with patch("shap.TreeExplainer", side_effect=ImportError("shap not available")):
            result = compute_shap_global_importance(pipeline, X_test, feature_cols)

        returned_features = {r["feature"] for r in result}
        assert "window_index" not in returned_features
        assert "window_year" not in returned_features
        assert len(result) == 3
