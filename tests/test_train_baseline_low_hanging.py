"""Extra low-hanging coverage tests for canary.train.baseline."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import numpy as np
import pytest

from canary.train.baseline import (
    _extract_feature_importance,
    _load_jsonl,
    _select_feature_columns,
    _split_rows,
    _stable_plugin_bucket,
    _write_predictions_csv,
)


def test_load_jsonl_skips_blank_lines(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('\n{"plugin_id": "git"}\n   \n{"plugin_id": "ant"}\n', encoding="utf-8")

    assert _load_jsonl(path) == [{"plugin_id": "git"}, {"plugin_id": "ant"}]


def test_load_jsonl_invalid_json_reports_line_number(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"plugin_id": "git"}\nnot-json\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON on line 2"):
        _load_jsonl(path)


def test_select_feature_columns_honors_extra_exclude():
    rows = [
        {
            "plugin_id": "git",
            "month": "2025-01",
            "label_advisory_within_6m": 0,
            "keep_me": 1,
            "drop_me": 2,
        }
    ]

    assert _select_feature_columns(
        rows,
        target_col="label_advisory_within_6m",
        extra_exclude={"drop_me"},
    ) == ["keep_me"]


def test_write_predictions_csv_creates_parent_and_normalizes_yyyymm(tmp_path):
    out_path = tmp_path / "nested" / "predictions.csv"

    _write_predictions_csv(
        path=out_path,
        rows=[{"plugin_id": "git", "yyyymm": 202501}],
        y_true=np.array([1]),
        y_prob=np.array([0.875]),
    )

    assert out_path.read_text(encoding="utf-8").splitlines() == [
        "plugin_id,month,y_true,y_prob",
        "git,2025-01,1,0.875",
    ]


def test_extract_feature_importance_uses_unsigned_fallback_for_tree_models():
    class FakeForest:
        feature_importances_ = np.array([0.0, 0.3, 0.7])

    top_positive, top_negative = _extract_feature_importance(
        FakeForest(), ["zero", "small", "large"], "random_forest"
    )

    assert top_positive == [
        {"feature": "large", "importance": 0.7},
        {"feature": "small", "importance": 0.3},
    ]
    assert top_negative == []


def test_extract_feature_importance_uses_signed_shap_for_xgb_like_model(monkeypatch):
    class FakeXGBClassifier:
        pass

    class FakeExplainer:
        def __init__(self, model):
            self.model = model

        def shap_values(self, X_sample):
            assert X_sample == "sample"
            return np.array([[0.2, -0.4, 0.0], [0.4, -0.2, -0.2]])

    monkeypatch.setitem(sys.modules, "shap", SimpleNamespace(TreeExplainer=FakeExplainer))

    top_positive, top_negative = _extract_feature_importance(
        FakeXGBClassifier(), ["raises", "reduces", "mixed"], "xgboost", X_sample="sample"
    )

    assert top_positive == [{"feature": "raises", "mean_shap": 0.3, "mean_abs_shap": 0.3}]
    assert top_negative == [
        {"feature": "reduces", "mean_shap": -0.3, "mean_abs_shap": 0.3},
        {"feature": "mixed", "mean_shap": -0.1, "mean_abs_shap": 0.1},
    ]


def test_extract_feature_importance_falls_back_when_shap_raises(monkeypatch):
    class FakeLGBMClassifier:
        feature_importances_ = np.array([0.25, 0.75])

    class BrokenExplainer:
        def __init__(self, model):
            raise RuntimeError("boom")

    monkeypatch.setitem(sys.modules, "shap", SimpleNamespace(TreeExplainer=BrokenExplainer))

    top_positive, top_negative = _extract_feature_importance(
        FakeLGBMClassifier(), ["a", "b"], "lightgbm", X_sample="sample"
    )

    assert top_positive == [
        {"feature": "b", "importance": 0.75},
        {"feature": "a", "importance": 0.25},
    ]
    assert top_negative == []


def test_stable_plugin_bucket_is_deterministic_and_in_unit_interval():
    first = _stable_plugin_bucket("workflow-cps", seed=42)
    second = _stable_plugin_bucket("workflow-cps", seed=42)

    assert first == second
    assert 0.0 <= first < 1.0


def test_split_rows_group_keeps_group_members_together():
    rows = [
        {"plugin_id": "train-plugin", "month": "2025-01"},
        {"plugin_id": "test-plugin", "month": "2025-02"},
        {"plugin_id": "test-plugin", "month": "2025-03"},
    ]

    train_rows, test_rows, test_groups = _split_rows(
        rows,
        split_strategy="group",
        test_start_month="2025-10",
        group_col="plugin_id",
        test_fraction=1.0,
        random_seed=42,
    )

    assert train_rows == []
    assert test_rows == rows
    assert test_groups == {"test-plugin", "train-plugin"}


def test_split_rows_group_time_requires_test_group_and_future_month():
    rows = [
        {"plugin_id": "p1", "month": "2025-01"},
        {"plugin_id": "p1", "month": "2025-11"},
        {"plugin_id": "p2", "month": "2025-01"},
        {"plugin_id": "p2", "month": "2025-11"},
    ]

    train_rows, test_rows, test_groups = _split_rows(
        rows,
        split_strategy="group_time",
        test_start_month="2025-10",
        group_col="plugin_id",
        test_fraction=1.0,
        random_seed=42,
    )

    assert test_groups == {"p1", "p2"}
    assert train_rows == []
    assert test_rows == [rows[1], rows[3]]


def test_split_rows_unknown_strategy_raises():
    with pytest.raises(ValueError, match="Unknown split_strategy"):
        _split_rows(
            [{"plugin_id": "git", "month": "2025-01"}],
            split_strategy="nope",
            test_start_month="2025-10",
            group_col="plugin_id",
            test_fraction=0.2,
            random_seed=42,
        )
