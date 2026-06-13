"""
Behavior tests for canary.train.baseline.

Consolidates test_train_baseline.py + test_train_baseline_low_hanging.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from canary.train.baseline import (
    _coerce_numeric,
    _extract_feature_importance,
    _is_numeric_like,
    _load_jsonl,
    _month_to_sortable,
    _parse_month_value,
    _rows_to_matrix,
    _select_feature_columns,
    _split_rows,
    _stable_plugin_bucket,
    _write_predictions_csv,
    train_baseline,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _write_labeled_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_labeled_rows(n_train: int = 30, n_test: int = 10) -> list[dict]:
    rows = []
    for i in range(n_train):
        rows.append(
            {
                "plugin_id": f"plugin-{i}",
                "month": "2025-01",
                "label_advisory_within_6m": i % 2,
                "feat_a": float(i),
                "feat_b": float(n_train - i),
            }
        )
    for i in range(n_test):
        rows.append(
            {
                "plugin_id": f"plugin-test-{i}",
                "month": "2025-11",
                "label_advisory_within_6m": i % 2,
                "feat_a": float(i * 2),
                "feat_b": float(10 - i),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# _load_jsonl
# ---------------------------------------------------------------------------


def test_load_jsonl_skips_blank_lines(tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text('\n{"plugin_id": "git"}\n   \n{"plugin_id": "ant"}\n', encoding="utf-8")
    assert _load_jsonl(path) == [{"plugin_id": "git"}, {"plugin_id": "ant"}]


def test_load_jsonl_invalid_json_reports_line_number(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"plugin_id": "git"}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON on line 2"):
        _load_jsonl(path)


# ---------------------------------------------------------------------------
# _is_numeric_like
# ---------------------------------------------------------------------------


def test_is_numeric_like_none():
    assert _is_numeric_like(None) is True


def test_is_numeric_like_bool():
    assert _is_numeric_like(True) is True
    assert _is_numeric_like(False) is True


def test_is_numeric_like_int():
    assert _is_numeric_like(0) is True
    assert _is_numeric_like(42) is True


def test_is_numeric_like_float():
    assert _is_numeric_like(3.14) is True


def test_is_numeric_like_string():
    assert _is_numeric_like("hello") is False


def test_is_numeric_like_list():
    assert _is_numeric_like([1, 2]) is False


# ---------------------------------------------------------------------------
# _coerce_numeric
# ---------------------------------------------------------------------------


def test_coerce_numeric_none():
    assert _coerce_numeric(None) is None


def test_coerce_numeric_bool_true():
    assert _coerce_numeric(True) == 1.0


def test_coerce_numeric_bool_false():
    assert _coerce_numeric(False) == 0.0


def test_coerce_numeric_int():
    assert _coerce_numeric(5) == 5.0


def test_coerce_numeric_float():
    assert _coerce_numeric(3.5) == 3.5


def test_coerce_numeric_string():
    assert _coerce_numeric("text") is None


# ---------------------------------------------------------------------------
# _parse_month_value
# ---------------------------------------------------------------------------


def test_parse_month_value_month_key():
    assert _parse_month_value({"month": "2025-06", "plugin_id": "my-plugin"}) == "2025-06"


def test_parse_month_value_month_id_key():
    assert _parse_month_value({"month_id": "2025-07"}) == "2025-07"


def test_parse_month_value_period_key():
    assert _parse_month_value({"period": "2025-08"}) == "2025-08"


def test_parse_month_value_yyyymm_key():
    assert _parse_month_value({"yyyymm": 202509}) == "2025-09"


def test_parse_month_value_missing_raises():
    with pytest.raises(KeyError):
        _parse_month_value({"plugin_id": "x"})


# ---------------------------------------------------------------------------
# _month_to_sortable
# ---------------------------------------------------------------------------


def test_month_to_sortable():
    assert _month_to_sortable("2025-03") == (2025, 3)
    assert _month_to_sortable("2024-12") == (2024, 12)


def test_month_to_sortable_ordering():
    assert _month_to_sortable("2024-11") < _month_to_sortable("2025-01")


# ---------------------------------------------------------------------------
# _select_feature_columns
# ---------------------------------------------------------------------------


def test_select_feature_columns_basic():
    rows = [
        {
            "plugin_id": "a",
            "month": "2025-01",
            "label_advisory_within_6m": 0,
            "feat_x": 1.0,
            "feat_y": 2.0,
        },
        {
            "plugin_id": "b",
            "month": "2025-02",
            "label_advisory_within_6m": 1,
            "feat_x": 3.0,
            "feat_y": 4.0,
        },
    ]
    cols = _select_feature_columns(rows, target_col="label_advisory_within_6m")
    assert "feat_x" in cols
    assert "feat_y" in cols
    assert "plugin_id" not in cols
    assert "month" not in cols
    assert "label_advisory_within_6m" not in cols


def test_select_feature_columns_excludes_non_numeric():
    rows = [
        {
            "plugin_id": "a",
            "month": "2025-01",
            "label_advisory_within_6m": 0,
            "numeric": 1.0,
            "text_col": "hello",
        },
    ]
    cols = _select_feature_columns(rows, target_col="label_advisory_within_6m")
    assert "numeric" in cols
    assert "text_col" not in cols


def test_select_feature_columns_excludes_all_none():
    rows = [
        {
            "plugin_id": "a",
            "month": "2025-01",
            "label_advisory_within_6m": 0,
            "all_none": None,
            "has_value": 1.0,
        },
    ]
    cols = _select_feature_columns(rows, target_col="label_advisory_within_6m")
    assert "all_none" not in cols
    assert "has_value" in cols


def test_select_feature_columns_include_prefixes():
    rows = [
        {
            "plugin_id": "a",
            "month": "2025-01",
            "label_advisory_within_6m": 0,
            "gharchive_events": 5,
            "github_stars": 10,
            "other": 1,
        },
    ]
    cols = _select_feature_columns(
        rows, target_col="label_advisory_within_6m", include_prefixes=("gharchive_",)
    )
    assert "gharchive_events" in cols
    assert "github_stars" not in cols
    assert "other" not in cols


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


# ---------------------------------------------------------------------------
# _rows_to_matrix
# ---------------------------------------------------------------------------


def test_rows_to_matrix_basic():
    rows = [{"feat_a": 1.0, "feat_b": 2.0}, {"feat_a": 3.0, "feat_b": None}]
    df = _rows_to_matrix(rows, ["feat_a", "feat_b"])
    assert df.shape == (2, 2)
    assert df["feat_a"][0] == 1.0
    assert bool(pd.isna(df["feat_b"].iloc[1]))


def test_rows_to_matrix_missing_column():
    rows = [{"feat_a": 1.0}]
    df = _rows_to_matrix(rows, ["feat_a", "feat_missing"])
    assert "feat_a" in df.columns
    assert "feat_missing" in df.columns
    assert bool(pd.isna(df["feat_missing"].iloc[0]))


# ---------------------------------------------------------------------------
# _write_predictions_csv
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _extract_feature_importance
# ---------------------------------------------------------------------------


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
            pass

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


# ---------------------------------------------------------------------------
# _stable_plugin_bucket
# ---------------------------------------------------------------------------


def test_stable_plugin_bucket_is_deterministic_and_in_unit_interval():
    first = _stable_plugin_bucket("workflow-cps", seed=42)
    second = _stable_plugin_bucket("workflow-cps", seed=42)
    assert first == second
    assert 0.0 <= first < 1.0


# ---------------------------------------------------------------------------
# _split_rows
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# train_baseline — end-to-end with synthetic dataset
# ---------------------------------------------------------------------------


def test_train_baseline_runs_and_returns_metrics(tmp_path: Path):
    in_path = tmp_path / "labeled.jsonl"
    _write_labeled_jsonl(in_path, _make_labeled_rows())

    metrics = train_baseline(
        in_path=in_path,
        target_col="label_advisory_within_6m",
        out_dir=tmp_path / "model",
        test_start_month="2025-10",
    )

    assert isinstance(metrics, dict)
    assert metrics["train_row_count"] == 30
    assert metrics["test_row_count"] == 10
    assert metrics["feature_count"] >= 1
    assert "confusion_matrix" in metrics
    assert "classification_report" in metrics
    assert (tmp_path / "model" / "metrics.json").exists()
    assert (tmp_path / "model" / "test_predictions.csv").exists()
    assert (tmp_path / "model" / "pr_curve.json").exists()


def test_train_baseline_raises_when_no_usable_rows(tmp_path: Path):
    in_path = tmp_path / "empty.jsonl"
    _write_labeled_jsonl(in_path, [])
    with pytest.raises(ValueError, match="No rows"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
        )


def test_train_baseline_raises_when_no_train_rows(tmp_path: Path):
    in_path = tmp_path / "only_test.jsonl"
    _write_labeled_jsonl(
        in_path,
        [{"plugin_id": "p1", "month": "2025-11", "label_advisory_within_6m": 0, "feat": 1.0}],
    )
    with pytest.raises(ValueError, match="No training rows"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
            test_start_month="2025-01",
        )


def test_train_baseline_raises_when_no_test_rows(tmp_path: Path):
    in_path = tmp_path / "only_train.jsonl"
    _write_labeled_jsonl(
        in_path,
        [{"plugin_id": "p1", "month": "2025-01", "label_advisory_within_6m": 0, "feat": 1.0}],
    )
    with pytest.raises(ValueError, match="No test rows"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
            test_start_month="2025-10",
        )


def test_train_baseline_raises_when_no_feature_columns(tmp_path: Path):
    in_path = tmp_path / "no_features.jsonl"
    _write_labeled_jsonl(
        in_path,
        [
            {"plugin_id": "p1", "month": "2025-01", "label_advisory_within_6m": 0},
            {"plugin_id": "p2", "month": "2025-11", "label_advisory_within_6m": 1},
        ],
    )
    with pytest.raises(ValueError, match="No usable numeric feature"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
            test_start_month="2025-10",
        )


def test_train_baseline_with_include_prefixes(tmp_path: Path):
    in_path = tmp_path / "labeled.jsonl"
    rows = _make_labeled_rows()
    for row in rows:
        row["gharchive_events"] = 1.0
    _write_labeled_jsonl(in_path, rows)

    metrics = train_baseline(
        in_path=in_path,
        target_col="label_advisory_within_6m",
        out_dir=tmp_path / "model",
        test_start_month="2025-10",
        include_prefixes=("gharchive_", "feat_"),
    )
    assert "gharchive_events" in metrics["feature_columns"]


def test_train_baseline_skips_null_target_rows(tmp_path: Path):
    in_path = tmp_path / "with_nulls.jsonl"
    rows = _make_labeled_rows()
    rows.append(
        {
            "plugin_id": "null-target",
            "month": "2025-01",
            "label_advisory_within_6m": None,
            "feat_a": 5.0,
            "feat_b": 3.0,
        }
    )
    _write_labeled_jsonl(in_path, rows)

    metrics = train_baseline(
        in_path=in_path,
        target_col="label_advisory_within_6m",
        out_dir=tmp_path / "model",
        test_start_month="2025-10",
    )
    assert metrics["train_row_count"] == 30
    assert metrics["test_row_count"] == 10
