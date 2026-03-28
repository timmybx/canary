"""Tests for canary.train.baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.train.baseline import (
    _coerce_numeric,
    _is_numeric_like,
    _month_to_sortable,
    _parse_month_value,
    _rows_to_matrix,
    _select_feature_columns,
    train_baseline,
)

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
    row = {"month": "2025-06", "plugin_id": "my-plugin"}
    assert _parse_month_value(row) == "2025-06"


def test_parse_month_value_month_id_key():
    row = {"month_id": "2025-07"}
    assert _parse_month_value(row) == "2025-07"


def test_parse_month_value_period_key():
    row = {"period": "2025-08"}
    assert _parse_month_value(row) == "2025-08"


def test_parse_month_value_yyyymm_key():
    row = {"yyyymm": 202509}
    assert _parse_month_value(row) == "2025-09"


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
    # excluded columns must not appear
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


# ---------------------------------------------------------------------------
# _rows_to_matrix
# ---------------------------------------------------------------------------


def test_rows_to_matrix_basic():
    import math

    rows = [
        {"feat_a": 1.0, "feat_b": 2.0},
        {"feat_a": 3.0, "feat_b": None},
    ]
    df = _rows_to_matrix(rows, ["feat_a", "feat_b"])
    assert df.shape == (2, 2)
    assert df["feat_a"][0] == 1.0
    # None coerces to NaN inside a DataFrame
    assert math.isnan(df["feat_b"][1])


def test_rows_to_matrix_missing_column():
    import pandas as pd

    rows = [{"feat_a": 1.0}]
    df = _rows_to_matrix(rows, ["feat_a", "feat_missing"])
    assert "feat_a" in df.columns
    assert "feat_missing" in df.columns
    assert pd.isna(df["feat_missing"][0])


# ---------------------------------------------------------------------------
# train_baseline — end-to-end with tiny synthetic dataset
# ---------------------------------------------------------------------------


def _write_labeled_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_labeled_rows(n_train: int = 30, n_test: int = 10) -> list[dict]:
    """Generate simple synthetic labeled rows for training tests."""
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
    # Output files should exist
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
    rows = [
        {"plugin_id": "p1", "month": "2025-11", "label_advisory_within_6m": 0, "feat": 1.0},
    ]
    _write_labeled_jsonl(in_path, rows)

    with pytest.raises(ValueError, match="No training rows"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
            test_start_month="2025-01",
        )


def test_train_baseline_raises_when_no_test_rows(tmp_path: Path):
    in_path = tmp_path / "only_train.jsonl"
    rows = [
        {"plugin_id": "p1", "month": "2025-01", "label_advisory_within_6m": 0, "feat": 1.0},
    ]
    _write_labeled_jsonl(in_path, rows)

    with pytest.raises(ValueError, match="No test rows"):
        train_baseline(
            in_path=in_path,
            target_col="label_advisory_within_6m",
            out_dir=tmp_path / "model",
            test_start_month="2025-10",
        )


def test_train_baseline_raises_when_no_feature_columns(tmp_path: Path):
    in_path = tmp_path / "no_features.jsonl"
    rows = [
        {"plugin_id": "p1", "month": "2025-01", "label_advisory_within_6m": 0},
        {"plugin_id": "p2", "month": "2025-11", "label_advisory_within_6m": 1},
    ]
    _write_labeled_jsonl(in_path, rows)

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
    # Add a prefixed feature
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
    # Add rows with null target (should be excluded)
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
    # null target row excluded: 30 train + 10 test
    assert metrics["train_row_count"] == 30
    assert metrics["test_row_count"] == 10
