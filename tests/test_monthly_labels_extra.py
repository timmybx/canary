"""Tests for canary.build.monthly_labels helper functions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.build.monthly_labels import (
    _build_labels_for_plugin_rows,
    _get_month_value,
    _parse_month_key,
    _row_has_advisory_this_month,
    _write_csv,
    _write_jsonl,
    build_monthly_labels,
)

# ---------------------------------------------------------------------------
# _parse_month_key
# ---------------------------------------------------------------------------


def test_parse_month_key_valid():
    assert _parse_month_key("2025-01") == (2025, 1)
    assert _parse_month_key("2024-12") == (2024, 12)


def test_parse_month_key_ordering():
    keys = ["2025-03", "2024-12", "2025-01"]
    sorted_keys = sorted(keys, key=_parse_month_key)
    assert sorted_keys == ["2024-12", "2025-01", "2025-03"]


# ---------------------------------------------------------------------------
# _get_month_value
# ---------------------------------------------------------------------------


def test_get_month_value_month_key():
    assert _get_month_value({"month": "2025-01"}) == "2025-01"


def test_get_month_value_month_id_key():
    assert _get_month_value({"month_id": "2025-02"}) == "2025-02"


def test_get_month_value_period_key():
    assert _get_month_value({"period": "2025-03"}) == "2025-03"


def test_get_month_value_yyyymm_key_converts():
    # 6-digit numeric yyyymm should convert to yyyy-mm
    result = _get_month_value({"yyyymm": "202504"})
    assert result == "2025-04"


def test_get_month_value_yyyymm_integer():
    result = _get_month_value({"yyyymm": 202504})
    assert result == "2025-04"


def test_get_month_value_yyyymm_non_six_digit_returned_as_str():
    # If yyyymm isn't 6 chars, just return as-is (as str)
    result = _get_month_value({"yyyymm": "20250401"})
    assert result == "20250401"


def test_get_month_value_missing_key_raises():
    with pytest.raises(KeyError, match="missing a recognized month field"):
        _get_month_value({"plugin_id": "something", "value": 1})


# ---------------------------------------------------------------------------
# _row_has_advisory_this_month
# ---------------------------------------------------------------------------


def test_row_has_advisory_this_month_had_advisory_true():
    assert _row_has_advisory_this_month({"had_advisory_this_month": True}) is True


def test_row_has_advisory_this_month_had_advisory_false():
    assert _row_has_advisory_this_month({"had_advisory_this_month": False}) is False


def test_row_has_advisory_this_month_has_advisory_key():
    assert _row_has_advisory_this_month({"has_advisory_this_month": True}) is True


def test_row_has_advisory_this_month_advisory_this_month_key():
    assert _row_has_advisory_this_month({"advisory_this_month": True}) is True


def test_row_has_advisory_this_month_advisory_count_positive():
    assert _row_has_advisory_this_month({"advisory_count_this_month": 2}) is True


def test_row_has_advisory_this_month_advisory_count_zero():
    assert _row_has_advisory_this_month({"advisory_count_this_month": 0}) is False


def test_row_has_advisory_this_month_advisory_count_invalid():
    # Invalid count should return False (from fallback)
    assert _row_has_advisory_this_month({"advisory_count_this_month": "not-a-number"}) is False


def test_row_has_advisory_this_month_missing_key_raises():
    with pytest.raises(KeyError, match="missing advisory indicator"):
        _row_has_advisory_this_month({"plugin_id": "no-advisory-key"})


# ---------------------------------------------------------------------------
# _write_jsonl and _write_csv
# ---------------------------------------------------------------------------


def test_write_jsonl_creates_file(tmp_path: Path):
    rows = [{"a": 1}, {"b": 2}]
    out = tmp_path / "out.jsonl"
    _write_jsonl(out, rows)
    assert out.exists()
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1}


def test_write_jsonl_creates_parent_dirs(tmp_path: Path):
    out = tmp_path / "deep" / "nested" / "out.jsonl"
    _write_jsonl(out, [{"x": 1}])
    assert out.exists()


def test_write_jsonl_sort_keys(tmp_path: Path):
    rows = [{"z": 3, "a": 1}]
    out = tmp_path / "out.jsonl"
    _write_jsonl(out, rows)
    line = out.read_text(encoding="utf-8").strip()
    # sort_keys=True means "a" should appear before "z"
    assert line.index('"a"') < line.index('"z"')


def test_write_csv_creates_file(tmp_path: Path):
    rows = [{"plugin_id": "a", "month": "2025-01", "score": 1}]
    out = tmp_path / "out.csv"
    _write_csv(out, rows)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "plugin_id" in content
    assert "month" in content


def test_write_csv_creates_parent_dirs(tmp_path: Path):
    out = tmp_path / "deep" / "out.csv"
    _write_csv(out, [{"a": 1}])
    assert out.exists()


# ---------------------------------------------------------------------------
# _build_labels_for_plugin_rows
# ---------------------------------------------------------------------------


def test_build_labels_single_row_all_null():
    rows = [{"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False}]
    result = _build_labels_for_plugin_rows(rows, horizons=(1, 3))
    assert len(result) == 1
    assert result[0]["label_advisory_within_1m"] is None
    assert result[0]["label_advisory_within_3m"] is None


def test_build_labels_months_until_next_advisory():
    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": True},
    ]
    result = _build_labels_for_plugin_rows(rows, horizons=(1,))
    jan = next(r for r in result if r["month"] == "2025-01")
    assert jan["months_until_next_advisory"] == 2


def test_build_labels_future_advisory_count():
    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": True},
    ]
    result = _build_labels_for_plugin_rows(rows, horizons=(1,))
    jan = next(r for r in result if r["month"] == "2025-01")
    assert jan["future_advisory_count"] == 2


def test_build_labels_no_future_advisory_months_until_is_none():
    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
    ]
    result = _build_labels_for_plugin_rows(rows, horizons=(1,))
    jan = next(r for r in result if r["month"] == "2025-01")
    assert jan["months_until_next_advisory"] is None


# ---------------------------------------------------------------------------
# build_monthly_labels — end-to-end additional cases
# ---------------------------------------------------------------------------


def _write_jsonl_helper(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_build_monthly_labels_multiple_plugins(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "beta", "month": "2025-01", "had_advisory_this_month": True},
        {"plugin_id": "beta", "month": "2025-02", "had_advisory_this_month": False},
    ]
    _write_jsonl_helper(in_path, rows)

    result = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    assert len(result) == 4
    plugin_ids = {r["plugin_id"] for r in result}
    assert plugin_ids == {"alpha", "beta"}


def test_build_monthly_labels_writes_csv(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    csv_path = tmp_path / "out.csv"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
    ]
    _write_jsonl_helper(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=csv_path,
        summary_path=None,
        horizons=(1,),
    )

    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "plugin_id" in content


def test_build_monthly_labels_writes_summary(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    summary_path = tmp_path / "summary.json"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
    ]
    _write_jsonl_helper(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=summary_path,
        horizons=(1,),
    )

    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert "row_count" in summary
    assert summary["row_count"] == 2
    assert "plugin_count" in summary
    assert summary["plugin_count"] == 1


def test_build_monthly_labels_invalid_json_raises(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    in_path.write_text("valid json\nnot valid {{{", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON on line"):
        build_monthly_labels(
            in_path=in_path,
            out_path=out_path,
            out_csv_path=None,
            summary_path=None,
        )


def test_build_monthly_labels_yyyymm_format(tmp_path: Path):
    """Test that yyyymm-formatted month fields are handled correctly."""
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "yyyymm": "202501", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "yyyymm": "202502", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "yyyymm": "202503", "had_advisory_this_month": False},
    ]
    _write_jsonl_helper(in_path, rows)

    result = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    assert len(result) == 3
    jan = next(r for r in result if r["yyyymm"] == "202501")
    assert jan["label_advisory_within_1m"] == 1
