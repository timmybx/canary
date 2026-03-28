"""Additional tests for canary.build.monthly_labels."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from canary.build.monthly_labels import (
    _get_month_value,
    _load_jsonl,
    _parse_month_key,
    _row_has_advisory_this_month,
    build_monthly_labels,
)

# ---------------------------------------------------------------------------
# _parse_month_key
# ---------------------------------------------------------------------------


def test_parse_month_key_basic():
    assert _parse_month_key("2025-03") == (2025, 3)


def test_parse_month_key_december():
    assert _parse_month_key("2024-12") == (2024, 12)


def test_parse_month_key_ordering():
    assert _parse_month_key("2024-11") < _parse_month_key("2025-01")


# ---------------------------------------------------------------------------
# _get_month_value
# ---------------------------------------------------------------------------


def test_get_month_value_month_key():
    assert _get_month_value({"month": "2025-01"}) == "2025-01"


def test_get_month_value_month_id_key():
    assert _get_month_value({"month_id": "2025-02"}) == "2025-02"


def test_get_month_value_period_key():
    assert _get_month_value({"period": "2025-03"}) == "2025-03"


def test_get_month_value_yyyymm_key_6_digits():
    assert _get_month_value({"yyyymm": "202504"}) == "2025-04"


def test_get_month_value_yyyymm_key_integer():
    assert _get_month_value({"yyyymm": 202505}) == "2025-05"


def test_get_month_value_yyyymm_key_non_6digits():
    # Non-6-digit yyyymm: returned as-is
    result = _get_month_value({"yyyymm": "short"})
    assert result == "short"


def test_get_month_value_missing_raises():
    with pytest.raises(KeyError, match="month"):
        _get_month_value({"plugin_id": "x"})


# ---------------------------------------------------------------------------
# _row_has_advisory_this_month
# ---------------------------------------------------------------------------


def test_row_has_advisory_had_advisory_this_month_true():
    assert _row_has_advisory_this_month({"had_advisory_this_month": True}) is True


def test_row_has_advisory_had_advisory_this_month_false():
    assert _row_has_advisory_this_month({"had_advisory_this_month": False}) is False


def test_row_has_advisory_has_advisory_this_month():
    assert _row_has_advisory_this_month({"has_advisory_this_month": 1}) is True


def test_row_has_advisory_advisory_this_month():
    assert _row_has_advisory_this_month({"advisory_this_month": True}) is True


def test_row_has_advisory_advisory_count_nonzero():
    assert _row_has_advisory_this_month({"advisory_count_this_month": 3}) is True


def test_row_has_advisory_advisory_count_zero():
    assert _row_has_advisory_this_month({"advisory_count_this_month": 0}) is False


def test_row_has_advisory_advisory_count_invalid():
    assert _row_has_advisory_this_month({"advisory_count_this_month": "bad"}) is False


def test_row_has_advisory_missing_raises():
    with pytest.raises(KeyError):
        _row_has_advisory_this_month({"plugin_id": "x", "month": "2025-01"})


# ---------------------------------------------------------------------------
# _load_jsonl
# ---------------------------------------------------------------------------


def test_load_jsonl_basic(tmp_path: Path):
    p = tmp_path / "data.jsonl"
    p.write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
    rows = _load_jsonl(p)
    assert rows == [{"a": 1}, {"b": 2}]


def test_load_jsonl_skips_blank_lines(tmp_path: Path):
    p = tmp_path / "data.jsonl"
    p.write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    rows = _load_jsonl(p)
    assert len(rows) == 2


def test_load_jsonl_raises_on_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"a":1}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        _load_jsonl(p)


# ---------------------------------------------------------------------------
# build_monthly_labels — CSV and summary outputs
# ---------------------------------------------------------------------------


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_build_monthly_labels_writes_csv(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    csv_path = tmp_path / "out.csv"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=csv_path,
        summary_path=None,
        horizons=(1,),
    )

    assert csv_path.exists()
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)
    assert len(csv_rows) == 3
    assert "label_advisory_within_1m" in csv_rows[0]


def test_build_monthly_labels_writes_summary(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    summary_path = tmp_path / "summary.json"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=summary_path,
        horizons=(1, 3),
    )

    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["row_count"] == 3
    assert summary["plugin_count"] == 1
    assert "label_advisory_within_1m" in summary["label_non_null_counts"]
    assert "label_advisory_within_3m" in summary["label_non_null_counts"]


def test_build_monthly_labels_multiple_plugins(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "beta", "month": "2025-01", "had_advisory_this_month": True},
        {"plugin_id": "beta", "month": "2025-02", "had_advisory_this_month": False},
    ]
    _write_jsonl(in_path, rows)

    labeled = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    assert len(labeled) == 4
    plugin_ids = {r["plugin_id"] for r in labeled}
    assert plugin_ids == {"alpha", "beta"}


def test_build_monthly_labels_months_until_next_advisory(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": True},
    ]
    _write_jsonl(in_path, rows)

    labeled = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["months_until_next_advisory"] == 2

    feb = next(r for r in labeled if r["month"] == "2025-02")
    assert feb["months_until_next_advisory"] == 1

    mar = next(r for r in labeled if r["month"] == "2025-03")
    assert mar["months_until_next_advisory"] is None


def test_build_monthly_labels_future_advisory_count(tmp_path: Path):
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "had_advisory_this_month": False},
        {"plugin_id": "alpha", "month": "2025-02", "had_advisory_this_month": True},
        {"plugin_id": "alpha", "month": "2025-03", "had_advisory_this_month": True},
    ]
    _write_jsonl(in_path, rows)

    labeled = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["future_advisory_count"] == 2


def test_build_monthly_labels_uses_advisory_count_this_month_fallback(tmp_path: Path):
    """Rows using advisory_count_this_month instead of had_advisory_this_month."""
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"

    rows = [
        {"plugin_id": "alpha", "month": "2025-01", "advisory_count_this_month": 0},
        {"plugin_id": "alpha", "month": "2025-02", "advisory_count_this_month": 2},
    ]
    _write_jsonl(in_path, rows)

    labeled = build_monthly_labels(
        in_path=in_path,
        out_path=out_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )

    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == 1
