from __future__ import annotations

import json
import math
from pathlib import Path

import pytest  # pyright: ignore[reportMissingImports]

from canary.build.features_bundle import (
    _iter_registry_records,
    _max_float,
    _mean_float,
    _read_json,
    _read_jsonl,
    _safe_float,
    _sum_float,
)

# ---------------------------------------------------------------------------
# _safe_float
# ---------------------------------------------------------------------------


def test_safe_float_with_int() -> None:
    assert _safe_float(42) == 42.0


def test_safe_float_with_float() -> None:
    assert _safe_float(3.14) == pytest.approx(3.14)


def test_safe_float_with_string_number() -> None:
    assert _safe_float("2.5") == pytest.approx(2.5)


def test_safe_float_with_nan_string() -> None:
    assert _safe_float("nan") is None


def test_safe_float_with_inf_string() -> None:
    assert _safe_float("inf") is None


def test_safe_float_with_negative_inf_string() -> None:
    assert _safe_float("-inf") is None


def test_safe_float_with_none() -> None:
    assert _safe_float(None) is None


def test_safe_float_with_non_numeric_string() -> None:
    assert _safe_float("hello") is None


def test_safe_float_with_math_nan() -> None:
    assert _safe_float(math.nan) is None


def test_safe_float_with_math_inf() -> None:
    assert _safe_float(math.inf) is None


def test_safe_float_with_negative_math_inf() -> None:
    assert _safe_float(-math.inf) is None


def test_safe_float_with_zero() -> None:
    assert _safe_float(0) == 0.0


def test_safe_float_with_negative_number() -> None:
    assert _safe_float(-7.5) == pytest.approx(-7.5)


def test_safe_float_with_empty_string() -> None:
    assert _safe_float("") is None


# ---------------------------------------------------------------------------
# _max_float
# ---------------------------------------------------------------------------


def test_max_float_empty_list() -> None:
    assert _max_float([]) is None


def test_max_float_all_none() -> None:
    assert _max_float([None, None]) is None


def test_max_float_normal_values() -> None:
    assert _max_float([1.0, 5.0, 3.0]) == pytest.approx(5.0)


def test_max_float_mixed_with_none() -> None:
    assert _max_float([None, 2.0, None, 7.0, None]) == pytest.approx(7.0)


def test_max_float_single_value() -> None:
    assert _max_float([42]) == pytest.approx(42.0)


def test_max_float_filters_nan_and_inf() -> None:
    # nan and inf are filtered by _safe_float, so the result should be the valid max
    assert _max_float([math.nan, 3.0, math.inf]) == pytest.approx(3.0)


def test_max_float_all_invalid() -> None:
    assert _max_float([math.nan, math.inf]) is None


# ---------------------------------------------------------------------------
# _mean_float
# ---------------------------------------------------------------------------


def test_mean_float_empty_list() -> None:
    assert _mean_float([]) is None


def test_mean_float_all_none() -> None:
    assert _mean_float([None, None]) is None


def test_mean_float_normal_values() -> None:
    assert _mean_float([1.0, 2.0, 3.0]) == pytest.approx(2.0)


def test_mean_float_mixed_with_none() -> None:
    # None values are excluded → mean of [2.0, 4.0] = 3.0
    assert _mean_float([None, 2.0, None, 4.0]) == pytest.approx(3.0)


def test_mean_float_single_value() -> None:
    assert _mean_float([5.0]) == pytest.approx(5.0)


def test_mean_float_string_numbers() -> None:
    assert _mean_float(["10", "20"]) == pytest.approx(15.0)


# ---------------------------------------------------------------------------
# _sum_float
# ---------------------------------------------------------------------------


def test_sum_float_empty_list() -> None:
    assert _sum_float([]) is None


def test_sum_float_all_none() -> None:
    assert _sum_float([None, None]) is None


def test_sum_float_normal_values() -> None:
    assert _sum_float([1.0, 2.0, 3.0]) == pytest.approx(6.0)


def test_sum_float_mixed_with_none() -> None:
    assert _sum_float([None, 2.0, None, 3.0]) == pytest.approx(5.0)


def test_sum_float_single_value() -> None:
    assert _sum_float([10.0]) == pytest.approx(10.0)


def test_sum_float_with_negative_values() -> None:
    assert _sum_float([-1.0, 2.0, -3.0]) == pytest.approx(-2.0)


def test_sum_float_filters_nan() -> None:
    # nan is excluded → sum of [1.0, 2.0]
    assert _sum_float([1.0, math.nan, 2.0]) == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# _read_jsonl
# ---------------------------------------------------------------------------


def test_read_jsonl_nonexistent_file_returns_empty(tmp_path: Path) -> None:
    result = _read_jsonl(tmp_path / "missing.jsonl")
    assert result == []


def test_read_jsonl_valid_records(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2
    assert result[0]["plugin_id"] == "a"
    assert result[1]["plugin_id"] == "b"


def test_read_jsonl_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n\n\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2


def test_read_jsonl_skips_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\nNOT VALID JSON\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2
    assert result[0]["plugin_id"] == "a"
    assert result[1]["plugin_id"] == "b"


def test_read_jsonl_skips_non_dict_records(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n[1, 2, 3]\n"a string"\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2


def test_read_jsonl_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert _read_jsonl(path) == []


# ---------------------------------------------------------------------------
# _read_json
# ---------------------------------------------------------------------------


def test_read_json_reads_dict(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text('{"key": "value", "count": 42}', encoding="utf-8")
    result = _read_json(path)
    assert result == {"key": "value", "count": 42}


def test_read_json_reads_list(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    result = _read_json(path)
    assert result == [1, 2, 3]


def test_read_json_reads_nested(tmp_path: Path) -> None:
    payload = {"plugin": "test", "scores": [1.0, 2.0], "meta": {"active": True}}
    path = tmp_path / "nested.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    assert _read_json(path) == payload


# ---------------------------------------------------------------------------
# _iter_registry_records
# ---------------------------------------------------------------------------


def test_iter_registry_records_valid(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text(
        '{"plugin_id": "cucumber-reports", "version": "1.0"}\n'
        '{"plugin_id": "workflow-cps", "version": "2.0"}\n',
        encoding="utf-8",
    )
    records = _iter_registry_records(path)
    assert len(records) == 2
    assert records[0]["plugin_id"] == "cucumber-reports"
    assert records[1]["plugin_id"] == "workflow-cps"


def test_iter_registry_records_raises_when_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _iter_registry_records(tmp_path / "nonexistent.jsonl")


def test_iter_registry_records_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text(
        '{"plugin_id": "cucumber-reports"}\n\n\n{"plugin_id": "workflow-cps"}\n',
        encoding="utf-8",
    )
    records = _iter_registry_records(path)
    assert len(records) == 2


def test_iter_registry_records_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text("", encoding="utf-8")
    records = _iter_registry_records(path)
    assert records == []
