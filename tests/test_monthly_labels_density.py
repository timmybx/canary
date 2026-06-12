"""
Validity guard: horizon labels in monthly_labels.py are positional (the next
H rows are treated as the next H calendar months). These tests pin the
invariant that input rows must be a dense run of consecutive months, and that
violations fail loudly instead of silently mislabeling advisory windows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from canary.build.monthly_labels import build_monthly_labels


def _row(plugin_id: str, month: str, had_advisory: bool = False) -> dict[str, Any]:
    return {
        "plugin_id": plugin_id,
        "month": month,
        "had_advisory_this_month": had_advisory,
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _run(tmp_path: Path, rows: list[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    in_path = tmp_path / "monthly.features.jsonl"
    _write_jsonl(in_path, rows)
    return build_monthly_labels(
        in_path=in_path,
        out_path=tmp_path / "labeled.jsonl",
        out_csv_path=None,
        summary_path=None,
        horizons=(1, 3),
        **kwargs,
    )


def test_dense_months_pass_and_label_correctly(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-02"),
        _row("demo-plugin", "2025-03", had_advisory=True),
        _row("demo-plugin", "2025-04"),
    ]
    labeled = _run(tmp_path, rows)

    by_month = {r["month"]: r for r in labeled}
    # Advisory lands in 2025-03: Jan sees it within 3 months but not 1.
    assert by_month["2025-01"]["label_advisory_within_1m"] == 0
    assert by_month["2025-01"]["label_advisory_within_3m"] == 1
    assert by_month["2025-02"]["label_advisory_within_1m"] == 1
    # Right-censored rows are None, not 0.
    assert by_month["2025-04"]["label_advisory_within_1m"] is None


def test_dense_months_across_year_boundary_pass(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2024-11"),
        _row("demo-plugin", "2024-12"),
        _row("demo-plugin", "2025-01"),
    ]
    labeled = _run(tmp_path, rows)
    assert len(labeled) == 3


def test_month_gap_raises_value_error(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-02"),
        # 2025-03 missing
        _row("demo-plugin", "2025-04", had_advisory=True),
    ]
    with pytest.raises(ValueError, match=r"Month gap for plugin 'demo-plugin'"):
        _run(tmp_path, rows)


def test_gap_error_names_the_offending_months(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-05"),
    ]
    with pytest.raises(ValueError) as excinfo:
        _run(tmp_path, rows)
    message = str(excinfo.value)
    assert "2025-01" in message
    assert "2025-05" in message
    assert "expected 2025-02" in message


def test_duplicate_month_raises_value_error(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-02"),
    ]
    with pytest.raises(ValueError, match=r"Duplicate month 2025-01 for plugin 'demo-plugin'"):
        _run(tmp_path, rows)


def test_gap_in_one_plugin_does_not_pass_because_other_plugin_is_dense(tmp_path: Path) -> None:
    rows = [
        _row("dense-plugin", "2025-01"),
        _row("dense-plugin", "2025-02"),
        _row("gappy-plugin", "2025-01"),
        _row("gappy-plugin", "2025-03"),
    ]
    with pytest.raises(ValueError, match=r"gappy-plugin"):
        _run(tmp_path, rows)


def test_require_dense_months_false_allows_gaps(tmp_path: Path) -> None:
    rows = [
        _row("demo-plugin", "2025-01"),
        _row("demo-plugin", "2025-04", had_advisory=True),
    ]
    labeled = _run(tmp_path, rows, require_dense_months=False)
    # Escape hatch keeps the old (positional) behavior: the caller has
    # explicitly accepted that horizons count rows, not calendar months.
    assert len(labeled) == 2
