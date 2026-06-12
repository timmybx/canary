"""
Behavior tests for canary.build.monthly_labels.

Consolidates test_monthly_label.py, test_monthly_labels_extra.py,
test_build_monthly_labels_extra.py, and test_monthly_labels_density.py into
one file organized by behavior. Tests enter through build_monthly_labels()
(the public surface); the few deliberate private-helper tests are marked.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from canary.build.monthly_labels import (
    _get_month_value,
    _parse_month_key,
    build_monthly_labels,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _run(tmp_path: Path, rows: list[dict[str, Any]], **kwargs: Any) -> list[dict[str, Any]]:
    in_path = tmp_path / "in.jsonl"
    _write_jsonl(in_path, rows)
    kwargs.setdefault("out_path", tmp_path / "out.jsonl")
    kwargs.setdefault("out_csv_path", None)
    kwargs.setdefault("summary_path", None)
    kwargs.setdefault("horizons", (1,))
    return build_monthly_labels(in_path=in_path, **kwargs)


def _row(plugin_id: str, month: str, had_advisory: bool = False) -> dict[str, Any]:
    return {
        "plugin_id": plugin_id,
        "month": month,
        "had_advisory_this_month": had_advisory,
    }


# ---------------------------------------------------------------------------
# Horizon labeling: 1 / 0 / None (right-censored)
# ---------------------------------------------------------------------------


def test_label_is_one_when_advisory_falls_inside_horizon(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02", had_advisory=True),
        _row("alpha", "2025-03"),
    ]
    labeled = _run(tmp_path, rows, horizons=(1, 3))

    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == 1
    # not enough future months for the full 3m window -> right-censored
    assert jan["label_advisory_within_3m"] is None


def test_label_is_zero_when_full_window_exists_with_no_advisory(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-02"), _row("alpha", "2025-03")]
    labeled = _run(tmp_path, rows, horizons=(1, 2))

    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == 0
    assert jan["label_advisory_within_2m"] == 0


def test_labels_are_none_when_future_window_is_incomplete(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-02")]
    labeled = _run(tmp_path, rows, horizons=(3,))

    assert all(r["label_advisory_within_3m"] is None for r in labeled)


def test_single_row_has_all_null_labels(tmp_path: Path) -> None:
    labeled = _run(tmp_path, [_row("alpha", "2025-01")], horizons=(1, 3))
    assert len(labeled) == 1
    assert labeled[0]["label_advisory_within_1m"] is None
    assert labeled[0]["label_advisory_within_3m"] is None


# ---------------------------------------------------------------------------
# Future-advisory metadata columns
# ---------------------------------------------------------------------------


def test_months_until_next_advisory(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02"),
        _row("alpha", "2025-03", had_advisory=True),
    ]
    labeled = _run(tmp_path, rows)

    by_month = {r["month"]: r for r in labeled}
    assert by_month["2025-01"]["months_until_next_advisory"] == 2
    assert by_month["2025-02"]["months_until_next_advisory"] == 1
    assert by_month["2025-03"]["months_until_next_advisory"] is None


def test_months_until_next_advisory_is_none_without_future_advisory(tmp_path: Path) -> None:
    labeled = _run(tmp_path, [_row("alpha", "2025-01"), _row("alpha", "2025-02")])
    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["months_until_next_advisory"] is None


def test_future_advisory_count(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02", had_advisory=True),
        _row("alpha", "2025-03", had_advisory=True),
    ]
    labeled = _run(tmp_path, rows)
    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["future_advisory_count"] == 2


# ---------------------------------------------------------------------------
# Month-key contract: rows may use month / month_id / period / yyyymm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("month_key", "values"),
    [
        ("month", ["2025-01", "2025-02", "2025-03"]),
        ("month_id", ["2025-01", "2025-02", "2025-03"]),
        ("period", ["2025-01", "2025-02", "2025-03"]),
        ("yyyymm", ["202501", "202502", "202503"]),
        ("yyyymm", [202501, 202502, 202503]),
    ],
)
def test_all_recognized_month_keys_label_correctly(
    tmp_path: Path, month_key: str, values: list[Any]
) -> None:
    rows = [
        {"plugin_id": "alpha", month_key: v, "had_advisory_this_month": i == 1}
        for i, v in enumerate(values)
    ]
    labeled = _run(tmp_path, rows)

    assert len(labeled) == 3
    first = next(r for r in labeled if str(r[month_key]) == str(values[0]))
    assert first["label_advisory_within_1m"] == 1


def test_missing_month_key_raises_key_error(tmp_path: Path) -> None:
    rows = [{"plugin_id": "alpha", "had_advisory_this_month": False}]
    with pytest.raises(KeyError, match="missing a recognized month field"):
        _run(tmp_path, rows)


# Deliberate private-helper tests: the yyyymm passthrough and tuple ordering
# are contract details of the loose month-key normalization that are not
# cleanly observable through build_monthly_labels (a non-6-digit yyyymm fails
# later, in sorting). Kept narrow on purpose.


def test_helper_contract_non_six_digit_yyyymm_passes_through() -> None:
    assert _get_month_value({"yyyymm": "20250401"}) == "20250401"
    assert _get_month_value({"yyyymm": "short"}) == "short"


def test_helper_contract_month_keys_sort_chronologically() -> None:
    keys = ["2025-03", "2024-12", "2025-01"]
    assert sorted(keys, key=_parse_month_key) == ["2024-12", "2025-01", "2025-03"]


# ---------------------------------------------------------------------------
# Advisory-indicator contract: had_ / has_ / advisory_this_month / count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("indicator", "advisory_value", "quiet_value", "expected_label"),
    [
        ("had_advisory_this_month", True, False, 1),
        ("has_advisory_this_month", True, False, 1),
        ("advisory_this_month", True, False, 1),
        ("advisory_count_this_month", 2, 0, 1),
        # an unparseable count is treated as "no advisory", not an error
        ("advisory_count_this_month", "not-a-number", 0, 0),
    ],
)
def test_all_recognized_advisory_indicators(
    tmp_path: Path,
    indicator: str,
    advisory_value: Any,
    quiet_value: Any,
    expected_label: int,
) -> None:
    rows = [
        {"plugin_id": "alpha", "month": "2025-01", indicator: quiet_value},
        {"plugin_id": "alpha", "month": "2025-02", indicator: advisory_value},
    ]
    labeled = _run(tmp_path, rows)
    jan = next(r for r in labeled if r["month"] == "2025-01")
    assert jan["label_advisory_within_1m"] == expected_label


def test_missing_advisory_indicator_raises_key_error(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        {"plugin_id": "alpha", "month": "2025-02"},  # future row lacks any indicator
    ]
    with pytest.raises(KeyError, match="missing advisory indicator"):
        _run(tmp_path, rows)


# ---------------------------------------------------------------------------
# Month-density validation: positional horizons require consecutive months
# ---------------------------------------------------------------------------


def test_dense_months_across_year_boundary_pass(tmp_path: Path) -> None:
    rows = [_row("alpha", "2024-11"), _row("alpha", "2024-12"), _row("alpha", "2025-01")]
    labeled = _run(tmp_path, rows)
    assert len(labeled) == 3


def test_month_gap_raises_value_error(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02"),
        # 2025-03 missing
        _row("alpha", "2025-04", had_advisory=True),
    ]
    with pytest.raises(ValueError, match=r"Month gap for plugin 'alpha'"):
        _run(tmp_path, rows)


def test_gap_error_names_the_offending_months(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-05")]
    with pytest.raises(ValueError) as excinfo:
        _run(tmp_path, rows)
    message = str(excinfo.value)
    assert "2025-01" in message
    assert "2025-05" in message
    assert "expected 2025-02" in message


def test_duplicate_month_raises_value_error(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-01"), _row("alpha", "2025-02")]
    with pytest.raises(ValueError, match=r"Duplicate month 2025-01 for plugin 'alpha'"):
        _run(tmp_path, rows)


def test_gap_is_attributed_to_the_gappy_plugin(tmp_path: Path) -> None:
    rows = [
        _row("dense-plugin", "2025-01"),
        _row("dense-plugin", "2025-02"),
        _row("gappy-plugin", "2025-01"),
        _row("gappy-plugin", "2025-03"),
    ]
    with pytest.raises(ValueError, match=r"gappy-plugin"):
        _run(tmp_path, rows)


def test_require_dense_months_false_allows_gaps(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-04", had_advisory=True)]
    # Escape hatch keeps the old (positional) behavior: the caller has
    # explicitly accepted that horizons count rows, not calendar months.
    labeled = _run(tmp_path, rows, require_dense_months=False)
    assert len(labeled) == 2


# ---------------------------------------------------------------------------
# Multiple plugins and input handling
# ---------------------------------------------------------------------------


def test_multiple_plugins_are_labeled_independently(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02", had_advisory=True),
        _row("beta", "2025-01", had_advisory=True),
        _row("beta", "2025-02"),
    ]
    labeled = _run(tmp_path, rows)

    assert len(labeled) == 4
    assert {r["plugin_id"] for r in labeled} == {"alpha", "beta"}
    alpha_jan = next(r for r in labeled if r["plugin_id"] == "alpha" and r["month"] == "2025-01")
    beta_jan = next(r for r in labeled if r["plugin_id"] == "beta" and r["month"] == "2025-01")
    assert alpha_jan["label_advisory_within_1m"] == 1
    assert beta_jan["label_advisory_within_1m"] == 0


def test_blank_input_lines_are_skipped(tmp_path: Path) -> None:
    in_path = tmp_path / "in.jsonl"
    body = "\n".join(
        [
            json.dumps(_row("alpha", "2025-01")),
            "",
            json.dumps(_row("alpha", "2025-02")),
        ]
    )
    in_path.write_text(body + "\n", encoding="utf-8")

    labeled = build_monthly_labels(
        in_path=in_path,
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
        horizons=(1,),
    )
    assert len(labeled) == 2


def test_invalid_json_raises_with_line_number(tmp_path: Path) -> None:
    in_path = tmp_path / "in.jsonl"
    in_path.write_text('{"plugin_id": "a", "month": "2025-01"}\nnot valid {{{', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON on line"):
        build_monthly_labels(
            in_path=in_path,
            out_path=tmp_path / "out.jsonl",
            out_csv_path=None,
            summary_path=None,
        )


# ---------------------------------------------------------------------------
# Output artifacts: JSONL, CSV, summary
# ---------------------------------------------------------------------------


def test_jsonl_output_creates_parent_dirs_and_sorts_keys(tmp_path: Path) -> None:
    rows = [_row("alpha", "2025-01"), _row("alpha", "2025-02")]
    out_path = tmp_path / "deep" / "nested" / "out.jsonl"
    _run(tmp_path, rows, out_path=out_path)

    assert out_path.exists()
    first_line = out_path.read_text(encoding="utf-8").splitlines()[0]
    # json.dumps(sort_keys=True): keys appear alphabetically
    assert first_line.index('"had_advisory_this_month"') < first_line.index('"plugin_id"')


def test_csv_output_contains_all_rows_and_label_columns(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02", had_advisory=True),
        _row("alpha", "2025-03"),
    ]
    csv_path = tmp_path / "out.csv"
    _run(tmp_path, rows, out_csv_path=csv_path)

    assert csv_path.exists()
    with csv_path.open(encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    assert len(csv_rows) == 3
    assert "label_advisory_within_1m" in csv_rows[0]


def test_summary_reports_counts_per_horizon(tmp_path: Path) -> None:
    rows = [
        _row("alpha", "2025-01"),
        _row("alpha", "2025-02", had_advisory=True),
        _row("alpha", "2025-03"),
    ]
    summary_path = tmp_path / "summary.json"
    _run(tmp_path, rows, summary_path=summary_path, horizons=(1, 3))

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["row_count"] == 3
    assert summary["plugin_count"] == 1
    assert "label_advisory_within_1m" in summary["label_non_null_counts"]
    assert "label_advisory_within_3m" in summary["label_non_null_counts"]
    assert summary["label_positive_counts"]["label_advisory_within_1m"] == 1
