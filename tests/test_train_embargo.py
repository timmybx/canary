"""
Behavior tests for the label embargo (as-of relabeling), the bounded test
window, and the rolling-origin backtest tool built on them.

The synthetic dataset is a dense monthly grid labeled by the real
canary.build.monthly_labels code path, so "stored label" here means exactly
what `canary build monthly-labels` would have written.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

from canary.build.monthly_labels import _build_labels_for_plugin_rows
from canary.cli.train import _add_embargo_arguments, _resolve_label_as_of
from canary.train.baseline import (
    _add_months,
    _load_jsonl,
    _month_to_sortable,
    _parse_month_value,
    _split_rows,
    deployment_as_of_month,
    horizon_months_from_target,
    relabel_as_of,
    train_baseline,
)

TARGET = "label_advisory_within_6m"
FIRST_MONTH = (2024, 1)
MONTH_COUNT = 18  # 2024-01 .. 2025-06
PLUGIN_COUNT = 40


def _month_str(key: tuple[int, int]) -> str:
    return f"{key[0]:04d}-{key[1]:02d}"


def _advisory_months_for(plugin_index: int) -> set[str]:
    """Deterministic advisory schedule: every plugin gets 1-2 advisories."""
    first = _add_months(FIRST_MONTH, 2 + (plugin_index * 5) % 15)
    months = {_month_str(first)}
    if plugin_index % 3 == 0:
        months.add(_month_str(_add_months(first, 4)))
    return months


def _make_dense_grid() -> list[dict]:
    """Dense plugin-month grid with stored labels from the real labeler."""
    rows: list[dict] = []
    for p in range(PLUGIN_COUNT):
        advisories = _advisory_months_for(p)
        plugin_rows = []
        for i in range(MONTH_COUNT):
            month = _month_str(_add_months(FIRST_MONTH, i))
            plugin_rows.append(
                {
                    "plugin_id": f"plugin-{p:02d}",
                    "month": month,
                    "advisory_count_this_month": 1 if month in advisories else 0,
                    # Mildly informative features so logistic regression fits.
                    "feat_a": float((p * 7 + i * 3) % 11),
                    "feat_b": float((p + i) % 5),
                    "advisory_count_to_date": float(
                        sum(
                            1
                            for m in advisories
                            if _month_to_sortable(m) <= _add_months(FIRST_MONTH, i)
                        )
                    ),
                }
            )
        rows.extend(_build_labels_for_plugin_rows(plugin_rows, horizons=(6,)))
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


@pytest.fixture(scope="module")
def grid() -> list[dict]:
    return _make_dense_grid()


@pytest.fixture()
def grid_path(tmp_path: Path, grid: list[dict]) -> Path:
    path = tmp_path / "labeled.jsonl"
    _write_jsonl(path, grid)
    return path


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("label_advisory_within_6m", 6),
        ("label_advisory_within_12m", 12),
        ("label_advisory_within_1m", 1),
        ("some_other_label", None),
    ],
)
def test_horizon_months_from_target(target: str, expected: int | None) -> None:
    assert horizon_months_from_target(target) == expected


def test_add_months_wraps_years() -> None:
    assert _add_months((2024, 11), 2) == (2025, 1)
    assert _add_months((2024, 1), 12) == (2025, 1)
    assert _add_months((2025, 6), 0) == (2025, 6)


def test_deployment_as_of_month_is_month_after_test_start() -> None:
    assert deployment_as_of_month("2025-05") == "2025-06"
    assert deployment_as_of_month("2024-12") == "2025-01"
    with pytest.raises(ValueError, match="YYYY-MM"):
        deployment_as_of_month("May 2025")


# ---------------------------------------------------------------------------
# relabel_as_of
# ---------------------------------------------------------------------------


def _train_rows_before(rows: list[dict], month: str) -> list[dict]:
    cut = _month_to_sortable(month)
    return [
        r
        for r in rows
        if r.get(TARGET) is not None and _month_to_sortable(_parse_month_value(r)) < cut
    ]


def test_relabel_as_of_matured_windows_reproduce_stored_labels(grid: list[dict]) -> None:
    train_rows = _train_rows_before(grid, "2024-12")
    labels_before = [r[TARGET] for r in train_rows]
    relabeled, stats = relabel_as_of(grid, train_rows, target_col=TARGET, as_of_month="2025-01")

    assert stats["matured_mismatch"] == 0
    assert stats["train_rows"] == len(train_rows)
    for original, new in zip(train_rows, relabeled, strict=True):
        window_end = _add_months(_month_to_sortable(original["month"]), 6)
        if window_end < (2025, 1):  # fully matured before the as-of month
            assert new[TARGET] == original[TARGET]
    # Input rows are never mutated.
    assert [r[TARGET] for r in train_rows] == labels_before
    assert relabeled is not train_rows


def test_relabel_as_of_withholds_only_future_advisories(grid: list[dict]) -> None:
    """A row is positive only because of an advisory published at/after as-of -> 0."""
    train_rows = _train_rows_before(grid, "2024-12")
    as_of = "2024-12"  # stricter than deployment (withholds December too)
    relabeled, stats = relabel_as_of(grid, train_rows, target_col=TARGET, as_of_month=as_of)

    by_key = {(r["plugin_id"], r["month"]): r for r in relabeled}
    advisory_months = {
        p: {
            _month_to_sortable(r["month"])
            for r in grid
            if r["plugin_id"] == p and r["advisory_count_this_month"]
        }
        for p in {r["plugin_id"] for r in grid}
    }
    flipped = 0
    for original in train_rows:
        key = _month_to_sortable(original["month"])
        window = {_add_months(key, i) for i in range(1, 7)}
        hits = advisory_months[original["plugin_id"]] & window
        knowable = {m for m in hits if m < _month_to_sortable(as_of)}
        expected = int(bool(knowable))
        assert by_key[(original["plugin_id"], original["month"])][TARGET] == expected
        if original[TARGET] == 1 and expected == 0:
            flipped += 1
    assert flipped > 0, "fixture must contain rows whose only advisory is in the future"
    assert stats["flipped_1_to_0"] == flipped
    assert stats["positives_as_of"] == stats["positives_stored"] - flipped


def test_relabel_as_of_never_creates_positives(grid: list[dict]) -> None:
    train_rows = _train_rows_before(grid, "2024-12")
    relabeled, _ = relabel_as_of(grid, train_rows, target_col=TARGET, as_of_month="2025-01")
    for original, new in zip(train_rows, relabeled, strict=True):
        assert not (original[TARGET] == 0 and new[TARGET] == 1)


def test_relabel_as_of_detects_inconsistent_stored_labels(grid: list[dict]) -> None:
    train_rows = [dict(r) for r in _train_rows_before(grid, "2024-06")]
    # Corrupt one fully matured stored label.
    train_rows[0][TARGET] = 1 - int(train_rows[0][TARGET])
    with pytest.raises(ValueError, match="disagree with their stored"):
        relabel_as_of(grid, train_rows, target_col=TARGET, as_of_month="2025-01")


def test_relabel_as_of_requires_horizon() -> None:
    with pytest.raises(ValueError, match="horizon"):
        relabel_as_of([], [], target_col="label_custom", as_of_month="2025-01")
    relabeled, stats = relabel_as_of(
        [], [], target_col="label_custom", as_of_month="2025-01", horizon_months=3
    )
    assert relabeled == [] and stats["train_rows"] == 0


def test_relabel_as_of_reconstructs_advisories_from_within_1m_label() -> None:
    """Family-filtered files (e.g. gharchive_only) drop the advisory indicator
    but keep the label columns; the calendar must reconstruct from
    label_advisory_within_1m and produce identical relabeling."""
    rows: list[dict] = []
    for p_idx in range(PLUGIN_COUNT):
        advisories = _advisory_months_for(p_idx)
        plugin_rows = [
            {
                "plugin_id": f"plugin-{p_idx:02d}",
                "month": _month_str(_add_months(FIRST_MONTH, i)),
                "advisory_count_this_month": (
                    1 if _month_str(_add_months(FIRST_MONTH, i)) in advisories else 0
                ),
                "feat_a": float(i),
            }
            for i in range(MONTH_COUNT)
        ]
        rows.extend(_build_labels_for_plugin_rows(plugin_rows, horizons=(1, 6)))

    # Simulate the family filter: keep labels, drop the advisory indicator.
    filtered = [{k: v for k, v in r.items() if k != "advisory_count_this_month"} for r in rows]

    train_full = _train_rows_before(rows, "2024-12")
    train_filtered = _train_rows_before(filtered, "2024-12")
    relabeled_full, stats_full = relabel_as_of(
        rows, train_full, target_col=TARGET, as_of_month="2024-12"
    )
    relabeled_filtered, stats_filtered = relabel_as_of(
        filtered, train_filtered, target_col=TARGET, as_of_month="2024-12"
    )

    assert stats_filtered == stats_full
    assert stats_filtered["flipped_1_to_0"] > 0
    assert [r[TARGET] for r in relabeled_filtered] == [r[TARGET] for r in relabeled_full]


def test_relabel_as_of_rejects_rows_with_no_advisory_source(grid: list[dict]) -> None:
    stripped = [
        {
            k: v
            for k, v in r.items()
            if k not in {"advisory_count_this_month", "label_advisory_within_1m"}
        }
        for r in grid
    ]
    train_rows = _train_rows_before(stripped, "2024-12")
    with pytest.raises(ValueError, match="neither an advisory-this-month indicator"):
        relabel_as_of(stripped, train_rows, target_col=TARGET, as_of_month="2024-12")


def test_relabel_as_of_rejects_bad_month() -> None:
    with pytest.raises(ValueError, match="as_of_month must be YYYY-MM"):
        relabel_as_of([], [], target_col=TARGET, as_of_month="2025/01")


# ---------------------------------------------------------------------------
# train_model / train_baseline integration
# ---------------------------------------------------------------------------


def test_train_baseline_without_as_of_uses_stored_labels(grid_path: Path, tmp_path: Path) -> None:
    metrics = train_baseline(
        in_path=grid_path, target_col=TARGET, out_dir=tmp_path / "m", test_start_month="2024-11"
    )
    stored_positives = sum(
        int(r[TARGET]) for r in _train_rows_before(_load_jsonl(grid_path), "2024-11")
    )
    assert metrics["train_positive_count"] == stored_positives
    assert metrics["label_as_of_month"] is None
    assert metrics["label_as_of_stats"] is None
    assert metrics["label_horizon_months"] == 6
    assert metrics["test_end_month"] is None


def test_train_baseline_as_of_reduces_train_positives_and_records_metadata(
    grid_path: Path, tmp_path: Path
) -> None:
    plain = train_baseline(
        in_path=grid_path, target_col=TARGET, out_dir=tmp_path / "plain", test_start_month="2024-11"
    )
    embargoed = train_baseline(
        in_path=grid_path,
        target_col=TARGET,
        out_dir=tmp_path / "embargo",
        test_start_month="2024-11",
        label_as_of_month="2024-12",
    )

    stats = embargoed["label_as_of_stats"]
    assert embargoed["label_as_of_month"] == "2024-12"
    assert stats["flipped_1_to_0"] > 0
    assert stats["matured_mismatch"] == 0
    assert (
        embargoed["train_positive_count"] == plain["train_positive_count"] - stats["flipped_1_to_0"]
    )
    # Same rows, same features, same test set: only the training labels changed.
    assert embargoed["train_row_count"] == plain["train_row_count"]
    assert embargoed["test_row_count"] == plain["test_row_count"]
    assert embargoed["test_positive_count"] == plain["test_positive_count"]
    assert embargoed["feature_columns"] == plain["feature_columns"]

    saved = json.loads((tmp_path / "embargo" / "metrics.json").read_text(encoding="utf-8"))
    assert saved["label_as_of_month"] == "2024-12"
    assert saved["label_as_of_stats"]["flipped_1_to_0"] == stats["flipped_1_to_0"]


def test_train_baseline_rejects_as_of_inside_test_label_window(grid_path: Path, tmp_path: Path):
    with pytest.raises(ValueError, match="more than one month after"):
        train_baseline(
            in_path=grid_path,
            target_col=TARGET,
            out_dir=tmp_path / "m",
            test_start_month="2024-11",
            label_as_of_month="2025-01",
        )


def test_train_baseline_allows_deployment_as_of(grid_path: Path, tmp_path: Path) -> None:
    metrics = train_baseline(
        in_path=grid_path,
        target_col=TARGET,
        out_dir=tmp_path / "m",
        test_start_month="2024-11",
        label_as_of_month=deployment_as_of_month("2024-11"),
    )
    assert metrics["label_as_of_month"] == "2024-12"


def test_train_baseline_test_end_month_bounds_test_window(grid_path: Path, tmp_path: Path) -> None:
    open_ended = train_baseline(
        in_path=grid_path, target_col=TARGET, out_dir=tmp_path / "a", test_start_month="2024-10"
    )
    bounded = train_baseline(
        in_path=grid_path,
        target_col=TARGET,
        out_dir=tmp_path / "b",
        test_start_month="2024-10",
        test_end_month="2024-11",
    )
    assert bounded["test_end_month"] == "2024-11"
    assert bounded["test_row_count"] == 2 * PLUGIN_COUNT
    assert bounded["test_row_count"] < open_ended["test_row_count"]
    assert bounded["train_row_count"] == open_ended["train_row_count"]


def test_split_rows_rejects_test_end_before_start() -> None:
    with pytest.raises(ValueError, match="precedes"):
        _split_rows(
            [],
            split_strategy="time",
            test_start_month="2024-10",
            group_col="plugin_id",
            test_fraction=0.2,
            random_seed=42,
            test_end_month="2024-09",
        )


def test_train_baseline_accepts_preloaded_rows(grid_path: Path, tmp_path: Path) -> None:
    rows = _load_jsonl(grid_path)
    snapshot = json.dumps(rows, sort_keys=True)
    from_rows = train_baseline(
        in_path=grid_path,
        target_col=TARGET,
        out_dir=tmp_path / "rows",
        test_start_month="2024-11",
        label_as_of_month="2024-12",
        rows=rows,
    )
    from_disk = train_baseline(
        in_path=grid_path,
        target_col=TARGET,
        out_dir=tmp_path / "disk",
        test_start_month="2024-11",
        label_as_of_month="2024-12",
    )
    assert from_rows["average_precision"] == from_disk["average_precision"]
    assert json.dumps(rows, sort_keys=True) == snapshot, "caller's rows must not be mutated"


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def test_cli_embargo_flags_parse() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-start-month", default="2025-05")
    _add_embargo_arguments(parser)
    args = parser.parse_args(["--embargo", "--test-end-month", "2025-06"])
    assert args.embargo is True
    assert args.test_end_month == "2025-06"
    assert args.label_as_of_month is None


def _ns(**kwargs: object) -> argparse.Namespace:
    return argparse.Namespace(test_start_month="2025-05", **kwargs)


def test_resolve_label_as_of_shorthand_and_explicit() -> None:
    assert _resolve_label_as_of(_ns()) is None
    assert _resolve_label_as_of(_ns(embargo=True)) == "2025-06"
    assert _resolve_label_as_of(_ns(label_as_of_month="2025-03")) == "2025-03"
    # Explicit month equal to the shorthand default is fine; a different one is an error.
    assert _resolve_label_as_of(_ns(embargo=True, label_as_of_month="2025-06")) == "2025-06"
    with pytest.raises(SystemExit, match="Pass only one"):
        _resolve_label_as_of(_ns(embargo=True, label_as_of_month="2025-01"))


# ---------------------------------------------------------------------------
# tools/rolling_backtest.py
# ---------------------------------------------------------------------------


def _load_rolling_module():
    path = Path(__file__).resolve().parents[1] / "tools" / "rolling_backtest.py"
    spec = importlib.util.spec_from_file_location("rolling_backtest", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fold_months_steps_and_validates() -> None:
    rolling = _load_rolling_module()
    assert rolling.fold_months("2024-11", "2025-03", 2) == ["2024-11", "2025-01", "2025-03"]
    assert rolling.fold_months("2024-11", "2024-11", 1) == ["2024-11"]
    with pytest.raises(ValueError, match="after end"):
        rolling.fold_months("2025-01", "2024-11", 1)
    with pytest.raises(ValueError, match="step"):
        rolling.fold_months("2024-11", "2025-01", 0)


def test_rolling_backtest_writes_per_fold_and_pooled_summary(
    grid_path: Path, tmp_path: Path
) -> None:
    rolling = _load_rolling_module()
    out_dir = tmp_path / "rolling"
    result = rolling.run_rolling_backtest(
        in_path=grid_path,
        model_name="logistic",
        out_dir=out_dir,
        start="2024-08",
        end="2024-11",
        step=2,
        test_months=2,
        target_col=TARGET,
    )

    assert [f["test_start_month"] for f in result["folds"]] == ["2024-08", "2024-10"]
    for fold in result["folds"]:
        assert fold["label_as_of_month"] == deployment_as_of_month(fold["test_start_month"])
        assert fold["test_row_count"] == 2 * PLUGIN_COUNT
        assert fold["label_as_of_stats"]["matured_mismatch"] == 0
        assert (Path(fold["out_dir"]) / "metrics.json").exists()
    assert result["summary"]["fold_count"] == 2
    assert result["summary"]["total_test_rows"] == 4 * PLUGIN_COUNT
    assert result["test_windows_overlap"] is False
    assert result["pooled"] is not None
    assert result["pooled"]["n_rows"] == 4 * PLUGIN_COUNT
    assert 0.0 <= result["pooled"]["roc_auc"] <= 1.0

    saved = json.loads((out_dir / "rolling_backtest.json").read_text(encoding="utf-8"))
    assert saved["embargo"] is True
    assert saved["summary"]["roc_auc"]["n"] == 2
    assert "ci95_descriptive" in saved["summary"]["roc_auc"]


def test_rolling_backtest_no_embargo_and_overlapping_windows(grid_path: Path, tmp_path: Path):
    rolling = _load_rolling_module()
    result = rolling.run_rolling_backtest(
        in_path=grid_path,
        model_name="logistic",
        out_dir=tmp_path / "rolling",
        start="2024-10",
        end="2024-11",
        step=1,
        test_months=2,
        target_col=TARGET,
        embargo=False,
    )
    assert all(f["label_as_of_month"] is None for f in result["folds"])
    assert all(f["label_as_of_stats"] is None for f in result["folds"])
    assert result["test_windows_overlap"] is True
    assert result["pooled"] is None
