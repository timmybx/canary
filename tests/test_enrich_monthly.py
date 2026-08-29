"""
Behavior tests for the advhist_/ghclock_ enrichment
(canary.build.enrich_monthly + tools/enrich_monthly_features.py) and the
filter tool's union-of-columns fix.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

from canary.build.enrich_monthly import (
    ADVHIST_MONTHS_CAP,
    GHCLOCK_DAYS_CAP,
    GHCLOCK_KINDS,
    _month_end,
    build_advhist_features,
    build_ghclock_features,
    collect_event_dates,
    enrich_rows,
)


def _row(plugin: str, month: str, advisories: int = 0, **extra) -> dict:
    return {
        "plugin_id": plugin,
        "month": month,
        "advisory_count_this_month": advisories,
        "feat_a": 1.0,
        **extra,
    }


# ---------------------------------------------------------------------------
# advhist_*
# ---------------------------------------------------------------------------


@pytest.fixture()
def advisory_grid() -> list[dict]:
    """Two plugins over 2024-01..2024-12; p1 hit in 03 (2 advisories) and 08,
    p2 hit in 03 only, p3 never."""
    months = [f"2024-{m:02d}" for m in range(1, 13)]
    rows: list[dict] = []
    for month in months:
        rows.append(
            _row(
                "p1",
                month,
                advisories=2 if month == "2024-03" else (1 if month == "2024-08" else 0),
            )
        )
        rows.append(_row("p2", month, advisories=1 if month == "2024-03" else 0))
        rows.append(_row("p3", month))
    return rows


def test_advhist_is_as_of_and_caps_before_first_advisory(advisory_grid) -> None:
    feats = build_advhist_features(advisory_grid)
    before = feats[("p1", "2024-02")]
    assert before["advhist_has_history"] is False
    assert before["advhist_months_since_last"] == ADVHIST_MONTHS_CAP
    assert before["advhist_months_since_first"] == ADVHIST_MONTHS_CAP
    assert before["advhist_advisory_months_to_date"] == 0
    assert before["advhist_advisory_count_to_date"] == 0
    assert before["advhist_latest_batch_size"] == 0
    assert before["advhist_recency_decay"] == 0.0


def test_advhist_counts_and_recency(advisory_grid) -> None:
    feats = build_advhist_features(advisory_grid)

    at_hit = feats[("p1", "2024-03")]
    assert at_hit["advhist_has_history"] is True
    assert at_hit["advhist_months_since_last"] == 0
    assert at_hit["advhist_advisory_count_to_date"] == 2  # two advisories that month
    assert at_hit["advhist_advisory_months_to_date"] == 1

    later = feats[("p1", "2024-10")]
    assert later["advhist_months_since_last"] == 2  # last hit 2024-08
    assert later["advhist_months_since_first"] == 7  # first hit 2024-03
    assert later["advhist_advisory_months_to_date"] == 2
    assert later["advhist_advisory_count_to_date"] == 3
    assert later["advhist_months_with_advisory_last_12m"] == 2
    assert later["advhist_mean_gap_months"] == 5  # 03 -> 08
    assert 0.0 < later["advhist_recency_decay"] < 1.0


def test_advhist_batch_size_is_ecosystem_wide_and_as_of(advisory_grid) -> None:
    feats = build_advhist_features(advisory_grid)
    # 2024-03 hit both p1 and p2 -> batch size 2 for both, from that month on
    # (until a later advisory replaces "latest").
    assert feats[("p1", "2024-04")]["advhist_latest_batch_size"] == 2
    assert feats[("p2", "2024-12")]["advhist_latest_batch_size"] == 2
    # p1's latest advisory becomes 2024-08 (only p1 hit) from August on.
    assert feats[("p1", "2024-09")]["advhist_latest_batch_size"] == 1


def test_advhist_trailing_window_expires() -> None:
    months = [f"{y}-{m:02d}" for y in (2020, 2021, 2022, 2023) for m in range(1, 13)]
    rows = [_row("p", m, advisories=1 if m == "2020-06" else 0) for m in months]
    feats = build_advhist_features(rows)
    assert feats[("p", "2021-05")]["advhist_months_with_advisory_last_12m"] == 1
    assert feats[("p", "2021-07")]["advhist_months_with_advisory_last_12m"] == 0
    assert feats[("p", "2022-05")]["advhist_months_with_advisory_last_24m"] == 1
    assert feats[("p", "2022-07")]["advhist_months_with_advisory_last_24m"] == 0
    # Recency keeps counting up (capped far later).
    assert feats[("p", "2023-12")]["advhist_months_since_last"] == 42


# ---------------------------------------------------------------------------
# ghclock_*
# ---------------------------------------------------------------------------


def _event(plugin: str, ts: str, event_type: str, **extra) -> dict:
    return {"plugin_id": plugin, "event_ts": ts, "event_type": event_type, **extra}


@pytest.fixture()
def events_dir(tmp_path: Path) -> Path:
    events = [
        _event("p1", "2024-01-10T12:00:00Z", "PushEvent", actor_login="alice"),
        _event("p1", "2024-02-20T09:00:00Z", "PushEvent", actor_login="dependabot[bot]"),
        _event("p1", "2024-03-05T10:00:00Z", "ReleaseEvent"),
        _event("p1", "2024-03-06T10:00:00Z", "PullRequestEvent", action="opened"),
        _event("p1", "2024-03-07T10:00:00Z", "PullRequestEvent", action="closed", pr_merged=True),
        _event("p1", "2024-03-08T10:00:00Z", "PullRequestReviewEvent"),
        _event("p1", "2024-03-09T10:00:00Z", "IssuesEvent", action="opened"),
        _event("p1", "2024-03-10T10:00:00Z", "CreateEvent", ref_type="tag"),
        _event("p1", "2024-03-11T10:00:00Z", "CreateEvent", ref_type="branch"),  # not a tag
        # p2 has no events at all.
    ]
    path = tmp_path / "events"
    path.mkdir()
    with (path / "2024-01.gharchive.events.jsonl").open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return path


def test_ghclock_days_at_month_end_and_bot_split(events_dir: Path) -> None:
    rows = [_row("p1", "2024-02"), _row("p1", "2024-03"), _row("p2", "2024-03")]
    feats = build_ghclock_features(rows, collect_event_dates(events_dir))

    feb = feats[("p1", "2024-02")]
    # Feb 29 2024 (leap year): human push Jan 10 -> 50 days; bot push Feb 20 -> 9 days.
    assert feb["ghclock_days_since_human_push"] == (date(2024, 2, 29) - date(2024, 1, 10)).days
    assert feb["ghclock_days_since_any_push"] == (date(2024, 2, 29) - date(2024, 2, 20)).days
    assert feb["ghclock_days_since_release"] == GHCLOCK_DAYS_CAP  # release is in March
    assert feb["ghclock_has_events"] is True

    mar = feats[("p1", "2024-03")]
    end = date(2024, 3, 31)
    assert mar["ghclock_days_since_release"] == (end - date(2024, 3, 5)).days
    assert mar["ghclock_days_since_pr_opened"] == (end - date(2024, 3, 6)).days
    assert mar["ghclock_days_since_pr_merged"] == (end - date(2024, 3, 7)).days
    assert mar["ghclock_days_since_pr_review"] == (end - date(2024, 3, 8)).days
    assert mar["ghclock_days_since_issue_opened"] == (end - date(2024, 3, 9)).days
    assert mar["ghclock_days_since_tag_create"] == (end - date(2024, 3, 10)).days


def test_ghclock_never_is_capped_not_zero(events_dir: Path) -> None:
    rows = [_row("p2", "2024-03")]
    feats = build_ghclock_features(rows, collect_event_dates(events_dir))
    p2 = feats[("p2", "2024-03")]
    for kind in GHCLOCK_KINDS:
        assert p2[f"ghclock_days_since_{kind}"] == GHCLOCK_DAYS_CAP
    assert p2["ghclock_has_events"] is False


def test_ghclock_branch_create_is_not_a_tag(events_dir: Path) -> None:
    dates = collect_event_dates(events_dir)
    assert dates["p1"]["tag_create"] == [date(2024, 3, 10)]


def test_month_end_handles_december_and_leap() -> None:
    assert _month_end((2024, 2)) == date(2024, 2, 29)
    assert _month_end((2023, 2)) == date(2023, 2, 28)
    assert _month_end((2024, 12)) == date(2024, 12, 31)


def test_collect_event_dates_requires_files(tmp_path: Path) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        collect_event_dates(empty)


# ---------------------------------------------------------------------------
# enrich_rows + CLI
# ---------------------------------------------------------------------------


def test_enrich_rows_preserves_originals_and_adds_families(
    advisory_grid: list[dict], events_dir: Path
) -> None:
    snapshot = json.dumps(advisory_grid, sort_keys=True)
    enriched, summary = enrich_rows(advisory_grid, events_dir=events_dir)

    assert len(enriched) == len(advisory_grid)
    assert json.dumps(advisory_grid, sort_keys=True) == snapshot, "inputs must not be mutated"
    for original, new in zip(advisory_grid, enriched, strict=True):
        for key, value in original.items():
            assert new[key] == value
        assert any(k.startswith("advhist_") for k in new)
        assert any(k.startswith("ghclock_") for k in new)
    assert summary["row_count"] == len(advisory_grid)
    assert summary["added_column_count"] == len(summary["advhist_columns"]) + len(
        summary["ghclock_columns"]
    )


def test_enrich_rows_skip_ghclock(advisory_grid: list[dict]) -> None:
    enriched, summary = enrich_rows(advisory_grid, events_dir=None)
    assert summary["ghclock_columns"] == []
    assert not any(k.startswith("ghclock_") for k in enriched[0])
    assert any(k.startswith("advhist_") for k in enriched[0])


def _load_tool(name: str):
    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_enrich_cli_end_to_end(
    tmp_path: Path, advisory_grid: list[dict], events_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_path = tmp_path / "labeled.jsonl"
    out_path = tmp_path / "enriched.jsonl"
    with in_path.open("w", encoding="utf-8") as f:
        for row in advisory_grid:
            f.write(json.dumps(row) + "\n")

    tool = _load_tool("enrich_monthly_features")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enrich_monthly_features.py",
            "--in-path",
            str(in_path),
            "--out-path",
            str(out_path),
            "--events-dir",
            str(events_dir),
        ],
    )
    assert tool.main() == 0

    lines = [json.loads(x) for x in out_path.read_text(encoding="utf-8").splitlines() if x]
    assert len(lines) == len(advisory_grid)
    assert any(k.startswith("advhist_") for k in lines[0])
    summary = json.loads((tmp_path / "enriched.jsonl.summary.json").read_text(encoding="utf-8"))
    assert summary["row_count"] == len(advisory_grid)


def test_enrich_cli_failure_leaves_no_partial_output(
    tmp_path: Path, advisory_grid: list[dict], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted or failed run must never leave a file at --out-path:
    a partial dataset that parses cleanly is worse than a crash (a truncated
    output was silently trained on before this guarantee existed)."""
    in_path = tmp_path / "labeled.jsonl"
    out_path = tmp_path / "enriched.jsonl"
    with in_path.open("w", encoding="utf-8") as f:
        for row in advisory_grid:
            f.write(json.dumps(row) + "\n")

    tool = _load_tool("enrich_monthly_features")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "x",
            "--in-path",
            str(in_path),
            "--out-path",
            str(out_path),
            "--events-dir",
            str(tmp_path / "missing-events"),
        ],
    )
    with pytest.raises(FileNotFoundError):
        tool.main()
    assert not out_path.exists()
    assert not out_path.with_name(out_path.name + ".tmp").exists()
    assert not Path(str(out_path) + ".summary.json").exists()


def test_enrich_cli_refuses_inplace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    in_path = tmp_path / "labeled.jsonl"
    in_path.write_text("{}\n", encoding="utf-8")
    tool = _load_tool("enrich_monthly_features")
    monkeypatch.setattr(
        sys,
        "argv",
        ["x", "--in-path", str(in_path), "--out-path", str(in_path), "--skip-ghclock"],
    )
    with pytest.raises(SystemExit, match="Refusing to overwrite"):
        tool.main()


# ---------------------------------------------------------------------------
# filter tool: union-of-columns fix
# ---------------------------------------------------------------------------


def test_filter_keeps_sparse_columns_absent_from_first_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        {
            "plugin_id": "a",
            "month": "2024-01",
            "label_advisory_within_6m": 0,
            "advisory_count_to_date": 0,
        },
        {
            "plugin_id": "b",
            "month": "2024-01",
            "label_advisory_within_6m": 1,
            "advisory_count_to_date": 3,
            "advisory_days_since_latest_to_date": 12,
            "advisories_last_365d": 2,
        },
    ]
    in_path = tmp_path / "labeled.jsonl"
    with in_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    out_path = tmp_path / "advisory_only.jsonl"

    tool = _load_tool("filter_monthly_labeled_features")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "x",
            "--in-path",
            str(in_path),
            "--out-path",
            str(out_path),
            "--families",
            "advisory_,advisories_",
        ],
    )
    assert tool.main() == 0

    out_rows = [json.loads(x) for x in out_path.read_text(encoding="utf-8").splitlines() if x]
    # The sparse columns (absent from row 1) must survive, as explicit None
    # on rows that lack them.
    assert "advisory_days_since_latest_to_date" in out_rows[0]
    assert out_rows[0]["advisory_days_since_latest_to_date"] is None
    assert out_rows[1]["advisory_days_since_latest_to_date"] == 12
    assert out_rows[1]["advisories_last_365d"] == 2
