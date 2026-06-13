"""
Behavior tests for canary.collectors.gharchive_history.

Consolidates test_gharchive_helpers.py + test_gharchive_history.py
+ test_gharchive_history_more.py.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from canary.collectors import gharchive_history
from canary.collectors.gharchive_history import (
    _build_normalized_event_row,
    _build_raw_event_query_with_sampling,
    _coerce_bool_or_none,
    _event_yyyymm_from_value,
    _fallback_repo_names,
    _infer_repo_url,
    _iter_windows,
    _normalize_date_value,
    _normalize_timestamp_value,
    _parse_yyyymmdd,
    _split_repo_full_name,
    collect_gharchive_history_real,
    resolve_plugin_repo_targets,
)

# ---------------------------------------------------------------------------
# Test helpers / fakes
# ---------------------------------------------------------------------------


class _FakeQueryJob:
    def __init__(self, rows, total_bytes_processed=123456):
        self._rows = rows
        self.total_bytes_processed = total_bytes_processed

    def result(self):
        return self._rows


class _FakeBigQueryModule:
    class QueryJobConfig:
        def __init__(self, query_parameters=None, maximum_bytes_billed=None):
            self.query_parameters = query_parameters or []
            self.maximum_bytes_billed = maximum_bytes_billed

    class ScalarQueryParameter:
        def __init__(self, name, typ, value):
            self.name = name
            self.typ = typ
            self.value = value

    class ArrayQueryParameter:
        def __init__(self, name, typ, values):
            self.name = name
            self.typ = typ
            self.values = values

    class Client:
        def query(self, sql, job_config=None):
            if "INFORMATION_SCHEMA.TABLES" in sql:
                return _FakeQueryJob(
                    [
                        {"table_name": "20260101"},
                        {"table_name": "20260102"},
                    ]
                )
            return _FakeQueryJob(
                [
                    {
                        "repo": "jenkinsci/cucumber-reports-plugin",
                        "event_type": "PushEvent",
                        "event_ts": "2026-01-02T03:04:05Z",
                        "event_date": "2026-01-02",
                        "actor_login": "alice",
                        "action": None,
                        "pr_merged": None,
                        "pr_created_ts": None,
                        "pr_closed_ts": None,
                        "issue_created_ts": None,
                        "issue_closed_ts": None,
                        "text_blob": None,
                    }
                ],
                total_bytes_processed=987654,
            )


class _FakeBigQuery:
    class Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs


# ---------------------------------------------------------------------------
# _coerce_bool_or_none
# ---------------------------------------------------------------------------


def test_coerce_bool_true_returns_true():
    assert _coerce_bool_or_none(True) is True


def test_coerce_bool_false_returns_false():
    assert _coerce_bool_or_none(False) is False


def test_coerce_bool_string_true():
    assert _coerce_bool_or_none("true") is True
    assert _coerce_bool_or_none("True") is True
    assert _coerce_bool_or_none("TRUE") is True
    assert _coerce_bool_or_none("  true  ") is True


def test_coerce_bool_string_false():
    assert _coerce_bool_or_none("false") is False
    assert _coerce_bool_or_none("False") is False
    assert _coerce_bool_or_none("FALSE") is False


def test_coerce_bool_other_string_returns_none():
    assert _coerce_bool_or_none("yes") is None
    assert _coerce_bool_or_none("no") is None
    assert _coerce_bool_or_none("1") is None
    assert _coerce_bool_or_none("") is None


def test_coerce_bool_non_bool_non_string_returns_none():
    assert _coerce_bool_or_none(1) is None
    assert _coerce_bool_or_none(0) is None
    assert _coerce_bool_or_none(None) is None
    assert _coerce_bool_or_none(3.14) is None
    assert _coerce_bool_or_none(["list"]) is None


# ---------------------------------------------------------------------------
# _event_yyyymm_from_value
# ---------------------------------------------------------------------------


def test_event_yyyymm_from_value_none_returns_none():
    assert _event_yyyymm_from_value(None) is None


def test_event_yyyymm_from_value_datetime():
    dt = datetime(2025, 7, 18, 12, 34, 56, tzinfo=UTC)
    assert _event_yyyymm_from_value(dt) == "2025-07"


def test_event_yyyymm_from_value_date():
    d = date(2024, 3, 5)
    assert _event_yyyymm_from_value(d) == "2024-03"


def test_event_yyyymm_from_value_iso_timestamp_string():
    assert _event_yyyymm_from_value("2026-01-15T10:20:30Z") == "2026-01"


def test_event_yyyymm_from_value_string_starts_with_yyyy_dash():
    assert _event_yyyymm_from_value("2023-11-01") == "2023-11"
    assert _event_yyyymm_from_value("2023-11") == "2023-11"


def test_event_yyyymm_from_value_empty_string_returns_none():
    assert _event_yyyymm_from_value("") is None
    assert _event_yyyymm_from_value("   ") is None


def test_event_yyyymm_from_value_non_string_non_date_returns_none():
    assert _event_yyyymm_from_value(42) is None
    assert _event_yyyymm_from_value(3.14) is None


# ---------------------------------------------------------------------------
# _normalize_timestamp_value
# ---------------------------------------------------------------------------


def test_normalize_timestamp_none_returns_none():
    assert _normalize_timestamp_value(None) is None


def test_normalize_timestamp_datetime_with_tz():
    dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    result = _normalize_timestamp_value(dt)
    assert result == "2025-01-15T12:00:00Z"


def test_normalize_timestamp_datetime_without_tz_gets_utc():
    dt = datetime(2025, 6, 20, 8, 30, 0)
    result = _normalize_timestamp_value(dt)
    assert result == "2025-06-20T08:30:00Z"


def test_normalize_timestamp_z_terminated_string():
    result = _normalize_timestamp_value("2025-03-10T14:22:00Z")
    assert result == "2025-03-10T14:22:00Z"


def test_normalize_timestamp_iso_string_without_z():
    result = _normalize_timestamp_value("2025-03-10T14:22:00+00:00")
    assert result == "2025-03-10T14:22:00Z"


def test_normalize_timestamp_non_iso_string_returned_as_is():
    result = _normalize_timestamp_value("not-a-timestamp")
    assert result == "not-a-timestamp"


def test_normalize_timestamp_empty_string_returns_none():
    assert _normalize_timestamp_value("") is None
    assert _normalize_timestamp_value("   ") is None


# ---------------------------------------------------------------------------
# _normalize_date_value
# ---------------------------------------------------------------------------


def test_normalize_date_none_returns_none():
    assert _normalize_date_value(None) is None


def test_normalize_date_datetime_object():
    dt = datetime(2025, 8, 5, 10, 0, 0, tzinfo=UTC)
    assert _normalize_date_value(dt) == "2025-08-05"


def test_normalize_date_date_object():
    d = date(2024, 12, 31)
    assert _normalize_date_value(d) == "2024-12-31"


def test_normalize_date_iso_date_string():
    assert _normalize_date_value("2025-07-04") == "2025-07-04"


def test_normalize_date_timestamp_string_with_T():
    assert _normalize_date_value("2025-07-04T15:30:00Z") == "2025-07-04"


def test_normalize_date_invalid_string_returns_none():
    assert _normalize_date_value("not-a-date") is None


def test_normalize_date_empty_string_returns_none():
    assert _normalize_date_value("") is None
    assert _normalize_date_value("   ") is None


# ---------------------------------------------------------------------------
# _build_raw_event_query_with_sampling
# ---------------------------------------------------------------------------


def test_build_query_raises_for_zero_sample_percent():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=0.0,
        )


def test_build_query_raises_for_negative_sample_percent():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=-5.0,
        )


def test_build_query_raises_for_sample_percent_over_100():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=101.0,
        )


def test_build_query_raises_for_no_matching_tables():
    with pytest.raises(ValueError, match="No GH Archive"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20251201"},
            sample_percent=5.0,
        )


def test_build_query_100_percent_omits_tablesample():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260101",
        available_tables={"20260101"},
        sample_percent=100.0,
    )
    assert "TABLESAMPLE" not in sql


def test_build_query_less_than_100_includes_tablesample():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260101",
        available_tables={"20260101"},
        sample_percent=10.0,
    )
    assert "TABLESAMPLE SYSTEM (10.0 PERCENT)" in sql


def test_build_query_includes_repo_filter():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260102",
        available_tables={"20260101", "20260102"},
        sample_percent=5.0,
    )
    assert "repo.name IN UNNEST(@repo_names)" in sql
    assert "TABLESAMPLE SYSTEM (5.0 PERCENT)" in sql


def test_build_query_unions_multiple_tables():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260103",
        available_tables={"20260101", "20260102", "20260103"},
        sample_percent=100.0,
    )
    assert sql.count("UNION ALL") == 2
    assert "githubarchive.day.20260101" in sql
    assert "githubarchive.day.20260102" in sql
    assert "githubarchive.day.20260103" in sql


def test_build_query_only_includes_available_tables():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260103",
        available_tables={"20260102"},
        sample_percent=100.0,
    )
    assert "githubarchive.day.20260101" not in sql
    assert "githubarchive.day.20260102" in sql
    assert "githubarchive.day.20260103" not in sql


# ---------------------------------------------------------------------------
# _split_repo_full_name
# ---------------------------------------------------------------------------


def test_split_repo_full_name_valid():
    owner, repo = _split_repo_full_name("jenkinsci/my-plugin")
    assert owner == "jenkinsci"
    assert repo == "my-plugin"


def test_split_repo_full_name_empty_string():
    owner, repo = _split_repo_full_name("")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_no_slash():
    owner, repo = _split_repo_full_name("noslash")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_strips_whitespace():
    owner, repo = _split_repo_full_name("  jenkinsci / my-plugin  ")
    assert owner == "jenkinsci"
    assert repo == "my-plugin"


def test_split_repo_full_name_empty_parts_become_none():
    owner, repo = _split_repo_full_name("/")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_only_slash_in_owner():
    owner, repo = _split_repo_full_name("/repo")
    assert owner is None
    assert repo == "repo"


# ---------------------------------------------------------------------------
# _parse_yyyymmdd
# ---------------------------------------------------------------------------


def test_parse_yyyymmdd_valid():
    d = _parse_yyyymmdd("20240101")
    assert d.year == 2024
    assert d.month == 1
    assert d.day == 1


def test_parse_yyyymmdd_another_date():
    d = _parse_yyyymmdd("20231231")
    assert d.year == 2023
    assert d.month == 12
    assert d.day == 31


def test_parse_yyyymmdd_invalid_raises():
    with pytest.raises(ValueError):
        _parse_yyyymmdd("2024-01-01")


# ---------------------------------------------------------------------------
# _fallback_repo_names
# ---------------------------------------------------------------------------


def test_fallback_repo_names_adds_plugin_suffix():
    names = _fallback_repo_names("git")
    assert "jenkinsci/git-plugin" in names
    assert "jenkinsci/git" in names


def test_fallback_repo_names_no_duplicate_plugin_suffix():
    names = _fallback_repo_names("git-plugin")
    assert "jenkinsci/git-plugin-plugin" in names
    assert "jenkinsci/git-plugin" not in names


def test_fallback_repo_names_normalizes_slug():
    names = _fallback_repo_names("My Cool Plugin")
    assert all(n.startswith("jenkinsci/") for n in names)
    assert all(n == n.lower() for n in names)


def test_fallback_repo_names_empty_returns_empty():
    assert _fallback_repo_names("") == []
    assert _fallback_repo_names("   ") == []


# ---------------------------------------------------------------------------
# _infer_repo_url
# ---------------------------------------------------------------------------


def test_infer_repo_url_checks_scm_url_and_plugin_api_fallbacks() -> None:
    assert (
        _infer_repo_url({"scm_url": " https://github.com/jenkinsci/from-scm-url-plugin "})
        == "https://github.com/jenkinsci/from-scm-url-plugin"
    )
    assert (
        _infer_repo_url({"scm_url": {"url": "https://github.com/jenkinsci/from-scm-dict"}})
        == "https://github.com/jenkinsci/from-scm-dict"
    )
    assert (
        _infer_repo_url({"plugin_api": {"scm": "https://github.com/jenkinsci/from-api-scm"}})
        == "https://github.com/jenkinsci/from-api-scm"
    )
    assert (
        _infer_repo_url(
            {"plugin_api": {"scm": {"url": "https://github.com/jenkinsci/from-api-dict"}}}
        )
        == "https://github.com/jenkinsci/from-api-dict"
    )
    assert _infer_repo_url({"plugin_api": {"scm": {}}}) is None


# ---------------------------------------------------------------------------
# _iter_windows
# ---------------------------------------------------------------------------


def test_iter_windows_chunks_range():
    windows = _iter_windows("20260101", "20260110", 4)
    assert windows == [
        ("20260101", "20260104"),
        ("20260105", "20260108"),
        ("20260109", "20260110"),
    ]


# ---------------------------------------------------------------------------
# resolve_plugin_repo_targets
# ---------------------------------------------------------------------------


def test_resolve_plugin_repo_targets_from_snapshot(tmp_path: Path):
    data_dir = tmp_path / "data" / "raw"
    plugins_dir = data_dir / "plugins"
    registry_dir = data_dir / "registry"
    plugins_dir.mkdir(parents=True)
    registry_dir.mkdir(parents=True)

    (plugins_dir / "cucumber-reports.snapshot.json").write_text(
        json.dumps({"repo_url": "https://github.com/jenkinsci/cucumber-reports-plugin"}),
        encoding="utf-8",
    )
    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "cucumber-reports"}) + "\n",
        encoding="utf-8",
    )

    targets = resolve_plugin_repo_targets(
        data_dir=str(data_dir),
        registry_path=str(registry_dir / "plugins.jsonl"),
    )
    assert targets == {"cucumber-reports": "jenkinsci/cucumber-reports-plugin"}


# ---------------------------------------------------------------------------
# _build_normalized_event_row
# ---------------------------------------------------------------------------


def test_build_normalized_event_row_schema():
    raw_row = {
        "event_type": "PullRequestEvent",
        "event_ts": "2025-07-18T12:34:56Z",
        "event_date": "2025-07-18",
        "actor_login": "octocat",
        "action": "closed",
        "pr_merged": "true",
        "pr_created_ts": "2025-07-10T09:00:00Z",
        "pr_closed_ts": "2025-07-18T12:34:00Z",
        "issue_created_ts": None,
        "issue_closed_ts": None,
        "text_blob": "  fix retry logic  ",
    }

    row = _build_normalized_event_row(
        raw_row,
        "kubernetes",
        "jenkinsci/kubernetes-plugin",
        collected_at="2026-03-15T13:34:56+00:00",
        sample_percent=1.0,
        registry_path="data/raw/registry/plugins.jsonl",
        source_window_start_yyyymmdd="20250701",
        source_window_end_yyyymmdd="20250731",
    )

    assert row["source"] == "gharchive_bigquery"
    assert row["plugin_id"] == "kubernetes"
    assert row["repo_full_name"] == "jenkinsci/kubernetes-plugin"
    assert row["repo_owner"] == "jenkinsci"
    assert row["repo_name"] == "kubernetes-plugin"
    assert row["event_type"] == "PullRequestEvent"
    assert row["event_ts"] == "2025-07-18T12:34:56Z"
    assert row["event_date"] == "2025-07-18"
    assert row["event_yyyymm"] == "2025-07"
    assert row["event_year"] == 2025
    assert row["event_month"] == 7
    assert row["actor_login"] == "octocat"
    assert row["action"] == "closed"
    assert row["pr_merged"] is True
    assert row["pr_created_ts"] == "2025-07-10T09:00:00Z"
    assert row["pr_closed_ts"] == "2025-07-18T12:34:00Z"
    assert row["issue_created_ts"] is None
    assert row["issue_closed_ts"] is None
    assert row["text_blob"] == "fix retry logic"
    assert row["sample_percent"] == 1.0
    assert row["registry_path"] == "data/raw/registry/plugins.jsonl"
    assert row["source_window_start_yyyymmdd"] == "20250701"
    assert row["source_window_end_yyyymmdd"] == "20250731"


def test_build_normalized_event_row_handles_missing_repo_parts_and_false_bool():
    raw_row = {
        "event_type": "IssuesEvent",
        "event_ts": None,
        "event_date": "2025-08-01",
        "actor_login": "someone",
        "action": "reopened",
        "pr_merged": "false",
        "text_blob": "",
    }

    row = _build_normalized_event_row(
        raw_row,
        "example-plugin",
        "not-a-full-name",
        collected_at="2026-03-15T13:34:56+00:00",
        sample_percent=5.0,
        registry_path="data/raw/registry/plugins.jsonl",
        source_window_start_yyyymmdd="20250801",
        source_window_end_yyyymmdd="20250831",
    )

    assert row["repo_owner"] is None
    assert row["repo_name"] is None
    assert row["event_ts"] is None
    assert row["event_date"] == "2025-08-01"
    assert row["event_yyyymm"] == "2025-08"
    assert row["event_year"] == 2025
    assert row["event_month"] == 8
    assert row["pr_merged"] is False
    assert row["text_blob"] is None


def test_build_normalized_event_row_accepts_python_datetime_objects():
    raw_row = {
        "event_type": "PushEvent",
        "event_ts": datetime(2025, 1, 15, 12, 34, 56, tzinfo=UTC),
        "event_date": date(2025, 1, 15),
        "actor_login": "octocat",
        "action": None,
        "pr_merged": None,
        "pr_created_ts": None,
        "pr_closed_ts": None,
        "issue_created_ts": None,
        "issue_closed_ts": None,
        "text_blob": None,
    }

    row = _build_normalized_event_row(
        raw_row,
        plugin_id="example-plugin",
        repo_full_name="jenkinsci/example-plugin",
        collected_at="2026-03-15T00:00:00Z",
        sample_percent=1.0,
        registry_path="data/raw/registry/plugins.jsonl",
        source_window_start_yyyymmdd="20250101",
        source_window_end_yyyymmdd="20250131",
    )

    assert row["event_date"] == "2025-01-15"
    assert row["event_yyyymm"] == "2025-01"
    assert row["event_year"] == 2025
    assert row["event_month"] == 1


# ---------------------------------------------------------------------------
# collect_gharchive_history_real — mocked BigQuery
# ---------------------------------------------------------------------------


def test_collect_gharchive_history_writes_month_based_normalized_event_files(
    tmp_path: Path, monkeypatch
):
    data_dir = tmp_path / "data" / "raw"
    plugins_dir = data_dir / "plugins"
    registry_dir = data_dir / "registry"
    out_dir = data_dir / "gharchive"
    plugins_dir.mkdir(parents=True)
    registry_dir.mkdir(parents=True)

    (plugins_dir / "cucumber-reports.snapshot.json").write_text(
        json.dumps({"repo_url": "https://github.com/jenkinsci/cucumber-reports-plugin"}),
        encoding="utf-8",
    )
    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "cucumber-reports"}) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "canary.collectors.gharchive_history._import_bigquery",
        lambda: _FakeBigQueryModule,
    )

    result = collect_gharchive_history_real(
        data_dir=str(data_dir),
        registry_path=str(registry_dir / "plugins.jsonl"),
        out_dir=str(out_dir),
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260102",
        bucket_days=30,
        sample_percent=5.0,
        max_bytes_billed=1000,
        overwrite=True,
    )

    assert result["plugins_written"] == 1
    assert result["rows_written"] == 1
    assert result["events_written"] == 1
    assert result["months_written"] == 1
    assert result["bytes_scanned_total"] == 987654

    month_path = out_dir / "normalized-events" / "2026-01.gharchive.events.jsonl"
    index_path = out_dir / "gharchive_index.json"

    assert month_path.exists()
    assert index_path.exists()

    month_rows = [json.loads(line) for line in month_path.read_text(encoding="utf-8").splitlines()]
    assert len(month_rows) == 1
    assert month_rows[0]["plugin_id"] == "cucumber-reports"
    assert month_rows[0]["repo_full_name"] == "jenkinsci/cucumber-reports-plugin"
    assert month_rows[0]["event_type"] == "PushEvent"
    assert month_rows[0]["event_yyyymm"] == "2026-01"
    assert month_rows[0]["actor_login"] == "alice"


def test_collect_gharchive_history_dry_run_estimates_windows_without_writing_events(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_estimate_window_bytes(client: Any, **kwargs: Any) -> int:
        calls.append(kwargs)
        return 123_456

    monkeypatch.setattr(gharchive_history, "_import_bigquery", lambda: _FakeBigQuery)
    monkeypatch.setattr(
        gharchive_history,
        "resolve_plugin_repo_targets",
        lambda **kwargs: {"demo-plugin": "jenkinsci/demo-plugin"},
    )
    monkeypatch.setattr(gharchive_history, "_estimate_window_bytes", fake_estimate_window_bytes)

    result = collect_gharchive_history_real(
        data_dir=str(tmp_path / "data" / "raw"),
        registry_path=str(tmp_path / "data" / "raw" / "registry" / "plugins.jsonl"),
        out_dir=str(tmp_path / "data" / "raw" / "gharchive"),
        start_yyyymmdd="20250101",
        end_yyyymmdd="20250131",
        bucket_days=31,
        sample_percent=5.0,
        max_bytes_billed=999,
        dry_run=True,
    )

    assert calls == [
        {
            "repo_names": ["jenkinsci/demo-plugin"],
            "start_yyyymmdd": "20250101",
            "end_yyyymmdd": "20250131",
            "sample_percent": 5.0,
            "max_bytes_billed": 999,
        }
    ]
    assert result["dry_run"] is True
    assert result["bytes_scanned_total"] == 123_456
    assert result["rows_written"] == 0
    assert result["events_written"] == 0
    assert result["months_written"] == 0
    assert result["windows"] == [
        {
            "window_start_yyyymmdd": "20250101",
            "window_end_yyyymmdd": "20250131",
            "rows": None,
            "bytes_scanned": 0,
            "estimated_bytes_scanned": 123_456,
            "path": None,
            "dry_run": True,
        }
    ]
    out_path = (
        tmp_path
        / "data"
        / "raw"
        / "gharchive"
        / "normalized-events"
        / "2025-01.gharchive.events.jsonl"
    )
    assert not out_path.exists()
