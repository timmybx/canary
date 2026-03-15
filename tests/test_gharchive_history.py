import json
from pathlib import Path

from canary.collectors.gharchive_history import (
    _build_normalized_event_row,
    _build_query_with_sampling,
    _iter_windows,
    collect_gharchive_history_real,
    resolve_plugin_repo_targets,
)


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
                        "window_start_yyyymmdd": "20260101",
                        "window_end_yyyymmdd": "20260102",
                        "events_total": 25,
                        "actors_unique": 4,
                        "pushes": 8,
                        "committers_unique": 3,
                        "push_days_active": 2,
                        "prs_opened": 2,
                        "prs_closed": 2,
                        "prs_merged": 1,
                        "prs_closed_unmerged": 1,
                        "pr_reviewed_ratio": 0.5,
                        "pr_merge_time_p50_hours": 12,
                        "pr_close_without_merge_ratio": 0.5,
                        "issues_opened": 1,
                        "issues_closed": 1,
                        "issues_reopened": 0,
                        "issue_reopen_rate": 0.0,
                        "issue_close_time_p50_hours": 6,
                        "releases": 0,
                        "days_since_last_release": 30,
                        "hotfix_proxy": 0.0,
                        "security_label_proxy": 0,
                        "churn_intensity": 2.5,
                        "owner_concentration": 0.75,
                    }
                ],
                total_bytes_processed=987654,
            )


def test_iter_windows_chunks_range():
    windows = _iter_windows("20260101", "20260110", 4)
    assert windows == [
        ("20260101", "20260104"),
        ("20260105", "20260108"),
        ("20260109", "20260110"),
    ]


def test_build_query_includes_repo_filter():
    sql = _build_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260102",
        available_tables={"20260101", "20260102"},
        sample_percent=5.0,
    )
    assert "repo.name IN UNNEST(@repo_names)" in sql
    assert "TABLESAMPLE SYSTEM (5.0 PERCENT)" in sql


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


def test_collect_gharchive_history_writes_window_and_plugin_files(tmp_path: Path, monkeypatch):
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
    assert result["bytes_scanned_total"] == 987654

    window_path = out_dir / "windows" / "20260101_20260102.gharchive.jsonl"
    plugin_path = out_dir / "plugins" / "cucumber-reports.gharchive.jsonl"
    index_path = out_dir / "gharchive_index.json"

    assert window_path.exists()
    assert plugin_path.exists()
    assert index_path.exists()

    window_rows = [
        json.loads(line) for line in window_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(window_rows) == 1
    assert window_rows[0]["plugin_id"] == "cucumber-reports"
    assert window_rows[0]["repo_full_name"] == "jenkinsci/cucumber-reports-plugin"
    assert window_rows[0]["events_total"] == 25


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
