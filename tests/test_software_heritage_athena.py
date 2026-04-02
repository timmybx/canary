"""Tests for canary.collectors.software_heritage_athena (pure/helper coverage)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest  # pyright: ignore[reportMissingImports]

from canary.collectors.software_heritage_athena import (
    AthenaQueryResult,
    SwhVisitFeatures,
    _directory_entries_query,
    _extract_feature_flags,
    _format_bytes,
    _log,
    _normalize_repo_slug,
    _repo_visits_query,
    _snapshot_directories_query,
    _sql_escape,
    _utc_now_iso,
    collect_software_heritage_athena_repo,
    collect_software_heritage_athena_repo_to_file,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# Pure helper tests
# ---------------------------------------------------------------------------


def test_utc_now_iso_returns_string():
    result = _utc_now_iso()
    assert isinstance(result, str)
    assert "T" in result


def test_sql_escape_replaces_single_quotes():
    assert _sql_escape("it's") == "it''s"
    assert _sql_escape("no quotes") == "no quotes"
    assert _sql_escape("two''quotes") == "two''''quotes"


def test_normalize_repo_slug_strips_trailing_slash():
    assert _normalize_repo_slug("https://github.com/org/my-repo") == "my-repo"
    assert _normalize_repo_slug("https://github.com/org/my-repo/") == "my-repo"


def test_normalize_repo_slug_sanitizes_characters():
    assert _normalize_repo_slug("https://github.com/org/repo with spaces") == "repo_with_spaces"


def test_normalize_repo_slug_empty_returns_unknown():
    assert _normalize_repo_slug("") == "unknown-repo"
    assert _normalize_repo_slug("/") == "unknown-repo"


def test_format_bytes_none():
    assert _format_bytes(None) == "unknown"


def test_format_bytes_small():
    result = _format_bytes(512)
    assert "B" in result or "512" in result


def test_format_bytes_kilobytes():
    result = _format_bytes(2048)
    assert "KB" in result


def test_format_bytes_megabytes():
    result = _format_bytes(1024 * 1024 * 5)
    assert "MB" in result


def test_log_verbose_true(capsys):
    _log("hello world", verbose=True)
    captured = capsys.readouterr()
    assert "hello world" in captured.out


def test_log_verbose_false_produces_no_output(capsys):
    _log("silent message", verbose=False)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_repo_visits_query_contains_repo_url():
    q = _repo_visits_query("https://github.com/org/repo", max_visits=5)
    assert "https://github.com/org/repo" in q
    assert "LIMIT 5" in q


def test_repo_visits_query_escapes_single_quote():
    q = _repo_visits_query("https://github.com/org/it's-repo", max_visits=1)
    assert "it''s-repo" in q


def test_snapshot_directories_query_contains_snapshot_id():
    q = _snapshot_directories_query("abc123", max_directories=10)
    assert "abc123" in q
    assert "LIMIT 10" in q


def test_snapshot_directories_query_escapes_quote():
    q = _snapshot_directories_query("snap'id", max_directories=5)
    assert "snap''id" in q


def test_directory_entries_query_contains_ids():
    q = _directory_entries_query(["dir1", "dir2"])
    assert "'dir1'" in q
    assert "'dir2'" in q


def test_directory_entries_query_escapes_quote_in_id():
    q = _directory_entries_query(["dir'1"])
    assert "dir''1" in q


def test_extract_feature_flags_all_false_on_empty():
    flags = _extract_feature_flags([])
    assert flags == {
        "has_readme": False,
        "has_dot_github": False,
        "has_jenkinsfile": False,
        "has_travis_yml": False,
    }


def test_extract_feature_flags_multiple_files():
    rows: list[dict[str, str | None]] = [
        {"entry_name": "README.md"},
        {"entry_name": ".github"},
        {"entry_name": "Jenkinsfile"},
        {"entry_name": ".travis.yml"},
    ]
    flags = _extract_feature_flags(rows)
    assert all(flags.values())


# ---------------------------------------------------------------------------
# write_jsonl
# ---------------------------------------------------------------------------


def test_write_jsonl_creates_file(tmp_path: Path):
    out_path = tmp_path / "sub" / "out.jsonl"
    records = [{"a": 1, "b": "hello"}, {"a": 2, "b": "world"}]
    write_jsonl(records, out_path)
    assert out_path.exists()
    lines = out_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1, "b": "hello"}


def test_write_jsonl_empty(tmp_path: Path):
    out_path = tmp_path / "empty.jsonl"
    write_jsonl([], out_path)
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == ""


def test_write_jsonl_sorts_keys(tmp_path: Path):
    out_path = tmp_path / "sorted.jsonl"
    write_jsonl([{"z": 1, "a": 2}], out_path)
    line = out_path.read_text(encoding="utf-8").strip()
    assert line == '{"a": 2, "z": 1}'


# ---------------------------------------------------------------------------
# SwhVisitFeatures dataclass
# ---------------------------------------------------------------------------


def test_swh_visit_features_asdict():
    from dataclasses import asdict

    feat = SwhVisitFeatures(
        source="software_heritage_athena",
        collected_at="2024-01-01T00:00:00+00:00",
        repo_url="https://github.com/org/repo",
        visit=1,
        visit_date="2024-01-01",
        snapshot_id="abc123",
        has_readme=True,
        has_dot_github=False,
        has_jenkinsfile=False,
        has_travis_yml=True,
        has_security_md=False,
        has_changelog=False,
        has_contributing_md=False,
        has_dockerfile=False,
        has_pom_xml=False,
        has_build_gradle=False,
        has_mvn_wrapper=False,
        has_tests_directory=False,
        has_github_actions=False,
        has_dependabot=False,
        has_sonar_config=False,
        has_snyk_config=False,
        top_level_entry_count=0,
    )
    d = asdict(feat)
    assert d["source"] == "software_heritage_athena"
    assert d["has_readme"] is True
    assert d["has_travis_yml"] is True


# ---------------------------------------------------------------------------
# AthenaQueryResult dataclass
# ---------------------------------------------------------------------------


def test_athena_query_result_fields():
    result = AthenaQueryResult(
        rows=[{"col": "val"}],
        query_execution_id="qeid-123",
        elapsed_s=1.5,
        data_scanned_bytes=1024,
    )
    assert result.query_execution_id == "qeid-123"
    assert result.data_scanned_bytes == 1024
    assert result.rows == [{"col": "val"}]


# ---------------------------------------------------------------------------
# collect_software_heritage_athena_repo — mocked Athena
# ---------------------------------------------------------------------------


def _make_athena_client_mock(
    visit_rows: list[dict],
    directory_rows: list[dict],
    entry_rows: list[dict],
):
    """Build a mock boto3 Athena client that returns canned results."""
    client = MagicMock()

    call_count = {"n": 0}
    execution_ids = ["eid-visits", "eid-dirs", "eid-entries"]

    def start_query_execution(**kwargs):
        idx = min(call_count["n"], len(execution_ids) - 1)
        call_count["n"] += 1
        return {"QueryExecutionId": execution_ids[idx]}

    client.start_query_execution.side_effect = start_query_execution

    def get_query_execution(QueryExecutionId):
        return {
            "QueryExecution": {
                "Status": {"State": "SUCCEEDED"},
                "Statistics": {"DataScannedInBytes": 100},
            }
        }

    client.get_query_execution.side_effect = get_query_execution

    # Paginator
    def get_paginator(operation):
        paginator = MagicMock()

        def paginate(QueryExecutionId):
            if QueryExecutionId == "eid-visits":
                rows_data = visit_rows
            elif QueryExecutionId == "eid-dirs":
                rows_data = directory_rows
            else:
                rows_data = entry_rows

            if not rows_data:
                yield {
                    "ResultSet": {
                        "ResultSetMetadata": {"ColumnInfo": []},
                        "Rows": [],
                    }
                }
                return

            columns = list(rows_data[0].keys())
            col_info = [{"Name": c} for c in columns]

            def make_row(d: dict):
                return {
                    "Data": [
                        {"VarCharValue": str(v) if v is not None else None} for v in d.values()
                    ]
                }

            yield {
                "ResultSet": {
                    "ResultSetMetadata": {"ColumnInfo": col_info},
                    "Rows": [make_row(r) for r in rows_data],
                }
            }

        paginator.paginate.side_effect = paginate
        return paginator

    client.get_paginator.side_effect = get_paginator
    return client


def test_collect_athena_no_visits_returns_empty(monkeypatch, tmp_path):
    client = _make_athena_client_mock(visit_rows=[], directory_rows=[], entry_rows=[])

    monkeypatch.setattr(
        "canary.collectors.software_heritage_athena._get_athena_client",
        lambda: client,
    )
    monkeypatch.setenv("ATHENA_S3_STAGING_DIR", "s3://bucket/staging/")

    records = collect_software_heritage_athena_repo(
        repo_url="https://github.com/org/repo",
        output_location="s3://bucket/staging/",
        poll_initial_seconds=0,
        poll_max_seconds=0.1,
        verbose=False,
    )
    assert records == []


def test_collect_athena_raises_without_output_location(monkeypatch):
    monkeypatch.delenv("ATHENA_S3_STAGING_DIR", raising=False)
    with pytest.raises(ValueError, match="ATHENA_S3_STAGING_DIR"):
        collect_software_heritage_athena_repo(
            repo_url="https://github.com/org/repo",
            output_location=None,
            poll_initial_seconds=0,
            poll_max_seconds=0.1,
        )


def test_collect_athena_with_visits_and_entries(monkeypatch, tmp_path):
    visit_rows = [
        {
            "repo_url": "https://github.com/org/repo",
            "visit": "1",
            "visit_date": "2024-01-15",
            "snapshot_id": "snap-abc",
        }
    ]
    directory_rows = [{"directory": "dir-001"}]
    entry_rows = [
        {"directory_id": "dir-001", "entry_name": "README.md", "type": "file"},
        {"directory_id": "dir-001", "entry_name": ".github", "type": "dir"},
    ]
    client = _make_athena_client_mock(visit_rows, directory_rows, entry_rows)

    monkeypatch.setattr(
        "canary.collectors.software_heritage_athena._get_athena_client",
        lambda: client,
    )

    records = collect_software_heritage_athena_repo(
        repo_url="https://github.com/org/repo",
        output_location="s3://bucket/staging/",
        poll_initial_seconds=0,
        poll_max_seconds=0.1,
        verbose=False,
    )

    assert len(records) == 1
    r = records[0]
    assert r["source"] == "software_heritage_athena"
    assert r["repo_url"] == "https://github.com/org/repo"
    assert r["snapshot_id"] == "snap-abc"
    assert r["has_readme"] is True
    assert r["has_dot_github"] is True
    assert r["has_jenkinsfile"] is False


def test_collect_athena_with_multiple_rows(monkeypatch):
    visit_rows = [
        {
            "repo_url": "https://github.com/org/repo",
            "visit": "1",
            "visit_date": "2024-01-01",
            "snapshot_id": "snap-shared",
        },
        {
            "repo_url": "https://github.com/org/repo",
            "visit": "2",
            "visit_date": "2024-02-01",
            "snapshot_id": "snap-shared",
        },
    ]
    directory_rows = [{"directory": "dir-xyz"}]
    entry_rows = [{"directory_id": "dir-xyz", "entry_name": "Jenkinsfile", "type": "file"}]
    client = _make_athena_client_mock(visit_rows, directory_rows, entry_rows)

    monkeypatch.setattr(
        "canary.collectors.software_heritage_athena._get_athena_client",
        lambda: client,
    )

    records = collect_software_heritage_athena_repo(
        repo_url="https://github.com/org/repo",
        output_location="s3://bucket/staging/",
        poll_initial_seconds=0,
        poll_max_seconds=0.1,
        verbose=False,
    )

    assert len(records) == 2
    for r in records:
        assert r["has_jenkinsfile"] is True


def test_collect_athena_to_file_writes_jsonl(monkeypatch, tmp_path):
    visit_rows = [
        {
            "repo_url": "https://github.com/org/myrepo",
            "visit": "1",
            "visit_date": "2024-01-01",
            "snapshot_id": "snap-1",
        }
    ]
    directory_rows: list[dict] = []
    entry_rows: list[dict] = []
    client = _make_athena_client_mock(visit_rows, directory_rows, entry_rows)

    monkeypatch.setattr(
        "canary.collectors.software_heritage_athena._get_athena_client",
        lambda: client,
    )

    out_path = collect_software_heritage_athena_repo_to_file(
        repo_url="https://github.com/org/myrepo",
        out_dir=tmp_path,
        output_location="s3://bucket/staging/",
        poll_initial_seconds=0,
        poll_max_seconds=0.1,
        verbose=False,
    )

    assert out_path.exists()
    lines = out_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["snapshot_id"] == "snap-1"
