"""
Behavior tests for canary.collectors.software_heritage_athena.

Consolidates test_software_heritage_athena{,_extra,_real_and_main}.py.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import UTC, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import canary.collectors.software_heritage_athena as swh_athena
from canary.collectors.software_heritage_athena import (
    AthenaQueryResult,
    SwhVisitFeatures,
    _chunked,
    _directory_entries_query,
    _extract_feature_flags,
    _extract_revision_signals,
    _format_bytes,
    _log,
    _merge_swh_visit_records,
    _normalize_repo_slug,
    _parse_swh_timestamp,
    _read_jsonl,
    _repo_visits_query,
    _safe_median,
    _safe_percentile,
    _snapshot_directories_query,
    _sql_escape,
    _utc_now_iso,
    collect_software_heritage_athena_repo,
    collect_software_heritage_athena_repo_to_file,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _write_snapshot(data_dir: Path, plugin_id: str, payload: dict) -> Path:
    snap_dir = data_dir / "plugins"
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_path = snap_dir / f"{plugin_id}.snapshot.json"
    snap_path.write_text(json.dumps(payload), encoding="utf-8")
    return snap_path


def _load_jsonl_file(path: Path) -> list[dict]:
    """Read a JSONL file into a list of dicts (test helper)."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


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


# ---------------------------------------------------------------------------
# Pure scalar helpers
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


# ---------------------------------------------------------------------------
# _chunked
# ---------------------------------------------------------------------------


def test_chunked_even_split():
    assert _chunked(["a", "b", "c", "d"], 2) == [["a", "b"], ["c", "d"]]


def test_chunked_uneven_split():
    assert _chunked(["a", "b", "c"], 2) == [["a", "b"], ["c"]]


def test_chunked_larger_than_list():
    assert _chunked(["a", "b"], 10) == [["a", "b"]]


def test_chunked_empty():
    assert _chunked([], 5) == []


def test_chunked_size_one():
    assert _chunked(["x", "y", "z"], 1) == [["x"], ["y"], ["z"]]


def test_chunked_zero_chunk_size_treated_as_one():
    result = _chunked(["a", "b", "c"], 0)
    assert all(len(chunk) == 1 for chunk in result)


# ---------------------------------------------------------------------------
# _safe_median
# ---------------------------------------------------------------------------


def test_safe_median_empty():
    assert _safe_median([]) is None


def test_safe_median_single():
    assert _safe_median([5.0]) == 5.0


def test_safe_median_odd():
    assert _safe_median([1.0, 3.0, 5.0]) == 3.0


def test_safe_median_even():
    assert _safe_median([1.0, 3.0, 5.0, 7.0]) == 4.0


def test_safe_median_unsorted():
    assert _safe_median([5.0, 1.0, 3.0]) == 3.0


# ---------------------------------------------------------------------------
# _safe_percentile
# ---------------------------------------------------------------------------


def test_safe_percentile_empty():
    assert _safe_percentile([], 50) is None


def test_safe_percentile_single():
    assert _safe_percentile([10.0], 50) == 10.0
    assert _safe_percentile([10.0], 0) == 10.0
    assert _safe_percentile([10.0], 100) == 10.0


def test_safe_percentile_p50():
    result = _safe_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50)
    assert result == pytest.approx(3.0)


def test_safe_percentile_p90():
    result = _safe_percentile([1.0, 2.0, 3.0, 4.0, 5.0], 90)
    assert result == pytest.approx(4.6)


def test_safe_percentile_p0():
    assert _safe_percentile([3.0, 1.0, 2.0], 0) == pytest.approx(1.0)


def test_safe_percentile_p100():
    assert _safe_percentile([3.0, 1.0, 2.0], 100) == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# _parse_swh_timestamp
# ---------------------------------------------------------------------------


def test_parse_swh_timestamp_none():
    assert _parse_swh_timestamp(None) is None


def test_parse_swh_timestamp_empty():
    assert _parse_swh_timestamp("") is None


def test_parse_swh_timestamp_utc_z():
    result = _parse_swh_timestamp("2024-06-01T12:00:00Z")
    assert result is not None
    assert result.year == 2024
    assert result.month == 6
    assert result.tzinfo is not None


def test_parse_swh_timestamp_with_offset():
    result = _parse_swh_timestamp("2024-06-01T14:00:00+02:00")
    assert result is not None
    assert result.utcoffset() == timedelta(hours=2)


def test_parse_swh_timestamp_no_tz_gets_utc():
    result = _parse_swh_timestamp("2024-06-01T12:00:00")
    assert result is not None
    assert result.tzinfo == UTC


def test_parse_swh_timestamp_invalid():
    assert _parse_swh_timestamp("not-a-timestamp") is None


# ---------------------------------------------------------------------------
# Query builders
# ---------------------------------------------------------------------------


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
# _read_jsonl
# ---------------------------------------------------------------------------


def test_read_jsonl_missing_file(tmp_path: Path):
    assert _read_jsonl(tmp_path / "missing.jsonl") == []


def test_read_jsonl_empty_file(tmp_path: Path):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert _read_jsonl(p) == []


def test_read_jsonl_valid_records(tmp_path: Path):
    p = tmp_path / "data.jsonl"
    p.write_text('{"a": 1}\n{"b": 2}\n', encoding="utf-8")
    rows = _read_jsonl(p)
    assert rows == [{"a": 1}, {"b": 2}]


def test_read_jsonl_skips_blank_lines(tmp_path: Path):
    p = tmp_path / "blanks.jsonl"
    p.write_text('{"a": 1}\n\n{"b": 2}\n', encoding="utf-8")
    assert len(_read_jsonl(p)) == 2


def test_read_jsonl_skips_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"a": 1}\nnot-json\n{"b": 2}\n', encoding="utf-8")
    rows = _read_jsonl(p)
    assert len(rows) == 2


def test_read_jsonl_skips_non_dict_lines(tmp_path: Path):
    p = tmp_path / "mixed.jsonl"
    p.write_text('{"a": 1}\n[1, 2, 3]\n{"b": 2}\n', encoding="utf-8")
    rows = _read_jsonl(p)
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# _merge_swh_visit_records
# ---------------------------------------------------------------------------


def test_merge_swh_visit_records_deduplicates():
    existing = [
        {"repo_url": "r", "snapshot_id": "s1", "visit": 1, "visit_date": "2024-01-01", "old": True}
    ]
    new = [
        {"repo_url": "r", "snapshot_id": "s1", "visit": 1, "visit_date": "2024-01-01", "old": False}
    ]
    result = _merge_swh_visit_records(existing, new)
    assert len(result) == 1
    assert result[0]["old"] is False


def test_merge_swh_visit_records_combines_distinct():
    existing = [{"repo_url": "r", "snapshot_id": "s1", "visit": 1, "visit_date": "2024-01-01"}]
    new = [{"repo_url": "r", "snapshot_id": "s2", "visit": 2, "visit_date": "2024-02-01"}]
    result = _merge_swh_visit_records(existing, new)
    assert len(result) == 2


def test_merge_swh_visit_records_sorts_by_date():
    existing = [{"repo_url": "r", "snapshot_id": "s2", "visit": 2, "visit_date": "2024-03-01"}]
    new = [{"repo_url": "r", "snapshot_id": "s1", "visit": 1, "visit_date": "2024-01-01"}]
    result = _merge_swh_visit_records(existing, new)
    assert result[0]["visit_date"] == "2024-01-01"
    assert result[1]["visit_date"] == "2024-03-01"


def test_merge_swh_visit_records_empty_inputs():
    assert _merge_swh_visit_records([], []) == []
    rec = {"repo_url": "r", "snapshot_id": "s", "visit": 1, "visit_date": "d"}
    assert _merge_swh_visit_records([rec], []) == [rec]


# ---------------------------------------------------------------------------
# _extract_feature_flags
# ---------------------------------------------------------------------------


def test_extract_feature_flags_all_false_on_empty():
    flags = _extract_feature_flags([])
    assert flags == {
        "has_readme": False,
        "has_dot_github": False,
        "has_jenkinsfile": False,
        "has_travis_yml": False,
        "has_security_md": False,
        "has_changelog": False,
        "has_contributing_md": False,
        "has_dockerfile": False,
        "has_pom_xml": False,
        "has_build_gradle": False,
        "has_mvn_wrapper": False,
        "has_tests_directory": False,
        "has_github_actions": False,
        "has_dependabot": False,
        "has_sonar_config": False,
        "has_snyk_config": False,
        "top_level_entry_count": 0,
    }


def test_extract_feature_flags_multiple_files():
    rows: list[dict[str, str | None]] = [
        {"entry_name": "README.md"},
        {"entry_name": ".github"},
        {"entry_name": "Jenkinsfile"},
        {"entry_name": ".travis.yml"},
    ]
    flags = _extract_feature_flags(rows)
    assert flags["has_readme"] is True
    assert flags["has_dot_github"] is True
    assert flags["has_jenkinsfile"] is True
    assert flags["has_travis_yml"] is True


def test_extract_feature_flags_new_flags():
    rows: list[dict[str, str | None]] = [
        {"entry_name": "security.md"},
        {"entry_name": "CHANGELOG.md"},
        {"entry_name": "CONTRIBUTING.md"},
        {"entry_name": "Dockerfile"},
        {"entry_name": "pom.xml"},
        {"entry_name": "build.gradle"},
        {"entry_name": ".mvn"},
        {"entry_name": "tests"},
        {"entry_name": "workflows"},
        {"entry_name": "dependabot.yml"},
        {"entry_name": "sonar-project.properties"},
        {"entry_name": ".snyk"},
    ]
    flags = _extract_feature_flags(rows)
    assert flags["has_security_md"] is True
    assert flags["has_changelog"] is True
    assert flags["has_contributing_md"] is True
    assert flags["has_dockerfile"] is True
    assert flags["has_pom_xml"] is True
    assert flags["has_build_gradle"] is True
    assert flags["has_mvn_wrapper"] is True
    assert flags["has_tests_directory"] is True
    assert flags["has_github_actions"] is True
    assert flags["has_dependabot"] is True
    assert flags["has_sonar_config"] is True
    assert flags["has_snyk_config"] is True


def test_extract_feature_flags_alternate_names():
    flags = _extract_feature_flags([{"entry_name": "history.md"}])
    assert flags["has_changelog"] is True

    flags = _extract_feature_flags([{"entry_name": "security.txt"}])
    assert flags["has_security_md"] is True

    flags = _extract_feature_flags([{"entry_name": "build.gradle.kts"}])
    assert flags["has_build_gradle"] is True

    flags = _extract_feature_flags([{"entry_name": ".sonarcloud.properties"}])
    assert flags["has_sonar_config"] is True

    flags = _extract_feature_flags([{"entry_name": "dockerfile.build"}])
    assert flags["has_dockerfile"] is True


def test_extract_feature_flags_top_level_entry_count():
    rows: list[dict[str, str | None]] = [
        {"entry_name": "README.md"},
        {"entry_name": "src"},
        {"entry_name": "pom.xml"},
    ]
    flags = _extract_feature_flags(rows)
    assert flags["top_level_entry_count"] == 3


# ---------------------------------------------------------------------------
# _extract_revision_signals
# ---------------------------------------------------------------------------

_VISIT_DATE = "2024-06-01T00:00:00Z"


def _row(
    author_date: str,
    committer_date: str | None = None,
    msg: str = "update",
    author_tz: int = 0,
    committer_tz: int = 0,
) -> dict:
    return {
        "author_date": author_date,
        "committer_date": committer_date or author_date,
        "commit_message": msg,
        "author_tz_offset_minutes": author_tz,
        "committer_tz_offset_minutes": committer_tz,
    }


def test_extract_revision_signals_includes_late_night_commit_fraction():
    rows = [
        {
            "author_date": "2024-01-01T06:00:00+00:00",
            "committer_date": "2024-01-01T06:30:00+00:00",
            "author_tz_offset_minutes": -300,
            "committer_tz_offset_minutes": -300,
            "commit_message": "feat: add thing",
        },
        {
            "author_date": "2024-01-01T18:00:00+00:00",
            "committer_date": "2024-01-01T18:10:00+00:00",
            "author_tz_offset_minutes": 0,
            "committer_tz_offset_minutes": 0,
            "commit_message": "fix: daylight work",
        },
    ]
    signals = _extract_revision_signals(rows, "2024-01-02T00:00:00+00:00")
    assert signals["late_night_commit_fraction"] == 0.5


def test_revision_signals_empty_rows():
    signals = _extract_revision_signals([], _VISIT_DATE)
    assert signals["commit_count"] == 0
    assert signals["weekend_commit_fraction"] is None
    assert signals["security_fix_commit_count"] == 0


def test_revision_signals_weekend_commit():
    # 2024-01-06 is a Saturday (weekday=5)
    signals = _extract_revision_signals(
        [
            _row("2024-01-06T10:00:00Z"),  # Saturday
            _row("2024-01-08T10:00:00Z"),  # Monday
        ],
        _VISIT_DATE,
    )
    assert signals["weekend_commit_fraction"] == pytest.approx(0.5)


def test_revision_signals_security_keywords():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", msg="fix: cve-2024-1234"),
            _row("2024-01-02T10:00:00Z", msg="fix: vulnerability in auth"),
            _row("2024-01-03T10:00:00Z", msg="chore: update deps"),
        ],
        _VISIT_DATE,
    )
    assert signals["security_fix_commit_count"] == 2


def test_revision_signals_merge_commits():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", msg="Merge branch 'main' into dev"),
            _row("2024-01-02T10:00:00Z", msg="feat: add feature"),
        ],
        _VISIT_DATE,
    )
    assert signals["merge_commit_fraction"] == pytest.approx(0.5)


def test_revision_signals_conventional_commits():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", msg="feat: add login"),
            _row("2024-01-02T10:00:00Z", msg="fix(auth): fix redirect"),
            _row("2024-01-03T10:00:00Z", msg="random message"),
        ],
        _VISIT_DATE,
    )
    assert signals["conventional_commit_fraction"] == pytest.approx(2 / 3, abs=1e-3)


def test_revision_signals_issue_references():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", msg="fix: closes #42"),
            _row("2024-01-02T10:00:00Z", msg="update readme"),
        ],
        _VISIT_DATE,
    )
    assert signals["issue_reference_rate"] == pytest.approx(0.5)


def test_revision_signals_empty_messages():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", msg="."),
            _row("2024-01-02T10:00:00Z", msg="-"),
            _row("2024-01-03T10:00:00Z", msg="wip"),
            _row("2024-01-04T10:00:00Z", msg="real commit"),
        ],
        _VISIT_DATE,
    )
    assert signals["empty_message_rate"] == pytest.approx(0.75)


def test_revision_signals_timezone_diversity():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", author_tz=0),
            _row("2024-01-02T10:00:00Z", author_tz=60),
            _row("2024-01-03T10:00:00Z", author_tz=60),
        ],
        _VISIT_DATE,
    )
    assert signals["timezone_diversity"] == 2


def test_revision_signals_tz_mismatch():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", author_tz=0, committer_tz=60),
            _row("2024-01-02T10:00:00Z", author_tz=0, committer_tz=0),
        ],
        _VISIT_DATE,
    )
    assert signals["author_committer_mismatch_rate"] == pytest.approx(0.5)


def test_revision_signals_lag():
    signals = _extract_revision_signals(
        [
            _row("2024-01-01T10:00:00Z", committer_date="2024-01-01T12:00:00Z"),
        ],
        _VISIT_DATE,
    )
    assert signals["author_committer_lag_p50_hours"] == pytest.approx(2.0)
    assert signals["author_committer_lag_p90_hours"] == pytest.approx(2.0)


def test_revision_signals_days_since_last_commit():
    signals = _extract_revision_signals(
        [_row("2024-05-31T00:00:00Z")],
        "2024-06-01T00:00:00Z",
    )
    assert signals["days_since_last_commit"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# SwhVisitFeatures dataclass
# ---------------------------------------------------------------------------


def test_swh_visit_features_asdict():
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
        commit_count=0,
        days_since_last_commit=None,
        author_committer_lag_p50_hours=None,
        author_committer_lag_p90_hours=None,
        timezone_diversity=0,
        weekend_commit_fraction=None,
        security_fix_commit_count=0,
        merge_commit_fraction=None,
        conventional_commit_fraction=None,
        issue_reference_rate=None,
        empty_message_rate=None,
        author_committer_mismatch_rate=None,
        late_night_commit_fraction=None,
    )
    d = asdict(feat)
    assert d["source"] == "software_heritage_athena"
    assert d["has_readme"] is True
    assert d["has_travis_yml"] is True
    assert d["late_night_commit_fraction"] is None


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


# ---------------------------------------------------------------------------
# collect_software_heritage_athena_real — plugin wrapper
# ---------------------------------------------------------------------------


def test_collect_real_raises_when_snapshot_has_no_repo_url(tmp_path: Path):
    data_dir = tmp_path / "raw"
    _write_snapshot(data_dir, "missing-repo", {"name": "missing-repo"})

    with pytest.raises(RuntimeError, match="No repo_url/scm_url found"):
        swh_athena.collect_software_heritage_athena_real(
            plugin_id="missing-repo",
            data_dir=str(data_dir),
            out_dir=tmp_path / "swh",
            verbose=False,
        )


def test_collect_real_writes_index_and_visit_records(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "raw"
    out_dir = tmp_path / "swh"
    _write_snapshot(
        data_dir,
        "demo-plugin",
        {"repo_url": "https://github.com/example/demo-plugin"},
    )

    fetched_records = [
        {
            "source": "software_heritage_athena",
            "repo_url": "https://github.com/example/demo-plugin",
            "visit": 1,
            "visit_date": "2024-01-01",
            "snapshot_id": "snap-001",
        }
    ]

    def fake_collect_repo(**kwargs):
        assert kwargs["repo_url"] == "https://github.com/example/demo-plugin"
        assert kwargs["database"] == "swh"
        assert kwargs["max_visits"] == 7
        assert kwargs["directory_batch_size"] == 3
        assert kwargs["max_directories"] == 11
        return fetched_records

    monkeypatch.setattr(swh_athena, "collect_software_heritage_athena_repo", fake_collect_repo)
    monkeypatch.setattr(swh_athena, "_utc_now_iso", lambda: "2026-01-02T03:04:05+00:00")

    result = swh_athena.collect_software_heritage_athena_real(
        plugin_id="demo-plugin",
        data_dir=str(data_dir),
        out_dir=out_dir,
        overwrite=True,
        database="swh",
        output_location="s3://bucket/staging/",
        max_visits=7,
        directory_batch_size=3,
        max_directories=11,
        verbose=False,
    )

    visits_path = out_dir / "demo-plugin.swh_athena_visits.jsonl"
    index_path = out_dir / "demo-plugin.swh_athena_index.json"

    assert result["plugin_id"] == "demo-plugin"
    assert result["repo_url"] == "https://github.com/example/demo-plugin"
    assert result["written"] == 1
    assert result["record_count"] == 1
    assert Path(result["files"]["visits"]) == visits_path
    assert Path(result["files"]["index"]) == index_path

    assert _load_jsonl_file(visits_path) == fetched_records
    index_payload = json.loads(index_path.read_text(encoding="utf-8"))
    assert index_payload == {
        "plugin_id": "demo-plugin",
        "repo_url": "https://github.com/example/demo-plugin",
        "backend": "athena",
        "database": "swh",
        "collected_at": "2026-01-02T03:04:05+00:00",
        "record_count": 1,
        "files": {"visits": str(visits_path)},
    }


def test_collect_real_merges_existing_records_when_not_overwriting(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "raw"
    out_dir = tmp_path / "swh"
    out_dir.mkdir()
    _write_snapshot(
        data_dir,
        "demo-plugin",
        {"plugin_api": {"scm": {"link": "https://github.com/example/demo-plugin"}}},
    )

    visits_path = out_dir / "demo-plugin.swh_athena_visits.jsonl"
    write_jsonl(
        [
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 1,
                "visit_date": "2024-01-01",
                "snapshot_id": "snap-existing",
                "has_readme": False,
            }
        ],
        visits_path,
    )

    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo",
        lambda **_: [
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 1,
                "visit_date": "2024-01-01",
                "snapshot_id": "snap-existing",
                "has_readme": True,
            },
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 2,
                "visit_date": "2024-02-01",
                "snapshot_id": "snap-new",
            },
        ],
    )

    result = swh_athena.collect_software_heritage_athena_real(
        plugin_id="demo-plugin",
        data_dir=str(data_dir),
        out_dir=out_dir,
        overwrite=False,
        verbose=False,
    )

    merged = _load_jsonl_file(visits_path)
    assert result["record_count"] == 2
    assert result["fetched_record_count"] == 2
    assert [row["visit"] for row in merged] == [1, 2]
    # New fetched record replaces the existing duplicate visit key during merge.
    assert merged[0]["has_readme"] is True


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_returns_zero_and_prints_output_path(monkeypatch, capsys, tmp_path: Path):
    expected_path = tmp_path / "repo.software_heritage.jsonl"

    def fake_to_file(**kwargs):
        assert kwargs["repo_url"] == "https://github.com/example/repo"
        assert kwargs["database"] == "swh"
        assert kwargs["out_dir"] == str(tmp_path)
        assert kwargs["poll_initial_seconds"] == 0.25
        assert kwargs["poll_max_seconds"] == 2.5
        assert kwargs["max_visits"] == 4
        assert kwargs["directory_batch_size"] == 5
        assert kwargs["max_directories"] == 6
        assert kwargs["verbose"] is False
        return expected_path

    monkeypatch.setattr(swh_athena, "collect_software_heritage_athena_repo_to_file", fake_to_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "software_heritage_athena",
            "--repo-url",
            "https://github.com/example/repo",
            "--database",
            "swh",
            "--out-dir",
            str(tmp_path),
            "--poll-initial-seconds",
            "0.25",
            "--poll-max-seconds",
            "2.5",
            "--max-visits",
            "4",
            "--directory-batch-size",
            "5",
            "--max-directories",
            "6",
            "--quiet",
        ],
    )

    assert swh_athena.main() == 0
    captured = capsys.readouterr()
    assert f"Wrote Software Heritage Athena records to {expected_path}" in captured.out


@pytest.mark.parametrize("exc", [ValueError("bad repo"), RuntimeError("athena failed")])
def test_main_returns_one_for_expected_errors(monkeypatch, capsys, exc):
    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo_to_file",
        lambda **_: (_ for _ in ()).throw(exc),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["software_heritage_athena", "--repo-url", "https://github.com/example/repo"],
    )

    assert swh_athena.main() == 1
    captured = capsys.readouterr()
    assert f"[ERROR] {exc}" in captured.out


def test_main_returns_one_for_unexpected_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo_to_file",
        lambda **_: (_ for _ in ()).throw(Exception("surprise")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["software_heritage_athena", "--repo-url", "https://github.com/example/repo"],
    )

    assert swh_athena.main() == 1
    captured = capsys.readouterr()
    assert "[ERROR] surprise" in captured.out
