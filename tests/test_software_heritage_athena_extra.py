"""Additional tests for software_heritage_athena pure helpers."""

from __future__ import annotations

from datetime import UTC, timedelta
from pathlib import Path

import pytest

from canary.collectors.software_heritage_athena import (
    _chunked,
    _extract_feature_flags,
    _extract_revision_signals,
    _merge_swh_visit_records,
    _parse_swh_timestamp,
    _read_jsonl,
    _safe_median,
    _safe_percentile,
)

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
# _extract_feature_flags — new flags not covered by existing tests
# ---------------------------------------------------------------------------


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
# _extract_revision_signals — branches not covered by existing tests
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
