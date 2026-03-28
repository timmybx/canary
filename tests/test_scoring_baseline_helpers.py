"""Additional tests for canary.scoring.baseline helper functions."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from canary.scoring.baseline import (
    ScoreResult,
    _advisory_record_max_cvss,
    _cvss_base_score_to_label,
    _extract_dependency_plugin_ids,
    _healthscore_to_risk_points,
    _load_advisories_for_plugin,
    _load_healthscore_record,
    _load_plugin_snapshot,
    _parse_date,
    _parse_iso_datetime,
    _safe_int,
    _safe_join_under,
    _safe_plugin_filename,
    _safe_plugin_id,
)

# ---------------------------------------------------------------------------
# _safe_plugin_id
# ---------------------------------------------------------------------------


def test_safe_plugin_id_valid():
    assert _safe_plugin_id("cucumber-reports") == "cucumber-reports"
    assert _safe_plugin_id("workflow_cps") == "workflow_cps"
    assert _safe_plugin_id("plugin1.test") == "plugin1.test"


def test_safe_plugin_id_strips_whitespace():
    assert _safe_plugin_id("  my-plugin  ") == "my-plugin"


def test_safe_plugin_id_empty_returns_none():
    assert _safe_plugin_id("") is None
    assert _safe_plugin_id("   ") is None


def test_safe_plugin_id_invalid_chars_returns_none():
    assert _safe_plugin_id("../etc/passwd") is None
    assert _safe_plugin_id("plugin/subdir") is None
    assert _safe_plugin_id("plugin name") is None  # space not allowed


def test_safe_plugin_id_starts_with_valid_char():
    assert _safe_plugin_id("a") == "a"
    assert _safe_plugin_id("1plugin") == "1plugin"


# ---------------------------------------------------------------------------
# _safe_plugin_filename
# ---------------------------------------------------------------------------


def test_safe_plugin_filename_valid():
    assert _safe_plugin_filename("my-plugin", ".snapshot.json") == "my-plugin.snapshot.json"


def test_safe_plugin_filename_invalid_id_returns_none():
    assert _safe_plugin_filename("../escape", ".json") is None


# ---------------------------------------------------------------------------
# _safe_join_under
# ---------------------------------------------------------------------------


def test_safe_join_under_valid(tmp_path: Path):
    result = _safe_join_under(tmp_path, "subdir", "file.json")
    assert result.parent == tmp_path / "subdir"


def test_safe_join_under_escape_raises(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes data directory"):
        _safe_join_under(tmp_path, "..", "etc", "passwd")


# ---------------------------------------------------------------------------
# _parse_date
# ---------------------------------------------------------------------------


def test_parse_date_iso_format():
    assert _parse_date("2025-03-15") == date(2025, 3, 15)


def test_parse_date_datetime_string():
    # Should truncate to date portion
    assert _parse_date("2025-03-15T12:00:00Z") == date(2025, 3, 15)


def test_parse_date_empty():
    assert _parse_date("") is None


def test_parse_date_invalid():
    assert _parse_date("not-a-date") is None


# ---------------------------------------------------------------------------
# _parse_iso_datetime
# ---------------------------------------------------------------------------


def test_parse_iso_datetime_valid():
    dt = _parse_iso_datetime("2025-03-15T12:00:00+00:00")
    assert dt is not None
    assert dt.year == 2025


def test_parse_iso_datetime_z_suffix():
    dt = _parse_iso_datetime("2025-03-15T12:00:00Z")
    assert dt is not None


def test_parse_iso_datetime_empty():
    assert _parse_iso_datetime("") is None


def test_parse_iso_datetime_invalid():
    assert _parse_iso_datetime("not-a-datetime") is None


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------


def test_safe_int_valid():
    assert _safe_int(5) == 5
    assert _safe_int("42") == 42


def test_safe_int_default_on_invalid():
    assert _safe_int("bad", default=0) == 0
    assert _safe_int(None, default=-1) == -1


# ---------------------------------------------------------------------------
# _cvss_base_score_to_label
# ---------------------------------------------------------------------------


def test_cvss_base_score_to_label_none():
    assert _cvss_base_score_to_label(None) is None


def test_cvss_base_score_to_label_zero():
    assert _cvss_base_score_to_label(0.0) == "None"


def test_cvss_base_score_to_label_low():
    assert _cvss_base_score_to_label(2.5) == "Low"


def test_cvss_base_score_to_label_medium():
    assert _cvss_base_score_to_label(5.0) == "Medium"


def test_cvss_base_score_to_label_high():
    assert _cvss_base_score_to_label(7.5) == "High"


def test_cvss_base_score_to_label_critical():
    assert _cvss_base_score_to_label(9.5) == "Critical"


def test_cvss_base_score_to_label_invalid():
    assert _cvss_base_score_to_label("not-a-number") is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _healthscore_to_risk_points
# ---------------------------------------------------------------------------


def test_healthscore_to_risk_points_100():
    assert _healthscore_to_risk_points(100) == 0


def test_healthscore_to_risk_points_0():
    assert _healthscore_to_risk_points(0) == 20


def test_healthscore_to_risk_points_50():
    pts = _healthscore_to_risk_points(50)
    assert pts is not None
    assert 0 <= pts <= 20


def test_healthscore_to_risk_points_invalid():
    assert _healthscore_to_risk_points("bad") is None


def test_healthscore_to_risk_points_clamps_high():
    # > 100 should clamp
    pts = _healthscore_to_risk_points(200)
    assert pts == 0


def test_healthscore_to_risk_points_clamps_low():
    # < 0 should clamp
    pts = _healthscore_to_risk_points(-10)
    assert pts == 20


# ---------------------------------------------------------------------------
# _advisory_record_max_cvss
# ---------------------------------------------------------------------------


def test_advisory_record_max_cvss_empty():
    assert _advisory_record_max_cvss({}) is None


def test_advisory_record_max_cvss_from_vulnerabilities():
    rec = {
        "vulnerabilities": [
            {"cvss": {"base_score": 7.5}},
            {"cvss": {"base_score": 9.1}},
        ]
    }
    assert _advisory_record_max_cvss(rec) == 9.1


def test_advisory_record_max_cvss_from_severity_summary():
    rec = {"severity_summary": {"max_cvss_base_score": 6.4}}
    assert _advisory_record_max_cvss(rec) == 6.4


def test_advisory_record_max_cvss_prefers_vulnerabilities_over_summary():
    rec = {
        "vulnerabilities": [{"cvss": {"base_score": 4.0}}],
        "severity_summary": {"max_cvss_base_score": 9.9},
    }
    assert _advisory_record_max_cvss(rec) == 4.0


def test_advisory_record_max_cvss_ignores_non_numeric():
    rec = {"vulnerabilities": [{"cvss": {"base_score": "not-a-number"}}]}
    assert _advisory_record_max_cvss(rec) is None


def test_advisory_record_max_cvss_non_dict_cvss():
    rec = {"vulnerabilities": [{"cvss": "5.0"}]}
    assert _advisory_record_max_cvss(rec) is None


# ---------------------------------------------------------------------------
# _extract_dependency_plugin_ids
# ---------------------------------------------------------------------------


def test_extract_dependency_plugin_ids_basic():
    snap = {
        "plugin_api": {
            "dependencies": [
                {"name": "token-macro", "version": "1.0"},
                {"name": "plain-credentials", "version": "2.0"},
            ]
        }
    }
    result = _extract_dependency_plugin_ids(snap)
    assert sorted(result) == ["plain-credentials", "token-macro"]


def test_extract_dependency_plugin_ids_deduplicates():
    snap = {
        "plugin_api": {
            "dependencies": [
                {"name": "same-plugin"},
                {"name": "same-plugin"},
            ]
        }
    }
    result = _extract_dependency_plugin_ids(snap)
    assert result == ["same-plugin"]


def test_extract_dependency_plugin_ids_empty_api():
    assert _extract_dependency_plugin_ids({"plugin_api": {}}) == []


def test_extract_dependency_plugin_ids_no_plugin_api():
    assert _extract_dependency_plugin_ids({}) == []


def test_extract_dependency_plugin_ids_invalid_entries():
    snap = {
        "plugin_api": {
            "dependencies": [
                {"name": "valid-plugin"},
                "not-a-dict",
                {"no_name": "something"},
            ]
        }
    }
    result = _extract_dependency_plugin_ids(snap)
    assert result == ["valid-plugin"]


# ---------------------------------------------------------------------------
# _load_plugin_snapshot
# ---------------------------------------------------------------------------


def test_load_plugin_snapshot_returns_none_for_missing(tmp_path: Path):
    result = _load_plugin_snapshot("no-such-plugin", tmp_path)
    assert result is None


def test_load_plugin_snapshot_returns_none_for_invalid_id(tmp_path: Path):
    result = _load_plugin_snapshot("../invalid", tmp_path)
    assert result is None


def test_load_plugin_snapshot_reads_file(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    snap = {"plugin_id": "my-plugin", "plugin_api": {}}
    (plugins_dir / "my-plugin.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")

    result = _load_plugin_snapshot("my-plugin", tmp_path)
    assert result is not None
    assert result["plugin_id"] == "my-plugin"


# ---------------------------------------------------------------------------
# _load_advisories_for_plugin
# ---------------------------------------------------------------------------


def _write_advisories(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_load_advisories_returns_empty_when_no_files(tmp_path: Path):
    result = _load_advisories_for_plugin("no-plugin", tmp_path)
    assert result == []


def test_load_advisories_reads_real_jsonl(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    _write_advisories(
        advisories_dir / "my-plugin.advisories.real.jsonl",
        [{"plugin_id": "my-plugin", "advisory_id": "2025-01-01"}],
    )
    result = _load_advisories_for_plugin("my-plugin", tmp_path, prefer_real=True)
    assert len(result) == 1
    assert result[0]["advisory_id"] == "2025-01-01"


def test_load_advisories_reads_sample_jsonl(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    _write_advisories(
        advisories_dir / "my-plugin.advisories.sample.jsonl",
        [{"plugin_id": "my-plugin", "advisory_id": "2025-02-01"}],
    )
    result = _load_advisories_for_plugin("my-plugin", tmp_path)
    assert len(result) == 1


def test_load_advisories_prefer_real_over_sample(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    _write_advisories(
        advisories_dir / "my-plugin.advisories.real.jsonl",
        [{"advisory_id": "real-001"}],
    )
    _write_advisories(
        advisories_dir / "my-plugin.advisories.sample.jsonl",
        [{"advisory_id": "sample-001"}],
    )
    result = _load_advisories_for_plugin("my-plugin", tmp_path, prefer_real=True)
    assert result[0]["advisory_id"] == "real-001"


# ---------------------------------------------------------------------------
# _load_healthscore_record
# ---------------------------------------------------------------------------


def test_load_healthscore_record_returns_none_for_missing(tmp_path: Path):
    assert _load_healthscore_record("no-plugin", tmp_path) is None


def test_load_healthscore_record_per_plugin_file(tmp_path: Path):
    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    payload = {
        "plugin_id": "my-plugin",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"plugin_id": "my-plugin", "value": 75},
    }
    (hs_dir / "my-plugin.healthscore.json").write_text(json.dumps(payload), encoding="utf-8")

    result = _load_healthscore_record("my-plugin", tmp_path)
    assert result is not None
    assert result["value"] == 75


def test_load_healthscore_record_uses_score_field_as_fallback(tmp_path: Path):
    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    payload = {
        "plugin_id": "score-plugin",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"plugin_id": "score-plugin", "score": 88},
    }
    (hs_dir / "score-plugin.healthscore.json").write_text(json.dumps(payload), encoding="utf-8")

    result = _load_healthscore_record("score-plugin", tmp_path)
    assert result is not None
    assert result["value"] == 88


def test_load_healthscore_record_returns_none_for_invalid_id(tmp_path: Path):
    assert _load_healthscore_record("../escape", tmp_path) is None


# ---------------------------------------------------------------------------
# ScoreResult
# ---------------------------------------------------------------------------


def test_score_result_to_dict():
    result = ScoreResult(
        plugin="my-plugin",
        score=42,
        reasons=("reason one", "reason two"),
        features={"advisory_count": 3},
    )
    d = result.to_dict()
    assert d["plugin"] == "my-plugin"
    assert d["score"] == 42
    assert d["reasons"] == ["reason one", "reason two"]
    assert d["features"]["advisory_count"] == 3
