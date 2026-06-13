"""
Behavior tests for canary.scoring.baseline.

Consolidates test_scoring.py + test_scoring_baseline_helpers.py
+ test_scoring_baseline_extra.py.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

import canary.scoring.baseline as _baseline_mod
from canary.scoring.baseline import (  # type: ignore[attr-defined]
    _CAP_ADVISORY_HISTORY,
    _CAP_GOVERNANCE,
    _CAP_STALENESS,
    ScoreResult,
    _advisory_record_max_cvss,
    _cvss_base_score_to_label,
    _dependency_points,
    _extract_dependency_plugin_ids,
    _governance_points,
    _healthscore_to_risk_points,
    _load_advisories_for_plugin,
    _load_healthscore_record,
    _load_plugin_snapshot,
    _load_swh_features,
    _parse_date,
    _parse_iso_datetime,
    _safe_int,
    _safe_join_under,
    _safe_plugin_filename,
    _safe_plugin_id,
    _staleness_points,
    score_plugin_baseline,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _today_str() -> str:
    return datetime.now(UTC).date().isoformat()


# ---------------------------------------------------------------------------
# Integration tests — use committed fixture data (tests/fixtures/data/raw/)
# so these pass in CI without the gitignored data/raw/ tree.
# ---------------------------------------------------------------------------


def test_score_range_and_shape(fixture_data_dir, monkeypatch):
    monkeypatch.setattr(_baseline_mod, "_DATA_ROOT", fixture_data_dir)
    r = score_plugin_baseline("workflow-cps")
    d = r.to_dict()

    assert d["plugin"] == "workflow-cps"
    assert 0 <= d["score"] <= 100
    assert isinstance(d["reasons"], list)
    assert len(d["reasons"]) >= 1
    if "features" in d:
        assert isinstance(d["features"], dict)


def test_score_is_deterministic(fixture_data_dir, monkeypatch):
    monkeypatch.setattr(_baseline_mod, "_DATA_ROOT", fixture_data_dir)
    d1 = score_plugin_baseline("workflow-cps").to_dict()
    d2 = score_plugin_baseline("workflow-cps").to_dict()
    assert d1 == d2


def test_score_security_keyword(fixture_data_dir, monkeypatch):
    monkeypatch.setattr(_baseline_mod, "_DATA_ROOT", fixture_data_dir)
    d = score_plugin_baseline("credentials").to_dict()
    assert d["score"] >= 20


def test_score_default_baseline_low(fixture_data_dir, monkeypatch):
    monkeypatch.setattr(_baseline_mod, "_DATA_ROOT", fixture_data_dir)
    d = score_plugin_baseline("totally-random-plugin-name").to_dict()
    assert 0 <= d["score"] <= 10


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
    assert _safe_plugin_id("plugin name") is None


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
    assert _parse_iso_datetime("2025-03-15T12:00:00Z") is not None


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


@pytest.mark.parametrize(
    "score,expected",
    [
        # Exact lower edges of each severity band
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
    ],
)
def test_cvss_base_score_to_label_exact_boundaries(score: float, expected: str) -> None:
    """Pin the four boundary constants so off-by-one mutations are caught."""
    assert _cvss_base_score_to_label(score) == expected


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
    assert _healthscore_to_risk_points(200) == 0


def test_healthscore_to_risk_points_clamps_low():
    assert _healthscore_to_risk_points(-10) == 20


@pytest.mark.parametrize(
    "value,expected",
    [
        # int(round((100 - v) / 5))  — probes both the divisor (5) and subtrahend (100)
        (95, 1),
        (90, 2),
        (75, 5),
        (60, 8),
        (40, 12),
        (20, 16),
        (5, 19),
    ],
)
def test_healthscore_to_risk_points_intermediate_values(value: int, expected: int) -> None:
    """Pin the formula constants so mutations to 5.0 or 100.0 are caught."""
    assert _healthscore_to_risk_points(value) == expected


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
    assert sorted(_extract_dependency_plugin_ids(snap)) == ["plain-credentials", "token-macro"]


def test_extract_dependency_plugin_ids_deduplicates():
    snap = {
        "plugin_api": {
            "dependencies": [
                {"name": "same-plugin"},
                {"name": "same-plugin"},
            ]
        }
    }
    assert _extract_dependency_plugin_ids(snap) == ["same-plugin"]


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
    assert _extract_dependency_plugin_ids(snap) == ["valid-plugin"]


# ---------------------------------------------------------------------------
# _load_plugin_snapshot
# ---------------------------------------------------------------------------


def test_load_plugin_snapshot_returns_none_for_missing(tmp_path: Path):
    assert _load_plugin_snapshot("no-such-plugin", tmp_path) is None


def test_load_plugin_snapshot_returns_none_for_invalid_id(tmp_path: Path):
    assert _load_plugin_snapshot("../invalid", tmp_path) is None


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


def test_load_advisories_returns_empty_when_no_files(tmp_path: Path):
    assert _load_advisories_for_plugin("no-plugin", tmp_path) == []


def test_load_advisories_reads_real_jsonl(tmp_path: Path):
    _write_jsonl(
        tmp_path / "advisories" / "my-plugin.advisories.real.jsonl",
        [{"plugin_id": "my-plugin", "advisory_id": "2025-01-01"}],
    )
    result = _load_advisories_for_plugin("my-plugin", tmp_path, prefer_real=True)
    assert len(result) == 1
    assert result[0]["advisory_id"] == "2025-01-01"


def test_load_advisories_reads_sample_jsonl(tmp_path: Path):
    _write_jsonl(
        tmp_path / "advisories" / "my-plugin.advisories.sample.jsonl",
        [{"plugin_id": "my-plugin", "advisory_id": "2025-02-01"}],
    )
    assert len(_load_advisories_for_plugin("my-plugin", tmp_path)) == 1


def test_load_advisories_prefer_real_over_sample(tmp_path: Path):
    _write_jsonl(
        tmp_path / "advisories" / "my-plugin.advisories.real.jsonl",
        [{"advisory_id": "real-001"}],
    )
    _write_jsonl(
        tmp_path / "advisories" / "my-plugin.advisories.sample.jsonl",
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


def test_load_healthscore_record_aggregate_file(tmp_path: Path):
    hs_dir = tmp_path / "healthscore"
    hs_dir.mkdir(parents=True)
    agg = {
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"my-plugin": {"value": 60, "date": "2024-01-01"}},
    }
    (hs_dir / "plugins.healthscore.json").write_text(json.dumps(agg), encoding="utf-8")

    result = _load_healthscore_record("my-plugin", tmp_path)
    assert result is not None
    assert result["value"] == 60


def test_load_healthscore_record_aggregate_nested_plugins_dir(tmp_path: Path):
    hs_plugins_dir = tmp_path / "healthscore" / "plugins"
    hs_plugins_dir.mkdir(parents=True)
    agg = {
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"nested-plugin": {"value": 55, "date": "2024-01-01"}},
    }
    (hs_plugins_dir / "plugins.healthscore.json").write_text(json.dumps(agg), encoding="utf-8")

    result = _load_healthscore_record("nested-plugin", tmp_path)
    assert result is not None
    assert result["value"] == 55


def test_load_healthscore_record_malformed_aggregate_returns_none(tmp_path: Path):
    hs_dir = tmp_path / "healthscore"
    hs_dir.mkdir(parents=True)
    (hs_dir / "plugins.healthscore.json").write_text("not json {{{", encoding="utf-8")
    assert _load_healthscore_record("my-plugin", tmp_path) is None


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


# ---------------------------------------------------------------------------
# _dependency_points
# ---------------------------------------------------------------------------


def test_dependency_points_no_data(tmp_path: Path):
    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=date.today(),
        prefer_real=False,
    )
    assert pts == 0
    assert details["advisory_count"] == 0
    assert details["recent_advisory_365d"] is False


def test_dependency_points_with_advisories(tmp_path: Path):
    _write_jsonl(
        tmp_path / "advisories" / "dep-plugin.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": _today_str(),
                "vulnerabilities": [{"cvss": {"base_score": 7.5}}],
            }
        ],
    )

    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=date.today(),
        prefer_real=False,
    )
    assert pts > 0
    assert details["advisory_count"] == 1
    assert details["recent_advisory_365d"] is True
    assert details["max_cvss"] == 7.5


def test_dependency_points_with_active_security_warnings(tmp_path: Path):
    snap = {
        "plugin_id": "dep-plugin",
        "plugin_api": {
            "securityWarnings": [
                {"id": "SECURITY-1", "active": True},
                {"id": "SECURITY-2", "active": False},
            ]
        },
    }
    _write_json(tmp_path / "plugins" / "dep-plugin.snapshot.json", snap)

    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=date.today(),
        prefer_real=False,
    )
    assert details["active_security_warning_count"] == 1
    assert pts > 0


def test_dependency_points_with_healthscore(tmp_path: Path):
    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    (hs_dir / "dep-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "dep-plugin",
                "collected_at": "2024-01-01T00:00:00+00:00",
                "record": {"value": 20},
            }
        ),
        encoding="utf-8",
    )

    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=date.today(),
        prefer_real=False,
    )
    assert details["healthscore"] == 20
    assert pts > 0


# ---------------------------------------------------------------------------
# score_plugin_baseline — integration with monkeypatched data dir
# ---------------------------------------------------------------------------


def test_score_plugin_baseline_with_snapshot(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {
            "requiredCore": "2.346",
            "dependencies": [],
            "securityWarnings": [],
            "releaseTimestamp": "2025-01-01T00:00:00+00:00",
        },
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["plugin"] == "test-plugin"
    assert 0 <= d["score"] <= 100
    assert any("2.346" in r for r in d["reasons"])


def test_score_plugin_baseline_with_advisories(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    _write_jsonl(
        tmp_path / "advisories" / "test-plugin.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": _today_str(),
                "vulnerabilities": [{"cvss": {"base_score": 9.1}}],
            }
        ],
    )

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["score"] > 0
    assert d["features"]["advisory_count"] == 1
    assert any("advisory" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_healthscore(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    (hs_dir / "test-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "test-plugin",
                "collected_at": "2024-01-01T00:00:00+00:00",
                "record": {"value": 0},
            }
        ),
        encoding="utf-8",
    )

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["features"]["healthscore_value"] == 0
    assert any("health score" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_active_security_warnings(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {
            "dependencies": [],
            "securityWarnings": [
                {"id": "SECURITY-100", "active": True},
                {"id": "SECURITY-200", "active": True},
            ],
        },
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["features"]["active_security_warning_count"] == 2
    assert any("active security warning" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_many_deps(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    deps = [{"name": f"dep-{i}", "version": "1.0"} for i in range(12)]
    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {"dependencies": deps, "securityWarnings": []},
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["features"]["dependency_count"] == 12
    assert any("dependency" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_dep_advisories(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {
            "dependencies": [{"name": "risky-dep", "version": "1.0"}],
            "securityWarnings": [],
        },
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    _write_jsonl(
        tmp_path / "advisories" / "risky-dep.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": _today_str(),
                "vulnerabilities": [{"cvss": {"base_score": 9.5}}],
            }
        ],
    )

    d = score_plugin_baseline("test-plugin").to_dict()
    assert d["features"]["dependency_total"] == 1
    assert d["features"]["dependency_risk_points"] > 0


def test_score_plugin_baseline_invalid_plugin_id_raises(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    with pytest.raises(ValueError, match="Invalid plugin id"):
        score_plugin_baseline("../../../etc/passwd")


def test_score_plugin_baseline_no_heuristics_returns_default(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    d = score_plugin_baseline("totally-unknown-plugin-xyzzy").to_dict()
    assert d["score"] >= 5
    assert any("No heuristics matched" in r or "No advisories found" in r for r in d["reasons"])


def test_score_plugin_baseline_security_keyword(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    d = score_plugin_baseline("my-credentials-plugin").to_dict()
    assert d["score"] >= 20
    assert any("auth/security" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_old_advisory_no_recency_bonus(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    _write_jsonl(
        tmp_path / "advisories" / "old-plugin.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2020-01-01",
                "published_date": "2020-01-01",
                "vulnerabilities": [],
            }
        ],
    )

    d = score_plugin_baseline("old-plugin").to_dict()
    assert d["features"]["advisory_count"] == 1
    assert d["features"]["had_advisory_within_365d"] is False
    assert any("365 days" in r for r in d["reasons"])


def test_score_plugin_baseline_recent_release_reduces_score(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    snap = {
        "plugin_id": "active-plugin",
        "plugin_api": {
            "dependencies": [],
            "securityWarnings": [],
            "releaseTimestamp": datetime.now(UTC).isoformat(),
        },
    }
    _write_json(tmp_path / "plugins" / "active-plugin.snapshot.json", snap)

    d = score_plugin_baseline("active-plugin").to_dict()
    assert any("maintenance" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_five_to_nine_deps(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    deps = [{"name": f"dep-{i}", "version": "1.0"} for i in range(7)]
    snap = {
        "plugin_id": "medium-plugin",
        "plugin_api": {"dependencies": deps, "securityWarnings": []},
    }
    _write_json(tmp_path / "plugins" / "medium-plugin.snapshot.json", snap)

    d = score_plugin_baseline("medium-plugin").to_dict()
    assert d["features"]["dependency_count"] == 7


# ---------------------------------------------------------------------------
# _advisory_record_max_cvss — additional edge cases
# ---------------------------------------------------------------------------


def test_advisory_record_max_cvss_multiple_vulnerabilities_returns_max():
    rec = {
        "vulnerabilities": [
            {"cvss": {"base_score": 4.3}},
            {"cvss": {"base_score": 9.1}},
            {"cvss": {"base_score": 6.5}},
        ]
    }
    assert _advisory_record_max_cvss(rec) == 9.1


def test_advisory_record_max_cvss_string_score_is_parsed():
    rec = {"vulnerabilities": [{"cvss": {"base_score": "8.2"}}]}
    assert _advisory_record_max_cvss(rec) == 8.2


def test_advisory_record_max_cvss_invalid_string_skipped_valid_kept():
    rec = {
        "vulnerabilities": [
            {"cvss": {"base_score": "not-a-number"}},
            {"cvss": {"base_score": 5.0}},
        ]
    }
    assert _advisory_record_max_cvss(rec) == 5.0


def test_advisory_record_max_cvss_non_dict_vuln_entry_skipped():
    rec = {"vulnerabilities": ["not-a-dict", {"cvss": {"base_score": 5.5}}]}
    assert _advisory_record_max_cvss(rec) == 5.5


def test_advisory_record_max_cvss_missing_cvss_key_skipped():
    rec = {
        "vulnerabilities": [
            {"severity": "high"},
            {"cvss": {"base_score": 7.0}},
        ]
    }
    assert _advisory_record_max_cvss(rec) == 7.0


def test_advisory_record_max_cvss_none_vulnerabilities_key():
    assert _advisory_record_max_cvss({"vulnerabilities": None}) is None


def test_advisory_record_max_cvss_zero_is_valid():
    assert _advisory_record_max_cvss({"vulnerabilities": [{"cvss": {"base_score": 0.0}}]}) == 0.0


# ---------------------------------------------------------------------------
# _staleness_points
# ---------------------------------------------------------------------------


class TestStalenessPoints:
    """Pure-function tests for _staleness_points — no I/O, no mocks needed."""

    def test_no_data_returns_zero(self) -> None:
        pts, reasons = _staleness_points(None, None)
        assert pts == 0
        assert reasons == []

    def test_recent_commit_returns_zero_points(self) -> None:
        pts, reasons = _staleness_points(30, None)
        assert pts == 0
        assert any("recent" in r.lower() or "active" in r.lower() for r in reasons)

    def test_six_to_twelve_months_stale(self) -> None:
        pts, reasons = _staleness_points(200, None)
        assert pts == 3
        assert any("staleness" in r.lower() for r in reasons)

    def test_one_to_two_years_stale(self) -> None:
        pts, _ = _staleness_points(400, None)
        assert pts == 6

    def test_two_to_three_years_stale(self) -> None:
        pts, _ = _staleness_points(800, None)
        assert pts == 9

    def test_three_to_five_years_stale(self) -> None:
        pts, _ = _staleness_points(1200, None)
        assert pts == 12

    def test_over_five_years_stale(self) -> None:
        pts, _ = _staleness_points(2000, None)
        assert pts == 16

    def test_cap_is_respected(self) -> None:
        pts, _ = _staleness_points(9999, 9999)
        assert pts <= _CAP_STALENESS

    def test_release_staleness_only_when_no_commits(self) -> None:
        pts, reasons = _staleness_points(None, 800)
        assert pts > 0
        assert any("release" in r.lower() for r in reasons)

    def test_release_staleness_not_double_counted(self) -> None:
        pts_commit_only, _ = _staleness_points(2000, None)
        pts_both, _ = _staleness_points(2000, 800)
        assert pts_both <= _CAP_STALENESS
        assert pts_both >= pts_commit_only

    def test_recent_release_adds_reason(self) -> None:
        pts, reasons = _staleness_points(None, 90)
        assert any("recent" in r.lower() or "active" in r.lower() for r in reasons)

    def test_invalid_commit_value_handled(self) -> None:
        pts, _ = _staleness_points("not-a-number", None)  # type: ignore[arg-type]
        assert pts == 0

    def test_float_input_accepted(self) -> None:
        pts, _ = _staleness_points(400.7, None)
        assert pts == 6

    def test_exactly_180_days_is_not_stale(self) -> None:
        assert _staleness_points(180, None)[0] == 0

    def test_exactly_181_days_is_stale(self) -> None:
        assert _staleness_points(181, None)[0] == 3

    @pytest.mark.parametrize(
        "days,expected_pts",
        [
            # Exact threshold value — still in the LOWER bracket (threshold is strict >)
            # dsc > 365 is False at 365, but dsc > 180 is True, so pts = 3
            (365, 3),
            # dsc > 730 is False at 730, but dsc > 365 is True, so pts = 6
            (730, 6),
            # dsc > 1095 is False at 1095, but dsc > 730 is True, so pts = 9
            (1095, 9),
            # dsc > 1825 is False at 1825, but dsc > 1095 is True, so pts = 12
            (1825, 12),
            # One day past each threshold — crosses into the HIGHER bracket
            (366, 6),
            (731, 9),
            (1096, 12),
            (1826, 16),
        ],
    )
    def test_staleness_exact_bracket_boundaries(self, days: int, expected_pts: int) -> None:
        """Pin every staleness threshold so mutations to the constants are caught."""
        pts, _ = _staleness_points(days, None)
        assert pts == expected_pts


# ---------------------------------------------------------------------------
# _governance_points
# ---------------------------------------------------------------------------


class TestGovernancePoints:
    """Pure-function tests for _governance_points."""

    def test_not_present_returns_zero(self) -> None:
        pts, reasons = _governance_points({})
        assert pts == 0
        assert reasons == []

    def test_not_present_flag_returns_zero(self) -> None:
        pts, reasons = _governance_points({"swh_present": False})
        assert pts == 0
        assert reasons == []

    def test_all_governance_artifacts_present_low_score(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": True,
            "swh_has_dependabot": True,
            "swh_has_tests_directory": True,
            "swh_has_changelog": True,
        }
        pts, reasons = _governance_points(swh)
        assert pts == 0
        assert reasons == []

    def test_missing_security_md_adds_points(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": False,
            "swh_has_dependabot": True,
            "swh_has_tests_directory": True,
            "swh_has_changelog": True,
        }
        pts, reasons = _governance_points(swh)
        assert pts == 3
        assert any("SECURITY.md" in r for r in reasons)

    def test_missing_automation_adds_points(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": True,
            "swh_has_dependabot": False,
            "swh_has_github_actions": False,
            "swh_has_tests_directory": True,
            "swh_has_changelog": True,
        }
        pts, reasons = _governance_points(swh)
        assert pts == 3
        assert any("Dependabot" in r for r in reasons)

    def test_github_actions_satisfies_automation(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": True,
            "swh_has_dependabot": False,
            "swh_has_github_actions": True,
            "swh_has_tests_directory": True,
            "swh_has_changelog": True,
        }
        pts, _ = _governance_points(swh)
        assert pts == 0

    def test_missing_tests_directory_adds_points(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": True,
            "swh_has_dependabot": True,
            "swh_has_tests_directory": False,
            "swh_has_changelog": True,
        }
        pts, reasons = _governance_points(swh)
        assert pts == 2
        assert any("test" in r.lower() for r in reasons)

    def test_missing_changelog_adds_points(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": True,
            "swh_has_dependabot": True,
            "swh_has_tests_directory": True,
            "swh_has_changelog": False,
        }
        pts, reasons = _governance_points(swh)
        assert pts == 2
        assert any("changelog" in r.lower() for r in reasons)

    def test_all_missing_respects_cap(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": False,
            "swh_has_dependabot": False,
            "swh_has_github_actions": False,
            "swh_has_tests_directory": False,
            "swh_has_changelog": False,
        }
        pts, _ = _governance_points(swh)
        assert pts <= _CAP_GOVERNANCE

    def test_all_missing_accumulates_all_penalties(self) -> None:
        swh = {
            "swh_present": True,
            "swh_has_security_md": False,
            "swh_has_dependabot": False,
            "swh_has_github_actions": False,
            "swh_has_tests_directory": False,
            "swh_has_changelog": False,
        }
        pts, reasons = _governance_points(swh)
        assert pts == _CAP_GOVERNANCE
        assert len(reasons) == 4


# ---------------------------------------------------------------------------
# score_plugin_baseline — advisory formula component tests
# ---------------------------------------------------------------------------
# The advisory scoring formula inside score_plugin_baseline is:
#   history_pts = min(15, advisory_count * 2)
#   recency_pts = min(15, within_90 * 10 + max(0, within_365 - within_90) * 5)
#   advisory_history_pts = min(_CAP_ADVISORY_HISTORY, history_pts + recency_pts)
#
# These tests place advisories at controlled dates to pin the exact multipliers
# (2, 10, 5) so that mutations to those constants are detected.
# ---------------------------------------------------------------------------


def _days_ago(n: int) -> str:
    """Return an ISO date string for n days before today."""
    from datetime import timedelta

    return (datetime.now(UTC).date() - timedelta(days=n)).isoformat()


class TestAdvisoryFormulaComponents:
    """Pin the exact history_pts and recency_pts multipliers in score_plugin_baseline."""

    def _setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisories: list[dict]
    ) -> None:
        import canary.scoring.baseline as baseline

        monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
        monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)
        _write_jsonl(
            tmp_path / "advisories" / "test-plugin.advisories.sample.jsonl",
            advisories,
        )

    def test_history_pts_two_per_advisory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """3 old advisories → history_pts = 3*2 = 6, recency_pts = 0 → score includes exactly 6."""
        self._setup(
            tmp_path,
            monkeypatch,
            [{"advisory_id": f"A{i}", "published_date": _days_ago(400 + i)} for i in range(3)],
        )
        result = score_plugin_baseline("test-plugin")
        # history_pts = 6, recency_pts = 0  →  advisory component = 6
        # Verify by checking that the score is at least 6 and the reasons mention the count
        assert result.score >= 6
        assert any("3 prior advisory" in r for r in result.reasons)

    def test_history_pts_caps_at_15(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """8 old advisories → history_pts = min(15, 16) = 15 (cap applies)."""
        self._setup(
            tmp_path,
            monkeypatch,
            [{"advisory_id": f"A{i}", "published_date": _days_ago(400 + i)} for i in range(8)],
        )
        result = score_plugin_baseline("test-plugin")
        assert any("8 prior advisory" in r for r in result.reasons)
        # history_pts is capped at 15 — the component total in the reason line must show <= 30
        reason = next(r for r in result.reasons if "prior advisory" in r)
        assert "history +15" in reason

    def test_recency_pts_within_90d(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """2 advisories within 90 days → recency_pts = 2*10 = 20 (capped at 15)."""
        self._setup(
            tmp_path,
            monkeypatch,
            [
                {"advisory_id": "A1", "published_date": _days_ago(10)},
                {"advisory_id": "A2", "published_date": _days_ago(30)},
            ],
        )
        result = score_plugin_baseline("test-plugin")
        reason = next(r for r in result.reasons if "prior advisory" in r)
        # 2 within 90d → within_90*10 = 20, capped at 15
        assert "recency +15" in reason

    def test_recency_pts_within_365d_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """1 advisory between 90-365 days ago → recency = (0*10 + 1*5) = 5."""
        self._setup(
            tmp_path,
            monkeypatch,
            [{"advisory_id": "A1", "published_date": _days_ago(180)}],
        )
        result = score_plugin_baseline("test-plugin")
        reason = next(r for r in result.reasons if "prior advisory" in r)
        # history=2, recency=5 → total=7
        assert "history +2" in reason
        assert "recency +5" in reason

    def test_mixed_90d_and_365d_recency(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """1 within 90d, 2 between 90-365d → recency = 1*10 + 2*5 = 20, capped at 15."""
        self._setup(
            tmp_path,
            monkeypatch,
            [
                {"advisory_id": "A1", "published_date": _days_ago(30)},
                {"advisory_id": "A2", "published_date": _days_ago(180)},
                {"advisory_id": "A3", "published_date": _days_ago(200)},
            ],
        )
        result = score_plugin_baseline("test-plugin")
        reason = next(r for r in result.reasons if "prior advisory" in r)
        assert "recency +15" in reason  # capped: 10 + 10 = 20 → min(15, 20) = 15

    def test_advisory_component_total_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Component total is capped at _CAP_ADVISORY_HISTORY = 30."""
        self._setup(
            tmp_path,
            monkeypatch,
            [{"advisory_id": f"A{i}", "published_date": _days_ago(10 + i)} for i in range(10)],
        )
        result = score_plugin_baseline("test-plugin")
        reason = next(r for r in result.reasons if "prior advisory" in r)
        # history=15 (cap), recency=15 (cap) → total=30 (= _CAP_ADVISORY_HISTORY)
        assert f"(cap {_CAP_ADVISORY_HISTORY})" in reason
        assert result.score <= 100


# ---------------------------------------------------------------------------
# _staleness_points — release staleness sub-path
# ---------------------------------------------------------------------------
# The release path formula is: rel_pts = min(8, dsr // 365 * 3)
# It only fires when dsr > 730, and only adds a *bonus* above what commit
# staleness already gave.  These tests pin the multiplier (3), the cap (8),
# and the bonus-only accumulation logic.
# ---------------------------------------------------------------------------


class TestStalenessReleaseFormula:
    """Pin the release-staleness sub-formula so mutations to its constants are caught."""

    def test_release_731_days_gives_6_pts(self) -> None:
        # dsr=731 → 731//365=2 → 2*3=6 → min(8,6)=6
        pts, reasons = _staleness_points(None, 731)
        assert pts == 6
        assert any("release" in r.lower() for r in reasons)

    def test_release_1094_days_gives_6_pts(self) -> None:
        # dsr=1094 → 1094//365=2 → 2*3=6 → min(8,6)=6
        pts, _ = _staleness_points(None, 1094)
        assert pts == 6

    def test_release_1095_days_hits_cap(self) -> None:
        # dsr=1095 → 1095//365=3 → 3*3=9 → min(8,9)=8 (cap applies)
        pts, _ = _staleness_points(None, 1095)
        assert pts == 8

    def test_release_cap_is_8_not_higher(self) -> None:
        # Very old release should not exceed 8
        pts, _ = _staleness_points(None, 9999)
        assert pts == 8

    def test_release_bonus_over_commit_pts(self) -> None:
        # commit=181d → 3 pts; release=731d → rel_pts=6; bonus=6-3=3 → total=6
        pts, _ = _staleness_points(181, 731)
        assert pts == 6

    def test_release_no_bonus_when_commit_already_exceeds(self) -> None:
        # commit=800d → 9 pts; release=731d → rel_pts=6; 6 < 9 → no bonus → still 9
        pts, _ = _staleness_points(800, 731)
        assert pts == 9

    def test_release_recent_180d_adds_reason_no_pts(self) -> None:
        # dsr=90 → does not exceed 730 threshold, just adds a maintenance reason
        pts, reasons = _staleness_points(None, 90)
        assert pts == 0
        assert any("recent" in r.lower() or "active" in r.lower() for r in reasons)


# ---------------------------------------------------------------------------
# _dependency_points — exact component value tests
# ---------------------------------------------------------------------------
# The function accumulates points from four sub-components:
#   advisory history: min(10, advisory_count * 2)
#   CVSS severity:    >= 9.0 → 6,  >= 7.0 → 4,  >= 4.0 → 2,  else 0
#   recency:          recent advisory within 365d → +3
#   active warnings:  min(10, active_warn * 5)
#   healthscore:      int(round((100 - hv) / 25))  capped at [0, 4]
# Existing tests only assert pts > 0; these pin the exact formula values.
# ---------------------------------------------------------------------------


class TestDependencyPointsFormula:
    """Pin exact sub-component values in _dependency_points."""

    def _adv(self, cvss: float | None, days_ago: int = 400) -> dict:
        from datetime import timedelta

        pub = (date.today() - timedelta(days=days_ago)).isoformat()
        rec: dict = {"advisory_id": "A1", "published_date": pub}
        if cvss is not None:
            rec["vulnerabilities"] = [{"cvss": {"base_score": cvss}}]
        return rec

    def _write_advisory(self, tmp_path: Path, records: list[dict]) -> None:
        _write_jsonl(
            tmp_path / "advisories" / "dep-plugin.advisories.sample.jsonl",
            records,
        )

    def test_advisory_history_multiplier_2(self, tmp_path: Path) -> None:
        # 3 old advisories, no recent → adv_pts = min(10, 3*2) = 6
        self._write_advisory(tmp_path, [self._adv(None) for _ in range(3)])
        pts, details = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        # only advisory history contributes (no cvss, no recency)
        assert pts == 6
        assert details["advisory_count"] == 3

    def test_advisory_history_cap_at_10(self, tmp_path: Path) -> None:
        # 6 advisories → 6*2=12 → min(10, 12)=10
        self._write_advisory(tmp_path, [self._adv(None, days_ago=400 + i) for i in range(6)])
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 10

    def test_cvss_low_boundary_4_0(self, tmp_path: Path) -> None:
        # CVSS 4.0 → sev_pts = 2 (>= 4.0 branch)
        self._write_advisory(tmp_path, [self._adv(4.0)])
        _, details = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert details["max_cvss"] == 4.0
        # adv_pts=2, sev_pts=2 → total=4 (no recency since advisory is 400d old)
        # check severity component via reasons
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 4  # 2 (advisory) + 2 (CVSS >= 4.0)

    def test_cvss_medium_boundary_7_0(self, tmp_path: Path) -> None:
        # CVSS 7.0 → sev_pts = 4 (>= 7.0 branch)
        self._write_advisory(tmp_path, [self._adv(7.0)])
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 6  # 2 (advisory) + 4 (CVSS >= 7.0)

    def test_cvss_critical_boundary_9_0(self, tmp_path: Path) -> None:
        # CVSS 9.0 → sev_pts = 6 (>= 9.0 branch)
        self._write_advisory(tmp_path, [self._adv(9.0)])
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 8  # 2 (advisory) + 6 (CVSS >= 9.0)

    def test_cvss_below_4_gives_zero_severity(self, tmp_path: Path) -> None:
        # CVSS 3.9 → sev_pts = 0
        self._write_advisory(tmp_path, [self._adv(3.9)])
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 2  # 2 (advisory) + 0 (no CVSS bonus)

    def test_recency_adds_3_pts(self, tmp_path: Path) -> None:
        # 1 advisory within 365d (no CVSS) → adv_pts=2 + recency=3 = 5
        from datetime import timedelta

        recent = (date.today() - timedelta(days=30)).isoformat()
        self._write_advisory(tmp_path, [{"advisory_id": "A1", "published_date": recent}])
        pts, details = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert details["recent_advisory_365d"] is True
        assert pts == 5  # 2 + 3

    def test_active_warnings_multiplier_5(self, tmp_path: Path) -> None:
        # 2 active warnings → min(10, 2*5) = 10
        snap = {
            "plugin_id": "dep-plugin",
            "plugin_api": {
                "securityWarnings": [
                    {"id": "W1", "active": True},
                    {"id": "W2", "active": True},
                ]
            },
        }
        _write_json(tmp_path / "plugins" / "dep-plugin.snapshot.json", snap)
        pts, details = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert details["active_security_warning_count"] == 2
        assert pts == 10

    def test_active_warnings_cap_at_10(self, tmp_path: Path) -> None:
        # 3 active warnings → min(10, 3*5)=10 (same cap as 2)
        snap = {
            "plugin_id": "dep-plugin",
            "plugin_api": {"securityWarnings": [{"id": f"W{i}", "active": True} for i in range(3)]},
        }
        _write_json(tmp_path / "plugins" / "dep-plugin.snapshot.json", snap)
        pts, _ = _dependency_points(
            "dep-plugin", data_dir=tmp_path, today=date.today(), prefer_real=False
        )
        assert pts == 10

    def test_healthscore_formula_divisor_25(self, tmp_path: Path) -> None:
        # hv=75 → int(round((100-75)/25)) = int(round(1.0)) = 1
        # hv=50 → int(round((100-50)/25)) = int(round(2.0)) = 2
        # hv=25 → int(round((100-25)/25)) = int(round(3.0)) = 3
        hs_dir = tmp_path / "healthscore" / "plugins"
        hs_dir.mkdir(parents=True)
        for hv, expected_hs_pts in [(75, 1), (50, 2), (25, 3), (0, 4)]:
            hs_tmp = tmp_path / f"hs_{hv}"
            hs_tmp.mkdir(parents=True, exist_ok=True)
            hs_plugin_dir = hs_tmp / "healthscore" / "plugins"
            hs_plugin_dir.mkdir(parents=True, exist_ok=True)
            (hs_plugin_dir / "dep-plugin.healthscore.json").write_text(
                json.dumps(
                    {
                        "plugin_id": "dep-plugin",
                        "collected_at": "2024-01-01T00:00:00Z",
                        "record": {"value": hv},
                    }
                )
            )
            pts, _ = _dependency_points(
                "dep-plugin", data_dir=hs_tmp, today=date.today(), prefer_real=False
            )
            assert pts == expected_hs_pts, f"hv={hv}: expected pts={expected_hs_pts}, got {pts}"


# ---------------------------------------------------------------------------
# _load_swh_features
# ---------------------------------------------------------------------------


def test_load_swh_features_returns_dict_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Success path: delegates to _load_software_heritage_features and returns its result."""
    import canary.build.features_bundle as fb

    expected = {"swh_present": True, "swh_commit_count": 42}
    monkeypatch.setattr(fb, "_load_software_heritage_features", lambda pid, ddir, **kw: expected)
    result = _load_swh_features("test-plugin", tmp_path)
    assert result == expected


def test_load_swh_features_returns_empty_dict_on_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exception path: any error from the inner import/call returns {}."""
    import canary.build.features_bundle as fb

    monkeypatch.setattr(
        fb,
        "_load_software_heritage_features",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = _load_swh_features("test-plugin", tmp_path)
    assert result == {}
