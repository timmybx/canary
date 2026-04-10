"""Additional integration tests for canary.scoring.baseline using temp data dirs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from canary.scoring.baseline import (
    _dependency_points,
    _load_healthscore_record,
    score_plugin_baseline,
)


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
# _load_healthscore_record — aggregate file path
# ---------------------------------------------------------------------------


def test_load_healthscore_record_aggregate_file(tmp_path: Path):
    hs_dir = tmp_path / "healthscore"
    hs_dir.mkdir(parents=True)
    agg = {
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {
            "my-plugin": {"value": 60, "date": "2024-01-01"},
        },
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
        "record": {
            "nested-plugin": {"value": 55, "date": "2024-01-01"},
        },
    }
    (hs_plugins_dir / "plugins.healthscore.json").write_text(json.dumps(agg), encoding="utf-8")

    result = _load_healthscore_record("nested-plugin", tmp_path)
    assert result is not None
    assert result["value"] == 55


def test_load_healthscore_record_malformed_aggregate_returns_none(tmp_path: Path):
    hs_dir = tmp_path / "healthscore"
    hs_dir.mkdir(parents=True)
    (hs_dir / "plugins.healthscore.json").write_text("not json {{{", encoding="utf-8")
    result = _load_healthscore_record("my-plugin", tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# _dependency_points
# ---------------------------------------------------------------------------


def test_dependency_points_no_data(tmp_path: Path):
    """No advisory or snapshot data -> minimal points."""
    from datetime import date

    today = date.today()
    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=today,
        prefer_real=False,
    )
    assert pts == 0
    assert details["advisory_count"] == 0
    assert details["recent_advisory_365d"] is False


def test_dependency_points_with_advisories(tmp_path: Path):
    from datetime import date

    today = date.today()
    advisories_dir = tmp_path / "advisories"
    today_str = today.isoformat()
    _write_jsonl(
        advisories_dir / "dep-plugin.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": today_str,
                "vulnerabilities": [{"cvss": {"base_score": 7.5}}],
            }
        ],
    )

    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=today,
        prefer_real=False,
    )

    assert pts > 0
    assert details["advisory_count"] == 1
    assert details["recent_advisory_365d"] is True
    assert details["max_cvss"] == 7.5


def test_dependency_points_with_active_security_warnings(tmp_path: Path):
    from datetime import date

    today = date.today()
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
        today=today,
        prefer_real=False,
    )

    assert details["active_security_warning_count"] == 1
    assert pts > 0


def test_dependency_points_with_healthscore(tmp_path: Path):
    from datetime import date

    today = date.today()
    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    payload = {
        "plugin_id": "dep-plugin",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"value": 20},  # low health score -> high risk
    }
    (hs_dir / "dep-plugin.healthscore.json").write_text(json.dumps(payload), encoding="utf-8")

    pts, details = _dependency_points(
        "dep-plugin",
        data_dir=tmp_path,
        today=today,
        prefer_real=False,
    )
    # Low healthscore should contribute points
    assert details["healthscore"] == 20
    assert pts > 0


# ---------------------------------------------------------------------------
# score_plugin_baseline — integration tests with temp data
# ---------------------------------------------------------------------------


def test_score_plugin_baseline_with_snapshot(tmp_path: Path, monkeypatch):
    """score_plugin_baseline returns a valid result when snapshot data exists."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(
        baseline,
        "_resolved_base_dir",
        lambda: tmp_path,
    )

    # Create minimal plugin snapshot
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

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["plugin"] == "test-plugin"
    assert 0 <= d["score"] <= 100
    assert isinstance(d["reasons"], list)
    assert any("2.346" in r for r in d["reasons"])


def test_score_plugin_baseline_with_advisories(tmp_path: Path, monkeypatch):
    """Score includes advisory points when advisory data exists."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    today_str = datetime.now(UTC).date().isoformat()
    _write_jsonl(
        tmp_path / "advisories" / "test-plugin.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": today_str,
                "vulnerabilities": [{"cvss": {"base_score": 9.1}}],
            }
        ],
    )

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["score"] > 0
    assert d["features"]["advisory_count"] == 1
    assert any("advisory" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_healthscore(tmp_path: Path, monkeypatch):
    """Health score data contributes to final score."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    hs_dir = tmp_path / "healthscore" / "plugins"
    hs_dir.mkdir(parents=True)
    payload = {
        "plugin_id": "test-plugin",
        "collected_at": "2024-01-01T00:00:00+00:00",
        "record": {"value": 0},  # very low health -> 20 risk points
    }
    (hs_dir / "test-plugin.healthscore.json").write_text(json.dumps(payload), encoding="utf-8")

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["features"]["healthscore_value"] == 0
    assert any("health score" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_active_security_warnings(tmp_path: Path, monkeypatch):
    """Active security warnings significantly increase score."""
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

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["features"]["active_security_warning_count"] == 2
    assert any("active security warning" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_many_deps(tmp_path: Path, monkeypatch):
    """10+ dependencies trigger dependency surface area scoring."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    deps = [{"name": f"dep-{i}", "version": "1.0"} for i in range(12)]
    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {
            "dependencies": deps,
            "securityWarnings": [],
        },
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["features"]["dependency_count"] == 12
    # Should mention dependency(ies) in reasons
    assert any("dependency" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_dep_advisories(tmp_path: Path, monkeypatch):
    """Risky dependencies increase score."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    # Create main plugin snapshot with one dep
    snap = {
        "plugin_id": "test-plugin",
        "plugin_api": {
            "dependencies": [{"name": "risky-dep", "version": "1.0"}],
            "securityWarnings": [],
        },
    }
    _write_json(tmp_path / "plugins" / "test-plugin.snapshot.json", snap)

    # Create advisory for the dependency
    today_str = datetime.now(UTC).date().isoformat()
    _write_jsonl(
        tmp_path / "advisories" / "risky-dep.advisories.sample.jsonl",
        [
            {
                "advisory_id": "2025-01-01",
                "published_date": today_str,
                "vulnerabilities": [{"cvss": {"base_score": 9.5}}],
            }
        ],
    )

    result = score_plugin_baseline("test-plugin")
    d = result.to_dict()

    assert d["features"]["dependency_total"] == 1
    assert d["features"]["dependency_risk_points"] > 0


def test_score_plugin_baseline_invalid_plugin_id_raises(tmp_path: Path, monkeypatch):
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    with pytest.raises(ValueError, match="Invalid plugin id"):
        score_plugin_baseline("../../../etc/passwd")


def test_score_plugin_baseline_no_heuristics_returns_default(tmp_path: Path, monkeypatch):
    """Totally unknown plugin with no data should return score >= 5 (default floor)."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    result = score_plugin_baseline("totally-unknown-plugin-xyzzy")
    d = result.to_dict()

    assert d["score"] >= 5
    assert any("No heuristics matched" in r or "No advisories found" in r for r in d["reasons"])


def test_score_plugin_baseline_security_keyword(tmp_path: Path, monkeypatch):
    """Plugin with 'credentials' in its name should score >= 20."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    result = score_plugin_baseline("my-credentials-plugin")
    d = result.to_dict()

    assert d["score"] >= 20
    assert any("auth/security" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_old_advisory_no_recency_bonus(tmp_path: Path, monkeypatch):
    """Old advisory (> 365 days ago) should not add recency bonus."""
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

    result = score_plugin_baseline("old-plugin")
    d = result.to_dict()

    assert d["features"]["advisory_count"] == 1
    assert d["features"]["had_advisory_within_365d"] is False
    # The recency reasons should say "no activity in last 365 days"
    assert any("365 days" in r for r in d["reasons"])


def test_score_plugin_baseline_recent_release_reduces_score(tmp_path: Path, monkeypatch):
    """Active maintenance (recent release) should slightly reduce score."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    # Fresh release
    fresh_ts = datetime.now(UTC).isoformat().replace("+00:00", "+00:00")

    snap = {
        "plugin_id": "active-plugin",
        "plugin_api": {
            "dependencies": [],
            "securityWarnings": [],
            "releaseTimestamp": fresh_ts,
        },
    }
    _write_json(tmp_path / "plugins" / "active-plugin.snapshot.json", snap)

    result = score_plugin_baseline("active-plugin")
    d = result.to_dict()

    assert any("maintenance" in r.lower() for r in d["reasons"])


def test_score_plugin_baseline_with_five_to_nine_deps(tmp_path: Path, monkeypatch):
    """5-9 dependencies -> small surface area bump."""
    import canary.scoring.baseline as baseline

    monkeypatch.setattr(baseline, "_DATA_ROOT", tmp_path)
    monkeypatch.setattr(baseline, "_resolved_base_dir", lambda: tmp_path)

    deps = [{"name": f"dep-{i}", "version": "1.0"} for i in range(7)]
    snap = {
        "plugin_id": "medium-plugin",
        "plugin_api": {
            "dependencies": deps,
            "securityWarnings": [],
        },
    }
    _write_json(tmp_path / "plugins" / "medium-plugin.snapshot.json", snap)

    result = score_plugin_baseline("medium-plugin")
    d = result.to_dict()
    assert d["features"]["dependency_count"] == 7
