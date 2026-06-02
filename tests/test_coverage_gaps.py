"""
Coverage gap tests — low-hanging fruit for uncovered pure-logic paths.

Targets:
  - canary/scoring/baseline.py  : _staleness_points, _governance_points,
                                   _advisory_record_max_cvss
  - canary/devtools/pip_audit_wrapper.py : load_ignored_vulns, _ignore_file_path
  - canary/plugin_aliases.py    : snapshot-file alias loading path
  - canary/train/registry.py    : optional model registry completeness
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.devtools.pip_audit_wrapper import load_ignored_vulns
from canary.plugin_aliases import load_plugin_alias_map

# ---------------------------------------------------------------------------
# scoring/baseline.py — _staleness_points
# ---------------------------------------------------------------------------
from canary.scoring.baseline import (  # type: ignore[attr-defined]
    _CAP_GOVERNANCE,
    _CAP_STALENESS,
    _advisory_record_max_cvss,
    _governance_points,
    _staleness_points,
)
from canary.train.registry import AVAILABLE_MODELS, MODEL_REGISTRY, get_model


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
        pts, reasons = _staleness_points(400, None)
        assert pts == 6

    def test_two_to_three_years_stale(self) -> None:
        pts, reasons = _staleness_points(800, None)
        assert pts == 9

    def test_three_to_five_years_stale(self) -> None:
        pts, reasons = _staleness_points(1200, None)
        assert pts == 12

    def test_over_five_years_stale(self) -> None:
        pts, reasons = _staleness_points(2000, None)
        assert pts == 16

    def test_cap_is_respected(self) -> None:
        pts, _ = _staleness_points(9999, 9999)
        assert pts <= _CAP_STALENESS

    def test_release_staleness_only_when_no_commits(self) -> None:
        # release stale > 2 years, no commit data
        pts, reasons = _staleness_points(None, 800)
        assert pts > 0
        assert any("release" in r.lower() for r in reasons)

    def test_release_staleness_not_double_counted(self) -> None:
        # commit staleness already gives pts; release should not exceed cap
        pts_commit_only, _ = _staleness_points(2000, None)
        pts_both, _ = _staleness_points(2000, 800)
        assert pts_both <= _CAP_STALENESS
        # release shouldn't reduce the score
        assert pts_both >= pts_commit_only

    def test_recent_release_adds_reason(self) -> None:
        # days_since_release <= 180 should note active maintenance
        pts, reasons = _staleness_points(None, 90)
        assert any("recent" in r.lower() or "active" in r.lower() for r in reasons)

    def test_invalid_commit_value_handled(self) -> None:
        pts, reasons = _staleness_points("not-a-number", None)  # type: ignore[arg-type]
        assert pts == 0

    def test_float_input_accepted(self) -> None:
        pts, _ = _staleness_points(400.7, None)
        assert pts == 6

    def test_exactly_180_days_is_not_stale(self) -> None:
        pts, _ = _staleness_points(180, None)
        assert pts == 0

    def test_exactly_181_days_is_stale(self) -> None:
        pts, _ = _staleness_points(181, None)
        assert pts == 3


# ---------------------------------------------------------------------------
# scoring/baseline.py — _governance_points
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
        pts, reasons = _governance_points(swh)
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
        # 3 + 3 + 2 + 2 = 10 — should hit the cap
        assert pts == _CAP_GOVERNANCE
        assert len(reasons) == 4


# ---------------------------------------------------------------------------
# scoring/baseline.py — _advisory_record_max_cvss
# ---------------------------------------------------------------------------


class TestCvssFromAdvisoryRecord:
    """Pure-function tests for _advisory_record_max_cvss."""

    def test_empty_record_returns_none(self) -> None:
        assert _advisory_record_max_cvss({}) is None

    def test_single_vulnerability_with_cvss(self) -> None:
        rec = {"vulnerabilities": [{"cvss": {"base_score": 7.5}}]}
        assert _advisory_record_max_cvss(rec) == 7.5

    def test_multiple_vulnerabilities_returns_max(self) -> None:
        rec = {
            "vulnerabilities": [
                {"cvss": {"base_score": 4.3}},
                {"cvss": {"base_score": 9.1}},
                {"cvss": {"base_score": 6.5}},
            ]
        }
        assert _advisory_record_max_cvss(rec) == 9.1

    def test_cvss_as_string_is_parsed(self) -> None:
        rec = {"vulnerabilities": [{"cvss": {"base_score": "8.2"}}]}
        assert _advisory_record_max_cvss(rec) == 8.2

    def test_invalid_cvss_string_skipped(self) -> None:
        rec = {
            "vulnerabilities": [
                {"cvss": {"base_score": "not-a-number"}},
                {"cvss": {"base_score": 5.0}},
            ]
        }
        assert _advisory_record_max_cvss(rec) == 5.0

    def test_falls_back_to_severity_summary(self) -> None:
        rec = {
            "vulnerabilities": [],
            "severity_summary": {"max_cvss_base_score": 6.0},
        }
        assert _advisory_record_max_cvss(rec) == 6.0

    def test_vulnerability_score_preferred_over_summary(self) -> None:
        rec = {
            "vulnerabilities": [{"cvss": {"base_score": 9.8}}],
            "severity_summary": {"max_cvss_base_score": 4.0},
        }
        assert _advisory_record_max_cvss(rec) == 9.8

    def test_non_dict_vulnerability_entry_skipped(self) -> None:
        rec = {"vulnerabilities": ["not-a-dict", {"cvss": {"base_score": 5.5}}]}
        assert _advisory_record_max_cvss(rec) == 5.5

    def test_missing_cvss_key_skipped(self) -> None:
        rec = {
            "vulnerabilities": [
                {"severity": "high"},  # no cvss key
                {"cvss": {"base_score": 7.0}},
            ]
        }
        assert _advisory_record_max_cvss(rec) == 7.0

    def test_non_dict_cvss_skipped(self) -> None:
        rec = {
            "vulnerabilities": [
                {"cvss": "high"},  # not a dict
                {"cvss": {"base_score": 6.0}},
            ]
        }
        assert _advisory_record_max_cvss(rec) == 6.0

    def test_none_vulnerabilities_key(self) -> None:
        rec = {"vulnerabilities": None}
        assert _advisory_record_max_cvss(rec) is None

    def test_zero_score_is_valid(self) -> None:
        rec = {"vulnerabilities": [{"cvss": {"base_score": 0.0}}]}
        assert _advisory_record_max_cvss(rec) == 0.0


# ---------------------------------------------------------------------------
# devtools/pip_audit_wrapper.py — load_ignored_vulns
# ---------------------------------------------------------------------------


class TestLoadIgnoredVulns:
    """Tests for load_ignored_vulns — uses tmp_path, no network needed."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        result = load_ignored_vulns(tmp_path / "nonexistent.txt")
        assert result == []

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text("", encoding="utf-8")
        assert load_ignored_vulns(f) == []

    def test_single_vuln_id(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text("GHSA-1234-5678-abcd\n", encoding="utf-8")
        assert load_ignored_vulns(f) == ["GHSA-1234-5678-abcd"]

    def test_multiple_vuln_ids(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text("GHSA-aaaa-bbbb-cccc\nGHSA-dddd-eeee-ffff\n", encoding="utf-8")
        assert load_ignored_vulns(f) == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]

    def test_comments_are_stripped(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text(
            "GHSA-1111-2222-3333  # known false positive\n"
            "# full comment line\n"
            "GHSA-4444-5555-6666\n",
            encoding="utf-8",
        )
        result = load_ignored_vulns(f)
        assert result == ["GHSA-1111-2222-3333", "GHSA-4444-5555-6666"]

    def test_blank_lines_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text("\n\nGHSA-7777-8888-9999\n\n", encoding="utf-8")
        assert load_ignored_vulns(f) == ["GHSA-7777-8888-9999"]

    def test_whitespace_only_lines_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text("   \nGHSA-abcd-efgh-ijkl\n   \n", encoding="utf-8")
        assert load_ignored_vulns(f) == ["GHSA-abcd-efgh-ijkl"]


# ---------------------------------------------------------------------------
# train/registry.py — model registry completeness
# ---------------------------------------------------------------------------


class TestModelRegistry:
    """Tests for model registry — pure dict/function calls, no I/O."""

    def test_registry_has_all_core_models(self) -> None:
        for name in ("logistic", "random_forest"):
            assert name in MODEL_REGISTRY, f"Missing core model: {name}"

    def test_available_models_is_subset_of_registry(self) -> None:
        assert set(AVAILABLE_MODELS).issubset(set(MODEL_REGISTRY))

    def test_get_model_logistic_returns_object(self) -> None:
        model = get_model("logistic")
        assert model is not None

    def test_get_model_random_forest_returns_object(self) -> None:
        model = get_model("random_forest")
        assert model is not None

    def test_get_model_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown model"):
            get_model("definitely_not_a_model")

    def test_get_model_none_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate a model that failed to import by temporarily setting it to None
        import canary.train.registry as reg

        monkeypatch.setitem(reg.MODEL_REGISTRY, "logistic", None)
        with pytest.raises(ValueError, match="not installed"):
            get_model("logistic")

    def test_registry_values_are_not_strings(self) -> None:
        for name, model in MODEL_REGISTRY.items():
            if model is not None:
                assert not isinstance(model, str), f"{name} stored as string"


# ---------------------------------------------------------------------------
# plugin_aliases.py — snapshot file loading path
# ---------------------------------------------------------------------------


class TestBuildAliasMapSnapshotPath:
    """Test the snapshot file loading branch in build_alias_map."""

    def test_snapshot_file_aliases_are_loaded(self, tmp_path: Path) -> None:
        """A .snapshot.json file with previousNames should register aliases."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        snap = {
            "plugin_id": "my-plugin",
            "plugin_api": {"previousNames": ["old-plugin-name", "older-plugin-name"]},
        }
        (plugins_dir / "my-plugin.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")
        alias_map = load_plugin_alias_map(data_dir=tmp_path)
        assert alias_map.get("old-plugin-name") == "my-plugin"
        assert alias_map.get("older-plugin-name") == "my-plugin"

    def test_snapshot_file_with_no_previous_names(self, tmp_path: Path) -> None:
        """A snapshot with no previousNames should not add aliases."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        snap = {"plugin_id": "clean-plugin", "plugin_api": {}}
        (plugins_dir / "clean-plugin.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")
        alias_map = load_plugin_alias_map(data_dir=tmp_path)
        assert "clean-plugin" not in alias_map

    def test_malformed_snapshot_file_is_skipped(self, tmp_path: Path) -> None:
        """A snapshot file with invalid JSON should not raise."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        (plugins_dir / "bad-plugin.snapshot.json").write_text("not valid json {{", encoding="utf-8")
        alias_map = load_plugin_alias_map(data_dir=tmp_path)
        assert isinstance(alias_map, dict)

    def test_snapshot_without_plugin_id_falls_back_to_filename(self, tmp_path: Path) -> None:
        """A snapshot missing plugin_id should use the filename as canonical."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        snap = {"plugin_api": {"previousNames": ["legacy-name"]}}
        (plugins_dir / "inferred-plugin.snapshot.json").write_text(
            json.dumps(snap), encoding="utf-8"
        )
        alias_map = load_plugin_alias_map(data_dir=tmp_path)
        assert alias_map.get("legacy-name") == "inferred-plugin"
