"""
Behavior tests for canary.build.features_bundle: the static current-point
feature bundle that joins all collector outputs per plugin.

Covers numeric-coercion contracts, payload-shape edge cases observed in real
collected data, the Software Heritage loaders (API and Athena backends, with
static fixtures), path-safety for plugin ids, and the full bundle build.

Consolidates test_build_feature_bundle.py, test_features_bundle_helpers.py,
test_features_bundle_coverage_gaps.py, and
test_features_bundle_swh_athena_fixture.py.
"""

from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import pytest

from canary.build.features_bundle import (
    _advisory_cve_ids,
    _cvss_candidates,
    _days_between_iso_dates,
    _extract_swh_visits,
    _iter_registry_records,
    _latest_installations_total,
    _load_advisory_features,
    _load_gharchive_features,
    _load_github_features,
    _load_healthscore_features,
    _load_snapshot_features,
    _load_software_heritage_features,
    _load_software_heritage_features_api,
    _load_software_heritage_features_athena,
    _max_float,
    _mean_float,
    _parse_iso_date,
    _parse_iso_datetime_prefix,
    _read_json,
    _read_jsonl,
    _repo_url_from_snapshot,
    _resolve_swh_backend_dir,
    _safe_float,
    _snapshot_branch_count,
    _sum_float,
    build_feature_bundle,
)

# ---------------------------------------------------------------------------
# Numeric coercion helpers: NaN/inf must never leak into features
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (42, 42.0),
        (3.14, 3.14),
        ("2.5", 2.5),
        (0, 0.0),
        (-7.5, -7.5),
        ("nan", None),
        ("inf", None),
        ("-inf", None),
        (math.nan, None),
        (math.inf, None),
        (-math.inf, None),
        (None, None),
        ("hello", None),
        ("", None),
    ],
)
def test_safe_float_coerces_numbers_and_rejects_nan_inf(value, expected) -> None:
    if expected is None:
        assert _safe_float(value) is None
    else:
        assert _safe_float(value) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ([], None),
        ([None, None], None),
        ([math.nan, math.inf], None),
        ([1.0, 5.0, 3.0], 5.0),
        ([None, 2.0, None, 7.0, None], 7.0),
        ([42], 42.0),
        ([math.nan, 3.0, math.inf], 3.0),
    ],
)
def test_max_float_ignores_invalid_values(values, expected) -> None:
    if expected is None:
        assert _max_float(values) is None
    else:
        assert _max_float(values) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ([], None),
        ([None, None], None),
        ([1.0, 2.0, 3.0], 2.0),
        ([None, 2.0, None, 4.0], 3.0),
        ([5.0], 5.0),
        (["10", "20"], 15.0),
    ],
)
def test_mean_float_ignores_invalid_values(values, expected) -> None:
    if expected is None:
        assert _mean_float(values) is None
    else:
        assert _mean_float(values) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ([], None),
        ([None, None], None),
        ([1.0, 2.0, 3.0], 6.0),
        ([None, 2.0, None, 3.0], 5.0),
        ([10.0], 10.0),
        ([-1.0, 2.0, -3.0], -2.0),
        ([1.0, math.nan, 2.0], 3.0),
    ],
)
def test_sum_float_ignores_invalid_values(values, expected) -> None:
    if expected is None:
        assert _sum_float(values) is None
    else:
        assert _sum_float(values) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# JSONL / JSON readers and registry iteration
# ---------------------------------------------------------------------------


def test_read_jsonl_nonexistent_file_returns_empty(tmp_path: Path) -> None:
    result = _read_jsonl(tmp_path / "missing.jsonl")
    assert result == []


def test_read_jsonl_valid_records(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2
    assert result[0]["plugin_id"] == "a"
    assert result[1]["plugin_id"] == "b"


def test_read_jsonl_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n\n\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2


def test_read_jsonl_skips_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\nNOT VALID JSON\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2
    assert result[0]["plugin_id"] == "a"
    assert result[1]["plugin_id"] == "b"


def test_read_jsonl_skips_non_dict_records(tmp_path: Path) -> None:
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"plugin_id": "a"}\n[1, 2, 3]\n"a string"\n{"plugin_id": "b"}\n',
        encoding="utf-8",
    )
    result = _read_jsonl(path)
    assert len(result) == 2


def test_read_jsonl_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    assert _read_jsonl(path) == []


def test_read_json_reads_dict(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text('{"key": "value", "count": 42}', encoding="utf-8")
    result = _read_json(path)
    assert result == {"key": "value", "count": 42}


def test_read_json_reads_list(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    result = _read_json(path)
    assert result == [1, 2, 3]


def test_read_json_reads_nested(tmp_path: Path) -> None:
    payload = {"plugin": "test", "scores": [1.0, 2.0], "meta": {"active": True}}
    path = tmp_path / "nested.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    assert _read_json(path) == payload


def test_iter_registry_records_valid(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text(
        '{"plugin_id": "cucumber-reports", "version": "1.0"}\n'
        '{"plugin_id": "workflow-cps", "version": "2.0"}\n',
        encoding="utf-8",
    )
    records = _iter_registry_records(path)
    assert len(records) == 2
    assert records[0]["plugin_id"] == "cucumber-reports"
    assert records[1]["plugin_id"] == "workflow-cps"


def test_iter_registry_records_raises_when_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _iter_registry_records(tmp_path / "nonexistent.jsonl")


def test_iter_registry_records_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text(
        '{"plugin_id": "cucumber-reports"}\n\n\n{"plugin_id": "workflow-cps"}\n',
        encoding="utf-8",
    )
    records = _iter_registry_records(path)
    assert len(records) == 2


def test_iter_registry_records_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "plugins.jsonl"
    path.write_text("", encoding="utf-8")
    records = _iter_registry_records(path)
    assert records == []


# ---------------------------------------------------------------------------
# Payload-shape edge cases observed in real collected data
# ---------------------------------------------------------------------------


def test_latest_installations_total_empty_list() -> None:
    # installs is an empty list
    plugin_api = {"stats": {"installations": []}}
    assert _latest_installations_total(plugin_api) is None


def test_latest_installations_total_non_list_installs() -> None:
    # installs is not a list
    plugin_api = {"stats": {"installations": "not-a-list"}}
    assert _latest_installations_total(plugin_api) is None


def test_latest_installations_total_non_dict_latest() -> None:
    # last element is not a dict
    plugin_api = {"stats": {"installations": ["not-a-dict"]}}
    assert _latest_installations_total(plugin_api) is None


def test_repo_url_from_snapshot_dict_with_link() -> None:
    # repo_url is a dict with "link" key
    snapshot = {"repo_url": {"link": "https://github.com/jenkinsci/demo-plugin"}}
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_dict_with_url_key() -> None:
    # repo_url is a dict with "url" key
    snapshot = {"repo_url": {"url": "https://github.com/jenkinsci/demo-plugin"}}
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_dict_with_no_valid_link() -> None:
    # repo_url is a dict but link/url is absentcontinues loop
    snapshot = {"repo_url": {"other": "value"}}
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_scm_str_in_plugin_api() -> None:
    # falls through to plugin_api.scm as str
    snapshot = {
        "plugin_api": {"scm": "https://github.com/jenkinsci/demo-plugin"},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_scm_dict_with_link() -> None:
    # plugin_api.scm is a dict with "link" key
    snapshot = {
        "plugin_api": {"scm": {"link": "https://github.com/jenkinsci/demo-plugin"}},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_scm_dict_with_url_key() -> None:
    # plugin_api.scm is a dict with "url" key
    snapshot = {
        "plugin_api": {"scm": {"url": "https://github.com/jenkinsci/demo-plugin"}},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_returns_none_when_all_empty() -> None:
    # nothing useful
    snapshot: dict = {}
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_scm_dict_with_no_valid_link() -> None:
    # plugin_api.scm is a dict but has no usable link/urlFalse branch)
    snapshot = {
        "plugin_api": {"scm": {"other": "value"}},
    }
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_plugin_api_dict_no_scm() -> None:
    # plugin_api is a dict but scm is absentFalse branch, scm is None)
    snapshot = {"plugin_api": {"other": "value"}}
    assert _repo_url_from_snapshot(snapshot) is None


def test_cvss_candidates_direct_value() -> None:
    # direct cvss value present and valid
    rec = {"cvss": 7.5}
    result = _cvss_candidates(rec)
    assert 7.5 in result


def test_cvss_candidates_direct_value_invalid_skipped() -> None:
    # direct cvss present but not convertiblebranch where num is None
    rec = {"cvss": "not-a-number"}
    result = _cvss_candidates(rec)
    assert result == []


def test_cvss_candidates_severity_summary_skipped_when_not_dict() -> None:
    # severity_summary is not a dictFalse branch)
    rec = {"severity_summary": "high"}
    result = _cvss_candidates(rec)
    assert result == []


def test_cvss_candidates_vulnerabilities_list() -> None:
    # vulnerabilities list present and processed
    rec = {
        "vulnerabilities": [
            {"cvss": 9.0},
            {"cvss_base_score": 6.5},
            {"cvssScore": 4.0},
        ]
    }
    result = _cvss_candidates(rec)
    assert 9.0 in result
    assert 6.5 in result
    assert 4.0 in result


def test_cvss_candidates_vulnerabilities_non_dict_entry_skipped() -> None:
    # non-dict entry in vulnerabilities is skipped
    rec = {"vulnerabilities": ["not-a-dict", {"cvss": 5.0}]}
    result = _cvss_candidates(rec)
    assert 5.0 in result
    assert len(result) == 1


def test_cvss_candidates_vulnerabilities_empty_list() -> None:
    # empty vulnerabilities listloop body never executed)
    rec = {"vulnerabilities": []}
    result = _cvss_candidates(rec)
    assert result == []


def test_load_snapshot_features_plugin_api_not_dict(tmp_path: Path) -> None:
    # plugin_api is not a dict
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    snapshot = {
        "plugin_id": "demo-plugin",
        "repo_url": "https://github.com/jenkinsci/demo-plugin",
        "plugin_api": "not-a-dict",
    }
    (plugins_dir / "demo-plugin.snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    result = _load_snapshot_features("demo-plugin", tmp_path)
    assert result["snapshot_present"] is True
    # plugin_api defaults to {} so deps/maintainers/labels are all 0
    assert result["snapshot_dependencies_count"] == 0
    assert result["snapshot_maintainers_count"] == 0


def test_parse_iso_date_non_string_returns_none() -> None:
    # not a string

    assert _parse_iso_date(None) is None
    assert _parse_iso_date(42) is None
    assert _parse_iso_date([]) is None


def test_parse_iso_date_empty_string_returns_none() -> None:
    # empty/whitespace string

    assert _parse_iso_date("") is None
    assert _parse_iso_date("   ") is None


def test_parse_iso_date_invalid_format_returns_none() -> None:
    # invalid date stringValueError)

    assert _parse_iso_date("not-a-date") is None
    assert _parse_iso_date("2025-99-99") is None


def test_advisory_cve_ids_no_cve_ids_key() -> None:
    # cve_ids key absentFalse branch, skip to vulns)
    rec = {"vulnerabilities": [{"cve_id": "CVE-2025-0001"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0001" in result


def test_advisory_cve_ids_cve_ids_not_a_list() -> None:
    # cve_ids is not a listFalse branch)
    rec = {"cve_ids": "CVE-2025-0001"}
    result = _advisory_cve_ids(rec)
    assert result == set()


def test_advisory_cve_ids_empty_string_cve_skipped() -> None:
    # cve entry in list is empty stringFalse branch, skip)
    rec = {"cve_ids": ["", "  ", "CVE-2025-0001"]}
    result = _advisory_cve_ids(rec)
    assert result == {"CVE-2025-0001"}


def test_advisory_cve_ids_vulnerabilities_list_cve_id() -> None:
    # vuln with cve_id key
    rec = {"vulnerabilities": [{"cve_id": "CVE-2025-0002", "cvss": 7.5}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0002" in result


def test_advisory_cve_ids_vulnerabilities_non_dict_skipped() -> None:
    # non-dict vuln is skipped
    rec = {"vulnerabilities": ["not-a-dict", {"cve_id": "CVE-2025-0003"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0003" in result
    assert len(result) == 1


def test_advisory_cve_ids_vuln_uses_cve_fallback() -> None:
    # vuln has "cve" key (not cve_id)
    rec = {"vulnerabilities": [{"cve": "CVE-2025-0004"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0004" in result


def test_advisory_cve_ids_vuln_empty_cve_skipped() -> None:
    # vuln with empty/whitespace cveFalse branch)
    rec = {"vulnerabilities": [{"cve_id": "   "}]}
    result = _advisory_cve_ids(rec)
    assert result == set()


def test_load_advisory_features_warnings_not_a_list(tmp_path: Path) -> None:
    # warnings is a non-list truthy valueFalse branch)
    advisories_dir = tmp_path / "advisories"
    advisories_dir.mkdir(parents=True)
    rec = {
        "published_date": "2025-01-01",
        "warnings": "some-string-not-a-list",
    }
    path = advisories_dir / "demo-plugin.advisories.real.jsonl"
    path.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    result = _load_advisory_features("demo-plugin", tmp_path)
    assert result["advisories_present"] is True
    assert result["advisory_active_warning_count"] == 0


def test_load_advisory_features_active_warning_counted(tmp_path: Path) -> None:
    # warnings list with an active dict warning
    advisories_dir = tmp_path / "advisories"
    advisories_dir.mkdir(parents=True)
    rec = {
        "published_date": "2025-01-01",
        "warnings": [
            "not-a-dict",
            {"active": False, "message": "inactive"},
            {"active": True, "message": "active warning"},
        ],
    }
    path = advisories_dir / "demo-plugin.advisories.real.jsonl"
    path.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    result = _load_advisory_features("demo-plugin", tmp_path)
    assert result["advisory_active_warning_count"] == 1


def test_load_github_features_contributors_all_zero(tmp_path: Path) -> None:
    # total contributions == 0False branch, skip top_share)
    github_dir = tmp_path / "github"
    github_dir.mkdir(parents=True)
    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps({"repo_full_name": "jenkinsci/demo-plugin"}), encoding="utf-8"
    )
    (github_dir / "demo-plugin.contributors.json").write_text(
        json.dumps([{"login": "alice", "contributions": 0}]), encoding="utf-8"
    )
    result = _load_github_features("demo-plugin", tmp_path)
    assert result["github_contributors_top_share"] is None


def test_load_github_features_commit_file_valid_days(tmp_path: Path) -> None:
    # commit file name matches pattern and has a parseable integer
    github_dir = tmp_path / "github"
    github_dir.mkdir(parents=True)
    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps({"repo_full_name": "jenkinsci/demo-plugin"}), encoding="utf-8"
    )
    (github_dir / "demo-plugin.commits_365d.json").write_text(
        json.dumps([{"sha": "abc"}, {"sha": "def"}]), encoding="utf-8"
    )
    result = _load_github_features("demo-plugin", tmp_path)
    assert result["github_commits_latest_window_days"] == 365
    assert result["github_commits_latest_window_count"] == 2


def test_load_github_features_commit_file_non_numeric_days(tmp_path: Path) -> None:
    # commit file matches pattern prefix/suffix but has non-numeric days
    github_dir = tmp_path / "github"
    github_dir.mkdir(parents=True)
    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps({"repo_full_name": "jenkinsci/demo-plugin"}), encoding="utf-8"
    )
    # e.g. "demo-plugin.commits_XYZd.json" where "XYZ" is not an int
    (github_dir / "demo-plugin.commits_XYZd.json").write_text(
        json.dumps([{"sha": "abc"}]), encoding="utf-8"
    )
    result = _load_github_features("demo-plugin", tmp_path)
    assert result["github_commits_latest_window_days"] is None


def test_parse_iso_datetime_prefix_non_string() -> None:
    # not a stringreturn None)
    assert _parse_iso_datetime_prefix(None) is None
    assert _parse_iso_datetime_prefix(123) is None


def test_parse_iso_datetime_prefix_empty_string() -> None:
    # empty stringreturn None)
    assert _parse_iso_datetime_prefix("") is None
    assert _parse_iso_datetime_prefix("   ") is None


def test_parse_iso_datetime_prefix_valid_string() -> None:
    # valid stringreturn stripped value)
    result = _parse_iso_datetime_prefix("  2025-06-01T12:00:00+00:00  ")
    assert result == "2025-06-01T12:00:00+00:00"


def test_days_between_iso_dates_none_start() -> None:
    # start is None
    assert _days_between_iso_dates(None, "2025-06-01") is None


def test_days_between_iso_dates_none_end() -> None:
    # end is None
    assert _days_between_iso_dates("2025-01-01", None) is None


def test_days_between_iso_dates_both_none() -> None:
    # both None
    assert _days_between_iso_dates(None, None) is None


def test_days_between_iso_dates_invalid_start() -> None:
    # invalid date stringValueError)
    assert _days_between_iso_dates("not-a-date", "2025-06-01") is None


def test_days_between_iso_dates_invalid_end() -> None:
    # invalid end dateValueError)
    assert _days_between_iso_dates("2025-01-01", "not-a-date") is None


def test_extract_swh_visits_payload_is_list() -> None:
    # payload is a list
    visits = [{"date": "2025-01-01"}, {"date": "2025-06-01"}]
    result = _extract_swh_visits(visits)
    assert len(result) == 2


def test_extract_swh_visits_list_filters_non_dicts() -> None:
    # list with non-dict entries
    result = _extract_swh_visits([{"date": "2025-01-01"}, "not-a-dict", 42])
    assert len(result) == 1


def test_extract_swh_visits_dict_without_recognized_key() -> None:
    # dict without "results" or "visits" keysthen 560
    result = _extract_swh_visits({"other": [{"date": "x"}]})
    assert result == []


def test_extract_swh_visits_dict_with_non_list_results() -> None:
    # dict with "results" key but value is not a listcontinue)
    result = _extract_swh_visits({"results": "not-a-list", "visits": [{"date": "x"}]})
    assert len(result) == 1


def test_extract_swh_visits_non_dict_non_list() -> None:
    # payload is neither list nor dict
    assert _extract_swh_visits(None) == []
    assert _extract_swh_visits(42) == []
    assert _extract_swh_visits("string") == []


def test_snapshot_branch_count_non_dict() -> None:
    # not a dict
    assert _snapshot_branch_count(None) == 0
    assert _snapshot_branch_count([]) == 0
    assert _snapshot_branch_count("string") == 0


def test_snapshot_branch_count_branches_as_list() -> None:
    # branches is a list
    payload = {"branches": ["main", "dev", "feature"]}
    assert _snapshot_branch_count(payload) == 3


def test_snapshot_branch_count_branches_neither() -> None:
    # branches key exists but is neither dict nor list
    payload = {"branches": "main"}
    assert _snapshot_branch_count(payload) == 0


def test_snapshot_branch_count_no_branches_key() -> None:
    # no branches key at all
    payload = {"other": "value"}
    assert _snapshot_branch_count(payload) == 0


def test_resolve_swh_backend_dir_fallback_to_api(tmp_path: Path) -> None:
    # athena dir does not exist
    result = _resolve_swh_backend_dir(tmp_path)
    assert result == tmp_path / "software_heritage_api"


def test_resolve_swh_backend_dir_athena_exists(tmp_path: Path) -> None:
    # athena dir existsnot 586)
    athena_dir = tmp_path / "software_heritage_athena"
    athena_dir.mkdir()
    result = _resolve_swh_backend_dir(tmp_path)
    assert result == athena_dir


def test_load_swh_athena_index_present_but_visits_empty(tmp_path: Path) -> None:
    # index_path exists, visits emptyFalse branch)
    swh_dir = tmp_path / "software_heritage_athena"
    swh_dir.mkdir(parents=True)
    index = {"record_count": 0}
    (swh_dir / "demo-plugin.swh_athena_index.json").write_text(json.dumps(index), encoding="utf-8")
    # visits file absent (or empty)
    result = _load_software_heritage_features_athena("demo-plugin", tmp_path)
    assert result["swh_present"] is True
    assert result["swh_has_snapshot"] is False
    assert result["swh_visit_count"] == 0
    assert result["swh_first_visit_date"] is None


def test_load_swh_athena_visit_with_no_valid_date(tmp_path: Path) -> None:
    # visits present but visit_date not parseableFalse branch)
    swh_dir = tmp_path / "software_heritage_athena"
    swh_dir.mkdir(parents=True)
    index = {"record_count": 1}
    (swh_dir / "demo-plugin.swh_athena_index.json").write_text(json.dumps(index), encoding="utf-8")
    # visit record with no valid visit_date
    visit = {"visit_date": None, "has_readme": True}
    visits_path = swh_dir / "demo-plugin.swh_athena_visits.jsonl"
    visits_path.write_text(json.dumps(visit) + "\n", encoding="utf-8")
    result = _load_software_heritage_features_athena("demo-plugin", tmp_path)
    assert result["swh_visit_count"] == 1
    assert result["swh_first_visit_date"] is None  # no valid dates
    assert result["swh_latest_visit_date"] is None
    assert result["swh_has_readme"] is True  # visits block still runs


def test_load_swh_athena_visit_dates_present_computes_last_365d(tmp_path: Path) -> None:
    # visit_dates presentTrue branch (swh_visits_last_365d computed)
    swh_dir = tmp_path / "software_heritage_athena"
    swh_dir.mkdir(parents=True)
    index = {"record_count": 2}
    (swh_dir / "demo-plugin.swh_athena_index.json").write_text(json.dumps(index), encoding="utf-8")
    visits_path = swh_dir / "demo-plugin.swh_athena_visits.jsonl"
    visits_path.write_text(
        json.dumps({"visit_date": "2024-01-01", "has_readme": False})
        + "\n"
        + json.dumps({"visit_date": "2025-06-01", "has_readme": True})
        + "\n",
        encoding="utf-8",
    )
    result = _load_software_heritage_features_athena("demo-plugin", tmp_path)
    assert result["swh_visit_count"] == 2
    assert result["swh_visits_last_365d"] >= 1


def test_load_swh_athena_uses_most_recent_visit_for_features(tmp_path: Path) -> None:
    # Regression test: visits are stored oldest-first in the JSONL file.
    # The loader must pick the record with the LATEST visit_date for feature
    # extraction, not visits[0] (which is the oldest).
    swh_dir = tmp_path / "software_heritage_athena"
    swh_dir.mkdir(parents=True)
    (swh_dir / "demo-plugin.swh_athena_index.json").write_text(
        json.dumps({"record_count": 2}), encoding="utf-8"
    )
    visits_path = swh_dir / "demo-plugin.swh_athena_visits.jsonl"
    # Oldest visit: has_readme=False, days_since_last_commit=230, commit_count=10
    # Newest visit: has_readme=True,  days_since_last_commit=5,   commit_count=100
    visits_path.write_text(
        json.dumps(
            {
                "visit_date": "2020-01-01",
                "has_readme": False,
                "days_since_last_commit": 230.0,
                "commit_count": 10,
                "has_dot_github": False,
            }
        )
        + "\n"
        + json.dumps(
            {
                "visit_date": "2025-06-01",
                "has_readme": True,
                "days_since_last_commit": 5.0,
                "commit_count": 100,
                "has_dot_github": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = _load_software_heritage_features_athena("demo-plugin", tmp_path)
    # Must reflect the NEWEST visit, not the oldest
    assert result["swh_has_readme"] is True, "should use newest visit, not visits[0]"
    assert result["swh_days_since_last_commit"] == 5.0
    assert result["swh_commit_count"] == 100
    assert result["swh_has_dot_github"] is True


def test_load_swh_api_index_not_present(tmp_path: Path) -> None:
    # index_path does not exist
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_present"] is False


def test_load_swh_api_visits_no_valid_key(tmp_path: Path) -> None:
    # visits with no "date" or "visit_date"
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True, "snapshot_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    visits = {"results": [{"other_key": "2025-01-01"}, {"another": "2025-06-01"}]}
    (swh_dir / "demo-plugin.swh_visits.json").write_text(json.dumps(visits), encoding="utf-8")
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_visit_count"] == 2
    assert result["swh_first_visit_date"] is None  # no valid visit dates


def test_load_swh_api_no_visit_dates_skips_last_365d(tmp_path: Path) -> None:
    # visit_dates emptyFalse branch, skip last_365d block)
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    # no visits file
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_visits_last_365d"] == 0


def test_load_swh_api_latest_visit_not_dict(tmp_path: Path) -> None:
    # latest_visit_payload is not a dictFalse branch)
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    (swh_dir / "demo-plugin.swh_latest_visit.json").write_text(
        json.dumps("not-a-dict"), encoding="utf-8"
    )
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_latest_visit_status"] is None
    assert result["swh_latest_visit_type"] is None


def test_load_swh_api_latest_visit_no_inner_visit_key(tmp_path: Path) -> None:
    # latest_visit_payload is a dict but "visit" key is not a dict
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    # "visit" key present but is a string, not a dict → falls back to payload itself
    (swh_dir / "demo-plugin.swh_latest_visit.json").write_text(
        json.dumps({"status": "full", "type": "git", "visit": "not-a-dict"}),
        encoding="utf-8",
    )
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_latest_visit_status"] == "full"
    assert result["swh_latest_visit_type"] == "git"


def test_load_swh_api_latest_visit_date_overrides(tmp_path: Path) -> None:
    # latest_visit_payload has a valid dateoverrides visit_date)
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True, "snapshot_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    (swh_dir / "demo-plugin.swh_visits.json").write_text(
        json.dumps({"results": [{"date": "2025-01-01T00:00:00+00:00"}]}),
        encoding="utf-8",
    )
    (swh_dir / "demo-plugin.swh_latest_visit.json").write_text(
        json.dumps(
            {"visit": {"status": "full", "type": "git", "date": "2025-06-15T00:00:00+00:00"}}
        ),
        encoding="utf-8",
    )
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_latest_visit_date"] == "2025-06-15"  # line 808 overwrites


def test_build_feature_bundle_skips_empty_plugin_id(tmp_path: Path) -> None:
    # registry record with empty plugin_idcontinue)
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)

    registry_path = registry_dir / "plugins.jsonl"
    # First record has no/empty plugin_id, second is valid
    registry_path.write_text(
        json.dumps({"plugin_id": "", "title": "Empty"})
        + "\n"
        + json.dumps({"plugin_id": "   ", "title": "Whitespace"})
        + "\n"
        + json.dumps({"plugin_id": "demo-plugin", "title": "Demo"})
        + "\n",
        encoding="utf-8",
    )

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_path,
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
    )

    # Only the valid plugin_id record should be included
    assert len(rows) == 1
    assert rows[0]["plugin_id"] == "demo-plugin"


# ---------------------------------------------------------------------------
# Software Heritage Athena loader — static fixtures
# ---------------------------------------------------------------------------


def _copy_swh_athena_fixture(data_raw: Path) -> None:
    fixture_dir = Path(__file__).parent / "fixtures" / "software_heritage_athena"
    target_dir = data_raw / "software_heritage_athena"
    target_dir.mkdir(parents=True, exist_ok=True)
    for fixture_file in fixture_dir.iterdir():
        shutil.copy(fixture_file, target_dir / fixture_file.name)


def test_load_swh_athena_features_from_fixture_files(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    _copy_swh_athena_fixture(data_raw)

    row = _load_software_heritage_features_athena("demo-plugin", data_raw)

    assert row["swh_present"] is True
    assert row["swh_origin_found"] is True
    assert row["swh_has_snapshot"] is True
    assert row["swh_visit_count"] == 2
    assert row["swh_first_visit_date"] == "2024-06-01"
    assert row["swh_latest_visit_date"] == "2025-06-15"
    assert row["swh_archive_age_days"] == 379
    assert row["swh_visits_last_365d"] == 1

    # The current static feature builder intentionally uses the first visit record
    # as the latest/representative Athena snapshot payload.
    assert row["swh_has_readme"] is True
    assert row["swh_has_dot_github"] is True
    assert row["swh_has_jenkinsfile"] is True
    assert row["swh_has_security_md"] is True
    assert row["swh_has_changelog"] is True
    assert row["swh_has_dockerfile"] is True
    assert row["swh_has_pom_xml"] is True
    assert row["swh_has_mvn_wrapper"] is True
    assert row["swh_has_tests_directory"] is True
    assert row["swh_has_github_actions"] is True
    assert row["swh_has_dependabot"] is True
    assert row["swh_has_snyk_config"] is True
    assert row["swh_has_travis_yml"] is False
    assert row["swh_has_contributing_md"] is False
    assert row["swh_has_build_gradle"] is False
    assert row["swh_has_sonar_config"] is False

    assert row["swh_top_level_entry_count"] == 17
    assert row["swh_commit_count"] == 42
    assert row["swh_days_since_last_commit"] == 11
    assert row["swh_author_committer_lag_p50_hours"] == 1.5
    assert row["swh_author_committer_lag_p90_hours"] == 8.25
    assert row["swh_timezone_diversity"] == 3
    assert row["swh_weekend_commit_fraction"] == 0.2
    assert row["swh_security_fix_commit_count"] == 4
    assert row["swh_merge_commit_fraction"] == 0.6
    assert row["swh_conventional_commit_fraction"] == 0.7
    assert row["swh_issue_reference_rate"] == 0.8
    assert row["swh_empty_message_rate"] == 0.0
    assert row["swh_author_committer_mismatch_rate"] == 0.1
    assert row["swh_late_night_commit_fraction"] == 0.05
    assert row["swh_backend"] == "athena"


def test_swh_backend_auto_selects_athena_when_fixture_dir_exists(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    _copy_swh_athena_fixture(data_raw)

    row = _load_software_heritage_features("demo-plugin", data_raw)

    assert row["swh_present"] is True
    assert row["swh_backend"] == "athena"
    assert row["swh_commit_count"] == 42


def test_build_feature_bundle_uses_swh_athena_fixture_in_ci(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    _copy_swh_athena_fixture(data_raw)

    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo Plugin"}) + "\n",
        encoding="utf-8",
    )

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_path,
        out_path=tmp_path / "plugins.features.jsonl",
        out_csv_path=None,
        summary_path=None,
        software_heritage_backend="athena",
    )

    assert len(rows) == 1
    assert rows[0]["plugin_id"] == "demo-plugin"
    assert rows[0]["swh_present"] is True
    assert rows[0]["swh_origin_found"] is True
    assert rows[0]["swh_visit_count"] == 2
    assert rows[0]["swh_commit_count"] == 42


# ---------------------------------------------------------------------------
# Full bundle build and plugin-id path safety
# ---------------------------------------------------------------------------


def test_build_feature_bundle_loads_software_heritage_features(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    github_dir = data_raw / "github"
    swh_dir = data_raw / "software_heritage_api"
    health_dir = data_raw / "healthscore" / "plugins"

    for p in [registry_dir, plugins_dir, github_dir, swh_dir, health_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo"}) + "\n",
        encoding="utf-8",
    )

    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "repo_url": "https://github.com/jenkinsci/demo-plugin",
                "plugin_api": {"maintainers": [], "dependencies": []},
            }
        ),
        encoding="utf-8",
    )

    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-22T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 75},
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_index.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "origin_found": True,
                "snapshot_found": True,
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_visits.json").write_text(
        json.dumps(
            {
                "results": [
                    {"date": "2025-03-10T12:00:00+00:00"},
                    {"date": "2025-06-15T12:00:00+00:00"},
                ]
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_latest_visit.json").write_text(
        json.dumps({"visit": {"status": "full", "type": "git"}}),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_snapshot.json").write_text(
        json.dumps({"branches": {"refs/heads/main": {}, "refs/heads/dev": {}}}),
        encoding="utf-8",
    )

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
        software_heritage_backend="api",
    )

    row = rows[0]
    assert row["swh_present"] is True
    assert row["swh_origin_found"] is True
    assert row["swh_has_snapshot"] is True
    assert row["swh_visit_count"] == 2
    assert row["swh_first_visit_date"] == "2025-03-10"
    assert row["swh_latest_visit_date"] == "2025-06-15"
    assert row["swh_latest_visit_status"] == "full"
    assert row["swh_latest_visit_type"] == "git"
    assert row["swh_snapshot_branch_count"] == 2


def test_build_feature_bundle_writes_joined_outputs(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"
    gharchive_dir = data_raw / "gharchive" / "plugins"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir, gharchive_dir]:
        p.mkdir(parents=True, exist_ok=True)

    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "plugin_site_url": "https://plugins.jenkins.io/demo-plugin/",
                "plugin_api_url": "https://plugins.jenkins.io/api/plugin/demo-plugin/",
                "title": "Demo Plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    snapshot = {
        "plugin_id": "demo-plugin",
        "collected_at": "2026-03-15T00:00:00+00:00",
        "current_version": "1.2.3",
        "repo_url": "https://github.com/jenkinsci/demo-plugin",
        "plugin_api": {
            "requiredCore": "2.479.3",
            "labels": ["report"],
            "categories": ["buildManagement"],
            "maintainers": [{"id": "alice"}, {"id": "bob"}],
            "dependencies": [{"name": "structs"}, {"name": "workflow-step-api"}],
            "securityWarnings": [{"id": "SECURITY-1", "active": True}],
            "releaseTimestamp": "2026-01-13T07:44:00.00Z",
            "stats": {"installations": [{"timestamp": 1, "total": 1234}]},
        },
    }
    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8"
    )

    advisories = [
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "demo-plugin",
            "advisory_id": "2026-01-01",
            "published_date": "2026-01-01",
            "title": "Demo issue",
            "url": "https://www.jenkins.io/security/advisory/2026-01-01/",
            "severity_summary": {"max_cvss_base_score": 7.5},
            "cve_ids": ["CVE-2026-0001"],
        }
    ]
    with (advisories_dir / "demo-plugin.advisories.real.jsonl").open("w", encoding="utf-8") as f:
        for rec in advisories:
            f.write(json.dumps(rec) + "\n")

    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 88},
            }
        ),
        encoding="utf-8",
    )

    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "repo_full_name": "jenkinsci/demo-plugin",
                "repo_url": "https://github.com/jenkinsci/demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.repo.json").write_text(
        json.dumps(
            {
                "stargazers_count": 42,
                "forks_count": 5,
                "watchers_count": 42,
                "open_issues_count": 3,
                "subscribers_count": 4,
                "archived": False,
                "default_branch": "main",
                "license": {"spdx_id": "MIT"},
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.releases.json").write_text(
        json.dumps([{"published_at": "2026-01-13T07:44:00.00Z"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.tags.json").write_text(
        json.dumps([{"name": "v1.2.3"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.contributors.json").write_text(
        json.dumps([{"login": "alice", "contributions": 8}, {"login": "bob", "contributions": 2}]),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.open_issues.json").write_text(
        json.dumps([{"id": 1}, {"id": 2}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.open_pulls.json").write_text(
        json.dumps([{"id": 3}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.workflows_dir.json").write_text(
        json.dumps([{"name": "ci.yml"}, {"name": "codeql-analysis.yml"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.codeowners.json").write_text(
        json.dumps({"name": "CODEOWNERS", "path": ".github/CODEOWNERS"}), encoding="utf-8"
    )
    (github_dir / "demo-plugin.security_policy.json").write_text(
        json.dumps({"name": "SECURITY.md", "path": ".github/SECURITY.md"}), encoding="utf-8"
    )
    (github_dir / "demo-plugin.dependabot.json").write_text(
        json.dumps({"name": "dependabot.yml", "path": ".github/dependabot.yml"}), encoding="utf-8"
    )
    (github_dir / "demo-plugin.commits_365d.json").write_text(
        json.dumps([{"sha": "a"}, {"sha": "b"}]), encoding="utf-8"
    )

    with (gharchive_dir / "demo-plugin.gharchive.jsonl").open("w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "plugin_id": "demo-plugin",
                    "window_start_yyyymmdd": "20250101",
                    "window_end_yyyymmdd": "20250130",
                    "sample_percent": 1.0,
                    "events_total": 10,
                    "actors_unique": 3,
                    "pushes": 4,
                    "committers_unique": 2,
                    "push_days_active": 2,
                    "prs_opened": 1,
                    "prs_closed": 1,
                    "prs_merged": 1,
                    "prs_closed_unmerged": 0,
                    "pr_reviewed_ratio": 1.0,
                    "pr_merge_time_p50_hours": 12,
                    "pr_close_without_merge_ratio": 0.0,
                    "issues_opened": 1,
                    "issues_closed": 1,
                    "issues_reopened": 0,
                    "issue_reopen_rate": 0.0,
                    "issue_close_time_p50_hours": 24,
                    "releases": 1,
                    "days_since_last_release": 60,
                    "hotfix_proxy": 0.0,
                    "security_label_proxy": 1,
                    "churn_intensity": 1.67,
                    "owner_concentration": 0.75,
                }
            )
            + "\n"
        )

    out_path = tmp_path / "data" / "processed" / "features" / "plugins.features.jsonl"
    out_csv = tmp_path / "data" / "processed" / "features" / "plugins.features.csv"
    summary_path = tmp_path / "data" / "processed" / "features" / "plugins.features.summary.json"

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_path,
        out_path=out_path,
        out_csv_path=out_csv,
        summary_path=summary_path,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["plugin_id"] == "demo-plugin"
    assert row["snapshot_present"] is True
    assert row["snapshot_dependencies_count"] == 2
    assert row["advisory_count"] == 1
    assert row["advisory_max_cvss"] == 7.5
    assert row["healthscore_value"] == 88.0
    assert row["github_present"] is True
    assert row["github_stargazers_count"] == 42
    assert row["github_workflows_count"] == 2
    assert row["github_has_codeowners"] is True
    assert row["github_has_security_policy"] is True
    assert row["github_has_dependabot_config"] is True
    assert row["github_has_codeql_workflow"] is True
    assert row["gharchive_present"] is True
    assert row["gharchive_events_total_sum"] == 10.0
    assert row["gharchive_latest_window_end"] == "20250130"

    assert out_path.exists()
    assert out_csv.exists()
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["plugins_total"] == 1
    assert summary["plugins_with_gharchive"] == 1


_INVALID_PLUGIN_IDS = [
    "../evil",
    "../../etc/passwd",
    "/etc/passwd",
    "plugin\x00id",
    "",
    "  ",
    "../",
    "a/b",
]


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_snapshot_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "plugins").mkdir(parents=True)
    result = _load_snapshot_features(bad_id, data_raw)
    assert result == {"snapshot_present": False}


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_advisory_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "advisories").mkdir(parents=True)
    result = _load_advisory_features(bad_id, data_raw)
    assert result["advisories_present"] is False
    assert result["advisory_count"] == 0


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_healthscore_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "healthscore" / "plugins").mkdir(parents=True)
    result = _load_healthscore_features(bad_id, data_raw)
    assert result["healthscore_present"] is False
    assert result["healthscore_value"] is None


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_github_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "github").mkdir(parents=True)
    result = _load_github_features(bad_id, data_raw)
    assert result == {"github_present": False}


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_gharchive_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "gharchive" / "plugins").mkdir(parents=True)
    result = _load_gharchive_features(bad_id, data_raw)
    assert result["gharchive_present"] is False


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_swh_api_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "software_heritage_api").mkdir(parents=True)
    result = _load_software_heritage_features_api(bad_id, data_raw)
    assert result["swh_present"] is False


@pytest.mark.parametrize("bad_id", _INVALID_PLUGIN_IDS)
def test_load_swh_athena_features_rejects_invalid_plugin_id(bad_id: str, tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    (data_raw / "software_heritage_athena").mkdir(parents=True)
    result = _load_software_heritage_features_athena(bad_id, data_raw)
    assert result["swh_present"] is False
