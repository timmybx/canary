"""
Coverage gap tests for canary/build/features_bundle.py.

Targets lines that were not covered by the existing test suite:
  110, 113, 123-136, 143-145, 147->152, 154-160, 177, 247, 251-252,
  280->286, 283->281, 288-293, 334->320, 336-339, 510->513, 519->526,
  523-524, 530-532, 543, 547-548, 554, 558->556, 560, 565, 569-571,
  586, 658->656, 669->676, 676->718, 761, 775->774, 778->775,
  790->797, 799->810, 802, 808, 882
"""

from __future__ import annotations

import json
from pathlib import Path

from canary.build.features_bundle import (
    _advisory_cve_ids,
    _cvss_candidates,
    _days_between_iso_dates,
    _extract_swh_visits,
    _latest_installations_total,
    _load_advisory_features,
    _load_github_features,
    _load_snapshot_features,
    _load_software_heritage_features_api,
    _load_software_heritage_features_athena,
    _parse_iso_date,
    _parse_iso_datetime_prefix,
    _repo_url_from_snapshot,
    _resolve_swh_backend_dir,
    _snapshot_branch_count,
    build_feature_bundle,
)

# ---------------------------------------------------------------------------
# _latest_installations_total  (lines 110, 113)
# ---------------------------------------------------------------------------


def test_latest_installations_total_empty_list() -> None:
    # installs is an empty list → line 110
    plugin_api = {"stats": {"installations": []}}
    assert _latest_installations_total(plugin_api) is None


def test_latest_installations_total_non_list_installs() -> None:
    # installs is not a list → line 110
    plugin_api = {"stats": {"installations": "not-a-list"}}
    assert _latest_installations_total(plugin_api) is None


def test_latest_installations_total_non_dict_latest() -> None:
    # last element is not a dict → line 113
    plugin_api = {"stats": {"installations": ["not-a-dict"]}}
    assert _latest_installations_total(plugin_api) is None


# ---------------------------------------------------------------------------
# _repo_url_from_snapshot  (lines 123-136)
# ---------------------------------------------------------------------------


def test_repo_url_from_snapshot_dict_with_link() -> None:
    # repo_url is a dict with "link" key → lines 123-126
    snapshot = {"repo_url": {"link": "https://github.com/jenkinsci/demo-plugin"}}
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_dict_with_url_key() -> None:
    # repo_url is a dict with "url" key → lines 123-126
    snapshot = {"repo_url": {"url": "https://github.com/jenkinsci/demo-plugin"}}
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_dict_with_no_valid_link() -> None:
    # repo_url is a dict but link/url is absent → lines 123-124, continues loop
    snapshot = {"repo_url": {"other": "value"}}
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_scm_str_in_plugin_api() -> None:
    # falls through to plugin_api.scm as str → lines 127-131
    snapshot = {
        "plugin_api": {"scm": "https://github.com/jenkinsci/demo-plugin"},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_scm_dict_with_link() -> None:
    # plugin_api.scm is a dict with "link" key → lines 132-135
    snapshot = {
        "plugin_api": {"scm": {"link": "https://github.com/jenkinsci/demo-plugin"}},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_scm_dict_with_url_key() -> None:
    # plugin_api.scm is a dict with "url" key → lines 132-135
    snapshot = {
        "plugin_api": {"scm": {"url": "https://github.com/jenkinsci/demo-plugin"}},
    }
    assert _repo_url_from_snapshot(snapshot) == "https://github.com/jenkinsci/demo-plugin"


def test_repo_url_from_snapshot_returns_none_when_all_empty() -> None:
    # nothing useful → line 136
    snapshot: dict = {}
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_scm_dict_with_no_valid_link() -> None:
    # plugin_api.scm is a dict but has no usable link/url → line 134->136 (False branch)
    snapshot = {
        "plugin_api": {"scm": {"other": "value"}},
    }
    assert _repo_url_from_snapshot(snapshot) is None


def test_repo_url_from_snapshot_plugin_api_dict_no_scm() -> None:
    # plugin_api is a dict but scm is absent → line 132->136 (False branch, scm is None)
    snapshot = {"plugin_api": {"other": "value"}}
    assert _repo_url_from_snapshot(snapshot) is None


# ---------------------------------------------------------------------------
# _cvss_candidates  (lines 143-145, 147->152, 154-160)
# ---------------------------------------------------------------------------


def test_cvss_candidates_direct_value() -> None:
    # direct cvss value present and valid → lines 143-145
    rec = {"cvss": 7.5}
    result = _cvss_candidates(rec)
    assert 7.5 in result


def test_cvss_candidates_direct_value_invalid_skipped() -> None:
    # direct cvss present but not convertible → line 143, branch where num is None
    rec = {"cvss": "not-a-number"}
    result = _cvss_candidates(rec)
    assert result == []


def test_cvss_candidates_severity_summary_skipped_when_not_dict() -> None:
    # severity_summary is not a dict → line 147->152 (False branch)
    rec = {"severity_summary": "high"}
    result = _cvss_candidates(rec)
    assert result == []


def test_cvss_candidates_vulnerabilities_list() -> None:
    # vulnerabilities list present and processed → lines 154-160
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
    # non-dict entry in vulnerabilities is skipped → lines 154-156
    rec = {"vulnerabilities": ["not-a-dict", {"cvss": 5.0}]}
    result = _cvss_candidates(rec)
    assert 5.0 in result
    assert len(result) == 1


def test_cvss_candidates_vulnerabilities_empty_list() -> None:
    # empty vulnerabilities list → lines 153-154 (loop body never executed)
    rec = {"vulnerabilities": []}
    result = _cvss_candidates(rec)
    assert result == []


# ---------------------------------------------------------------------------
# _load_snapshot_features  (line 177)
# ---------------------------------------------------------------------------


def test_load_snapshot_features_plugin_api_not_dict(tmp_path: Path) -> None:
    # plugin_api is not a dict → line 177
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


# ---------------------------------------------------------------------------
# _parse_iso_date  (lines 247, 251-252)
# ---------------------------------------------------------------------------


def test_parse_iso_date_non_string_returns_none() -> None:
    # not a string → line 247

    assert _parse_iso_date(None) is None
    assert _parse_iso_date(42) is None
    assert _parse_iso_date([]) is None


def test_parse_iso_date_empty_string_returns_none() -> None:
    # empty/whitespace string → line 247

    assert _parse_iso_date("") is None
    assert _parse_iso_date("   ") is None


def test_parse_iso_date_invalid_format_returns_none() -> None:
    # invalid date string → lines 251-252 (ValueError)

    assert _parse_iso_date("not-a-date") is None
    assert _parse_iso_date("2025-99-99") is None


# ---------------------------------------------------------------------------
# _advisory_cve_ids  (lines 280->286, 283->281, 288-293)
# ---------------------------------------------------------------------------


def test_advisory_cve_ids_no_cve_ids_key() -> None:
    # cve_ids key absent → line 280->286 (False branch, skip to vulns)
    rec = {"vulnerabilities": [{"cve_id": "CVE-2025-0001"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0001" in result


def test_advisory_cve_ids_cve_ids_not_a_list() -> None:
    # cve_ids is not a list → line 280->286 (False branch)
    rec = {"cve_ids": "CVE-2025-0001"}
    result = _advisory_cve_ids(rec)
    assert result == set()


def test_advisory_cve_ids_empty_string_cve_skipped() -> None:
    # cve entry in list is empty string → line 283->281 (False branch, skip)
    rec = {"cve_ids": ["", "  ", "CVE-2025-0001"]}
    result = _advisory_cve_ids(rec)
    assert result == {"CVE-2025-0001"}


def test_advisory_cve_ids_vulnerabilities_list_cve_id() -> None:
    # vuln with cve_id key → lines 288-293
    rec = {"vulnerabilities": [{"cve_id": "CVE-2025-0002", "cvss": 7.5}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0002" in result


def test_advisory_cve_ids_vulnerabilities_non_dict_skipped() -> None:
    # non-dict vuln is skipped → lines 288-290
    rec = {"vulnerabilities": ["not-a-dict", {"cve_id": "CVE-2025-0003"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0003" in result
    assert len(result) == 1


def test_advisory_cve_ids_vuln_uses_cve_fallback() -> None:
    # vuln has "cve" key (not cve_id) → lines 291-293
    rec = {"vulnerabilities": [{"cve": "CVE-2025-0004"}]}
    result = _advisory_cve_ids(rec)
    assert "CVE-2025-0004" in result


def test_advisory_cve_ids_vuln_empty_cve_skipped() -> None:
    # vuln with empty/whitespace cve → line 292 (False branch)
    rec = {"vulnerabilities": [{"cve_id": "   "}]}
    result = _advisory_cve_ids(rec)
    assert result == set()


# ---------------------------------------------------------------------------
# _load_advisory_features  warnings  (lines 334->320, 336-339)
# ---------------------------------------------------------------------------


def test_load_advisory_features_warnings_not_a_list(tmp_path: Path) -> None:
    # warnings is a non-list truthy value → line 334->320 (False branch)
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
    # warnings list with an active dict warning → lines 336-339
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


# ---------------------------------------------------------------------------
# _load_github_features  (lines 510->513, 519->526, 523-524)
# ---------------------------------------------------------------------------


def test_load_github_features_contributors_all_zero(tmp_path: Path) -> None:
    # total contributions == 0 → line 510->513 (False branch, skip top_share)
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
    # commit file name matches pattern and has a parseable integer → lines 519-522
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
    # commit file matches pattern prefix/suffix but has non-numeric days → lines 523-524
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


# ---------------------------------------------------------------------------
# _parse_iso_datetime_prefix  (lines 530-532)
# ---------------------------------------------------------------------------


def test_parse_iso_datetime_prefix_non_string() -> None:
    # not a string → line 531 (return None)
    assert _parse_iso_datetime_prefix(None) is None
    assert _parse_iso_datetime_prefix(123) is None


def test_parse_iso_datetime_prefix_empty_string() -> None:
    # empty string → line 531 (return None)
    assert _parse_iso_datetime_prefix("") is None
    assert _parse_iso_datetime_prefix("   ") is None


def test_parse_iso_datetime_prefix_valid_string() -> None:
    # valid string → line 532 (return stripped value)
    result = _parse_iso_datetime_prefix("  2025-06-01T12:00:00+00:00  ")
    assert result == "2025-06-01T12:00:00+00:00"


# ---------------------------------------------------------------------------
# _days_between_iso_dates  (lines 543, 547-548)
# ---------------------------------------------------------------------------


def test_days_between_iso_dates_none_start() -> None:
    # start is None → line 543
    assert _days_between_iso_dates(None, "2025-06-01") is None


def test_days_between_iso_dates_none_end() -> None:
    # end is None → line 543
    assert _days_between_iso_dates("2025-01-01", None) is None


def test_days_between_iso_dates_both_none() -> None:
    # both None → line 543
    assert _days_between_iso_dates(None, None) is None


def test_days_between_iso_dates_invalid_start() -> None:
    # invalid date string → lines 547-548 (ValueError)
    assert _days_between_iso_dates("not-a-date", "2025-06-01") is None


def test_days_between_iso_dates_invalid_end() -> None:
    # invalid end date → lines 547-548 (ValueError)
    assert _days_between_iso_dates("2025-01-01", "not-a-date") is None


# ---------------------------------------------------------------------------
# _extract_swh_visits  (lines 554, 558->556, 560)
# ---------------------------------------------------------------------------


def test_extract_swh_visits_payload_is_list() -> None:
    # payload is a list → line 554
    visits = [{"date": "2025-01-01"}, {"date": "2025-06-01"}]
    result = _extract_swh_visits(visits)
    assert len(result) == 2


def test_extract_swh_visits_list_filters_non_dicts() -> None:
    # list with non-dict entries → line 554
    result = _extract_swh_visits([{"date": "2025-01-01"}, "not-a-dict", 42])
    assert len(result) == 1


def test_extract_swh_visits_dict_without_recognized_key() -> None:
    # dict without "results" or "visits" keys → lines 555-559, then 560
    result = _extract_swh_visits({"other": [{"date": "x"}]})
    assert result == []


def test_extract_swh_visits_dict_with_non_list_results() -> None:
    # dict with "results" key but value is not a list → line 558->556 (continue)
    result = _extract_swh_visits({"results": "not-a-list", "visits": [{"date": "x"}]})
    assert len(result) == 1


def test_extract_swh_visits_non_dict_non_list() -> None:
    # payload is neither list nor dict → line 560
    assert _extract_swh_visits(None) == []
    assert _extract_swh_visits(42) == []
    assert _extract_swh_visits("string") == []


# ---------------------------------------------------------------------------
# _snapshot_branch_count  (lines 565, 569-571)
# ---------------------------------------------------------------------------


def test_snapshot_branch_count_non_dict() -> None:
    # not a dict → line 565
    assert _snapshot_branch_count(None) == 0
    assert _snapshot_branch_count([]) == 0
    assert _snapshot_branch_count("string") == 0


def test_snapshot_branch_count_branches_as_list() -> None:
    # branches is a list → lines 569-570
    payload = {"branches": ["main", "dev", "feature"]}
    assert _snapshot_branch_count(payload) == 3


def test_snapshot_branch_count_branches_neither() -> None:
    # branches key exists but is neither dict nor list → line 571
    payload = {"branches": "main"}
    assert _snapshot_branch_count(payload) == 0


def test_snapshot_branch_count_no_branches_key() -> None:
    # no branches key at all → line 571
    payload = {"other": "value"}
    assert _snapshot_branch_count(payload) == 0


# ---------------------------------------------------------------------------
# _resolve_swh_backend_dir  (line 586)
# ---------------------------------------------------------------------------


def test_resolve_swh_backend_dir_fallback_to_api(tmp_path: Path) -> None:
    # athena dir does not exist → line 586
    result = _resolve_swh_backend_dir(tmp_path)
    assert result == tmp_path / "software_heritage_api"


def test_resolve_swh_backend_dir_athena_exists(tmp_path: Path) -> None:
    # athena dir exists → line 585 (not 586)
    athena_dir = tmp_path / "software_heritage_athena"
    athena_dir.mkdir()
    result = _resolve_swh_backend_dir(tmp_path)
    assert result == athena_dir


# ---------------------------------------------------------------------------
# _load_software_heritage_features_athena  (lines 658->656, 669->676, 676->718)
# ---------------------------------------------------------------------------


def test_load_swh_athena_index_present_but_visits_empty(tmp_path: Path) -> None:
    # index_path exists, visits empty → line 676->718 (False branch)
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
    # visits present but visit_date not parseable → lines 658->656 (False branch)
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
    assert result["swh_first_visit_date"] is None  # no valid dates → line 669->676
    assert result["swh_latest_visit_date"] is None
    assert result["swh_has_readme"] is True  # visits block still runs → line 676


def test_load_swh_athena_visit_dates_present_computes_last_365d(tmp_path: Path) -> None:
    # visit_dates present → line 669 True branch (swh_visits_last_365d computed)
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


# ---------------------------------------------------------------------------
# _load_software_heritage_features_api  (lines 761, 775->774, 778->775,
#                                         790->797, 799->810, 802, 808)
# ---------------------------------------------------------------------------


def test_load_swh_api_index_not_present(tmp_path: Path) -> None:
    # index_path does not exist → line 761
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_present"] is False


def test_load_swh_api_visits_no_valid_key(tmp_path: Path) -> None:
    # visits with no "date" or "visit_date" → lines 775->774, 778->775
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True, "snapshot_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    visits = {"results": [{"other_key": "2025-01-01"}, {"another": "2025-06-01"}]}
    (swh_dir / "demo-plugin.swh_visits.json").write_text(json.dumps(visits), encoding="utf-8")
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_visit_count"] == 2
    assert result["swh_first_visit_date"] is None  # no valid visit dates → line 790->797


def test_load_swh_api_no_visit_dates_skips_last_365d(tmp_path: Path) -> None:
    # visit_dates empty → line 790->797 (False branch, skip last_365d block)
    swh_dir = tmp_path / "software_heritage_api"
    swh_dir.mkdir(parents=True)
    index = {"origin_found": True}
    (swh_dir / "demo-plugin.swh_index.json").write_text(json.dumps(index), encoding="utf-8")
    # no visits file
    result = _load_software_heritage_features_api("demo-plugin", tmp_path)
    assert result["swh_visits_last_365d"] == 0


def test_load_swh_api_latest_visit_not_dict(tmp_path: Path) -> None:
    # latest_visit_payload is not a dict → line 799->810 (False branch)
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
    # latest_visit_payload is a dict but "visit" key is not a dict → line 802
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
    # latest_visit_payload has a valid date → line 808 (overrides visit_date)
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


# ---------------------------------------------------------------------------
# build_feature_bundle  (line 882)
# ---------------------------------------------------------------------------


def test_build_feature_bundle_skips_empty_plugin_id(tmp_path: Path) -> None:
    # registry record with empty plugin_id → line 882 (continue)
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
