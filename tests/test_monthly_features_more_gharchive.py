from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.build.monthly_features import (
    _HOTFIX_KEYWORDS,
    _SECURITY_KEYWORDS,
    _add_rolling_gharchive_features,
    _advisory_cve_ids,
    _advisory_cvss,
    _clip,
    _is_bot_actor,
    _load_advisory_monthly_features,
    _load_gharchive_monthly_features,
    _num,
    _parse_iso_date,
    _parse_iso_timestamp,
    _parse_month,
    _parse_yyyymmdd,
    _percentile,
    _safe_div,
    _text_blob_matches,
    iter_months,
)


def test_monthly_feature_small_helpers_cover_real_edge_cases() -> None:
    assert _is_bot_actor("") is False
    assert _is_bot_actor("release-drafter[bot]") is True
    assert _text_blob_matches(None, _SECURITY_KEYWORDS) is False
    assert _text_blob_matches("urgent security fix for CVE", _SECURITY_KEYWORDS) is True
    assert _text_blob_matches("urgent hotfix release", _HOTFIX_KEYWORDS) is True

    assert _percentile([], 50) is None
    assert _percentile([10.0, 20.0, 30.0], 50) == 20.0
    assert _percentile([0.0, 100.0], 25) == 25.0

    with pytest.raises(ValueError, match="Expected YYYY-MM"):
        _parse_month("2025/01")
    with pytest.raises(ValueError, match="start month"):
        iter_months("2025-03", "2025-02")
    dec_jan = iter_months("2024-12", "2025-01")
    assert [m["month"] for m in dec_jan] == ["2024-12", "2025-01"]
    assert dec_jan[0]["window_end"] == "2024-12-31"

    assert _parse_yyyymmdd(None) is None
    assert _parse_yyyymmdd("20250101") is not None
    assert _parse_yyyymmdd("20250231") is None
    assert _parse_iso_date(None) is None
    assert _parse_iso_date("not-a-date") is None
    assert _parse_iso_timestamp(None) is None
    assert _parse_iso_timestamp("2025-01-01T00:00:00Z") is not None
    assert _parse_iso_timestamp("definitely-not-a-timestamp") is None

    assert _num({"bad": None}, "bad") == 0.0
    assert _num({"bad": "nan-ish"}, "bad") == 0.0
    assert _safe_div(1.0, 0.0) is None
    assert _clip(-5.0, low=0.0) == 0.0
    assert _clip(15.0, high=10.0) == 10.0


def test_load_gharchive_monthly_features_counts_event_types_keywords_and_durations(
    tmp_path: Path,
) -> None:
    gharchive_dir = tmp_path / "gharchive" / "normalized-events"
    gharchive_dir.mkdir(parents=True)

    rows = [
        # Exercises the skip path for malformed/partial normalized rows.
        {"plugin_id": "", "event_yyyymm": "2025-01", "event_type": "PushEvent"},
        {"plugin_id": "demo-plugin", "event_yyyymm": "", "event_type": "PushEvent"},
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_date": "2025-01-01",
            "event_type": "PushEvent",
            "actor_login": "alice",
            "sample_percent": 1.0,
            "source_window_start_yyyymmdd": "20250101",
            "source_window_end_yyyymmdd": "20250131",
        },
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_date": "2025-01-02",
            "event_type": "PushEvent",
            "actor_login": "dependabot[bot]",
            "text_blob": "bump dependency version",
        },
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_date": "2025-01-03",
            "event_type": "PullRequestEvent",
            "action": "closed",
            "pr_merged": True,
            "pr_created_ts": "2025-01-01T00:00:00Z",
            "pr_closed_ts": "2025-01-02T12:00:00Z",
            "actor_login": "bob",
            "text_blob": "security fix for CVE-2025-0001",
        },
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_date": "2025-01-04",
            "event_type": "IssuesEvent",
            "action": "closed",
            "issue_created_ts": "2025-01-01T06:00:00Z",
            "issue_closed_ts": "2025-01-03T06:00:00Z",
            "actor_login": "carol",
            "text_blob": "critical hotfix for production",
        },
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_type": "PullRequestEvent",
            "actor_login": "renovate-bot",
            "text_blob": "ordinary maintenance",
        },
        {"plugin_id": "demo-plugin", "event_yyyymm": "2025-01", "event_type": "ReleaseEvent"},
        {"plugin_id": "demo-plugin", "event_yyyymm": "2025-01", "event_type": "WatchEvent"},
        {"plugin_id": "demo-plugin", "event_yyyymm": "2025-01", "event_type": "ForkEvent"},
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_type": "CreateEvent",
            "ref_type": "branch",
        },
        {
            "plugin_id": "demo-plugin",
            "event_yyyymm": "2025-01",
            "event_type": "CreateEvent",
            "ref_type": "tag",
        },
    ]
    (gharchive_dir / "2025-01.gharchive.events.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    out = _load_gharchive_monthly_features(tmp_path)
    bucket = out[("demo-plugin", "2025-01")]

    assert bucket["gharchive_events_total"] == 10
    assert bucket["gharchive_push_events"] == 2
    assert bucket["gharchive_bot_events"] == 2
    assert bucket["gharchive_human_events"] == 8
    assert bucket["gharchive_pull_request_events"] == 2
    assert bucket["gharchive_pull_request_closed_events"] == 1
    assert bucket["gharchive_pull_request_merged_events"] == 1
    assert bucket["gharchive_pr_merge_time_p50_hours"] == 36.0
    assert bucket["gharchive_issues_closed_events"] == 1
    assert bucket["gharchive_issue_close_time_p50_hours"] == 48.0
    assert bucket["gharchive_release_events"] == 1
    assert bucket["gharchive_watch_events"] == 1
    assert bucket["gharchive_fork_events"] == 1
    assert bucket["gharchive_branch_create_events"] == 1
    assert bucket["gharchive_tag_create_events"] == 1
    assert bucket["gharchive_security_keyword_events"] == 1
    assert bucket["gharchive_hotfix_keyword_events"] == 1
    # One explicit dependency text blob plus one bot-authored PR.
    assert bucket["gharchive_dependency_bump_events"] == 2
    assert bucket["gharchive_unique_actors"] == 5
    assert bucket["gharchive_unique_human_actors"] == 3
    assert bucket["gharchive_days_active"] == 4
    assert bucket["gharchive_owner_push_fraction"] == 1.0


def test_advisory_helpers_accept_nested_cvss_and_vulnerability_cves(tmp_path: Path) -> None:
    rec = {
        "published_date": "not-a-date",
        "cvss": "4.0",
        "severity_summary": {"max_cvss_base_score": "7.1"},
        "cve_ids": ["", " CVE-2025-0001 "],
        "vulnerabilities": [
            "not-a-dict",
            {"cvss_base_score": "8.8", "cve_id": "CVE-2025-0002"},
            {"cvssScore": "9.1", "cve": "CVE-2025-0003"},
        ],
    }
    assert _advisory_cvss(rec) == 9.1
    assert _advisory_cve_ids(rec) == {
        "CVE-2025-0001",
        "CVE-2025-0002",
        "CVE-2025-0003",
    }

    advisories_dir = tmp_path / "advisories"
    advisories_dir.mkdir()
    (advisories_dir / "demo-plugin.advisories.real.jsonl").write_text(
        json.dumps(rec)
        + "\n"
        + json.dumps(
            {
                "published_date": "2025-01-15",
                "vulnerabilities": [{"cvss": "7.5", "cve_id": "CVE-2025-0004"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    months = iter_months("2025-01", "2025-01")
    features = _load_advisory_monthly_features(tmp_path, ["demo-plugin"], months)
    jan = features[("demo-plugin", "2025-01")]
    assert jan["advisory_count_to_date"] == 1
    assert jan["advisory_cve_count_to_date"] == 1
    assert jan["advisory_max_cvss_to_date"] == 7.5
    assert jan["advisory_cvss_ge_7_count_to_date"] == 1


def test_add_rolling_gharchive_features_clips_ratios_and_tracks_bursts() -> None:
    rows = [
        {
            "month": "2025-01",
            "gharchive_events_total": 0,
            "gharchive_push_events": 0,
            "gharchive_pull_request_events": 0,
            "gharchive_issues_events": 0,
        },
        {
            "month": "2025-02",
            "gharchive_events_total": 10,
            "gharchive_push_events": 10,
            "gharchive_pull_request_events": 1,
            "gharchive_pull_request_closed_events": 1,
            "gharchive_pull_request_merged_events": 1,
            "gharchive_pull_request_review_events": 1,
            "gharchive_issues_events": 1,
            "gharchive_issues_closed_events": 1,
            "gharchive_release_events": 1,
            "gharchive_unique_actors": 20,
            "gharchive_days_active": 5,
            "gharchive_security_keyword_events": 1,
            "gharchive_watch_events": 1,
            "gharchive_fork_events": 1,
            "gharchive_bot_events": 20,
            "gharchive_tag_create_events": 1,
        },
        {
            "month": "2025-03",
            "gharchive_events_total": 100,
            "gharchive_push_events": 20,
            "gharchive_pull_request_events": 20,
            "gharchive_pull_request_closed_events": 30,
            "gharchive_pull_request_merged_events": 20,
            "gharchive_pull_request_review_events": 400,
            "gharchive_issues_events": 20,
            "gharchive_issues_closed_events": 40,
            "gharchive_release_events": 20,
            "gharchive_unique_actors": 200,
            "gharchive_days_active": 5,
            "gharchive_security_keyword_events": 20,
            "gharchive_watch_events": 4,
            "gharchive_fork_events": 3,
            "gharchive_bot_events": 200,
            "gharchive_tag_create_events": 0,
        },
    ]

    out = _add_rolling_gharchive_features(rows)
    first = out[0]
    latest = out[-1]

    assert first["gharchive_prs_per_push_3m"] is None
    assert first["gharchive_months_since_any_activity"] is None
    assert latest["gharchive_months_since_push"] == 0
    assert latest["gharchive_months_since_release_tag"] == 1
    assert latest["gharchive_active_month_ratio_3m"] == pytest.approx(2 / 3)
    assert latest["gharchive_actors_per_active_day_3m"] == 10.0
    assert latest["gharchive_pr_close_rate_3m"] == pytest.approx(32 / 23)
    assert latest["gharchive_pr_review_intensity_3m"] == 10.0
    assert latest["gharchive_issue_close_rate_3m"] == 1.5
    assert latest["gharchive_bot_event_ratio_3m"] == 1.0
    assert latest["gharchive_security_keyword_rate_3m"] > 0
    assert latest["gharchive_activity_burstiness_6m"] > 1.0
