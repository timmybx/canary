from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from canary.build.features_bundle import (
    _iter_registry_records,
    _read_json,
    _read_jsonl,
    _safe_float,
    _to_csv_scalar,
)
from canary.plugin_aliases import canonicalize_plugin_id

# ---------------------------------------------------------------------------
# GH Archive keyword sets for text_blob analysis
# ---------------------------------------------------------------------------

_SECURITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "cve",
        "vulnerability",
        "vulnerable",
        "vuln",
        "exploit",
        "exploitable",
        "security fix",
        "security patch",
        "security update",
        "security advisory",
        "rce",
        "remote code execution",
        "xss",
        "cross-site",
        "injection",
        "sql injection",
        "csrf",
        "ssrf",
        "xxe",
        "deserialization",
        "authentication bypass",
        "auth bypass",
        "privilege escalation",
        "path traversal",
        "directory traversal",
        "open redirect",
        "information disclosure",
        "data leak",
        "sanitize",
        "sanitise",
        "arbitrary code",
        "arbitrary file",
        "buffer overflow",
    }
)

_HOTFIX_KEYWORDS: frozenset[str] = frozenset(
    {
        "hotfix",
        "hot fix",
        "hot-fix",
        "urgent fix",
        "critical fix",
        "emergency fix",
        "emergency patch",
        "emergency release",
        "critical patch",
        "critical update",
        "critical bug",
    }
)

_DEPENDENCY_KEYWORDS: frozenset[str] = frozenset(
    {
        "bump ",
        "bumps ",
        "update dependency",
        "upgrade dependency",
        "dependabot",
        "renovate",
        "greenkeeper",
        "snyk",
    }
)

_BOT_LOGINS: frozenset[str] = frozenset(
    {
        "dependabot",
        "dependabot-preview",
        "renovate-bot",
        "greenkeeper",
        "snyk-bot",
        "github-actions",
        "codecov-io",
        "coveralls",
        "sonarcloud",
        "mergify",
        "semantic-release-bot",
    }
)


def _is_bot_actor(login: str) -> bool:
    """Return True if the actor login looks like a bot."""
    if not login:
        return False
    low = login.lower()
    if low.endswith("[bot]"):
        return True
    return low in _BOT_LOGINS


def _text_blob_matches(text: str | None, keywords: frozenset[str]) -> bool:
    """Return True if any keyword appears in the lowercased text blob."""
    if not text:
        return False
    return any(kw in text for kw in keywords)


def _percentile(values: list[float], p: float) -> float | None:
    """Return the p-th percentile (0-100) of a sorted or unsorted list."""
    if not values:
        return None
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    idx = (p / 100) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _parse_month(month_str: str) -> date:
    try:
        return datetime.strptime(month_str, "%Y-%m").date().replace(day=1)
    except ValueError as exc:
        raise ValueError(f"Invalid month '{month_str}'. Expected YYYY-MM") from exc


def _end_of_month(month_start: date) -> date:
    if month_start.month == 12:
        return date(month_start.year + 1, 1, 1) - timedelta(days=1)
    return date(month_start.year, month_start.month + 1, 1) - timedelta(days=1)


def iter_months(start_yyyy_mm: str, end_yyyy_mm: str) -> list[dict[str, Any]]:
    start = _parse_month(start_yyyy_mm)
    end = _parse_month(end_yyyy_mm)
    if start > end:
        raise ValueError("start month must be <= end month")
    months: list[dict[str, Any]] = []
    current = start
    idx = 0
    while current <= end:
        month_end = _end_of_month(current)
        months.append(
            {
                "month": current.strftime("%Y-%m"),
                "window_start": current.isoformat(),
                "window_end": month_end.isoformat(),
                "window_year": current.year,
                "window_month": current.month,
                "window_index": idx,
            }
        )
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)
        idx += 1
    return months


GHARCHIVE_MONTHLY_KEY_MAP = {
    "events_total": "gharchive_events_total",
    "pushes": "gharchive_push_events",
    "prs_opened": "gharchive_pull_request_events",
    "prs_closed": "gharchive_pull_request_closed_events",
    "prs_merged": "gharchive_pull_request_merged_events",
    "pull_request_review_events": "gharchive_pull_request_review_events",
    "issues_opened": "gharchive_issues_events",
    "issues_closed": "gharchive_issues_closed_events",
    "releases": "gharchive_release_events",
    "actors_unique": "gharchive_unique_actors",
    "push_days_active": "gharchive_days_active",
}
GHARCHIVE_ZERO_DEFAULTS: dict[str, Any] = {
    "gharchive_present": False,
    "gharchive_sample_percent": None,
    # --- core event counts ---
    "gharchive_events_total": 0,
    "gharchive_push_events": 0,
    "gharchive_pull_request_events": 0,
    "gharchive_pull_request_closed_events": 0,
    "gharchive_pull_request_merged_events": 0,
    "gharchive_pull_request_review_events": 0,
    "gharchive_issues_events": 0,
    "gharchive_issues_closed_events": 0,
    "gharchive_release_events": 0,
    "gharchive_unique_actors": 0,
    "gharchive_days_active": 0,
    "gharchive_source_window_count": 0,
    # --- new event type counts ---
    "gharchive_watch_events": 0,  # stars received this month
    "gharchive_fork_events": 0,  # forks created this month
    "gharchive_branch_create_events": 0,  # new branches created
    "gharchive_tag_create_events": 0,  # new tags created (release discipline)
    # --- actor quality signals ---
    "gharchive_bot_events": 0,  # events from known bot accounts
    "gharchive_human_events": 0,  # events from human accounts
    "gharchive_unique_human_actors": 0,
    "gharchive_owner_push_fraction": None,  # fraction of pushes from top contributor
    # --- text_blob keyword signals ---
    "gharchive_security_keyword_events": 0,  # PRs/issues mentioning CVE, vuln, exploit etc.
    "gharchive_hotfix_keyword_events": 0,  # PRs/issues mentioning hotfix, urgent fix etc.
    "gharchive_dependency_bump_events": 0,  # PRs/issues from dependabot or bump commits
    # --- time-to-merge / time-to-close (median hours) ---
    "gharchive_pr_merge_time_p50_hours": None,
    "gharchive_pr_merge_time_p90_hours": None,
    "gharchive_issue_close_time_p50_hours": None,
    "gharchive_issue_close_time_p90_hours": None,
}
ADVISORY_ZERO_DEFAULTS: dict[str, Any] = {
    "advisories_present_any": False,
    "advisory_count_to_date": 0,
    "advisory_count_this_month": 0,
    "advisory_cve_count_to_date": 0,
    "advisory_max_cvss_to_date": None,
    "had_advisory_this_month": False,
}
SWH_ZERO_DEFAULTS: dict[str, Any] = {
    "swh_present_any": False,
    "swh_origin_found": False,
    "swh_has_snapshot_to_date": False,
    "swh_visit_count_to_date": 0,
    "swh_visits_this_month": 0,
    "swh_visits_last_365d": 0,
    "swh_latest_visit_date_to_date": None,
    "swh_archive_age_days_to_date": None,
    # structural / governance flags
    "swh_has_readme": False,
    "swh_has_dot_github": False,
    "swh_has_jenkinsfile": False,
    "swh_has_travis_yml": False,
    "swh_has_security_md": False,
    "swh_has_changelog": False,
    "swh_has_contributing_md": False,
    "swh_has_dockerfile": False,
    "swh_has_pom_xml": False,
    "swh_has_build_gradle": False,
    "swh_has_mvn_wrapper": False,
    "swh_has_tests_directory": False,
    "swh_has_github_actions": False,
    "swh_has_dependabot": False,
    "swh_has_sonar_config": False,
    "swh_has_snyk_config": False,
    "swh_top_level_entry_count": 0,
    # revision-history signals
    "swh_commit_count": 0,
    "swh_days_since_last_commit": None,
    "swh_author_committer_lag_p50_hours": None,
    "swh_author_committer_lag_p90_hours": None,
    "swh_timezone_diversity": 0,
    "swh_weekend_commit_fraction": None,
    "swh_security_fix_commit_count": 0,
    "swh_merge_commit_fraction": None,
    "swh_conventional_commit_fraction": None,
    "swh_issue_reference_rate": None,
    "swh_empty_message_rate": None,
    "swh_author_committer_mismatch_rate": None,
    "swh_late_night_commit_fraction": None,
}


def _extract_swh_visits(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("results", "visits"):
            val = payload.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
    return []


def _load_swh_records(
    plugin_id: str,
    data_raw_dir: Path,
    backend: str | None = None,
) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)

    if backend == "athena":
        swh_dir = data_raw_dir / "software_heritage_athena"
        return {
            "index": _read_json(swh_dir / f"{plugin_id}.swh_athena_index.json")
            if (swh_dir / f"{plugin_id}.swh_athena_index.json").exists()
            else None,
            "visits": _read_jsonl(swh_dir / f"{plugin_id}.swh_athena_visits.jsonl")
            if (swh_dir / f"{plugin_id}.swh_athena_visits.jsonl").exists()
            else None,
        }

    swh_dir = data_raw_dir / "software_heritage_api"
    return {
        "index": _read_json(swh_dir / f"{plugin_id}.swh_index.json")
        if (swh_dir / f"{plugin_id}.swh_index.json").exists()
        else None,
        "visits": _read_json(swh_dir / f"{plugin_id}.swh_visits.json")
        if (swh_dir / f"{plugin_id}.swh_visits.json").exists()
        else None,
    }


def _load_software_heritage_monthly_features(
    data_raw_dir: Path,
    plugin_ids: list[str],
    months: list[dict[str, Any]],
    backend: str | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}

    month_meta = [
        {
            "month": m["month"],
            "window_start": date.fromisoformat(str(m["window_start"])),
            "window_end": date.fromisoformat(str(m["window_end"])),
        }
        for m in months
    ]

    athena_bool_keys = [
        "has_readme",
        "has_dot_github",
        "has_jenkinsfile",
        "has_travis_yml",
        "has_security_md",
        "has_changelog",
        "has_contributing_md",
        "has_dockerfile",
        "has_pom_xml",
        "has_build_gradle",
        "has_mvn_wrapper",
        "has_tests_directory",
        "has_github_actions",
        "has_dependabot",
        "has_sonar_config",
        "has_snyk_config",
    ]
    athena_int_keys = {
        "top_level_entry_count": "swh_top_level_entry_count",
        "commit_count": "swh_commit_count",
        "timezone_diversity": "swh_timezone_diversity",
        "security_fix_commit_count": "swh_security_fix_commit_count",
    }
    athena_float_keys = {
        "days_since_last_commit": "swh_days_since_last_commit",
        "author_committer_lag_p50_hours": "swh_author_committer_lag_p50_hours",
        "author_committer_lag_p90_hours": "swh_author_committer_lag_p90_hours",
        "weekend_commit_fraction": "swh_weekend_commit_fraction",
        "merge_commit_fraction": "swh_merge_commit_fraction",
        "conventional_commit_fraction": "swh_conventional_commit_fraction",
        "issue_reference_rate": "swh_issue_reference_rate",
        "empty_message_rate": "swh_empty_message_rate",
        "author_committer_mismatch_rate": "swh_author_committer_mismatch_rate",
        "late_night_commit_fraction": "swh_late_night_commit_fraction",
    }

    for plugin_id in plugin_ids:
        raw = _load_swh_records(plugin_id, data_raw_dir, backend=backend)
        index_payload = raw["index"] if isinstance(raw["index"], dict) else {}
        visits_payload = raw["visits"]
        visits = _extract_swh_visits(visits_payload)

        normalized_visits: list[dict[str, Any]] = []
        for visit in visits:
            dt = _parse_iso_date(visit.get("date") or visit.get("visit_date"))
            if dt is not None:
                normalized_visits.append({"date": dt, "record": visit})
        normalized_visits.sort(key=lambda x: x["date"])
        normalized_dates = [item["date"] for item in normalized_visits]

        is_athena = (backend == "athena") or (index_payload.get("backend") == "athena")
        origin_found = (
            bool(index_payload.get("record_count", 0) > 0)
            if is_athena
            else bool(index_payload.get("origin_found"))
        )
        snapshot_found = (
            bool(normalized_dates) if is_athena else bool(index_payload.get("snapshot_found"))
        )

        for month in month_meta:
            window_start = month["window_start"]
            window_end = month["window_end"]

            to_date = [item for item in normalized_visits if item["date"] <= window_end]
            this_month = [
                item for item in normalized_visits if window_start <= item["date"] <= window_end
            ]
            trailing = [
                item["date"]
                for item in normalized_visits
                if (window_end - item["date"]).days <= 365 and item["date"] <= window_end
            ]

            if not index_payload and not normalized_visits:
                continue

            first_date = to_date[0]["date"] if to_date else None
            latest_date = to_date[-1]["date"] if to_date else None

            row = {
                "swh_present_any": bool(index_payload) or bool(normalized_visits),
                "swh_origin_found": origin_found,
                "swh_has_snapshot_to_date": bool(to_date) and snapshot_found,
                "swh_visit_count_to_date": len(to_date),
                "swh_visits_this_month": len(this_month),
                "swh_visits_last_365d": len(trailing),
                "swh_latest_visit_date_to_date": latest_date.isoformat() if latest_date else None,
                "swh_archive_age_days_to_date": (
                    (latest_date - first_date).days if first_date and latest_date else None
                ),
            }

            if is_athena and to_date:
                latest_visit = to_date[-1]["record"]
                for key in athena_bool_keys:
                    row[f"swh_{key}"] = bool(latest_visit.get(key))
                for src_key, dst_key in athena_int_keys.items():
                    row[dst_key] = int(latest_visit.get(src_key) or 0)

                for src_key, dst_key in athena_float_keys.items():
                    if src_key == "days_since_last_commit":
                        # Recompute relative to observation month boundary
                        # latest_visit stores the raw author_dates via commit_count,
                        # but we need the last commit date itself — stored as visit_dt - days_since
                        stored_days = _safe_float(latest_visit.get("days_since_last_commit"))
                        visit_dt_str = latest_visit.get("visit_date") or latest_visit.get("date")
                        visit_dt = _parse_iso_date(visit_dt_str)
                        if stored_days is not None and visit_dt is not None:
                            last_commit_date = visit_dt - timedelta(days=stored_days)
                            recomputed = (window_end - last_commit_date).days
                            row[dst_key] = max(0.0, float(recomputed))
                        else:
                            row[dst_key] = None
                    else:
                        row[dst_key] = _safe_float(latest_visit.get(src_key))

            out[(plugin_id, month["month"])] = row

    return out


def _parse_yyyymmdd(value: Any) -> date | None:
    if not isinstance(value, str) or len(value) != 8 or not value.isdigit():
        return None
    try:
        return datetime.strptime(value, "%Y%m%d").date()
    except ValueError:
        return None


def _parse_iso_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


def _parse_iso_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp string into a timezone-aware datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _load_gharchive_monthly_features(data_raw_dir: Path) -> dict[tuple[str, str], dict[str, Any]]:
    gharchive_dir = data_raw_dir / "gharchive" / "normalized-events"
    out: dict[tuple[str, str], dict[str, Any]] = {}
    source_windows: dict[tuple[str, str], set[tuple[str | None, str | None]]] = defaultdict(set)
    active_days: dict[tuple[str, str], set[str]] = defaultdict(set)
    active_actors: dict[tuple[str, str], set[str]] = defaultdict(set)
    human_actors: dict[tuple[str, str], set[str]] = defaultdict(set)
    # For owner concentration: track push counts per actor per (plugin, month)
    push_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # For time-to-merge/close: accumulate durations in hours
    pr_merge_hours: dict[tuple[str, str], list[float]] = defaultdict(list)
    issue_close_hours: dict[tuple[str, str], list[float]] = defaultdict(list)

    if not gharchive_dir.exists():
        return out

    for path in sorted(gharchive_dir.glob("*.gharchive.events.jsonl")):
        rows = _read_jsonl(path)
        for row in rows:
            plugin_id = canonicalize_plugin_id(
                str(row.get("plugin_id") or "").strip(), data_dir=data_raw_dir
            )
            month_key = str(row.get("event_yyyymm") or "").strip()
            if not plugin_id or not month_key:
                continue
            key = (plugin_id, month_key)
            bucket = out.setdefault(key, dict(GHARCHIVE_ZERO_DEFAULTS))
            bucket["gharchive_present"] = True
            bucket["gharchive_events_total"] += 1

            sample = _safe_float(row.get("sample_percent"))
            if sample is not None:
                bucket["gharchive_sample_percent"] = sample

            event_type = str(row.get("event_type") or "").strip()
            action = str(row.get("action") or "").strip().lower()
            actor_login = str(row.get("actor_login") or "").strip()
            text_blob = row.get("text_blob")
            ref_type = str(row.get("ref_type") or "").strip().lower()

            # --- actor classification ---
            is_bot = _is_bot_actor(actor_login)
            if is_bot:
                bucket["gharchive_bot_events"] += 1
            else:
                bucket["gharchive_human_events"] += 1

            # --- core event type counting ---
            if event_type == "PushEvent":
                bucket["gharchive_push_events"] += 1
                if actor_login and not is_bot:
                    push_counts[key][actor_login] += 1
            elif event_type == "PullRequestEvent":
                bucket["gharchive_pull_request_events"] += 1
                if action == "closed":
                    bucket["gharchive_pull_request_closed_events"] += 1
                if row.get("pr_merged") is True:
                    bucket["gharchive_pull_request_merged_events"] += 1
                    # time-to-merge
                    pr_created = _parse_iso_timestamp(row.get("pr_created_ts"))
                    pr_closed = _parse_iso_timestamp(row.get("pr_closed_ts"))
                    if pr_created and pr_closed and pr_closed > pr_created:
                        hours = (pr_closed - pr_created).total_seconds() / 3600
                        pr_merge_hours[key].append(hours)
            elif event_type == "PullRequestReviewEvent":
                bucket["gharchive_pull_request_review_events"] += 1
            elif event_type == "IssuesEvent":
                bucket["gharchive_issues_events"] += 1
                if action == "closed":
                    bucket["gharchive_issues_closed_events"] += 1
                    # time-to-close
                    iss_created = _parse_iso_timestamp(row.get("issue_created_ts"))
                    iss_closed = _parse_iso_timestamp(row.get("issue_closed_ts"))
                    if iss_created and iss_closed and iss_closed > iss_created:
                        hours = (iss_closed - iss_created).total_seconds() / 3600
                        issue_close_hours[key].append(hours)
            elif event_type == "ReleaseEvent":
                bucket["gharchive_release_events"] += 1
            elif event_type == "WatchEvent":
                bucket["gharchive_watch_events"] += 1
            elif event_type == "ForkEvent":
                bucket["gharchive_fork_events"] += 1
            elif event_type == "CreateEvent":
                if ref_type == "branch":
                    bucket["gharchive_branch_create_events"] += 1
                elif ref_type == "tag":
                    bucket["gharchive_tag_create_events"] += 1

            # --- text_blob keyword signals ---
            if _text_blob_matches(text_blob, _SECURITY_KEYWORDS):
                bucket["gharchive_security_keyword_events"] += 1
            if _text_blob_matches(text_blob, _HOTFIX_KEYWORDS):
                bucket["gharchive_hotfix_keyword_events"] += 1
            if _text_blob_matches(text_blob, _DEPENDENCY_KEYWORDS) or (
                actor_login and _is_bot_actor(actor_login) and event_type == "PullRequestEvent"
            ):
                bucket["gharchive_dependency_bump_events"] += 1

            # --- actor / day tracking ---
            if actor_login:
                active_actors[key].add(actor_login)
                if not is_bot:
                    human_actors[key].add(actor_login)
            event_date = str(row.get("event_date") or "").strip()
            if event_date:
                active_days[key].add(event_date)
            source_windows[key].add(
                (
                    str(row.get("source_window_start_yyyymmdd") or "").strip() or None,
                    str(row.get("source_window_end_yyyymmdd") or "").strip() or None,
                )
            )

    for key, bucket in out.items():
        bucket["gharchive_unique_actors"] = len(active_actors.get(key, set()))
        bucket["gharchive_days_active"] = len(active_days.get(key, set()))
        bucket["gharchive_source_window_count"] = len(source_windows.get(key, set()))
        bucket["gharchive_unique_human_actors"] = len(human_actors.get(key, set()))

        # owner concentration: fraction of pushes from single most active human
        pc = push_counts.get(key, {})
        if pc:
            total_pushes = sum(pc.values())
            top_pushes = max(pc.values())
            bucket["gharchive_owner_push_fraction"] = (
                top_pushes / total_pushes if total_pushes > 0 else None
            )

        # time-to-merge percentiles
        pm = pr_merge_hours.get(key, [])
        bucket["gharchive_pr_merge_time_p50_hours"] = _percentile(pm, 50)
        bucket["gharchive_pr_merge_time_p90_hours"] = _percentile(pm, 90)

        # time-to-close percentiles
        ic = issue_close_hours.get(key, [])
        bucket["gharchive_issue_close_time_p50_hours"] = _percentile(ic, 50)
        bucket["gharchive_issue_close_time_p90_hours"] = _percentile(ic, 90)

    return out


def _load_advisory_records(plugin_id: str, data_raw_dir: Path) -> list[dict[str, Any]]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    advisories_dir = data_raw_dir / "advisories"
    candidates = [
        advisories_dir / f"{plugin_id}.advisories.real.jsonl",
        advisories_dir / f"{plugin_id}.advisories.sample.jsonl",
        advisories_dir / f"{plugin_id}.advisories.jsonl",
    ]
    for path in candidates:
        if path.exists():
            return _read_jsonl(path)
    return []


def _advisory_cvss(rec: dict[str, Any]) -> float | None:
    candidates: list[Any] = [rec.get("cvss")]
    sev = rec.get("severity_summary")
    if isinstance(sev, dict):
        candidates.extend([sev.get("max_cvss_base_score"), sev.get("cvss"), sev.get("max_cvss")])
    vulns = rec.get("vulnerabilities")
    if isinstance(vulns, list):
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            candidates.extend(
                [vuln.get("cvss"), vuln.get("cvss_base_score"), vuln.get("cvssScore")]
            )
    nums = [n for n in (_safe_float(v) for v in candidates) if n is not None]
    return max(nums) if nums else None


def _advisory_cve_ids(rec: dict[str, Any]) -> set[str]:
    cve_ids: set[str] = set()
    direct = rec.get("cve_ids")
    if isinstance(direct, list):
        for cve in direct:
            text = str(cve).strip()
            if text:
                cve_ids.add(text)
    vulns = rec.get("vulnerabilities")
    if isinstance(vulns, list):
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            cve = vuln.get("cve_id") or vuln.get("cve")
            if isinstance(cve, str) and cve.strip():
                cve_ids.add(cve.strip())
    return cve_ids


def _load_advisory_monthly_features(
    data_raw_dir: Path,
    plugin_ids: list[str],
    months: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    month_meta = [
        {
            "month": m["month"],
            "window_start": date.fromisoformat(str(m["window_start"])),
            "window_end": date.fromisoformat(str(m["window_end"])),
        }
        for m in months
    ]
    for plugin_id in plugin_ids:
        records = _load_advisory_records(plugin_id, data_raw_dir)
        normalized: list[dict[str, Any]] = []
        for rec in records:
            published = _parse_iso_date(rec.get("published_date") or rec.get("date"))
            if published is None:
                continue
            normalized.append(
                {
                    "published": published,
                    "cvss": _advisory_cvss(rec),
                    "cve_ids": _advisory_cve_ids(rec),
                }
            )
        normalized.sort(key=lambda x: x["published"])
        for month in month_meta:
            window_start = month["window_start"]
            window_end = month["window_end"]
            to_date = [r for r in normalized if r["published"] <= window_end]
            this_month = [r for r in normalized if window_start <= r["published"] <= window_end]
            if not to_date and not this_month:
                continue

            cve_ids: set[str] = set()
            cvss_vals: list[float] = []
            for rec in to_date:
                cve_ids.update(rec["cve_ids"])
                if rec["cvss"] is not None:
                    cvss_vals.append(rec["cvss"])

            first_date = to_date[0]["published"] if to_date else None
            latest_date = to_date[-1]["published"] if to_date else None
            recent_365 = [r for r in to_date if (window_end - r["published"]).days <= 365]
            cvss_ge_7_count = sum(1 for r in to_date if r["cvss"] is not None and r["cvss"] >= 7.0)

            out[(plugin_id, month["month"])] = {
                "advisories_present_any": bool(normalized),
                "advisory_count_to_date": len(to_date),
                "advisory_count_this_month": len(this_month),
                "advisory_cve_count_to_date": len(cve_ids),
                "advisory_max_cvss_to_date": max(cvss_vals) if cvss_vals else None,
                "had_advisory_this_month": bool(this_month),
                "advisory_days_since_first_to_date": (
                    (window_end - first_date).days if first_date else None
                ),
                "advisory_days_since_latest_to_date": (
                    (window_end - latest_date).days if latest_date else None
                ),
                "advisory_span_days_to_date": (
                    (latest_date - first_date).days if first_date and latest_date else None
                ),
                "advisories_last_365d": len(recent_365),
                "advisory_cvss_ge_7_count_to_date": cvss_ge_7_count,
                "advisory_mean_cvss_to_date": (
                    sum(cvss_vals) / len(cvss_vals) if cvss_vals else None
                ),
            }
    return out


def _num(row: dict[str, Any], key: str) -> float:
    value = row.get(key)
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _trailing_sum(rows: list[dict[str, Any]], idx: int, key: str, window: int) -> float:
    start = max(0, idx - window + 1)
    return sum(_num(rows[j], key) for j in range(start, idx + 1))


def _trailing_values(rows: list[dict[str, Any]], idx: int, key: str, window: int) -> list[float]:
    start = max(0, idx - window + 1)
    return [_num(rows[j], key) for j in range(start, idx + 1)]


def _trailing_active_months(rows: list[dict[str, Any]], idx: int, key: str, window: int) -> int:
    return sum(1 for value in _trailing_values(rows, idx, key, window) if value > 0)


def _previous_window_sum(rows: list[dict[str, Any]], idx: int, key: str, window: int) -> float:
    end = idx - window
    if end < 0:
        return 0.0
    start = max(0, end - window + 1)
    return sum(_num(rows[j], key) for j in range(start, end + 1))


def _months_since_last_nonzero(rows: list[dict[str, Any]], idx: int, key: str) -> int | None:
    for offset in range(0, idx + 1):
        j = idx - offset
        if _num(rows[j], key) > 0:
            return offset
    return None


def _safe_div(numer: float, denom: float) -> float | None:
    if denom <= 0:
        return None
    return numer / denom


def _safe_div_min(
    numer: float,
    denom: float,
    *,
    min_denom: float = 1.0,
) -> float | None:
    if denom < min_denom:
        return None
    return numer / denom


def _safe_div_smooth(
    numer: float,
    denom: float,
    *,
    min_denom: float = 1.0,
    numer_smooth: float = 1.0,
    denom_smooth: float = 2.0,
) -> float | None:
    if denom < min_denom:
        return None
    return (numer + numer_smooth) / (denom + denom_smooth)


def _clip(
    value: float | None, *, low: float | None = None, high: float | None = None
) -> float | None:
    if value is None:
        return None
    if low is not None and value < low:
        value = low
    if high is not None and value > high:
        value = high
    return value


def _add_rolling_gharchive_features(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = sorted(rows, key=lambda r: str(r.get("month") or ""))

    count_keys = [
        "gharchive_events_total",
        "gharchive_push_events",
        "gharchive_pull_request_events",
        "gharchive_pull_request_closed_events",
        "gharchive_pull_request_merged_events",
        "gharchive_pull_request_review_events",
        "gharchive_issues_events",
        "gharchive_issues_closed_events",
        "gharchive_release_events",
        "gharchive_unique_actors",
        "gharchive_days_active",
        # new signals
        "gharchive_watch_events",
        "gharchive_fork_events",
        "gharchive_tag_create_events",
        "gharchive_branch_create_events",
        "gharchive_bot_events",
        "gharchive_human_events",
        "gharchive_unique_human_actors",
        "gharchive_security_keyword_events",
        "gharchive_hotfix_keyword_events",
        "gharchive_dependency_bump_events",
    ]

    for i, row in enumerate(rows):
        for key in count_keys:
            row[f"{key}_trailing_3m"] = _trailing_sum(rows, i, key, 3)
            row[f"{key}_trailing_6m"] = _trailing_sum(rows, i, key, 6)

        row["gharchive_months_since_push"] = _months_since_last_nonzero(
            rows, i, "gharchive_push_events"
        )
        row["gharchive_months_since_pr"] = _months_since_last_nonzero(
            rows, i, "gharchive_pull_request_events"
        )
        row["gharchive_months_since_issue"] = _months_since_last_nonzero(
            rows, i, "gharchive_issues_events"
        )
        row["gharchive_months_since_release"] = _months_since_last_nonzero(
            rows, i, "gharchive_release_events"
        )
        row["gharchive_months_since_any_activity"] = _months_since_last_nonzero(
            rows, i, "gharchive_events_total"
        )

        push_3m = _num(row, "gharchive_push_events_trailing_3m")
        pr_3m = _num(row, "gharchive_pull_request_events_trailing_3m")
        pr_closed_3m = _num(row, "gharchive_pull_request_closed_events_trailing_3m")
        pr_review_3m = _num(row, "gharchive_pull_request_review_events_trailing_3m")
        merged_3m = _num(row, "gharchive_pull_request_merged_events_trailing_3m")
        issues_3m = _num(row, "gharchive_issues_events_trailing_3m")
        issues_closed_3m = _num(row, "gharchive_issues_closed_events_trailing_3m")
        actors_3m = _num(row, "gharchive_unique_actors_trailing_3m")
        active_days_3m = _num(row, "gharchive_days_active_trailing_3m")

        push_6m = _num(row, "gharchive_push_events_trailing_6m")
        pr_6m = _num(row, "gharchive_pull_request_events_trailing_6m")
        pr_closed_6m = _num(row, "gharchive_pull_request_closed_events_trailing_6m")
        pr_review_6m = _num(row, "gharchive_pull_request_review_events_trailing_6m")
        merged_6m = _num(row, "gharchive_pull_request_merged_events_trailing_6m")
        issues_6m = _num(row, "gharchive_issues_events_trailing_6m")
        issues_closed_6m = _num(row, "gharchive_issues_closed_events_trailing_6m")
        releases_6m = _num(row, "gharchive_release_events_trailing_6m")
        actors_6m = _num(row, "gharchive_unique_actors_trailing_6m")
        active_days_6m = _num(row, "gharchive_days_active_trailing_6m")
        events_6m = _num(row, "gharchive_events_total_trailing_6m")

        row["gharchive_push_events_trailing_3m_delta_prev_3m"] = push_3m - _previous_window_sum(
            rows, i, "gharchive_push_events", 3
        )
        row["gharchive_pull_request_events_trailing_3m_delta_prev_3m"] = (
            pr_3m - _previous_window_sum(rows, i, "gharchive_pull_request_events", 3)
        )
        row["gharchive_release_events_trailing_3m_delta_prev_3m"] = _num(
            row, "gharchive_release_events_trailing_3m"
        ) - _previous_window_sum(rows, i, "gharchive_release_events", 3)

        row["gharchive_prs_per_push_3m"] = _clip(
            _safe_div_smooth(pr_3m, push_3m, min_denom=5.0),
            high=10.0,
        )
        row["gharchive_prs_per_push_6m"] = _clip(
            _safe_div_smooth(pr_6m, push_6m, min_denom=8.0),
            high=10.0,
        )

        row["gharchive_merge_rate_3m"] = _clip(
            _safe_div_smooth(merged_3m, pr_3m, min_denom=5.0),
            low=0.0,
            high=1.0,
        )
        row["gharchive_merge_rate_6m"] = _clip(
            _safe_div_smooth(merged_6m, pr_6m, min_denom=8.0),
            low=0.0,
            high=1.0,
        )

        row["gharchive_pr_close_rate_3m"] = _clip(
            _safe_div_smooth(pr_closed_3m, pr_3m, min_denom=5.0),
            low=0.0,
            high=1.5,
        )
        row["gharchive_pr_close_rate_6m"] = _clip(
            _safe_div_smooth(pr_closed_6m, pr_6m, min_denom=8.0),
            low=0.0,
            high=1.5,
        )

        row["gharchive_pr_review_intensity_3m"] = _clip(
            _safe_div_smooth(pr_review_3m, pr_3m, min_denom=5.0),
            low=0.0,
            high=10.0,
        )
        row["gharchive_pr_review_intensity_6m"] = _clip(
            _safe_div_smooth(pr_review_6m, pr_6m, min_denom=8.0),
            low=0.0,
            high=10.0,
        )

        row["gharchive_issue_close_rate_3m"] = _clip(
            _safe_div_smooth(issues_closed_3m, issues_3m, min_denom=5.0),
            low=0.0,
            high=1.5,
        )
        row["gharchive_issue_close_rate_6m"] = _clip(
            _safe_div_smooth(issues_closed_6m, issues_6m, min_denom=8.0),
            low=0.0,
            high=1.5,
        )

        row["gharchive_actors_per_active_day_3m"] = _clip(
            _safe_div_min(actors_3m, active_days_3m, min_denom=5.0),
            low=0.0,
            high=10.0,
        )
        row["gharchive_actors_per_active_day_6m"] = _clip(
            _safe_div_min(actors_6m, active_days_6m, min_denom=8.0),
            low=0.0,
            high=10.0,
        )

        active_months_any_3m = _trailing_active_months(rows, i, "gharchive_events_total", 3)
        active_months_any_6m = _trailing_active_months(rows, i, "gharchive_events_total", 6)
        observed_months_3m = min(i + 1, 3)
        observed_months_6m = min(i + 1, 6)

        row["gharchive_active_month_ratio_3m"] = _clip(
            _safe_div(active_months_any_3m, observed_months_3m),
            low=0.0,
            high=1.0,
        )
        row["gharchive_active_month_ratio_6m"] = _clip(
            _safe_div(active_months_any_6m, observed_months_6m),
            low=0.0,
            high=1.0,
        )
        row["gharchive_releases_per_active_month_6m"] = _clip(
            _safe_div_min(releases_6m, active_months_any_6m, min_denom=2.0),
            low=0.0,
            high=12.0,
        )
        row["gharchive_events_per_active_month_6m"] = _clip(
            _safe_div_min(events_6m, active_months_any_6m, min_denom=2.0),
            low=0.0,
            high=500.0,
        )
        values_6m = _trailing_values(rows, i, "gharchive_events_total", 6)
        if values_6m:
            avg_6m = sum(values_6m) / len(values_6m)
            if avg_6m >= 5.0:
                row["gharchive_activity_burstiness_6m"] = _clip(
                    max(values_6m) / avg_6m,
                    low=0.0,
                    high=10.0,
                )
            else:
                row["gharchive_activity_burstiness_6m"] = None
        else:
            row["gharchive_activity_burstiness_6m"] = None

        # --- new derived features ---

        # staleness for new event types
        row["gharchive_months_since_release_tag"] = _months_since_last_nonzero(
            rows, i, "gharchive_tag_create_events"
        )
        row["gharchive_months_since_security_keyword"] = _months_since_last_nonzero(
            rows, i, "gharchive_security_keyword_events"
        )

        # bot ratio: fraction of events from bots (high = potentially abandoned)
        total_events = _num(row, "gharchive_events_total_trailing_3m")
        bot_events_3m = _num(row, "gharchive_bot_events_trailing_3m")
        row["gharchive_bot_event_ratio_3m"] = _clip(
            _safe_div_smooth(bot_events_3m, total_events, min_denom=5.0),
            low=0.0,
            high=1.0,
        )

        # security keyword rate: security events per total PR+issue events (leading indicator)
        pr_issue_3m = _num(row, "gharchive_pull_request_events_trailing_3m") + _num(
            row, "gharchive_issues_events_trailing_3m"
        )
        sec_3m = _num(row, "gharchive_security_keyword_events_trailing_3m")
        row["gharchive_security_keyword_rate_3m"] = _clip(
            _safe_div_smooth(sec_3m, pr_issue_3m, min_denom=5.0),
            low=0.0,
            high=1.0,
        )

        # cumulative star / fork proxies (trailing sums as historical approximations)
        row["gharchive_stars_trailing_6m"] = _num(row, "gharchive_watch_events_trailing_6m")
        row["gharchive_forks_trailing_6m"] = _num(row, "gharchive_fork_events_trailing_6m")

        # delta signals for new event types
        row["gharchive_security_keyword_events_trailing_3m_delta_prev_3m"] = (
            sec_3m - _previous_window_sum(rows, i, "gharchive_security_keyword_events", 3)
        )
        row["gharchive_watch_events_trailing_3m_delta_prev_3m"] = _num(
            row, "gharchive_watch_events_trailing_3m"
        ) - _previous_window_sum(rows, i, "gharchive_watch_events", 3)

    return rows


def build_monthly_feature_bundle(
    *,
    data_raw_dir: str | Path = "data/raw",
    registry_path: str | Path = "data/raw/registry/plugins.jsonl",
    start_month: str,
    end_month: str,
    out_path: str | Path = "data/processed/features/plugins.monthly.features.jsonl",
    out_csv_path: str | Path | None = "data/processed/features/plugins.monthly.features.csv",
    summary_path: str | Path | None = (
        "data/processed/features/plugins.monthly.features.summary.json"
    ),
    software_heritage_backend: str | None = "athena",
) -> list[dict[str, Any]]:
    data_raw_dir = Path(data_raw_dir)
    registry_path = Path(registry_path)
    out_path = Path(out_path)
    out_csv = Path(out_csv_path) if out_csv_path is not None else None
    summary = Path(summary_path) if summary_path is not None else None
    registry = _iter_registry_records(registry_path)
    plugin_ids = sorted(
        {
            canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
            for rec in registry
            if (plugin_id := str(rec.get("plugin_id") or "").strip())
        }
    )
    months = iter_months(start_month, end_month)
    gharchive_monthly = _load_gharchive_monthly_features(data_raw_dir)
    swh_rows = _load_software_heritage_monthly_features(
        data_raw_dir,
        plugin_ids,
        months,
        backend=software_heritage_backend,
    )
    advisory_monthly = _load_advisory_monthly_features(data_raw_dir, plugin_ids, months)
    registry_by_plugin = {
        canonicalize_plugin_id(str(rec.get("plugin_id") or "").strip(), data_dir=data_raw_dir): rec
        for rec in registry
        if str(rec.get("plugin_id") or "").strip()
    }
    rows: list[dict[str, Any]] = []
    for plugin_id in plugin_ids:
        registry_rec = registry_by_plugin[plugin_id]
        for month in months:
            row: dict[str, Any] = {
                "plugin_id": plugin_id,
                "month": month["month"],
                "window_start": month["window_start"],
                "window_end": month["window_end"],
                "window_year": month["window_year"],
                "window_month": month["window_month"],
                "window_index": month["window_index"],
                "registry_collected_at": registry_rec.get("collected_at"),
                "registry_plugin_site_url": registry_rec.get("plugin_site_url"),
                "registry_plugin_api_url": registry_rec.get("plugin_api_url"),
                "registry_title": registry_rec.get("title") or registry_rec.get("plugin_title"),
            }
            row.update(dict(ADVISORY_ZERO_DEFAULTS))
            row.update(advisory_monthly.get((plugin_id, month["month"]), {}))
            row.update(dict(GHARCHIVE_ZERO_DEFAULTS))
            row.update(gharchive_monthly.get((plugin_id, month["month"]), {}))
            row.update(SWH_ZERO_DEFAULTS)
            row.update(swh_rows.get((plugin_id, month["month"]), {}))
            rows.append(row)
    rows_by_plugin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        rows_by_plugin[str(row.get("plugin_id") or "")].append(row)

    rows = []
    for plugin_id in sorted(rows_by_plugin):
        rows.extend(_add_rolling_gharchive_features(rows_by_plugin[plugin_id]))

    rows.sort(key=lambda r: (str(r.get("plugin_id") or ""), str(r.get("month") or "")))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    if out_csv is not None:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        fieldnames: list[str] = sorted({key for row in rows for key in row.keys()})
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: _to_csv_scalar(row.get(k)) for k in fieldnames})
    if summary is not None:
        summary.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "registry_path": str(registry_path),
            "data_raw_dir": str(data_raw_dir),
            "start_month": start_month,
            "end_month": end_month,
            "months_total": len(months),
            "plugins_total": len(plugin_ids),
            "rows_total": len(rows),
            "rows_with_gharchive": sum(1 for r in rows if r.get("gharchive_present")),
            "rows_with_advisory_this_month": sum(
                1 for r in rows if r.get("had_advisory_this_month")
            ),
            "software_heritage_backend": software_heritage_backend,
            "out_path": str(out_path),
            "out_csv_path": str(out_csv) if out_csv is not None else None,
        }
        summary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return rows
