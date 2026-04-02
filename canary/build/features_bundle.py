from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterable
from datetime import date, datetime
from pathlib import Path
from statistics import mean
from typing import Any

from canary.plugin_aliases import canonicalize_plugin_id
from canary.scoring.baseline import _load_healthscore_record


def _iter_registry_records(registry_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not registry_path.exists():
        raise FileNotFoundError(f"Registry file not found: {registry_path}")
    with registry_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    return out


def _safe_float(value: Any) -> float | None:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(out) or math.isinf(out):
        return None
    return out


def _max_float(values: Iterable[Any]) -> float | None:
    nums = [v for v in (_safe_float(x) for x in values) if v is not None]
    return max(nums) if nums else None


def _mean_float(values: Iterable[Any]) -> float | None:
    nums = [v for v in (_safe_float(x) for x in values) if v is not None]
    return mean(nums) if nums else None


def _sum_float(values: Iterable[Any]) -> float | None:
    nums = [v for v in (_safe_float(x) for x in values) if v is not None]
    return sum(nums) if nums else None


GHARCHIVE_NUMERIC_KEYS = [
    "events_total",
    "actors_unique",
    "pushes",
    "committers_unique",
    "push_days_active",
    "prs_opened",
    "prs_closed",
    "prs_merged",
    "prs_closed_unmerged",
    "pr_reviewed_ratio",
    "pr_merge_time_p50_hours",
    "pr_close_without_merge_ratio",
    "issues_opened",
    "issues_closed",
    "issues_reopened",
    "issue_reopen_rate",
    "issue_close_time_p50_hours",
    "releases",
    "days_since_last_release",
    "hotfix_proxy",
    "security_label_proxy",
    "churn_intensity",
    "owner_concentration",
]


def _latest_installations_total(plugin_api: dict[str, Any]) -> int | None:
    stats = plugin_api.get("stats")
    if not isinstance(stats, dict):
        return None
    installs = stats.get("installations")
    if not isinstance(installs, list) or not installs:
        return None
    latest = installs[-1]
    if not isinstance(latest, dict):
        return None
    total = latest.get("total")
    return int(total) if isinstance(total, int) else None


def _repo_url_from_snapshot(snapshot: dict[str, Any]) -> str | None:
    for key in ("repo_url", "scm_url"):
        val = snapshot.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, dict):
            link = val.get("link") or val.get("url")
            if isinstance(link, str) and link.strip():
                return link.strip()
    plugin_api = snapshot.get("plugin_api")
    if isinstance(plugin_api, dict):
        scm = plugin_api.get("scm")
        if isinstance(scm, str) and scm.strip():
            return scm.strip()
        if isinstance(scm, dict):
            link = scm.get("link") or scm.get("url")
            if isinstance(link, str) and link.strip():
                return link.strip()
    return None


def _cvss_candidates(rec: dict[str, Any]) -> list[float]:
    out: list[float] = []
    direct = rec.get("cvss")
    if direct is not None:
        num = _safe_float(direct)
        if num is not None:
            out.append(num)
    sev = rec.get("severity_summary")
    if isinstance(sev, dict):
        for key in ("max_cvss_base_score", "cvss", "max_cvss"):
            num = _safe_float(sev.get(key))
            if num is not None:
                out.append(num)
    vulns = rec.get("vulnerabilities")
    if isinstance(vulns, list):
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            for key in ("cvss", "cvss_base_score", "cvssScore"):
                num = _safe_float(vuln.get(key))
                if num is not None:
                    out.append(num)
    return out


def _load_snapshot_features(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    path = data_raw_dir / "plugins" / f"{plugin_id}.snapshot.json"
    row: dict[str, Any] = {"snapshot_present": False}
    if not path.exists():
        return row

    snapshot = _read_json(path)
    plugin_api = snapshot.get("plugin_api") if isinstance(snapshot, dict) else None
    if not isinstance(plugin_api, dict):
        plugin_api = {}

    raw_deps = plugin_api.get("dependencies")
    deps: list[dict[str, Any]] = (
        [d for d in raw_deps if isinstance(d, dict)] if isinstance(raw_deps, list) else []
    )

    raw_maintainers = plugin_api.get("maintainers")
    maintainers: list[dict[str, Any] | str] = (
        [m for m in raw_maintainers if isinstance(m, (dict, str))]
        if isinstance(raw_maintainers, list)
        else []
    )

    raw_sec_warnings = plugin_api.get("securityWarnings")
    sec_warnings: list[dict[str, Any]] = (
        [w for w in raw_sec_warnings if isinstance(w, dict)]
        if isinstance(raw_sec_warnings, list)
        else []
    )

    raw_labels = plugin_api.get("labels")
    labels: list[str] = (
        [str(x) for x in raw_labels if isinstance(x, str)] if isinstance(raw_labels, list) else []
    )

    raw_categories = plugin_api.get("categories")
    categories: list[str] = (
        [str(x) for x in raw_categories if isinstance(x, str)]
        if isinstance(raw_categories, list)
        else []
    )

    current_version = snapshot.get("current_version") or plugin_api.get("version")
    latest_release = plugin_api.get("releaseTimestamp") or snapshot.get("latest_release_date")

    return {
        "snapshot_present": True,
        "snapshot_collected_at": snapshot.get("collected_at"),
        "snapshot_current_version": current_version,
        "snapshot_required_core": plugin_api.get("requiredCore"),
        "snapshot_repo_url": _repo_url_from_snapshot(snapshot),
        "snapshot_maintainers_count": len(maintainers),
        "snapshot_dependencies_count": len(deps),
        "snapshot_labels_count": len(labels),
        "snapshot_labels": labels,
        "snapshot_categories_count": len(categories),
        "snapshot_categories": categories,
        "snapshot_security_warning_count": len(sec_warnings),
        "snapshot_active_security_warning_count": sum(
            1 for w in sec_warnings if w.get("active") is True
        ),
        "snapshot_latest_release_timestamp": latest_release,
        "snapshot_first_release": plugin_api.get("firstRelease"),
        "snapshot_previous_version": plugin_api.get("previousVersion"),
        "snapshot_installations_latest": _latest_installations_total(plugin_api),
        "snapshot_github_stars_enriched": snapshot.get("github_stars"),
        "snapshot_github_forks_enriched": snapshot.get("github_forks"),
        "snapshot_github_watchers_enriched": snapshot.get("github_watchers"),
        "snapshot_github_open_issues_only_enriched": snapshot.get("github_open_issues_only"),
        "snapshot_github_open_prs_enriched": snapshot.get("github_open_prs"),
        "snapshot_github_contributors_top_sampled": snapshot.get("github_contributors_top_sampled"),
        "snapshot_github_top_contributor_share": snapshot.get("github_top_contributor_share"),
        "snapshot_github_has_ci_workflows": snapshot.get("github_has_ci_workflows"),
        "snapshot_github_ci_workflow_count": snapshot.get("github_ci_workflow_count"),
    }


def _parse_iso_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


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
    return _max_float(_cvss_candidates(rec))


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


def _load_advisory_features(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    records = _load_advisory_records(plugin_id, data_raw_dir)
    if not records:
        return {
            "advisories_present": False,
            "advisory_count": 0,
            "advisory_cve_count": 0,
            "advisory_latest_published_date": None,
            "advisory_first_published_date": None,
            "advisory_max_cvss": None,
            "advisory_active_warning_count": 0,
            "advisory_days_since_first": None,
            "advisory_days_since_latest": None,
            "advisory_span_days": None,
            "advisory_count_last_365d": 0,
            "advisory_cvss_ge_7_count": 0,
            "advisory_mean_cvss": None,
        }

    normalized: list[dict[str, Any]] = []
    active_warning_count = 0

    for rec in records:
        published = _parse_iso_date(rec.get("published_date") or rec.get("date"))
        cvss = _advisory_cvss(rec)
        cve_ids = _advisory_cve_ids(rec)

        normalized.append(
            {
                "published": published,
                "cvss": cvss,
                "cve_ids": cve_ids,
            }
        )

        warnings = rec.get("warnings") or []
        if isinstance(warnings, list):
            for warning in warnings:
                if not isinstance(warning, dict):
                    continue
                if bool(warning.get("active")):
                    active_warning_count += 1

    published_dates = sorted(r["published"] for r in normalized if r["published"] is not None)
    cvss_vals = [r["cvss"] for r in normalized if r["cvss"] is not None]

    cve_ids: set[str] = set()
    for rec in normalized:
        cve_ids.update(rec["cve_ids"])

    first_date = published_dates[0] if published_dates else None
    latest_date = published_dates[-1] if published_dates else None
    today = date.today()

    advisory_count_last_365d = sum(
        1
        for rec in normalized
        if rec["published"] is not None and (today - rec["published"]).days <= 365
    )
    advisory_cvss_ge_7_count = sum(
        1 for rec in normalized if rec["cvss"] is not None and rec["cvss"] >= 7.0
    )

    return {
        "advisories_present": True,
        "advisory_count": len(records),
        "advisory_cve_count": len(cve_ids),
        "advisory_latest_published_date": (latest_date.isoformat() if latest_date else None),
        "advisory_first_published_date": (first_date.isoformat() if first_date else None),
        "advisory_max_cvss": max(cvss_vals) if cvss_vals else None,
        "advisory_active_warning_count": active_warning_count,
        "advisory_days_since_first": ((today - first_date).days if first_date else None),
        "advisory_days_since_latest": ((today - latest_date).days if latest_date else None),
        "advisory_span_days": (
            (latest_date - first_date).days if first_date and latest_date else None
        ),
        "advisory_count_last_365d": advisory_count_last_365d,
        "advisory_cvss_ge_7_count": advisory_cvss_ge_7_count,
        "advisory_mean_cvss": (sum(cvss_vals) / len(cvss_vals) if cvss_vals else None),
    }


def _load_healthscore_features(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    hs = _load_healthscore_record(plugin_id, data_raw_dir.resolve())

    if not isinstance(hs, dict):
        return {
            "healthscore_present": False,
            "healthscore_value": None,
            "healthscore_date": None,
            "healthscore_collected_at": None,
        }

    return {
        "healthscore_present": hs.get("value") is not None,
        "healthscore_value": hs.get("value"),
        "healthscore_date": hs.get("date"),
        "healthscore_collected_at": hs.get("collected_at"),
    }


def _load_github_features(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    github_dir = data_raw_dir / "github"
    index_path = github_dir / f"{plugin_id}.github_index.json"
    repo_path = github_dir / f"{plugin_id}.repo.json"
    releases_path = github_dir / f"{plugin_id}.releases.json"
    tags_path = github_dir / f"{plugin_id}.tags.json"
    contributors_path = github_dir / f"{plugin_id}.contributors.json"
    open_issues_path = github_dir / f"{plugin_id}.open_issues.json"
    open_pulls_path = github_dir / f"{plugin_id}.open_pulls.json"
    workflows_path = github_dir / f"{plugin_id}.workflows_dir.json"
    codeowners_path = github_dir / f"{plugin_id}.codeowners.json"
    security_policy_path = github_dir / f"{plugin_id}.security_policy.json"
    dependabot_path = github_dir / f"{plugin_id}.dependabot.json"
    commit_candidates = sorted(github_dir.glob(f"{plugin_id}.commits_*d.json"))

    out: dict[str, Any] = {"github_present": False}
    index = _read_json(index_path) if index_path.exists() else {}
    repo = _read_json(repo_path) if repo_path.exists() else {}
    releases = _read_json(releases_path) if releases_path.exists() else []
    tags = _read_json(tags_path) if tags_path.exists() else []
    contributors = _read_json(contributors_path) if contributors_path.exists() else []
    open_issues = _read_json(open_issues_path) if open_issues_path.exists() else []
    open_pulls = _read_json(open_pulls_path) if open_pulls_path.exists() else []
    workflows = _read_json(workflows_path) if workflows_path.exists() else []

    if any(
        path.exists()
        for path in [index_path, repo_path, releases_path, tags_path, contributors_path]
    ):
        out["github_present"] = True

    out.update(
        {
            "github_repo_full_name": index.get("repo_full_name")
            if isinstance(index, dict)
            else None,
            "github_repo_url": index.get("repo_url") if isinstance(index, dict) else None,
            "github_collected_at": index.get("collected_at") if isinstance(index, dict) else None,
            "github_stargazers_count": repo.get("stargazers_count")
            if isinstance(repo, dict)
            else None,
            "github_forks_count": repo.get("forks_count") if isinstance(repo, dict) else None,
            "github_watchers_count": repo.get("watchers_count") if isinstance(repo, dict) else None,
            "github_open_issues_count_repo": repo.get("open_issues_count")
            if isinstance(repo, dict)
            else None,
            "github_subscribers_count": repo.get("subscribers_count")
            if isinstance(repo, dict)
            else None,
            "github_archived": repo.get("archived") if isinstance(repo, dict) else None,
            "github_default_branch": repo.get("default_branch") if isinstance(repo, dict) else None,
            "github_license_spdx": (
                (repo.get("license") or {}).get("spdx_id")
                if isinstance(repo, dict) and isinstance(repo.get("license"), dict)
                else None
            ),
            "github_releases_count": len(releases) if isinstance(releases, list) else 0,
            "github_latest_release_published_at": (
                max(
                    (
                        str(r.get("published_at") or r.get("created_at") or "")
                        for r in releases
                        if isinstance(r, dict)
                    ),
                    default=None,
                )
                if isinstance(releases, list)
                else None
            ),
            "github_tags_count": len(tags) if isinstance(tags, list) else 0,
            "github_contributors_count": len(contributors) if isinstance(contributors, list) else 0,
            "github_contributors_top_share": None,
            "github_open_issues_count_api": len(open_issues)
            if isinstance(open_issues, list)
            else 0,
            "github_open_pulls_count_api": len(open_pulls) if isinstance(open_pulls, list) else 0,
            "github_workflows_count": len(workflows) if isinstance(workflows, list) else 0,
            "github_has_codeowners": codeowners_path.exists(),
            "github_has_security_policy": security_policy_path.exists(),
            "github_has_dependabot_config": dependabot_path.exists(),
            "github_has_codeql_workflow": (
                any(
                    isinstance(workflow, dict)
                    and "codeql" in str(workflow.get("name") or "").lower()
                    for workflow in workflows
                )
                if isinstance(workflows, list)
                else False
            ),
            "github_commit_windows_present": len(commit_candidates),
            "github_commits_latest_window_days": None,
            "github_commits_latest_window_count": None,
        }
    )

    if isinstance(contributors, list) and contributors:
        counts = [int(c.get("contributions", 0)) for c in contributors if isinstance(c, dict)]
        total = sum(counts)
        if total > 0 and counts:
            out["github_contributors_top_share"] = max(counts) / total

    if commit_candidates:
        latest_path = commit_candidates[-1]
        commits = _read_json(latest_path)
        out["github_commits_latest_window_count"] = len(commits) if isinstance(commits, list) else 0
        name = latest_path.name
        prefix = f"{plugin_id}.commits_"
        if name.startswith(prefix) and name.endswith("d.json"):
            days_str = name[len(prefix) : -len("d.json")]
            try:
                out["github_commits_latest_window_days"] = int(days_str)
            except ValueError:
                out["github_commits_latest_window_days"] = None

    return out


def _parse_iso_datetime_prefix(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _parse_iso_date_prefix(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:10]


def _days_between_iso_dates(start: str | None, end: str | None) -> int | None:
    if not start or not end:
        return None
    try:
        start_dt = datetime.fromisoformat(start[:10])
        end_dt = datetime.fromisoformat(end[:10])
    except ValueError:
        return None
    return (end_dt.date() - start_dt.date()).days


def _extract_swh_visits(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("results", "visits"):
            val = payload.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
    return []


def _snapshot_branch_count(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    branches = payload.get("branches")
    if isinstance(branches, dict):
        return len(branches)
    if isinstance(branches, list):
        return len(branches)
    return 0


def _resolve_swh_backend_dir(
    data_raw_dir: Path,
    backend: str | None = None,
) -> Path:
    if backend == "athena":
        return data_raw_dir / "software_heritage_athena"
    if backend == "api":
        return data_raw_dir / "software_heritage_api"

    athena_dir = data_raw_dir / "software_heritage_athena"
    if athena_dir.exists():
        return athena_dir
    return data_raw_dir / "software_heritage_api"


def _load_software_heritage_features_athena(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    swh_dir = data_raw_dir / "software_heritage_athena"

    index_path = swh_dir / f"{plugin_id}.swh_athena_index.json"
    visits_path = swh_dir / f"{plugin_id}.swh_athena_visits.jsonl"

    row: dict[str, Any] = {
        "swh_present": False,
        "swh_origin_found": False,
        "swh_has_snapshot": False,
        "swh_visit_count": 0,
        "swh_first_visit_date": None,
        "swh_latest_visit_date": None,
        "swh_latest_visit_status": None,
        "swh_latest_visit_type": None,
        "swh_archive_age_days": None,
        "swh_visits_last_365d": 0,
        "swh_snapshot_branch_count": 0,
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
        # revision signals
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
        "swh_backend": "athena",
    }

    if not index_path.exists():
        return row

    row["swh_present"] = True
    index_payload = _read_json(index_path) if index_path.exists() else {}
    visits = _read_jsonl(visits_path) if visits_path.exists() else []

    row["swh_origin_found"] = bool(index_payload.get("record_count", 0) > 0)
    row["swh_has_snapshot"] = bool(visits)

    visit_dates: list[str] = []
    for visit in visits:
        parsed = _parse_iso_date_prefix(visit.get("visit_date"))
        if parsed:
            visit_dates.append(parsed)

    visit_dates = sorted(visit_dates)
    row["swh_visit_count"] = len(visits)
    row["swh_first_visit_date"] = visit_dates[0] if visit_dates else None
    row["swh_latest_visit_date"] = visit_dates[-1] if visit_dates else None
    row["swh_archive_age_days"] = _days_between_iso_dates(
        row["swh_first_visit_date"], row["swh_latest_visit_date"]
    )

    if visit_dates:
        latest = datetime.fromisoformat(visit_dates[-1])
        trailing_start = latest.date().toordinal() - 365
        row["swh_visits_last_365d"] = sum(
            1 for d in visit_dates if datetime.fromisoformat(d).date().toordinal() >= trailing_start
        )

    if visits:
        latest_visit = visits[0]
        row["swh_has_readme"] = bool(latest_visit.get("has_readme"))
        row["swh_has_dot_github"] = bool(latest_visit.get("has_dot_github"))
        row["swh_has_jenkinsfile"] = bool(latest_visit.get("has_jenkinsfile"))
        row["swh_has_travis_yml"] = bool(latest_visit.get("has_travis_yml"))
        row["swh_has_security_md"] = bool(latest_visit.get("has_security_md"))
        row["swh_has_changelog"] = bool(latest_visit.get("has_changelog"))
        row["swh_has_contributing_md"] = bool(latest_visit.get("has_contributing_md"))
        row["swh_has_dockerfile"] = bool(latest_visit.get("has_dockerfile"))
        row["swh_has_pom_xml"] = bool(latest_visit.get("has_pom_xml"))
        row["swh_has_build_gradle"] = bool(latest_visit.get("has_build_gradle"))
        row["swh_has_mvn_wrapper"] = bool(latest_visit.get("has_mvn_wrapper"))
        row["swh_has_tests_directory"] = bool(latest_visit.get("has_tests_directory"))
        row["swh_has_github_actions"] = bool(latest_visit.get("has_github_actions"))
        row["swh_has_dependabot"] = bool(latest_visit.get("has_dependabot"))
        row["swh_has_sonar_config"] = bool(latest_visit.get("has_sonar_config"))
        row["swh_has_snyk_config"] = bool(latest_visit.get("has_snyk_config"))
        row["swh_top_level_entry_count"] = int(latest_visit.get("top_level_entry_count") or 0)
        # revision signals
        row["swh_commit_count"] = int(latest_visit.get("commit_count") or 0)
        row["swh_days_since_last_commit"] = latest_visit.get("days_since_last_commit")
        row["swh_author_committer_lag_p50_hours"] = latest_visit.get(
            "author_committer_lag_p50_hours"
        )
        row["swh_author_committer_lag_p90_hours"] = latest_visit.get(
            "author_committer_lag_p90_hours"
        )
        row["swh_timezone_diversity"] = int(latest_visit.get("timezone_diversity") or 0)
        row["swh_weekend_commit_fraction"] = latest_visit.get("weekend_commit_fraction")
        row["swh_security_fix_commit_count"] = int(
            latest_visit.get("security_fix_commit_count") or 0
        )
        row["swh_merge_commit_fraction"] = latest_visit.get("merge_commit_fraction")
        row["swh_conventional_commit_fraction"] = latest_visit.get("conventional_commit_fraction")
        row["swh_issue_reference_rate"] = latest_visit.get("issue_reference_rate")
        row["swh_empty_message_rate"] = latest_visit.get("empty_message_rate")
        row["swh_author_committer_mismatch_rate"] = latest_visit.get(
            "author_committer_mismatch_rate"
        )
        row["swh_late_night_commit_fraction"] = latest_visit.get("late_night_commit_fraction")

    return row


def _load_software_heritage_features(
    plugin_id: str,
    data_raw_dir: Path,
    backend: str | None = None,
) -> dict[str, Any]:
    resolved = _resolve_swh_backend_dir(data_raw_dir, backend=backend)
    if resolved.name == "software_heritage_athena":
        return _load_software_heritage_features_athena(plugin_id, data_raw_dir)
    return _load_software_heritage_features_api(plugin_id, data_raw_dir)


def _load_software_heritage_features_api(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    swh_dir = data_raw_dir / "software_heritage_api"

    index_path = swh_dir / f"{plugin_id}.swh_index.json"
    origin_path = swh_dir / f"{plugin_id}.swh_origin.json"
    visits_path = swh_dir / f"{plugin_id}.swh_visits.json"
    latest_visit_path = swh_dir / f"{plugin_id}.swh_latest_visit.json"
    snapshot_path = swh_dir / f"{plugin_id}.swh_snapshot.json"

    row: dict[str, Any] = {
        "swh_present": False,
        "swh_origin_found": False,
        "swh_has_snapshot": False,
        "swh_visit_count": 0,
        "swh_first_visit_date": None,
        "swh_latest_visit_date": None,
        "swh_latest_visit_status": None,
        "swh_latest_visit_type": None,
        "swh_archive_age_days": None,
        "swh_visits_last_365d": 0,
        "swh_snapshot_branch_count": 0,
    }

    if not index_path.exists():
        return row

    row["swh_present"] = True
    index_payload = _read_json(index_path) if index_path.exists() else {}
    visits_payload = _read_json(visits_path) if visits_path.exists() else None
    latest_visit_payload = _read_json(latest_visit_path) if latest_visit_path.exists() else None
    snapshot_payload = _read_json(snapshot_path) if snapshot_path.exists() else None

    row["swh_origin_found"] = bool(index_payload.get("origin_found")) or origin_path.exists()
    row["swh_has_snapshot"] = bool(index_payload.get("snapshot_found")) or snapshot_path.exists()

    visits = _extract_swh_visits(visits_payload)
    visit_dates: list[str] = []
    for visit in visits:
        for key in ("date", "visit_date"):
            raw = visit.get(key)
            parsed = _parse_iso_date_prefix(raw)
            if parsed:
                visit_dates.append(parsed)
                break

    visit_dates = sorted(visit_dates)
    row["swh_visit_count"] = len(visits)
    row["swh_first_visit_date"] = visit_dates[0] if visit_dates else None
    row["swh_latest_visit_date"] = visit_dates[-1] if visit_dates else None
    row["swh_archive_age_days"] = _days_between_iso_dates(
        row["swh_first_visit_date"], row["swh_latest_visit_date"]
    )

    if visit_dates:
        latest = datetime.fromisoformat(visit_dates[-1])
        trailing_start = latest.date().toordinal() - 365
        row["swh_visits_last_365d"] = sum(
            1 for d in visit_dates if datetime.fromisoformat(d).date().toordinal() >= trailing_start
        )

    row["swh_snapshot_branch_count"] = _snapshot_branch_count(snapshot_payload)

    if isinstance(latest_visit_payload, dict):
        visit_obj = latest_visit_payload.get("visit")
        if not isinstance(visit_obj, dict):
            visit_obj = latest_visit_payload

        row["swh_latest_visit_status"] = visit_obj.get("status")
        row["swh_latest_visit_type"] = visit_obj.get("type")
        latest_visit_date = _parse_iso_date_prefix(visit_obj.get("date"))
        if latest_visit_date:
            row["swh_latest_visit_date"] = latest_visit_date

    return row


def _load_gharchive_features(plugin_id: str, data_raw_dir: Path) -> dict[str, Any]:
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=data_raw_dir)
    path = data_raw_dir / "gharchive" / "plugins" / f"{plugin_id}.gharchive.jsonl"
    rows = _read_jsonl(path)
    if not rows:
        return {
            "gharchive_present": False,
            "gharchive_window_count": 0,
            "gharchive_sample_percent": None,
            "gharchive_latest_window_end": None,
        }

    latest = max(rows, key=lambda r: str(r.get("window_end_yyyymmdd") or ""))
    out: dict[str, Any] = {
        "gharchive_present": True,
        "gharchive_window_count": len(rows),
        "gharchive_sample_percent": _safe_float(latest.get("sample_percent")),
        "gharchive_latest_window_start": latest.get("window_start_yyyymmdd"),
        "gharchive_latest_window_end": latest.get("window_end_yyyymmdd"),
    }

    for key in GHARCHIVE_NUMERIC_KEYS:
        values = [row.get(key) for row in rows]
        out[f"gharchive_{key}_sum"] = _sum_float(values)
        out[f"gharchive_{key}_mean"] = _mean_float(values)
        out[f"gharchive_{key}_max"] = _max_float(values)
        out[f"gharchive_latest_{key}"] = latest.get(key)

    return out


def _to_csv_scalar(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def build_feature_bundle(
    *,
    data_raw_dir: str | Path = "data/raw",
    registry_path: str | Path = "data/raw/registry/plugins.jsonl",
    out_path: str | Path = "data/processed/features/plugins.features.jsonl",
    out_csv_path: str | Path | None = "data/processed/features/plugins.features.csv",
    summary_path: str | Path | None = "data/processed/features/plugins.features.summary.json",
    software_heritage_backend: str | None = "athena",
) -> list[dict[str, Any]]:
    """Build a unified per-plugin feature bundle from collected CANARY artifacts.

    Reads current raw collectors under data/raw and joins them into one row per plugin.
    The output is intentionally ML-friendly: flat scalar columns with a few provenance/list
    fields preserved as JSON-compatible lists.
    """

    data_raw_dir = Path(data_raw_dir)
    registry_path = Path(registry_path)
    out_path = Path(out_path)
    out_csv = Path(out_csv_path) if out_csv_path is not None else None
    summary = Path(summary_path) if summary_path is not None else None

    registry = _iter_registry_records(registry_path)
    rows: list[dict[str, Any]] = []

    for rec in registry:
        plugin_id = str(rec.get("plugin_id") or "").strip()
        if not plugin_id:
            continue

        row: dict[str, Any] = {
            "plugin_id": plugin_id,
            "registry_collected_at": rec.get("collected_at"),
            "registry_plugin_site_url": rec.get("plugin_site_url"),
            "registry_plugin_api_url": rec.get("plugin_api_url"),
            "registry_title": rec.get("title") or rec.get("plugin_title"),
        }
        row.update(_load_snapshot_features(plugin_id, data_raw_dir))
        row.update(_load_advisory_features(plugin_id, data_raw_dir))
        row.update(_load_healthscore_features(plugin_id, data_raw_dir))
        row.update(
            _load_software_heritage_features(
                plugin_id,
                data_raw_dir,
                software_heritage_backend,
            )
        )
        row.update(_load_github_features(plugin_id, data_raw_dir))
        row.update(_load_gharchive_features(plugin_id, data_raw_dir))
        rows.append(row)

    rows.sort(key=lambda r: str(r.get("plugin_id") or ""))

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
            "out_path": str(out_path),
            "out_csv_path": str(out_csv) if out_csv is not None else None,
            "plugins_total": len(rows),
            "plugins_with_snapshot": sum(1 for r in rows if r.get("snapshot_present")),
            "plugins_with_advisories": sum(1 for r in rows if r.get("advisories_present")),
            "plugins_with_healthscore": sum(1 for r in rows if r.get("healthscore_present")),
            "plugins_with_github": sum(1 for r in rows if r.get("github_present")),
            "plugins_with_gharchive": sum(1 for r in rows if r.get("gharchive_present")),
        }
        summary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    return rows
