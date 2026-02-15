from __future__ import annotations

import argparse
import csv
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import requests  # pyright: ignore[reportMissingModuleSource]


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


def _github_session() -> requests.Session:
    sess = requests.Session()
    sess.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "User-Agent": "canary/0.1 (github-repo-features)",
        }
    )
    token = os.getenv("GITHUB_TOKEN")
    if token:
        sess.headers["Authorization"] = f"Bearer {token}"
    return sess


def _get_json(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None = None,
    *,
    allow_statuses: set[int] | None = None,
) -> Any:
    resp = session.get(url, params=params, timeout=20)
    allow_statuses = allow_statuses or set()
    if resp.status_code in allow_statuses:
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
        reset = resp.headers.get("X-RateLimit-Reset", "unknown")
        reset_msg = str(reset)
        try:
            reset_epoch = int(str(reset))
            reset_dt = datetime.fromtimestamp(reset_epoch, tz=UTC)
            reset_msg = f"{reset} ({reset_dt.isoformat()})"
        except (TypeError, ValueError, OSError):
            reset_msg = str(reset)
        raise RuntimeError(
            "GitHub API rate limit exceeded. "
            f"X-RateLimit-Reset={reset_msg}. "
            "Set GITHUB_TOKEN to increase limits."
        )
    resp.raise_for_status()
    return resp.json()


def _get_json_list(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None = None,
    *,
    allow_statuses: set[int] | None = None,
) -> list[dict[str, Any]] | None:
    data = _get_json(session, url, params=params, allow_statuses=allow_statuses)
    if data is None:
        return None
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return None


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(value: str | None) -> int | None:
    dt = _parse_iso8601(value)
    if dt is None:
        return None
    now = datetime.now(UTC)
    return (now - dt.astimezone(UTC)).days


def _path_exists(session: requests.Session, repo: RepoRef, path: str) -> bool:
    url = f"https://api.github.com/repos/{repo.full_name}/contents/{path}"
    data = _get_json(session, url)
    return data is not None


def _security_policy_present(session: requests.Session, repo: RepoRef) -> bool:
    candidates = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
    return any(_path_exists(session, repo, p) for p in candidates)


def _codeowners_present(session: requests.Session, repo: RepoRef) -> bool:
    candidates = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
    return any(_path_exists(session, repo, p) for p in candidates)


def _workflows_present(session: requests.Session, repo: RepoRef) -> bool:
    url = f"https://api.github.com/repos/{repo.full_name}/contents/.github/workflows"
    data = _get_json(session, url)
    return isinstance(data, list) and len(data) > 0


def _scorecard_project_url(repo: RepoRef) -> str:
    return f"https://api.scorecard.dev/projects/github.com/{repo.full_name}"


def _fetch_scorecard(repo: RepoRef, *, timeout_s: float = 20.0) -> dict[str, Any] | None:
    url = _scorecard_project_url(repo)
    try:
        resp = requests.get(url, timeout=timeout_s)
    except requests.RequestException:
        return None
    if resp.status_code >= 400:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _scorecard_check_map(payload: dict[str, Any] | None) -> dict[str, float]:
    if not payload:
        return {}
    checks = payload.get("checks")
    if not isinstance(checks, list):
        return {}
    out: dict[str, float] = {}
    for check in checks:
        if not isinstance(check, dict):
            continue
        name = check.get("name")
        score = check.get("score")
        if isinstance(name, str) and isinstance(score, (int, float)):
            out[name] = float(score)
    return out


def _as_float_or_none(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _dependabot_alert_metrics(
    session: requests.Session,
    repo: RepoRef,
) -> dict[str, Any]:
    # Endpoint often requires authenticated access and may be unavailable for some repos.
    url = f"https://api.github.com/repos/{repo.full_name}/dependabot/alerts"
    alerts = _get_json_list(
        session,
        url,
        params={"state": "open", "per_page": 100},
        allow_statuses={401, 403, 404},
    )
    if alerts is None:
        return {
            "dependabot_alerts_visible": False,
            "dependabot_open_alerts": None,
            "dependabot_open_alerts_critical": None,
            "dependabot_open_alerts_high": None,
            "dependabot_open_alerts_medium": None,
            "dependabot_open_alerts_low": None,
            "dependabot_open_alerts_unknown": None,
        }

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for alert in alerts:
        sec_adv = alert.get("security_advisory")
        sev = None
        if isinstance(sec_adv, dict):
            v = sec_adv.get("severity")
            if isinstance(v, str):
                sev = v.lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["unknown"] += 1

    return {
        "dependabot_alerts_visible": True,
        "dependabot_open_alerts": len(alerts),
        "dependabot_open_alerts_critical": sev_counts["critical"],
        "dependabot_open_alerts_high": sev_counts["high"],
        "dependabot_open_alerts_medium": sev_counts["medium"],
        "dependabot_open_alerts_low": sev_counts["low"],
        "dependabot_open_alerts_unknown": sev_counts["unknown"],
    }


def _code_scanning_alert_metrics(
    session: requests.Session,
    repo: RepoRef,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo.full_name}/code-scanning/alerts"
    alerts = _get_json_list(
        session,
        url,
        params={"state": "open", "per_page": 100},
        allow_statuses={401, 403, 404},
    )
    if alerts is None:
        return {
            "code_scanning_alerts_visible": False,
            "code_scanning_open_alerts": None,
            "code_scanning_open_alerts_error": None,
            "code_scanning_open_alerts_warning": None,
            "code_scanning_open_alerts_note": None,
            "code_scanning_open_alerts_unknown": None,
        }

    sev_counts = {"error": 0, "warning": 0, "note": 0, "unknown": 0}
    for alert in alerts:
        rule = alert.get("rule")
        sev = None
        if isinstance(rule, dict):
            v = rule.get("severity")
            if isinstance(v, str):
                sev = v.lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["unknown"] += 1

    return {
        "code_scanning_alerts_visible": True,
        "code_scanning_open_alerts": len(alerts),
        "code_scanning_open_alerts_error": sev_counts["error"],
        "code_scanning_open_alerts_warning": sev_counts["warning"],
        "code_scanning_open_alerts_note": sev_counts["note"],
        "code_scanning_open_alerts_unknown": sev_counts["unknown"],
    }


def _repository_security_advisory_metrics(
    session: requests.Session,
    repo: RepoRef,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo.full_name}/security-advisories"
    advisories = _get_json_list(
        session,
        url,
        params={"per_page": 100},
        allow_statuses={401, 403, 404},
    )
    if advisories is None:
        return {
            "repo_security_advisories_visible": False,
            "repo_security_advisories_total": None,
            "repo_security_advisories_published_30d": None,
            "repo_security_advisories_critical": None,
            "repo_security_advisories_high": None,
            "repo_security_advisories_medium": None,
            "repo_security_advisories_low": None,
            "repo_security_advisories_unknown": None,
            "repo_security_advisories_cvss_max": None,
            "repo_security_advisories_cvss_avg": None,
        }

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    cvss_scores: list[float] = []
    cutoff_30d = datetime.now(UTC) - timedelta(days=30)
    published_30d = 0

    for advisory in advisories:
        sev_raw = advisory.get("severity")
        sev = sev_raw.lower() if isinstance(sev_raw, str) else "unknown"
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["unknown"] += 1

        published_at = _parse_iso8601(advisory.get("published_at"))
        if published_at and published_at.astimezone(UTC) >= cutoff_30d:
            published_30d += 1

        cvss = advisory.get("cvss")
        if isinstance(cvss, dict):
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                cvss_scores.append(float(score))

    cvss_max = max(cvss_scores) if cvss_scores else None
    cvss_avg = (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else None

    return {
        "repo_security_advisories_visible": True,
        "repo_security_advisories_total": len(advisories),
        "repo_security_advisories_published_30d": published_30d,
        "repo_security_advisories_critical": sev_counts["critical"],
        "repo_security_advisories_high": sev_counts["high"],
        "repo_security_advisories_medium": sev_counts["medium"],
        "repo_security_advisories_low": sev_counts["low"],
        "repo_security_advisories_unknown": sev_counts["unknown"],
        "repo_security_advisories_cvss_max": cvss_max,
        "repo_security_advisories_cvss_avg": cvss_avg,
    }


def list_repos_for_org(
    session: requests.Session,
    org: str,
    *,
    name_suffix: str,
    max_repos: int,
    include_archived: bool,
) -> list[RepoRef]:
    repos: list[RepoRef] = []
    page = 1
    per_page = 100
    while len(repos) < max_repos:
        url = f"https://api.github.com/orgs/{org}/repos"
        batch = _get_json(
            session,
            url,
            params={"type": "public", "sort": "pushed", "per_page": per_page, "page": page},
        )
        if not isinstance(batch, list) or not batch:
            break
        for item in batch:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            archived = bool(item.get("archived"))
            if not name.endswith(name_suffix):
                continue
            if archived and not include_archived:
                continue
            repos.append(RepoRef(owner=org, name=name))
            if len(repos) >= max_repos:
                break
        page += 1
    return repos


def collect_repo_features(
    session: requests.Session,
    repos: list[RepoRef],
    *,
    include_scorecard: bool,
    include_alerts: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for repo in repos:
        repo_api = f"https://api.github.com/repos/{repo.full_name}"
        meta = _get_json(session, repo_api)
        if not isinstance(meta, dict):
            continue

        default_branch = str(meta.get("default_branch") or "main")
        latest_release = _get_json(session, f"{repo_api}/releases/latest")
        latest_release_published_at = (
            latest_release.get("published_at") if isinstance(latest_release, dict) else None
        )
        scorecard = _fetch_scorecard(repo) if include_scorecard else None
        scorecard_checks = _scorecard_check_map(scorecard)
        dependabot_metrics = _dependabot_alert_metrics(session, repo) if include_alerts else {}
        code_scan_metrics = _code_scanning_alert_metrics(session, repo) if include_alerts else {}
        repo_adv_metrics = (
            _repository_security_advisory_metrics(session, repo) if include_alerts else {}
        )
        row = {
            "repo": repo.full_name,
            "stars": int(meta.get("stargazers_count") or 0),
            "forks": int(meta.get("forks_count") or 0),
            "watchers": int(meta.get("subscribers_count") or 0),
            "open_issues_count": int(meta.get("open_issues_count") or 0),
            "topics_count": len(meta.get("topics") or []),
            "default_branch": default_branch,
            "archived": bool(meta.get("archived")),
            "days_since_last_push": _days_since(meta.get("pushed_at")),
            "days_since_last_release": _days_since(latest_release_published_at),
            "dependabot_config_present": _path_exists(session, repo, ".github/dependabot.yml"),
            "codeql_workflow_present": _path_exists(session, repo, ".github/workflows/codeql.yml"),
            "codeowners_present": _codeowners_present(session, repo),
            "security_policy_present": _security_policy_present(session, repo),
            "workflows_present": _workflows_present(session, repo),
            "scorecard_overall": _as_float_or_none(scorecard.get("score") if scorecard else None),
            "scorecard_branch_protection": scorecard_checks.get("Branch-Protection"),
            "scorecard_pinned_dependencies": scorecard_checks.get("Pinned-Dependencies"),
            "scorecard_token_permissions": scorecard_checks.get("Token-Permissions"),
            "scorecard_dangerous_workflow": scorecard_checks.get("Dangerous-Workflow"),
            "scorecard_maintained": scorecard_checks.get("Maintained"),
        }
        row.update(
            {
                "dependabot_alerts_visible": False,
                "dependabot_open_alerts": None,
                "dependabot_open_alerts_critical": None,
                "dependabot_open_alerts_high": None,
                "dependabot_open_alerts_medium": None,
                "dependabot_open_alerts_low": None,
                "dependabot_open_alerts_unknown": None,
                "code_scanning_alerts_visible": False,
                "code_scanning_open_alerts": None,
                "code_scanning_open_alerts_error": None,
                "code_scanning_open_alerts_warning": None,
                "code_scanning_open_alerts_note": None,
                "code_scanning_open_alerts_unknown": None,
                "repo_security_advisories_visible": False,
                "repo_security_advisories_total": None,
                "repo_security_advisories_published_30d": None,
                "repo_security_advisories_critical": None,
                "repo_security_advisories_high": None,
                "repo_security_advisories_medium": None,
                "repo_security_advisories_low": None,
                "repo_security_advisories_unknown": None,
                "repo_security_advisories_cvss_max": None,
                "repo_security_advisories_cvss_avg": None,
            }
        )
        row.update(dependabot_metrics)
        row.update(code_scan_metrics)
        row.update(repo_adv_metrics)
        rows.append(row)
    return rows


def write_csv(rows: list[dict[str, Any]], out_path: str) -> None:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "repo",
        "stars",
        "forks",
        "watchers",
        "open_issues_count",
        "topics_count",
        "default_branch",
        "archived",
        "days_since_last_push",
        "days_since_last_release",
        "dependabot_config_present",
        "codeql_workflow_present",
        "codeowners_present",
        "security_policy_present",
        "workflows_present",
        "scorecard_overall",
        "scorecard_branch_protection",
        "scorecard_pinned_dependencies",
        "scorecard_token_permissions",
        "scorecard_dangerous_workflow",
        "scorecard_maintained",
        "dependabot_alerts_visible",
        "dependabot_open_alerts",
        "dependabot_open_alerts_critical",
        "dependabot_open_alerts_high",
        "dependabot_open_alerts_medium",
        "dependabot_open_alerts_low",
        "dependabot_open_alerts_unknown",
        "code_scanning_alerts_visible",
        "code_scanning_open_alerts",
        "code_scanning_open_alerts_error",
        "code_scanning_open_alerts_warning",
        "code_scanning_open_alerts_note",
        "code_scanning_open_alerts_unknown",
        "repo_security_advisories_visible",
        "repo_security_advisories_total",
        "repo_security_advisories_published_30d",
        "repo_security_advisories_critical",
        "repo_security_advisories_high",
        "repo_security_advisories_medium",
        "repo_security_advisories_low",
        "repo_security_advisories_unknown",
        "repo_security_advisories_cvss_max",
        "repo_security_advisories_cvss_avg",
    ]
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect GitHub repo-level security/process features for Jenkins plugins."
    )
    parser.add_argument("--org", default="jenkinsci", help="GitHub org to scan.")
    parser.add_argument(
        "--repo-suffix",
        default="-plugin",
        help="Include repos whose names end with this suffix.",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=10,
        help="Maximum repos to fetch from the org after filtering.",
    )
    parser.add_argument(
        "--include-archived",
        action="store_true",
        help="Include archived repos in output.",
    )
    parser.add_argument(
        "--out",
        default="data/processed/github_repo_features.csv",
        help="Output CSV path.",
    )
    parser.add_argument(
        "--skip-scorecard",
        action="store_true",
        help="Skip OpenSSF Scorecard API enrichment fields.",
    )
    parser.add_argument(
        "--include-alerts",
        action="store_true",
        help="Include Dependabot and code-scanning alert metrics (best-effort).",
    )
    args = parser.parse_args()
    has_token = bool(os.getenv("GITHUB_TOKEN"))
    if not has_token and args.max_repos > 10:
        print(
            "No GITHUB_TOKEN detected; capping --max-repos to 10 to reduce rate-limit failures.",
            file=sys.stderr,
        )
        args.max_repos = 10

    session = _github_session()
    repos = list_repos_for_org(
        session,
        args.org,
        name_suffix=args.repo_suffix,
        max_repos=args.max_repos,
        include_archived=args.include_archived,
    )
    rows = collect_repo_features(
        session,
        repos,
        include_scorecard=not args.skip_scorecard,
        include_alerts=args.include_alerts,
    )
    write_csv(rows, args.out)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
