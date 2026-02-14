from __future__ import annotations

import argparse
import csv
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
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
    rows = collect_repo_features(session, repos, include_scorecard=not args.skip_scorecard)
    write_csv(rows, args.out)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
