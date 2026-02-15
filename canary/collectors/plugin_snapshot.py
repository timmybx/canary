# canary/collectors/plugin_snapshot.py
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

_ALLOWED_NETLOCS = {"plugins.jenkins.io"}


def _fetch_plugin_api_json(plugin_id: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    url = f"https://plugins.jenkins.io/api/plugin/{plugin_id}"

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in _ALLOWED_NETLOCS:
        raise ValueError(f"Refusing to fetch unexpected URL: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "canary/0.0 (plugin-snapshot)",
        },
        method="GET",
    )
    try:
        # URL is constructed and allowlisted above (prevents file:// and custom schemes).
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Plugin API request failed ({e.code}) for {url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Plugin API request failed (network) for {url}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Plugin API response was not valid JSON for {url}") from e


def collect_plugin_snapshot(
    *,
    plugin_id: str,
    repo_url: str | None = None,
    real: bool = False,
) -> dict[str, Any]:
    plugin_site_url = f"https://plugins.jenkins.io/{plugin_id}/"

    # v0 curated mapping for pilot plugin
    if repo_url is None and plugin_id == "cucumber-reports":
        repo_url = "https://github.com/jenkinsci/cucumber-reports-plugin"

    advisory_urls: list[str] = []
    if plugin_id == "cucumber-reports":
        advisory_urls.append("https://www.jenkins.io/security/advisory/2016-07-27/")

    snapshot: dict[str, Any] = {
        "plugin_id": plugin_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "plugin_site_url": plugin_site_url,
        "repo_url": repo_url,
        "security_advisory_urls": advisory_urls,
        "plugin_api": None,  # filled only when real=True succeeds
    }

    if real:
        api = _fetch_plugin_api_json(plugin_id)
        # Keep the raw API payload (useful while you’re iterating)
        snapshot["plugin_api"] = api

        from datetime import timedelta

        from canary.collectors.github_repo import (
            fetch_github_commits_since,
            fetch_github_contributors,
            fetch_github_open_issues,
            fetch_github_open_pulls,
            fetch_github_releases,
            fetch_github_repo,
            fetch_github_tags,
            fetch_github_workflows_dir,
            parse_github_owner_repo,
        )

        # Also surface a few stable, high-value fields at top-level
        snapshot["plugin_name"] = api.get("name")
        snapshot["plugin_title"] = api.get("title")
        snapshot["plugin_excerpt"] = api.get("excerpt")
        snapshot["plugin_labels"] = api.get("labels") or []

        # Current release info tends to be useful
        current_release = api.get("currentRelease") or {}
        snapshot["current_version"] = current_release.get("version")
        snapshot["release_timestamp"] = current_release.get("timestamp")

        # Some plugins API responses include wiki/GitHub links; keep if present
        snapshot["wiki_url"] = api.get("wiki")
        snapshot["scm_url"] = api.get("scm")

        # --- GitHub repo metadata (optional, if repo_url is a GitHub repo) ---
        gh = None
        gh_owner_repo: tuple[str, str] | None = None
        if repo_url:
            parsed = parse_github_owner_repo(repo_url)
            if parsed:
                owner, repo = parsed
                gh_owner_repo = (owner, repo)
                try:
                    gh = fetch_github_repo(owner, repo)
                except RuntimeError as e:
                    # GitHub API data is nice-to-have, but should not fail snapshot collection
                    # (e.g. CI rate-limits or missing credentials).
                    snapshot["github_repo_error"] = str(e)

        snapshot["github_repo"] = gh

        if gh:
            snapshot["github_stars"] = gh.get("stargazers_count")
            snapshot["github_forks"] = gh.get("forks_count")
            snapshot["github_open_issues"] = gh.get("open_issues_count")
            snapshot["github_pushed_at"] = gh.get("pushed_at")

        # --- Additional GitHub signals (PoC-friendly summaries) ---
        # Only attempt these if the basic repo fetch succeeded
        # (avoids cascading failures on rate-limit).
        if gh_owner_repo and gh:
            owner, repo = gh_owner_repo

            # Releases + tags (some repos use tags only)
            releases = fetch_github_releases(owner, repo)
            snapshot["github_release_count"] = len(releases)
            snapshot["github_latest_release"] = (
                {
                    "tag_name": releases[0].get("tag_name"),
                    "name": releases[0].get("name"),
                    "published_at": releases[0].get("published_at"),
                    "prerelease": releases[0].get("prerelease"),
                    "draft": releases[0].get("draft"),
                }
                if releases
                else None
            )

            tags = fetch_github_tags(owner, repo)
            snapshot["github_tag_count_sampled"] = len(tags)

            # Commit cadence in simple time windows
            now = datetime.now(UTC)
            windows = [30, 90, 365]
            commit_counts: dict[str, int] = {}
            for days in windows:
                since = (now - timedelta(days=days)).isoformat()
                commits = fetch_github_commits_since(owner, repo, since_iso=since)
                commit_counts[f"commits_{days}d"] = len(commits)
            snapshot["github_commit_counts"] = commit_counts

            # Contributors (bus factor-ish proxy)
            contributors = fetch_github_contributors(owner, repo)
            contrib_counts = [c.get("contributions", 0) for c in contributors]
            total = sum(contrib_counts) if contrib_counts else 0
            snapshot["github_contributors_top_sampled"] = len(contributors)
            snapshot["github_top_contributor_share"] = (
                (max(contrib_counts) / total) if total else None
            )

            # Issues vs PRs split
            open_prs = fetch_github_open_pulls(owner, repo)
            open_items = fetch_github_open_issues(owner, repo)
            open_issues_only = [i for i in open_items if "pull_request" not in i]
            snapshot["github_open_prs"] = len(open_prs)
            snapshot["github_open_issues_only"] = len(open_issues_only)

            # CI workflows presence
            workflows = fetch_github_workflows_dir(owner, repo)
            snapshot["github_has_ci_workflows"] = bool(workflows)
            snapshot["github_ci_workflow_count"] = len(workflows) if workflows else 0

    return snapshot
