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

        from canary.collectors.github_repo import fetch_github_repo, parse_github_owner_repo

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
        if repo_url:
            parsed = parse_github_owner_repo(repo_url)
            if parsed:
                owner, repo = parsed
                gh = fetch_github_repo(owner, repo)

        snapshot["github_repo"] = gh

        if gh:
            snapshot["github_stars"] = gh.get("stargazers_count")
            snapshot["github_forks"] = gh.get("forks_count")
            snapshot["github_open_issues"] = gh.get("open_issues_count")
            snapshot["github_pushed_at"] = gh.get("pushed_at")

    return snapshot
