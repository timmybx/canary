"""Supporting services for the CANARY web console.

Extracted move-only from canary/webapp.py; behavior is unchanged.
"""

from __future__ import annotations

import collections
import json
import logging
import re
import threading
from pathlib import Path
from typing import Any

# Keep the historical logger name so existing log filtering/config still applies.
logger = logging.getLogger("canary.webapp")


_EXPLAIN_RATE_LIMIT_LOCK = threading.Lock()

_EXPLAIN_RATE_LIMIT: dict[str, list[float]] = collections.defaultdict(list)

_EXPLAIN_RATE_WINDOW = 3600  # 1 hour window

_EXPLAIN_RATE_MAX = 3  # max requests per IP per window


def _load_registry_plugin_choices_cached(registry_path: str, mtime_ns: int) -> tuple[str, ...]:
    path = Path(registry_path)
    plugin_ids: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugin_id = str(record.get("plugin_id") or "").strip()
            if plugin_id:
                plugin_ids.append(plugin_id)
    return tuple(sorted(set(plugin_ids)))


def _load_plugin_choices(registry_path: str) -> list[str]:
    path = Path(registry_path)
    if not path.exists() or not path.is_file():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    return list(_load_registry_plugin_choices_cached(str(path.resolve()), stat.st_mtime_ns))


def _fetch_live_commit_date(plugin_id: str) -> str | None:
    """
    Fetch the most recent commit date for a Jenkins plugin from the GitHub API.

    Jenkins plugins follow the naming convention:
        https://github.com/jenkinsci/{plugin_id}-plugin

    Falls back gracefully — returns None if the repo cannot be found or the
    API call fails for any reason (network error, rate limit, non-standard repo).
    The result is used only to enrich the supporting signals display; a failure
    here never blocks scoring.
    """
    import urllib.parse
    import urllib.request

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", plugin_id):
        return None

    def _read_commit_date(api_url: str) -> str | None:
        from datetime import datetime

        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise ValueError("Refusing to call non-allowlisted GitHub API URL.")

        req = urllib.request.Request(
            api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "CANARY-score/1.0 (https://canary-score.com)",
            },
        )
        with urllib.request.urlopen(req, timeout=4) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            return None

        commit = data[0].get("commit", {})
        if not isinstance(commit, dict):
            return None
        author = commit.get("author", {})
        committer = commit.get("committer", {})
        raw = ""
        if isinstance(author, dict):
            raw = str(author.get("date", "") or "")
        if not raw and isinstance(committer, dict):
            raw = str(committer.get("date", "") or "")
        if not raw:
            return None

        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return f"{dt:%B} {dt.day}, {dt:%Y}"

    for repo_name in (f"{plugin_id}-plugin", plugin_id):
        try:
            return _read_commit_date(
                f"https://api.github.com/repos/jenkinsci/{repo_name}/commits?per_page=1"
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.debug("Live GitHub commit lookup failed for %s: %s", repo_name, exc)

    return None


def _inject_live_commit_signal(
    score_result: dict[str, Any],
    plugin_id: str,
) -> dict[str, Any]:
    """
    Replace any stale "commit activity" reason with a live GitHub commit date.

    Looks for reasons that contain commit-recency language (e.g. "4 days ago")
    and replaces them with a fresh "Last commit: May 20, 2026" line fetched
    directly from the GitHub API.  If the fetch fails the original reasons
    are returned unchanged.
    """
    live_date = _fetch_live_commit_date(plugin_id)
    if not live_date:
        return score_result

    # Replace the stale commit recency reason
    import re as _re

    _stale_pattern = _re.compile(
        r"recent commit activity.*?suggests",
        _re.IGNORECASE,
    )
    new_reasons: list[str] = []
    replaced = False
    for reason in score_result.get("reasons", []):
        if _stale_pattern.search(reason) and not replaced:
            new_reasons.append(f"Last commit: {live_date} — live data from GitHub.")
            replaced = True
        else:
            new_reasons.append(reason)

    # If no stale reason was found but we have a live date, prepend it
    if not replaced:
        new_reasons = [f"Last commit: {live_date} — live data from GitHub."] + new_reasons

    result = dict(score_result)
    result["reasons"] = new_reasons
    return result
