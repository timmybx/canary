from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

_ALLOWED_NETLOCS = {"api.github.com"}


def _allowlisted_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in _ALLOWED_NETLOCS:
        raise ValueError(f"Refusing to fetch unexpected URL: {url}")


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "canary/0.0 (github-repo)",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_json(url: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    _allowlisted_url(url)
    req = urllib.request.Request(url, headers=_github_headers(), method="GET")
    try:
        # URL is allowlisted above (prevents file:// and custom schemes).
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API request failed ({e.code}) for {url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"GitHub API request failed (network) for {url}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"GitHub API response was not valid JSON for {url}") from e


def parse_github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """
    Supports:
      - https://github.com/<owner>/<repo>
      - https://github.com/<owner>/<repo>.git
    """
    try:
        p = urlparse(repo_url)
    except Exception:
        return None

    if p.scheme not in {"http", "https"}:
        return None
    if p.netloc.lower() != "github.com":
        return None

    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def fetch_github_repo(owner: str, repo: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    return _fetch_json(url, timeout_s=timeout_s)
