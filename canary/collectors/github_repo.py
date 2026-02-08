from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlencode, urlparse

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


def _url_with_params(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    enc = urlencode(params, doseq=True)
    return f"{url}&{enc}" if "?" in url else f"{url}?{enc}"


def _fetch_json_any(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    timeout_s: float = 15.0,
) -> tuple[Any, dict[str, str]]:
    url = _url_with_params(url, params)
    _allowlisted_url(url)
    req = urllib.request.Request(url, headers=_github_headers(), method="GET")
    try:
        # URL is allowlisted above (prevents file:// and custom schemes).
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            data = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(data)
            headers = {k: v for (k, v) in resp.headers.items()}
            return payload, headers
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API request failed ({e.code}) for {url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"GitHub API request failed (network) for {url}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"GitHub API response was not valid JSON for {url}") from e


def _fetch_json(url: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    payload, _headers = _fetch_json_any(url, timeout_s=timeout_s)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected JSON object from GitHub API, got {type(payload)} for {url}")
    return payload


def _parse_link_header(link: str | None) -> dict[str, str]:
    """Parse GitHub Link header into rel->url mapping."""
    if not link:
        return {}
    out: dict[str, str] = {}
    for part in link.split(","):
        segs = [s.strip() for s in part.split(";")]
        if not segs:
            continue
        raw_url = segs[0].strip()
        if raw_url.startswith("<") and raw_url.endswith(">"):
            raw_url = raw_url[1:-1]
        rel = None
        for s in segs[1:]:
            if s.startswith("rel="):
                rel = s.split("=", 1)[1].strip().strip('"')
        if rel:
            out[rel] = raw_url
    return out


def _fetch_all_pages(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    timeout_s: float = 15.0,
    max_pages: int = 10,
) -> list[Any]:
    """Fetch a paginated GitHub list endpoint (best-effort, capped by max_pages)."""
    items: list[Any] = []
    page_url: str | None = url
    page_params = dict(params or {})
    pages = 0
    while page_url and pages < max_pages:
        payload, headers = _fetch_json_any(
            page_url, params=page_params if pages == 0 else None, timeout_s=timeout_s
        )
        if isinstance(payload, list):
            items.extend(payload)
        else:
            # Some endpoints return objects; still return as single-item list.
            items.append(payload)

        links = _parse_link_header(headers.get("Link"))
        page_url = links.get("next")
        pages += 1
    return items


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


def fetch_github_releases(
    owner: str,
    repo: str,
    *,
    per_page: int = 100,
    max_pages: int = 5,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    items = _fetch_all_pages(
        url, params={"per_page": per_page}, max_pages=max_pages, timeout_s=timeout_s
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_tags(
    owner: str,
    repo: str,
    *,
    per_page: int = 100,
    max_pages: int = 5,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    items = _fetch_all_pages(
        url, params={"per_page": per_page}, max_pages=max_pages, timeout_s=timeout_s
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_commits_since(
    owner: str,
    repo: str,
    *,
    since_iso: str,
    per_page: int = 100,
    max_pages: int = 10,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    items = _fetch_all_pages(
        url,
        params={"since": since_iso, "per_page": per_page},
        max_pages=max_pages,
        timeout_s=timeout_s,
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_contributors(
    owner: str,
    repo: str,
    *,
    per_page: int = 100,
    max_pages: int = 3,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contributors"
    items = _fetch_all_pages(
        url,
        params={"per_page": per_page, "anon": "1"},
        max_pages=max_pages,
        timeout_s=timeout_s,
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_open_pulls(
    owner: str,
    repo: str,
    *,
    per_page: int = 100,
    max_pages: int = 3,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
    items = _fetch_all_pages(
        url,
        params={"state": "open", "per_page": per_page},
        max_pages=max_pages,
        timeout_s=timeout_s,
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_open_issues(
    owner: str,
    repo: str,
    *,
    per_page: int = 100,
    max_pages: int = 3,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    """Fetch open issues (includes PRs; filter client-side via 'pull_request' key)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    items = _fetch_all_pages(
        url,
        params={"state": "open", "per_page": per_page},
        max_pages=max_pages,
        timeout_s=timeout_s,
    )
    return [x for x in items if isinstance(x, dict)]


def fetch_github_workflows_dir(
    owner: str,
    repo: str,
    *,
    timeout_s: float = 15.0,
) -> list[dict[str, Any]] | None:
    """Return contents of .github/workflows, or None if not present (404)."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows"
    try:
        payload, _headers = _fetch_json_any(url, timeout_s=timeout_s)
    except RuntimeError as e:
        # Map 404 to "no workflows" without failing the whole snapshot.
        if "(404)" in str(e):
            return None
        raise

    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    return None
