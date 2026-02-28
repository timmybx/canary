from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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


def _nonempty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _load_plugin_snapshot(plugin_id: str, *, data_dir: str) -> dict[str, Any]:
    snap_path = Path(data_dir) / "plugins" / f"{plugin_id}.snapshot.json"
    if not snap_path.exists():
        raise FileNotFoundError(
            f"Plugin snapshot not found: {snap_path}. "
            f"Run: canary collect plugin --id {plugin_id} --real"
        )
    return json.loads(snap_path.read_text(encoding="utf-8"))


def _scm_to_url(val: object) -> str | None:
    """Normalize snapshot SCM fields to a URL string.

    The Jenkins plugins API may represent SCM as either:
      - a plain URL string, or
      - an object like {"link": "https://github.com/org/repo", ...}

    This helper returns the URL string (or None if not present/usable).
    """
    if val is None:
        return None
    if isinstance(val, str):
        v = val.strip()
        return v or None
    if isinstance(val, dict):
        link = val.get("link")
        if isinstance(link, str):
            v = link.strip()
            return v or None
    return None


def _infer_repo_url(snapshot: dict[str, Any]) -> str | None:
    # Prefer explicit curated mapping if present
    url = _scm_to_url(snapshot.get("repo_url"))
    if url:
        return url

    # Then SCM URL, if present
    scm = snapshot.get("scm_url")
    url = _scm_to_url(scm)
    if url:
        return url

    # Some snapshots store scm_url as an object with a link field
    if isinstance(scm, dict):
        url = _scm_to_url(scm.get("link") or scm.get("url"))
        if url:
            return url

    # Finally: plugins API field(s), if present
    plugin_api = snapshot.get("plugin_api")
    if isinstance(plugin_api, dict):
        url = _scm_to_url(plugin_api.get("scm"))
        if url:
            return url
        # Sometimes plugin_api.scm is also nested
        scm2 = plugin_api.get("scm")
        if isinstance(scm2, dict):
            url = _scm_to_url(scm2.get("link") or scm2.get("url"))
            if url:
                return url

    return None


def backfill_github_identities_from_indexes(
    *,
    out_dir: str = "data/raw/github",
    overwrite: bool = False,
) -> dict[str, Any]:
    """Backfill plugins/<plugin_id>/identity.json from existing <plugin_id>.github_index.json files.

    This is a **no-API** operation intended to support cases where the enrich pipeline
    skips GitHub collection because prior payloads already exist.

    Returns a summary dict with counts and per-plugin errors.
    """
    out_base = Path(out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "out_dir": str(out_base),
        "processed": 0,
        "written": 0,
        "skipped": 0,
        "errors": {},
    }

    for idx_path in sorted(out_base.glob("*.github_index.json")):
        plugin_id = idx_path.name.split(".github_index.json", 1)[0]
        results["processed"] += 1
        try:
            idx = json.loads(idx_path.read_text(encoding="utf-8"))
            full_name = idx.get("repo_full_name") or idx.get("repo_fullname")
            repo_url = idx.get("repo_url")

            if not isinstance(full_name, str) or "/" not in full_name:
                raise ValueError(f"Missing/invalid repo_full_name in {idx_path.name}")

            owner, repo = full_name.split("/", 1)

            identity_path = out_base / "plugins" / plugin_id / "identity.json"
            if not overwrite and _nonempty(identity_path):
                results["skipped"] += 1
                continue

            identity = {
                "plugin_id": plugin_id,
                "github_full_name": full_name,
                "github_owner": owner,
                "github_repo": repo,
                "repo_url": repo_url,
                "collected_at": idx.get("collected_at"),
                "source_index": str(idx_path),
            }
            _write_json(identity_path, identity)
            results["written"] += 1
        except Exception as e:
            results["errors"][plugin_id] = str(e)

    return results


def collect_github_plugin_real(
    *,
    plugin_id: str,
    data_dir: str = "data/raw",
    out_dir: str = "data/raw/github",
    timeout_s: float = 20.0,
    max_pages: int = 5,
    commits_days: int = 365,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Collect raw GitHub API payloads for a plugin and write them to JSON files.

    This collector is intentionally "raw":
      - It stores unmodified JSON returned by GitHub endpoints
        (or small wrappers with metadata).
      - It is keyed by plugin_id, and expects repo mapping from the plugin snapshot.

    Outputs (default under data/raw/github):
      - <plugin>.github_index.json
      - <plugin>.repo.json
      - <plugin>.releases.json
      - <plugin>.tags.json
      - <plugin>.contributors.json
      - <plugin>.open_issues.json
      - <plugin>.open_pulls.json
      - <plugin>.commits_<days>d.json
      - <plugin>.workflows_dir.json
    """
    snapshot = _load_plugin_snapshot(plugin_id, data_dir=data_dir)
    repo_url = _infer_repo_url(snapshot)
    if not repo_url:
        raise RuntimeError(
            f"No GitHub repo_url/scm_url found for plugin '{plugin_id}' in its snapshot. "
            "Set --repo-url when collecting the snapshot, or curate repo_url in the snapshot."
        )

    parsed = parse_github_owner_repo(repo_url)
    if not parsed:
        raise RuntimeError(
            f"Snapshot repo URL is not a supported GitHub repo URL: {repo_url}. "
            "Expected https://github.com/<owner>/<repo> (optionally .git)"
        )
    owner, repo = parsed
    full_name = f"{owner}/{repo}"

    out_base = Path(out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    def out(name: str) -> Path:
        return out_base / f"{plugin_id}.{name}.json"

    results: dict[str, Any] = {
        "plugin_id": plugin_id,
        "repo_url": repo_url,
        "repo_full_name": full_name,
        "collected_at": datetime.now(UTC).isoformat(),
        "files": {},
        "errors": {},
    }

    # index is always rewritten
    index_path = out_base / f"{plugin_id}.github_index.json"

    # Helper to fetch+write with resume
    def fetch_and_store(key: str, path: Path, fetch_fn) -> None:
        if not overwrite and _nonempty(path):
            results["files"][key] = str(path)
            return
        try:
            payload = fetch_fn()
            _write_json(path, payload)
            results["files"][key] = str(path)
        except Exception as e:
            results["errors"][key] = str(e)

    fetch_and_store(
        "repo", out("repo"), lambda: fetch_github_repo(owner, repo, timeout_s=timeout_s)
    )
    fetch_and_store(
        "releases",
        out("releases"),
        lambda: fetch_github_releases(owner, repo, max_pages=max_pages, timeout_s=timeout_s),
    )
    fetch_and_store(
        "tags",
        out("tags"),
        lambda: fetch_github_tags(owner, repo, max_pages=max_pages, timeout_s=timeout_s),
    )
    fetch_and_store(
        "contributors",
        out("contributors"),
        lambda: fetch_github_contributors(owner, repo, max_pages=max_pages, timeout_s=timeout_s),
    )
    fetch_and_store(
        "open_issues",
        out("open_issues"),
        lambda: fetch_github_open_issues(owner, repo, max_pages=max_pages, timeout_s=timeout_s),
    )
    fetch_and_store(
        "open_pulls",
        out("open_pulls"),
        lambda: fetch_github_open_pulls(owner, repo, max_pages=max_pages, timeout_s=timeout_s),
    )

    # Commits since N days (summary-ish but still raw commit objects from list endpoint)
    commits_key = f"commits_{commits_days}d"
    since_iso = (datetime.now(UTC) - timedelta(days=commits_days)).isoformat()
    fetch_and_store(
        commits_key,
        out(commits_key),
        lambda: fetch_github_commits_since(
            owner,
            repo,
            since_iso=since_iso,
            max_pages=max_pages,
            timeout_s=timeout_s,
        ),
    )

    fetch_and_store(
        "workflows_dir",
        out("workflows_dir"),
        lambda: fetch_github_workflows_dir(owner, repo, timeout_s=timeout_s),
    )

    _write_json(index_path, results)
    results["files"]["index"] = str(index_path)
    return results
