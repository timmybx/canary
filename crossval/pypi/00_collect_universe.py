"""
crossval/pypi/00_collect_universe.py
======================================
Build the PyPI package universe for the cross-validation study.

Strategy
--------
1. Download the top-N PyPI packages by monthly downloads from
   https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json
   (published monthly, covers the top ~8,000 packages)

2. For each package, fetch the PyPI JSON API
   (https://pypi.org/pypi/{package}/json) and extract a GitHub repository URL
   from the project_urls and home_page metadata fields.

3. Write only packages with a resolvable GitHub URL to the universe file.
   The "has GitHub URL" criterion is a data-availability filter, not a
   risk filter, so it does not introduce selection bias on the outcome
   variable (advisory history).

Usage
-----
    python crossval/pypi/00_collect_universe.py [--top N] [--delay SECS]

    --top   N       Number of top packages to process (default: 8000)
    --delay SECS    Seconds to sleep between PyPI API calls (default: 0.15)

Output
------
    data/pypi/raw/package_universe.jsonl
        One record per package that has a resolvable GitHub URL.
        Fields: package_id, github_owner, github_repo, github_url,
                downloads_rank, monthly_downloads

    data/pypi/raw/package_universe_skipped.jsonl
        Packages that could not be resolved (no GitHub URL, fetch error, etc.)
        Useful for auditing coverage.

Notes
-----
- Progress is saved incrementally every 100 packages so the script can
  be safely interrupted and re-run; already-fetched packages are skipped.
- The PyPI JSON API has no published rate limit but requests should be
  polite. The default 0.15 s delay processes 8,000 packages in ~20 min.
- GitHub URLs are normalised to owner/repo form, stripping .git suffixes,
  issue tracker paths, and similar noise.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"

OUT_PATH = Path("data/pypi/raw/package_universe.jsonl")
SKIPPED_PATH = Path("data/pypi/raw/package_universe_skipped.jsonl")
DEFAULT_TOP_N = 8000
DEFAULT_DELAY_S = 0.15
SAVE_INTERVAL = 100  # write progress every N packages
REQUEST_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# GitHub URL extraction
# ---------------------------------------------------------------------------

_GITHUB_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


def _extract_github_owner_repo(text: str) -> tuple[str, str] | None:
    """
    Return (owner, repo) from the first github.com URL found in *text*,
    stripping .git suffixes and path noise (e.g. /tree/main, /issues).
    Returns None if no GitHub URL is found.
    """
    m = _GITHUB_RE.search(text)
    if not m:
        return None
    owner = m.group(1)
    repo = m.group(2).rstrip("/")
    # Strip common suffixes that are not part of the repo name
    for suffix in (".git", "/issues", "/pulls", "/tree", "/blob", "/actions"):
        if repo.endswith(suffix):
            repo = repo[: -len(suffix)]
    repo = repo.rstrip("/")
    if not owner or not repo:
        return None
    return (owner, repo)


def _find_github_url(info: dict[str, Any]) -> tuple[str, str] | None:
    """
    Search PyPI package info dict for a GitHub URL.
    Checks project_urls values first (most reliable), then home_page.
    """
    # 1. project_urls — try all values, prefer "Source" > "Homepage" > others
    project_urls: dict[str, str] = info.get("project_urls") or {}
    priority_keys = [
        "Source",
        "source",
        "Source Code",
        "source_code",
        "Repository",
        "repository",
        "Code",
        "code",
        "Homepage",
        "homepage",
        "Home",
        "home",
    ]
    checked: list[str] = []
    for key in priority_keys:
        url = project_urls.get(key, "")
        if url and "github.com" in url.lower():
            result = _extract_github_owner_repo(url)
            if result:
                return result
        if url:
            checked.append(url)

    # Try all remaining project_urls values
    for key, url in project_urls.items():
        if key not in priority_keys and url and "github.com" in url.lower():
            result = _extract_github_owner_repo(url)
            if result:
                return result

    # 2. home_page field
    home = info.get("home_page") or ""
    if "github.com" in home.lower():
        result = _extract_github_owner_repo(home)
        if result:
            return result

    return None


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _normalise_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _fetch_json(url: str, *, timeout: float = REQUEST_TIMEOUT) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "canary-crossval/0.1 (pypi-universe)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Progress / resume helpers
# ---------------------------------------------------------------------------


def _load_existing(path: Path) -> set[str]:
    """Return package_ids already written to *path*."""
    if not path.exists():
        return set()
    seen: set[str] = set()
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    seen.add(json.loads(line)["package_id"])
                except (json.JSONDecodeError, KeyError):
                    pass
    return seen


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(top_n: int, delay_s: float) -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Resume support: load already-processed packages
    already_done = _load_existing(OUT_PATH) | _load_existing(SKIPPED_PATH)
    print(f"Already processed: {len(already_done):,} packages (will skip)")

    # Step 1: Download ranked package list
    print(f"\nFetching top-{top_n} package list from hugovk ...")
    data = _fetch_json(TOP_PACKAGES_URL)
    rows = data.get("rows", [])
    if not rows:
        raise RuntimeError("Unexpected response format from top-packages endpoint")

    # rows is a list of {"project": "name", "download_count": N}
    ranked = [
        (_normalise_package(r["project"]), int(r.get("download_count", 0)))
        for r in rows
        if r.get("project")
    ]
    ranked = ranked[:top_n]
    print(f"  {len(ranked):,} packages in ranked list")

    to_process = [(pkg, cnt) for pkg, cnt in ranked if pkg not in already_done]
    print(f"  {len(to_process):,} packages to fetch")

    # Step 2: Fetch PyPI JSON for each package and extract GitHub URL
    found = 0
    skipped = 0
    errors = 0
    buffer_found: list[dict[str, Any]] = []
    buffer_skipped: list[dict[str, Any]] = []

    def _flush() -> None:
        if buffer_found:
            with OUT_PATH.open("a", encoding="utf-8") as f:
                for rec in buffer_found:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            buffer_found.clear()
        if buffer_skipped:
            with SKIPPED_PATH.open("a", encoding="utf-8") as f:
                for rec in buffer_skipped:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            buffer_skipped.clear()

    for idx, (pkg, downloads) in enumerate(to_process, start=1):
        url = PYPI_JSON_URL.format(package=pkg)
        try:
            pypi_data = _fetch_json(url)
            info = pypi_data.get("info") or {}
            github = _find_github_url(info)

            rank = next((i + 1 for i, (p, _) in enumerate(ranked) if p == pkg), None)

            if github:
                owner, repo = github
                buffer_found.append(
                    {
                        "package_id": pkg,
                        "github_owner": owner,
                        "github_repo": repo,
                        "github_url": f"https://github.com/{owner}/{repo}",
                        "downloads_rank": rank,
                        "monthly_downloads": downloads,
                    }
                )
                found += 1
            else:
                buffer_skipped.append(
                    {
                        "package_id": pkg,
                        "reason": "no_github_url",
                        "downloads_rank": rank,
                        "monthly_downloads": downloads,
                    }
                )
                skipped += 1

        except urllib.error.HTTPError as e:
            if e.code == 404:
                buffer_skipped.append(
                    {
                        "package_id": pkg,
                        "reason": "pypi_404",
                    }
                )
                skipped += 1
            else:
                print(f"  [WARN] {pkg}: HTTP {e.code} — skipping")
                buffer_skipped.append({"package_id": pkg, "reason": f"http_{e.code}"})
                errors += 1
        except Exception as e:
            print(f"  [WARN] {pkg}: {type(e).__name__}: {e} — skipping")
            buffer_skipped.append({"package_id": pkg, "reason": f"error_{type(e).__name__}"})
            errors += 1

        # Progress reporting and incremental save
        if idx % SAVE_INTERVAL == 0:
            _flush()
            pct = idx / len(to_process) * 100
            print(
                f"  [{idx:>5}/{len(to_process)}  {pct:5.1f}%]  "
                f"found={found}  no_url={skipped}  errors={errors}"
            )
        else:
            time.sleep(delay_s)

    _flush()

    # Final summary
    total_found = len(_load_existing(OUT_PATH))
    print("\nDone.")
    print(f"  Packages with GitHub URL : {total_found:,}")
    print(f"  No GitHub URL found      : {skipped:,}")
    print(f"  Fetch errors             : {errors:,}")
    coverage = total_found / len(ranked) * 100 if ranked else 0
    print(f"  Coverage                 : {coverage:.1f}% of top-{len(ranked)} packages")
    print(f"  Universe output          : {OUT_PATH}")
    print(f"  Skipped log              : {SKIPPED_PATH}")
    print("\nNext step: run 01_collect_osv.py (if not done), then 02_build_monthly.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build PyPI package universe")
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"Number of top packages to process (default: {DEFAULT_TOP_N})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_S,
        help=f"Seconds between PyPI API calls (default: {DEFAULT_DELAY_S})",
    )
    args = parser.parse_args()
    main(top_n=args.top, delay_s=args.delay)
