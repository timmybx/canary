"""Survivorship audit: advisories naming plugins outside the 2026 registry snapshot.

The CANARY panel uses a single registry snapshot (data/raw/registry/plugins.jsonl,
2,053 plugins, collected 2026-02-28) observed at every month of the study period.
Plugins delisted or suspended before that date are therefore outside the sampling
frame, and any advisories they received are positives the model never sees.

This tool bounds that gap. It reads the public Jenkins security advisory archive,
extracts the plugins each advisory names, and counts advisory/plugin pairs whose
plugin is not in the snapshot. It also cross-checks against the Update Center
warnings feed, which is the machine-readable list of plugin security warnings.

Usage (from the repository root):

    python tools/survivorship_audit.py
    python tools/survivorship_audit.py --start 2018-01-01 --end 2026-06-30

Outputs:
    data/processed/results/survivorship_audit.json   summary + per-plugin detail
    data/processed/results/survivorship_audit_pairs.csv   every (advisory, plugin) pair

Network: fetches only https://www.jenkins.io and https://updates.jenkins.io.
Advisory pages are cached under data/cache/advisory_pages/ so reruns are offline.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_NETLOCS = {"www.jenkins.io", "jenkins.io", "updates.jenkins.io"}
INDEX_URL = "https://www.jenkins.io/security/advisories/"
UC_URL = "https://updates.jenkins.io/update-center.actual.json"
USER_AGENT = "canary-survivorship-audit/1.0 (+https://github.com/timmybx/canary)"

ADVISORY_PATH_RE = re.compile(r"/security/advisory/(\d{4}-\d{2}-\d{2})(?:-(\d{3}))?/?")
PLUGIN_LINK_RE = re.compile(r"https?://plugins\.jenkins\.io/([A-Za-z0-9_.\-]+)/?(?:[\"'#?\s<]|$)")
WIKI_LINK_RE = re.compile(r"https?://wiki\.jenkins(?:-ci)?\.io/display/JENKINS/([A-Za-z0-9_.+\-]+)")
SECURITY_ID_RE = re.compile(r"SECURITY-\d+")


def _fetch(url: str, *, timeout_s: float = 30.0) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in ALLOWED_NETLOCS:
        raise ValueError(f"Refusing to fetch unexpected URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310 (allowlisted)
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"fetch failed after retries: {url} ({last_err})")


KEY_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:-\d{3})?$")


def _advisory_date(url_or_key: str) -> date | None:
    """Date from a full advisory URL/path or from a bare key such as 2025-01-29-001."""
    m = ADVISORY_PATH_RE.search(url_or_key) or KEY_RE.match(url_or_key.strip())
    if not m:
        return None
    y, mo, d = (int(x) for x in m.group(1).split("-"))
    try:
        return date(y, mo, d)
    except ValueError:
        return None


def _advisory_key(url: str) -> str:
    m = ADVISORY_PATH_RE.search(url)
    return m.group(0).strip("/").split("/")[-1] if m else url


def load_frame(registry_path: Path) -> set[str]:
    ids: set[str] = set()
    with registry_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            pid = rec.get("plugin_id") or rec.get("plugin_name")
            if pid:
                ids.add(str(pid).strip().lower())
    return ids


def list_advisories(cache_dir: Path) -> list[str]:
    html = _fetch(INDEX_URL)
    (cache_dir / "_index.html").write_text(html, encoding="utf-8")
    keys = set()
    for m in ADVISORY_PATH_RE.finditer(html):
        keys.add(m.group(0).strip("/").split("/")[-1])
    return sorted(keys)


def fetch_advisory(key: str, cache_dir: Path, *, sleep_s: float) -> str:
    cached = cache_dir / f"{key}.html"
    if cached.exists():
        return cached.read_text(encoding="utf-8")
    html = _fetch(f"https://www.jenkins.io/security/advisory/{key}/")
    cached.write_text(html, encoding="utf-8")
    time.sleep(sleep_s)
    return html


def plugins_named(html: str) -> tuple[set[str], set[str]]:
    """Return (plugin ids linked via plugins.jenkins.io, legacy wiki names)."""
    ids = {m.group(1).lower() for m in PLUGIN_LINK_RE.finditer(html)}
    # Links in the page chrome (navigation, footers) are not plugin references;
    # restrict to the main content if the page exposes it.
    main = re.search(r"<main[^>]*>(.*?)</main>", html, re.S)
    if main:
        ids = {m.group(1).lower() for m in PLUGIN_LINK_RE.finditer(main.group(1))}
        wiki = {m.group(1).lower() for m in WIKI_LINK_RE.finditer(main.group(1))}
    else:
        wiki = {m.group(1).lower() for m in WIKI_LINK_RE.finditer(html)}
    return ids, wiki


def update_center_warnings() -> list[dict]:
    raw = _fetch(UC_URL)
    # update-center.actual.json is plain JSON; the .json variant is JSONP.
    data = json.loads(raw)
    out = []
    for w in data.get("warnings", []) or []:
        if (w or {}).get("type") != "plugin":
            continue
        out.append(
            {
                "id": w.get("id"),
                "plugin_id": str(w.get("name") or "").lower(),
                "url": w.get("url"),
                "date": (_advisory_date(w.get("url") or "") or date.min).isoformat(),
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--registry", default="data/raw/registry/plugins.jsonl")
    ap.add_argument(
        "--start", default="2018-01-01", help="first advisory date to count (inclusive)"
    )
    ap.add_argument("--end", default="2026-06-30", help="last advisory date to count (inclusive)")
    ap.add_argument("--out-dir", default="data/processed/results")
    ap.add_argument("--cache-dir", default="data/cache/advisory_pages")
    ap.add_argument(
        "--sleep", type=float, default=0.4, help="seconds between advisory page fetches"
    )
    ap.add_argument("--skip-update-center", action="store_true")
    args = ap.parse_args(argv)

    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end)
    registry_path = Path(args.registry)
    out_dir = Path(args.out_dir)
    cache_dir = Path(args.cache_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    frame = load_frame(registry_path)
    print(f"frame: {len(frame)} plugins from {registry_path}")

    keys = list_advisories(cache_dir)
    in_window = [k for k in keys if (d := _advisory_date(k)) and start <= d <= end]
    print(f"advisory index: {len(keys)} advisories total, {len(in_window)} in {start}..{end}")

    pairs: list[dict] = []  # one row per (advisory, plugin)
    no_plugin_links: list[str] = []
    wiki_only: dict[str, set[str]] = {}
    for i, key in enumerate(in_window, 1):
        html = fetch_advisory(key, cache_dir, sleep_s=args.sleep)
        ids, wiki = plugins_named(html)
        d = _advisory_date(key)
        sec_ids = sorted(set(SECURITY_ID_RE.findall(html)))
        if not ids and wiki:
            wiki_only[key] = wiki
        if not ids and not wiki:
            no_plugin_links.append(key)
        for pid in sorted(ids):
            pairs.append(
                {
                    "advisory": key,
                    "date": d.isoformat() if d else "",
                    "plugin_id": pid,
                    "in_frame": pid in frame,
                    "security_ids_on_page": len(sec_ids),
                }
            )
        if i % 25 == 0:
            print(f"  ... {i}/{len(in_window)} advisory pages parsed")

    # Summaries
    pairs_out = [p for p in pairs if not p["in_frame"]]
    plugins_out = Counter(p["plugin_id"] for p in pairs_out)
    plugins_in = {p["plugin_id"] for p in pairs if p["in_frame"]}
    by_year_total: Counter = Counter()
    by_year_out: Counter = Counter()
    for p in pairs:
        y = p["date"][:4]
        by_year_total[y] += 1
        if not p["in_frame"]:
            by_year_out[y] += 1
    advisories_with_out = {p["advisory"] for p in pairs_out}

    summary = {
        "registry": str(registry_path),
        "frame_size": len(frame),
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "advisories_in_window": len(in_window),
        "advisory_plugin_pairs": len(pairs),
        "pairs_in_frame": len(pairs) - len(pairs_out),
        "pairs_outside_frame": len(pairs_out),
        "share_outside_frame": round(len(pairs_out) / len(pairs), 4) if pairs else None,
        "distinct_plugins_named": len(plugins_in) + len(plugins_out),
        "distinct_plugins_in_frame": len(plugins_in),
        "distinct_plugins_outside_frame": len(plugins_out),
        "advisories_naming_an_outside_plugin": len(advisories_with_out),
        "by_year": {
            y: {"pairs": by_year_total[y], "outside_frame": by_year_out[y]}
            for y in sorted(by_year_total)
        },
        "outside_frame_plugins": [
            {"plugin_id": pid, "advisory_pairs": n} for pid, n in plugins_out.most_common()
        ],
        "advisories_with_no_plugin_links": no_plugin_links,
        "advisories_with_wiki_links_only": {k: sorted(v) for k, v in wiki_only.items()},
    }

    if not args.skip_update_center:
        try:
            warnings = update_center_warnings()
            w_in = [w for w in warnings if start <= date.fromisoformat(w["date"]) <= end]
            w_out = [w for w in w_in if w["plugin_id"] not in frame]
            summary["update_center_crosscheck"] = {
                "plugin_warnings_total": len(warnings),
                "plugin_warnings_in_window": len(w_in),
                "warnings_outside_frame": len(w_out),
                "distinct_plugins_outside_frame": len({w["plugin_id"] for w in w_out}),
                "outside_frame_plugins": sorted({w["plugin_id"] for w in w_out}),
            }
        except Exception as e:  # noqa: BLE001
            summary["update_center_crosscheck"] = {"error": str(e)}

    (out_dir / "survivorship_audit.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    with (out_dir / "survivorship_audit_pairs.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["advisory", "date", "plugin_id", "in_frame", "security_ids_on_page"]
        )
        w.writeheader()
        w.writerows(pairs)

    print()
    print(f"advisory/plugin pairs {start}..{end}: {summary['advisory_plugin_pairs']}")
    print(f"  in frame:      {summary['pairs_in_frame']}")
    print(
        f"  outside frame: {summary['pairs_outside_frame']} "
        f"({summary['share_outside_frame']:.1%} of pairs) across "
        f"{summary['distinct_plugins_outside_frame']} plugins, "
        f"in {summary['advisories_naming_an_outside_plugin']} advisories"
        if pairs
        else ""
    )
    print("  by year (pairs / outside frame):")
    for y, v in summary["by_year"].items():
        print(f"    {y}: {v['pairs']:4d} / {v['outside_frame']:3d}")
    if no_plugin_links:
        print(f"  advisories with no plugin links (check manually): {len(no_plugin_links)}")
    if wiki_only:
        print(f"  advisories with legacy wiki links only (not matched): {len(wiki_only)}")
    uc = summary.get("update_center_crosscheck", {})
    if uc and "error" not in uc:
        print(
            f"  update center cross-check: {uc['warnings_outside_frame']} warnings on "
            f"{uc['distinct_plugins_outside_frame']} plugins outside the frame"
        )
    print(f"\nwrote {out_dir / 'survivorship_audit.json'} and survivorship_audit_pairs.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
