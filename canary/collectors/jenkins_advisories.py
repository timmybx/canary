# canary/collectors/jenkins_advisories.py
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

_ALLOWED_NETLOCS = {"jenkins.io", "www.jenkins.io"}


@dataclass(frozen=True)
class AdvisoryRecord:
    source: str
    type: str
    advisory_id: str
    published_date: date
    plugin_id: str
    title: str
    url: str
    fixed_version: str | None = None
    affected_versions: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    severity: str | None = None
    cvss: float | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["published_date"] = self.published_date.isoformat()
        d["cve_ids"] = d["cve_ids"] or []
        d["cwe_ids"] = d["cwe_ids"] or []
        return d


def _allowlisted_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in _ALLOWED_NETLOCS:
        raise ValueError(f"Refusing to fetch unexpected URL: {url}")


def _canonicalize_jenkins_url(url: str | None) -> str | None:
    """
    Normalize Jenkins advisory URLs safely.

    - Forces https (if scheme is http or missing).
    - Normalizes hostname strictly: jenkins.io -> www.jenkins.io.
    - Avoids substring matching (CodeQL-friendly).
    - Keeps path/query/fragment intact.
    """
    if not url:
        return url

    url = url.strip()
    parsed = urlparse(url)

    # Normalize scheme
    scheme = parsed.scheme or "https"
    if scheme == "http":
        scheme = "https"

    # Normalize host strictly (no substring checks)
    netloc = parsed.netloc
    if netloc == "jenkins.io":
        netloc = "www.jenkins.io"

    normalized = parsed._replace(scheme=scheme, netloc=netloc)
    return urlunparse(normalized)


def _fetch_text(url: str, *, timeout_s: float = 15.0) -> str:
    url = _canonicalize_jenkins_url(url) or url
    _allowlisted_url(url)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "canary/0.0 (advisories)"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Fetch failed ({e.code}) for {url}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Fetch failed (network) for {url}") from e


def _extract_title(html: str) -> str | None:
    m = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


def _date_from_advisory_url(url: str) -> date | None:
    # matches .../security/advisory/YYYY-MM-DD/
    m = re.search(r"/security/advisory/(\d{4}-\d{2}-\d{2})/?$", url)
    if not m:
        return None
    try:
        return date.fromisoformat(m.group(1))
    except ValueError:
        return None


def _load_plugin_snapshot(plugin_id: str, data_dir: Path) -> dict[str, Any]:
    path = data_dir / "plugins" / f"{plugin_id}.snapshot.json"
    return json.loads(path.read_text(encoding="utf-8"))


def merge_advisory_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Deduplicate advisory records and merge fields.

    Dedupe key: (source, type, plugin_id, advisory_id)

    Merge rules:
      - URL: canonicalize Jenkins domain; prefer host www.jenkins.io when present
      - security_warning_ids: union + stable sort
      - active_security_warning: True if any record has True
      - published_date: keep earliest (lexicographic works for YYYY-MM-DD)
      - title: prefer a non-empty title, else keep existing
      - adds _merged_from_count for transparency when duplicates were merged
    """
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    counts: dict[tuple[str, str, str, str], int] = {}

    def key_for(r: dict[str, Any]) -> tuple[str, str, str, str]:
        return (
            str(r.get("source", "")),
            str(r.get("type", "")),
            str(r.get("plugin_id", "")),
            str(r.get("advisory_id", "")),
        )

    def host(u: str | None) -> str:
        if not u:
            return ""
        return urlparse(u).netloc

    for r_in in records:
        r = dict(r_in)  # copy
        if r.get("source") == "jenkins" and r.get("type") == "advisory":
            r["url"] = _canonicalize_jenkins_url(r.get("url"))

        # normalize list fields early
        r["security_warning_ids"] = sorted(set(r.get("security_warning_ids") or []))

        k = key_for(r)
        counts[k] = counts.get(k, 0) + 1

        if k not in merged:
            merged[k] = r
            continue

        base = merged[k]

        # URL preference: prefer canonical host www.jenkins.io when available
        base_url = base.get("url")
        new_url = r.get("url")
        if new_url:
            if (not base_url) or (
                host(new_url) == "www.jenkins.io" and host(base_url) != "www.jenkins.io"
            ):
                base["url"] = new_url

        # Merge security_warning_ids (union)
        base_ids = set(base.get("security_warning_ids") or [])
        new_ids = set(r.get("security_warning_ids") or [])
        base["security_warning_ids"] = sorted(base_ids | new_ids)

        # Merge active_security_warning (any True wins)
        base["active_security_warning"] = bool(base.get("active_security_warning")) or bool(
            r.get("active_security_warning")
        )

        # published_date: keep earliest if both exist
        base_date = base.get("published_date")
        new_date = r.get("published_date")
        if base_date and new_date:
            base["published_date"] = min(str(base_date), str(new_date))
        elif not base_date and new_date:
            base["published_date"] = new_date

        # title: prefer a non-empty title
        if not base.get("title") and r.get("title"):
            base["title"] = r.get("title")

        merged[k] = base

    out: list[dict[str, Any]] = []
    for k, obj in merged.items():
        c = counts.get(k, 1)
        if c > 1:
            obj["_merged_from_count"] = c
        out.append(obj)
    return out


def collect_advisories_sample(plugin_id: str | None = None) -> list[dict[str, Any]]:
    records = [
        AdvisoryRecord(
            source="jenkins",
            type="advisory",
            advisory_id="2025-01-001",
            published_date=date(2025, 1, 10),
            plugin_id="workflow-cps",
            title="Sample advisory record (replace with real data)",
            url="https://www.jenkins.io/security/advisory/2025-01-001/",
            fixed_version="3.0",
            affected_versions="<= 2.9",
            notes="Placeholder data so the pipeline works end-to-end.",
        ),
        AdvisoryRecord(
            source="jenkins",
            type="advisory",
            advisory_id="2016-07-27",
            published_date=date(2016, 7, 27),
            plugin_id="cucumber-reports",
            title="Cucumber Reports Plugin advisory (pilot sample)",
            url="https://www.jenkins.io/security/advisory/2016-07-27/",
            notes="Pilot sample record; replace with parsed fields later.",
        ),
    ]

    out = [r.to_dict() for r in records]
    if plugin_id:
        out = [r for r in out if r.get("plugin_id") == plugin_id]
    return merge_advisory_records(out)


def collect_advisories_real(
    plugin_id: str,
    *,
    data_dir: str | Path = "data/raw",
    timeout_s: float = 15.0,
) -> list[dict[str, Any]]:
    """
    Collect plugin-specific advisories using the plugins API data stored in the snapshot.
    Requires: collect plugin --real --id <plugin_id> ran first.
    """
    snapshot = _load_plugin_snapshot(plugin_id, Path(data_dir))
    api = snapshot.get("plugin_api") or {}

    urls: set[str] = set()

    # 1) securityWarnings from plugins API (best source)
    for w in api.get("securityWarnings") or []:
        u = (w or {}).get("url")
        if u:
            urls.add(_canonicalize_jenkins_url(str(u)) or str(u).strip())

    # 2) any curated URLs you already store
    for u in snapshot.get("security_advisory_urls") or []:
        if u:
            urls.add(_canonicalize_jenkins_url(str(u)) or str(u).strip())

    # Canonicalize once so matching below is consistent
    warnings = api.get("securityWarnings") or []
    warnings_by_url: dict[str, list[dict[str, Any]]] = {}
    for w in warnings:
        u = _canonicalize_jenkins_url((w or {}).get("url"))
        if not u:
            continue
        warnings_by_url.setdefault(u, []).append(w)

    records: list[dict[str, Any]] = []
    for url in sorted(urls):
        url = _canonicalize_jenkins_url(url) or url

        html = _fetch_text(url, timeout_s=timeout_s)
        title = _extract_title(html)

        published = _date_from_advisory_url(url)
        advisory_id = published.isoformat() if published else None

        related_warnings = warnings_by_url.get(url, [])

        security_warning_ids: list[str] = []
        for w in related_warnings:
            wid = (w or {}).get("id")
            if wid:
                security_warning_ids.append(str(wid))

        active_security_warning = any((w or {}).get("active") is True for w in related_warnings)

        records.append(
            {
                "source": "jenkins",
                "type": "advisory",
                "advisory_id": advisory_id,
                "plugin_id": plugin_id,
                "url": url,
                "published_date": published.isoformat() if published else None,
                "title": title,
                "security_warning_ids": security_warning_ids,
                "active_security_warning": active_security_warning,
            }
        )

    # Deduplicate/merge near-duplicates (e.g., jenkins.io vs www.jenkins.io)
    return merge_advisory_records(records)
