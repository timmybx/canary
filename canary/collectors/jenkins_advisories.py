# canary/collectors/jenkins_advisories.py
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


def _fetch_text(url: str, *, timeout_s: float = 15.0) -> str:
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
    return out


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
            urls.add(str(u).strip())

    # 2) any curated URLs you already store
    for u in snapshot.get("security_advisory_urls") or []:
        if u:
            urls.add(str(u).strip())

    records: list[dict[str, Any]] = []
    for url in sorted(urls):
        html = _fetch_text(url, timeout_s=timeout_s)
        title = _extract_title(html)

        published = _date_from_advisory_url(url)
        advisory_id = published.isoformat() if published else None

        records.append(
            {
                "source": "jenkins",
                "type": "advisory",
                "advisory_id": advisory_id,
                "plugin_id": plugin_id,
                "url": url,
                "published_date": published.isoformat() if published else None,
                "title": title,
                "security_warning_ids": [
                    (w or {}).get("id")
                    for w in (api.get("securityWarnings") or [])
                    if (w or {}).get("url") == url
                ],
                "active_security_warning": any(
                    (w or {}).get("active") is True
                    for w in (api.get("securityWarnings") or [])
                    if (w or {}).get("url") == url
                ),
            }
        )

    return records
