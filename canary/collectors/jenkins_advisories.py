# canary/collectors/jenkins_advisories.py
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

_ALLOWED_NETLOCS = {"jenkins.io", "www.jenkins.io"}


_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _cvss_base_score_to_severity_label(score: float | None) -> str | None:
    """Derive a severity label from a CVSS v3.x base score.

    Jenkins advisories often provide CVSS vectors/scores but not a structured
    severity label. This mapping follows the CVSS v3.x qualitative severity
    ratings.
    """
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None

    if s <= 0.0:
        return "none"
    if s < 4.0:
        return "low"
    if s < 7.0:
        return "medium"
    if s < 9.0:
        return "high"
    return "critical"


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

    try:
        parsed = urlparse(url)
    except ValueError:
        # Malformed URLs (e.g., invalid bracketed IPv6) should not crash the pipeline.
        return None

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


def _strip_query_fragment(url: str) -> str:
    """Return URL without query/fragment (keeps scheme/host/path)."""
    try:
        p = urlparse(url)
    except ValueError:
        return url
    return urlunparse(p._replace(query="", fragment=""))


def _normalize_advisory_url(url: str) -> str:
    """Canonicalize Jenkins advisory URL and drop query/fragment for stable matching."""
    return _strip_query_fragment(_canonicalize_jenkins_url(url) or url)


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
    url = _strip_query_fragment(url)
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
            if r.get("url"):
                r["url"] = _normalize_advisory_url(str(r.get("url")))

            # If advisory_id/published_date are missing, derive from URL when possible.
            derived = _date_from_advisory_url(str(r.get("url") or ""))
            if derived:
                if not r.get("advisory_id"):
                    r["advisory_id"] = derived.isoformat()
                if not r.get("published_date"):
                    r["published_date"] = derived.isoformat()

        # normalize list fields early
        r["security_warning_ids"] = sorted(set(r.get("security_warning_ids") or []))

        # normalize vulnerabilities
        vulns = r.get("vulnerabilities")
        if isinstance(vulns, list):
            norm_v: list[dict[str, Any]] = []
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                sid = v.get("security_warning_id")
                if sid:
                    vv = dict(v)
                    vv["security_warning_id"] = str(sid)
                    norm_v.append(vv)
            r["vulnerabilities"] = norm_v

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

        # Merge vulnerabilities (union by security_warning_id)
        base_vulns = {
            v.get("security_warning_id"): v
            for v in (base.get("vulnerabilities") or [])
            if isinstance(v, dict)
        }
        new_vulns = {
            v.get("security_warning_id"): v
            for v in (r.get("vulnerabilities") or [])
            if isinstance(v, dict)
        }
        for sid, v in new_vulns.items():
            if not sid:
                continue
            if sid not in base_vulns:
                base_vulns[sid] = v
                continue
            # prefer non-null fields from the new record
            b = dict(base_vulns[sid])
            for field_name in ["severity_label", "url_fragment"]:
                if not b.get(field_name) and v.get(field_name):
                    b[field_name] = v.get(field_name)
            # cvss object merge
            if isinstance(v.get("cvss"), dict):
                bcv = dict(b.get("cvss") or {}) if isinstance(b.get("cvss"), dict) else {}
                for kk, vv in v["cvss"].items():
                    if bcv.get(kk) in (None, "") and vv not in (None, ""):
                        bcv[kk] = vv
                b["cvss"] = bcv
            base_vulns[sid] = b
        if base_vulns:
            sorted_vuln_ids = sorted(
                sid for sid in base_vulns.keys() if isinstance(sid, str) and sid
            )
            base["vulnerabilities"] = [base_vulns[sid] for sid in sorted_vuln_ids]

        merged[k] = base

    out: list[dict[str, Any]] = []
    for k, obj in merged.items():
        c = counts.get(k, 1)
        if c > 1:
            obj["_merged_from_count"] = c
        out.append(obj)
    return out


def _extract_severity_labels(html: str) -> dict[str, str]:
    """Best-effort parse of Jenkins advisory severity lines."""
    out: dict[str, str] = {}
    for m in re.finditer(
        r"\b(SECURITY-\d+)\b\s+is\s+considered\s+\b(low|medium|high|critical)\b",
        html,
        flags=re.IGNORECASE,
    ):
        out[m.group(1).upper()] = m.group(2).lower()
    return out


def _extract_security_sections(html: str) -> dict[str, str]:
    """Split HTML into SECURITY-<id> sections using a loose heuristic."""
    matches = list(re.finditer(r"\bSECURITY-\d+\b", html))
    if not matches:
        return {}
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        sid = m.group(0).upper()
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(html)
        chunk = html[start:end]
        if sid not in out or len(chunk) > len(out[sid]):
            out[sid] = chunk
    return out


def _parse_cvss_vector_from_url(url: str) -> tuple[str | None, str | None]:
    """Extract (version, vector) from a FIRST CVSS calculator URL."""
    try:
        p = urlparse(url)
    except ValueError:
        return (None, None)
    frag = p.fragment or ""
    if frag.startswith("CVSS:"):
        parts = frag.split("/", 1)
        vpart = parts[0]  # CVSS:3.0
        version = vpart.split(":", 1)[1] if ":" in vpart else None
        return (version, frag)
    return (None, None)


def _cvss3_round_up_1_decimal(x: float) -> float:
    # CVSS v3 uses "round up" to one decimal place.
    import math

    return math.ceil(x * 10.0 + 1e-10) / 10.0


def _cvss3_base_score(vector: str) -> float | None:
    """Compute CVSS v3.x base score from a vector string."""
    if not vector.startswith("CVSS:3"):
        return None

    metrics: dict[str, str] = {}
    try:
        parts = vector.split("/")
        for p in parts[1:]:
            if ":" not in p:
                continue
            k, v = p.split(":", 1)
            metrics[k] = v
    except Exception:
        return None

    av_w = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_w = {"L": 0.77, "H": 0.44}
    ui_w = {"N": 0.85, "R": 0.62}
    s = metrics.get("S")
    cia_w = {"N": 0.0, "L": 0.22, "H": 0.56}
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}

    try:
        av = av_w[metrics["AV"]]
        ac = ac_w[metrics["AC"]]
        ui = ui_w[metrics["UI"]]
        pr = (pr_c if s == "C" else pr_u)[metrics["PR"]]
        c = cia_w[metrics["C"]]
        i = cia_w[metrics["I"]]
        a = cia_w[metrics["A"]]
    except KeyError:
        return None

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if s == "C":
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return 0.0

    if s == "C":
        base = _cvss3_round_up_1_decimal(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = _cvss3_round_up_1_decimal(min(impact + exploitability, 10.0))

    return float(f"{base:.1f}")


def _extract_cvss_by_security_id(html: str) -> dict[str, dict[str, Any]]:
    """Best-effort mapping of SECURITY-id -> CVSS metadata."""
    out: dict[str, dict[str, Any]] = {}
    sections = _extract_security_sections(html)
    for sid, chunk in sections.items():
        m = re.search(
            r"https?://www\.first\.org/cvss/calculator/[^\"'\s>]+",
            chunk,
            flags=re.IGNORECASE,
        )
        if not m:
            continue
        cvss_url = m.group(0)
        version, vector = _parse_cvss_vector_from_url(cvss_url)
        if not vector:
            continue
        base = _cvss3_base_score(vector)
        out[sid] = {
            "version": version,
            "vector": vector,
            "base_score": base,
            "url": cvss_url,
        }
    return out


def _max_severity_label(labels: Iterable[str]) -> str | None:
    best = None
    best_v = -1
    for lab in labels:
        v = _SEVERITY_ORDER.get(str(lab).lower(), -1)
        if v > best_v:
            best_v = v
            best = str(lab).lower()
    return best


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
            urls.add(_normalize_advisory_url(str(u).strip()))

    # 2) any curated URLs you already store
    for u in snapshot.get("security_advisory_urls") or []:
        if u:
            urls.add(_normalize_advisory_url(str(u).strip()))

    # Canonicalize once so matching below is consistent
    warnings = api.get("securityWarnings") or []
    warnings_by_url: dict[str, list[dict[str, Any]]] = {}
    for w in warnings:
        u_raw = (w or {}).get("url")
        u = _normalize_advisory_url(str(u_raw)) if u_raw else None
        if not u:
            continue
        warnings_by_url.setdefault(u, []).append(w)

    records: list[dict[str, Any]] = []
    for url in sorted(urls):
        url = _normalize_advisory_url(url)

        # Fetch advisory HTML.
        # Treat 404s as a non-fatal dead-link and retry once on transient errors.
        try:
            html = _fetch_text(url, timeout_s=timeout_s)
        except RuntimeError as e:
            msg = str(e)
            if "Fetch failed (404)" in msg:
                print(f"[WARN] {plugin_id}: advisory URL returned 404; skipping: {url}")
                continue
            print(f"[WARN] {plugin_id}: fetch failed; retrying once: {url} ({msg})")
            time.sleep(1.0)
            html = _fetch_text(url, timeout_s=timeout_s)
        except Exception as e:
            # e.g., IncompleteRead or other transient read errors
            print(
                f"[WARN] {plugin_id}: fetch failed; retrying once: {url} ({type(e).__name__}: {e})"
            )
            time.sleep(1.0)
            html = _fetch_text(url, timeout_s=timeout_s)

        title = _extract_title(html)
        severity_labels = _extract_severity_labels(html)
        cvss_by_sid = _extract_cvss_by_security_id(html)

        published = _date_from_advisory_url(url)
        advisory_id = published.isoformat() if published else None

        related_warnings = warnings_by_url.get(url, [])

        security_warning_ids: list[str] = []
        for w in related_warnings:
            wid = (w or {}).get("id")
            if wid:
                security_warning_ids.append(str(wid))

        active_security_warning = any((w or {}).get("active") is True for w in related_warnings)

        vulnerabilities: list[dict[str, Any]] = []
        for wid in sorted(set(security_warning_ids)):
            v: dict[str, Any] = {
                "security_warning_id": wid,
                "url_fragment": f"{url}#{wid}",
                "severity_label": severity_labels.get(wid),
                "severity_source": "jenkins_advisory",
            }
            if wid in cvss_by_sid:
                v["cvss"] = cvss_by_sid[wid]

            # Derive a severity label from CVSS when missing.
            if v.get("severity_label") in (None, ""):
                cv = v.get("cvss")
                if isinstance(cv, dict):
                    sc = cv.get("base_score")
                    if isinstance(sc, (int, float)):
                        derived = _cvss_base_score_to_severity_label(float(sc))
                        if derived:
                            v["severity_label"] = derived
                            v["severity_source"] = "cvss_v3_derived"
            vulnerabilities.append(v)

        max_cvss = None
        for v in vulnerabilities:
            cv = v.get("cvss")
            if isinstance(cv, dict):
                sc = cv.get("base_score")
                if isinstance(sc, (int, float)):
                    max_cvss = float(sc) if max_cvss is None else max(max_cvss, float(sc))

        severity_labels_for_max: list[str] = []
        for v in vulnerabilities:
            label = v.get("severity_label")
            if isinstance(label, str) and label:
                severity_labels_for_max.append(label)
        max_sev = _max_severity_label(severity_labels_for_max)

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
                "vulnerabilities": vulnerabilities,
                "severity_summary": {
                    "max_severity_label": max_sev,
                    "max_cvss_base_score": max_cvss,
                },
            }
        )

    # Deduplicate/merge near-duplicates (e.g., jenkins.io vs www.jenkins.io)
    return merge_advisory_records(records)
