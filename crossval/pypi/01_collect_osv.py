"""
crossval/pypi/01_collect_osv.py
================================
Download PyPI advisory data from the OSV bulk export and write a flat JSONL
file that mirrors the shape used by the Jenkins advisory pipeline.

Usage
-----
    python crossval/pypi/01_collect_osv.py

Output
------
    data/pypi/raw/advisories.jsonl   — one record per (package, advisory_id)

OSV bulk export
---------------
The Open Source Vulnerabilities project (https://osv.dev) publishes a
nightly zip of all PyPI advisories at:
    https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip

Each zip entry is a JSON file for a single advisory.  Records may cover
multiple packages (e.g. a monorepo advisory).  This script expands them to
one row per affected PyPI package.

Output record fields (match Jenkins advisory shape used in modeling)
--------------------------------------------------------------------
    package_id          str   — normalised PyPI package name (lowercase, hyphens)
    advisory_id         str   — OSV id (e.g. GHSA-xxxx or PYSEC-xxxx)
    published_date      str   — ISO date (YYYY-MM-DD)
    source              str   — "osv_pypi"
    cve_ids             list  — CVE identifiers mentioned in the advisory
    cvss                float | None — CVSS v3 base score when available
    severity            str | None   — qualitative label (low/medium/high/critical)
"""

from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
OUT_PATH = Path("data/pypi/raw/advisories.jsonl")
REQUEST_TIMEOUT_S = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_package(name: str) -> str:
    """Normalise PyPI package name: lowercase, replace _ with -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_date(value: str | None) -> str | None:
    """Return YYYY-MM-DD from an ISO-8601 timestamp or date string."""
    if not value:
        return None
    # Trim sub-second precision and timezone, keep date part
    try:
        dt = datetime.fromisoformat(value.rstrip("Z").split(".")[0])
        return dt.date().isoformat()
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", value)
        return m.group(1) if m else None


def _cvss_score_from_severity_list(severity: list[dict[str, Any]]) -> float | None:
    """Extract the first CVSS v3 base score from the OSV severity array."""
    for s in severity or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            vector = s.get("score", "")
            score = _cvss3_base_score(vector)
            if score is not None:
                return score
    return None


def _cvss3_base_score(vector: str) -> float | None:
    """Compute CVSS v3.x base score from a vector string (subset implementation)."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    av_w = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_w = {"L": 0.77, "H": 0.44}
    ui_w = {"N": 0.85, "R": 0.62}
    cia_w = {"N": 0.0, "L": 0.22, "H": 0.56}
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
    s = metrics.get("S")
    try:
        av = av_w[metrics["AV"]]
        ac = ac_w[metrics["AC"]]
        ui = ui_w[metrics["UI"]]
        pr = (pr_c if s == "C" else pr_u)[metrics["PR"]]
        c = cia_w[metrics["C"]]
        i_val = cia_w[metrics["I"]]
        a = cia_w[metrics["A"]]
    except KeyError:
        return None

    import math

    exploitability = 8.22 * av * ac * pr * ui
    isc_base = 1.0 - (1.0 - c) * (1.0 - i_val) * (1.0 - a)
    if s == "C":
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    if s == "C":
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    return float(f"{math.ceil(raw * 10 + 1e-10) / 10:.1f}")


def _cvss_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _extract_cves(aliases: list[str], related: list[str]) -> list[str]:
    cves: list[str] = []
    for v in (aliases or []) + (related or []):
        if isinstance(v, str) and v.upper().startswith("CVE-"):
            cves.append(v.upper())
    return sorted(set(cves))


def _parse_osv_record(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Expand one OSV record into one row per affected PyPI package.
    Returns [] for records with no PyPI-ecosystem affected packages.
    """
    advisory_id: str = data.get("id", "")
    published_date = _parse_date(data.get("published"))
    if not published_date:
        # Fall back to modified date
        published_date = _parse_date(data.get("modified"))
    if not published_date:
        return []

    cve_ids = _extract_cves(
        data.get("aliases", []),
        data.get("related", []),
    )

    severity_list = data.get("severity") or []
    cvss = _cvss_score_from_severity_list(severity_list)

    # Some records store severity in database_specific
    db_specific = data.get("database_specific") or {}
    severity_label: str | None = None
    if cvss is not None:
        severity_label = _cvss_to_severity(cvss)
    else:
        raw_sev = db_specific.get("severity")
        if isinstance(raw_sev, str) and raw_sev:
            severity_label = raw_sev.lower()

    rows: list[dict[str, Any]] = []
    for affected in data.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "PyPI":
            continue
        name = pkg.get("name")
        if not name:
            continue

        rows.append(
            {
                "source": "osv_pypi",
                "advisory_id": advisory_id,
                "package_id": _normalise_package(name),
                "published_date": published_date,
                "cve_ids": cve_ids,
                "cvss": cvss,
                "severity": severity_label,
            }
        )

    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"Downloading OSV PyPI bulk export from {OSV_URL} ...")
    req = urllib.request.Request(
        OSV_URL,
        headers={"User-Agent": "canary-crossval/0.1 (pypi-advisory-collection)"},
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:  # nosec B310
        zip_bytes = resp.read()

    print(f"Downloaded {len(zip_bytes):,} bytes.  Parsing ...")

    all_rows: list[dict[str, Any]] = []
    skipped = 0

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        print(f"  {len(names):,} advisory files in zip")
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                skipped += 1
                continue
            rows = _parse_osv_record(data)
            all_rows.extend(rows)

    # Deduplicate by (package_id, advisory_id) — keep first occurrence
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for r in all_rows:
        key = (r["package_id"], r["advisory_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    # Sort for stable diffs
    deduped.sort(key=lambda r: (r["published_date"], r["package_id"], r["advisory_id"]))

    with OUT_PATH.open("w", encoding="utf-8") as f:
        for r in deduped:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    unique_packages = len({r["package_id"] for r in deduped})
    print("\nDone.")
    print(f"  Total records written : {len(deduped):,}")
    print(f"  Unique packages       : {unique_packages:,}")
    print(f"  Skipped (parse error) : {skipped:,}")
    print(f"  Output                : {OUT_PATH}")


if __name__ == "__main__":
    main()
