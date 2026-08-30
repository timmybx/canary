"""
Collector for Jenkins plugin installation statistics (stats.jenkins.io).

Source: ``https://stats.jenkins.io/plugin-installation-trend/<plugin>.stats.json``
— one static JSON per plugin with monthly installation counts and install-share
percentages derived from anonymous usage pings, with history back to 2008.
Unlike the plugin Health Score (a current-only snapshot), this is TRUE monthly
history, so it is the one Jenkins-ecosystem source that can enter the
historical model: every panel month has an as-of value that was actually
published near that time and is never restated.

Payload shape (verified Aug 2026)::

    {
      "name": "git",
      "installations":            {"<epoch millis>": 46, ...},
      "installationsPercentage":  {"<epoch millis>": 3.57, ...},
      "installationsPerVersion":  {...},
      "installationsPercentagePerVersion": {...}
    }

Collection is deliberately gentle: ~2,000 small GETs against a static file
host, throttled by ``--sleep`` (default 0.2s), resumable (existing files are
skipped unless ``--overwrite``), with plugins missing from the stats site
(404) recorded in the summary rather than treated as errors.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from canary.collectors._path_utils import safe_join_under, safe_plugin_id
from canary.plugin_aliases import canonicalize_plugin_id

INSTALL_STATS_URL = "https://stats.jenkins.io/plugin-installation-trend/{plugin_id}.stats.json"
STATS_SUFFIX = ".stats.json"


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _iter_registry_plugin_ids(registry_path: Path):
    """Yield canonical plugin ids from the registry jsonl (local copy of the
    CLI helper — collectors must not import ``canary.cli``)."""
    with registry_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            pid = (rec.get("plugin_id") or "").strip()
            if pid:
                yield canonicalize_plugin_id(pid, registry_path=registry_path)


def validate_install_stats(payload: Any) -> dict[str, Any] | None:
    """
    Return the payload if it looks like a plugin installation-trend record
    (a dict whose ``installations`` is a non-empty dict), else None.
    """
    if not isinstance(payload, dict):
        return None
    installations = payload.get("installations")
    if not isinstance(installations, dict) or not installations:
        return None
    return payload


def fetch_install_stats(
    plugin_id: str,
    *,
    timeout_s: float = 30.0,
) -> dict[str, Any] | None:
    """
    Fetch one plugin's installation-trend JSON. Returns None when the stats
    site has no record for the plugin (HTTP 404); raises on other failures.
    """
    url = INSTALL_STATS_URL.format(plugin_id=plugin_id)
    r = requests.get(url, timeout=timeout_s)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return validate_install_stats(r.json())


def collect_install_stats(
    *,
    data_dir: str = "data/raw",
    registry_path: str = "data/raw/registry/plugins.jsonl",
    sleep_s: float = 0.2,
    overwrite: bool = False,
    max_plugins: int | None = None,
    timeout_s: float = 30.0,
    fetch: Callable[[str], dict[str, Any] | None] | None = None,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Bulk-collect installation trends for every registry plugin into
    ``<data_dir>/jenkins_stats/<plugin>.stats.json``.

    Resumable: existing files are skipped unless *overwrite*. Plugins the
    stats site does not know (404, or a payload with no installation series)
    are recorded under ``missing`` in the returned summary — and in
    ``_collection_summary.json`` beside the output files — rather than
    treated as errors. *fetch* is injectable for tests.
    """
    registry = Path(registry_path)
    if not registry.exists():
        raise SystemExit(f"ERROR: registry file not found: {registry}")
    out_dir = Path(data_dir) / "jenkins_stats"
    out_dir.mkdir(parents=True, exist_ok=True)
    fetch_one = fetch or (lambda pid: fetch_install_stats(pid, timeout_s=timeout_s))

    written = 0
    skipped = 0
    missing: list[str] = []
    errors: list[str] = []
    processed = 0

    for plugin_id in _iter_registry_plugin_ids(registry):
        if max_plugins is not None and processed >= max_plugins:
            break
        processed += 1
        safe_id = safe_plugin_id(plugin_id)
        if safe_id is None:
            errors.append(f"{plugin_id}: invalid plugin id, skipped")
            continue
        out_path = safe_join_under(out_dir, f"{safe_id}{STATS_SUFFIX}")
        if out_path.exists() and not overwrite:
            skipped += 1
            continue
        try:
            payload = fetch_one(plugin_id)
        except Exception as exc:  # noqa: BLE001 — one bad plugin must not kill the crawl
            errors.append(f"{plugin_id}: {exc}")
            continue
        if payload is None:
            missing.append(plugin_id)
            continue
        out_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        written += 1
        if verbose and written % 100 == 0:
            print(f"  … {written} written ({processed} processed)")
        if sleep_s > 0:
            time.sleep(sleep_s)

    summary = {
        "collected_at": _utc_now_iso(),
        "source": "stats.jenkins.io/plugin-installation-trend",
        "processed": processed,
        "written": written,
        "skipped_existing": skipped,
        "missing": sorted(missing),
        "missing_count": len(missing),
        "errors": errors,
        "error_count": len(errors),
    }
    (out_dir / "_collection_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary
