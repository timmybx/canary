from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def fetch_health_scores(timeout_s: float = 30.0) -> Any:
    """
    Fetch health score export.

    Notes:
    - Jenkins infra folks mention scores are exposed via /api/scores.
    - Exact JSON shape can evolve; we keep this tolerant.
    """
    url = "https://plugin-health.jenkins.io/api/scores"
    r = requests.get(url, timeout=timeout_s)
    r.raise_for_status()
    return r.json()


def _iter_score_records(payload: Any) -> list[dict[str, Any]]:
    """
    Normalize payload into a list of dict records.
    We accept either:
      - a list[dict]
      - a dict containing a list under common keys
      - a dict mapping plugin_id -> record
    """
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    if isinstance(payload, dict):
        # common "container" patterns
        for k in ("scores", "data", "items", "plugins"):
            v = payload.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # mapping pattern: {"translation": {...}, ...}
        # Convert to records with explicit plugin_id
        records: list[dict[str, Any]] = []
        for plugin_id, rec in payload.items():
            if isinstance(plugin_id, str) and isinstance(rec, dict):
                out = dict(rec)
                out.setdefault("plugin_id", plugin_id)
                records.append(out)
        if records:
            return records

    return []


def _extract_plugin_id(rec: dict[str, Any]) -> str | None:
    for k in ("plugin_id", "pluginId", "id", "plugin"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # Sometimes nested
    plugin = rec.get("plugin")
    if isinstance(plugin, dict):
        v = plugin.get("id") or plugin.get("name")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def collect_health_scores(
    *,
    data_dir: str = "data/raw",
    timeout_s: float = 30.0,
    overwrite: bool = False,
) -> dict[str, Any]:
    """
    Fetch health scores once and write:
      - data/raw/healthscore/scores.json
      - data/raw/healthscore/plugins/<plugin_id>.healthscore.json
    """
    base = Path(data_dir) / "healthscore"
    scores_path = base / "scores.json"

    results: dict[str, Any] = {
        "collected_at": _utc_now_iso(),
        "scores_path": str(scores_path),
        "processed": 0,
        "written": 0,
        "skipped": 0,
        "errors": {},
    }

    if scores_path.exists() and scores_path.stat().st_size > 0 and not overwrite:
        payload = json.loads(scores_path.read_text(encoding="utf-8"))
    else:
        payload = fetch_health_scores(timeout_s=timeout_s)
        _write_json(scores_path, payload)

    records = _iter_score_records(payload)

    for rec in records:
        plugin_id = _extract_plugin_id(rec)
        if not plugin_id:
            continue

        results["processed"] += 1
        out_path = base / "plugins" / f"{plugin_id}.healthscore.json"

        if out_path.exists() and out_path.stat().st_size > 0 and not overwrite:
            results["skipped"] += 1
            continue

        try:
            # Store record plus collection timestamp for provenance
            out = {
                "plugin_id": plugin_id,
                "collected_at": results["collected_at"],
                "record": rec,
            }
            _write_json(out_path, out)
            results["written"] += 1
        except Exception as e:
            results["errors"][plugin_id] = str(e)

    return results
