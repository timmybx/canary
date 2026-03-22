from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SWH_API_BASE = "https://archive.softwareheritage.org/api/1"


def _nonempty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_plugin_snapshot(plugin_id: str, *, data_dir: str) -> dict[str, Any]:
    snap_path = Path(data_dir) / "plugins" / f"{plugin_id}.snapshot.json"
    if not snap_path.exists():
        raise FileNotFoundError(
            f"Plugin snapshot not found: {snap_path}. "
            f"Run: canary collect plugin --id {plugin_id} --real"
        )
    payload = _read_json(snap_path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid snapshot JSON for plugin '{plugin_id}'")
    return payload


def _scm_to_url(val: object) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        v = val.strip()
        return v or None
    if isinstance(val, dict):
        link = val.get("link") or val.get("url")
        if isinstance(link, str):
            v = link.strip()
            return v or None
    return None


def _infer_repo_url(snapshot: dict[str, Any]) -> str | None:
    url = _scm_to_url(snapshot.get("repo_url"))
    if url:
        return url

    scm = snapshot.get("scm_url")
    url = _scm_to_url(scm)
    if url:
        return url

    plugin_api = snapshot.get("plugin_api")
    if isinstance(plugin_api, dict):
        url = _scm_to_url(plugin_api.get("scm"))
        if url:
            return url

    return None


def _normalize_origin_url(repo_url: str) -> str:
    text = repo_url.strip()
    if text.endswith(".git"):
        text = text[:-4]
    return text.rstrip("/")


def _safe_slug(plugin_id: str) -> str:
    return plugin_id.strip().replace("/", "_")


def _validate_http_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Software Heritage requests require an absolute https URL.")
    if parsed.netloc != "archive.softwareheritage.org":
        raise ValueError("Software Heritage requests must target archive.softwareheritage.org.")


def _http_get_json(url: str, *, timeout_s: float) -> Any:
    _validate_http_url(url)
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "canary/0.1 (+SoftwareHeritage collector)",
        },
    )
    # URL scheme and host are validated above before performing the request.
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def _origin_get_url(origin_url: str) -> str:
    quoted = urllib.parse.quote(origin_url, safe="")
    return f"{SWH_API_BASE}/origin/{quoted}/get/"


def _origin_visits_url(origin_url: str) -> str:
    quoted = urllib.parse.quote(origin_url, safe="")
    return f"{SWH_API_BASE}/origin/{quoted}/visits/"


def _origin_latest_visit_url(origin_url: str) -> str:
    quoted = urllib.parse.quote(origin_url, safe="")
    return f"{SWH_API_BASE}/origin/{quoted}/visit/latest/?require_snapshot=true"


def _snapshot_url(snapshot_id: str) -> str:
    return f"{SWH_API_BASE}/snapshot/{snapshot_id}/"


def collect_software_heritage_real(
    *,
    plugin_id: str,
    data_dir: str = "data/raw",
    out_dir: str = "data/raw/software_heritage",
    timeout_s: float = 20.0,
    overwrite: bool = False,
) -> dict[str, Any]:
    snapshot = _load_plugin_snapshot(plugin_id, data_dir=data_dir)
    repo_url = _infer_repo_url(snapshot)
    if not repo_url:
        raise RuntimeError(
            f"No repo_url/scm_url found for plugin '{plugin_id}' in its snapshot. "
            "Collect the plugin snapshot first or curate repo_url in the snapshot."
        )

    origin_url = _normalize_origin_url(repo_url)
    out_base = Path(out_dir)
    out_base.mkdir(parents=True, exist_ok=True)

    slug = _safe_slug(plugin_id)

    def out(name: str) -> Path:
        return out_base / f"{slug}.{name}.json"

    origin_path = out("swh_origin")
    visits_path = out("swh_visits")
    latest_visit_path = out("swh_latest_visit")
    snapshot_path = out("swh_snapshot")
    index_path = out_base / f"{slug}.swh_index.json"

    result: dict[str, Any] = {
        "plugin_id": plugin_id,
        "repo_url": repo_url,
        "origin_url": origin_url,
        "collected_at": datetime.now(UTC).isoformat(),
        "files": {},
        "errors": {},
    }

    origin_payload: Any = None
    visits_payload: Any = None
    latest_visit_payload: Any = None
    snapshot_payload: Any = None

    try:
        if overwrite or not _nonempty(origin_path):
            origin_payload = _http_get_json(_origin_get_url(origin_url), timeout_s=timeout_s)
            _write_json(origin_path, origin_payload)
        else:
            origin_payload = _read_json(origin_path)
        result["files"]["origin"] = str(origin_path)
    except Exception as e:
        result["errors"]["origin"] = str(e)

    try:
        if overwrite or not _nonempty(visits_path):
            visits_payload = _http_get_json(_origin_visits_url(origin_url), timeout_s=timeout_s)
            _write_json(visits_path, visits_payload)
        else:
            visits_payload = _read_json(visits_path)
        result["files"]["visits"] = str(visits_path)
    except Exception as e:
        result["errors"]["visits"] = str(e)

    try:
        if overwrite or not _nonempty(latest_visit_path):
            latest_visit_payload = _http_get_json(
                _origin_latest_visit_url(origin_url), timeout_s=timeout_s
            )
            _write_json(latest_visit_path, latest_visit_payload)
        else:
            latest_visit_payload = _read_json(latest_visit_path)
        result["files"]["latest_visit"] = str(latest_visit_path)
    except Exception as e:
        result["errors"]["latest_visit"] = str(e)

    snapshot_id: str | None = None
    if isinstance(latest_visit_payload, dict):
        visit = latest_visit_payload.get("visit")
        if isinstance(visit, dict):
            snapshot_id = visit.get("snapshot") if isinstance(visit.get("snapshot"), str) else None
        if snapshot_id is None:
            snapshot_id = (
                latest_visit_payload.get("snapshot")
                if isinstance(latest_visit_payload.get("snapshot"), str)
                else None
            )

    if snapshot_id:
        try:
            if overwrite or not _nonempty(snapshot_path):
                snapshot_payload = _http_get_json(_snapshot_url(snapshot_id), timeout_s=timeout_s)
                _write_json(snapshot_path, snapshot_payload)
            else:
                snapshot_payload = _read_json(snapshot_path)
            result["files"]["snapshot"] = str(snapshot_path)
        except Exception as e:
            result["errors"]["snapshot"] = str(e)

    index_payload = {
        "plugin_id": plugin_id,
        "repo_url": repo_url,
        "origin_url": origin_url,
        "collected_at": result["collected_at"],
        "origin_found": "origin" in result["files"],
        "visits_found": "visits" in result["files"],
        "latest_visit_found": "latest_visit" in result["files"],
        "snapshot_found": "snapshot" in result["files"],
        "snapshot_id": snapshot_id,
        "files": result["files"],
        "errors": result["errors"],
    }
    _write_json(index_path, index_payload)
    result["files"]["index"] = str(index_path)

    return result
