"""Additional tests for canary.collectors.software_heritage — covering gaps."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from canary.collectors.software_heritage import (
    SWH_API_BASE,
    _http_get_json,
    _load_plugin_snapshot,
    _scm_to_url,
    collect_software_heritage_real,
)

_SWH_VALID_URL = f"{SWH_API_BASE}/origin/https%3A%2F%2Fgithub.com%2Forg%2Frepo/get/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _write_plugin_snapshot(data_dir: Path, plugin_id: str, content: object) -> None:
    plugins_dir = data_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / f"{plugin_id}.snapshot.json").write_text(json.dumps(content), encoding="utf-8")


# ---------------------------------------------------------------------------
# _scm_to_url — "url" fallback key (not covered by existing tests)
# ---------------------------------------------------------------------------


def test_scm_to_url_dict_with_url_key():
    assert _scm_to_url({"url": "https://github.com/org/repo"}) == "https://github.com/org/repo"


def test_scm_to_url_dict_url_key_empty():
    assert _scm_to_url({"url": ""}) is None


def test_scm_to_url_dict_url_key_whitespace():
    assert _scm_to_url({"url": "   "}) is None


# ---------------------------------------------------------------------------
# _http_get_json
# ---------------------------------------------------------------------------


def test_http_get_json_success(monkeypatch):
    payload = {"url": "https://github.com/org/repo"}
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeResponse(json.dumps(payload).encode()),
    )
    result = _http_get_json(_SWH_VALID_URL, timeout_s=5.0)
    assert result == payload


def test_http_get_json_propagates_url_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(urllib.error.URLError):
        _http_get_json(_SWH_VALID_URL, timeout_s=5.0)


def test_http_get_json_propagates_json_decode_error(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=None: _FakeResponse(b"not-valid-json!!!"),
    )
    with pytest.raises(json.JSONDecodeError):
        _http_get_json(_SWH_VALID_URL, timeout_s=5.0)


def test_http_get_json_rejects_invalid_url():
    with pytest.raises(ValueError, match="archive.softwareheritage.org"):
        _http_get_json("https://evil.example.com/api/1/", timeout_s=5.0)


# ---------------------------------------------------------------------------
# _load_plugin_snapshot
# ---------------------------------------------------------------------------


def test_load_plugin_snapshot_returns_dict(tmp_path: Path):
    snap = {"plugin_id": "myplugin", "repo_url": "https://github.com/org/repo"}
    _write_plugin_snapshot(tmp_path, "myplugin", snap)
    result = _load_plugin_snapshot("myplugin", data_dir=str(tmp_path))
    assert result == snap


def test_load_plugin_snapshot_raises_file_not_found(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="snapshot not found"):
        _load_plugin_snapshot("nonexistent", data_dir=str(tmp_path))


def test_load_plugin_snapshot_raises_on_non_dict(tmp_path: Path):
    _write_plugin_snapshot(tmp_path, "myplugin", ["this", "is", "a", "list"])
    with pytest.raises(RuntimeError, match="Invalid snapshot JSON"):
        _load_plugin_snapshot("myplugin", data_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Snapshot ID extraction branches in collect_software_heritage_real
# ---------------------------------------------------------------------------


def _setup_collection(tmp_path: Path, monkeypatch, latest_visit_payload: dict):
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "myplugin",
        {"plugin_id": "myplugin", "repo_url": "https://github.com/org/myplugin"},
    )

    def fake_http_get(url: str, *, timeout_s: float = 20.0):
        if "/visit/latest/" in url:
            return latest_visit_payload
        if "/visits/" in url:
            return [{"visit": 1}]
        if "/snapshot/" in url:
            return {"id": "snap123", "branches": {}}
        return {"url": url}

    monkeypatch.setattr("canary.collectors.software_heritage._http_get_json", fake_http_get)
    return data_raw, out_dir


def test_collect_real_snapshot_id_from_nested_visit_dict(tmp_path: Path, monkeypatch):
    """Snapshot ID from latest_visit_payload['visit']['snapshot'] (nested path)."""
    data_raw, out_dir = _setup_collection(tmp_path, monkeypatch, {"visit": {"snapshot": "snap123"}})

    result = collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )
    assert "snapshot" in result["files"]
    assert not result["errors"].get("snapshot")


def test_collect_real_snapshot_id_visit_dict_not_string_falls_through(tmp_path: Path, monkeypatch):
    """Non-string snapshot in visit dict → falls through to top-level check."""
    data_raw, out_dir = _setup_collection(
        tmp_path, monkeypatch, {"visit": {"snapshot": 12345}, "snapshot": "snap-fallback"}
    )

    result = collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )
    assert "snapshot" in result["files"]


def test_collect_real_no_snapshot_id_skips_snapshot_fetch(tmp_path: Path, monkeypatch):
    """When snapshot ID is None, the snapshot endpoint is not fetched."""
    data_raw, out_dir = _setup_collection(tmp_path, monkeypatch, {"snapshot": None})
    http_calls: list[str] = []

    def tracking_http_get(url: str, *, timeout_s: float = 20.0):
        http_calls.append(url)
        if "/visit/latest/" in url:
            return {"snapshot": None}
        if "/visits/" in url:
            return [{"visit": 1}]
        return {"url": url}

    monkeypatch.setattr("canary.collectors.software_heritage._http_get_json", tracking_http_get)

    result = collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )
    assert "snapshot" not in result["files"]
    assert not any("/snapshot/" in u for u in http_calls)


# ---------------------------------------------------------------------------
# Index JSON fields
# ---------------------------------------------------------------------------


def test_collect_real_index_has_all_fields(tmp_path: Path, monkeypatch):
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "myplugin",
        {"plugin_id": "myplugin", "repo_url": "https://github.com/org/myplugin"},
    )
    monkeypatch.setattr(
        "canary.collectors.software_heritage._http_get_json",
        lambda url, *, timeout_s: {"url": url},
    )

    result = collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )
    index_path = Path(result["files"]["index"])
    assert index_path.exists()
    index = json.loads(index_path.read_text(encoding="utf-8"))
    for key in (
        "plugin_id",
        "repo_url",
        "origin_url",
        "collected_at",
        "origin_found",
        "visits_found",
        "latest_visit_found",
        "snapshot_found",
        "snapshot_id",
        "files",
        "errors",
    ):
        assert key in index, f"Missing key in index: {key}"


# ---------------------------------------------------------------------------
# overwrite=True refetches even when files exist
# ---------------------------------------------------------------------------


def test_collect_real_overwrite_true_refetches_cached_files(tmp_path: Path, monkeypatch):
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "myplugin",
        {"plugin_id": "myplugin", "repo_url": "https://github.com/org/myplugin"},
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "myplugin.swh_origin.json").write_text('{"url": "cached"}', encoding="utf-8")
    (out_dir / "myplugin.swh_visits.json").write_text('[{"visit": 1}]', encoding="utf-8")
    (out_dir / "myplugin.swh_latest_visit.json").write_text('{"snapshot": null}', encoding="utf-8")

    http_calls: list[str] = []

    def fake_http_get(url: str, *, timeout_s: float = 20.0):
        http_calls.append(url)
        return {}

    monkeypatch.setattr("canary.collectors.software_heritage._http_get_json", fake_http_get)

    collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )
    assert len(http_calls) >= 3, "Should refetch all endpoints when overwrite=True"
