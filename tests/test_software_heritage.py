"""Tests for canary.collectors.software_heritage (pure helpers + mocked HTTP)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.collectors.software_heritage import (
    SWH_API_BASE,
    _infer_repo_url,
    _nonempty,
    _normalize_origin_url,
    _origin_get_url,
    _origin_latest_visit_url,
    _origin_visits_url,
    _scm_to_url,
    _snapshot_url,
    _validate_http_url,
    collect_software_heritage_real,
)

# ---------------------------------------------------------------------------
# _nonempty
# ---------------------------------------------------------------------------


def test_nonempty_returns_false_for_missing(tmp_path: Path):
    assert _nonempty(tmp_path / "does_not_exist.json") is False


def test_nonempty_returns_false_for_empty_file(tmp_path: Path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    assert _nonempty(p) is False


def test_nonempty_returns_true_for_nonempty_file(tmp_path: Path):
    p = tmp_path / "data.json"
    p.write_text("{}", encoding="utf-8")
    assert _nonempty(p) is True


# ---------------------------------------------------------------------------
# _scm_to_url
# ---------------------------------------------------------------------------


def test_scm_to_url_none():
    assert _scm_to_url(None) is None


def test_scm_to_url_string():
    assert _scm_to_url("https://github.com/org/repo") == "https://github.com/org/repo"


def test_scm_to_url_empty_string():
    assert _scm_to_url("") is None
    assert _scm_to_url("   ") is None


def test_scm_to_url_dict_with_link():
    assert _scm_to_url({"link": "https://github.com/org/repo"}) == "https://github.com/org/repo"


def test_scm_to_url_dict_with_empty_link():
    assert _scm_to_url({"link": ""}) is None


def test_scm_to_url_dict_without_link():
    assert _scm_to_url({"other": "value"}) is None


def test_scm_to_url_non_string_non_dict():
    assert _scm_to_url(42) is None  # type: ignore[arg-type]
    assert _scm_to_url([]) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _infer_repo_url
# ---------------------------------------------------------------------------


def test_infer_repo_url_from_repo_url_field():
    snap = {"repo_url": "https://github.com/org/repo"}
    assert _infer_repo_url(snap) == "https://github.com/org/repo"


def test_infer_repo_url_from_scm_url_string():
    snap = {"scm_url": "https://github.com/org/repo2"}
    assert _infer_repo_url(snap) == "https://github.com/org/repo2"


def test_infer_repo_url_from_scm_url_dict():
    snap = {"scm_url": {"link": "https://github.com/org/repo3"}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo3"


def test_infer_repo_url_from_plugin_api():
    snap = {"plugin_api": {"scm": "https://github.com/org/repo4"}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo4"


def test_infer_repo_url_returns_none_when_missing():
    assert _infer_repo_url({}) is None
    assert _infer_repo_url({"repo_url": None}) is None


# ---------------------------------------------------------------------------
# _normalize_origin_url
# ---------------------------------------------------------------------------


def test_normalize_origin_url_strips_git_suffix():
    assert _normalize_origin_url("https://github.com/org/repo.git") == "https://github.com/org/repo"


def test_normalize_origin_url_strips_trailing_slash():
    assert _normalize_origin_url("https://github.com/org/repo/") == "https://github.com/org/repo"


def test_normalize_origin_url_no_change_needed():
    url = "https://github.com/org/repo"
    assert _normalize_origin_url(url) == url


# ---------------------------------------------------------------------------
# _validate_http_url
# ---------------------------------------------------------------------------


def test_validate_http_url_valid():
    _validate_http_url(f"{SWH_API_BASE}/origin/https://github.com/org/repo/get/")


def test_validate_http_url_wrong_scheme():
    with pytest.raises(ValueError, match="absolute https"):
        _validate_http_url("http://archive.softwareheritage.org/api/1/origin/")


def test_validate_http_url_wrong_host():
    with pytest.raises(ValueError, match="archive.softwareheritage.org"):
        _validate_http_url("https://evil.example.com/api/1/")


# ---------------------------------------------------------------------------
# URL builder helpers
# ---------------------------------------------------------------------------


def test_origin_get_url_encodes_slashes():
    url = _origin_get_url("https://github.com/org/repo")
    assert url.startswith(SWH_API_BASE)
    assert "get" in url


def test_origin_visits_url_contains_visits():
    url = _origin_visits_url("https://github.com/org/repo")
    assert "visits" in url


def test_origin_latest_visit_url_contains_latest():
    url = _origin_latest_visit_url("https://github.com/org/repo")
    assert "latest" in url


def test_snapshot_url_contains_snapshot_id():
    url = _snapshot_url("abc123")
    assert "abc123" in url
    assert "snapshot" in url


# ---------------------------------------------------------------------------
# collect_software_heritage_real — filesystem + HTTP mocked
# ---------------------------------------------------------------------------


def _write_plugin_snapshot(data_dir: Path, plugin_id: str, snap: dict) -> None:
    plugins_dir = data_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / f"{plugin_id}.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")


def test_collect_real_raises_when_no_repo_url(tmp_path: Path):
    _write_plugin_snapshot(
        tmp_path / "data" / "raw",
        "myplugin",
        {"plugin_id": "myplugin", "plugin_api": {}},
    )
    with pytest.raises(RuntimeError, match="No repo_url"):
        collect_software_heritage_real(
            plugin_id="myplugin",
            data_dir=str(tmp_path / "data" / "raw"),
            out_dir=str(tmp_path / "out"),
        )


def test_collect_real_writes_files_and_returns_result(tmp_path: Path, monkeypatch):
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "myplugin",
        {"plugin_id": "myplugin", "repo_url": "https://github.com/org/myplugin"},
    )

    origin_payload = {"url": "https://github.com/org/myplugin"}
    visits_payload = [{"visit": 1, "date": "2024-01-01"}]
    latest_visit_payload = {"snapshot": "snap-abc123"}
    snapshot_payload = {"id": "snap-abc123", "branches": {}}

    call_order = []

    def fake_http_get(url: str, *, timeout_s: float = 20.0):
        call_order.append(url)
        if "get/" in url and "visit" not in url:
            return origin_payload
        if "visits/" in url and "latest" not in url:
            return visits_payload
        if "latest" in url:
            return latest_visit_payload
        if "snapshot" in url:
            return snapshot_payload
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage._http_get_json",
        fake_http_get,
    )

    result = collect_software_heritage_real(
        plugin_id="myplugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        timeout_s=5.0,
        overwrite=True,
    )

    assert result["plugin_id"] == "myplugin"
    assert "origin" in result["files"]
    assert "visits" in result["files"]
    assert "latest_visit" in result["files"]
    assert not result["errors"]


def test_collect_real_reads_cached_files_without_http(tmp_path: Path, monkeypatch):
    """If files already exist and overwrite=False, no HTTP calls should be made."""
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "cached-plugin",
        {"plugin_id": "cached-plugin", "repo_url": "https://github.com/org/cached-plugin"},
    )

    # Pre-populate output files
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = "cached-plugin"
    (out_dir / f"{slug}.swh_origin.json").write_text('{"url": "x"}', encoding="utf-8")
    (out_dir / f"{slug}.swh_visits.json").write_text('[{"visit":1}]', encoding="utf-8")
    (out_dir / f"{slug}.swh_latest_visit.json").write_text('{"snapshot": null}', encoding="utf-8")

    http_calls: list[str] = []

    def fake_http_get(url: str, *, timeout_s: float = 20.0):
        http_calls.append(url)
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage._http_get_json",
        fake_http_get,
    )

    result = collect_software_heritage_real(
        plugin_id="cached-plugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=False,
    )

    assert http_calls == [], "Should not make HTTP calls when all files exist"
    assert "origin" in result["files"]
    assert "visits" in result["files"]


def test_collect_real_handles_http_errors_gracefully(tmp_path: Path, monkeypatch):
    data_raw = tmp_path / "data" / "raw"
    out_dir = tmp_path / "out"
    _write_plugin_snapshot(
        data_raw,
        "error-plugin",
        {"plugin_id": "error-plugin", "repo_url": "https://github.com/org/error-plugin"},
    )

    def fake_http_get(url: str, *, timeout_s: float = 20.0):
        raise RuntimeError("Network error")

    monkeypatch.setattr(
        "canary.collectors.software_heritage._http_get_json",
        fake_http_get,
    )

    result = collect_software_heritage_real(
        plugin_id="error-plugin",
        data_dir=str(data_raw),
        out_dir=str(out_dir),
        overwrite=True,
    )

    # Errors should be captured, not raised
    assert "origin" in result["errors"]
    assert "visits" in result["errors"]
