"""Tests for canary.collectors.software_heritage_backend."""

from __future__ import annotations

import pytest

from canary.collectors.software_heritage_backend import (
    DEFAULT_API_OUT_DIR,
    DEFAULT_ATHENA_OUT_DIR,
    collect_software_heritage,
    default_out_dir_for_backend,
)


# ---------------------------------------------------------------------------
# default_out_dir_for_backend
# ---------------------------------------------------------------------------


def test_default_out_dir_for_backend_api():
    result = default_out_dir_for_backend("api")
    assert result == DEFAULT_API_OUT_DIR


def test_default_out_dir_for_backend_athena():
    result = default_out_dir_for_backend("athena")
    assert result == DEFAULT_ATHENA_OUT_DIR


def test_default_out_dir_for_backend_invalid():
    with pytest.raises(ValueError, match="Unsupported software heritage backend"):
        default_out_dir_for_backend("s3")


def test_default_out_dir_for_backend_empty():
    with pytest.raises(ValueError, match="Unsupported software heritage backend"):
        default_out_dir_for_backend("")


# ---------------------------------------------------------------------------
# collect_software_heritage - dispatch logic
# ---------------------------------------------------------------------------


def test_collect_software_heritage_dispatches_to_api(monkeypatch):
    called_with: list[dict] = []

    def fake_api(**kwargs):
        called_with.append(dict(kwargs))
        return {"status": "ok", "backend": "api"}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_real",
        fake_api,
    )

    result = collect_software_heritage(
        plugin_id="my-plugin",
        backend="api",
        data_dir="data/raw",
        timeout_s=10.0,
        overwrite=True,
    )

    assert result["backend"] == "api"
    assert len(called_with) == 1
    assert called_with[0]["plugin_id"] == "my-plugin"


def test_collect_software_heritage_dispatches_to_athena(monkeypatch):
    called_with: list[dict] = []

    def fake_athena(**kwargs):
        called_with.append(dict(kwargs))
        return {"status": "ok", "backend": "athena"}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_athena_real",
        fake_athena,
    )

    result = collect_software_heritage(
        plugin_id="my-plugin",
        backend="athena",
        data_dir="data/raw",
        overwrite=False,
    )

    assert result["backend"] == "athena"
    assert len(called_with) == 1
    assert called_with[0]["plugin_id"] == "my-plugin"


def test_collect_software_heritage_uses_default_out_dir_for_api(monkeypatch):
    called_with: list[dict] = []

    def fake_api(**kwargs):
        called_with.append(dict(kwargs))
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_real",
        fake_api,
    )

    collect_software_heritage(plugin_id="my-plugin", backend="api")

    assert called_with[0]["out_dir"] == DEFAULT_API_OUT_DIR


def test_collect_software_heritage_uses_default_out_dir_for_athena(monkeypatch):
    called_with: list[dict] = []

    def fake_athena(**kwargs):
        called_with.append(dict(kwargs))
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_athena_real",
        fake_athena,
    )

    collect_software_heritage(plugin_id="my-plugin", backend="athena")

    assert called_with[0]["out_dir"] == DEFAULT_ATHENA_OUT_DIR


def test_collect_software_heritage_uses_explicit_out_dir(monkeypatch):
    called_with: list[dict] = []

    def fake_api(**kwargs):
        called_with.append(dict(kwargs))
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_real",
        fake_api,
    )

    collect_software_heritage(
        plugin_id="my-plugin",
        backend="api",
        out_dir="/custom/out/dir",
    )

    assert called_with[0]["out_dir"] == "/custom/out/dir"


def test_collect_software_heritage_unknown_backend_raises():
    with pytest.raises(ValueError, match="Unsupported software heritage backend"):
        collect_software_heritage(plugin_id="my-plugin", backend="unknown")


def test_collect_software_heritage_athena_passes_database(monkeypatch):
    called_with: list[dict] = []

    def fake_athena(**kwargs):
        called_with.append(dict(kwargs))
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_athena_real",
        fake_athena,
    )

    collect_software_heritage(
        plugin_id="my-plugin",
        backend="athena",
        database="custom_db",
    )

    assert called_with[0]["database"] == "custom_db"


def test_collect_software_heritage_athena_defaults_database(monkeypatch):
    called_with: list[dict] = []

    def fake_athena(**kwargs):
        called_with.append(dict(kwargs))
        return {}

    monkeypatch.setattr(
        "canary.collectors.software_heritage_backend.collect_software_heritage_athena_real",
        fake_athena,
    )

    collect_software_heritage(plugin_id="my-plugin", backend="athena")

    assert called_with[0]["database"] == "swh_jenkins"
