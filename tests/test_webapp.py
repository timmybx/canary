from __future__ import annotations

from io import BytesIO

import pytest  # pyright: ignore[reportMissingImports]

import canary.webapp as webapp
from canary.webapp import _load_plugin_choices, app, render_page


def _run_app(method: str, path: str, body: bytes = b"") -> tuple[str, list[tuple[str, str]], bytes]:
    status: str | None = None
    headers: list[tuple[str, str]] = []

    def start_response(resp_status: str, resp_headers: list[tuple[str, str]]) -> None:
        nonlocal status, headers
        status = resp_status
        headers = resp_headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    response = b"".join(app(environ, start_response))
    assert status is not None
    return (status, headers, response)


def test_health_endpoint():
    status, headers, body = _run_app("GET", "/health")
    assert status == "200 OK"
    assert ("Content-Type", "application/json; charset=utf-8") in headers
    assert body == b'{"status": "ok"}'


def test_index_renders_console():
    status, headers, body = _run_app("GET", "/")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert ("Content-Type", "text/html; charset=utf-8") in headers
    assert "CANARY Web Console" in text
    assert "Score a plugin" in text
    assert "Data collection" in text


def test_render_page_shows_errors():
    html = render_page(
        {
            "plugin": "",
            "data_dir": "data/raw",
            "real": True,
            "command": "collect-registry",
            "overwrite": False,
            "out_dir": "data/raw/plugins",
            "registry_path": "data/raw/registry/plugins.jsonl",
            "max_plugins": "",
            "sleep": "0",
            "repo_url": "",
            "timeout_s": "30",
            "page_size": "2500",
            "raw_out": "",
            "out_name": "plugins.jsonl",
            "github_out_dir": "data/raw/github",
            "github_timeout_s": "20",
            "github_max_pages": "5",
            "github_commits_days": "365",
            "only": "",
            "healthscore_timeout_s": "30",
        },
        score_error="boom",
    )
    assert "boom" in html
    assert "Prefer real advisory data" in html


def test_static_logo_route():
    status, headers, body = _run_app("GET", "/static/canary-logo.png")
    assert status == "200 OK"
    assert any(name == "Content-Type" and value == "image/png" for name, value in headers)
    assert body[:8] == b"\x89PNG\r\n\x1a\n"


def test_index_includes_logo_and_favicon():
    status, headers, body = _run_app("GET", "/")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "/static/canary-logo.png" in text
    assert "/static/favicon.ico" in text


def test_load_plugin_choices_reads_registry(tmp_path):
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        """{"plugin_id": "cucumber-reports"}
{"plugin_id": "workflow-cps"}
{"plugin_id": "cucumber-reports"}
""",
        encoding="utf-8",
    )

    assert _load_plugin_choices(str(registry)) == ["cucumber-reports", "workflow-cps"]


def test_render_page_includes_plugin_autocomplete_and_readonly_fields():
    html = render_page(
        {
            "plugin": "cucumber-reports",
            "data_dir": "data/raw",
            "real": True,
            "command": "collect-registry",
            "overwrite": False,
            "out_dir": "data/raw/plugins",
            "registry_path": "data/raw/registry/plugins.jsonl",
            "max_plugins": "",
            "sleep": "0",
            "repo_url": "",
            "timeout_s": "30",
            "page_size": "2500",
            "raw_out": "",
            "out_name": "plugins.jsonl",
            "github_out_dir": "data/raw/github",
            "github_timeout_s": "20",
            "github_max_pages": "5",
            "github_commits_days": "365",
            "only": "",
            "healthscore_timeout_s": "30",
        },
        plugin_options=["cucumber-reports", "workflow-cps"],
    )
    assert 'datalist id="plugin-list"' in html
    assert 'value="cucumber-reports"' in html
    assert 'data-plugin-input="true"' in html
    assert "readonly" in html
    assert "Unknown plugin IDs are blocked." in html


def test_load_metrics_action_loads_metrics_from_models_root(tmp_path, monkeypatch):
    models_root = (tmp_path / "models").resolve()
    run_dir = models_root / "baseline_6m"
    run_dir.mkdir(parents=True)
    (run_dir / "metrics.json").write_text('{"accuracy": 0.91}', encoding="utf-8")
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", models_root)
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT_PARTS", ("data", "processed", "models"))

    result = webapp._run_load_metrics_action({"model_out_dir": "data/processed/models/baseline_6m"})

    assert result["metrics"] == {"accuracy": 0.91}
    assert result["metrics_path"] == str(run_dir / "metrics.json")


def test_load_metrics_action_rejects_paths_outside_models_root(tmp_path, monkeypatch):
    models_root = (tmp_path / "models").resolve()
    models_root.mkdir(parents=True)
    outside_dir = (tmp_path / "outside").resolve()
    outside_dir.mkdir()
    (outside_dir / "metrics.json").write_text('{"accuracy": 0.42}', encoding="utf-8")
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", models_root)
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT_PARTS", ("data", "processed", "models"))

    with pytest.raises(ValueError, match="must stay under"):
        webapp._run_load_metrics_action({"model_out_dir": "../outside"})
