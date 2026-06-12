"""
Route-level behavior tests for the web console, through the WSGI interface.

These pin what the app *does* at its public boundary (request in, response
out) rather than how it is implemented. They patch only true seams — scoring,
the rate limiter, the Anthropic client, metrics loaders — so internal
refactoring of rendering/presentation code should never require touching
this file.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any

from canary import webapp
from canary.webapp import app


def _run(
    method: str,
    path: str,
    *,
    query: str = "",
    body: bytes = b"",
    environ_extra: dict[str, Any] | None = None,
) -> tuple[str, dict[str, str], bytes]:
    status: str | None = None
    headers: list[tuple[str, str]] = []

    def start_response(resp_status: str, resp_headers: list[tuple[str, str]]) -> None:
        nonlocal status, headers
        status = resp_status
        headers = resp_headers

    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    if environ_extra:
        environ.update(environ_extra)
    response = b"".join(app(environ, start_response))
    assert status is not None
    return (status, dict(headers), response)


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------


def test_health_returns_json_ok():
    status, headers, body = _run("GET", "/health")
    assert status == "200 OK"
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert body == b'{"status": "ok"}'


def test_index_serves_console_with_all_tabs():
    status, headers, body = _run("GET", "/")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert "CANARY Web Console" in text
    for tab in ("score", "ml", "about", "casestudy"):
        assert f'data-tab-link="{tab}"' in text


def test_each_tab_renders():
    for tab in ("score", "ml", "about", "casestudy"):
        status, _, body = _run("GET", "/", query=f"tab={tab}")
        assert status == "200 OK"
        assert f'data-tab-panel="{tab}"' in body.decode("utf-8")


def test_unknown_tab_falls_back_to_score():
    status, _, body = _run("GET", "/", query="tab=nonsense")
    assert status == "200 OK"
    assert 'data-tab-panel="score"' in body.decode("utf-8")


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


def test_static_asset_served_with_cache_header():
    status, headers, body = _run("GET", "/static/canary-logo.png")
    assert status == "200 OK"
    assert headers["Content-Type"] == "image/png"
    assert "max-age" in headers.get("Cache-Control", "")
    assert body[:8] == b"\x89PNG\r\n\x1a\n"


def test_static_missing_asset_is_404():
    status, _, body = _run("GET", "/static/does-not-exist.png")
    assert status == "404 Not Found"
    assert body == b"Not found"


def test_static_path_traversal_is_404():
    status, _, body = _run("GET", "/static/../../pyproject.toml")
    assert status == "404 Not Found"
    assert body == b"Not found"


# ---------------------------------------------------------------------------
# Disabled and redirect routes
# ---------------------------------------------------------------------------


def test_run_and_train_are_disabled_for_all_methods():
    for path in ("/run", "/train"):
        for method in ("GET", "POST"):
            status, _, body = _run(method, path)
            assert status == "404 Not Found", f"{method} {path}"
            assert body == b"Not found"


def test_score_redirects_to_get_equivalent():
    status, headers, _ = _run("GET", "/score", query="plugin=demo-plugin")
    assert status == "302 Found"
    assert "tab=score" in headers["Location"]
    assert "plugin=demo-plugin" in headers["Location"]


def test_explain_redirects_with_explain_flag():
    status, headers, _ = _run("GET", "/explain", query="plugin=demo-plugin")
    assert status == "302 Found"
    assert "explain=1" in headers["Location"]


def test_ml_explain_redirects_to_ml_tab():
    status, headers, _ = _run("GET", "/ml_explain", query="model_out_dir=x")
    assert status == "302 Found"
    assert "tab=ml" in headers["Location"]
    assert "ml_explain=1" in headers["Location"]


# ---------------------------------------------------------------------------
# Scoring flow (seams patched; no network, no real model)
# ---------------------------------------------------------------------------


class _StubScore:
    def to_dict(self) -> dict[str, Any]:
        return {"plugin": "demo-plugin", "score": 42, "reasons": ["stub reason"], "features": {}}


def _patch_score_seams(monkeypatch) -> None:
    monkeypatch.setattr(webapp, "_plugin_known", lambda plugin, registry: True)
    monkeypatch.setattr(webapp, "score_plugin_baseline", lambda plugin, real: _StubScore())
    monkeypatch.setattr(webapp, "_inject_live_commit_signal", lambda result, plugin: result)
    monkeypatch.setattr(webapp, "_get_ml_scorer", lambda model_dir: None)


def test_get_scoring_renders_result(monkeypatch):
    _patch_score_seams(monkeypatch)
    status, _, body = _run("GET", "/", query="tab=score&plugin=demo-plugin")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "demo-plugin" in text
    assert "stub reason" in text


def test_get_scoring_unknown_plugin_shows_error_not_traceback(monkeypatch):
    _patch_score_seams(monkeypatch)
    monkeypatch.setattr(webapp, "_plugin_known", lambda plugin, registry: False)
    status, _, body = _run("GET", "/", query="tab=score&plugin=not-a-plugin")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "could not be completed" in text


# ---------------------------------------------------------------------------
# ML explain flow (rate limiting and AI seams)
# ---------------------------------------------------------------------------

_ML_QUERY = "tab=ml&model_out_dir=data/processed/models/test_run&ml_explain=1"


def _patch_ml_explain_seams(monkeypatch) -> None:
    monkeypatch.setattr(webapp, "_load_model_metrics", lambda d: {"model_name": "xgboost"})
    monkeypatch.setattr(webapp, "_load_precision_at_k", lambda d: None)
    monkeypatch.setattr(webapp, "_load_feature_selection", lambda d: None)
    monkeypatch.setattr(webapp, "_build_ml_explain_prompt", lambda m, pk, fs, d: "PROMPT")


def test_ml_explain_rate_limited_shows_message(monkeypatch):
    _patch_ml_explain_seams(monkeypatch)
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda ip: False)
    status, _, body = _run("GET", "/", query=_ML_QUERY)
    assert status == "200 OK"
    assert "Rate limit reached" in body.decode("utf-8")


def test_ml_explain_success_renders_ai_text(monkeypatch):
    _patch_ml_explain_seams(monkeypatch)
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda ip: True)
    monkeypatch.setattr(webapp, "_call_anthropic_explain", lambda prompt: "AI EXPLANATION TEXT")
    status, _, body = _run("GET", "/", query=_ML_QUERY)
    assert status == "200 OK"
    assert "AI EXPLANATION TEXT" in body.decode("utf-8")


def test_ml_explain_api_failure_degrades_gracefully(monkeypatch):
    _patch_ml_explain_seams(monkeypatch)
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda ip: True)

    def _boom(prompt: str) -> str:
        raise RuntimeError("Anthropic API error 500: boom")

    monkeypatch.setattr(webapp, "_call_anthropic_explain", _boom)
    status, _, body = _run("GET", "/", query=_ML_QUERY)
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "AI explanation unavailable" in text
    # The raw API error body must never reach the user.
    assert "boom" not in text


def test_rate_limiter_keyed_on_first_forwarded_ip(monkeypatch):
    _patch_ml_explain_seams(monkeypatch)
    seen: list[str] = []

    def _record(ip: str) -> bool:
        seen.append(ip)
        return False

    monkeypatch.setattr(webapp, "_check_explain_rate_limit", _record)
    _run(
        "GET",
        "/",
        query=_ML_QUERY,
        environ_extra={"HTTP_X_FORWARDED_FOR": "1.2.3.4, 5.6.7.8", "REMOTE_ADDR": "9.9.9.9"},
    )
    assert seen == ["1.2.3.4"]
