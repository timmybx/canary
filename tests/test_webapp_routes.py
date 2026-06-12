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

import pytest

from canary import webapp
from canary.scoring.baseline import ScoreResult
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


@pytest.mark.parametrize("tab", ["nonsense", "data"])
def test_unknown_tab_falls_back_to_score(tab: str):
    status, _, body = _run("GET", "/", query=f"tab={tab}")
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


# ---------------------------------------------------------------------------
# Absorbed app-boundary tests (from test_webapp_extra/_helpers/test_webapp)
# ---------------------------------------------------------------------------


def _run_app(
    method: str, path: str, body: bytes = b"", query_string: str = ""
) -> tuple[str, list[tuple[str, str]], bytes]:
    status: str | None = None
    headers: list[tuple[str, str]] = []

    def start_response(resp_status: str, resp_headers: list[tuple[str, str]]) -> None:
        nonlocal status, headers
        status = resp_status
        headers = resp_headers

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    from canary.webapp import app

    response = b"".join(app(environ, start_response))
    assert status is not None
    return (status, headers, response)


def test_app_post_score_empty_plugin():
    body = b"plugin=&real=true"
    status, headers, response = _run_app("POST", "/score", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert response == b""


def test_app_get_score_query_unknown_plugin_shows_error(tmp_path, monkeypatch):
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "known-plugin"}\n', encoding="utf-8")
    monkeypatch.setitem(webapp.DEFAULTS, "registry_path", str(registry))

    status, _, response = _run_app(
        "GET", "/", query_string="tab=score&plugin=totally-unknown-plugin"
    )
    text = response.decode("utf-8")

    assert status == "200 OK"
    assert "The scoring request could not be completed" in text


def test_app_get_explain_scoring_failure_hides_exception_text(monkeypatch):
    marker = "internal-scoring-message"

    def _raise_scoring(plugin, real):
        raise Exception(marker)

    monkeypatch.setattr(webapp, "score_plugin_baseline", _raise_scoring)

    status, _, response = _run_app(
        "GET", "/", query_string="tab=score&plugin=known-plugin&explain=1"
    )
    text = response.decode("utf-8")

    assert status == "200 OK"
    assert "Unable to score the requested plugin right now." in text
    assert marker not in text


def test_app_get_explain_ai_failure_hides_exception_text(monkeypatch):
    marker = "internal-explain-message"

    monkeypatch.setattr(
        webapp,
        "score_plugin_baseline",
        lambda plugin, real: ScoreResult(
            plugin=plugin,
            score=37,
            reasons=("fixture reason",),
            features={"feature_a": 1},
        ),
    )
    monkeypatch.setattr(webapp, "_get_ml_scorer", lambda model_dir: None)
    monkeypatch.setattr(webapp, "_inject_live_commit_signal", lambda result, plugin: result)

    def _raise_explain(prompt: str):
        raise Exception(marker)

    monkeypatch.setattr(webapp, "_call_anthropic_explain", _raise_explain)

    status, _, response = _run_app(
        "GET", "/", query_string="tab=score&plugin=known-plugin&explain=1"
    )
    text = response.decode("utf-8")

    assert status == "200 OK"
    assert "AI explanation unavailable — use Copy or Open buttons below." in text
    assert marker not in text


def test_app_post_explain_redirects_to_get_route():
    body = b"plugin=workflow-cps&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m"
    status, headers, response = _run_app("POST", "/explain", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m&explain=1",
    ) in headers
    assert ("Location", "/?tab=score&plugin=workflow-cps&explain=1") not in headers
    assert response == b""


def test_app_post_ml_explain_redirects_to_get_route():
    body = b"model_out_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m"
    status, headers, response = _run_app("POST", "/ml_explain", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=ml&model_out_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m&ml_explain=1",
    ) in headers
    assert response == b""


def test_app_get_cs_explain_sets_ai_result(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _render_capture(values: dict[str, object], **kwargs: object) -> str:
        captured["values"] = values
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(webapp, "_prepare_request_state", lambda values: ([], None, []))
    monkeypatch.setattr(
        webapp,
        "_load_model_metrics",
        lambda _model_dir: {
            "train_start_month": "2023-01",
            "test_positive_count": 2,
            "test_unique_plugin_count": 10,
        },
    )
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda _ip: True)
    monkeypatch.setattr(
        webapp,
        "_load_cs_prediction_rows",
        lambda *_args, **_kwargs: (
            "2024-01",
            "2024-07-31",
            [{"plugin_id": "p1", "score": 0.9}],
            [],
        ),
    )
    monkeypatch.setattr(webapp, "_call_anthropic_explain", lambda _prompt: "generated text")
    monkeypatch.setattr(webapp, "render_page", _render_capture)

    status, _, _body = _run_app(
        "GET",
        "/",
        query_string=(
            "tab=casestudy&model_out_dir=data%2Fprocessed%2Fmodels%2Frun_case&cs_explain=1"
        ),
    )

    assert status == "200 OK"
    assert captured["cs_ai_result"] == "generated text"
    assert captured["cs_ai_error"] is None
    assert captured["cs_rate_limited"] is False
    assert isinstance(captured["values"], dict)
    assert captured["values"]["active_tab"] == "casestudy"


def test_app_get_ml_explain_sets_ai_result(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _render_capture(values: dict[str, object], **kwargs: object) -> str:
        captured["values"] = values
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(webapp, "_prepare_request_state", lambda values: ([], None, []))
    monkeypatch.setattr(webapp, "_load_model_metrics", lambda _model_dir: {"test_row_count": 10})
    monkeypatch.setattr(webapp, "_load_precision_at_k", lambda _model_dir: {"scenarios": []})
    monkeypatch.setattr(
        webapp, "_load_feature_selection", lambda _model_dir: {"h3_satisfied": False}
    )
    monkeypatch.setattr(webapp, "_build_ml_explain_prompt", lambda *_args, **_kwargs: "prompt")
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda _ip: True)
    monkeypatch.setattr(webapp, "_call_anthropic_explain", lambda _prompt: "ml generated text")
    monkeypatch.setattr(webapp, "render_page", _render_capture)

    status, _, _body = _run_app(
        "GET",
        "/",
        query_string="tab=ml&model_out_dir=data%2Fprocessed%2Fmodels%2Frun_case&ml_explain=1",
    )

    assert status == "200 OK"
    assert captured["ml_ai_result"] == "ml generated text"
    assert captured["ml_ai_error"] is None
    assert captured["ml_rate_limited"] is False
    assert isinstance(captured["values"], dict)
    assert captured["values"]["active_tab"] == "ml"


def test_app_get_cs_explain_rate_limited_and_error(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _render_capture(values: dict[str, object], **kwargs: object) -> str:
        captured["values"] = values
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(webapp, "_prepare_request_state", lambda values: ([], None, []))
    monkeypatch.setattr(
        webapp,
        "_load_model_metrics",
        lambda _model_dir: {
            "train_start_month": "2023-01",
            "test_positive_count": 2,
            "test_unique_plugin_count": 10,
        },
    )
    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda _ip: False)
    monkeypatch.setattr(webapp, "render_page", _render_capture)

    status, _, _body = _run_app(
        "GET",
        "/",
        query_string=(
            "tab=casestudy&model_out_dir=data%2Fprocessed%2Fmodels%2Frun_case&cs_explain=1"
        ),
    )
    assert status == "200 OK"
    assert captured["cs_rate_limited"] is True
    assert captured["cs_ai_result"] is None
    assert captured["cs_ai_error"] is None

    def _raise_explain(_prompt: str) -> str:
        raise Exception("hidden-internal-message")

    monkeypatch.setattr(webapp, "_check_explain_rate_limit", lambda _ip: True)
    monkeypatch.setattr(
        webapp,
        "_load_cs_prediction_rows",
        lambda *_args, **_kwargs: (
            "2024-01",
            "2024-07-31",
            [{"plugin_id": "p1", "score": 0.9}],
            [],
        ),
    )
    monkeypatch.setattr(webapp, "_call_anthropic_explain", _raise_explain)

    status2, _, _body2 = _run_app(
        "GET",
        "/",
        query_string=(
            "tab=casestudy&model_out_dir=data%2Fprocessed%2Fmodels%2Frun_case&cs_explain=1"
        ),
    )
    assert status2 == "200 OK"
    assert captured["cs_ai_error"] == "AI explanation unavailable — use Copy or Open buttons below."


def test_score_get_with_query_params_redirects_to_score_tab() -> None:
    status, headers, body = _run_app(
        "GET",
        "/score",
        query_string="plugin=cucumber-reports&score_model_dir=data%2Fprocessed%2Fmodels%2Frun",
    )

    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=cucumber-reports&score_model_dir=data%2Fprocessed%2Fmodels%2Frun",
    ) in headers
    assert body == b""


def test_unknown_route_returns_200_with_main_page() -> None:
    # The webapp serves the main page for all unknown paths (no 404 handler).
    status, _headers, body = _run_app("GET", "/not-a-real-route")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "CANARY" in text


def test_favicon_ico_returns_200() -> None:
    status, headers, body = _run_app("GET", "/static/favicon.ico")
    assert status == "200 OK"
    assert len(body) > 0


def test_index_includes_logo_and_favicon():
    status, headers, body = _run_app("GET", "/")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "/static/canary-logo.png" in text
    assert "/static/favicon.ico" in text
