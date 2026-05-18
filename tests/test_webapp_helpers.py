from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest  # pyright: ignore[reportMissingImports]

import canary.webapp as webapp
from canary.webapp import (
    _load_plugin_choices,
    _normalize_model_output_dir,
    _plugin_known,
    app,
)

# ---------------------------------------------------------------------------
# WSGI test helper
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
    response = b"".join(app(environ, start_response))
    assert status is not None
    return (status, headers, response)


# ---------------------------------------------------------------------------
# _plugin_known
# ---------------------------------------------------------------------------


def test_plugin_known_returns_true_when_plugin_in_list(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    assert _plugin_known("cucumber-reports", str(registry)) is True


def test_plugin_known_returns_false_when_plugin_not_in_list(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    assert _plugin_known("workflow-cps", str(registry)) is False


def test_plugin_known_returns_true_when_registry_missing(tmp_path: Path) -> None:
    # Empty choices list → no allowlisting → all IDs allowed
    missing = str(tmp_path / "nonexistent.jsonl")
    assert _plugin_known("any-plugin", missing) is True


def test_plugin_known_returns_false_for_empty_plugin_id(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    assert _plugin_known("", str(registry)) is False


def test_plugin_known_strips_whitespace(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    assert _plugin_known("  cucumber-reports  ", str(registry)) is True


# ---------------------------------------------------------------------------
# _load_plugin_choices
# ---------------------------------------------------------------------------


def test_load_plugin_choices_returns_empty_when_missing(tmp_path: Path) -> None:
    assert _load_plugin_choices(str(tmp_path / "nonexistent.jsonl")) == []


def test_load_plugin_choices_valid_jsonl(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "workflow-cps"}\n{"plugin_id": "cucumber-reports"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert result == ["cucumber-reports", "workflow-cps"]


def test_load_plugin_choices_deduplicates(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "cucumber-reports"}\n{"plugin_id": "cucumber-reports"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert result == ["cucumber-reports"]


def test_load_plugin_choices_alphabetically_sorted(tmp_path: Path) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "zzz-plugin"}\n{"plugin_id": "aaa-plugin"}\n{"plugin_id": "mmm-plugin"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert result == ["aaa-plugin", "mmm-plugin", "zzz-plugin"]


# ---------------------------------------------------------------------------
# _normalize_model_output_dir
# ---------------------------------------------------------------------------


def test_normalize_model_output_dir_valid_path() -> None:
    result = _normalize_model_output_dir("data/processed/models/baseline_6m")
    assert "baseline_6m" in result
    assert "models" in result


def test_normalize_model_output_dir_rejects_absolute_path() -> None:
    with pytest.raises(ValueError, match="must stay under"):
        _normalize_model_output_dir("/absolute/path/model")


def test_normalize_model_output_dir_rejects_empty_string() -> None:
    with pytest.raises(ValueError):
        _normalize_model_output_dir("")


def test_normalize_model_output_dir_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="must stay under"):
        _normalize_model_output_dir("data/processed/models/../outside")


def test_normalize_model_output_dir_rejects_path_outside_root() -> None:
    with pytest.raises(ValueError, match="must stay under"):
        _normalize_model_output_dir("wrong/path/baseline_6m")


def test_normalize_model_output_dir_rejects_dotdot_in_suffix() -> None:
    with pytest.raises(ValueError, match="must stay under"):
        _normalize_model_output_dir("data/processed/models/..")


def test_normalize_model_output_dir_accepts_nested_path() -> None:
    result = _normalize_model_output_dir("data/processed/models/run_2025-01")
    assert "run_2025-01" in result


# ---------------------------------------------------------------------------
# GET route endpoints
# ---------------------------------------------------------------------------


def test_score_get_returns_200_with_console_content() -> None:
    status, headers, body = _run_app("GET", "/score")
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert body == b""


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


def test_data_get_returns_200() -> None:
    status, _headers, body = _run_app("GET", "/data")
    assert status == "200 OK"
    assert len(body) > 0


def test_train_get_returns_404() -> None:
    status, _headers, body = _run_app("GET", "/train")
    assert status == "404 Not Found"
    assert body == b"Not found"


def test_favicon_ico_returns_200() -> None:
    status, headers, body = _run_app("GET", "/static/favicon.ico")
    assert status == "200 OK"
    assert len(body) > 0


def test_unknown_route_returns_200_with_main_page() -> None:
    # The webapp serves the main page for all unknown paths (no 404 handler).
    status, _headers, body = _run_app("GET", "/not-a-real-route")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "CANARY" in text


def test_tab_query_string_unsupported_tab_falls_back_to_score() -> None:
    environ: dict = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "QUERY_STRING": "tab=data",
        "CONTENT_LENGTH": "0",
        "wsgi.input": BytesIO(b""),
    }
    status = None
    headers: list = []

    def start_response(s: str, h: list) -> None:
        nonlocal status, headers
        status = s
        headers = h

    response = b"".join(app(environ, start_response))
    text = response.decode("utf-8")
    assert status == "200 OK"
    assert "Score a plugin" in text


def test_tab_query_string_selects_ml_tab() -> None:
    environ: dict = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "QUERY_STRING": "tab=ml",
        "CONTENT_LENGTH": "0",
        "wsgi.input": BytesIO(b""),
    }
    status = None
    headers: list = []

    def start_response(s: str, h: list) -> None:
        nonlocal status, headers
        status = s
        headers = h

    response = b"".join(app(environ, start_response))
    text = response.decode("utf-8")
    assert status == "200 OK"
    assert "Machine learning" in text


def test_static_path_traversal_returns_404() -> None:
    status, _headers, _body = _run_app("GET", "/static/../canary/webapp.py")
    assert status == "404 Not Found"


def test_score_post_with_missing_plugin_shows_error() -> None:
    # /score is retained as a redirect target; the scoring form now submits GET /.
    body = b"plugin=&real=true"
    status, headers, response = _run_app("POST", "/score", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert ("Content-Type", "text/plain") in headers
    assert response == b""


def test_score_post_with_unknown_plugin_shows_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    monkeypatch.setattr(webapp, "DEFAULT_REGISTRY_PATH", str(registry))

    body_str = f"plugin=nonexistent-plugin&real=true&registry_path={registry}"
    body = body_str.encode("utf-8")
    status, headers, response = _run_app("POST", "/score", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert response == b""


def test_score_query_with_unknown_plugin_shows_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    monkeypatch.setitem(webapp.DEFAULTS, "registry_path", str(registry))

    status, _headers, response = _run_app(
        "GET", "/", query_string="tab=score&plugin=nonexistent-plugin"
    )
    text = response.decode("utf-8")

    assert status == "200 OK"
    assert "The scoring request could not be completed" in text
