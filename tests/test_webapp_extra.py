"""Additional tests for canary.webapp helper functions and routes."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

import canary.webapp as webapp
from canary.scoring.baseline import ScoreResult
from canary.webapp import (
    _bool_from_form,
    _checkbox,
    _escape,
    _input_text,
    _merge_defaults,
    _metric_value,
    _model_output_dir_parts,
    _optional_str,
    _plugin_known,
    _render_confusion_matrix,
    _render_ml_metrics,
    _select,
    parse_form,
    render_page,
)

# ---------------------------------------------------------------------------
# _escape
# ---------------------------------------------------------------------------


def test_escape_plain_text():
    assert _escape("hello") == "hello"


def test_escape_html_entities():
    assert "&amp;" in _escape("a&b")
    assert "&lt;" in _escape("<script>")
    assert "&gt;" in _escape(">")


def test_escape_quotes():
    # quote=True escapes double quotes
    assert "&quot;" in _escape('"quoted"')


def test_escape_non_string():
    # Should convert to string first
    result = _escape(42)
    assert result == "42"


# ---------------------------------------------------------------------------
# _bool_from_form
# ---------------------------------------------------------------------------


def test_bool_from_form_truthy():
    assert _bool_from_form("1") is True
    assert _bool_from_form("true") is True
    assert _bool_from_form("True") is True
    assert _bool_from_form("on") is True
    assert _bool_from_form("yes") is True
    assert _bool_from_form("YES") is True


def test_bool_from_form_falsy():
    assert _bool_from_form("0") is False
    assert _bool_from_form("false") is False
    assert _bool_from_form("") is False
    assert _bool_from_form("off") is False
    assert _bool_from_form("no") is False


# ---------------------------------------------------------------------------
# _optional_str
# ---------------------------------------------------------------------------


def test_optional_str_non_empty():
    assert _optional_str("hello") == "hello"


def test_optional_str_strips_whitespace():
    assert _optional_str("  hello  ") == "hello"


def test_optional_str_empty():
    assert _optional_str("") is None
    assert _optional_str("   ") is None


# ---------------------------------------------------------------------------
# _merge_defaults
# ---------------------------------------------------------------------------


def test_merge_defaults_returns_defaults_with_no_form():
    result = _merge_defaults()
    assert result["active_tab"] == "score"
    assert result["real"] is True


def test_merge_defaults_applies_form_values():
    result = _merge_defaults(
        {"plugin": "my-plugin", "score_model_dir": "data/processed/models/run"}
    )
    assert result["plugin"] == "my-plugin"
    assert result["score_model_dir"] == "data/processed/models/run"


def test_merge_defaults_handles_bool_fields():
    result = _merge_defaults({"real": "false", "overwrite": "true"})
    assert result["real"] is False
    assert result["overwrite"] is True


def test_merge_defaults_uses_default_for_missing_keys():
    result = _merge_defaults({"plugin": "test"})
    assert result["model_out_dir"] == "data/processed/models/baseline_6m"
    assert result["plugin"] == "test"


# ---------------------------------------------------------------------------
# _input_text
# ---------------------------------------------------------------------------


def test_input_text_basic():
    html = _input_text("myfield", "My Label", "my-value")
    assert 'name="myfield"' in html
    assert 'value="my-value"' in html
    assert "My Label" in html


def test_input_text_readonly():
    html = _input_text("myfield", "My Label", "my-value", readonly=True)
    assert "readonly" in html
    assert "Shown for reference only." in html


def test_input_text_not_readonly():
    html = _input_text("myfield", "My Label", "my-value", readonly=False)
    assert "readonly" not in html


def test_input_text_placeholder():
    html = _input_text("myfield", "My Label", "", "some placeholder")
    assert 'placeholder="some placeholder"' in html


def test_input_text_input_type():
    html = _input_text("myfield", "My Label", "2025-01", input_type="month")
    assert 'type="month"' in html


def test_input_text_escapes_value():
    html = _input_text("myfield", "My Label", '<script>alert("xss")</script>')
    assert "<script>" not in html


# ---------------------------------------------------------------------------
# _checkbox
# ---------------------------------------------------------------------------


def test_checkbox_checked():
    html = _checkbox("my-checkbox", "My Checkbox", True)
    assert "checked" in html
    assert "My Checkbox" in html
    assert 'name="my-checkbox"' in html


def test_checkbox_unchecked():
    html = _checkbox("my-checkbox", "My Checkbox", False)
    assert 'type="checkbox"' in html
    # Should not have "checked" attribute
    assert "checked" not in html or " checked" not in html


# ---------------------------------------------------------------------------
# _select
# ---------------------------------------------------------------------------


def test_select_basic():
    html = _select("myselect", "My Select", "a", [("a", "Option A"), ("b", "Option B")])
    assert 'name="myselect"' in html
    assert "Option A" in html
    assert "Option B" in html
    assert "My Select" in html


def test_select_marks_current():
    html = _select("myselect", "My Select", "b", [("a", "Option A"), ("b", "Option B")])
    # "b" should be selected
    assert "selected" in html
    assert 'value="b"' in html


# ---------------------------------------------------------------------------
# _metric_value
# ---------------------------------------------------------------------------


def test_metric_value_none():
    assert _metric_value(None) == "n/a"


def test_metric_value_float():
    assert _metric_value(0.75) == "0.750"


def test_metric_value_float_digits():
    assert _metric_value(0.75123, digits=2) == "0.75"


def test_metric_value_int():
    assert _metric_value(42) == "42"


def test_metric_value_string():
    assert _metric_value("some_string") == "some_string"


# ---------------------------------------------------------------------------
# _render_confusion_matrix
# ---------------------------------------------------------------------------


def test_render_confusion_matrix_valid():
    confusion = [[50, 10], [5, 35]]
    html = _render_confusion_matrix(confusion)
    assert "50" in html
    assert "10" in html
    assert "5" in html
    assert "35" in html
    assert "True negative" in html
    assert "True positive" in html


def test_render_confusion_matrix_invalid_type():
    html = _render_confusion_matrix("not a list")
    assert "<pre>" in html


def test_render_confusion_matrix_wrong_length():
    html = _render_confusion_matrix([[1, 2, 3]])
    assert "<pre>" in html


def test_render_confusion_matrix_none():
    html = _render_confusion_matrix(None)
    assert "<pre>" in html


# ---------------------------------------------------------------------------
# _render_ml_metrics
# ---------------------------------------------------------------------------


def test_render_ml_metrics_no_metrics():
    html = _render_ml_metrics(None)
    assert "Train a baseline" in html


def test_render_ml_metrics_with_metrics():
    metrics = {
        "roc_auc": 0.75,
        "average_precision": 0.5,
        "train_row_count": 1000,
        "test_row_count": 200,
        "feature_count": 30,
        "ranking_metrics": {"precision_at_10": 0.6},
        "top_positive_features": [{"feature": "feature_a", "coefficient": 0.5}],
        "top_negative_features": [{"feature": "feature_b", "coefficient": -0.3}],
        "confusion_matrix": [[90, 10], [5, 45]],
    }
    html = _render_ml_metrics(metrics)
    assert "ROC AUC" in html
    assert "0.750" in html
    assert "feature_a" in html
    assert "feature_b" in html


def test_render_ml_metrics_with_empty_features():
    metrics = {
        "roc_auc": 0.8,
        "top_positive_features": [],
        "top_negative_features": [],
    }
    html = _render_ml_metrics(metrics)
    assert "No features found." in html
    assert "No negative coefficients found." in html


# ---------------------------------------------------------------------------
# _model_output_dir_parts
# ---------------------------------------------------------------------------


def test_model_output_dir_parts_empty_raises():
    with pytest.raises(ValueError, match="Please choose"):
        _model_output_dir_parts("")


def test_model_output_dir_parts_absolute_raises():
    with pytest.raises(ValueError, match="must stay under"):
        _model_output_dir_parts("/absolute/path")


def test_model_output_dir_parts_dotdot_raises():
    with pytest.raises(ValueError, match="must stay under"):
        _model_output_dir_parts("../outside")


def test_model_output_dir_parts_valid(monkeypatch):
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT_PARTS", ("data", "processed", "models"))
    result = _model_output_dir_parts("data/processed/models/baseline_6m")
    assert result == ("baseline_6m",)


def test_model_output_dir_parts_invalid_chars_raise(monkeypatch):
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT_PARTS", ("data", "processed", "models"))
    with pytest.raises(ValueError):
        _model_output_dir_parts("data/processed/models/../../../etc")


# ---------------------------------------------------------------------------
# parse_form
# ---------------------------------------------------------------------------


def test_parse_form_basic():
    body = b"plugin=cucumber-reports&real=true"
    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    result = parse_form(environ)
    assert result["plugin"] == "cucumber-reports"
    assert result["real"] == "true"


def test_parse_form_empty_body():
    environ = {
        "CONTENT_LENGTH": "0",
        "wsgi.input": BytesIO(b""),
    }
    result = parse_form(environ)
    assert result == {}


def test_parse_form_no_content_length():
    environ = {
        "CONTENT_LENGTH": "",
        "wsgi.input": BytesIO(b""),
    }
    result = parse_form(environ)
    assert result == {}


def test_parse_form_multi_value_returns_last():
    body = b"plugin=first&plugin=second"
    environ = {
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    result = parse_form(environ)
    assert result["plugin"] == "second"


def test_parse_form_invalid_content_length():
    body = b"plugin=test"
    environ = {
        "CONTENT_LENGTH": "notanumber",
        "wsgi.input": BytesIO(body),
    }
    result = parse_form(environ)
    assert result == {}


# _plugin_known
# ---------------------------------------------------------------------------


def test_plugin_known_empty_plugin():
    assert _plugin_known("", "nonexistent/registry.jsonl") is False


def test_plugin_known_no_registry_file():
    # If registry file doesn't exist, return True (allow any plugin)
    result = _plugin_known("my-plugin", "/nonexistent/path/registry.jsonl")
    assert result is True


def test_plugin_known_in_registry(tmp_path: Path):
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "cucumber-reports"}\n{"plugin_id": "workflow-cps"}\n',
        encoding="utf-8",
    )
    assert _plugin_known("cucumber-reports", str(registry)) is True
    assert _plugin_known("unknown-plugin", str(registry)) is False


# ---------------------------------------------------------------------------
# render_page — tab switching
# ---------------------------------------------------------------------------


def test_render_page_score_tab_default():
    html = render_page({})
    assert "Score a plugin" in html or "Plugin risk score" in html or "scoring" in html.lower()


def test_render_page_data_tab():
    html = render_page({"active_tab": "data"})
    assert "Score a plugin" in html


def test_render_page_ml_tab():
    html = render_page({"active_tab": "ml"})
    assert "Train" in html or "baseline" in html.lower()


def test_render_page_score_result_shown():
    result = {
        "plugin": "my-plugin",
        "score": 42,
        "reasons": ["reason one", "reason two"],
        "features": {},
        "data_files": [],
        "pretty_json": "{}",
        "pretty_features": "{}",
    }
    html = render_page({}, score_result=result)
    assert "42" in html


def test_render_page_score_error_shown():
    html = render_page({}, score_error="Something went wrong")
    assert "Something went wrong" in html


def test_render_page_score_error_escaped():
    # XSS: error message should be HTML-escaped
    html = render_page({}, score_error='<script>alert("xss")</script>')
    # The error should appear HTML-escaped, not raw
    assert "&lt;script&gt;" in html
    # The unescaped XSS payload should not appear in the notice element
    assert '<div class="notice"><script>' not in html


def test_render_page_contains_csrf_free_form():
    html = render_page({})
    assert "<form" in html


# ---------------------------------------------------------------------------
# WSGI app routes
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


def test_app_score_tab_query_param():
    status, _, body = _run_app("GET", "/", query_string="tab=score")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "CANARY" in text


def test_app_data_tab_query_param():
    status, _, body = _run_app("GET", "/", query_string="tab=data")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "Score a plugin" in text


def test_app_ml_tab_query_param():
    status, _, body = _run_app("GET", "/", query_string="tab=ml")
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "Train" in text or "ml" in text.lower()


def test_app_static_favicon():
    status, headers, body = _run_app("GET", "/static/favicon.ico")
    # Should serve static file or 404 if missing
    assert status in {"200 OK", "404 Not Found"}


def test_app_static_path_traversal_blocked():
    status, _, body = _run_app("GET", "/static/../webapp.py")
    assert status == "404 Not Found"


def test_app_post_score_empty_plugin():
    body = b"plugin=&real=true"
    status, headers, response = _run_app("POST", "/score", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert response == b""


def test_app_post_score_unknown_plugin(tmp_path, monkeypatch):
    # Create a registry with only known plugins
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "known-plugin"}\n', encoding="utf-8")

    body = f"plugin=totally-unknown-plugin&real=true&registry_path={registry}".encode()
    status, headers, response = _run_app("POST", "/score", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m",
    ) in headers
    assert response == b""


def test_app_get_score_query_renders_result(monkeypatch):
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
    monkeypatch.setattr(webapp, "_plugin_known", lambda plugin, registry_path: True)

    status, _, response = _run_app("GET", "/", query_string="tab=score&plugin=known-plugin")
    text = response.decode("utf-8")

    assert status == "200 OK"
    assert "known-plugin" in text
    assert "fixture reason" in text
    assert "37" in text


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


def test_app_post_run_collect_registry():
    """POST to /run is disabled in the public webapp."""
    body = b"command=collect-registry&real=false&page_size=10"
    status, _, response = _run_app("POST", "/run", body)
    assert status == "404 Not Found"
    assert response == b"Not found"


def test_app_post_run_collect_github_missing_plugin():
    body = b"command=collect-github&plugin="
    status, _, response = _run_app("POST", "/run", body)
    text = response.decode("utf-8")
    assert status == "404 Not Found"
    assert text == "Not found"
