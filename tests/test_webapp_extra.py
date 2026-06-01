"""Additional tests for canary.webapp helper functions and routes."""

from __future__ import annotations

import urllib.error
import urllib.request
from email.message import Message
from io import BytesIO
from pathlib import Path

import pytest

import canary.webapp as webapp
from canary.scoring.baseline import ScoreResult
from canary.scoring.ml import FeatureDriver, MLScoreResult
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


def test_render_page_about_tab_exercises_about_content():
    html = render_page({"active_tab": "about"})
    assert "What is CANARY?" in html
    assert "View on GitHub" in html
    assert "Jenkins Security Advisories" in html


def test_render_page_case_study_tab_without_model_selected():
    html = render_page({"active_tab": "casestudy", "model_out_dir": ""}, model_dir_options=[])
    assert "Validated predictions" in html
    assert "Select a model to view results" in html


def test_render_page_case_study_tab_with_missing_predictions_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    model_root = tmp_path / "models"
    model_root.mkdir()
    run_dir = model_root / "run_1"
    run_dir.mkdir()

    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)
    monkeypatch.setattr(webapp, "ADVISORY_DATA_ROOT", tmp_path / "advisories")

    html = render_page(
        {"active_tab": "casestudy", "model_out_dir": "data/processed/models/run_1"},
        model_dir_options=["data/processed/models/run_1"],
    )

    assert "No predictions file found" in html
    assert "test_predictions.csv" in html


def test_render_page_case_study_tab_with_predictions_and_advisories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    model_root = tmp_path / "models"
    run_name = "run_2"
    run_dir = model_root / run_name
    run_dir.mkdir(parents=True)
    advisories_root = tmp_path / "advisories"
    advisories_root.mkdir(parents=True)

    (run_dir / "metrics.json").write_text(
        """{
  "test_start_month": "2024-01",
  "test_positive_count": 1,
  "test_row_count": 2,
  "test_unique_plugin_count": 100
}""",
        encoding="utf-8",
    )
    (run_dir / "test_predictions.csv").write_text(
        "\n".join(
            [
                "plugin_id,month,y_true,y_prob",
                "confirmed-plugin,2024-01,1,0.90",
                "unconfirmed-plugin,2024-01,0,0.40",
                "confirmed-plugin,2024-01,1,0.10",
            ]
        ),
        encoding="utf-8",
    )
    (advisories_root / "confirmed-plugin.advisories.real.jsonl").write_text(
        (
            '{"published_date":"2024-04-15","url":"https://example.test/advisory/1",'
            '"severity_summary":{"max_severity_label":"high","max_cvss_base_score":8.5},'
            '"security_warning_ids":["SECURITY-1234","SECURITY-9999"]}\n'
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)
    monkeypatch.setattr(webapp, "ADVISORY_DATA_ROOT", advisories_root)

    html = render_page(
        {"active_tab": "casestudy", "model_out_dir": f"data/processed/models/{run_name}"},
        model_dir_options=[f"data/processed/models/{run_name}"],
    )

    assert "Top-2 predictions vs. confirmed advisories" in html
    assert "Confirmed predictions" in html
    assert "Unconfirmed predictions" in html
    assert "confirmed-plugin" in html
    assert "SECURITY-1234" in html


def test_app_post_explain_redirects_to_get_route():
    body = b"plugin=workflow-cps&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m"
    status, headers, response = _run_app("POST", "/explain", body)
    assert status == "302 Found"
    assert (
        "Location",
        "/?tab=score&plugin=&score_model_dir=data%2Fprocessed%2Fmodels%2Fbaseline_6m&explain=1",
    ) in headers
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


def test_render_operational_panel_includes_headline_and_callouts():
    html = webapp._render_operational_panel(
        {
            "n_positive": 20,
            "n_test": 1000,
            "base_rate": 0.02,
            "split_strategy": "gt",
            "scenarios": [
                {
                    "label": "Top 10",
                    "k": 10,
                    "true_positives": 6,
                    "precision": 0.95,
                    "recall": 0.3,
                    "lift": 47.5,
                },
                {
                    "label": "Top 25",
                    "k": 25,
                    "true_positives": 9,
                    "precision": 0.72,
                    "recall": 0.45,
                    "lift": 36.0,
                },
                {
                    "label": "Top 50",
                    "k": 50,
                    "true_positives": 12,
                    "precision": 0.50,
                    "recall": 0.6,
                    "lift": 25.0,
                },
            ],
            "recall_targets": [
                {
                    "target_recall": 0.5,
                    "plugins_to_review": 42,
                    "pct_of_ecosystem": 4.2,
                    "true_positives": 10,
                    "precision": 0.24,
                }
            ],
        }
    )
    assert "Operational scenario analysis" in html
    assert "group-time split" in html
    assert "Key finding" in html
    assert "50% recall" in html


def test_render_ml_metrics_with_rich_xgb_payload(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        webapp,
        "_load_precision_at_k",
        lambda _: {
            "n_positive": 20,
            "n_test": 1000,
            "base_rate": 0.02,
            "split_strategy": "time",
            "scenarios": [
                {
                    "label": "Top 10",
                    "k": 10,
                    "true_positives": 5,
                    "precision": 0.5,
                    "recall": 0.25,
                    "lift": 25.0,
                },
                {
                    "label": "Top 25",
                    "k": 25,
                    "true_positives": 8,
                    "precision": 0.32,
                    "recall": 0.4,
                    "lift": 16.0,
                },
                {
                    "label": "Top 50",
                    "k": 50,
                    "true_positives": 12,
                    "precision": 0.24,
                    "recall": 0.6,
                    "lift": 12.0,
                },
            ],
            "recall_targets": [],
        },
    )
    html = webapp._render_ml_metrics(
        {
            "model_name": "xgboost",
            "target_col": "label_advisory_within_6m",
            "roc_auc": 0.84,
            "average_precision": 0.33,
            "feature_count": 15,
            "feature_columns": [f"f{i}" for i in range(12)],
            "train_row_count": 5000,
            "train_positive_count": 100,
            "test_row_count": 1000,
            "test_positive_count": 20,
            "test_start_month": "2024-01",
            "train_start_month": "2023-01",
            "ranking_metrics": {
                "precision_at_10": 0.5,
                "precision_at_25": 0.32,
                "precision_at_50": 0.24,
                "precision_at_100": 0.15,
            },
            "top_positive_features": [
                {"feature": "repo_days_since_last_commit", "mean_abs_shap": 0.456},
                {"feature": "gh_total_commits_90d", "importance": 0.321},
            ],
            "top_negative_features": [
                {"feature": "has_security_policy", "mean_abs_shap": 0.199},
            ],
            "classification_report": {
                "0": {"precision": 0.98, "recall": 0.99, "f1-score": 0.99, "support": 980},
                "1": {"precision": 0.50, "recall": 0.25, "f1-score": 0.33, "support": 20},
            },
            "confusion_matrix": [[970, 10], [15, 5]],
        },
        model_out_dir="data/processed/models/xgb_6m_full_cleaned_time",
    )
    assert "Operational scenario analysis" in html
    assert "Risk-reducing features" in html
    assert "Per-class classification report" in html
    assert "Confusion matrix" in html


def test_render_feature_selection_panel_with_show_controls():
    ranking = [
        {"rank": i + 1, "feature": f"feature_{i + 1}", "mean_abs_shap": 1.0 / (i + 1)}
        for i in range(12)
    ]
    html = webapp._render_feature_selection_panel(
        {
            "full_model_feature_count": 154,
            "full_model_average_precision": 0.4123,
            "h3_satisfied": True,
            "h3_smallest_qualifying_subset": {
                "size": 20,
                "ap_retention": 0.93,
                "average_precision": 0.3834,
            },
            "subset_results": [
                {
                    "subset_label": "full_model",
                    "actual_feature_count": 154,
                    "average_precision": 0.4123,
                    "ap_retention_vs_full": 1.0,
                    "meets_h3_threshold": True,
                },
                {
                    "subset_label": "top_20",
                    "actual_feature_count": 20,
                    "average_precision": 0.3834,
                    "ap_retention_vs_full": 0.93,
                    "meets_h3_threshold": True,
                },
            ],
            "feature_ranking": ranking,
        }
    )
    assert "H3 SATISFIED" in html
    assert "Top 10 features by importance" in html
    assert "Show:" in html
    assert "All" in html


def test_build_ml_explain_prompt_includes_operational_and_feature_selection():
    prompt = webapp._build_ml_explain_prompt(
        {
            "model_name": "xgboost",
            "roc_auc": 0.81,
            "average_precision": 0.42,
            "test_row_count": 1000,
            "test_positive_count": 30,
            "feature_count": 40,
            "ranking_metrics": {"precision_at_10": 0.6, "precision_at_25": 0.4},
            "top_positive_features": [
                {"feature": "repo_days_since_last_commit", "mean_abs_shap": 0.22}
            ],
        },
        {
            "scenarios": [
                {"k": 50, "true_positives": 18, "precision": 0.36, "lift": 12.0},
            ]
        },
        {
            "h3_satisfied": True,
            "h3_smallest_qualifying_subset": {
                "size": 15,
                "ap_retention": 0.91,
                "average_precision": 0.3821,
            },
            "full_model_average_precision": 0.4201,
        },
        "data/processed/models/xgb_6m_full_cleaned_time",
    )
    assert "MODEL:" in prompt
    assert "OPERATIONAL FINDING" in prompt
    assert "FEATURE SELECTION (H3)" in prompt


def test_render_ml_explain_card_variants():
    values = {"model_out_dir": "data/processed/models/xgb_6m_full_cleaned_time"}
    metrics = {"model_name": "xgboost", "test_row_count": 10, "test_positive_count": 1}

    assert webapp._render_ml_explain_card(values, None, None, None) == ""

    limited = webapp._render_ml_explain_card(values, metrics, None, None, rate_limited=True)
    assert "Rate limit reached" in limited

    rendered = webapp._render_ml_explain_card(
        values,
        metrics,
        None,
        None,
        ai_result="**Summary**\n\nLooks useful.",
    )
    assert "AI explanation (Claude)" in rendered
    assert "<strong>Summary</strong>" in rendered


def test_render_ml_tab_feature_selection_messages(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(webapp, "_load_precision_at_k", lambda _: None)
    monkeypatch.setattr(webapp, "_load_feature_selection", lambda _: None)

    metrics = {
        "model_name": "logistic",
        "roc_auc": 0.7,
        "average_precision": 0.2,
        "test_row_count": 100,
        "test_positive_count": 10,
    }

    html_single = webapp._render_ml_tab(
        {"model_out_dir": "data/processed/models/logistic_6m_advisory_only_time"},
        metrics,
        ["data/processed/models/logistic_6m_advisory_only_time"],
    )
    assert "Metrics source" in html_single
    assert "Feature selection is not applicable for single-family feature sets" in html_single

    html_not_run = webapp._render_ml_tab(
        {"model_out_dir": "data/processed/models/logistic_6m_full_cleaned_time"},
        metrics,
        ["data/processed/models/logistic_6m_full_cleaned_time"],
    )
    assert "Feature selection has not yet been run for this model" in html_not_run


def test_load_precision_at_k_invalid_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    model_root = tmp_path / "models"
    run_dir = model_root / "xgb_6m_full_cleaned_time"
    run_dir.mkdir(parents=True)
    (run_dir / "precision_at_k.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)

    assert webapp._load_precision_at_k("/absolute/path") is None
    assert webapp._load_precision_at_k("data/processed/models/xgb_6m_full_cleaned_time") is None


def test_score_and_ml_payload_helpers():
    score = ScoreResult(plugin="plugin-a", score=12, reasons=("a",), features={"f1": 1.2})
    payload = webapp._score_payload(score, score_model_dir="data/processed/models/run")
    assert payload["score_model_dir"] == "data/processed/models/run"
    assert "pretty_json" in payload
    assert "pretty_features" in payload

    ml_result = MLScoreResult(
        plugin="plugin-a",
        probability=0.237,
        canary_score=0.237,
        risk_category="Medium",
        drivers=[FeatureDriver(name="f1", value=0.1, direction="neutral", rank=1)],
        feature_vector={"f1": 0.1},
        model_dir="data/processed/models/run",
        model_name="xgboost",
        scored_at="2026-01-01T00:00:00Z",
    )
    ml_payload = webapp._ml_score_payload(ml_result)
    assert ml_payload["probability_pct"] == "23.7%"
    assert "feature_vector" not in ml_payload["pretty_json"]


def test_render_command_result_and_ml_score_panel():
    cmd_html = webapp._render_command_result(
        {"command": "canary score", "exit_code": 0, "output": "ok"},
        "Score command",
    )
    assert "Score command preview" in cmd_html
    assert "Console output" in cmd_html

    ml_html = webapp._render_ml_score_panel(
        {
            "plugin": "workflow-cps",
            "probability": 0.42,
            "probability_pct": "42.0%",
            "risk_category": "High",
            "model_name": "xgboost",
            "drivers": [
                {
                    "name": "repo_days_since_last_commit",
                    "value": 930,
                    "direction": "increases_risk",
                },
                {"name": "has_security_policy", "value": 1, "direction": "decreases_risk"},
                {"name": "missing_driver", "value": None, "direction": "neutral"},
            ],
            "pretty_json": '{"probability": 0.42}',
        }
    )
    assert "ML Score (experimental)" in ml_html
    assert "Top contributing features" in ml_html
    assert "▲" in ml_html
    assert "▼" in ml_html


def test_fmt_driver_value_and_prompt_builder():
    assert webapp._fmt_driver_value(None, "x") == "n/a"
    assert webapp._fmt_driver_value(800, "repo_days_since_last_commit").endswith("yrs")
    assert webapp._fmt_driver_value(0.12345, "risk_ratio") == "0.123"
    assert webapp._fmt_driver_value(1234, "events_count") == "1,234"
    assert webapp._fmt_driver_value(30, "months_since_release") == "2.5 yrs"
    assert webapp._fmt_driver_value(12.3456, "misc_float") == "12.3"

    prompt = webapp._build_explain_prompt(
        "workflow-cps",
        {"reasons": ["reason one", "reason two"]},
        {
            "probability": 0.5,
            "risk_category": "High",
            "model_name": "xgboost",
            "model_dir": "data/processed/models/xgb_6m_full_cleaned_time",
            "drivers": [
                {"name": "repo_days_since_last_commit", "value": 100, "direction": "increases_risk"}
            ],
        },
    )
    assert "CANARY ASSESSMENT — Plugin: workflow-cps" in prompt
    assert "ML ADVISORY RISK SCORE" in prompt
    assert "Top contributing features" in prompt


def test_rate_limit_and_explain_card_variants():
    ip = "127.0.0.1"
    webapp._EXPLAIN_RATE_LIMIT[ip] = []
    assert webapp._check_explain_rate_limit(ip) is True
    webapp._EXPLAIN_RATE_LIMIT[ip] = [0.0] * webapp._EXPLAIN_RATE_MAX
    assert webapp._check_explain_rate_limit(ip) is False

    card_rate = webapp._render_explain_card(
        "workflow-cps",
        {"reasons": [], "ml": None, "score_model_dir": "data/processed/models/baseline_6m"},
        rate_limited=True,
    )
    assert "Rate limit reached" in card_rate

    card_ai = webapp._render_explain_card(
        "workflow-cps",
        {"reasons": [], "ml": None, "score_model_dir": "data/processed/models/baseline_6m"},
        ai_result="## Heading\n\n**bold** and *italic*",
    )
    assert "AI explanation (Claude)" in card_ai
    assert "<strong>Heading</strong>" in card_ai
    assert "<em>italic</em>" in card_ai


def test_call_anthropic_explain_success_and_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"content":[{"type":"text","text":"Hello"},{"type":"text","text":"World"}]}'

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=30: _Resp())
    assert webapp._call_anthropic_explain("prompt") == "Hello\n\nWorld"

    class _HttpErr(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("http://x", 401, "bad", Message(), None)

        def read(self):
            return b'{"error":"denied"}'

    def _raise_http(req, timeout=30):
        raise _HttpErr()

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http)
    with pytest.raises(RuntimeError, match="Anthropic API error 401"):
        webapp._call_anthropic_explain("prompt")

    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        webapp._call_anthropic_explain("prompt")
