"""
Rendering tests for the web console: render_page and the canary.web.ui
renderers, called with explicit data (never by patching loaders).

Consolidated from test_webapp_extra.py and test_webapp.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import canary.webapp as webapp
from canary.scoring.baseline import ScoreResult
from canary.scoring.ml import FeatureDriver, MLScoreResult
from canary.webapp import (
    _checkbox,
    _escape,
    _input_text,
    _metric_value,
    _render_confusion_matrix,
    _render_ml_metrics,
    _select,
    render_page,
)


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


def test_render_ml_metrics_with_rich_xgb_payload():
    pk_data = {
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
    }
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
        pk_data=pk_data,
    )
    assert "Operational scenario analysis" in html
    assert "Risk-reducing features" in html
    assert "Per-class classification report" in html
    assert "Confusion matrix" in html


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


def test_build_cs_explain_prompt_includes_summary_sections() -> None:
    confirmed_rows = [
        {"plugin_id": f"confirmed-{i}", "score": 0.9, "adv_sev": "High", "days_to_adv": 7}
        for i in range(11)
    ]
    unconfirmed_rows = [{"plugin_id": "forward-1", "score": 0.41}]

    prompt = webapp._build_cs_explain_prompt(
        metrics={"test_row_count": 100},
        confirmed_rows=confirmed_rows,
        unconfirmed_rows=unconfirmed_rows,
        obs_date="2024-01",
        window_end="2024-07-31",
        n_total=12,
        n_confirmed=11,
        lift=9.2,
        base_rate=0.03,
        train_start="2023-01",
        stem="baseline_6m",
    )

    assert "MODEL: baseline_6m" in prompt
    assert "Top-12 precision: 11/12 (92%)" in prompt
    assert "CONFIRMED PREDICTIONS (11):" in prompt
    assert "... and 1 more confirmed" in prompt
    assert "UNCONFIRMED / FORWARD-LOOKING (1):" in prompt
    assert "Please provide your plain-English explanation now." in prompt


def test_render_cs_explain_card_variants() -> None:
    values = {"model_out_dir": "data/processed/models/run_1"}
    metrics = {"test_row_count": 10}
    confirmed_rows = [{"plugin_id": "confirmed-plugin", "score": 0.91, "adv_sev": "High"}]

    assert (
        webapp._render_cs_explain_card(
            values,
            None,
            confirmed_rows,
            [],
            "2024-01",
            "2024-07-31",
            1,
            1,
            2.0,
            0.5,
            "2023-01",
            "run_1",
        )
        == ""
    )

    card_rate = webapp._render_cs_explain_card(
        values,
        metrics,
        confirmed_rows,
        [],
        "2024-01",
        "2024-07-31",
        1,
        1,
        2.0,
        0.5,
        "2023-01",
        "run_1",
        rate_limited=True,
    )
    assert "Rate limit reached" in card_rate

    card_error = webapp._render_cs_explain_card(
        values,
        metrics,
        confirmed_rows,
        [],
        "2024-01",
        "2024-07-31",
        1,
        1,
        2.0,
        0.5,
        "2023-01",
        "run_1",
        ai_error="<boom>",
    )
    assert "AI explanation error: &lt;boom&gt;" in card_error

    card_result = webapp._render_cs_explain_card(
        values,
        metrics,
        confirmed_rows,
        [],
        "2024-01",
        "2024-07-31",
        1,
        1,
        2.0,
        0.5,
        "2023-01",
        "run_1",
        ai_result="**Summary**\n\nLooks useful.",
    )
    assert "AI explanation (Claude)" in card_result
    assert "<strong>Summary</strong>" in card_result
    assert 'name="cs_explain" value="1"' in card_result
    assert "Open in Claude" in card_result
    assert "Open in ChatGPT" in card_result


def test_render_ml_tab_feature_selection_messages():
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
    assert "ML model" in html


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


def test_render_explain_card_variants():
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
