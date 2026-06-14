"""
Service-layer tests for the web console: form/value parsing, registry plugin
choices, model-directory validation, artifact loaders, the explain rate
limiter, the Anthropic client, and server startup (main).

Consolidated from test_webapp_extra.py, test_webapp_helpers.py, and
test_webapp_main_low_hanging.py.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from email.message import Message
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

import canary.webapp as webapp
from canary.webapp import (
    _bool_from_form,
    _load_plugin_choices,
    _merge_defaults,
    _model_output_dir_parts,
    _normalize_model_output_dir,
    _optional_str,
    _plugin_known,
    parse_form,
)


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


def test_optional_str_non_empty():
    assert _optional_str("hello") == "hello"


def test_optional_str_strips_whitespace():
    assert _optional_str("  hello  ") == "hello"


def test_optional_str_empty():
    assert _optional_str("") is None
    assert _optional_str("   ") is None


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


def test_load_cs_prediction_rows_splits_confirmed_and_unconfirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model_root = tmp_path / "models"
    run_dir = model_root / "run_case"
    run_dir.mkdir(parents=True)
    (run_dir / "test_predictions.csv").write_text(
        "\n".join(
            [
                "plugin_id,month,y_true,y_prob",
                "confirmed-plugin,2024-01,0,0.95",
                "ytrue-plugin,2024-01,1,0.50",
                "forward-plugin,2024-01,0,0.40",
                "confirmed-plugin,2024-01,1,0.10",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)

    def _fake_advisories(
        plugin_id: str, after_date: str, before_date: str
    ) -> list[dict[str, object]]:
        assert after_date == "2024-01"
        assert before_date == "2024-07-31"
        if plugin_id == "confirmed-plugin":
            return [
                {
                    "published_date": "2024-03-15",
                    "url": "https://example.test/a",
                    "severity_summary": {
                        "max_severity_label": "high",
                        "max_cvss_base_score": 8.5,
                    },
                },
                {
                    "published_date": "2024-02-15",
                    "url": "https://example.test/b",
                    "severity_summary": {
                        "max_severity_label": "medium",
                        "max_cvss_base_score": 6.2,
                    },
                },
            ]
        return []

    monkeypatch.setattr(webapp, "_advisories_in_window", _fake_advisories)

    obs_date, window_end, confirmed, unconfirmed = webapp._load_cs_prediction_rows(
        "data/processed/models/run_case",
        metrics={"test_start_month": "2024-01"},
        n_top=3,
    )

    assert obs_date == "2024-01"
    assert window_end == "2024-07-31"
    assert [row["plugin_id"] for row in confirmed] == ["confirmed-plugin", "ytrue-plugin"]
    assert confirmed[0]["adv_sev"] == "High"
    assert confirmed[0]["adv_cvss"] == 8.5
    assert confirmed[0]["days_to_adv"] == 74
    assert [row["plugin_id"] for row in unconfirmed] == ["forward-plugin"]


def test_load_cs_prediction_rows_returns_empty_on_bad_predictions_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model_root = tmp_path / "models"
    run_dir = model_root / "run_bad"
    run_dir.mkdir(parents=True)
    (run_dir / "test_predictions.csv").write_text(
        "plugin_id,month,y_true,y_prob\nbroken,2024-01,0,not-a-number\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)

    assert webapp._load_cs_prediction_rows("data/processed/models/run_bad", metrics={}) == (
        "",
        "",
        [],
        [],
    )


def test_load_precision_at_k_invalid_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    model_root = tmp_path / "models"
    run_dir = model_root / "xgb_6m_full_cleaned_time"
    run_dir.mkdir(parents=True)
    (run_dir / "precision_at_k.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(webapp, "MODEL_OUTPUTS_ROOT", model_root)

    assert webapp._load_precision_at_k("/absolute/path") is None
    assert webapp._load_precision_at_k("data/processed/models/xgb_6m_full_cleaned_time") is None
    (run_dir / "precision_at_k.json").write_text('{"unexpected":"shape"}', encoding="utf-8")
    assert webapp._load_precision_at_k("data/processed/models/xgb_6m_full_cleaned_time") == {
        "unexpected": "shape"
    }


def test_call_anthropic_explain_success_and_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"content":[{"type":"text","text":"Hello"},{"type":"text","text":"World"}]}'

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: _Resp())
    assert webapp._call_anthropic_explain("prompt") == "Hello\n\nWorld"

    class _HttpErr(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("https://x", 401, "bad", Message(), None)

        def read(self):
            return b'{"error":"denied"}'

    def _raise_http(*args, **kwargs):
        raise _HttpErr()

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http)
    with pytest.raises(RuntimeError, match="Anthropic API error 401"):
        webapp._call_anthropic_explain("prompt")

    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        webapp._call_anthropic_explain("prompt")


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


def test_main_uses_waitress_with_env_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    def fake_waitress_serve(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(webapp, "waitress_serve", fake_waitress_serve)
    monkeypatch.setenv("CANARY_WEB_HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("CANARY_WEB_THREADS", "12")
    monkeypatch.setenv("CANARY_WEB_CONNECTION_LIMIT", "345")

    webapp.main()

    assert captured == {
        "app": webapp.app,
        "host": "0.0.0.0",
        "port": 9000,
        "threads": 12,
        "connection_limit": 345,
    }
    output = capsys.readouterr().out
    assert "CANARY web console running on http://0.0.0.0:9000" in output
    assert "Using waitress with threads=12 and connection_limit=345" in output


def test_main_falls_back_to_defaults_for_invalid_numeric_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_waitress_serve(app: object, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(webapp, "waitress_serve", fake_waitress_serve)
    monkeypatch.setenv("CANARY_WEB_HOST", "127.0.0.2")
    monkeypatch.setenv("PORT", "not-a-port")
    monkeypatch.setenv("CANARY_WEB_THREADS", "not-threads")
    monkeypatch.setenv("CANARY_WEB_CONNECTION_LIMIT", "not-a-limit")

    webapp.main()

    assert captured == {
        "app": webapp.app,
        "host": "127.0.0.2",
        "port": 8000,
        "threads": 8,
        "connection_limit": 200,
    }


def test_main_uses_wsgiref_when_waitress_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, Any] = {}

    class FakeServer:
        def __enter__(self) -> FakeServer:
            captured["entered"] = True
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            captured["exited"] = True

        def serve_forever(self) -> None:
            captured["served"] = True

    def fake_make_server(host: str, port: int, app: object) -> FakeServer:
        captured["host"] = host
        captured["port"] = port
        captured["app"] = app
        return FakeServer()

    monkeypatch.setattr(webapp, "waitress_serve", None)
    monkeypatch.setattr(webapp, "make_server", fake_make_server)
    monkeypatch.setenv("CANARY_WEB_HOST", "localhost")
    monkeypatch.setenv("CANARY_WEB_PORT", "7777")
    monkeypatch.delenv("PORT", raising=False)

    webapp.main()

    assert captured == {
        "host": "localhost",
        "port": 7777,
        "app": webapp.app,
        "entered": True,
        "served": True,
        "exited": True,
    }
    assert (
        "Waitress is not installed; falling back to wsgiref.simple_server"
        in capsys.readouterr().out
    )


def test_rate_limiter_blocks_after_max_requests():
    ip = "127.0.0.1"
    webapp._EXPLAIN_RATE_LIMIT.pop(ip, None)
    assert webapp._check_explain_rate_limit(ip) is True
    now = webapp._time.monotonic()
    webapp._EXPLAIN_RATE_LIMIT[ip] = [now] * webapp._EXPLAIN_RATE_MAX
    assert webapp._check_explain_rate_limit(ip) is False
    webapp._EXPLAIN_RATE_LIMIT.pop(ip, None)


# ---------------------------------------------------------------------------
# _load_plugin_choices -- edge cases in JSONL parsing (services.py lines 35-44)
# ---------------------------------------------------------------------------


def test_load_plugin_choices_skips_blank_lines(tmp_path: Path) -> None:
    # line 35-36: "if not line: continue"
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "alpha"}\n\n{"plugin_id": "beta"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert "alpha" in result
    assert "beta" in result


def test_load_plugin_choices_skips_malformed_json_lines(tmp_path: Path) -> None:
    # line 39-40: "except json.JSONDecodeError: continue"
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": "good-plugin"}\nnot valid json {{{\n{"plugin_id": "also-good"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert "good-plugin" in result
    assert "also-good" in result


def test_load_plugin_choices_skips_records_without_plugin_id(tmp_path: Path) -> None:
    # line 42->33: "if plugin_id:" is False (empty string after strip)
    registry = tmp_path / "plugins.jsonl"
    registry.write_text(
        '{"plugin_id": ""}\n{"no_id_field": true}\n{"plugin_id": "real-plugin"}\n',
        encoding="utf-8",
    )
    result = _load_plugin_choices(str(registry))
    assert result == ["real-plugin"]


# ---------------------------------------------------------------------------
# _inject_live_commit_signal (services.py lines 134-160)
# ---------------------------------------------------------------------------


def test_inject_live_commit_signal_no_live_date_returns_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # line 135-136: live_date is falsy -> original score_result returned unchanged
    monkeypatch.setattr("canary.web.services._fetch_live_commit_date", lambda pid: None)
    original = {"reasons": ["Some reason."], "score": 5}
    result = webapp._inject_live_commit_signal(original, "my-plugin")
    assert result is original


def test_inject_live_commit_signal_replaces_matching_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # lines 148-150: stale commit reason is found and replaced
    monkeypatch.setattr(
        "canary.web.services._fetch_live_commit_date",
        lambda pid: "June 1, 2026",
    )
    score_result = {
        "reasons": [
            "Recent commit activity (45 days ago) suggests active maintenance.",
            "No advisories found.",
        ]
    }
    result = webapp._inject_live_commit_signal(score_result, "my-plugin")
    assert result["reasons"][0] == "Last commit: June 1, 2026 — live data from GitHub."
    assert result["reasons"][1] == "No advisories found."


def test_inject_live_commit_signal_prepends_when_no_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # lines 155-156: no stale reason found -> live date prepended
    monkeypatch.setattr(
        "canary.web.services._fetch_live_commit_date",
        lambda pid: "May 20, 2026",
    )
    score_result = {"reasons": ["No advisories found.", "Low staleness."]}
    result = webapp._inject_live_commit_signal(score_result, "my-plugin")
    assert result["reasons"][0] == "Last commit: May 20, 2026 — live data from GitHub."
    assert "No advisories found." in result["reasons"]
