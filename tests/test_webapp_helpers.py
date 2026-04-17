from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path

import pytest  # pyright: ignore[reportMissingImports]

import canary.webapp as webapp
from canary.webapp import (
    _argv_preview_data,
    _argv_preview_train,
    _load_plugin_choices,
    _normalize_model_output_dir,
    _plugin_known,
    app,
)

# ---------------------------------------------------------------------------
# WSGI test helper
# ---------------------------------------------------------------------------


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
# _argv_preview_data
# ---------------------------------------------------------------------------


def test_argv_preview_data_collect_registry_basic() -> None:
    args = argparse.Namespace(
        out_dir="data/raw/registry",
        out_name="plugins.jsonl",
        raw_out=None,
        page_size=2500,
        max_plugins=None,
        timeout_s=30.0,
        real=True,
    )
    result = _argv_preview_data("collect-registry", args)
    assert "--out-dir" in result
    assert "--out-name" in result
    assert "--page-size" in result
    assert "--real" in result
    assert "--timeout-s" in result
    # raw_out and max_plugins should be absent when None/falsy
    assert "--raw-out" not in result
    assert "--max-plugins" not in result


def test_argv_preview_data_collect_registry_with_raw_out_and_max_plugins() -> None:
    args = argparse.Namespace(
        out_dir="data/raw/registry",
        out_name="plugins.jsonl",
        raw_out="data/raw/registry.raw.json",
        page_size=100,
        max_plugins="50",
        timeout_s=10.0,
        real=False,
    )
    result = _argv_preview_data("collect-registry", args)
    assert "--raw-out" in result
    assert "--max-plugins" in result
    assert "--real" not in result


def test_argv_preview_data_collect_plugin() -> None:
    args = argparse.Namespace(
        id="cucumber-reports",
        out_dir="data/raw/plugins",
        repo_url=None,
        real=True,
        registry_path="data/raw/registry/plugins.jsonl",
        max_plugins=None,
        sleep=0.0,
        overwrite=False,
    )
    result = _argv_preview_data("collect-plugin", args)
    assert "--out-dir" in result
    assert "--registry-path" in result
    assert "--sleep" in result
    assert "--id" in result
    assert "--real" in result
    # repo_url is None, max_plugins is None, overwrite is False
    assert "--repo-url" not in result
    assert "--max-plugins" not in result
    assert "--overwrite" not in result


def test_argv_preview_data_collect_plugin_with_overwrite() -> None:
    args = argparse.Namespace(
        id=None,
        out_dir="data/raw/plugins",
        repo_url="https://github.com/jenkinsci/test",
        real=False,
        registry_path="data/raw/registry/plugins.jsonl",
        max_plugins=None,
        sleep=1.0,
        overwrite=True,
    )
    result = _argv_preview_data("collect-plugin", args)
    assert "--repo-url" in result
    assert "--overwrite" in result
    assert "--real" not in result
    assert "--id" not in result


def test_argv_preview_data_collect_advisories() -> None:
    args = argparse.Namespace(
        plugin=None,
        data_dir="data/raw",
        out_dir="data/raw/advisories",
        real=True,
        registry_path="data/raw/registry/plugins.jsonl",
        max_plugins=None,
        sleep=0.0,
        overwrite=False,
    )
    result = _argv_preview_data("collect-advisories", args)
    assert "--data-dir" in result
    assert "--out-dir" in result
    assert "--registry-path" in result
    assert "--sleep" in result
    assert "--real" in result
    assert "--plugin" not in result


def test_argv_preview_data_collect_advisories_with_plugin() -> None:
    args = argparse.Namespace(
        plugin="my-plugin",
        data_dir="data/raw",
        out_dir="data/raw/advisories",
        real=False,
        registry_path="data/raw/registry/plugins.jsonl",
        max_plugins=None,
        sleep=0.0,
        overwrite=False,
    )
    result = _argv_preview_data("collect-advisories", args)
    assert "--plugin" in result
    assert "my-plugin" in result


def test_argv_preview_data_collect_github() -> None:
    args = argparse.Namespace(
        plugin="cucumber-reports",
        data_dir="data/raw",
        out_dir="data/raw/github",
        timeout_s=20.0,
        max_pages=5,
        commits_days=365,
        overwrite=False,
    )
    result = _argv_preview_data("collect-github", args)
    assert "--plugin" in result
    assert "--data-dir" in result
    assert "--out-dir" in result
    assert "--timeout-s" in result
    assert "--max-pages" in result
    assert "--commits-days" in result
    assert "--overwrite" not in result


def test_argv_preview_data_collect_github_with_overwrite() -> None:
    args = argparse.Namespace(
        plugin="test-plugin",
        data_dir="data/raw",
        out_dir="data/raw/github",
        timeout_s=20.0,
        max_pages=5,
        commits_days=365,
        overwrite=True,
    )
    result = _argv_preview_data("collect-github", args)
    assert "--overwrite" in result


def test_argv_preview_data_collect_healthscore() -> None:
    args = argparse.Namespace(
        data_dir="data/raw",
        timeout_s=30.0,
        overwrite=False,
    )
    result = _argv_preview_data("collect-healthscore", args)
    assert "--data-dir" in result
    assert "--timeout-s" in result
    assert "--overwrite" not in result


def test_argv_preview_data_collect_enrich() -> None:
    args = argparse.Namespace(
        registry="data/raw/registry/plugins.jsonl",
        data_dir="data/raw",
        sleep=0.0,
        github_timeout_s=20.0,
        github_max_pages=5,
        github_commits_days=365,
        healthscore_timeout_s=30.0,
        only=None,
        max_plugins=None,
        real=True,
    )
    result = _argv_preview_data("collect-enrich", args)
    assert "--registry" in result
    assert "--data-dir" in result
    assert "--sleep" in result
    assert "--github-timeout-s" in result
    assert "--github-max-pages" in result
    assert "--github-commits-days" in result
    assert "--healthscore-timeout-s" in result
    assert "--real" in result
    assert "--only" not in result
    assert "--max-plugins" not in result


def test_argv_preview_data_collect_enrich_with_only() -> None:
    args = argparse.Namespace(
        registry="data/raw/registry/plugins.jsonl",
        data_dir="data/raw",
        sleep=0.0,
        github_timeout_s=20.0,
        github_max_pages=5,
        github_commits_days=365,
        healthscore_timeout_s=30.0,
        only="snapshot",
        max_plugins="10",
        real=False,
    )
    result = _argv_preview_data("collect-enrich", args)
    assert "--only" in result
    assert "snapshot" in result
    assert "--max-plugins" in result
    assert "--real" not in result


def test_argv_preview_data_build_monthly_features() -> None:
    args = argparse.Namespace(
        data_raw_dir="data/raw",
        registry="data/raw/registry/plugins.jsonl",
        start="2025-01",
        end="2025-12",
        out="data/processed/features/plugins.monthly.features.jsonl",
        out_csv="data/processed/features/plugins.monthly.features.csv",
        summary_out="data/processed/features/plugins.monthly.features.summary.json",
    )
    result = _argv_preview_data("build-monthly-features", args)
    assert "--data-raw-dir" in result
    assert "--registry" in result
    assert "--start" in result
    assert "--end" in result
    assert "--out" in result
    assert "--out-csv" in result
    assert "--summary-out" in result


def test_argv_preview_data_build_monthly_labels() -> None:
    args = argparse.Namespace(
        in_path="data/processed/features/plugins.monthly.features.jsonl",
        out_path="data/processed/features/plugins.monthly.labeled.jsonl",
        out_csv_path="data/processed/features/plugins.monthly.labeled.csv",
        summary_path="data/processed/features/plugins.monthly.labeled.summary.json",
        horizons="1,3,6,12",
    )
    result = _argv_preview_data("build-monthly-labels", args)
    assert "--in-path" in result
    assert "--out-path" in result
    assert "--out-csv-path" in result
    assert "--summary-path" in result
    assert "--horizons" in result


def test_argv_preview_data_unknown_command_returns_empty() -> None:
    args = argparse.Namespace()
    result = _argv_preview_data("unknown-command", args)
    assert result == []


# ---------------------------------------------------------------------------
# _argv_preview_train
# ---------------------------------------------------------------------------


def test_argv_preview_train_basic() -> None:
    args = argparse.Namespace(
        in_path="data/processed/features/plugins.monthly.labeled.jsonl",
        target_col="label_advisory_within_6m",
        out_dir="data/processed/models/baseline_6m",
        test_start_month="2025-10",
        exclude_cols="",
        include_prefixes="",
    )
    result = _argv_preview_train(args)
    assert "--in-path" in result
    assert "--target-col" in result
    assert "--out-dir" in result
    assert "--test-start-month" in result
    assert "--exclude-cols" not in result
    assert "--include-prefixes" not in result


def test_argv_preview_train_with_exclude_cols() -> None:
    args = argparse.Namespace(
        in_path="data/processed/features/plugins.monthly.labeled.jsonl",
        target_col="label_advisory_within_6m",
        out_dir="data/processed/models/baseline_6m",
        test_start_month="2025-10",
        exclude_cols="col_a,col_b",
        include_prefixes="",
    )
    result = _argv_preview_train(args)
    assert "--exclude-cols" in result
    assert "col_a,col_b" in result
    assert "--include-prefixes" not in result


def test_argv_preview_train_with_include_prefixes() -> None:
    args = argparse.Namespace(
        in_path="data/processed/features/plugins.monthly.labeled.jsonl",
        target_col="label_advisory_within_6m",
        out_dir="data/processed/models/baseline_6m",
        test_start_month="2025-10",
        exclude_cols="",
        include_prefixes="gharchive_,window_",
    )
    result = _argv_preview_train(args)
    assert "--include-prefixes" in result
    assert "gharchive_,window_" in result
    assert "--exclude-cols" not in result


def test_argv_preview_train_with_both_filters() -> None:
    args = argparse.Namespace(
        in_path="data/processed/features/plugins.monthly.labeled.jsonl",
        target_col="label_advisory_within_3m",
        out_dir="data/processed/models/run2",
        test_start_month="2024-01",
        exclude_cols="col_x",
        include_prefixes="snapshot_",
    )
    result = _argv_preview_train(args)
    assert "--exclude-cols" in result
    assert "--include-prefixes" in result


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
    text = body.decode("utf-8")
    assert status == "200 OK"
    assert "CANARY" in text


def test_data_get_returns_200() -> None:
    status, _headers, body = _run_app("GET", "/data")
    assert status == "200 OK"
    assert len(body) > 0


def test_train_get_returns_200() -> None:
    status, _headers, body = _run_app("GET", "/train")
    assert status == "200 OK"
    assert len(body) > 0


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


def test_tab_query_string_selects_data_tab() -> None:
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
    assert "Data collection" in text


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
    # Posting /score without a plugin should not crash but show an error page
    body = b"plugin=&real=true"
    status, headers, response = _run_app("POST", "/score", body)
    text = response.decode("utf-8")
    assert status == "200 OK"
    assert ("Content-Type", "text/html; charset=utf-8") in headers
    assert "The scoring request could not be completed" in text


def test_score_post_with_unknown_plugin_shows_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "plugins.jsonl"
    registry.write_text('{"plugin_id": "cucumber-reports"}\n', encoding="utf-8")
    monkeypatch.setattr(webapp, "DEFAULT_REGISTRY_PATH", str(registry))

    body_str = f"plugin=nonexistent-plugin&real=true&registry_path={registry}"
    body = body_str.encode("utf-8")
    status, _headers, response = _run_app("POST", "/score", body)
    text = response.decode("utf-8")
    assert status == "200 OK"
    assert "The scoring request could not be completed" in text
