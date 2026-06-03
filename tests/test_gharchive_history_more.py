from __future__ import annotations

from pathlib import Path
from typing import Any

from canary.collectors import gharchive_history
from canary.collectors.gharchive_history import _infer_repo_url, collect_gharchive_history_real


class _FakeBigQuery:
    class Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.args = args
            self.kwargs = kwargs


def test_infer_repo_url_checks_scm_url_and_plugin_api_fallbacks() -> None:
    assert (
        _infer_repo_url({"scm_url": " https://github.com/jenkinsci/from-scm-url-plugin "})
        == "https://github.com/jenkinsci/from-scm-url-plugin"
    )
    assert (
        _infer_repo_url({"scm_url": {"url": "https://github.com/jenkinsci/from-scm-dict"}})
        == "https://github.com/jenkinsci/from-scm-dict"
    )
    assert (
        _infer_repo_url({"plugin_api": {"scm": "https://github.com/jenkinsci/from-api-scm"}})
        == "https://github.com/jenkinsci/from-api-scm"
    )
    assert (
        _infer_repo_url(
            {"plugin_api": {"scm": {"url": "https://github.com/jenkinsci/from-api-dict"}}}
        )
        == "https://github.com/jenkinsci/from-api-dict"
    )
    assert _infer_repo_url({"plugin_api": {"scm": {}}}) is None


def test_collect_gharchive_history_dry_run_estimates_windows_without_writing_events(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_estimate_window_bytes(client: Any, **kwargs: Any) -> int:
        calls.append(kwargs)
        return 123_456

    monkeypatch.setattr(gharchive_history, "_import_bigquery", lambda: _FakeBigQuery)
    monkeypatch.setattr(
        gharchive_history,
        "resolve_plugin_repo_targets",
        lambda **kwargs: {"demo-plugin": "jenkinsci/demo-plugin"},
    )
    monkeypatch.setattr(gharchive_history, "_estimate_window_bytes", fake_estimate_window_bytes)

    result = collect_gharchive_history_real(
        data_dir=str(tmp_path / "data" / "raw"),
        registry_path=str(tmp_path / "data" / "raw" / "registry" / "plugins.jsonl"),
        out_dir=str(tmp_path / "data" / "raw" / "gharchive"),
        start_yyyymmdd="20250101",
        end_yyyymmdd="20250131",
        bucket_days=31,
        sample_percent=5.0,
        max_bytes_billed=999,
        dry_run=True,
    )

    assert calls == [
        {
            "repo_names": ["jenkinsci/demo-plugin"],
            "start_yyyymmdd": "20250101",
            "end_yyyymmdd": "20250131",
            "sample_percent": 5.0,
            "max_bytes_billed": 999,
        }
    ]
    assert result["dry_run"] is True
    assert result["bytes_scanned_total"] == 123_456
    assert result["rows_written"] == 0
    assert result["events_written"] == 0
    assert result["months_written"] == 0
    assert result["windows"] == [
        {
            "window_start_yyyymmdd": "20250101",
            "window_end_yyyymmdd": "20250131",
            "rows": None,
            "bytes_scanned": 0,
            "estimated_bytes_scanned": 123_456,
            "path": None,
            "dry_run": True,
        }
    ]
    out_path = (
        tmp_path
        / "data"
        / "raw"
        / "gharchive"
        / "normalized-events"
        / "2025-01.gharchive.events.jsonl"
    )
    assert not out_path.exists()
