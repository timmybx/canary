"""Tests for canary.collectors.healthscore."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from canary.collectors.healthscore import (
    _extract_plugin_id,
    _iter_score_records,
    collect_health_scores,
)


# ---------------------------------------------------------------------------
# _iter_score_records
# ---------------------------------------------------------------------------


def test_iter_score_records_list_input():
    payload = [{"plugin_id": "alpha", "score": 80}, {"plugin_id": "beta", "score": 60}]
    result = _iter_score_records(payload)
    assert len(result) == 2
    assert result[0]["plugin_id"] == "alpha"


def test_iter_score_records_list_filters_non_dicts():
    payload = [{"plugin_id": "alpha"}, "string", 42, None]
    result = _iter_score_records(payload)
    assert len(result) == 1


def test_iter_score_records_dict_with_scores_key():
    payload = {"scores": [{"plugin_id": "a"}, {"plugin_id": "b"}]}
    result = _iter_score_records(payload)
    assert len(result) == 2


def test_iter_score_records_dict_with_data_key():
    payload = {"data": [{"plugin_id": "x"}]}
    result = _iter_score_records(payload)
    assert len(result) == 1


def test_iter_score_records_dict_with_items_key():
    payload = {"items": [{"plugin_id": "y"}, {"plugin_id": "z"}]}
    result = _iter_score_records(payload)
    assert len(result) == 2


def test_iter_score_records_dict_with_plugins_key():
    payload = {"plugins": [{"plugin_id": "p"}]}
    result = _iter_score_records(payload)
    assert len(result) == 1


def test_iter_score_records_mapping_pattern():
    payload = {
        "translation": {"score": 75, "other": "x"},
        "git": {"score": 85},
    }
    result = _iter_score_records(payload)
    assert len(result) == 2
    plugin_ids = {r["plugin_id"] for r in result}
    assert "translation" in plugin_ids
    assert "git" in plugin_ids


def test_iter_score_records_mapping_preserves_existing_plugin_id():
    payload = {
        "translation": {"plugin_id": "already-set", "score": 75},
    }
    result = _iter_score_records(payload)
    # setdefault should not override existing plugin_id
    assert result[0]["plugin_id"] == "already-set"


def test_iter_score_records_unknown_type():
    result = _iter_score_records("unexpected_string")  # type: ignore[arg-type]
    assert result == []

    result = _iter_score_records(None)  # type: ignore[arg-type]
    assert result == []

    result = _iter_score_records(42)  # type: ignore[arg-type]
    assert result == []


# ---------------------------------------------------------------------------
# _extract_plugin_id
# ---------------------------------------------------------------------------


def test_extract_plugin_id_from_plugin_id_field():
    assert _extract_plugin_id({"plugin_id": "my-plugin"}) == "my-plugin"


def test_extract_plugin_id_from_pluginId_field():
    assert _extract_plugin_id({"pluginId": "my-plugin-2"}) == "my-plugin-2"


def test_extract_plugin_id_from_id_field():
    assert _extract_plugin_id({"id": "some-id"}) == "some-id"


def test_extract_plugin_id_from_plugin_field():
    assert _extract_plugin_id({"plugin": "plugin-from-plugin"}) == "plugin-from-plugin"


def test_extract_plugin_id_from_nested_plugin_dict():
    rec = {"plugin": {"id": "nested-plugin-id"}}
    assert _extract_plugin_id(rec) == "nested-plugin-id"


def test_extract_plugin_id_from_nested_plugin_name():
    rec = {"plugin": {"name": "nested-plugin-name"}}
    assert _extract_plugin_id(rec) == "nested-plugin-name"


def test_extract_plugin_id_returns_none_when_missing():
    assert _extract_plugin_id({}) is None


def test_extract_plugin_id_ignores_empty_string():
    assert _extract_plugin_id({"plugin_id": "  ", "id": "real-id"}) == "real-id"


# ---------------------------------------------------------------------------
# collect_health_scores
# ---------------------------------------------------------------------------


def test_collect_health_scores_fetches_and_writes(tmp_path: Path, monkeypatch):
    payload = [
        {"plugin_id": "alpha", "value": 80},
        {"plugin_id": "beta", "value": 60},
    ]

    monkeypatch.setattr(
        "canary.collectors.healthscore.fetch_health_scores",
        lambda timeout_s=30.0: payload,
    )

    result = collect_health_scores(data_dir=str(tmp_path), overwrite=True)

    scores_path = tmp_path / "healthscore" / "scores.json"
    assert scores_path.exists()
    assert result["written"] == 2
    assert result["processed"] == 2

    alpha_path = tmp_path / "healthscore" / "plugins" / "alpha.healthscore.json"
    assert alpha_path.exists()
    stored = json.loads(alpha_path.read_text(encoding="utf-8"))
    assert stored["plugin_id"] == "alpha"
    assert stored["record"] == {"plugin_id": "alpha", "value": 80}


def test_collect_health_scores_skips_existing_files(tmp_path: Path, monkeypatch):
    payload = [{"plugin_id": "myplugin", "value": 90}]

    monkeypatch.setattr(
        "canary.collectors.healthscore.fetch_health_scores",
        lambda timeout_s=30.0: payload,
    )

    # First run writes the file
    collect_health_scores(data_dir=str(tmp_path), overwrite=True)

    # Second run without overwrite should skip
    result2 = collect_health_scores(data_dir=str(tmp_path), overwrite=False)
    assert result2["skipped"] == 1
    assert result2["written"] == 0


def test_collect_health_scores_reads_cached_scores_file(tmp_path: Path, monkeypatch):
    """If scores.json exists and overwrite=False, fetch should not be called."""
    scores_path = tmp_path / "healthscore" / "scores.json"
    scores_path.parent.mkdir(parents=True)
    cached_payload = [{"plugin_id": "cached-plugin", "value": 55}]
    scores_path.write_text(json.dumps(cached_payload), encoding="utf-8")

    fetch_called: list[bool] = []

    def fake_fetch(timeout_s=30.0):
        fetch_called.append(True)
        return []

    monkeypatch.setattr("canary.collectors.healthscore.fetch_health_scores", fake_fetch)

    result = collect_health_scores(data_dir=str(tmp_path), overwrite=False)
    assert not fetch_called, "fetch_health_scores should not be called when cache exists"
    assert result["processed"] == 1


def test_collect_health_scores_handles_mapping_payload(tmp_path: Path, monkeypatch):
    payload = {
        "my-plugin": {"score": 70},
        "other-plugin": {"score": 40},
    }

    monkeypatch.setattr(
        "canary.collectors.healthscore.fetch_health_scores",
        lambda timeout_s=30.0: payload,
    )

    result = collect_health_scores(data_dir=str(tmp_path), overwrite=True)
    assert result["processed"] == 2
    assert result["written"] == 2


def test_collect_health_scores_skips_records_without_plugin_id(tmp_path: Path, monkeypatch):
    payload = [{"no_id": True, "score": 50}]

    monkeypatch.setattr(
        "canary.collectors.healthscore.fetch_health_scores",
        lambda timeout_s=30.0: payload,
    )

    result = collect_health_scores(data_dir=str(tmp_path), overwrite=True)
    assert result["processed"] == 0
    assert result["written"] == 0
