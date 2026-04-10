"""Additional tests for canary.plugin_aliases private helpers and edge cases."""

from __future__ import annotations

import json
from pathlib import Path

from canary.plugin_aliases import (
    _iter_alias_values,
    _load_json_if_exists,
    _merge_aliases,
    _normalize_plugin_id,
    alias_file_candidates,
    load_plugin_alias_map,
)


# ---------------------------------------------------------------------------
# _normalize_plugin_id
# ---------------------------------------------------------------------------


def test_normalize_plugin_id_valid():
    assert _normalize_plugin_id("my-plugin") == "my-plugin"


def test_normalize_plugin_id_strips_whitespace():
    assert _normalize_plugin_id("  my-plugin  ") == "my-plugin"


def test_normalize_plugin_id_empty_returns_none():
    assert _normalize_plugin_id("") is None
    assert _normalize_plugin_id("   ") is None


def test_normalize_plugin_id_non_string_returns_none():
    assert _normalize_plugin_id(None) is None  # type: ignore[arg-type]
    assert _normalize_plugin_id(42) is None  # type: ignore[arg-type]
    assert _normalize_plugin_id([]) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _iter_alias_values
# ---------------------------------------------------------------------------


def test_iter_alias_values_string():
    result = _iter_alias_values("my-plugin")
    assert result == ["my-plugin"]


def test_iter_alias_values_empty_string():
    result = _iter_alias_values("")
    assert result == []


def test_iter_alias_values_whitespace_string():
    result = _iter_alias_values("  ")
    assert result == []


def test_iter_alias_values_list():
    result = _iter_alias_values(["a", "b", "c"])
    assert result == ["a", "b", "c"]


def test_iter_alias_values_list_with_empty_strings():
    result = _iter_alias_values(["a", "", "  ", "b"])
    assert result == ["a", "b"]


def test_iter_alias_values_list_with_non_strings():
    result = _iter_alias_values(["a", 42, None, "b"])  # type: ignore[list-item]
    assert result == ["a", "b"]


def test_iter_alias_values_non_string_non_list_returns_empty():
    assert _iter_alias_values(None) == []  # type: ignore[arg-type]
    assert _iter_alias_values(42) == []  # type: ignore[arg-type]
    assert _iter_alias_values({}) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _merge_aliases
# ---------------------------------------------------------------------------


def test_merge_aliases_adds_aliases():
    alias_map: dict[str, str] = {}
    _merge_aliases(alias_map, "new-name", ["old-name", "former-name"])
    assert alias_map["old-name"] == "new-name"
    assert alias_map["former-name"] == "new-name"


def test_merge_aliases_skips_self_alias():
    alias_map: dict[str, str] = {}
    _merge_aliases(alias_map, "my-plugin", ["my-plugin"])
    assert "my-plugin" not in alias_map


def test_merge_aliases_setdefault_does_not_override_existing():
    alias_map = {"old-name": "first-canonical"}
    _merge_aliases(alias_map, "second-canonical", ["old-name"])
    # setdefault: first writer wins
    assert alias_map["old-name"] == "first-canonical"


def test_merge_aliases_empty_aliases():
    alias_map: dict[str, str] = {}
    _merge_aliases(alias_map, "canonical", [])
    assert alias_map == {}


# ---------------------------------------------------------------------------
# _load_json_if_exists
# ---------------------------------------------------------------------------


def test_load_json_if_exists_valid_file(tmp_path: Path):
    p = tmp_path / "test.json"
    p.write_text(json.dumps({"key": "value"}), encoding="utf-8")
    result = _load_json_if_exists(p)
    assert result == {"key": "value"}


def test_load_json_if_exists_missing_file(tmp_path: Path):
    p = tmp_path / "nonexistent.json"
    assert _load_json_if_exists(p) is None


def test_load_json_if_exists_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json {{{", encoding="utf-8")
    assert _load_json_if_exists(p) is None


def test_load_json_if_exists_directory(tmp_path: Path):
    # Passing a directory (not a file) should return None
    assert _load_json_if_exists(tmp_path) is None


# ---------------------------------------------------------------------------
# alias_file_candidates
# ---------------------------------------------------------------------------


def test_alias_file_candidates_returns_list(tmp_path: Path):
    candidates = alias_file_candidates(data_dir=tmp_path / "raw")
    assert isinstance(candidates, list)
    assert len(candidates) >= 1


def test_alias_file_candidates_includes_registry_dir(tmp_path: Path):
    data_dir = tmp_path / "raw"
    candidates = alias_file_candidates(data_dir=data_dir)
    paths_str = [str(c) for c in candidates]
    assert any("plugin_aliases.json" in p for p in paths_str)


# ---------------------------------------------------------------------------
# load_plugin_alias_map — edge cases
# ---------------------------------------------------------------------------


def test_load_plugin_alias_map_empty_dir(tmp_path: Path):
    (tmp_path / "registry").mkdir(parents=True)
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert isinstance(result, dict)
    # No aliases without files
    assert result == {}


def test_load_plugin_alias_map_reads_alias_json(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert result.get("old-name") == "new-name"


def test_load_plugin_alias_map_reads_registry_jsonl(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    record = {
        "plugin_id": "new-name",
        "aliases": ["old-name", "former-name"],
    }
    registry_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert result.get("old-name") == "new-name"
    assert result.get("former-name") == "new-name"


def test_load_plugin_alias_map_reads_snapshot_files(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    snap = {
        "plugin_id": "canonical-plugin",
        "aliases": ["snap-alias"],
    }
    (plugins_dir / "canonical-plugin.snapshot.json").write_text(
        json.dumps(snap), encoding="utf-8"
    )
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert result.get("snap-alias") == "canonical-plugin"


def test_load_plugin_alias_map_snapshot_with_plugin_api_aliases(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    snap = {
        "plugin_id": "canonical-plugin",
        "plugin_api": {
            "previousNames": ["api-former-name"],
        },
    }
    (plugins_dir / "canonical-plugin.snapshot.json").write_text(
        json.dumps(snap), encoding="utf-8"
    )
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert result.get("api-former-name") == "canonical-plugin"


def test_load_plugin_alias_map_skips_invalid_alias_json(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    (registry_dir / "plugin_aliases.json").write_text("{{{not valid json}}}", encoding="utf-8")
    # Should not raise; just return empty
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert isinstance(result, dict)


def test_load_plugin_alias_map_registry_path_skips_malformed_lines(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    content = (
        json.dumps({"plugin_id": "good-plugin", "aliases": ["good-alias"]}) + "\n"
        + "not json {{\n"
        + json.dumps({"plugin_id": "another-plugin", "aliases": ["another-alias"]}) + "\n"
    )
    registry_path.write_text(content, encoding="utf-8")
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert result.get("good-alias") == "good-plugin"
    assert result.get("another-alias") == "another-plugin"


def test_load_plugin_alias_map_snapshot_derives_id_from_filename(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    # Snapshot without explicit plugin_id - should derive from filename
    snap = {
        "aliases": ["snap-filename-alias"],
    }
    (plugins_dir / "derived-plugin.snapshot.json").write_text(
        json.dumps(snap), encoding="utf-8"
    )
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert result.get("snap-filename-alias") == "derived-plugin"
