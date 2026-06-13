"""
Behavior tests for canary.plugin_aliases.

Consolidates test_plugin_aliases.py + test_plugin_aliases_extra.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from canary.build.monthly_features import build_monthly_feature_bundle
from canary.plugin_aliases import (
    _iter_alias_values,
    _load_json_if_exists,
    _merge_aliases,
    _normalize_plugin_id,
    alias_candidates,
    alias_file_candidates,
    canonicalize_plugin_id,
    load_plugin_alias_map,
)
from canary.scoring.baseline import score_plugin_baseline
from canary.webapp import _plugin_known

# ---------------------------------------------------------------------------
# Integration tests: canonicalization + scoring + monthly features
# ---------------------------------------------------------------------------


def test_canonicalize_plugin_id_uses_curated_alias_file(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    registry = registry_dir / "plugins.jsonl"
    registry.write_text(json.dumps({"plugin_id": "new-name"}) + "\n", encoding="utf-8")
    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )

    assert (
        canonicalize_plugin_id("old-name", registry_path=registry, data_dir=data_raw) == "new-name"
    )
    assert alias_candidates("new-name", registry_path=registry, data_dir=data_raw) == [
        "new-name",
        "old-name",
    ]


def test_plugin_known_checks_registry_membership_literally(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    registry = registry_dir / "plugins.jsonl"
    registry.write_text(json.dumps({"plugin_id": "new-name"}) + "\n", encoding="utf-8")
    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )

    assert _plugin_known("new-name", str(registry)) is True
    assert _plugin_known("old-name", str(registry)) is False
    assert _plugin_known("totally-unknown", str(registry)) is False


def test_score_plugin_baseline_accepts_alias_and_reads_canonical_files(
    tmp_path: Path, monkeypatch
) -> None:
    data_raw = tmp_path / "data" / "raw"
    advisories = data_raw / "advisories"
    plugins = data_raw / "plugins"
    registry_dir = data_raw / "registry"
    for p in (advisories, plugins, registry_dir):
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )
    (plugins / "new-name.snapshot.json").write_text(
        json.dumps(
            {"plugin_id": "new-name", "plugin_api": {"maintainers": [], "dependencies": []}}
        ),
        encoding="utf-8",
    )
    (advisories / "new-name.advisories.real.jsonl").write_text(
        json.dumps({"plugin_id": "new-name", "published_date": "2025-01-10"}) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("canary.scoring.baseline._DATA_ROOT", data_raw.resolve())

    result = score_plugin_baseline("old-name", real=True).to_dict()
    assert result["plugin"] == "new-name"
    assert result["features"]["advisory_count"] == 1


def test_monthly_feature_bundle_rolls_alias_rows_into_canonical_plugin(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"
    gharchive_dir = data_raw / "gharchive" / "normalized-events"
    for p in [registry_dir, plugins_dir, health_dir, github_dir, gharchive_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "new-name", "title": "New Name"}) + "\n",
        encoding="utf-8",
    )
    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )
    (plugins_dir / "new-name.snapshot.json").write_text(
        json.dumps(
            {"plugin_id": "new-name", "plugin_api": {"maintainers": [], "dependencies": []}}
        ),
        encoding="utf-8",
    )
    (health_dir / "new-name.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "new-name",
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": "new-name", "value": 88},
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "new-name.github_index.json").write_text(
        json.dumps({"plugin_id": "new-name", "repo_full_name": "jenkinsci/new-name"}),
        encoding="utf-8",
    )
    (gharchive_dir / "2025-01.gharchive.events.jsonl").write_text(
        json.dumps(
            {
                "plugin_id": "old-name",
                "event_yyyymm": "2025-01",
                "event_date": "2025-01-03",
                "event_type": "PushEvent",
                "actor_login": "alice",
                "sample_percent": 1.0,
                "source_window_start_yyyymmdd": "20250101",
                "source_window_end_yyyymmdd": "20250131",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        start_month="2025-01",
        end_month="2025-01",
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["plugin_id"] == "new-name"
    assert row["gharchive_events_total"] == 1
    assert row["gharchive_push_events"] == 1


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
    assert _iter_alias_values("my-plugin") == ["my-plugin"]


def test_iter_alias_values_empty_string():
    assert _iter_alias_values("") == []


def test_iter_alias_values_whitespace_string():
    assert _iter_alias_values("  ") == []


def test_iter_alias_values_list():
    assert _iter_alias_values(["a", "b", "c"]) == ["a", "b", "c"]


def test_iter_alias_values_list_with_empty_strings():
    assert _iter_alias_values(["a", "", "  ", "b"]) == ["a", "b"]


def test_iter_alias_values_list_with_non_strings():
    assert _iter_alias_values(["a", 42, None, "b"]) == ["a", "b"]  # type: ignore[list-item]


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
    assert _load_json_if_exists(p) == {"key": "value"}


def test_load_json_if_exists_missing_file(tmp_path: Path):
    assert _load_json_if_exists(tmp_path / "nonexistent.json") is None


def test_load_json_if_exists_invalid_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("not json {{{", encoding="utf-8")
    assert _load_json_if_exists(p) is None


def test_load_json_if_exists_directory(tmp_path: Path):
    assert _load_json_if_exists(tmp_path) is None


# ---------------------------------------------------------------------------
# alias_file_candidates
# ---------------------------------------------------------------------------


def test_alias_file_candidates_returns_list(tmp_path: Path):
    candidates = alias_file_candidates(data_dir=tmp_path / "raw")
    assert isinstance(candidates, list)
    assert len(candidates) >= 1


def test_alias_file_candidates_includes_registry_dir(tmp_path: Path):
    paths_str = [str(c) for c in alias_file_candidates(data_dir=tmp_path / "raw")]
    assert any("plugin_aliases.json" in p for p in paths_str)


# ---------------------------------------------------------------------------
# load_plugin_alias_map
# ---------------------------------------------------------------------------


def test_load_plugin_alias_map_empty_dir(tmp_path: Path):
    (tmp_path / "registry").mkdir(parents=True)
    result = load_plugin_alias_map(data_dir=tmp_path)
    assert isinstance(result, dict)
    assert result == {}


def test_load_plugin_alias_map_reads_alias_json(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    (registry_dir / "plugin_aliases.json").write_text(
        json.dumps({"old-name": "new-name"}), encoding="utf-8"
    )
    assert load_plugin_alias_map(data_dir=tmp_path).get("old-name") == "new-name"


def test_load_plugin_alias_map_reads_registry_jsonl(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps({"plugin_id": "new-name", "aliases": ["old-name", "former-name"]}) + "\n",
        encoding="utf-8",
    )
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert result.get("old-name") == "new-name"
    assert result.get("former-name") == "new-name"


def test_load_plugin_alias_map_infers_data_dir_from_registry_path(tmp_path: Path):
    raw_dir = tmp_path / "raw"
    registry_dir = raw_dir / "registry"
    plugins_dir = raw_dir / "plugins"
    registry_dir.mkdir(parents=True)
    plugins_dir.mkdir(parents=True)

    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(json.dumps({"plugin_id": "canonical-plugin"}) + "\n", encoding="utf-8")
    (plugins_dir / "canonical-plugin.snapshot.json").write_text(
        json.dumps({"plugin_id": "canonical-plugin", "aliases": ["snapshot-alias"]}),
        encoding="utf-8",
    )

    assert (
        load_plugin_alias_map(registry_path=registry_path).get("snapshot-alias")
        == "canonical-plugin"
    )


def test_load_plugin_alias_map_reads_snapshot_files(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "canonical-plugin.snapshot.json").write_text(
        json.dumps({"plugin_id": "canonical-plugin", "aliases": ["snap-alias"]}),
        encoding="utf-8",
    )
    assert load_plugin_alias_map(data_dir=tmp_path).get("snap-alias") == "canonical-plugin"


def test_load_plugin_alias_map_snapshot_with_plugin_api_aliases(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "canonical-plugin.snapshot.json").write_text(
        json.dumps(
            {
                "plugin_id": "canonical-plugin",
                "plugin_api": {"previousNames": ["api-former-name"]},
            }
        ),
        encoding="utf-8",
    )
    assert load_plugin_alias_map(data_dir=tmp_path).get("api-former-name") == "canonical-plugin"


def test_load_plugin_alias_map_skips_invalid_alias_json(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    (registry_dir / "plugin_aliases.json").write_text("{{{not valid json}}}", encoding="utf-8")
    assert isinstance(load_plugin_alias_map(data_dir=tmp_path), dict)


def test_load_plugin_alias_map_registry_path_skips_malformed_lines(tmp_path: Path):
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    content = (
        json.dumps({"plugin_id": "good-plugin", "aliases": ["good-alias"]})
        + "\n"
        + "not json {{\n"
        + json.dumps({"plugin_id": "another-plugin", "aliases": ["another-alias"]})
        + "\n"
    )
    registry_path.write_text(content, encoding="utf-8")
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert result.get("good-alias") == "good-plugin"
    assert result.get("another-alias") == "another-plugin"


def test_load_plugin_alias_map_snapshot_derives_id_from_filename(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "derived-plugin.snapshot.json").write_text(
        json.dumps({"aliases": ["snap-filename-alias"]}), encoding="utf-8"
    )
    assert load_plugin_alias_map(data_dir=tmp_path).get("snap-filename-alias") == "derived-plugin"


def test_snapshot_file_multiple_previous_names_all_registered(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    snap = {
        "plugin_id": "my-plugin",
        "plugin_api": {"previousNames": ["old-plugin-name", "older-plugin-name"]},
    }
    (plugins_dir / "my-plugin.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")
    alias_map = load_plugin_alias_map(data_dir=tmp_path)
    assert alias_map.get("old-plugin-name") == "my-plugin"
    assert alias_map.get("older-plugin-name") == "my-plugin"


def test_snapshot_file_with_no_previous_names_adds_no_aliases(tmp_path: Path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    snap = {"plugin_id": "clean-plugin", "plugin_api": {}}
    (plugins_dir / "clean-plugin.snapshot.json").write_text(json.dumps(snap), encoding="utf-8")
    alias_map = load_plugin_alias_map(data_dir=tmp_path)
    assert "clean-plugin" not in alias_map


# ---------------------------------------------------------------------------
# load_plugin_alias_map — registry JSONL edge cases
# ---------------------------------------------------------------------------


def test_load_plugin_alias_map_skips_non_dict_jsonl_lines(tmp_path: Path):
    """A JSONL line that parses as a non-dict (e.g. a bare number) is skipped."""
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    # Mix of a valid record, a bare number, and another valid record
    registry_path.write_text(
        json.dumps({"plugin_id": "good-plugin", "aliases": ["good-alias"]})
        + "\n"
        + "42\n"
        + json.dumps({"plugin_id": "other-plugin", "aliases": ["other-alias"]})
        + "\n",
        encoding="utf-8",
    )
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert result.get("good-alias") == "good-plugin"
    assert result.get("other-alias") == "other-plugin"


def test_load_plugin_alias_map_registry_oserror_is_silently_ignored(
    tmp_path: Path, monkeypatch
) -> None:
    """If opening the registry file raises OSError, it's swallowed and an empty
    map is returned (lines 119-120 branch)."""
    registry_dir = tmp_path / "registry"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps({"plugin_id": "my-plugin", "aliases": ["old-name"]}) + "\n",
        encoding="utf-8",
    )

    original_open = Path.open

    def bad_open(self: Path, *args, **kwargs):
        if self == registry_path:
            raise OSError("permission denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", bad_open)
    # Should not raise; OSError is swallowed
    result = load_plugin_alias_map(registry_path=registry_path, data_dir=tmp_path)
    assert isinstance(result, dict)
