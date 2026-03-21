from __future__ import annotations

import json
from pathlib import Path

from canary.build.monthly_features import build_monthly_feature_bundle
from canary.plugin_aliases import alias_candidates, canonicalize_plugin_id
from canary.scoring.baseline import score_plugin_baseline
from canary.webapp import _plugin_known


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
