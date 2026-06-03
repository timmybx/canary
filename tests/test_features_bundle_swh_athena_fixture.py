from __future__ import annotations

import json
import shutil
from pathlib import Path

from canary.build.features_bundle import (
    _load_software_heritage_features,
    _load_software_heritage_features_athena,
    build_feature_bundle,
)


def _copy_swh_athena_fixture(data_raw: Path) -> None:
    fixture_dir = Path(__file__).parent / "fixtures" / "software_heritage_athena"
    target_dir = data_raw / "software_heritage_athena"
    target_dir.mkdir(parents=True, exist_ok=True)
    for fixture_file in fixture_dir.iterdir():
        shutil.copy(fixture_file, target_dir / fixture_file.name)


def test_load_swh_athena_features_from_fixture_files(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    _copy_swh_athena_fixture(data_raw)

    row = _load_software_heritage_features_athena("demo-plugin", data_raw)

    assert row["swh_present"] is True
    assert row["swh_origin_found"] is True
    assert row["swh_has_snapshot"] is True
    assert row["swh_visit_count"] == 2
    assert row["swh_first_visit_date"] == "2024-06-01"
    assert row["swh_latest_visit_date"] == "2025-06-15"
    assert row["swh_archive_age_days"] == 379
    assert row["swh_visits_last_365d"] == 1

    # The current static feature builder intentionally uses the first visit record
    # as the latest/representative Athena snapshot payload.
    assert row["swh_has_readme"] is True
    assert row["swh_has_dot_github"] is True
    assert row["swh_has_jenkinsfile"] is True
    assert row["swh_has_security_md"] is True
    assert row["swh_has_changelog"] is True
    assert row["swh_has_dockerfile"] is True
    assert row["swh_has_pom_xml"] is True
    assert row["swh_has_mvn_wrapper"] is True
    assert row["swh_has_tests_directory"] is True
    assert row["swh_has_github_actions"] is True
    assert row["swh_has_dependabot"] is True
    assert row["swh_has_snyk_config"] is True
    assert row["swh_has_travis_yml"] is False
    assert row["swh_has_contributing_md"] is False
    assert row["swh_has_build_gradle"] is False
    assert row["swh_has_sonar_config"] is False

    assert row["swh_top_level_entry_count"] == 17
    assert row["swh_commit_count"] == 42
    assert row["swh_days_since_last_commit"] == 11
    assert row["swh_author_committer_lag_p50_hours"] == 1.5
    assert row["swh_author_committer_lag_p90_hours"] == 8.25
    assert row["swh_timezone_diversity"] == 3
    assert row["swh_weekend_commit_fraction"] == 0.2
    assert row["swh_security_fix_commit_count"] == 4
    assert row["swh_merge_commit_fraction"] == 0.6
    assert row["swh_conventional_commit_fraction"] == 0.7
    assert row["swh_issue_reference_rate"] == 0.8
    assert row["swh_empty_message_rate"] == 0.0
    assert row["swh_author_committer_mismatch_rate"] == 0.1
    assert row["swh_late_night_commit_fraction"] == 0.05
    assert row["swh_backend"] == "athena"


def test_swh_backend_auto_selects_athena_when_fixture_dir_exists(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    _copy_swh_athena_fixture(data_raw)

    row = _load_software_heritage_features("demo-plugin", data_raw)

    assert row["swh_present"] is True
    assert row["swh_backend"] == "athena"
    assert row["swh_commit_count"] == 42


def test_build_feature_bundle_uses_swh_athena_fixture_in_ci(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    _copy_swh_athena_fixture(data_raw)

    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo Plugin"}) + "\n",
        encoding="utf-8",
    )

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_path,
        out_path=tmp_path / "plugins.features.jsonl",
        out_csv_path=None,
        summary_path=None,
        software_heritage_backend="athena",
    )

    assert len(rows) == 1
    assert rows[0]["plugin_id"] == "demo-plugin"
    assert rows[0]["swh_present"] is True
    assert rows[0]["swh_origin_found"] is True
    assert rows[0]["swh_visit_count"] == 2
    assert rows[0]["swh_commit_count"] == 42
