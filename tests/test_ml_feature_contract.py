"""
Validity guard: the _BUNDLE_TO_MODEL mapping in canary/scoring/ml.py is the
contract between training-time feature names (monthly_features.py) and
inference-time feature names (features_bundle.py loaders).

If either side renames a column, inference silently produces None for that
column and the imputer fills the training median — scores degrade with no
error. These tests fail loudly on any such rename.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from canary.build.features_bundle import (
    _load_advisory_features,
    _load_gharchive_features,
    _load_github_features,
    _load_healthscore_features,
    _load_snapshot_features,
    _load_software_heritage_features,
)
from canary.build.monthly_features import build_monthly_feature_bundle
from canary.scoring.ml import _BUNDLE_TO_MODEL, _window_features

PLUGIN_ID = "demo-plugin"


def _write_raw_fixture(tmp_path: Path) -> Path:
    """Minimal raw data tree with advisory + SWH + snapshot data present."""
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"
    swh_dir = data_raw / "software_heritage_api"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir, swh_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": PLUGIN_ID, "title": "Demo"}) + "\n", encoding="utf-8"
    )
    (plugins_dir / f"{PLUGIN_ID}.snapshot.json").write_text(
        json.dumps({"plugin_api": {"maintainers": [], "dependencies": []}}), encoding="utf-8"
    )
    (health_dir / f"{PLUGIN_ID}.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": PLUGIN_ID,
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": PLUGIN_ID, "value": 80},
            }
        ),
        encoding="utf-8",
    )
    (github_dir / f"{PLUGIN_ID}.github_index.json").write_text(
        json.dumps({"plugin_id": PLUGIN_ID, "repo_full_name": f"jenkinsci/{PLUGIN_ID}"}),
        encoding="utf-8",
    )
    (swh_dir / f"{PLUGIN_ID}.swh_index.json").write_text(
        json.dumps({"plugin_id": PLUGIN_ID, "origin_found": True, "snapshot_found": True}),
        encoding="utf-8",
    )
    (swh_dir / f"{PLUGIN_ID}.swh_visits.json").write_text(
        json.dumps({"results": [{"date": "2025-03-10T12:00:00+00:00"}]}), encoding="utf-8"
    )

    advisories = [
        {
            "plugin_id": PLUGIN_ID,
            "published_date": "2025-03-10",
            "severity_summary": {"max_cvss_base_score": 5.0},
            "cve_ids": ["CVE-2025-0001"],
        }
    ]
    with (advisories_dir / f"{PLUGIN_ID}.advisories.real.jsonl").open("w", encoding="utf-8") as f:
        for rec in advisories:
            f.write(json.dumps(rec) + "\n")

    return data_raw


def _bundle_loader_columns(data_raw: Path) -> set[str]:
    """Column names produced by the same loaders ml.py uses at inference."""
    raw: dict[str, Any] = {}
    raw.update(_load_snapshot_features(PLUGIN_ID, data_raw))
    raw.update(_load_advisory_features(PLUGIN_ID, data_raw))
    raw.update(_load_healthscore_features(PLUGIN_ID, data_raw))
    raw.update(_load_software_heritage_features(PLUGIN_ID, data_raw, backend="api"))
    raw.update(_load_github_features(PLUGIN_ID, data_raw))
    raw.update(_load_gharchive_features(PLUGIN_ID, data_raw))
    return set(raw.keys())


def _monthly_columns(data_raw: Path, tmp_path: Path) -> set[str]:
    """Column names produced by the monthly (training-time) feature builder."""
    rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=data_raw / "registry" / "plugins.jsonl",
        start_month="2025-03",
        end_month="2025-05",
        out_path=tmp_path / "monthly.jsonl",
        out_csv_path=None,
        summary_path=None,
        software_heritage_backend="api",
    )
    return {key for row in rows for key in row.keys()}


def test_bundle_to_model_keys_exist_in_bundle_loader_output(tmp_path: Path) -> None:
    """
    Every KEY in _BUNDLE_TO_MODEL must be a name the features_bundle loaders
    actually emit. A rename in features_bundle.py breaks this.
    """
    data_raw = _write_raw_fixture(tmp_path)
    bundle_cols = _bundle_loader_columns(data_raw)

    unknown_keys = sorted(set(_BUNDLE_TO_MODEL.keys()) - bundle_cols)
    assert not unknown_keys, (
        "_BUNDLE_TO_MODEL maps from bundle column names that the "
        f"features_bundle loaders no longer produce: {unknown_keys}. "
        "Update the mapping in canary/scoring/ml.py to match the rename, "
        "or ML inference will silently impute these features."
    )


def test_bundle_to_model_values_exist_in_monthly_output(tmp_path: Path) -> None:
    """
    Every VALUE in _BUNDLE_TO_MODEL must be a name the monthly feature builder
    actually emits (i.e. a name models are trained on). A rename in
    monthly_features.py breaks this.
    """
    data_raw = _write_raw_fixture(tmp_path)
    monthly_cols = _monthly_columns(data_raw, tmp_path)

    unknown_values = sorted(set(_BUNDLE_TO_MODEL.values()) - monthly_cols)
    assert not unknown_values, (
        "_BUNDLE_TO_MODEL maps to training column names that "
        f"monthly_features.py no longer produces: {unknown_values}. "
        "Update the mapping in canary/scoring/ml.py to match the rename, "
        "or ML inference will silently impute these features."
    )


def test_mapping_is_meaningful_and_window_features_are_synthesized() -> None:
    """
    Structural sanity for the mapping itself: no identity entries (a key
    mapping to itself means the rename it patched no longer exists), no two
    bundle columns collapsing onto one training column, and the window_*
    features models expect are synthesized rather than loaded.
    """
    identity = sorted(k for k, v in _BUNDLE_TO_MODEL.items() if k == v)
    assert not identity, (
        f"_BUNDLE_TO_MODEL contains identity mappings {identity}; "
        "remove them — they indicate the underlying rename was reverted."
    )

    values = list(_BUNDLE_TO_MODEL.values())
    assert len(values) == len(set(values)), (
        "_BUNDLE_TO_MODEL maps two different bundle columns onto the same "
        "training column; the second silently overwrites the first."
    )

    window = _window_features()
    assert set(window.keys()) == {"window_year", "window_month", "window_index"}
    assert all(isinstance(v, float) for v in window.values())
