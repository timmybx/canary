"""
End-to-end validity test for the modeling pipeline on synthetic fixtures:

    raw data -> build_monthly_feature_bundle -> build_monthly_labels
             -> train_baseline -> load_ml_scorer -> score_plugin_ml

This is the test that exercises the loose JSONL contracts between stages.
If a stage renames a column, changes a month key, or breaks the artifact
layout, this fails — instead of the pipeline silently producing degraded
labels, models, or scores.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from canary.build.monthly_features import build_monthly_feature_bundle
from canary.build.monthly_labels import build_monthly_labels
from canary.scoring.ml import load_ml_scorer, score_plugin_ml
from canary.train.baseline import train_baseline

ALPHA = "alpha-plugin"
BETA = "beta-plugin"


def _write_raw_tree(tmp_path: Path) -> Path:
    """Two plugins, twelve months of 2025; alpha has advisories in Jun + Oct."""
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir]:
        p.mkdir(parents=True, exist_ok=True)

    registry_rows = [{"plugin_id": pid, "title": pid} for pid in (ALPHA, BETA)]
    (registry_dir / "plugins.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in registry_rows), encoding="utf-8"
    )

    for pid in (ALPHA, BETA):
        (plugins_dir / f"{pid}.snapshot.json").write_text(
            json.dumps(
                {
                    "plugin_id": pid,
                    "plugin_api": {
                        "maintainers": [{"id": "alice"}],
                        "dependencies": [{"name": "structs"}],
                    },
                }
            ),
            encoding="utf-8",
        )
        (health_dir / f"{pid}.healthscore.json").write_text(
            json.dumps(
                {
                    "plugin_id": pid,
                    "collected_at": "2026-01-15T00:00:00+00:00",
                    "record": {"plugin_id": pid, "value": 75},
                }
            ),
            encoding="utf-8",
        )
        (github_dir / f"{pid}.github_index.json").write_text(
            json.dumps({"plugin_id": pid, "repo_full_name": f"jenkinsci/{pid}"}),
            encoding="utf-8",
        )

    advisories = [
        {
            "plugin_id": ALPHA,
            "published_date": "2025-06-15",
            "severity_summary": {"max_cvss_base_score": 7.5},
            "cve_ids": ["CVE-2025-1111"],
        },
        {
            "plugin_id": ALPHA,
            "published_date": "2025-10-10",
            "severity_summary": {"max_cvss_base_score": 5.0},
            "cve_ids": ["CVE-2025-2222"],
        },
    ]
    with (advisories_dir / f"{ALPHA}.advisories.real.jsonl").open("w", encoding="utf-8") as f:
        for rec in advisories:
            f.write(json.dumps(rec) + "\n")

    return data_raw


@pytest.fixture
def pipeline_artifacts(tmp_path: Path) -> dict[str, Any]:
    data_raw = _write_raw_tree(tmp_path)
    features_path = tmp_path / "processed" / "plugins.monthly.features.jsonl"
    labeled_path = tmp_path / "processed" / "plugins.monthly.labeled.jsonl"
    model_dir = tmp_path / "processed" / "models" / "e2e_3m"

    # Stage 1: monthly features (dense grid, leakage-safe to-date columns)
    feature_rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=data_raw / "registry" / "plugins.jsonl",
        start_month="2025-01",
        end_month="2025-12",
        out_path=features_path,
        out_csv_path=None,
        summary_path=None,
    )

    # Stage 2: positional horizon labels (density-validated)
    labeled_rows = build_monthly_labels(
        in_path=features_path,
        out_path=labeled_path,
        out_csv_path=None,
        summary_path=None,
        horizons=(1, 3),
    )

    # Stage 3: train a logistic baseline on the 3-month horizon
    metrics = train_baseline(
        in_path=labeled_path,
        target_col="label_advisory_within_3m",
        out_dir=model_dir,
        test_start_month="2025-07",
        model_name="logistic",
    )

    return {
        "data_raw": data_raw,
        "feature_rows": feature_rows,
        "labeled_rows": labeled_rows,
        "metrics": metrics,
        "model_dir": model_dir,
    }


def test_monthly_features_are_a_dense_grid(pipeline_artifacts: dict[str, Any]) -> None:
    rows = pipeline_artifacts["feature_rows"]
    assert len(rows) == 24  # 2 plugins x 12 months
    months = sorted({r["month"] for r in rows})
    assert months[0] == "2025-01"
    assert months[-1] == "2025-12"


def test_labels_match_known_advisory_timeline(pipeline_artifacts: dict[str, Any]) -> None:
    labeled = pipeline_artifacts["labeled_rows"]
    by_key = {(r["plugin_id"], r["month"]): r for r in labeled}

    # Alpha's June advisory: visible within 3 months from March-May.
    assert by_key[(ALPHA, "2025-03")]["label_advisory_within_3m"] == 1
    assert by_key[(ALPHA, "2025-05")]["label_advisory_within_3m"] == 1
    assert by_key[(ALPHA, "2025-05")]["label_advisory_within_1m"] == 1
    # June itself looks forward: next advisory is October, outside 3 months.
    assert by_key[(ALPHA, "2025-06")]["label_advisory_within_3m"] == 0
    # Right-censoring: December has no future window at all.
    assert by_key[(ALPHA, "2025-12")]["label_advisory_within_1m"] is None
    # Beta never has an advisory.
    assert by_key[(BETA, "2025-03")]["label_advisory_within_3m"] == 0


def test_training_produces_complete_artifacts(pipeline_artifacts: dict[str, Any]) -> None:
    metrics = pipeline_artifacts["metrics"]
    model_dir: Path = pipeline_artifacts["model_dir"]

    for artifact in (
        "metrics.json",
        "model.joblib",
        "feature_columns.json",
        "test_predictions.csv",
        "precision_at_k.json",
        "pr_curve.json",
    ):
        assert (model_dir / artifact).exists(), f"missing training artifact: {artifact}"

    # Both classes are present in train and test by construction, so the
    # ranking metrics must be computed (not None).
    assert metrics["roc_auc"] is not None
    assert metrics["average_precision"] is not None
    assert metrics["train_row_count"] > 0
    assert metrics["test_row_count"] > 0
    assert metrics["feature_count"] == len(metrics["feature_columns"])

    saved_columns = json.loads((model_dir / "feature_columns.json").read_text(encoding="utf-8"))
    assert saved_columns == metrics["feature_columns"]


def test_score_ml_round_trip_on_trained_model(pipeline_artifacts: dict[str, Any]) -> None:
    """The full inference path: load artifacts, rebuild a feature vector from
    the same raw tree, and score — exercising _BUNDLE_TO_MODEL on real I/O."""
    scorer = load_ml_scorer(pipeline_artifacts["model_dir"])
    assert scorer.model_name == "logistic"
    assert scorer.feature_columns  # non-empty contract

    result = score_plugin_ml(
        ALPHA,
        scorer=scorer,
        data_raw_dir=pipeline_artifacts["data_raw"],
    )

    assert result.plugin == ALPHA
    assert 0.0 <= result.probability <= 1.0
    assert result.risk_category in {"Low", "Medium", "High"}
    assert set(result.feature_vector.keys()) == set(scorer.feature_columns)

    # Inference-quality guard fields are populated and consistent.
    none_count = sum(1 for v in result.feature_vector.values() if v is None)
    assert result.missing_feature_count == none_count
    assert 0.0 <= result.missing_feature_fraction <= 1.0

    # The advisory history must actually reach the model: the mapped
    # training-name columns should be populated, not silently None.
    populated = {k for k, v in result.feature_vector.items() if v is not None}
    expected_mapped = {
        "advisory_count_to_date",
        "advisory_max_cvss_to_date",
    } & set(scorer.feature_columns)
    assert expected_mapped, "trained model lost all mapped advisory columns"
    assert expected_mapped <= populated, (
        "advisory features were collected but arrived at the model as None — "
        "_BUNDLE_TO_MODEL mapping is broken"
    )
