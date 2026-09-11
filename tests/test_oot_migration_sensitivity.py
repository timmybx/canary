"""Tests for canary.train.oot_sensitivity (descriptive OOT re-scoring; CLI in tools/)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from canary.train import oot_sensitivity as oms


def _write_events(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def _write_fold(run_dir: Path, fold: str, rows: list[tuple[str, str, int, float]]) -> None:
    d = run_dir / f"fold_{fold}"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "test_predictions.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["plugin_id", "month", "y_true", "y_prob"])
        w.writeheader()
        for pid, month, y, p in rows:
            w.writerow({"plugin_id": pid, "month": month, "y_true": y, "y_prob": p})


def test_find_migrated_plugins_filters_actor_type_action_and_month(tmp_path: Path) -> None:
    events_dir = tmp_path / "events"
    _write_events(
        events_dir / "2025-11.gharchive.events.jsonl",
        [
            {
                "plugin_id": "a",
                "actor_login": "jenkins-infra-bot",
                "event_type": "IssuesEvent",
                "action": "opened",
            },
            {
                "plugin_id": "b",
                "actor_login": "jenkins-infra-bot",
                "event_type": "IssuesEvent",
                "action": "closed",
            },
            {
                "plugin_id": "c",
                "actor_login": "someone",
                "event_type": "IssuesEvent",
                "action": "opened",
            },
            {"plugin_id": "d", "actor_login": "jenkins-infra-bot", "event_type": "PushEvent"},
        ],
    )
    _write_events(
        events_dir / "2025-12.gharchive.events.jsonl",
        [{"plugin_id": "e", "actor_login": "jenkins-infra-bot", "event_type": "IssuesEvent"}],
    )
    _write_events(
        events_dir / "2026-01.gharchive.events.jsonl",
        [
            {
                "plugin_id": "f",
                "actor_login": "jenkins-infra-bot",
                "event_type": "IssuesEvent",
                "action": "opened",
            }
        ],
    )
    hit = oms.find_migrated_plugins(events_dir, ["2025-11", "2025-12"])
    # "e" has no action key -> treated as opened (matches enrich_monthly's clock rule)
    assert hit == {"a", "e"}


def test_find_migrated_plugins_missing_month_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        oms.find_migrated_plugins(tmp_path, ["2025-11"])


def test_sensitivity_excludes_only_affected_fold_rows(tmp_path: Path) -> None:
    run_dir = tmp_path / "oot_champion"
    # fold 1: perfect ranking; fold 3: migrated plugin "m" is a high-scored negative
    _write_fold(run_dir, "2025-09", [("x", "2025-09", 1, 0.9), ("y", "2025-09", 0, 0.1)] * 15)
    fold3 = [("m", "2025-11", 0, 0.95), ("m", "2025-12", 0, 0.94)]
    fold3 += [("p", "2025-11", 1, 0.8), ("q", "2025-11", 0, 0.2)] * 15
    _write_fold(run_dir, "2025-11", fold3)
    (run_dir / "rolling_backtest.json").write_text(
        json.dumps(
            {
                "model_name": "logistic",
                "include_prefixes": ["ghclock_"],
                "folds": [{"test_start_month": "2025-11", "roc_auc": 0.5}],
                "pooled": {"roc_auc": 0.6},
            }
        ),
        encoding="utf-8",
    )

    res = oms.sensitivity_for_run(run_dir, fold_start="2025-11", migrated={"m", "x"})

    # "x" lives in fold 1 and must NOT be dropped: exclusion is fold-3 only
    assert res["fold_excluded_rows"] == 2
    assert res["fold_excluded_positives"] == 0
    assert res["pooled_all"]["rows"] == 62
    assert res["pooled_excluding_migrated_fold_rows"]["rows"] == 60
    # the all-folds control exclusion DOES drop "x" (15 rows) as well
    assert res["pooled_excluding_migrated_all_folds"]["rows"] == 45
    by_fold = {f["fold"]: f for f in res["folds"]}
    assert by_fold["2025-09"]["excluded_rows"] == 15
    assert by_fold["2025-09"]["excluded_positives"] == 15
    assert by_fold["2025-11"]["within_migrated"]["roc_auc"] is None  # no positives among "m"
    assert by_fold["2025-11"]["within_rest"]["roc_auc"] == 1.0
    # dropping the two high-scored negatives can only raise fold-3 ROC-AUC
    assert res["fold_excluding_migrated"]["roc_auc"] == 1.0
    assert res["fold_all"]["roc_auc"] < 1.0
    assert by_fold["2025-11"]["recorded_roc_auc"] == 0.5
    assert res["recorded_pooled_roc_auc"] == 0.6


def test_control_run_has_no_affected_fold(tmp_path: Path) -> None:
    run_dir = tmp_path / "ghclock_only_logistic"
    _write_fold(run_dir, "2023-05", [("m", "2023-05", 1, 0.9), ("y", "2023-05", 0, 0.1)] * 15)
    (run_dir / "rolling_backtest.json").write_text(
        json.dumps({"model_name": "logistic", "folds": [], "pooled": {"roc_auc": 1.0}}),
        encoding="utf-8",
    )
    res = oms.sensitivity_for_run(run_dir, fold_start=None, migrated={"m"})
    assert res["affected_fold"] is None
    assert "fold_all" not in res and "pooled_excluding_migrated_fold_rows" not in res
    assert res["pooled_excluding_migrated_all_folds"]["rows"] == 15
    assert res["pooled_excluding_migrated_all_folds"]["roc_auc"] is None


def test_score_degenerate_labels_report_none() -> None:
    rows = [{"plugin_id": "a", "month": "2025-11", "y_true": 0, "y_prob": 0.3}] * 3
    out = oms.score(rows)
    assert out["positives"] == 0
    assert out["roc_auc"] is None and out["average_precision"] is None
