"""
Descriptive fold-3 migration sensitivity for the out-of-time (OOT) result.

Library half of ``tools/oot_migration_sensitivity.py``; see that script's
docstring for the motivation (protocol changelog 2026-09-01, Event 2) and
the controls. Everything here re-scores ALREADY RECORDED test predictions:
no model is trained and no feature is rebuilt.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from canary.plugin_aliases import canonicalize_plugin_id

MIGRATION_ACTOR = "jenkins-infra-bot"
DEFAULT_RUNS = ("oot_champion", "oot_runnerup", "oot_ghclock_logistic")
# Development-era runs of the same three configurations, in the same order.
DEFAULT_CONTROL_RUNS = ("ghclock_ghdyn_logistic", "ghclock_installs_xgb", "ghclock_only_logistic")
DEFAULT_FOLD = "2025-11"


def fold_months(fold_start: str, test_months: int = 2) -> list[str]:
    year, month = (int(p) for p in fold_start.split("-"))
    out = []
    for _ in range(test_months):
        out.append(f"{year:04d}-{month:02d}")
        month += 1
        if month > 12:
            month = 1
            year += 1
    return out


def find_migrated_plugins(
    events_dir: Path,
    months: list[str],
    *,
    actor: str = MIGRATION_ACTOR,
    data_raw_dir: Path | None = None,
) -> set[str]:
    """Plugins with >=1 IssuesEvent opened by *actor* in any of *months*."""
    hit: set[str] = set()
    for month in months:
        path = events_dir / f"{month}.gharchive.events.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"normalized event file missing: {path}")
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                if str(ev.get("actor_login") or "") != actor:
                    continue
                if ev.get("event_type") != "IssuesEvent":
                    continue
                action = str(ev.get("action") or "opened").lower()
                if action != "opened":
                    continue
                pid = str(ev.get("plugin_id") or "").strip()
                if not pid:
                    continue
                if data_raw_dir is not None:
                    pid = canonicalize_plugin_id(pid, data_dir=data_raw_dir)
                hit.add(pid)
    return hit


def read_predictions(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8", newline="") as fh:
        rows = []
        for r in csv.DictReader(fh):
            rows.append(
                {
                    "plugin_id": r["plugin_id"],
                    "month": r["month"],
                    "y_true": int(float(r["y_true"])),
                    "y_prob": float(r["y_prob"]),
                }
            )
    return rows


def score(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """ROC-AUC / AP / lift over base rate / row-level P@25 over *rows*."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    y = [r["y_true"] for r in rows]
    p = [r["y_prob"] for r in rows]
    n = len(rows)
    pos = sum(y)
    base = pos / n if n else 0.0
    out: dict[str, Any] = {"rows": n, "positives": pos, "base_rate": round(base, 6)}
    if pos == 0 or pos == n:
        out.update({"roc_auc": None, "average_precision": None, "ap_lift": None})
        return out
    ap = float(average_precision_score(y, p))
    out["roc_auc"] = round(float(roc_auc_score(y, p)), 6)
    out["average_precision"] = round(ap, 6)
    out["ap_lift"] = round(ap / base, 4) if base else None
    # Row-level P@25, the same definition as ``ranking_metrics`` in the runner
    # (so it is comparable with the recorded fold value).
    top = sorted(rows, key=lambda r: -r["y_prob"])[:25]
    out["precision_at_25"] = (
        round(sum(r["y_true"] for r in top) / 25, 4) if len(rows) >= 25 else None
    )
    return out


def fold_breakdown(rows: list[dict[str, Any]], migrated: set[str]) -> dict[str, Any]:
    """All / excluding migrated / within migrated / within rest, for one fold."""
    kept = [r for r in rows if r["plugin_id"] not in migrated]
    dropped = [r for r in rows if r["plugin_id"] in migrated]
    return {
        "all": score(rows),
        "excluding_migrated": score(kept),
        "within_migrated": score(dropped),
        "within_rest": score(kept),
        "excluded_rows": len(dropped),
        "excluded_positives": sum(r["y_true"] for r in dropped),
        "excluded_plugins": len({r["plugin_id"] for r in dropped}),
    }


def sensitivity_for_run(
    run_dir: Path,
    *,
    fold_start: str | None,
    migrated: set[str],
) -> dict[str, Any]:
    """
    Re-score one run's recorded predictions. *fold_start* names the affected
    fold (the pooled "fold-only" exclusion drops migrated plugins from that
    fold alone); pass None for a control run, where no fold is affected and
    only the all-folds exclusion is meaningful.
    """
    summary = json.loads((run_dir / "rolling_backtest.json").read_text(encoding="utf-8"))
    fold_dirs = sorted(d for d in run_dir.glob("fold_*") if d.is_dir())
    target = run_dir / f"fold_{fold_start}" if fold_start else None
    if target is not None and target not in fold_dirs:
        raise FileNotFoundError(f"{target} not found among {[d.name for d in fold_dirs]}")

    recorded_by_fold = {
        f.get("test_start_month"): f.get("roc_auc") for f in summary.get("folds", [])
    }
    folds: list[dict[str, Any]] = []
    pooled_all: list[dict[str, Any]] = []
    pooled_excl_fold: list[dict[str, Any]] = []
    pooled_excl_all: list[dict[str, Any]] = []
    for d in fold_dirs:
        rows = read_predictions(d / "test_predictions.csv")
        month = d.name.removeprefix("fold_")
        kept = [r for r in rows if r["plugin_id"] not in migrated]
        folds.append(
            {"fold": month, "recorded_roc_auc": recorded_by_fold.get(month)}
            | fold_breakdown(rows, migrated)
        )
        pooled_all.extend(rows)
        pooled_excl_all.extend(kept)
        pooled_excl_fold.extend(kept if d == target else rows)

    out: dict[str, Any] = {
        "run": run_dir.name,
        "model": summary.get("model_name"),
        "include_prefixes": summary.get("include_prefixes"),
        "affected_fold": fold_start,
        "recorded_pooled_roc_auc": (summary.get("pooled") or {}).get("roc_auc"),
        "folds": folds,
        "pooled_all": score(pooled_all),
        "pooled_excluding_migrated_all_folds": score(pooled_excl_all),
    }
    if target is not None:
        affected = next(f for f in folds if f["fold"] == fold_start)
        out["fold_all"] = affected["all"]
        out["fold_excluding_migrated"] = affected["excluding_migrated"]
        out["fold_excluded_rows"] = affected["excluded_rows"]
        out["fold_excluded_positives"] = affected["excluded_positives"]
        out["pooled_excluding_migrated_fold_rows"] = score(pooled_excl_fold)
    return out
