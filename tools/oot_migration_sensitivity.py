"""
tools/oot_migration_sensitivity.py
==================================
Descriptive sensitivity check for the out-of-time (OOT) result, declared in
``docs/panel_extension_protocol.md`` (changelog, 2026-09-01, Event 2).

Why
---
On 2025-12-01 the ``jenkins-infra-bot`` account bulk-migrated JIRA issues
into GitHub for ~155 cohort plugins (smaller waves in 2025-11 and 2026-01).
The account was added to the bot list under the protocol's §6 deviation
policy, which fixes the actor-filtered ``ghdyn_*`` features, but the
``ghclock_days_since_issue_opened`` clock is NOT actor-filtered, so it
resets for the migrated plugins inside the third OOT fold (test window
2025-11/12). The protocol commits to reporting a fold-3 sensitivity that
excludes those plugins "as a secondary, descriptive number alongside the
primary result".

This tool does exactly that and nothing more: it re-scores the ALREADY
RECORDED test predictions of each declared OOT run with the migrated
plugins' fold-3 rows dropped. No model is trained, no feature is rebuilt,
and the primary numbers are untouched — this is a re-scoring of the
recorded predictions, permitted under §5 as reporting.

Affected plugins are identified from the normalized GH Archive event store:
any plugin with an ``IssuesEvent`` opened by ``jenkins-infra-bot`` in a
month inside the fold-3 test window (2025-11, 2025-12).

Usage
-----
    docker compose run --rm canary python tools/oot_migration_sensitivity.py

    # explicit paths
    python tools/oot_migration_sensitivity.py \\
        --events-dir data/raw/gharchive/normalized-events \\
        --results-dir data/processed/results/rolling_backtest \\
        --runs oot_champion oot_runnerup oot_ghclock_logistic \\
        --control-runs ghclock_ghdyn_logistic ghclock_installs_xgb ghclock_only_logistic \\
        --fold 2025-11 --out data/processed/results/rolling_backtest/oot_migration_sensitivity.json

Controls (why the headline number alone is not enough)
-------------------------------------------------------
The migrated plugins are the ones that HAD a JIRA tracker, i.e. the active,
watched plugins, and those carry a disproportionate share of advisories.
Dropping them therefore removes a positive-rich subset from the fold, and
the ROC-AUC would move even if the clock reset had no effect at all. Two
descriptive controls separate the two readings without training anything:

* the same exclusion applied to EVERY fold of the run (the earlier OOT
  folds and, via ``--control-runs``, the 13 development folds of the same
  configuration), where no migration happened. If those folds move by a
  similar amount, the movement is a population effect, not the artifact;
* within-subset ROC-AUC: the ranking quality among the migrated plugins
  only and among the rest only, per fold. A reset clock that pushed every
  migrated plugin to the top of the list would show up as a between-group
  effect (high overall, weak within-subset), not as better ranking inside
  the subset.

Output
------
A JSON file with, per run: the recorded fold-3 metrics, per-fold metrics
with and without the migrated plugins and within each subset, and the
pooled metrics with and without the exclusion (fold-3 only, and all folds).
``--control-runs`` adds the same per-fold table for the named development
runs. Plus console tables.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from canary.train.oot_sensitivity import (  # noqa: E402
    DEFAULT_CONTROL_RUNS,
    DEFAULT_FOLD,
    DEFAULT_RUNS,
    MIGRATION_ACTOR,
    find_migrated_plugins,
    fold_months,
    sensitivity_for_run,
)


def _fmt(v: Any) -> str:
    return "-" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--events-dir", default="data/raw/gharchive/normalized-events")
    ap.add_argument("--data-raw-dir", default="data/raw", help="for plugin alias canonicalization")
    ap.add_argument("--results-dir", default="data/processed/results/rolling_backtest")
    ap.add_argument("--runs", nargs="+", default=list(DEFAULT_RUNS))
    ap.add_argument(
        "--control-runs",
        nargs="*",
        default=list(DEFAULT_CONTROL_RUNS),
        help="development-era runs to re-score with the same exclusion on every fold",
    )
    ap.add_argument("--fold", default=DEFAULT_FOLD, help="test start month of the affected fold")
    ap.add_argument("--test-months", type=int, default=2)
    ap.add_argument(
        "--out",
        default="data/processed/results/rolling_backtest/oot_migration_sensitivity.json",
    )
    args = ap.parse_args(argv)

    months = fold_months(args.fold, args.test_months)
    migrated = find_migrated_plugins(
        Path(args.events_dir), months, data_raw_dir=Path(args.data_raw_dir)
    )
    print(f"{MIGRATION_ACTOR} opened issues on {len(migrated)} plugins in {months}")

    results = []
    for run in args.runs:
        run_dir = Path(args.results_dir) / run
        if not run_dir.exists():
            print(f"  skip {run}: {run_dir} not found")
            continue
        results.append(sensitivity_for_run(run_dir, fold_start=args.fold, migrated=migrated))

    controls = []
    for run in args.control_runs:
        run_dir = Path(args.results_dir) / run
        if not run_dir.exists():
            print(f"  skip control {run}: {run_dir} not found")
            continue
        controls.append(sensitivity_for_run(run_dir, fold_start=None, migrated=migrated))

    payload = {
        "actor": MIGRATION_ACTOR,
        "fold": args.fold,
        "months": months,
        "migrated_plugin_count": len(migrated),
        "migrated_plugins": sorted(migrated),
        "runs": results,
        "control_runs": controls,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print()
    print(
        f"{'run':<22} {'fold ROC':>9} {'excl ROC':>9} {'fold lift':>9} {'excl lift':>9} "
        f"{'pooled ROC':>10} {'excl pool':>9}  dropped rows/pos"
    )
    for r in results:
        print(
            f"{r['run']:<22} {_fmt(r['fold_all']['roc_auc']):>9} "
            f"{_fmt(r['fold_excluding_migrated']['roc_auc']):>9} "
            f"{_fmt(r['fold_all']['ap_lift']):>9} "
            f"{_fmt(r['fold_excluding_migrated']['ap_lift']):>9} "
            f"{_fmt(r['pooled_all']['roc_auc']):>10} "
            f"{_fmt(r['pooled_excluding_migrated_fold_rows']['roc_auc']):>9}  "
            f"{r['fold_excluded_rows']}/{r['fold_excluded_positives']}"
        )

    def per_fold_table(r: dict[str, Any]) -> None:
        print(
            f"\n{r['run']}: per fold, same exclusion everywhere "
            f"(pooled all folds {_fmt(r['pooled_all']['roc_auc'])} -> "
            f"{_fmt(r['pooled_excluding_migrated_all_folds']['roc_auc'])} excluding)"
        )
        print(
            f"  {'fold':<8} {'all':>7} {'excl':>7} {'delta':>7} {'within mig':>10} "
            f"{'within rest':>11}  mig rows/pos"
        )
        for f in r["folds"]:
            a, e = f["all"]["roc_auc"], f["excluding_migrated"]["roc_auc"]
            delta = None if a is None or e is None else e - a
            print(
                f"  {f['fold']:<8} {_fmt(a):>7} {_fmt(e):>7} {_fmt(delta):>7} "
                f"{_fmt(f['within_migrated']['roc_auc']):>10} "
                f"{_fmt(f['within_rest']['roc_auc']):>11}  "
                f"{f['excluded_rows']}/{f['excluded_positives']}"
            )

    for r in results + controls:
        per_fold_table(r)
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
