"""
tools/heuristic_baseline.py
============================
Compare CANARY's ML ranking against a trivial rule-based baseline.

Because advisory history is CANARY's dominant signal family, a fair committee
question is whether the ML model adds value over the obvious heuristic:
"flag any plugin that has ever had an advisory."  This tool answers that
question directly, at the component level, on a single observation month
(default 2025-05, the case study snapshot, whose 6 month label window is
fully covered by the advisory data).

Three comparisons are reported:

1.  The flag rule as a set: flag plugins with advisory_count_to_date >= 1.
    Reports set size, precision, coverage of positive plugins, and lift.
    A set is not a ranking; it cannot be cut to a review budget.

2.  CANARY at the matched budget: the model's top-N plugins where N equals
    the number the rule flagged, so both approaches spend the same review
    effort.  Reports precision, coverage, and lift.

3.  Ranked heuristic vs CANARY at k = 10, 25, 50, 100: the heuristic ranked
    by advisory_count_to_date (descending; ties broken alphabetically for
    determinism, and tie group sizes are reported because ties dominate
    this ranking) against the model's probability ranking.

Usage
-----
    # inside the container
    python tools/heuristic_baseline.py

    # different model or month
    python tools/heuristic_baseline.py \
        --model-dir data/processed/models/xgb_6m_advisory_swh_time \
        --month 2025-05
    python tools/heuristic_baseline.py --json data/processed/results/heuristic_baseline.json

Input
-----
    data/processed/features/plugins.monthly.labeled.jsonl  (rule features + labels)
    <model-dir>/test_predictions.csv                       (model ranking)

Output
------
    Console comparison tables; optional JSON.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
MODEL_DIR = "data/processed/models/xgb_6m_full_cleaned_time"
MONTH = "2025-05"
TARGET_COL = "label_advisory_within_6m"
RULE_COL = "advisory_count_to_date"
K_VALUES = (10, 25, 50, 100)


def _load_snapshot(path: str | Path, month: str) -> dict[str, dict[str, Any]]:
    """One row per plugin for the observation month: rule feature + label."""
    plugins: dict[str, dict[str, Any]] = {}
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if str(r.get("month", "")) != month:
                continue
            plugins[str(r["plugin_id"])] = {
                "advisory_count": int(r.get(RULE_COL) or 0),
                "positive": int(r.get(TARGET_COL) or 0) == 1,
            }
    return plugins


def _load_model_ranking(model_dir: str | Path, month: str) -> list[tuple[str, float, bool]]:
    """(plugin_id, prob, positive) for the observation month, highest prob first."""
    rows: list[tuple[str, float, bool]] = []
    with (Path(model_dir) / "test_predictions.csv").open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if str(r.get("month", "")) != month:
                continue
            rows.append((r["plugin_id"], float(r["y_prob"]), int(r["y_true"]) == 1))
    rows.sort(key=lambda x: (-x[1], x[0]))
    return rows


def _set_metrics(
    flagged_pos: int, flagged_n: int, total_pos: int, base_rate: float
) -> dict[str, Any]:
    precision = flagged_pos / flagged_n if flagged_n else 0.0
    return {
        "n": flagged_n,
        "true_positives": flagged_pos,
        "precision": round(precision, 4),
        "coverage": round(flagged_pos / total_pos, 4) if total_pos else None,
        "lift": round(precision / base_rate, 1) if base_rate else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Rule-based baseline vs CANARY ranking.")
    parser.add_argument("--data", default=IN_PATH)
    parser.add_argument("--model-dir", default=MODEL_DIR)
    parser.add_argument("--month", default=MONTH)
    parser.add_argument("--min-advisories", type=int, default=1, help="rule threshold")
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    plugins = _load_snapshot(args.data, args.month)
    n_plugins = len(plugins)
    total_pos = sum(1 for v in plugins.values() if v["positive"])
    base_rate = total_pos / n_plugins if n_plugins else 0.0
    print(
        f"Snapshot {args.month}: {n_plugins} plugins, {total_pos} positive "
        f"(component base rate {base_rate:.2%})\n"
    )

    out: dict[str, Any] = {
        "month": args.month,
        "n_plugins": n_plugins,
        "n_positive": total_pos,
        "base_rate": round(base_rate, 5),
        "model_dir": str(args.model_dir),
        "rule": f"{RULE_COL} >= {args.min_advisories}",
    }

    # 1. The flag rule as a set.
    flagged = {p: v for p, v in plugins.items() if v["advisory_count"] >= args.min_advisories}
    flagged_pos = sum(1 for v in flagged.values() if v["positive"])
    rule = _set_metrics(flagged_pos, len(flagged), total_pos, base_rate)
    out["rule_set"] = rule
    print(f"1. Flag rule ({RULE_COL} >= {args.min_advisories}) as a set:")
    print(
        f"   flags {rule['n']} plugins ({rule['n'] / n_plugins:.1%} of ecosystem), "
        f"precision {rule['precision']:.3f}, coverage {rule['coverage']:.0%}, "
        f"lift {rule['lift']}x\n"
    )

    # 2. CANARY at the matched budget.
    ranking = _load_model_ranking(args.model_dir, args.month)
    if not ranking:
        raise SystemExit(f"No rows for month {args.month} in {args.model_dir}/test_predictions.csv")
    model_plugins = {pid for pid, _, _ in ranking}
    model_pos = sum(1 for _, _, y in ranking if y)
    if model_plugins != set(plugins) or model_pos != total_pos:
        print(
            f"WARNING: snapshot and model prediction sets disagree "
            f"({len(plugins)} vs {len(model_plugins)} plugins, "
            f"{total_pos} vs {model_pos} positives). Coverage figures are only "
            "valid when both cover the same plugin set for the same month.\n"
        )
    budget = len(flagged)
    top = ranking[:budget]
    top_pos = sum(1 for _, _, y in top if y)
    model_at_budget = _set_metrics(top_pos, len(top), total_pos, base_rate)
    out["model_at_matched_budget"] = model_at_budget
    print(f"2. CANARY top {budget} (same review budget as the rule):")
    print(
        f"   precision {model_at_budget['precision']:.3f}, "
        f"coverage {model_at_budget['coverage']:.0%}, lift {model_at_budget['lift']}x\n"
    )

    # 3. Ranked heuristic vs model at fixed k.
    heur_order = sorted(plugins.items(), key=lambda kv: (-kv[1]["advisory_count"], kv[0]))
    print(f"3. Ranked comparison at fixed review sizes ({args.month} snapshot):")
    header = (
        f"   {'k':>4} {'heuristic P@k':>14} {'heuristic cov':>14} "
        f"{'CANARY P@k':>11} {'CANARY cov':>11}"
    )
    print(header)
    print("   " + "-" * (len(header) - 3))
    ranked: list[dict[str, Any]] = []
    for k in K_VALUES:
        h_top = heur_order[:k]
        h_pos = sum(1 for _, v in h_top if v["positive"])
        m_top = ranking[:k]
        m_pos = sum(1 for _, _, y in m_top if y)
        entry = {
            "k": k,
            "heuristic_precision": round(h_pos / k, 4),
            "heuristic_coverage": round(h_pos / total_pos, 4) if total_pos else None,
            "model_precision": round(m_pos / k, 4),
            "model_coverage": round(m_pos / total_pos, 4) if total_pos else None,
        }
        ranked.append(entry)
        print(
            f"   {k:>4} {entry['heuristic_precision']:>14.3f} "
            f"{entry['heuristic_coverage']:>14.0%} {entry['model_precision']:>11.3f} "
            f"{entry['model_coverage']:>11.0%}"
        )
    out["ranked_comparison"] = ranked

    # Tie structure of the heuristic ranking (ties dominate count-based rankings).
    counts: dict[int, int] = {}
    for v in plugins.values():
        counts[v["advisory_count"]] = counts.get(v["advisory_count"], 0) + 1
    top_counts = sorted((c for c in counts if c >= args.min_advisories), reverse=True)[:5]
    tie_note = {str(c): counts[c] for c in top_counts}
    out["heuristic_tie_groups"] = tie_note
    print(
        f"\n   Note: heuristic ranking is dominated by ties "
        f"(plugins per advisory count, top values): {tie_note}. "
        "Within a tie group the ordering is arbitrary, so heuristic P@k values "
        "depend on tie breaking; CANARY produces a total order."
    )

    if args.json:
        outp = Path(args.json)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"\nSaved: {outp}")


if __name__ == "__main__":
    main()
