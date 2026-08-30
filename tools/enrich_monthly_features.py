"""
tools/enrich_monthly_features.py
================================
Attach the post-hoc feature families (advhist_/ghclock_/ghtext_/contagion_/
ghdyn_/swhdelta_) to an existing labeled monthly dataset, without re-running
the monthly build.

Why
---
Features computable from data already on disk — no new collection. Six
families (see canary/build/enrich_monthly.py for definitions and the
no-missing-values encoding):

    advhist_    advisory recurrence (from the labeled rows themselves)
    ghclock_    days-since-last-<event kind> clocks (GH Archive events)
    ghtext_     security/CVE-vocabulary recency and counts (event text)
    contagion_  shared-maintainer graph, rebuilt as-of each month
    ghdyn_      contributor turnover / churn / concentration
    swhdelta_   Software Heritage visit-to-visit deltas + governance adoption

All four event families share a single pass over the events directory. No
family emits missing values: "never" is an explicit cap plus a has-* flag,
so the imputation layer never turns "no history" into "just happened".

Everything is as-of the observation month — no value depends on advisories
or events after it — so the enriched file is safe for the embargoed
training path and the rolling backtest.

Usage
-----
    # everything (default: all six families):
    docker compose run --rm canary python tools/enrich_monthly_features.py

    # a subset:
    docker compose run --rm canary python tools/enrich_monthly_features.py \\
        --families contagion,ghtext,ghdyn,swhdelta

    # advhist only (fast — skips the 3GB event scan):
    docker compose run --rm canary python tools/enrich_monthly_features.py --skip-ghclock

Measuring the new families needs no new filter files — train on the
enriched output with include-prefixes, e.g.:

    python tools/rolling_backtest.py \\
        --in-path data/processed/features/plugins.monthly.labeled.enriched.jsonl \\
        --model xgboost --start 2023-05 --end 2025-05 --step 2 --test-months 2 \\
        --include-prefixes contagion_ \\
        --out-dir data/processed/results/rolling_backtest/contagion_xgb

Output
------
    <out-path>                    the enriched JSONL (all original columns
                                  preserved, new families appended)
    <out-path>.summary.json       row/column counts and the added columns
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from canary.build.enrich_monthly import (  # noqa: E402
    ALL_FAMILIES,
    EVENT_FAMILIES,
    build_family_features,
)
from canary.build.monthly_labels import (  # noqa: E402
    _get_month_value,
    _row_has_advisory_this_month,
)

DEFAULT_IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
DEFAULT_OUT_PATH = "data/processed/features/plugins.monthly.labeled.enriched.jsonl"
DEFAULT_EVENTS_DIR = "data/raw/gharchive/normalized-events"
DEFAULT_SWH_DIR = "data/raw/software_heritage_athena"


def _stream_jsonl(path: Path):
    """Yield one parsed JSON object per non-blank line."""
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Invalid JSON on line {line_no} of {path}") from exc


def _collect_minimal_rows(in_path: Path) -> list[dict]:
    """
    First streaming pass: only the three fields the feature builders read.
    Keeps peak memory to the feature maps rather than the full dataset —
    the full rows of a 1.3GB labeled file do not fit comfortably in a
    memory-constrained container twice over, and a partially-written output
    is worse than a crash.
    """
    minimal: list[dict] = []
    for row in _stream_jsonl(in_path):
        minimal.append(
            {
                "plugin_id": row.get("plugin_id"),
                "month": _get_month_value(row),
                "advisory_count_this_month": int(_row_has_advisory_this_month(row))
                and int(row.get("advisory_count_this_month") or 1),
            }
        )
    return minimal


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--in-path", default=DEFAULT_IN_PATH, help="labeled dataset (jsonl)")
    parser.add_argument("--out-path", default=DEFAULT_OUT_PATH, help="enriched output (jsonl)")
    parser.add_argument(
        "--events-dir",
        default=DEFAULT_EVENTS_DIR,
        help="directory of normalized GH Archive event jsonl files (event families)",
    )
    parser.add_argument(
        "--swh-dir",
        default=DEFAULT_SWH_DIR,
        help="directory of <plugin>.swh_athena_visits.jsonl files (for swhdelta_*)",
    )
    parser.add_argument(
        "--families",
        default=",".join(ALL_FAMILIES),
        help=f"comma-separated subset of: {','.join(ALL_FAMILIES)} (default: all)",
    )
    parser.add_argument(
        "--skip-ghclock",
        action="store_true",
        help="drop every event-based family (no event scan; much faster)",
    )
    args = parser.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    if out_path.resolve() == in_path.resolve():
        raise SystemExit("Refusing to overwrite the input file; pick a different --out-path.")

    families = tuple(f.strip() for f in args.families.split(",") if f.strip())
    unknown = set(families) - set(ALL_FAMILIES)
    if unknown:
        raise SystemExit(
            f"Unknown families: {', '.join(sorted(unknown))} (valid: {', '.join(ALL_FAMILIES)})"
        )
    if args.skip_ghclock:
        families = tuple(f for f in families if f not in EVENT_FAMILIES)

    t0 = time.time()
    print(f"Pass 1: scanning {in_path} for the advisory calendar …")
    minimal = _collect_minimal_rows(in_path)
    print(f"  {len(minimal):,} rows ({time.time() - t0:.0f}s)")

    needs_events = any(f in EVENT_FAMILIES for f in families)
    if needs_events:
        print(f"Scanning events under {args.events_dir} … (one pass serves all event families)")
    by_family = build_family_features(
        minimal,
        families=families,
        events_dir=args.events_dir if needs_events else None,
        swh_dir=args.swh_dir if "swhdelta" in families else None,
    )

    # Second streaming pass: merge and write row by row. The output goes to a
    # temp file that is renamed into place only on success, so an interrupted
    # run (OOM, ctrl-C, container kill) can never leave a partial file at the
    # real output path masquerading as a complete dataset.
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Pass 2: writing {out_path} …")
    written = 0
    try:
        with tmp_path.open("w", encoding="utf-8") as f:
            for row in _stream_jsonl(in_path):
                key = (str(row.get("plugin_id") or ""), _get_month_value(row))
                for family in ALL_FAMILIES:
                    feats = by_family.get(family)
                    if feats:
                        row.update(feats.get(key, {}))
                f.write(json.dumps(row, sort_keys=True) + "\n")
                written += 1
        if written != len(minimal):
            raise SystemExit(
                f"Input changed between passes: pass 1 saw {len(minimal):,} rows, "
                f"pass 2 saw {written:,}. Aborting without touching {out_path}."
            )
        tmp_path.replace(out_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    columns = {
        f"{family}_columns": sorted({k for feats in by_family[family].values() for k in feats})
        if family in by_family
        else []
        for family in ALL_FAMILIES
    }
    summary = {
        "row_count": written,
        "plugin_count": len({str(r.get("plugin_id") or "") for r in minimal}),
        **columns,
        "added_column_count": sum(len(cols) for cols in columns.values()),
        "families": list(families),
        "input_path": str(in_path),
        "output_path": str(out_path),
    }
    summary_path = Path(str(out_path) + ".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    per_family = ", ".join(f"{len(columns[f'{family}_columns'])} {family}_" for family in by_family)
    print(
        f"Done in {time.time() - t0:.0f}s: {written:,} rows, "
        f"+{summary['added_column_count']} columns ({per_family})."
    )
    print(f"Summary: {summary_path}")
    print(
        "Sanity: the summary file existing is the completion marker — "
        "if it is absent, the run did not finish."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
