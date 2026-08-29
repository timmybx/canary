"""
tools/enrich_monthly_features.py
================================
Attach the ``advhist_*`` and ``ghclock_*`` feature families to an existing
labeled monthly dataset, without re-running the monthly build.

Why
---
Tier 1 of the honest-signal plan: features computable from data already on
disk. ``advhist_*`` (advisory recurrence: months since last advisory,
trailing counts, mean gap, latest batch size) comes straight from the
labeled rows' advisory calendar. ``ghclock_*`` (days since last human push /
release / PR merge / issue / tag, at month end) comes from the normalized
GH Archive events, replacing the Software Heritage visit-based staleness
clocks with exact timestamps. Neither family emits missing values: "never"
is encoded as an explicit cap plus a has-history flag, so the imputation
layer never turns "no history" into "just happened" (see the encoding note
in canary/build/enrich_monthly.py).

Everything is as-of the observation month — no value depends on advisories
or events after it — so the enriched file is safe for the embargoed
training path and the rolling backtest.

Usage
-----
    docker compose run --rm canary python tools/enrich_monthly_features.py

    # advhist only (fast — skips the 3GB event scan):
    docker compose run --rm canary python tools/enrich_monthly_features.py --skip-ghclock

Measuring the new families needs no new filter files — train on the
enriched output with include-prefixes, e.g.:

    python tools/rolling_backtest.py \\
        --in-path data/processed/features/plugins.monthly.labeled.enriched.jsonl \\
        --model xgboost --start 2023-05 --end 2025-05 --step 2 --test-months 2 \\
        --include-prefixes advisory_,advisories_,advhist_ \\
        --out-dir data/processed/results/rolling_backtest/advhist_xgb

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

from canary.build.enrich_monthly import enrich_rows  # noqa: E402
from canary.build.monthly_labels import _load_jsonl, _write_jsonl  # noqa: E402

DEFAULT_IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
DEFAULT_OUT_PATH = "data/processed/features/plugins.monthly.labeled.enriched.jsonl"
DEFAULT_EVENTS_DIR = "data/raw/gharchive/normalized-events"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--in-path", default=DEFAULT_IN_PATH, help="labeled dataset (jsonl)")
    parser.add_argument("--out-path", default=DEFAULT_OUT_PATH, help="enriched output (jsonl)")
    parser.add_argument(
        "--events-dir",
        default=DEFAULT_EVENTS_DIR,
        help="directory of normalized GH Archive event jsonl files (for ghclock_*)",
    )
    parser.add_argument(
        "--skip-ghclock",
        action="store_true",
        help="only add advhist_* (no event scan; much faster)",
    )
    args = parser.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    if out_path.resolve() == in_path.resolve():
        raise SystemExit("Refusing to overwrite the input file; pick a different --out-path.")

    t0 = time.time()
    print(f"Loading {in_path} …")
    rows = _load_jsonl(in_path)
    print(f"  {len(rows):,} rows ({time.time() - t0:.0f}s)")

    events_dir = None if args.skip_ghclock else args.events_dir
    if events_dir is not None:
        print(f"Scanning events under {events_dir} … (this reads every monthly file)")

    enriched, summary = enrich_rows(rows, events_dir=events_dir)

    print(f"Writing {out_path} …")
    _write_jsonl(out_path, enriched)
    summary_path = Path(str(out_path) + ".summary.json")
    summary["input_path"] = str(in_path)
    summary["output_path"] = str(out_path)
    summary["skip_ghclock"] = bool(args.skip_ghclock)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"Done in {time.time() - t0:.0f}s: {summary['row_count']:,} rows, "
        f"+{summary['added_column_count']} columns "
        f"({len(summary['advhist_columns'])} advhist_, {len(summary['ghclock_columns'])} ghclock_)."
    )
    print(f"Summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
