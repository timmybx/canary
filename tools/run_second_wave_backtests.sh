#!/usr/bin/env bash
# tools/run_second_wave_backtests.sh
# ==================================
# The full second-wave measurement grid: rolling-origin (embargoed) backtests
# for the new enrichment families (ghtext_/contagion_/ghdyn_/swhdelta_),
# alone and in combination with the ghclock_ champion — 14 configurations,
# all reported (the sweep-size disclosure is the point: the final number is
# "best of a declared 14-run sweep", not a cherry-pick).
#
# Prerequisite: the enriched dataset must exist and be COMPLETE —
#   docker compose run --rm canary python tools/enrich_monthly_features.py
# The `.summary.json` beside it is the completion marker; this script refuses
# to start without it and cross-checks the row count, so a truncated file
# (the failure mode that produced the ROC-0.400 garbage run) cannot be
# trained on silently.
#
# Usage:
#   docker compose run --rm canary bash tools/run_second_wave_backtests.sh
#
#   DRY_RUN=1 bash tools/run_second_wave_backtests.sh   # print, don't run
#
# Already-completed runs (out-dir contains rolling_backtest.json) are skipped,
# so the script is safe to re-run after an interruption.

set -euo pipefail
cd "$(dirname "$0")/.."

ENRICHED="${ENRICHED:-data/processed/features/plugins.monthly.labeled.enriched.jsonl}"
RESULTS_ROOT="${RESULTS_ROOT:-data/processed/results/rolling_backtest}"
EXPECTED_ROWS="${EXPECTED_ROWS:-197088}"
WINDOW_ARGS=(--start 2023-05 --end 2025-05 --step 2 --test-months 2)

# ── Pre-flight: refuse to train on a missing or truncated enriched file ────
if [[ ! -f "$ENRICHED" ]]; then
    echo "ERROR: $ENRICHED not found. Run tools/enrich_monthly_features.py first." >&2
    exit 1
fi
if [[ ! -f "$ENRICHED.summary.json" ]]; then
    echo "ERROR: $ENRICHED.summary.json is missing — the enrichment run did not" >&2
    echo "finish (the summary file is the completion marker). Re-run it." >&2
    exit 1
fi
summary_rows="$(python - "$ENRICHED.summary.json" <<'EOF'
import json, sys
print(json.load(open(sys.argv[1]))["row_count"])
EOF
)"
if [[ "$summary_rows" != "$EXPECTED_ROWS" ]]; then
    echo "ERROR: enriched summary reports $summary_rows rows, expected $EXPECTED_ROWS." >&2
    echo "(Override with EXPECTED_ROWS=<n> only if the panel really changed.)" >&2
    exit 1
fi
echo "Pre-flight OK: $ENRICHED complete with $summary_rows rows."

# ── Runner ─────────────────────────────────────────────────────────────────
run_backtest() {
    local name="$1" model="$2" prefixes="$3"
    local out_dir="$RESULTS_ROOT/$name"
    if [[ -f "$out_dir/rolling_backtest.json" ]]; then
        echo "== $name: already done, skipping ($out_dir/rolling_backtest.json exists)"
        return 0
    fi
    echo "== $name: model=$model prefixes=$prefixes"
    local cmd=(python tools/rolling_backtest.py
        --in-path "$ENRICHED"
        --model "$model"
        "${WINDOW_ARGS[@]}"
        --include-prefixes "$prefixes"
        --out-dir "$out_dir")
    if [[ "${DRY_RUN:-0}" != "0" ]]; then
        printf '   %q' "${cmd[@]}"
        printf '\n'
        return 0
    fi
    "${cmd[@]}"
}

t0=$SECONDS

# Phase 1: each new family alone (xgboost).
run_backtest ghtext_xgb            xgboost  ghtext_
run_backtest contagion_xgb         xgboost  contagion_
run_backtest ghdyn_xgb             xgboost  ghdyn_
run_backtest swhdelta_xgb          xgboost  swhdelta_

# Phase 2: ghclock_ champion + each family (xgboost).
run_backtest ghclock_ghtext_xgb    xgboost  ghclock_,ghtext_
run_backtest ghclock_contagion_xgb xgboost  ghclock_,contagion_
run_backtest ghclock_ghdyn_xgb     xgboost  ghclock_,ghdyn_
run_backtest ghclock_swhdelta_xgb  xgboost  ghclock_,swhdelta_

# Phase 3: all five honest families together.
run_backtest honest_all_xgb        xgboost  ghclock_,ghtext_,contagion_,ghdyn_,swhdelta_
run_backtest honest_all_logistic   logistic ghclock_,ghtext_,contagion_,ghdyn_,swhdelta_

# Phase 4: logistic on each champion pair (logistic is the current champion
# model family: ghclock_-only logistic, pooled ROC 0.627).
run_backtest ghclock_ghtext_logistic    logistic ghclock_,ghtext_
run_backtest ghclock_contagion_logistic logistic ghclock_,contagion_
run_backtest ghclock_ghdyn_logistic     logistic ghclock_,ghdyn_
run_backtest ghclock_swhdelta_logistic  logistic ghclock_,swhdelta_

echo "All 14 configurations done in $(( (SECONDS - t0) / 60 )) min."
echo "Every run is now visible on the web console's Honest evaluation tab."
echo "Sanity: every fold's test window should hold 4,106 rows — if any run"
echo "shows a different count, the enriched file is suspect; stop and check."
