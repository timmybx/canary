#!/usr/bin/env bash
# crossval/pypi/05_rolling_embargo.sh
# ====================================
# PyPI advisory-only check under the SAME embargoed rolling-origin protocol
# as the Jenkins development sweep (docs/panel_extension_protocol.md §1):
# 13 folds, test starts 2023-05 -> 2025-05 step 2, 2-month test windows,
# training labels rebuilt as-of test start + 1 month at every fold.
#
# Three runs:
#   advisory_only_xgb        embargoed, xgboost   (the PyPI headline model)
#   advisory_only_logistic   embargoed, logistic  (coefficient-readable reference)
#   advisory_only_xgb_leaky  same folds, stored labels (--no-embargo), for the
#                            leaky-vs-honest side-by-side
#
# Requires data/pypi/processed/monthly_labeled.jsonl rebuilt by the patched
# 02_build_monthly.py (it must carry plugin_id and advisory_count_this_month;
# the run aborts otherwise). Nothing here touches the Jenkins data, models or
# the out-of-time holdout.
#
# Usage (from the repo root):
#   docker compose run --rm canary bash crossval/pypi/05_rolling_embargo.sh
#   DRY_RUN=1 bash crossval/pypi/05_rolling_embargo.sh   # print commands only

set -euo pipefail

IN_PATH="${IN_PATH:-data/pypi/processed/monthly_labeled.jsonl}"
OUT_ROOT="${OUT_ROOT:-data/pypi/processed/results/rolling_backtest}"
START="${START:-2023-05}"
END="${END:-2025-05}"
STEP="${STEP:-2}"
TEST_MONTHS="${TEST_MONTHS:-2}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"

if [ ! -f "$IN_PATH" ]; then
  echo "missing $IN_PATH — run: python crossval/pypi/02_build_monthly.py" >&2
  exit 1
fi
if ! head -n 1 "$IN_PATH" | grep -q '"advisory_count_this_month"'; then
  echo "$IN_PATH predates the embargo columns — rebuild with the patched 02_build_monthly.py" >&2
  exit 1
fi

run() {
  local name="$1"; shift
  echo
  echo "=== $name ==="
  local cmd=(python tools/rolling_backtest.py
    --in-path "$IN_PATH"
    --start "$START" --end "$END" --step "$STEP" --test-months "$TEST_MONTHS"
    --include-prefixes advisory_
    --out-dir "$OUT_ROOT/$name"
    "$@")
  echo "${cmd[*]}"
  if [ "${DRY_RUN:-0}" != "1" ]; then
    "${cmd[@]}" 2>&1 | tee "$OUT_ROOT/$name.log"
  fi
}

mkdir -p "$OUT_ROOT"

# --- 1. embargoed, xgboost (headline) ---------------------------------------
run advisory_only_xgb --model xgboost

# --- 2. embargoed, logistic (reference) --------------------------------------
run advisory_only_logistic --model logistic

# --- 3. same folds, stored (leaky) labels ------------------------------------
run advisory_only_xgb_leaky --model xgboost --no-embargo

echo
echo "done. Summaries: $OUT_ROOT/*/rolling_backtest.json  (logs: $OUT_ROOT/*.log)"
