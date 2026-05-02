#!/usr/bin/env bash
# =============================================================================
# run_monthly_ablation_experiments.sh
#
# Runs the full CANARY ablation experiment suite.
#
# Experiment matrix
# -----------------
#   Models:          logistic, xgboost, lightgbm, random_forest
#   Split strategies: time (chronological), group_time (held-out plugins + time)
#   Feature families: advisory_only, gharchive_only, swh_only,
#                     advisory_gharchive, advisory_swh, gharchive_swh,
#                     full_no_time (all families, window_ vars excluded),
#                     full_cleaned (everything)
#
# Split strategy notes
# --------------------
#   time        Trains on months before TEST_START_MONTH, tests on months at
#               or after. Fast and useful for understanding performance, but
#               plugins in the test set were seen in training — this can
#               inflate tree model scores in small ecosystems.
#
#   group_time  Holds out a random PLUGIN_TEST_FRACTION of plugins entirely
#               from training, then tests only on those held-out plugins in
#               months >= TEST_START_MONTH. More conservative and better
#               measures generalisation to unseen plugins.
#
# Usage
# -----
#   # Run all experiments (default):
#   bash tools/run_monthly_ablation_experiments.sh
#
#   # Run only section 1 (logistic baselines):
#   bash tools/run_monthly_ablation_experiments.sh --section 1
#
#   # Run only group_time experiments (sections 5–6):
#   bash tools/run_monthly_ablation_experiments.sh --section 5
#   bash tools/run_monthly_ablation_experiments.sh --section 6
#
#   # Skip rebuilding filtered files if they already exist:
#   bash tools/run_monthly_ablation_experiments.sh --skip-filter
#
#   # Dry-run: print commands without executing:
#   bash tools/run_monthly_ablation_experiments.sh --dry-run
#
# Estimated wall time (Docker, single machine)
# --------------------------------------------
#   Logistic experiments (~12):   ~6 min
#   Tree model experiments (~17): ~50 min
#   Total:                        ~1 hour
#
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IN_PATH="data/processed/features/plugins.monthly.labeled.jsonl"
OUT_BASE="data/processed/features"
MODEL_BASE="data/processed/models"

TARGET_COL="label_advisory_within_6m"
TEST_START_MONTH="2025-05"

# group_time split settings
GROUP_COL="plugin_id"
PLUGIN_TEST_FRACTION="0.2"
RANDOM_SEED="42"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ONLY_SECTION=""
SKIP_FILTER=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --section)
      ONLY_SECTION="$2"; shift 2 ;;
    --skip-filter)
      SKIP_FILTER=1; shift ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--section N] [--skip-filter] [--dry-run]" >&2
      exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_run() {
  # Wrapper that either executes or just prints the command (--dry-run).
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[DRY RUN] $*"
  else
    "$@"
  fi
}

_section_active() {
  # Returns true if ONLY_SECTION is unset or matches the given section number.
  local section="$1"
  [[ -z "$ONLY_SECTION" || "$ONLY_SECTION" == "$section" ]]
}

_train() {
  # _train <model> <split_strategy> <in_path> <out_dir> [extra args...]
  #
  # Wraps `docker compose run --rm canary canary train baseline` with the
  # shared settings, and appends any extra arguments passed after the first four.
  local model="$1"
  local split="$2"
  local in_path="$3"
  local out_dir="$4"
  shift 4

  local cmd=(
    docker compose run --rm canary
    canary train baseline
    --in-path       "$in_path"
    --target-col    "$TARGET_COL"
    --model         "$model"
    --out-dir       "$out_dir"
    --test-start-month "$TEST_START_MONTH"
    --split-strategy   "$split"
    --random-seed   "$RANDOM_SEED"
  )

  # group and group_time splits need group-col and test-fraction
  if [[ "$split" == "group" || "$split" == "group_time" ]]; then
    cmd+=(
      --group-col       "$GROUP_COL"
      --test-fraction   "$PLUGIN_TEST_FRACTION"
    )
  fi

  # Any extra arguments passed by the caller (e.g. --exclude-cols, --include-prefixes)
  cmd+=("$@")

  echo ""
  echo "--- $(date '+%H:%M:%S') | model=$model split=$split out=$(basename "$out_dir") ---"
  _run "${cmd[@]}"
}

# ---------------------------------------------------------------------------
# Section 0 — Build filtered feature files
# ---------------------------------------------------------------------------
# These produce the single-family and combined-family JSONL files that all
# subsequent experiments consume.  Each filter run is idempotent: the output
# file is overwritten if it exists (controlled by --skip-filter).
# ---------------------------------------------------------------------------

if _section_active 0 && [[ "$SKIP_FILTER" -eq 0 ]]; then
  echo ""
  echo "======================================================================="
  echo "Section 0 — Creating filtered monthly labeled files"
  echo "======================================================================="

  for spec in \
    "advisory_:$OUT_BASE/plugins.monthly.labeled.advisory_only.jsonl" \
    "gharchive_:$OUT_BASE/plugins.monthly.labeled.gharchive_only.jsonl" \
    "swh_:$OUT_BASE/plugins.monthly.labeled.swh_only.jsonl" \
    "advisory_,gharchive_:$OUT_BASE/plugins.monthly.labeled.advisory_gharchive.jsonl" \
    "advisory_,swh_:$OUT_BASE/plugins.monthly.labeled.advisory_swh.jsonl" \
    "gharchive_,swh_:$OUT_BASE/plugins.monthly.labeled.gharchive_swh.jsonl"
  do
    families="${spec%%:*}"
    out_path="${spec##*:}"
    echo "  Filtering families=$families -> $out_path"
    _run python tools/filter_monthly_labeled_features.py \
      --in-path  "$IN_PATH" \
      --out-path "$out_path" \
      --families "$families"
  done

  # full_no_time drops the window_ time variables to avoid temporal leakage confounds
  echo "  Filtering all families, dropping time fields -> plugins.monthly.labeled.full_no_time.jsonl"
  _run python tools/filter_monthly_labeled_features.py \
    --in-path  "$IN_PATH" \
    --out-path "$OUT_BASE/plugins.monthly.labeled.full_no_time.jsonl" \
    --families "advisory_,gharchive_,swh_" \
    --drop-time-fields
else
  [[ "$SKIP_FILTER" -eq 1 ]] && echo "" && echo "Skipping section 0 (--skip-filter)."
fi

# Convenience aliases for the filtered paths used throughout
ADVISORY_ONLY="$OUT_BASE/plugins.monthly.labeled.advisory_only.jsonl"
GHARCHIVE_ONLY="$OUT_BASE/plugins.monthly.labeled.gharchive_only.jsonl"
SWH_ONLY="$OUT_BASE/plugins.monthly.labeled.swh_only.jsonl"
ADV_GHA="$OUT_BASE/plugins.monthly.labeled.advisory_gharchive.jsonl"
ADV_SWH="$OUT_BASE/plugins.monthly.labeled.advisory_swh.jsonl"
GHA_SWH="$OUT_BASE/plugins.monthly.labeled.gharchive_swh.jsonl"
FULL_NO_TIME="$OUT_BASE/plugins.monthly.labeled.full_no_time.jsonl"
FULL_CLEANED="$IN_PATH"  # The main labeled file includes window_ time variables

# =============================================================================
# Section 1 — Logistic regression, time split (reproducibility baselines)
# =============================================================================
# These reproduce the original ablation runs.  They are fast (~30s each),
# interpretable via signed coefficients, and serve as the anchor for all
# comparisons with tree models and stricter split strategies.
# =============================================================================

if _section_active 1; then
  echo ""
  echo "======================================================================="
  echo "Section 1 — Logistic regression | split=time"
  echo "Reproduces original ablation baselines with signed coefficient output."
  echo "======================================================================="

  _train logistic time "$ADVISORY_ONLY"  "$MODEL_BASE/logistic_6m_advisory_only"
  _train logistic time "$GHARCHIVE_ONLY" "$MODEL_BASE/logistic_6m_gharchive_only"
  _train logistic time "$SWH_ONLY"       "$MODEL_BASE/logistic_6m_swh_only"
  _train logistic time "$ADV_GHA"        "$MODEL_BASE/logistic_6m_advisory_gharchive"
  _train logistic time "$ADV_SWH"        "$MODEL_BASE/logistic_6m_advisory_swh"
  _train logistic time "$GHA_SWH"        "$MODEL_BASE/logistic_6m_gharchive_swh"
  _train logistic time "$FULL_NO_TIME"   "$MODEL_BASE/logistic_6m_full_no_time"
  _train logistic time "$FULL_CLEANED"   "$MODEL_BASE/logistic_6m_full_cleaned"
fi

# =============================================================================
# Section 2 — XGBoost, time split (performance ceiling / leakage check)
# =============================================================================
# XGBoost with a time split typically yields very high AUC in small ecosystems
# because it can learn plugin-identity patterns across the training/test
# boundary.  These results document that ceiling and set up the comparison with
# the group_time variants in section 5.
# =============================================================================

if _section_active 2; then
  echo ""
  echo "======================================================================="
  echo "Section 2 — XGBoost | split=time"
  echo "Documents performance ceiling; compare with group_time (section 5)"
  echo "to assess how much is generalizable signal vs. plugin-identity leakage."
  echo "======================================================================="

  _train xgboost time "$ADVISORY_ONLY"  "$MODEL_BASE/xgb_6m_advisory_only_time"
  _train xgboost time "$SWH_ONLY"       "$MODEL_BASE/xgb_6m_swh_only_time"
  _train xgboost time "$GHARCHIVE_ONLY" "$MODEL_BASE/xgb_6m_gharchive_only_time"
  _train xgboost time "$FULL_NO_TIME"   "$MODEL_BASE/xgb_6m_full_no_time_time"
  _train xgboost time "$FULL_CLEANED"   "$MODEL_BASE/xgb_6m_full_cleaned_time"
fi

# =============================================================================
# Section 3 — LightGBM, time split (compare to XGBoost, time split)
# =============================================================================
# LightGBM uses a different gradient boosting implementation.  Running the
# same key configurations allows direct model-family comparison under
# identical evaluation conditions.
# =============================================================================

if _section_active 3; then
  echo ""
  echo "======================================================================="
  echo "Section 3 — LightGBM | split=time"
  echo "Parallel to XGBoost section 2; allows direct model-family comparison."
  echo "======================================================================="

  _train lightgbm time "$SWH_ONLY"     "$MODEL_BASE/lgb_6m_swh_only_time"
  _train lightgbm time "$FULL_NO_TIME" "$MODEL_BASE/lgb_6m_full_no_time_time"
  _train lightgbm time "$FULL_CLEANED" "$MODEL_BASE/lgb_6m_full_cleaned_time"
fi

# =============================================================================
# Section 4 — Random Forest, time split (third ensemble for completeness)
# =============================================================================
# Random Forest is a bagging ensemble rather than a boosting one.  Including
# it gives a third point of comparison for feature importance stability and
# performance, without the gradient-boosting-specific characteristics of XGB/LGB.
# =============================================================================

if _section_active 4; then
  echo ""
  echo "======================================================================="
  echo "Section 4 — Random Forest | split=time"
  echo "Bagging ensemble; third comparison point for feature importance."
  echo "======================================================================="

  _train random_forest time "$SWH_ONLY"     "$MODEL_BASE/rf_6m_swh_only_time"
  _train random_forest time "$FULL_CLEANED" "$MODEL_BASE/rf_6m_full_cleaned_time"
fi

# =============================================================================
# Section 5 — Logistic regression, group_time split (rigorous evaluation)
# =============================================================================
# group_time holds out PLUGIN_TEST_FRACTION of plugins entirely from training,
# then evaluates only on those held-out plugins in months >= TEST_START_MONTH.
# This prevents plugin-identity leakage and better measures how CANARY would
# perform on plugins it has never seen before — the realistic deployment case.
# =============================================================================

if _section_active 5; then
  echo ""
  echo "======================================================================="
  echo "Section 5 — Logistic regression | split=group_time"
  echo "Most defensible evaluation: held-out plugins + chronological cutoff."
  echo "Plugin test fraction: $PLUGIN_TEST_FRACTION | seed: $RANDOM_SEED"
  echo "======================================================================="

  _train logistic group_time "$ADVISORY_ONLY" "$MODEL_BASE/logistic_6m_advisory_only_gt"
  _train logistic group_time "$SWH_ONLY"      "$MODEL_BASE/logistic_6m_swh_only_gt"
  _train logistic group_time "$FULL_NO_TIME"  "$MODEL_BASE/logistic_6m_full_no_time_gt"
  _train logistic group_time "$FULL_CLEANED"  "$MODEL_BASE/logistic_6m_full_cleaned_gt"
fi

# =============================================================================
# Section 6 — Tree models, group_time split (generalisation under rigorous eval)
# =============================================================================
# The same group_time evaluation applied to XGBoost, LightGBM, and Random
# Forest.  A large drop in AUC vs. the time-split results (section 2–4)
# indicates the models were exploiting plugin-identity patterns rather than
# learning generalizable behavioral signals.  A smaller drop supports the
# claim that the features carry real predictive content.
# =============================================================================

if _section_active 6; then
  echo ""
  echo "======================================================================="
  echo "Section 6 — Tree models | split=group_time"
  echo "Compare to time-split results to quantify plugin-identity leakage."
  echo "======================================================================="

  _train xgboost       group_time "$ADVISORY_ONLY" "$MODEL_BASE/xgb_6m_advisory_only_gt"
  _train xgboost       group_time "$SWH_ONLY"      "$MODEL_BASE/xgb_6m_swh_only_gt"
  _train xgboost       group_time "$FULL_NO_TIME"  "$MODEL_BASE/xgb_6m_full_no_time_gt"
  _train xgboost       group_time "$FULL_CLEANED"  "$MODEL_BASE/xgb_6m_full_cleaned_gt"

  _train lightgbm      group_time "$SWH_ONLY"      "$MODEL_BASE/lgb_6m_swh_only_gt"
  _train lightgbm      group_time "$FULL_CLEANED"  "$MODEL_BASE/lgb_6m_full_cleaned_gt"

  _train random_forest group_time "$FULL_CLEANED"  "$MODEL_BASE/rf_6m_full_cleaned_gt"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "======================================================================="
echo "Done. Results written under: $MODEL_BASE"
echo ""
echo "Experiment summary"
echo "------------------"
echo ""
echo "Section 1 — Logistic / time split (baseline comparisons)"
echo "  logistic_6m_advisory_only         advisory features only"
echo "  logistic_6m_gharchive_only        GH Archive features only"
echo "  logistic_6m_swh_only              Software Heritage features only"
echo "  logistic_6m_advisory_gharchive    advisory + GH Archive"
echo "  logistic_6m_advisory_swh          advisory + Software Heritage"
echo "  logistic_6m_gharchive_swh         GH Archive + Software Heritage (no advisory history)"
echo "  logistic_6m_full_no_time          all families, window_ time vars excluded"
echo "  logistic_6m_full_cleaned          all families including window_ time vars"
echo ""
echo "Section 2 — XGBoost / time split (performance ceiling)"
echo "  xgb_6m_advisory_only_time"
echo "  xgb_6m_swh_only_time"
echo "  xgb_6m_gharchive_only_time"
echo "  xgb_6m_full_no_time_time"
echo "  xgb_6m_full_cleaned_time"
echo ""
echo "Section 3 — LightGBM / time split"
echo "  lgb_6m_swh_only_time"
echo "  lgb_6m_full_no_time_time"
echo "  lgb_6m_full_cleaned_time"
echo ""
echo "Section 4 — Random Forest / time split"
echo "  rf_6m_swh_only_time"
echo "  rf_6m_full_cleaned_time"
echo ""
echo "Section 5 — Logistic / group_time split (rigorous evaluation)"
echo "  logistic_6m_advisory_only_gt"
echo "  logistic_6m_swh_only_gt"
echo "  logistic_6m_full_no_time_gt"
echo "  logistic_6m_full_cleaned_gt"
echo ""
echo "Section 6 — Tree models / group_time split (generalisation check)"
echo "  xgb_6m_advisory_only_gt"
echo "  xgb_6m_swh_only_gt"
echo "  xgb_6m_full_no_time_gt"
echo "  xgb_6m_full_cleaned_gt"
echo "  lgb_6m_swh_only_gt"
echo "  lgb_6m_full_cleaned_gt"
echo "  rf_6m_full_cleaned_gt"
echo "======================================================================="