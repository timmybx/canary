#!/usr/bin/env bash
set -euo pipefail

IN_PATH="data/processed/features/plugins.monthly.labeled.jsonl"
OUT_BASE="data/processed/features"
MODEL_BASE="data/processed/models"
TARGET_COL="label_advisory_within_6m"
TEST_START_MONTH="2025-05"

echo "=== Creating filtered monthly labeled files ==="

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.advisory_only.jsonl" \
  --families advisory_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.gharchive_only.jsonl" \
  --families gharchive_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.swh_only.jsonl" \
  --families swh_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.advisory_gharchive.jsonl" \
  --families advisory_,gharchive_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.advisory_swh.jsonl" \
  --families advisory_,swh_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.gharchive_swh.jsonl" \
  --families gharchive_,swh_

python tools/filter_monthly_labeled_features.py \
  --in-path "$IN_PATH" \
  --out-path "$OUT_BASE/plugins.monthly.labeled.full_no_time.jsonl" \
  --families advisory_,gharchive_,swh_ \
  --drop-time-fields

echo "=== Running baseline experiments ==="

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.advisory_only.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_advisory_only"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.gharchive_only.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_gharchive_only"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.swh_only.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_swh_only"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.advisory_gharchive.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_advisory_gharchive"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.advisory_swh.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_advisory_swh"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.gharchive_swh.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_gharchive_swh"

docker compose run --rm canary canary train baseline \
  --in-path "$OUT_BASE/plugins.monthly.labeled.full_no_time.jsonl" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_full_no_time"

docker compose run --rm canary canary train baseline \
  --in-path "$IN_PATH" \
  --target-col "$TARGET_COL" \
  --test-start-month "$TEST_START_MONTH" \
  --out-dir "$MODEL_BASE/baseline_6m_full_cleaned"

echo "=== Done ==="
echo "Results written under: $MODEL_BASE"