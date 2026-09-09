#!/usr/bin/env bash
set -euo pipefail
# Build the CANARY reproducibility bundle for Zenodo upload.
#
# Usage (from the repo root, Git Bash or Linux):
#   bash tools/make_zenodo_bundle.sh [output_dir]
#
# Default output_dir is ~/Downloads/canary-zenodo-<version> (kept outside the
# repo and outside OneDrive-synced folders; the bundle is several GB).
#
# Contents:
#   - every labeled monthly dataset (gzipped individually, so downstream users
#     can fetch only the variant they need) — the master panel, the per-family
#     ablation variants, and the enriched panels of the honest layer
#     (enriched / enriched2 / enriched_asof) with their .summary.json markers
#   - the plugin snapshot feature files (small tarball)
#   - the full saved model suite (metrics, predictions, feature lists, models)
#   - the analysis results (source-of-record SHAP, H1 odds, Brier, the
#     embargo suite comparison, and every rolling-backtest run directory —
#     development sweep, pre-registered out-of-time runs, sensitivity runs);
#     quarantined *_INVALID_* and *_PARTIAL_* directories are excluded
#   - docs/panel_extension_protocol.md, the pre-registered protocol whose
#     changelog is the provenance record for the honest-layer numbers
#   - DATASET_README.md with provenance, and a sha256 MANIFEST (verified)

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)
[ -n "$VERSION" ] || VERSION="unknown"
OUT="${1:-$HOME/Downloads/canary-zenodo-v$VERSION}"
SRC="data/processed"

[ -d "$SRC/features" ] && [ -d "$SRC/models" ] || { echo "ERROR: run from the repo root (data/processed not found)"; exit 1; }
mkdir -p "$OUT"

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DESC=$(git describe --tags --always)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Version: $VERSION | Git: $GIT_DESC ($GIT_COMMIT)"
echo "Output:  $OUT"

echo "== [1/5] Labeled monthly datasets (gzip, this is the slow part) =="
for f in "$SRC"/features/plugins.monthly.labeled*.jsonl "$SRC"/features/plugins.monthly.labeled.csv; do
  base=$(basename "$f")
  if [ -s "$OUT/$base.gz" ]; then echo "  skip $base (already built)"; continue; fi
  echo "  gzip $base"
  gzip -cn9 "$f" > "$OUT/$base.gz"
done
cp -f "$SRC/features/plugins.monthly.labeled.summary.json" "$OUT/"
# Completion markers of the enriched panels (absent marker = truncated build).
for f in "$SRC"/features/plugins.monthly.labeled.enriched*.jsonl.summary.json; do
  [ -f "$f" ] && cp -f "$f" "$OUT/"
done

echo "== [2/5] Plugin snapshot features =="
tar -czf "$OUT/plugins.features.snapshot.tar.gz" -C "$SRC/features" \
  plugins.features.csv plugins.features.jsonl plugins.features.summary.json

echo "== [3/5] Model suite + results + protocol =="
tar -czf "$OUT/models.tar.gz" -C "$SRC" models
tar -czf "$OUT/results.tar.gz" -C "$SRC" \
  --exclude='*_INVALID_*' --exclude='*_PARTIAL_*' --exclude='*.PARTIAL_DISCARD' \
  results
cp -f docs/panel_extension_protocol.md "$OUT/"

echo "== [4/5] DATASET_README.md =="
cat > "$OUT/DATASET_README.md" <<EOF
# CANARY reproducibility snapshot (v$VERSION)

Dataset, saved-model and evaluation artifacts for CANARY, a public-data-first
framework for forecasting security advisories in the Jenkins plugin ecosystem.

- Code (pinned): https://github.com/timmybx/canary at tag v$VERSION
- Git commit at bundle build: $GIT_COMMIT ($GIT_DESC)
- Built: $BUILD_DATE
- License: CC-BY-4.0

## Two evaluation layers

This record carries two layers of results, and the distinction matters:

1. **Historical / diagnostic layer** (the model suite in \`models.tar.gz\`):
   the 64-configuration ablation suite evaluated under the standard
   chronological split, plus its \`_embargo\` twin. These are the numbers a
   label-leakage audit showed to be structurally optimistic for this task
   (entity-level label overlap across the train/test boundary and
   advisory-label maturity): the official configuration falls from AP 0.583
   to 0.019 when training labels are restricted to those knowable at scoring
   time. They are retained in full because measuring that inflation is part
   of the contribution.
2. **Honest layer** (the \`results/rolling_backtest/\` directories in
   \`results.tar.gz\`): embargoed rolling-origin backtests — at every fold the
   training labels are rebuilt from advisories published before the fold's
   scoring date. The development sweep (13 non-overlapping folds, 2023-05 →
   2025-05, 760 advisory-positive plugin-months) selected the champion
   configurations; the \`oot_*\` directories are the pre-registered
   out-of-time evaluation of those frozen configurations on three untouched
   folds (2025-07 → 2025-12, 127 positives), each run once; the \`*_asof\`
   directories are the declared sensitivity analysis for one corrected
   feature encoding. \`panel_extension_protocol.md\` (included) is the
   pre-registration: what was frozen, when, and every deviation, with dates.

## Files

- \`plugins.monthly.labeled.jsonl.gz\` - master labeled plugin-month dataset
  (features to date t; binary label = advisory published in (t, t+180]).
- \`plugins.monthly.labeled.<family>.jsonl.gz\` - per-feature-family labeled
  variants used by the ablation experiments (advisory_only, advisory_swh,
  advisory_gharchive, gharchive_only, gharchive_swh, swh_only, full_no_time).
- \`plugins.monthly.labeled.enriched.jsonl.gz\` - the master dataset with the
  enrichment families attached (advhist_, ghclock_, ghtext_, contagion_,
  ghdyn_, swhdelta_, installs_; all as-of the observation month with
  cap-plus-flag encoding of "never"). This is the panel every honest-layer
  run reads, extended to 2026-06 for the out-of-time evaluation.
  \`enriched2\` is the earlier development-era file with installs_ added;
  \`enriched_asof\` recomputes ghdyn_ with the corrected as-of
  \`ghdyn_has_actors\` encoding (sensitivity analysis only).
  Each \`.summary.json\` is the build's completion marker.
- \`plugins.monthly.labeled.csv.gz\`, \`plugins.monthly.labeled.summary.json\` -
  CSV export and summary of the master dataset.
- \`plugins.features.snapshot.tar.gz\` - point-in-time (non-monthly) plugin
  feature snapshot.
- \`models.tar.gz\` - the full saved model suite (data/processed/models/):
  per-configuration model.joblib, metrics.json, precision_at_k.json,
  pr_curve.json, feature_columns.json, test_predictions.csv, and top-k
  feature-selection subdirectories, for both the historical and the
  \`_embargo\` suites.
- \`results.tar.gz\` - analysis outputs (data/processed/results/): H1 odds
  ratios, stratified analysis, heuristic baseline, Brier scores, SHAP
  source-of-record JSONs, retrain deltas, the embargo-suite comparison, and
  every rolling-backtest run directory (per fold: model.joblib, metrics.json,
  test_predictions.csv, precision_at_k.json, pr_curve.json; per run:
  rolling_backtest.json with per-fold, across-fold and pooled metrics).
- \`panel_extension_protocol.md\` - the pre-registered out-of-time protocol
  and its dated changelog.
- \`MANIFEST.sha256\` - checksums of every file above.

## Reproducing reported results

1. Clone the repository and check out tag v$VERSION.
2. Extract this bundle into the repo: gunzip the feature files into
   \`data/processed/features/\`, and extract \`models.tar.gz\` /
   \`results.tar.gz\` into \`data/processed/\`.
3. Build the pinned container (\`make build\`) and run the version-drift
   self-check, which re-scores a saved model and compares against its saved
   \`test_predictions.csv\`:
   \`docker compose run --rm canary python tools/shap_single_model.py\`
   Expected: max |diff| = 0.00e+00.
4. Honest layer: \`tools/rolling_backtest.py\` reproduces any run directory
   from the enriched panel (the exact command lines are in
   \`panel_extension_protocol.md\` and \`tools/README.md\`); the web console's
   "Honest evaluation" tab renders the run directories as they are.
5. Analysis tools in \`tools/\` regenerate the reported tables and figures
   from these artifacts; see \`tools/README.md\`.

## Notes

- All data derives from public sources: the Jenkins plugin registry and
  security advisories, GitHub Archive, Software Heritage, stats.jenkins.io
  install statistics, and the Jenkins plugin health score dataset.
- Labels come only from advisories published in the forward window; feature
  values use only information available at the observation date, and the
  honest layer additionally restricts training labels to those knowable at
  each fold's scoring date. Advisory history features (counts/severity to
  date t) are strictly backward-looking.
- GH Archive per-repository capture decays from mid-2025 (roughly 43-61% of
  GitHub's own PR-created counts in the out-of-time months, near zero by
  mid-2026); observation months from 2026 onward are present in the enriched
  panel but are not evaluable and are excluded from all reported results.
EOF

echo "== [5/5] Manifest + verification =="
(
  cd "$OUT"
  rm -f MANIFEST.sha256
  sha256sum -- *.gz *.tar.gz *.json DATASET_README.md panel_extension_protocol.md > MANIFEST.sha256
  sha256sum -c MANIFEST.sha256
)

echo
echo "Bundle complete: $OUT"
du -sh --apparent-size "$OUT" 2>/dev/null || true
echo "Upload the contents of this directory to the Zenodo record."
