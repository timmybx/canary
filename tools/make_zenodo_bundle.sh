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
#     can fetch only the variant they need)
#   - the plugin snapshot feature files (small tarball)
#   - the full saved model suite (metrics, predictions, feature lists, models)
#   - the analysis results JSONs (source-of-record SHAP, H1 odds, Brier, etc.)
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

echo "== [2/5] Plugin snapshot features =="
tar -czf "$OUT/plugins.features.snapshot.tar.gz" -C "$SRC/features" \
  plugins.features.csv plugins.features.jsonl plugins.features.summary.json

echo "== [3/5] Model suite + results =="
tar -czf "$OUT/models.tar.gz" -C "$SRC" models
tar -czf "$OUT/results.tar.gz" -C "$SRC" results

echo "== [4/5] DATASET_README.md =="
cat > "$OUT/DATASET_README.md" <<EOF
# CANARY reproducibility snapshot (v$VERSION)

Dataset and saved-model artifacts for CANARY, a public-data-first framework
for forecasting security advisories in the Jenkins plugin ecosystem.

- Code (pinned): https://github.com/timmybx/canary at tag v$VERSION
- Git commit at bundle build: $GIT_COMMIT ($GIT_DESC)
- Built: $BUILD_DATE
- License: CC-BY-4.0

## Files

- \`plugins.monthly.labeled.jsonl.gz\` - master labeled plugin-month dataset
  (features to date t; binary label = advisory published in (t, t+180]).
- \`plugins.monthly.labeled.<family>.jsonl.gz\` - per-feature-family labeled
  variants used by the ablation experiments (advisory_only, advisory_swh,
  advisory_gharchive, gharchive_only, gharchive_swh, swh_only, full_no_time).
- \`plugins.monthly.labeled.csv.gz\`, \`plugins.monthly.labeled.summary.json\` -
  CSV export and summary of the master dataset.
- \`plugins.features.snapshot.tar.gz\` - point-in-time (non-monthly) plugin
  feature snapshot.
- \`models.tar.gz\` - the full saved model suite (data/processed/models/):
  per-configuration model.joblib, metrics.json, precision_at_k.json,
  pr_curve.json, feature_columns.json, test_predictions.csv, and top-k
  feature-selection subdirectories.
- \`results.tar.gz\` - analysis outputs (data/processed/results/): H1 odds
  ratios, stratified analysis, heuristic baseline, Brier scores, SHAP
  source-of-record JSONs, retrain deltas.
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
4. Analysis tools in \`tools/\` regenerate the reported tables and figures
   from these artifacts; see \`tools/README.md\`.

## Notes

- All data derives from public sources: the Jenkins plugin registry and
  security advisories, GitHub Archive, Software Heritage, and the Jenkins
  plugin health score dataset.
- Labels come only from advisories published in the forward window; feature
  values use only information available at the observation date. Advisory
  history features (counts/severity to date t) are strictly backward-looking.
EOF

echo "== [5/5] Manifest + verification =="
(
  cd "$OUT"
  rm -f MANIFEST.sha256
  sha256sum -- *.gz *.tar.gz *.json DATASET_README.md > MANIFEST.sha256
  sha256sum -c MANIFEST.sha256
)

echo
echo "Bundle complete: $OUT"
du -sh --apparent-size "$OUT" 2>/dev/null || true
echo "Upload the contents of this directory to the Zenodo record."
