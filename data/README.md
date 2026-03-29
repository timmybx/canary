# CANARY data layout

CANARY separates data into three buckets:

- `data/raw/` — **as-collected** artifacts (API responses/pages/JSON payloads)
- `data/processed/` — **derived** datasets (normalized events, feature bundles, aggregates)
- `data/cache/` — optional speed-ups (HTTP caches, query caches)

Most files under `data/` are generated and should usually be ignored by Git. The
folder structure is preserved with `.gitkeep` where needed.

## Registry spine

Everything starts from the Jenkins plugin registry:

- `data/raw/registry/plugins.jsonl` — one JSON record per plugin, keyed by `plugin_id`

Produced by:

```bash
canary collect registry --real
```

## Raw per-plugin collections

From the registry, CANARY fans out into source-specific collections:

- `data/raw/plugins/<plugin_id>.snapshot.json` — Jenkins plugin snapshot (`collect plugin`)
- `data/raw/advisories/<plugin_id>.advisories.real.jsonl` — plugin advisories (`collect advisories --real`)
- `data/raw/github/<plugin_id>.*.json` — raw GitHub API payloads (`collect github` / `collect enrich --only github`)
- `data/raw/healthscore/plugins/<plugin_id>.healthscore.json` — per-plugin health score records (`collect healthscore` / `collect enrich --only healthscore`)
- `data/raw/gharchive/windows/<start>_<end>.gharchive.jsonl` — historical GH Archive window outputs (`collect gharchive`)
- `data/raw/gharchive/plugins/<plugin_id>.gharchive.jsonl` — per-plugin historical GH Archive timelines (`collect gharchive`)

## Processed datasets

Processed outputs are built from the raw collections and are intended to support
analysis, scoring, and later ML-oriented workflows.

- `data/processed/events/advisories.jsonl` — deduplicated advisory events stream (`build advisories-events`)
- `data/processed/features/plugins.features.jsonl` — unified feature bundle, one row per plugin (`build features`)
- `data/processed/features/plugins.features.csv` — CSV companion for the feature bundle (`build features`)
- `data/processed/features/plugins.features.summary.json` — summary counts for joined sources (`build features`)

## Current integrated workflow

A typical end-to-end flow now looks like this:

```bash
canary collect registry --real
canary collect enrich --real
canary collect gharchive \
  --registry-path data/raw/registry/plugins.jsonl \
  --start 20250101 \
  --end 20251231 \
  --bucket-days 30 \
  --sample-percent 1.0 \
  --max-bytes-billed 600000000000
canary build advisories-events
canary build features \
  --data-raw-dir data/raw \
  --registry data/raw/registry/plugins.jsonl
canary build monthly-features --start 2024-01 --end 2025-12
```

## Notes on GH Archive collection

- `--sample-percent 1.0` means **1% sampling**, not 100%.
- Historical collection is windowed by `--bucket-days` to keep runs predictable.
- Window outputs are written under `data/raw/gharchive/windows/` and then rolled up into per-plugin timelines under `data/raw/gharchive/plugins/`.

## Notes on feature bundles

The unified feature bundle joins plugin-level signals from:

- registry
- plugin snapshots
- advisories
- healthscore
- GitHub enrichment
- GH Archive history

The current feature bundle is a **plugin-level dataset** designed to support
analysis and to serve as the foundation for a later **time-sliced / ML-ready**
dataset builder.

## Obsolete material

Older proof-of-concept big-data paths are no longer the primary workflow. The
integrated `collect gharchive` + `build features` pipeline is now the supported
path for historical collection and dataset building.

## Plugin alias overrides

Use `data/raw/registry/plugin_aliases.json` to map historical plugin IDs to the current canonical ID when a plugin has been renamed.

Example:

```json
{
  "old-plugin-id": "current-plugin-id"
}
```

CANARY will resolve aliases during scoring, feature generation, health score ingestion, and web-console plugin validation so historical data can still roll up under the current plugin ID.
