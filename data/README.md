# CANARY data layout

CANARY separates data into three buckets:

- `data/raw/` — **as-collected** artifacts (API responses/pages/JSON payloads)
- `data/processed/` — **derived** datasets (normalized events, feature bundles, aggregates)
- `data/cache/` — optional speed-ups (HTTP caches, query caches)

Most files under `data/` are generated and should be ignored by Git. We keep the
folder structure using `.gitkeep`.

## Registry spine

Everything starts from the Jenkins plugin universe registry:

- `data/raw/registry/plugins.jsonl` — one JSON record per plugin, keyed by `plugin_id`

Produced by:

```bash
canary collect registry --real
```

## Raw per-plugin collections

From the registry you can fan out to per-plugin collectors:

- `data/raw/plugins/<plugin_id>.snapshot.json` — Jenkins plugin snapshot (`collect plugin`)
- `data/raw/advisories/<plugin_id>.advisories.real.jsonl` — plugin advisories (`collect advisories --real`)
- `data/raw/github/<plugin_id>.*.json` — raw GitHub API payloads (`collect github`)

## Processed datasets

- `data/processed/events/advisories.jsonl` — deduped advisory “events stream” (`build advisories-events`)
- `data/processed/features/<plugin_id>.features.json` — planned feature bundles for scoring/ML

## Typical workflow

```bash
canary collect registry --real
canary collect enrich --real --max-plugins 50
canary build advisories-events
```

This gets you a consistent raw/processed dataset set that can later be converted
into ML training tables using time-sliced feature building.
