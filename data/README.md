# CANARY Data Layout

This folder contains **all datasets produced by CANARY**. The project follows a simple rule:

- `data/raw/` = **as fetched** (original API responses / pages / JSON payloads)
- `data/processed/` = **normalized or derived** (cleaned tables, feature JSON, aggregates)
- `data/cache/` = **speed-ups** (HTTP/GitHub/BigQuery query caches, rate-limit helpers)

Most files under `data/` are **generated** and should not be committed to Git
(see repo `.gitignore`). We do commit `.gitkeep` files to preserve the folder
structure.

---

## The “registry spine”

CANARY treats the Jenkins plugin universe as a **registry/manifest**. Everything
else hangs off this.

### `data/raw/registry/plugins.jsonl`
Produced by: `canary collect registry --real`

- One JSON object per plugin (`JSONL` format).
- Each record is keyed by a canonical identifier:

**Canonical key:** `plugin_id` (the Jenkins plugin short name)

Minimal expected fields (may grow over time):

- `plugin_id`
- `plugin_site_url` (human page)
- `plugin_api_url` (plugins.jenkins.io API endpoint)
- `collected_at` (timestamp)

Optional/enriched fields when available:

- `title`, `labels`, `excerpt`
- `repo_url` / `repo_full_name` (if discoverable downstream)
- advisory pointers (if discoverable downstream)

This file is the input to per-plugin collectors (snapshot, advisories, GitHub, historical).

---

## Raw datasets (as-fetched)

### `data/raw/plugins/{plugin_id}.snapshot.json`
Produced by: `canary collect plugin --real --id <plugin_id>`

- The full plugin snapshot from `plugins.jenkins.io/api/plugin/<plugin_id>`
- This is the primary source for Jenkins plugin metadata, including any
  references to SCM/repo URLs and security warnings.

### `data/raw/advisories/{plugin_id}.advisories.jsonl`
Produced by: `canary collect advisories --real --plugin <plugin_id>`

- Security advisories related to the plugin.
- Stored as JSONL because one plugin can have multiple advisories and each
  advisory may yield multiple extracted records.

### `data/raw/github/*`
Produced by: `canary collect github --real ...` (planned / may be split out)

- Raw GitHub API responses derived from the plugin’s repository mapping.
- Example files (shape may evolve):
  - `{plugin_id}.repo.json`
  - `{plugin_id}.releases.json`
  - `{plugin_id}.contributors.json`
  - `{plugin_id}.activity.json`

### `data/raw/bigquery/*` or `data/raw/gharchive/*`
Produced by: `canary collect gharchive --start ... --end ...`

- Raw or lightly-structured outputs from historical queries (e.g., GH Archive
  public BigQuery dataset).
- Used to derive time-windowed activity features.

---

## Processed datasets (normalized / derived)

Processed outputs should be **easy to join by `plugin_id`** and stable enough to
support scoring.

### `data/processed/gharchive/`
- Aggregates and time-window outputs from GH Archive/BigQuery jobs.
- Example:
  - `gharchive_YYYYMMDD_YYYYMMDD_sample.csv`

### `data/processed/features/{plugin_id}.features.json` (recommended target)
A single “feature bundle” per plugin, created by a future `canary build features`
step. Intended to combine:

- snapshot-derived fields (update frequency, version info, labels)
- advisory-derived fields (counts, severity signals when available)
- GitHub-derived fields (stars, forks, recency, release cadence)
- historical-derived fields (events/commits/PR activity in time windows)

This becomes the primary input to scoring and reporting.

---

## Naming conventions

- **Plugin identity:** always use `plugin_id` as the primary key and file stem.
- **Raw files:** prefer `{plugin_id}.<source>.json` or `{plugin_id}.<source>.jsonl`
- **Processed files:** prefer `{plugin_id}.features.json` (per plugin) or a clearly
  named aggregate in a subfolder.

---

## Git policy

- The directory structure is committed via `.gitkeep`.
- Generated data outputs are ignored by default.
- If you want examples for documentation/tests, add small *sample* files like:
  - `data/raw/registry/plugins.sample.jsonl`

---

## Typical workflow

1. Build the plugin universe registry:
   - `canary collect registry --real`
2. Enrich plugins (per-plugin fan-out):
   - `canary collect plugin --real --id <plugin_id>` (or batch runner)
   - `canary collect advisories --real --plugin <plugin_id>`
   - `canary collect github --real --plugin <plugin_id>` (planned split)
3. Pull historical signals:
   - `canary collect gharchive --start YYYYMMDD --end YYYYMMDD`
4. Build processed features:
   - (planned) `canary build features`

---

## Notes

- Treat `data/raw/` as append-only whenever possible; it makes debugging and
  reproducibility much easier.
- Prefer adding new fields over changing/removing old ones. When changes are
  necessary, version the processed outputs or note schema changes in release notes.
