# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight adaptation of “Keep a Changelog”.
(Research prototype: entries focus on features, data pipeline changes, and scoring behavior.)

## [0.1.6] - 2026-04-13
### Added
- Model registry support for model-agnostic training, including CLI selection for logistic, random forest, XGBoost, and LightGBM workflows.
- Additional Athena visit-record merging helpers and tests for Software Heritage collection behavior.
- Expanded regression coverage across Jenkins advisory helpers, monthly labels, plugin aliases, scoring helpers, Software Heritage backends, training registry behavior, and webapp paths.

### Changed
- Upgraded the project baseline from Python 3.11 to Python 3.12 across package metadata, Docker image, CI, documentation, and regenerated requirement lockfiles.
- Updated Software Heritage Athena tooling for the 2025-10-08 export, refreshed Jenkins extraction/schema scripts, and clarified extraction/repartitioning documentation.
- Recomputed Software Heritage last-commit day calculations and extended the monthly feature window used by downstream training data.
- Moved development dependencies out of `pyproject.toml` extras and into `requirements-dev.in`, with CI and Makefile generation paths updated accordingly.
- Refreshed project naming/citation language around the "Component Analytics" CANARY tagline.

### Fixed
- Athena Software Heritage collection can now revisit existing indices instead of assuming a one-pass collection state.
- Dependabot requirement compilation now uses `requirements.txt` as a constraints file to avoid pip-compile conflicts.
- Container and pre-commit workflows were adjusted by removing unnecessary pre-commit rebuilds and adding `libgomp1` for native ML dependencies.
- Test modules were tidied for formatting, imports, and UTC-aware datetime usage.

### Security
- Bumped `cryptography` to `46.0.7`.
- Updated CodeQL/Scorecard GitHub Action pins and refreshed pre-commit hooks.
- Updated lint/test tooling pins, including Ruff `0.15.9` and pytest-cov `7.1.0`.

## [0.1.5] - 2026-04-02
### Added
- Software Heritage Athena backend support for collection and enrich flows, including Athena-specific raw data layout and collector wiring through the CLI/backend layer.
- Expanded Software Heritage feature extraction for both feature bundles and monthly features, including additional repository-structure flags, revision-level activity signals, and the late-night commit fraction metric.
- Additional GH Archive-derived behavioral features covering bot activity, keyword/security signals, and timing-oriented event summaries.
- Data documentation for `data/raw/gharchive` and `data/raw/software_heritage_athena` to clarify the new raw artifact layouts.

### Changed
- Feature bundle assembly now prefers the configured Software Heritage backend and normalizes Athena visit inputs into the same modeling-friendly shape used by downstream build steps.
- Software Heritage Athena collection was refined around Jenkins Athena tables, cached clients, batched directory inspection, timestamp normalization, and improved visit/snapshot feature derivation.
- Local tooling and container workflows were updated for more reliable security and typing checks, including the pip-audit wrapper flow, explicit compose DNS settings, `/tmp` cache handling, and requirement regeneration aligned to `pip>=26,<27`.
- Repository documentation was refreshed across README/CITATION-style materials to reflect the expanded data sources, metrics, and research references.

### Fixed
- Pyright/test breakages caused by newly added Software Heritage fields and backend refactors.
- Dependabot/pip audit workflow issues, including cache permission problems and the vulnerable pre-26 pip pin in requirements regeneration.
- Follow-up correctness issues in Software Heritage visit normalization, empty/default revision metrics, and bundled feature propagation for newly added SWH signals.

## [0.1.4] - 2026-03-20
### Added
- GH Archive and BigQuery-backed collection workflow for plugin event history, including CLI support and data directory scaffolding for raw and normalized monthly event outputs.
- Feature engineering pipeline for plugin risk modeling, including feature bundle generation, monthly feature bundle generation, and monthly label generation commands.
- Baseline training workflow with a dedicated CLI entry point and logistic baseline training support.
- Rolling GH Archive feature calculations with include-prefix support for building time-windowed training data.
- Model output directory tracking via `data/processed/models/.gitkeep`.

### Changed
- GH Archive ingestion moved from earlier proof-of-concept code to normalized monthly event builders with improved timestamp handling and sampling-aware raw event queries.
- Feature bundle assembly was refined to incorporate normalized GH Archive history and corrected healthscore integration behavior.
- Local development and cloud execution setup were updated for Google Cloud / BigQuery usage, including compose cleanup and ignoring local override configuration.
- Tooling and maintenance updates landed across pre-commit hooks, the Zizmor GitHub Action, and build requirements with a `setuptools` bump to `82.0.1`.
- README and data documentation were refreshed to reflect the new data pipeline and training workflow.

### Fixed
- Timestamp normalization and event-row generation issues in GH Archive history processing, with regression tests covering the monthly history pipeline.
- Healthscore feature assembly issues in the bundled feature output.

## [0.1.3] - 2026-03-08
### Added
- Web UI with `canary-web` entry point, static assets, and autocomplete-backed search flow.
- NGINX deployment configuration for serving the web frontend.
- New data collection and build capabilities for GitHub plugin metadata, plugin registry snapshots, healthscore data, and advisory event assembly.
- CVSS score collection and severity-category support for Jenkins advisories.
- Expanded Makefile targets and data directory scaffolding (`raw`, `processed`, `cache`) for repeatable pipeline runs.

### Changed
- Baseline scoring logic iterated across dependency scoring, real-data scoring pathways, and broader scoring refinements.
- CLI orchestration expanded to cover new collection and enrichment workflows.
- CI and security automation updated across CodeQL, Scorecard, ClusterFuzzLite, Dependabot, pre-commit autoupdate, and new Zizmor workflow checks.
- Docker and compose configuration updated for frontend serving and additional hardening tied to CodeQL findings.
- Repository governance and docs updates including CODEOWNERS, README flow updates, and citation metadata refresh.

### Fixed
- Plugin registry ingestion and GitHub link handling fixes to reduce collector edge-case failures.
- Collection/scoring integration fixes and follow-up stability fixes in baseline processing and webapp paths.
- Security audit and static-analysis warning remediation across application and container config.

## [0.1.2] - 2026-02-08
### Added
- CodeQL workflow for `main` push/PR and weekly scheduled analysis across `python` and `actions`.
- GH Archive dataset feature builder script at `canary/datasets/gharchive.py` (BigQuery -> parquet).

### Changed
- Refreshed pinned GitHub Action SHAs across CI, Scorecard, and pre-commit automation workflows.
- Tightened `pre-commit-autoupdate` token handling: kept `GITHUB_TOKEN` read-only and switched PR creation to `PR_BOT_TOKEN`.
- Refined CodeQL permissions to least privilege by keeping workflow-level read-only and elevating `security-events: write` only at the analyze job.
- Iterated ClusterFuzzLite PR workflow Docker-in-Docker configuration; current update adds checkout and removes TLS/cert env overrides while preserving `DOCKER_HOST` targeting the DinD service.
- Bumped `setuptools` from `72.2.0` to `82.0.0` in build requirements input.
- Bumped `pre-commit` from `4.3.0` to `4.5.1` in CI requirements input and lockfile.

### Fixed
- Addressed ClusterFuzzLite Docker client initialization failures caused by TLS cert path lookups (`/tmp/docker-config/ca.pem`) in PR fuzzing.

### Planned
- Live Jenkins advisory collector.
- Normalized advisory schema + validation.

## [0.1.1] - 2026-02-08
### Added
- ClusterFuzzLite PR fuzzing workflow (build + run fuzzers on pull requests using AddressSanitizer).
- Python fuzzing build pipeline that packages `*_fuzzer.py` targets into standalone executables (PyInstaller) and emits runnable wrappers into the expected output directory.
- Deterministic fuzzer dependency installation using hash-locked requirements (`pip --require-hashes`).
- OpenSSF scoring
- Added additional tests

### Changed
- Fuzzer discovery updated to search from the repo working directory to avoid `$SRC` path ambiguity.
- Improved build-time diagnostics (print `$SRC/$OUT`, list directories, and enumerate discovered fuzz targets) to speed up CI troubleshooting.
- Wrapper script updated to include the standard detection marker required for fuzz target discovery.

### Fixed
- Hardened Jenkins URL canonicalization to avoid crashes on malformed inputs discovered via fuzzing (invalid bracketed IPv6 forms); added regression coverage for the crash case.

## [0.1.0] - 2026-02-05
### Added
- Initial CANARY project scaffold (Python package + CLI)
- Sample Jenkins advisory collection output (JSONL)
- Baseline scoring with explainable reasons
- Unit tests for collectors and scoring
- Docker Compose dev workflow + Dockerfile
- Repo hygiene tooling: Ruff (lint/format), Bandit, pip-audit
- GitHub Actions CI (push/PR + scheduled), Dependabot updates
- Documentation: README, SECURITY.md, CITATION.cff
- Licensing: Apache-2.0 (LICENSE + NOTICE)
