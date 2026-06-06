# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight adaptation of “Keep a Changelog”.
(Research prototype: entries focus on features, data pipeline changes, and scoring behavior.)

## [0.1.10] - 2026-06-06
### Added
- Focused regression coverage for high-change surfaces, including `features_bundle.py` branch paths, `jenkins_advisories` edge/error flows, and webapp case-study/explain GET flows and route assumptions.

### Changed
- Refreshed runtime/developer dependency pins and lockfiles across merged dependency PRs, including `numpy`, `ruff`, `pyinstaller`, and `boto3` updates.
- Updated CI/tooling automation via multiple pre-commit autoupdates and GitHub Action bumps (CodeQL, Codecov, and Zizmor).
- Aligned ClusterFuzzLite build/runtime setup for Python 3.12-era ML dependencies, including follow-up `pip` pinning in fuzzing/container flows.

### Fixed
- Corrected the web console Machine Learning tab model-configuration count display (29 -> 64).

## [0.1.9] - 2026-05-26
### Added
- SHAP-based feature-selection study support, including a new CLI workflow, experiment helpers, web-console experiment sections, and more robust feature-selection artifact loading.
- In-page AI explanation support for scoring results, including rate limiting, clearer Anthropic error handling, formatted output, model context preservation, and a dedicated explanation card.
- Additional web-console analysis surfaces, including an About tab, case-study/advisory validation tab, operational precision@k metrics, grouped model dropdowns, and a live GitHub commit signal for plugins.
- Deployment documentation for the Render-based CANARY service, persistent data disk, SSH access, and data synchronization workflow.
- Extra regression coverage for webapp scoring/explanation behavior, CodeQL exception-sanitization handling, pip-audit wrapper behavior, and plugin alias helpers.

### Changed
- The local web console now focuses on scoring and read-only ML/model inspection: data-collection controls and the `/run` path were removed from the UI surface.
- Scoring flows now use GET-friendly URLs with a `/score` redirect, improved CANARY score presentation, refined ML result copy, and cleaner feature-driver formatting that filters imputed drivers.
- Feature-selection and training helpers now guard average-precision calculations, cap expensive random-forest work, skip unnecessary full retrains, add `train_start_month` reporting, and improve output-error handling.
- Container and deployment behavior now starts the web app by default, honors Render's `PORT` environment variable, gives the app user a shell for SSH, adds `rsync`, and removes the unused default Nginx config.
- README guidance was refreshed for ML labels/training, Software Heritage output paths, and current web-console scoring behavior.

### Fixed
- Prevented information exposure through raw exception strings in webapp scoring/explanation errors, with regression coverage for the CodeQL finding.
- Improved plugin alias matching resilience and added a network guard around pip-audit wrapper flows used by local hooks.
- Fixed the docker pytest pre-commit hook so coverage output is written to a writable `/tmp` path.
- Tightened score-form layout, feature-list styling, model-directory preservation, and several web-console edge cases.

### Security
- Upgraded `urllib3` to address `CVE-2026-44431` and `CVE-2026-44432`.
- Upgraded `idna` to address `CVE-2026-45409`.
- Removed the stale `PYSEC-2024-277` pip-audit ignore after confirming CANARY is pinned to `joblib` 1.5.3.
- Refreshed CodeQL, Scorecard, Zizmor, pre-commit, and Dependabot automation, and updated dependency pins including `pip`, `ruff`, `boto3`/`botocore`, `requests`, `pandas`, and `numpy`.

## [0.1.8] - 2026-05-10
### Added
- ML-backed scoring support for the CLI and local web console, including model-directory selection and SHAP-style driver extraction for trained baseline models.
- A componentized scoring model layer that separates baseline score components from aggregation logic while preserving explainable score output.
- Additional UI affordances for the web console, including score form refinements, tooltips, badges, clearer empty-feature messaging, and model-name display in ML scoring results.
- Expanded regression coverage for CLI helpers, ML scoring, feature-bundle path handling, train registry behavior, collector path utilities, and webapp scoring flows, raising coverage to roughly 81%.
- A `pytest-docker` pre-commit hook and expanded monthly ablation experiment helper script support.

### Changed
- ML scoring now reports model names, excludes time-window feature leakage from driver output, accepts broader mapping-like feature vectors, and uses the newer `shap.maskers.Independent` LinearExplainer API.
- Baseline scoring internals were refactored into smaller components, with follow-up fixes for the affected unit-test expectations.
- Software Heritage Athena loading is now lazy, reducing import-time coupling for flows that do not use the Athena backend.
- Refreshed pre-commit hooks and dependency pins, including updates for the pip tooling group, `boto3`/`botocore`, `cryptography`, and `s3transfer`.

### Fixed
- Prevented plugin ID path traversal in collectors and feature-bundle handling by centralizing strict path validation and adding regression tests for CodeQL CWE-022 findings.
- Fixed ML driver extraction and scoring UI edge cases, including alignment between `_extract_drivers(...)`, score form behavior, and test expectations.
- Resolved scoring baseline regressions that caused six unit tests to fail after the componentized scoring refactor.
- Updated webapp empty-feature assertions and previously skipped ML/train-registry test coverage.

## [0.1.7] - 2026-04-29
### Added
- Flexible train/test split controls for `canary train baseline`, including `time`, `group`, and `group_time` strategies with configurable grouping, holdout fraction, and seed behavior.
- Large helper-focused regression suites for CLI parsing, feature-bundle helpers, GH Archive helpers, GitHub repository helpers, and webapp helpers, raising overall coverage from 71% to 77%.
- Repository guidance for AI coding agents via `AGENTS.md` plus a unit-test agent spec under `.github/agents/`.

### Changed
- Refreshed runtime dependency floors and regenerated lockfiles for runtime, build, CI, and developer environments, including newer `boto3`, `google-cloud-bigquery`, `requests`, `numpy`, `pandas`, `ruff`, `pre-commit`, `pip`, `packaging`, and `wheel` versions.
- Updated Dependabot configuration to group pip ecosystem updates and refreshed pinned GitHub Action revisions across CodeQL, Scorecard, Zizmor, and pull-request automation workflows.
- Refreshed the Docker base image digest and supporting lockfiles so requirement regeneration and container-based workflows stay aligned with current packaging tooling.

### Fixed
- Restored compatibility between the train-baseline CLI and the backwards-compatible `train_baseline(...)` wrapper by accepting and forwarding the newer split-related keyword arguments.
- Resolved `make reqs` / lockfile regeneration failures caused by outdated packaging inputs and stale dependency constraints.

### Security
- Removed the blanket Bandit `B101` skip so assertion usage is checked again during security scans.
- Bumped `pip` to `26.1` to address `CVE-2026-3219`.

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
