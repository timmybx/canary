# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight adaptation of “Keep a Changelog”.
(Research prototype: entries focus on features, data pipeline changes, and scoring behavior.)

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
