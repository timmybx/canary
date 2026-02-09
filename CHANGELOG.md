# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight adaptation of “Keep a Changelog”.
(Research prototype: entries focus on features, data pipeline changes, and scoring behavior.)

## [Unreleased]
- Live Jenkins advisory collector (planned)
- Normalized advisory schema + validation (planned)

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

