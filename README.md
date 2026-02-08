[![CI](https://github.com/timmybx/canary/actions/workflows/ci.yml/badge.svg)](https://github.com/timmybx/canary/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/timmybx/canary/badge)](https://scorecard.dev/viewer/?uri=github.com/timmybx/canary)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Ruff](https://img.shields.io/badge/lint-ruff-2ea44f?logo=ruff)
![Dependabot](https://img.shields.io/badge/dependabot-enabled-2ea44f?logo=dependabot)
![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)
[![Checked with pyright](https://microsoft.github.io/pyright/img/pyright_badge.svg)](https://microsoft.github.io/pyright/)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![ClusterFuzzLite PR fuzzing](https://github.com/timmybx/canary/actions/workflows/cflite_pr.yml/badge.svg)](https://github.com/timmybx/canary/actions/workflows/cflite_pr.yml)

# 🐤 CANARY — Component Anomaly & Near-term Advisory Risk Yardstick

CANARY is a starter scaffold for a research prototype that collects software ecosystem signals (starting with Jenkins advisories) and produces a transparent, explainable “risk” score for components/plugins.

This repo is intentionally lightweight right now: a working CLI, a sample collector, a baseline scorer, and unit tests.

> **Dependency source of truth:** `pyproject.toml` is the source of dependency declarations.  
> `requirements*.txt` files are generated lockfiles used for reproducible installs.

---

## 🔐 Security & Supply Chain Notes

CANARY aims to be reproducible and supply-chain aware:

- Dependencies are **hash-locked** (`requirements*.txt`) and installed with `--require-hashes` in containers/CI.
- Vulnerability auditing runs in Docker to avoid OS-specific dependency drift.
- GitHub Actions are pinned to commit SHAs where possible.
- OpenSSF Scorecard is enabled to track supply-chain posture over time.

---

## 🔥 What This Does (Right Now)
- ✅ **Collect a plugin snapshot** (pilot/curated by default, or `--real` from the Jenkins plugins API)
- ✅ **Collect Jenkins advisories** as newline-delimited JSON (`.jsonl`)
  - sample mode (offline / deterministic)
  - real mode (plugin-specific) using the plugin snapshot’s `securityWarnings` → advisory URLs
- ✅ **Score a plugin** using explainable signals (name heuristics + advisory recency/count + snapshot metadata like dependencies, required core, release recency, and security warnings)
- ✅ **Run tests + lint/security checks** in a consistent Docker environment

## 📦 Project Structure
```
├── canary/                    # Python package (CLI, collectors, scoring)
│   ├── __init__.py
│   ├── cli.py                 # CLI entrypoint (`canary ...`)
│   ├── collectors/
│   │   ├── jenkins_advisories.py   # Sample + real advisory collection
│   │   └── plugin_snapshot.py      # Plugin snapshot (curated or plugins API `--real`)
│   └── scoring/
│       └── baseline.py        # Baseline scorer (name + local datasets)
├── tests/                     # Unit tests
│   ├── fixtures/              # Recorded API payloads for deterministic tests
│   │   └── plugins_api_cucumber-reports.json
│   ├── test_collectors.py
│   ├── test_github_repo.py
│   ├── test_jenkins_advisories_real.py
│   ├── test_plugin_snapshot.py
│   ├── test_scoring.py
│   └── test_smoke.py
├── data/
│   ├── raw/
│   │   ├── plugins/           # Plugin snapshots (generated)
│   │   │   └── cucumber-reports.snapshot.json
│   │   └── advisories/        # Advisory JSONL (generated)
│   │       └── cucumber-reports.advisories.{sample|real}.jsonl
│   └── processed/             # Optional derived outputs (future)
├── .github/
│   ├── workflows/
│   │   ├── ci.yml             # CI (lint/security/tests + coverage)
│   │   └── pre-commit-autoupdate.yml
│   └── ISSUE_TEMPLATE/
└── ...
```

## 📁 Repo Tour
### Top-level files
- **README.md** — What CANARY is and how to run it.
- **CHANGELOG.md** — Release notes (updated on releases).
- **CITATION.cff** — Citation metadata for GitHub’s “Cite this repository”.
- **Dockerfile / compose.yaml** — Reproducible dev/test environment.
- **pyproject.toml** — Tooling config (Ruff, pytest, etc.).

### Key source files
- **`canary/cli.py`** — CLI entrypoint (`canary collect …`, `canary score …`).
- **`canary/collectors/plugin_snapshot.py`** — Collects a per-plugin snapshot (curated by default; `--real` pulls the Jenkins plugins API).
- **`canary/collectors/jenkins_advisories.py`** — Collects advisories:
  - sample mode (offline)
  - real mode (plugin-specific) via snapshot → `securityWarnings` → advisory URLs
- **`canary/scoring/baseline.py`** — Baseline scoring using local artifacts (`data/raw/...`) with explainable features.

### Data outputs (generated)
- **`data/raw/plugins/<plugin>.snapshot.json`** — Plugin snapshot (includes plugins API payload when `--real`).
- **`data/raw/advisories/<plugin>.advisories.{sample|real}.jsonl`** — Advisory records (JSONL).

---

## ✅ Prerequisites (Docker)

To run CANARY locally, the recommended approach is Docker Compose.

### Required
- **Docker Desktop** (includes Docker Engine and Docker Compose v2)
- An internet connection (to pull base images and install Python dependencies during image build)

### Verify your install
```bash
docker --version
docker compose version
```

---

## 🚀 Quickstart (Docker Compose)
### 1) Build the image
```bash
docker compose build
```

### 2) Show CLI help
```bash
docker compose run --rm canary canary --help
```

### 3) Collect a plugin snapshot (pilot)
Curated snapshot (no network):
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports
```

Real snapshot from the Jenkins plugins API:
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports --real
```

### 4) Collect advisories
Sample (offline / deterministic):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --out-dir data/raw/advisories
```

Real (plugin-specific; uses the plugin snapshot’s `securityWarnings` to discover advisory URLs):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
```

### 5) Score a plugin
JSON output (recommended for now):
```bash
docker compose run --rm canary canary score cucumber-reports --data-dir data/raw --json
```

> Note: Scoring is intentionally a transparent baseline and will evolve as more signals/data sources are added.

---

## 🧪 Running Tests

```bash
docker compose run --rm canary pytest
```

### Coverage

Coverage is enabled by default (via `pytest-cov`) and prints missing lines in the terminal.

Generate an HTML report:

```bash
docker compose run --rm canary pytest --cov-report=html
```

Then open `htmlcov/index.html`.

Quiet mode:
```bash
docker compose run --rm canary pytest -q
```

Single test file:
```bash
docker compose run --rm canary pytest -q tests/test_scoring.py
```

---

## 🧹 Linting & Formatting (Ruff)

Fix lint issues Ruff knows how to auto-fix:
```bash
docker compose run --rm canary ruff check . --fix
```

Format code:
```bash
docker compose run --rm canary ruff format .
```

Common combo:
```bash
docker compose run --rm canary ruff check . --fix
docker compose run --rm canary ruff format .
```

---

## 🔁 Updating Dependencies (Locked)

This repo uses hash-locked requirements for reproducible installs.

Regenerate lockfiles (Docker):
```bash
docker compose run --rm canary pip-compile --generate-hashes -o requirements.txt pyproject.toml
docker compose run --rm canary pip-compile --extra=dev --generate-hashes -o requirements-dev.txt pyproject.toml
```

Run all checks locally:
```bash
pre-commit run -a
```

> Tip: For CI/workflow hardening, some workflows may install tools from additional hash-locked files
> (e.g., `requirements-ci.txt`). If present, regenerate them the same way using `pip-compile --generate-hashes`.

---

## 🧠 How Scoring Works (Baseline)
CANARY’s current scorer is intentionally simple and explainable. It combines:

- **Name heuristics** (e.g., keywords that suggest auth/security or SCM surface area)
- **Advisory features** (from local JSONL):
  - advisory count
  - most recent advisory date
  - *recency-weighted* advisory risk
- **Plugin snapshot features** (from `data/raw/plugins/<plugin>.snapshot.json` when available):
  - required Jenkins core
  - dependency count (surface area proxy)
  - security warnings (active warnings are a strong risk signal)
  - release recency (used as a light “maintenance” signal)

Outputs include the final score, a human-readable list of reasons, and the raw feature values (JSON mode).

## 🗺️ Roadmap (Next Steps)
- [x] CLI scaffold (`collect`, `score`) with Docker Compose workflow
- [x] Plugin snapshot collection (curated + `--real` via Jenkins plugins API)
- [x] Advisory collection:
  - [x] sample (offline) mode
  - [x] real (plugin-specific) mode via snapshot → `securityWarnings` → advisory URLs
  - [ ] real (global) mode via advisories RSS/index for all advisories
- [x] Baseline scoring with explainable features (name + advisories + snapshot metadata)
- [ ] Add GitHub signals (stars, recent activity, issues/PRs) for the plugin repo
- [ ] Expand datasets and scoring model for research evaluation

## 🧯 Troubleshooting

### Rebuild if Docker cached something weird
```bash
docker compose build --no-cache canary
```

---

## 📄 License

License: Apache-2.0

---

## ⚠️ Disclaimer

This is a research/prototype scaffold. Scores are **not** security guarantees and should not be used as the sole basis for operational risk decisions.

---

## 👤 Author

**Timothy Brennan**
