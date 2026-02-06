[![CI](https://github.com/timmybx/canary/actions/workflows/ci.yml/badge.svg)](https://github.com/timmybx/canary/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Ruff](https://img.shields.io/badge/lint-ruff-2ea44f?logo=ruff)
![Dependabot](https://img.shields.io/badge/dependabot-enabled-2ea44f?logo=dependabot)
![Python](https://img.shields.io/badge/python-3.11-blue?logo=python)

# 🐤 CANARY — Component Anomaly & Near-term Advisory Risk Yardstick

CANARY is a starter scaffold for a research prototype that collects software ecosystem signals (starting with Jenkins advisories) and produces a transparent, explainable “risk” score for components/plugins.

This repo is intentionally lightweight right now: a working CLI, a sample collector, a baseline scorer, and unit tests.

---

## 🔥 What This Does (Right Now)

- ✅ **Collect Jenkins advisories (sample stub)** into newline-delimited JSON (`.jsonl`)
- ✅ **Score a Jenkins plugin name** using a transparent baseline heuristic
- ✅ **Run tests + lint/format** in a consistent Docker environment

---

## 📦 Project Structure


```
├── canary/                    # Python package (CLI, collectors, scoring)
│   ├── __init__.py
│   ├── cli.py                 # CLI entrypoint (`canary ...`)
│   ├── collectors/
│   │   └── jenkins_advisories.py
│   └── scoring/
│       └── baseline.py
├── tests/                     # Unit tests
│   ├── test_collectors.py
│   ├── test_scoring.py
│   └── test_smoke.py
├── data/
│   ├── raw/                   # Placeholder for raw inputs
│   │   └── .gitkeep
│   └── processed/             # Processed outputs (generated)
│       ├── .gitkeep
│       └── jenkins_advisories.sample.jsonl
├── .github/
│   ├── workflows/
│   │   ├── ci.yml             # CI (lint/security/tests + coverage)
│   │   └── pre-commit-autoupdate.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── SECURITY.md            # Vulnerability reporting policy 
│   └── dependabot.yml
├── .pre-commit-config.yaml    # pre-commit hooks (ruff, etc.)
├── .bandit                    # Bandit config
├── .dockerignore
├── .gitignore
├── CHANGELOG.md               # Human-friendly release notes
├── CITATION.cff               # Citation metadata (GitHub “Cite this repository”)
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── Dockerfile                 # Container image for consistent runs
├── compose.yaml               # Docker Compose dev loop
├── docker-entrypoint.sh       # Container entrypoint
├── Makefile                   # Handy shortcuts (test/lint/format/audit)
├── pyproject.toml             # Project + tool config (pytest, coverage, ruff, etc.)
├── requirements.txt           # Pinned runtime deps (generated via pip-tools)
├── requirements-dev.txt       # Pinned dev/test/tooling deps (generated via pip-tools)
├── LICENSE                    # Apache-2.0 license
├── NOTICE                     # Apache-2.0 attribution notice
└── README.md                  # You are here 
```

---

## 📁 Repo Tour

### Top-level files
- **README.md** — What CANARY is, how to run it, and how to contribute.
- **CHANGELOG.md** — Release notes (kept human-readable; updated on releases).
- **CITATION.cff** — Citation metadata for GitHub’s “Cite this repository”.
- **LICENSE / NOTICE** — Apache-2.0 licensing + attribution notice.
- **SECURITY.md** — Responsible vulnerability reporting instructions (also mirrored under `.github/`).
- **CODE_OF_CONDUCT.md** — Community expectations for participation.
- **CONTRIBUTING.md** — How to propose changes, run checks, and open PRs.
- **pyproject.toml** — Project metadata + dependencies + tool configuration (pytest, coverage, ruff, etc.).
- **requirements.txt / requirements-dev.txt** — Pinned dependencies (generated from `pyproject.toml` via pip-tools).
- **compose.yaml / Dockerfile / docker-entrypoint.sh** — Reproducible Docker environment for running the CLI and tooling.
- **Makefile** — Handy shortcuts (lint/test/audit commands).
- **.pre-commit-config.yaml** — Local + CI hook runner (keeps style/security checks consistent).
- **.bandit** — Bandit configuration.
- **.github/** — GitHub “plumbing” (CI, templates, Dependabot):
  - **workflows/ci.yml** — Lint/security/test pipeline (includes coverage reporting).
  - **workflows/pre-commit-autoupdate.yml** — Keeps pre-commit hook versions fresh.
  - **dependabot.yml** — Dependency update automation.
  - **ISSUE_TEMPLATE/** + **PULL_REQUEST_TEMPLATE.md** — Contribution templates.

### Source code
- **canary/** — Main Python package.
  - **__init__.py** — Marks this directory as a package (optionally exports package API).
  - **cli.py** — Command-line interface entrypoint (`canary ...`).
  - **collectors/** — Data collection modules (currently Jenkins advisories).
  - **scoring/** — Scoring/risk model logic (baseline heuristic now; ML later).

### Tests
- **tests/** — Unit + smoke tests (`test_smoke.py`) to confirm the CLI and key paths run end-to-end.

### Data
- **data/raw/** — Placeholder for raw inputs (kept out of git except `.gitkeep`).
- **data/processed/** — Generated outputs (example: `jenkins_advisories.sample.jsonl`).

### Build artifacts (generated)
- **canary.egg-info/** — Packaging metadata created by editable installs (`pip install -e ...`).
  - Not hand-edited; safe to delete and regenerate.

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

### 3) Collect advisories (sample)
Writes `data/processed/jenkins_advisories.sample.jsonl` (or similar).
```bash
docker compose run --rm canary canary collect advisories
```

### 4) Score a plugin
Human-readable output:
```bash
docker compose run --rm canary canary score workflow-cps
```

JSON output:
```bash
docker compose run --rm canary canary score workflow-cps --json
```

> Note: The scorer is currently a transparent baseline heuristic. It will evolve as real signals/data sources are added.

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

## 🧠 How Scoring Works (Baseline)

The current baseline is intentionally simple and explainable:

- If the plugin name suggests auth/security-critical keywords → **+20**
- If the plugin name suggests SCM/integration surface area → **+10**
- Otherwise → **+5**
- Score is clamped to **0–100**
- Output includes **reasons** for transparency

This is a placeholder “yardstick” until CANARY integrates real signals.

---

## 🗺️ Roadmap (Next Steps)

Planned additions (in roughly this order):

- [ ] Real Jenkins advisory collection (live fetch + parsing)
- [ ] Normalized record schema & validation
- [ ] Add more ecosystem signals (e.g., release cadence, maintainer count, dependency centrality)
- [ ] Training dataset construction (time-aware)
- [ ] Research-grade evaluation + reporting

---

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
