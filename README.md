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

CANARY is a starter scaffold for a research prototype that collects software ecosystem signals (starting with Jenkins plugins + advisories) and produces a transparent, explainable “risk” score for components/plugins.

This repo is intentionally lightweight right now: a working CLI, collectors, a baseline scorer, and unit tests.

> **Dependency source of truth:** `pyproject.toml` is the source of dependency declarations.  
> `requirements*.txt` files are generated lockfiles used for reproducible installs.

---

## 🔥 What This Does (Right Now)

- ✅ **Collect the Jenkins plugin registry (“universe snapshot”)** as JSONL
- ✅ **Collect a per-plugin snapshot**
  - curated/pilot by default (no network)
  - real mode pulls the Jenkins plugins API
- ✅ **Collect Jenkins advisories** as newline-delimited JSON (`.jsonl`)
  - sample mode (offline / deterministic)
  - real mode (plugin-specific) via snapshot → `securityWarnings` → advisory URLs
- ✅ **Batch-enrich plugins from the registry** with resume-by-file-exists
  - snapshot + advisories in one command (`collect enrich`)
- ✅ **Build a normalized advisory events dataset** (deduped) for downstream analytics/ML
- ✅ **Score a plugin** using explainable signals (name heuristics + advisory recency/count + snapshot metadata like dependencies, required core, release recency, and security warnings)
- ✅ **Run tests + lint/security checks** in a consistent Docker environment

---

## 📦 Project Structure

```
├── canary/                         # Python package
│   ├── __init__.py
│   ├── cli.py                      # CLI entrypoint (`canary ...`)
│   ├── collectors/                 # Data collectors
│   │   ├── github_repo.py
│   │   ├── jenkins_advisories.py
│   │   ├── plugin_snapshot.py
│   │   └── plugins_registry.py     # Jenkins plugin universe registry collector
│   ├── build/                      # Dataset builders/normalizers (processed outputs)
│   │   └── advisories_events.py    # Normalize advisories -> events JSONL (deduped)
│   ├── datasets/                   # Dataset builders / feature extraction scripts
│   │   ├── gharchive.py            # BigQuery GH Archive feature PoC
│   │   └── github_repo_features.py # GitHub API repo features (+ Scorecard/alerts/advisories)
│   └── scoring/
│       └── baseline.py             # Baseline scorer (explainable)
├── fuzzers/
│   └── jenkins_url_fuzzer.py
├── tests/
│   ├── fixtures/
│   │   └── plugins_api_cucumber-reports.json
│   ├── test_collectors.py
│   ├── test_github_repo.py
│   ├── test_jenkins_advisories_real.py
│   ├── test_plugin_snapshot.py
│   ├── test_scoring.py
│   └── test_smoke.py
├── data/
│   ├── raw/                        # Collected raw artifacts (gitkept; generated)
│   │   ├── registry/               # plugins.jsonl (the “spine”)
│   │   ├── plugins/                # <plugin>.snapshot.json
│   │   └── advisories/             # <plugin>.advisories.real.jsonl
│   └── processed/                  # Derived datasets/features (gitkept; generated)
│       └── events/                 # advisories.jsonl (normalized/deduped)
├── .github/
│   ├── CODEOWNERS
│   ├── SECURITY.md
│   ├── dependabot.yml
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── cflite_pr.yml
│   │   ├── codeql.yml
│   │   ├── pre-commit-autoupdate.yml
│   │   └── scorecard.yml
│   └── rulesets/
│       └── main-branch-protection.json
├── Dockerfile
├── compose.yaml
├── Makefile
├── pyproject.toml
└── requirements*.txt               # Hash-locked lockfiles
```

### Data outputs (generated)

Raw:
- `data/raw/registry/plugins.jsonl` — plugin registry (the universe snapshot)
- `data/raw/plugins/<plugin>.snapshot.json` — plugin snapshot
- `data/raw/advisories/<plugin>.advisories.{sample|real}.jsonl` — advisories (per plugin)

Processed:
- `data/processed/events/advisories.jsonl` — normalized/deduped advisory events stream

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

### 3) Collect the plugin registry (the “universe snapshot”)
```bash
docker compose run --rm canary canary collect registry --real
```

This writes:
- `data/raw/registry/plugins.jsonl`

### 4) Batch-enrich from the registry (snapshot + advisories)
Start small:
```bash
docker compose run --rm canary canary collect enrich --real --max-plugins 25
```

Snapshot-only (fast):
```bash
docker compose run --rm canary canary collect enrich --real --only snapshot --max-plugins 200
```

Advisories-only (assumes snapshots already exist):
```bash
docker compose run --rm canary canary collect enrich --real --only advisories --max-plugins 200
```

### 5) (Optional) Collect a single plugin snapshot (pilot)
Curated snapshot (no network):
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports
```

Real snapshot from the Jenkins plugins API:
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports --real
```

### 6) (Optional) Collect advisories for a single plugin
Sample (offline / deterministic):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --out-dir data/raw/advisories
```

Real (plugin-specific; uses the plugin snapshot’s `securityWarnings` to discover advisory URLs):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
```

### 7) Build the normalized advisory events dataset (deduped)
```bash
docker compose run --rm canary canary build advisories-events
```

This writes:
- `data/processed/events/advisories.jsonl`

### 8) Score a plugin
JSON output (recommended for now):
```bash
docker compose run --rm canary canary score cucumber-reports --data-dir data/raw --json
```

> Note: Scoring is intentionally a transparent baseline and will evolve as more signals/data sources are added.

---

## Google BigQuery GH Archive PoC (Jenkins Plugins)

This repo includes a small proof-of-concept query in `canary/datasets/gharchive.py` that pulls
GitHub Archive activity for Jenkins plugin repos (`jenkinsci/*-plugin`) from BigQuery.

### 1) One-time local setup (Google Cloud CLI + ADC)

Install Google Cloud CLI:
- https://cloud.google.com/sdk/docs/install

Then run in your local terminal/PowerShell:

```bash
gcloud --version
gcloud init
```

Set your project and enable BigQuery API:

```bash
gcloud config set project <YOUR_PROJECT_ID>
gcloud services enable bigquery.googleapis.com --project <YOUR_PROJECT_ID>
```

Authenticate Application Default Credentials (ADC):

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <YOUR_PROJECT_ID>
```

Install Python dependency (local environment):

```bash
pip install google-cloud-bigquery
```

### 2) Run the sample query

Default run (last 7 complete UTC days):

```bash
make gharchive-sample
```

If `make` is unavailable on your platform:

```bash
python -m canary.datasets.gharchive
```

Custom date range/output:

```bash
python -m canary.datasets.gharchive --start 20260201 --end 20260207 --out data/processed/gharchive_sample.csv
```

### 3) Cost guardrail

The script sets `maximum_bytes_billed` to 2GB by default. You can override it:

```bash
python -m canary.datasets.gharchive --max-bytes-billed 500000000
```

The script also samples each day table to keep costs low (default: `--sample-percent 5`).
To sample less/more:

```bash
python -m canary.datasets.gharchive --sample-percent 2
python -m canary.datasets.gharchive --sample-percent 20
```

---

## GitHub Repo Feature PoC (API)

Use this to collect repo metadata and process/security posture features for Jenkins plugin repos.

### 1) Optional: set a GitHub token

Unauthenticated API usage is heavily rate-limited. For smoother runs, export `GITHUB_TOKEN` first.

```bash
export GITHUB_TOKEN=<your_token>
```

PowerShell:

```powershell
$env:GITHUB_TOKEN="<your_token>"
```

### 2) Run

Default (up to 10 `jenkinsci/*-plugin` repos):

```bash
make github-features
```

Direct Python command with options:

```bash
python -m canary.datasets.github_repo_features --org jenkinsci --repo-suffix -plugin --max-repos 25 --out data/processed/github_repo_features.csv
```

Skip Scorecard API enrichment (faster, fewer external calls):

```bash
python -m canary.datasets.github_repo_features --skip-scorecard
```

Include Dependabot/code-scanning alert metrics (best-effort):

```bash
python -m canary.datasets.github_repo_features --include-alerts
```

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

---

## 🔐 Security & Supply Chain Notes

CANARY aims to be reproducible and supply-chain aware:

- Dependencies are **hash-locked** (`requirements*.txt`) and installed with `--require-hashes` in containers/CI.
- Vulnerability auditing runs in Docker to avoid OS-specific dependency drift.
- GitHub Actions are pinned to commit SHAs where possible.
- OpenSSF Scorecard is enabled to track supply-chain posture over time.

---

## 🧠 How Scoring Works (Baseline)

CANARY’s current scorer is intentionally simple and explainable. It combines:

- **Name heuristics** (e.g., keywords that suggest auth/security or SCM surface area)
- **Advisory features** (from local JSONL):
  - advisory count
  - most recent advisory date
  - recency-weighted advisory risk
- **Plugin snapshot features** (from `data/raw/plugins/<plugin>.snapshot.json` when available):
  - required Jenkins core
  - dependency count (surface area proxy)
  - security warnings (active warnings are a strong risk signal)
  - release recency (used as a light “maintenance” signal)

Outputs include the final score, a human-readable list of reasons, and the raw feature values (JSON mode).

---

## 🗺️ Roadmap (Next Steps)

- [x] CLI scaffold (`collect`, `score`) with Docker Compose workflow
- [x] Plugin snapshot collection (curated + `--real` via Jenkins plugins API)
- [x] Plugin registry collection (`collect registry`) to snapshot the Jenkins plugin universe
- [x] Advisory collection:
  - [x] sample (offline) mode
  - [x] real (plugin-specific) mode via snapshot → `securityWarnings` → advisory URLs
- [x] Batch enrich runner (`collect enrich`) with resume-by-file-exists
- [x] Normalize advisories into a deduped events stream (`build advisories-events`)
- [x] Baseline scoring with explainable features (name + advisories + snapshot metadata)
- [ ] Add GitHub signals (stars, recent activity, issues/PRs) as first-class collectors (then add to `collect enrich`)
- [ ] Build per-plugin feature bundles (`data/processed/features/<plugin>.features.json`)
- [ ] Time-sliced dataset builder for ML (as-of date + prediction horizon)

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
