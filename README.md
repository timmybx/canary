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
  - bulk mode available (fan out over registry)
- ✅ **Collect Jenkins advisories** as newline-delimited JSON (`.jsonl`)
  - sample mode (offline / deterministic)
  - real mode (plugin-specific) via snapshot → `securityWarnings` → advisory URLs
  - batch mode available via `collect enrich`
- ✅ **Collect Jenkins plugin Health Score dataset** (bulk) from `plugin-health.jenkins.io`
- ✅ **Batch-enrich plugins from the registry** with resume-by-file-exists
  - snapshot + advisories + GitHub + healthscore in one command (`collect enrich`)
- ✅ **Build a normalized advisory events dataset** (deduped) for downstream analytics/ML
- ✅ **Score a plugin** using explainable signals:
  - name heuristics
  - advisory history + CVSS
  - plugin snapshot metadata (dependencies, required core, release recency, security warnings)
  - healthscore (higher = healthier; mapped into a small “risk points” contribution)
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
│   │   ├── advisories/             # <plugin>.advisories.real.jsonl
│   │   ├── github/                 # <plugin>.* GitHub payloads (best-effort)
│   │   └── healthscore/            # Healthscore dataset (bulk)
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
│   │   ├── scorecard.yml
│   │   └── pre-commit-autoupdate.yml
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
- `data/raw/healthscore/plugins/plugins.healthscore.json` — aggregated healthscore dataset (bulk)

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

> **Sanity check:** ensure your registry has mostly unique `plugin_id`s.
```bash
docker compose run --rm canary python - <<'PY'
import json
pids=[]
for line in open("data/raw/registry/plugins.jsonl","r",encoding="utf-8"):
    if line.strip():
        pids.append(json.loads(line)["plugin_id"])
print("lines:", len(pids))
print("unique:", len(set(pids)))
PY
```

If `unique << lines`, something is wrong with paging/collection and downstream “bulk” collection will only cover a small subset.

### 4) Collect snapshots + advisories in batch (recommended path)
Batch-enrich from the registry (snapshot + advisories + github + healthscore, resume-by-file-exists):
```bash
docker compose run --rm canary canary collect enrich --real --max-plugins 25
```

Run all stages for a larger batch:
```bash
docker compose run --rm canary canary collect enrich --real --max-plugins 200
```

Stage-specific runs:
```bash
docker compose run --rm canary canary collect enrich --real --only snapshot   --max-plugins 200
docker compose run --rm canary canary collect enrich --real --only advisories --max-plugins 200
docker compose run --rm canary canary collect enrich --real --only github     --max-plugins 200
docker compose run --rm canary canary collect enrich --real --only healthscore
```

### 5) (Optional) Bulk snapshot collection (fan out over registry)
`collect plugin` supports bulk mode when `--id` is omitted. Use `--sleep` to be polite to upstream services.

```bash
docker compose run --rm canary canary collect plugin --real --sleep 0.2
```

Useful knobs:
- `--registry data/raw/registry/plugins.jsonl`
- `--max-plugins N`
- `--overwrite`

### 6) (Optional) Collect a single plugin snapshot
Curated snapshot (no network):
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports
```

Real snapshot from the Jenkins plugins API:
```bash
docker compose run --rm canary canary collect plugin --id cucumber-reports --real
```

### 7) (Optional) Collect advisories for a single plugin
Sample (offline / deterministic):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --out-dir data/raw/advisories
```

Real (plugin-specific; uses the plugin snapshot’s `securityWarnings` to discover advisory URLs):
```bash
docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
```

### 8) Collect healthscores (bulk)
This fetches the Jenkins Plugin Health Score dataset from `plugin-health.jenkins.io` and writes an aggregated JSON file:

```bash
docker compose run --rm canary canary collect healthscore
```

Writes:
- `data/raw/healthscore/plugins/plugins.healthscore.json`

### 9) Build the normalized advisory events dataset (deduped)
```bash
docker compose run --rm canary canary build advisories-events
```

Writes:
- `data/processed/events/advisories.jsonl`

### 10) Score a plugin
JSON output (recommended for now):
```bash
docker compose run --rm canary canary score cucumber-reports --real --json
```

Output includes:
- final numeric score
- human-readable reasons
- raw feature values (including `healthscore_*` fields when available)

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
- **Healthscore features** (from the bulk healthscore dataset when available):
  - healthscore value/date
  - a small risk-points mapping (higher health = lower risk)

Outputs include the final score, a human-readable list of reasons, and the raw feature values (JSON mode).

---

## 🗺️ Roadmap (Next Steps)

- [x] CLI scaffold (`collect`, `score`) with Docker Compose workflow
- [x] Plugin snapshot collection (curated + `--real` via Jenkins plugins API)
- [x] Plugin registry collection (`collect registry`) to snapshot the Jenkins plugin universe
- [x] Advisory collection:
  - [x] sample (offline) mode
  - [x] real (plugin-specific) mode via snapshot → `securityWarnings` → advisory URLs
- [x] Healthscore bulk collector
- [x] Baseline scoring with explainable features (name + advisories + snapshot metadata + healthscore)
- [ ] Add GitHub signals (stars, recent activity, issues/PRs) as first-class collectors (then add to `collect enrich`)
- [ ] Build per-plugin feature bundles (`data/processed/features/<plugin>.features.json`)
- [ ] Time-sliced dataset builder for ML (as-of date + prediction horizon)

---

## 🧯 Troubleshooting

### Registry has duplicates (unique << lines)
If you see far fewer unique `plugin_id`s than lines in `plugins.jsonl`, downstream bulk collection will only cover that smaller set.
Re-run `collect registry --real` and verify uniqueness with the snippet in Quickstart step 3.

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
