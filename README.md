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
- **`canary/datasets/gharchive.py`** — BigQuery GH Archive proof-of-concept query for Jenkins plugin activity features.
- **`canary/datasets/github_repo_features.py`** — GitHub API PoC for repo-level security/process features.

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

Output file (default):
- `data/processed/gharchive_jenkins_plugins_last_week.csv`

Result shape:
- One row per Jenkins plugin repo for the selected window.
- Includes activity and risk-oriented features such as:
  - `committers_unique_30d`, `push_days_active_30d`
  - `pr_reviewed_ratio`, `pr_merge_time_p50_hours`, `pr_close_without_merge_ratio`
  - `issue_reopen_rate`, `issue_close_time_p50_hours`
  - `hotfix_proxy`, `releases_30d`, `days_since_last_release`
  - `security_label_proxy`, `churn_intensity`, `owner_concentration`

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

Without `GITHUB_TOKEN`, the script uses a conservative default (`--max-repos 10`) due to
GitHub's unauthenticated API rate limit (60 requests/hour).

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

For alert endpoints, your token may need additional read permissions depending on repo/org policy.
If unavailable, alert fields are emitted as `null` and `*_visible` is `false`.

### 3) Output

- `data/processed/github_repo_features.csv`
- Fields include:

| Category | Fields | Notes |
|---|---|---|
| Popularity/activity context | `stars`, `forks`, `watchers`, `open_issues_count`, `days_since_last_push` | Context for normalizing/segmenting risk signals. |
| Release recency | `days_since_last_release` | Maintenance freshness proxy. |
| Hygiene config presence | `dependabot_config_present`, `codeql_workflow_present` | Presence of configuration (not alert counts). |
| Security/process posture | `codeowners_present`, `security_policy_present`, `workflows_present` | Lightweight public posture signals. |
| OpenSSF posture | `scorecard_overall`, `scorecard_branch_protection`, `scorecard_pinned_dependencies`, `scorecard_token_permissions`, `scorecard_dangerous_workflow`, `scorecard_maintained` | Pulled from Scorecard API. |
| Alert posture (when visible) | `dependabot_open_alerts*`, `code_scanning_open_alerts*` plus `*_visible` flags | Depends on token/org access; emits `null` when unavailable. |
| Repository advisory posture (when visible) | `repo_security_advisories_total`, severity buckets, `repo_security_advisories_published_30d`, `repo_security_advisories_cvss_max`, `repo_security_advisories_cvss_avg` | Depends on token/org access; emits `null` when unavailable. |

### Feature Reference (What + Why)

The GH Archive PoC output includes one row per repo for your selected window and the
following feature fields:

| Name | Description | Why It Matters |
|---|---|---|
| `events_total` | Total GH Archive events observed for the repo in the window. | Normalizes overall activity; useful context for interpreting other rates. |
| `actors_unique` | Distinct GitHub actors across all events. | Low contributor diversity can increase key-person risk; very high churn can increase instability. |
| `pushes` | Count of `PushEvent`s. | Basic change-volume indicator; more code movement can increase exposure to defects. |
| `committers_unique_30d` | Distinct actors who pushed code. | Bus-factor proxy; concentrated commit access can increase operational/security risk. |
| `push_days_active_30d` | Number of days with at least one push. | Maintenance consistency proxy; long inactivity can correlate with delayed patching. |
| `prs_opened` | Pull requests opened. | Baseline for collaboration and denominator for PR-related ratios. |
| `prs_closed` | Pull requests closed (merged + unmerged). | Throughput and triage signal. |
| `prs_merged` | Pull requests merged. | Accepted change velocity; useful with review and latency signals. |
| `pr_reviewed_ratio` | `PullRequestReviewEvent` count divided by PRs opened. | Review rigor proxy; stronger review often reduces defect/security regression risk. |
| `pr_merge_time_p50_hours` | Median hours from PR creation to merge (merged PRs only). | Process quality/speed signal; extremes can indicate rushed or stalled pipelines. |
| `prs_closed_unmerged` | Closed PRs that were not merged. | Friction/rejection signal that can indicate quality issues or noisy contributions. |
| `pr_close_without_merge_ratio` | `prs_closed_unmerged / prs_opened`. | Normalized PR friction metric for cross-repo comparison. |
| `issues_opened` | Issues opened. | Workload/incoming problem volume proxy. |
| `issues_closed` | Issues closed. | Issue resolution throughput proxy. |
| `issues_reopened` | Reopened issues. | Potential quality/regression signal. |
| `issue_reopen_rate` | `issues_reopened / issues_closed`. | Normalized stability proxy; higher rates can indicate recurring defects. |
| `issue_close_time_p50_hours` | Median issue open-to-close duration. | Responsiveness/maintenance capacity signal. |
| `releases_30d` | Count of release events in the window. | Release cadence signal; long gaps may correlate with stale dependencies/fixes. |
| `days_since_last_release` | Days since latest release event observed. | Freshness/maintenance recency proxy. |
| `hotfix_proxy` | Share of pushes that happen within 48 hours after issue-open events. | Reactive churn proxy; persistent reactive behavior can indicate instability pressure. |
| `security_label_proxy` | Count of issue/PR text blobs matching security-related terms (`security`, `vuln`, `cve-`, `xss`, `sqli`, `rce`). | Weak proxy for security-related discussion and triage intensity. |
| `churn_intensity` | `(pushes + prs_opened) / actors_unique`. | Normalized code-change pressure per contributor. |
| `owner_concentration` | Max single-actor share of pushes in the window. | Ownership concentration (bus-factor) proxy; high concentration can raise maintenance and supply-chain risk. |

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
