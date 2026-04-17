# AGENTS.md — AI Agent Guide for CANARY

This file documents conventions, commands, and constraints that AI agents
(GitHub Copilot, Claude, ChatGPT, etc.) should follow when working in this
repository.  Nothing in this codebase is off-limits for agents, but the rules
below must be respected so that CI passes and outputs stay correct.

---

## Project overview

**CANARY** (Component Analytics & Near-term Advisory Risk Yardstick) is a
Python 3.12 research prototype that collects software-ecosystem signals for
Jenkins plugins and turns them into transparent, explainable risk scores.

### Top-level layout

```
canary/               Main Python package
  cli.py              argparse CLI entry point (canary …)
  webapp.py           Local web console (canary-web, served via waitress)
  plugin_aliases.py   Plugin ID canonicalization / alias resolution
  collectors/         One module per external data source
  build/              Feature-bundle and event builders
  scoring/            Scoring logic (baseline.py)
  train/              ML model training (baseline.py, registry.py)
  devtools/           Developer tooling (pip_audit_wrapper.py)
  static/             Web-console static assets
tests/                pytest test suite (offline/deterministic by default)
  fixtures/           Static fixture files used by tests
data/                 Runtime data (mostly gitignored)
  raw/                As-collected artifacts
  processed/          Derived datasets (events, features, models)
  cache/              Optional HTTP / query caches
deploy/               Deployment helpers
fuzzers/              ClusterFuzzLite fuzz targets
tools/                Miscellaneous scripts
```

---

## How to run things (no Docker required)

All commands below work from the repo root with a plain Python 3.12 virtual
environment.  Docker Compose is an alternative but is not required.

### Install dependencies

```bash
python -m pip install --require-hashes -r requirements.txt
python -m pip install --require-hashes -r requirements-dev.txt
```

> `pyproject.toml` is the **source of truth** for declared dependencies.  
> `requirements*.txt` files are generated, hash-pinned lockfiles — do not edit
> them by hand.  Regenerate with `make reqs` (requires Docker) or with
> `pip-compile` directly.

### Lint and format

```bash
ruff check . --fix     # lint (auto-fixes where possible)
ruff format .          # format
```

Both steps are required for CI to pass.  Run them before committing.

### Type check

```bash
pyright
```

### Security checks

```bash
bandit -r canary -q -s B608
python -m canary.devtools.pip_audit_wrapper
```

### Tests

```bash
pytest -ra
```

Coverage is measured automatically.  For CI-style output:

```bash
pytest --cov-report=xml
```

### All checks (CI order)

1. `ruff check .`
2. `ruff format . --check`
3. `pyright`
4. `bandit -r canary -q -s B608`
5. `python -m canary.devtools.pip_audit_wrapper`
6. `pytest --cov-report=xml`

All six must pass before a PR can be merged.

---

## CLI reference (canary …)

```
canary collect registry  [--real]                  Jenkins plugin registry
canary collect plugin    --id <id> [--real]         Per-plugin snapshot
canary collect advisories [--plugin <id>] [--real]  Jenkins advisories
canary collect github    --plugin <id>              GitHub API enrichment
canary collect healthscore                          Plugin Health Score bulk
canary collect gharchive --registry-path … --start … --end …  GH Archive (BigQuery)
canary collect software-heritage --plugin <id>      Software Heritage metadata
canary collect enrich    [--real] [--only <src>]   Bulk fan-out over registry

canary build advisories-events                     Normalized advisory events
canary build features    --registry …              Static current-point bundle
canary build monthly-features --start … --end …   Time-bounded monthly bundle
canary build monthly-labels  --in-path …           Label monthly bundle for ML

canary score <plugin_id> [--real] [--json]         Score a single plugin
canary train baseline    --in-path … --out-dir …   Train logistic regression by default (--model supports random_forest/xgboost/lightgbm)
```

Use `--help` on any subcommand for the full flag list.

---

## Data layout

```
data/raw/registry/plugins.jsonl              Registry spine (one record/line)
data/raw/registry/plugin_aliases.json        Manual ID → canonical-ID overrides
data/raw/plugins/<id>.snapshot.json          Jenkins plugin snapshot
data/raw/advisories/<id>.advisories.real.jsonl
data/raw/github/<id>.*.json
data/raw/healthscore/plugins/<id>.healthscore.json
data/raw/gharchive/normalized-events/YYYY-MM.gharchive.events.jsonl
data/raw/gharchive/gharchive_index.json
data/raw/software_heritage_api/<id>.swh.json
data/raw/software_heritage_athena/<id>.swh_athena.json

data/processed/events/advisories.jsonl
data/processed/features/plugins.features.jsonl
data/processed/features/plugins.features.csv
data/processed/features/plugins.features.summary.json
data/processed/features/plugins.monthly.features.jsonl
data/processed/features/plugins.monthly.features.csv
data/processed/features/plugins.monthly.labeled.jsonl
data/processed/models/baseline_6m/           Trained model artefacts
```

All bulk data files use **JSONL** (one JSON object per line, UTF-8).  Static
per-plugin JSON payloads should follow the `indent=2, ensure_ascii=False`
convention.

---

## Required environment variables

Agents should **not** make live API calls.  These variables are documented for
reference and for setting up a real collection run — they must not be hardcoded
in source code.

| Variable | Used by | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | `collectors/github_repo.py` | GitHub API authentication (optional but strongly recommended to avoid rate limits) |
| `GOOGLE_CLOUD_PROJECT` | `collectors/gharchive_history.py` | GCP project for BigQuery / GH Archive queries |
| `AWS_ACCESS_KEY_ID` | `collectors/software_heritage_athena.py` | AWS credentials for Athena backend |
| `AWS_SECRET_ACCESS_KEY` | `collectors/software_heritage_athena.py` | AWS credentials for Athena backend |
| `AWS_SESSION_TOKEN` | `collectors/software_heritage_athena.py` | AWS session token (optional) |
| `AWS_REGION` | `collectors/software_heritage_athena.py` | AWS region (default: `us-east-1`) |
| `ATHENA_DATABASE` | `collectors/software_heritage_athena.py` | Athena database name (default: `swh_jenkins`) |
| `ATHENA_S3_STAGING_DIR` | `collectors/software_heritage_athena.py` | S3 staging location for Athena query results |
| `CANARY_WEB_HOST` | `webapp.py` | Web console bind address (default: `127.0.0.1`) |
| `CANARY_WEB_PORT` | `webapp.py` | Web console port (default: `8000`) |
| `CANARY_WEB_THREADS` | `webapp.py` | Waitress worker thread count for the web console (default: `8`) |
| `CANARY_WEB_CONNECTION_LIMIT` | `webapp.py` | Waitress connection limit for the web console (default: `200`) |

The Athena collector also loads a `.env` file via `python-dotenv` at import
time — you can place these variables there for local runs.

---

## Coding conventions

### Every module must start with

```python
from __future__ import annotations
```

This is applied consistently across the entire package and tests.

### Line length

100 characters (enforced by ruff, configured in `pyproject.toml`).

### Ruff rule set

`E`, `F`, `I` (isort), `B` (flake8-bugbear), `UP` (pyupgrade).  
Target: Python 3.12.  Run `ruff check . --fix` to autofix most violations.

### Type annotations

All public functions and methods must be annotated.  Private helpers (`_name`)
should be annotated where the type is non-obvious.  Pyright runs in `basic`
mode — avoid patterns that cause type errors.

### Python version

Python 3.12+.  Use modern syntax freely:

- Union types: `str | None` (not `Optional[str]`)
- Built-in generics: `list[str]`, `dict[str, Any]` (not `List`, `Dict`)
- `datetime.UTC` (not `datetime.timezone.utc`)

### Imports

Standard library → third-party → local, separated by blank lines (isort
enforces this automatically via ruff).

### File I/O

Always use `pathlib.Path`.  Open files with `encoding="utf-8"` explicitly.

### JSON output

```python
json.dumps(record, ensure_ascii=False)          # compact / JSONL
json.dumps(record, indent=2, ensure_ascii=False) # pretty-print
```

### JSONL reading pattern

```python
with path.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
```

### Security patterns in collectors

- **URL allowlisting**: most HTTP collectors validate `scheme == "https"` and
  `netloc in _ALLOWED_NETLOCS` before fetching.  Note: `collectors/healthscore.py`
  uses a constant URL via `requests.get()` directly without an explicit allowlist
  check — new collectors should follow the allowlisting pattern.
- **Path traversal prevention**: untrusted strings are validated against a
  strict regex (`^[A-Za-z0-9][A-Za-z0-9._-]*$`) before being used as file
  name components.  Constructed paths are resolved with `.resolve()` and
  checked to lie under the expected base directory.
- **No `eval`, no `exec`, no `subprocess` with untrusted input.**

### Dataclasses

Use `@dataclass(frozen=True)` for immutable result types (e.g. `ScoreResult`).

### `lru_cache`

Use `functools.lru_cache` for functions that load files or perform expensive
one-time lookups (e.g. alias maps, registry lookups).

---

## Test conventions

- Tests live in `tests/` and are discovered by pytest automatically.
- **All tests that run in the default `pytest` invocation must be offline and
  deterministic.**  They use static fixture files from `tests/fixtures/` or
  mocked data.
- Files named `*_extra.py` or `*_real.py` are still discovered by pytest's
  default `test_*.py` rules unless they are explicitly excluded elsewhere.
  Treat those suffixes as naming conventions only, not as a mechanism that
  keeps tests out of CI's default `pytest` pass.
- Use `tests/fixtures/` for any static JSON/JSONL/CSV data needed by a test.
- Do not remove or skip existing tests unless the behaviour they cover has been
  intentionally deleted.

---

## Pull request checklist

When preparing a PR, ensure all of the following pass locally (these mirror the
steps in `.github/workflows/ci.yml`):

- [ ] `ruff check .` — no lint errors
- [ ] `ruff format . --check` — no formatting differences
- [ ] `pyright` — no type errors
- [ ] `bandit -r canary -q -s B608` — no security findings
- [ ] `python -m canary.devtools.pip_audit_wrapper` — no unresolved vulnerabilities
- [ ] `pytest -ra` — all tests pass

Fill in the PR template (`.github/PULL_REQUEST_TEMPLATE.md`) including the
data/schema impact section if any output formats or file paths changed.

---

## Things to avoid

- **Do not make live API calls** (GitHub, BigQuery, Athena, Software Heritage,
  plugins.jenkins.io) in tests or in offline/sample code paths.
- **Do not hardcode credentials or tokens** anywhere in source code.
- **Do not edit `requirements*.txt` by hand** — they are generated lockfiles.
- **Do not remove the `from __future__ import annotations` header** from any
  existing module.
- **Do not introduce new top-level dependencies** without also updating
  `pyproject.toml` and regenerating the lockfiles.
- **Do not bypass the URL allowlist** (`_ALLOWED_NETLOCS`) in any collector.
- **Do not use `subprocess` with shell=True or untrusted input.**
- **Do not ignore `pip-audit` findings** without adding the advisory ID to
  `.pip-audit-ignore.txt` with a dated comment explaining why.

---

## Reporting security issues

Do not open a public GitHub issue for security vulnerabilities.  Use GitHub
Security Advisories ("Report a vulnerability" in the Security tab) or email
`tebrennan@gwu.edu` with "CANARY security" in the subject line.
