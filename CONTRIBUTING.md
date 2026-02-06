# Contributing to CANARY

Thanks for taking an interest in CANARY! This project is a research prototype, so the main goals are
**reproducibility**, **data integrity**, and **clear, explainable outputs**.

## Development workflow (Docker recommended)

### Prereqs
- Docker Desktop (includes Docker Engine + Docker Compose v2)

### Common commands
Build the image:
```bash
docker compose build
```

Run the CLI:
```bash
docker compose run --rm canary canary --help
```

Run tests:
```bash
docker compose run --rm canary pytest -ra
```

Lint / format:
```bash
docker compose run --rm canary ruff check . --fix
docker compose run --rm canary ruff format .
```

Security checks:
```bash
docker compose run --rm canary bandit -r canary -q
docker compose run --rm canary pip-audit
```

## Pre-commit (recommended)
Install the git hooks locally:
```bash
python -m pip install --user pre-commit
python -m pre_commit install
```

Run all hooks:
```bash
python -m pre_commit run --all-files
```

## Updating pinned requirements (optional)
`pyproject.toml` is the source of truth. The `requirements*.txt` files are generated snapshots.

Generate pinned runtime deps:
```bash
python -m piptools compile --output-file requirements.txt pyproject.toml
```

Generate pinned dev deps:
```bash
python -m piptools compile --extra dev --output-file requirements-dev.txt pyproject.toml
```

## Pull request guidelines
- Keep PRs small and focused.
- Add/adjust unit tests for any behavior change.
- CI must pass (ruff, bandit, pip-audit, pytest).
- Prefer explainable changes: document assumptions and edge cases (especially around parsing and data normalization).

## Reporting security issues
Please see `SECURITY.md` (use GitHub Security Advisories and avoid public disclosure).
