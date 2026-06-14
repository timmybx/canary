# Contributing to CANARY

Thanks for taking an interest in CANARY! This project is a research prototype, so the main goals are
**reproducibility**, **data integrity**, and **clear, explainable outputs**.

## Getting the code

```bash
git clone https://github.com/timmybx/canary.git
cd canary
```

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
docker compose run --build --rm canary python -m canary.devtools.pip_audit_wrapper
```

If `pip-audit` is blocked by a known advisory with no upstream fix yet, add the advisory ID
to `.pip-audit-ignore.txt` with a short comment and remove it once a patched release exists.

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
python -m piptools compile --allow-unsafe --generate-hashes --output-file requirements.txt pyproject.toml
```

Generate pinned dev deps (source is `requirements-dev.in`, not `pyproject.toml`):
```bash
python -m piptools compile --allow-unsafe --generate-hashes --output-file requirements-dev.txt requirements-dev.in
```

Generate pinned CI deps (minimal lockfile for the pre-commit autoupdate workflow only):
```bash
python -m piptools compile --allow-unsafe --generate-hashes --output-file requirements-ci.txt requirements-ci.in
```

## Pull request guidelines
- Keep PRs small and focused.
- Add/adjust unit tests for any behavior change.
- CI must pass (ruff, pyright, bandit, pip-audit, pytest).
- Prefer explainable changes: document assumptions and edge cases (especially around parsing and data normalization).

## Testing

### Coverage policy
Coverage (`--cov-fail-under=93`) is a **ratchet, not a target**. It blocks regressions; it is not a reason to write tests. Write tests because behavior needs to be protected, then let coverage follow. Never add a test solely to bump a number.

When you raise the floor, do it in a separate commit after a green run that already shows headroom. Note the new floor and why in the commit message.

### Live-data tests and committed fixtures
Some tests exercise the full scoring pipeline and normally read from `data/raw/` (gitignored). These tests use a committed fixture tree at `tests/fixtures/data/raw/` that contains trimmed, representative copies of real data so they run in CI without the local data directory.

If you add a new live-data integration test:
1. Place trimmed fixture files under `tests/fixtures/data/raw/<subdir>/`.
2. Accept the `fixture_data_dir` and `monkeypatch` fixtures (defined in `tests/conftest.py`).
3. Monkeypatch the module-level `_DATA_ROOT` constant before calling the function under test:
   ```python
   import canary.scoring.baseline as _baseline_mod

   def test_something(fixture_data_dir, monkeypatch):
       monkeypatch.setattr(_baseline_mod, "_DATA_ROOT", fixture_data_dir)
       result = score_plugin_baseline("workflow-cps")
       ...
   ```
4. The fixture directory is **not** gitignored (`.gitignore` anchors `data/raw/**` to the repo root), so the files commit normally.

## Type checking
Pyright runs in CI (`pyright` step in `.github/workflows/ci.yml`) and covers **both** `canary/` and `tests/` as configured in `pyproject.toml`:

```toml
[tool.pyright]
include = ["canary", "tests"]
pythonVersion = "3.12"
typeCheckingMode = "basic"
```

Run it locally the same way:
```bash
docker compose run --rm canary pyright
```

When pyright flags a pandas or third-party-stub false positive that you cannot fix without obscuring real logic, suppress it inline with a comment scoped to the specific rule:
```python
pd.DataFrame(data, columns=cols)  # pyright: ignore[reportArgumentType]
```

Avoid blanket `# type: ignore` unless no rule-specific suppression exists.

## Notes for AI agents
If you are an AI agent working in this repository:
- Read `.github/agents/unit-test.agent.md` before writing or modifying any test.
- The coverage ratchet means a failing `--cov-fail-under` in CI is a regression, not a style issue. Fix it by adding tests that protect real behavior, not by lowering the floor.
- Pyright covers test files in CI. New test files must be pyright-clean. Add `# pyright: ignore[<rule>]` for unavoidable false positives rather than suppressing whole files.
- When committing fixture data for live-data tests, keep fixtures minimal (only the fields the code under test actually reads) to reduce maintenance burden.

## Reporting security issues
Please see `SECURITY.md` (use GitHub Security Advisories and avoid public disclosure).
