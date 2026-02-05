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
.
├── canary/                 # Python package (CLI, collectors, scoring)
├── data/
│   └── processed/          # Output data (e.g., advisories JSONL)
├── tests/                  # Unit tests
├── compose.yaml            # Docker Compose for dev loop
├── Dockerfile              # Container image for consistent runs
├── docker-entrypoint.sh    # Container entrypoint
└── pyproject.toml          # Dependencies + tooling config (pytest, ruff, etc.)
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
docker compose run --rm canary pytest -ra
```

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

### “TOMLDecodeError: Cannot declare ('tool', ...) twice”
Your `pyproject.toml` has duplicate tool tables (e.g., `[tool.ruff]` or `[tool.pytest.ini_options]`) declared more than once.
Merge them into a single section per tool.

### Rebuild if Docker cached something weird
```bash
docker compose build --no-cache canary
```

---

## 📄 License

TBD 

---

## ⚠️ Disclaimer

This is a research/prototype scaffold. Scores are **not** security guarantees and should not be used as the sole basis for operational risk decisions.

---

## 👤 Author

**Timothy Brennan**
