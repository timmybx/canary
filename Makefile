build:
	docker compose build --no-cache canary

test:
	docker compose run --rm canary pytest --cov-report=html

lint:
	docker compose run --rm canary ruff check . --fix

format:
	docker compose run --rm canary ruff format .

audit:
	docker compose run --rm canary pip-audit

ruff: lint format

bandit:
	docker compose run --rm canary bandit -r canary -q -s B608

security: bandit audit
	
pyright:
	docker compose run --rm canary pyright

reqs:
	docker compose run --rm canary sh -lc "python -m pip install --quiet 'pip<26' && pip-compile --allow-unsafe --generate-hashes -o requirements-build.txt requirements-build.in"
	docker compose run --rm canary sh -lc "python -m pip install --quiet 'pip<26' && pip-compile --generate-hashes -o requirements-ci.txt requirements-ci.in"
	docker compose run --rm canary sh -lc "python -m pip install --quiet 'pip<26' && pip-compile --generate-hashes -o requirements.txt pyproject.toml"
	docker compose run --rm canary sh -lc "python -m pip install --quiet 'pip<26' && pip-compile --extra=dev --generate-hashes -o requirements-dev.txt pyproject.toml"

all: ruff security pyright reqs test

demo:
	docker compose run --rm canary canary collect plugin --id cucumber-reports --real
	docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
	docker compose run --rm canary canary score cucumber-reports --data-dir data/raw --json

gharchive-sample:
	python -m canary.datasets.gharchive $(ARGS)

github-features:
	python -m canary.datasets.github_repo_features $(ARGS)


.PHONY: metrics metrics-top clean help

# Quick metrics to summarize severity distribution in the collected real advisories.
# Counts are based on CVSS v3.x base_score buckets (None/Low/Medium/High/Critical).
metrics:
	@echo "Vulnerability CVSS severity counts (instances):"
	@cat data/raw/advisories/*.advisories.real.jsonl | jq -r '.vulnerabilities[]? | select(.cvss?.base_score? != null) | (.cvss.base_score) as $$s | if $$s == 0 then "None" elif $$s < 4 then "Low" elif $$s < 7 then "Medium" elif $$s < 9 then "High" else "Critical" end' | sort | uniq -c
	@echo ""
	@echo "Unique plugins with any CVSS score in advisories:"
	@cat data/raw/advisories/*.advisories.real.jsonl | jq -r 'select(.vulnerabilities[]? | .cvss?.base_score? != null) | .plugin_id' | sort -u | wc -l
	@echo ""
	@echo "Unique plugin severity (max CVSS per plugin):"
	@cat data/raw/advisories/*.advisories.real.jsonl | jq -r '.plugin_id as $$p | ([.vulnerabilities[]? | .cvss?.base_score?] | map(select(. != null)) | max) as $$m | select($$m != null) | (if $$m == 0 then "None" elif $$m < 4 then "Low" elif $$m < 7 then "Medium" elif $$m < 9 then "High" else "Critical" end) as $$label | $$label' | sort | uniq -c

metrics-top:
	@echo "Top 10 plugins by max CVSS base score:"
	@cat data/raw/advisories/*.advisories.real.jsonl | jq -r '.plugin_id as $$p | ([.vulnerabilities[]? | .cvss?.base_score?] | map(select(.!=null)) | max) as $$m | select($$m != null) | [($$m|tostring), $$p] | @tsv' \
	| sort -t $$'\t' -k1,1nr \
	| head -n 10

clean:
	@rm -rf .pytest_cache .ruff_cache htmlcov .coverage

help:
	@echo "Common targets:"
	@echo "  make build            Build the Docker image"
	@echo "  make test             Run pytest (writes htmlcov/)"
	@echo "  make ruff             Run ruff lint + format"
	@echo "  make security         Run bandit + pip-audit"
	@echo "  make pyright          Run pyright type checks"
	@echo "  make reqs             Rebuild requirements*txt with hashes"
	@echo "  make metrics          Show CVSS severity distributions from real advisories"
	@echo "  make clean            Remove local test/lint artifacts"

# ---- Scoring leaderboard  ----
# How many plugins to score (override with: make score-top LIMIT=30)
LIMIT ?= 20
.PHONY: score-top score-top20 score-top20-tsv
score-top: score-top20

.PHONY: score-top20
score-top20:
	@ls data/raw/advisories/*.advisories.real.jsonl >/dev/null 2>&1 || (echo "No real advisory files found. Run: docker compose run --rm canary canary collect enrich --real --only advisories" && exit 1)
	@tmpfile=score_top_input.tsv; \
	  rm -f $$tmpfile; \
	  for f in data/raw/advisories/*.advisories.real.jsonl; do \
	    plugin=$$(basename "$$f" .advisories.real.jsonl); \
	    maxcvss=$$(jq -r '[.vulnerabilities[]? | .cvss?.base_score?] | map(select(.!=null)) | max // empty' "$$f"); \
	    if [ -n "$$maxcvss" ]; then printf "%s\t%s\n" "$$plugin" "$$maxcvss"; fi; \
	  done | sort -k2,2nr | head -n $(LIMIT) > $$tmpfile; \
	  printf "score\tplugin_id\tadvisory_count\tmax_cvss\tadvisories_365d\tactive_sec_warnings\tdeps\tlatest_release\n"; \
	  COMPOSE_PROGRESS=quiet docker compose run --rm -T canary bash -lc '\
	    set -euo pipefail; \
	    tmp="score_top_input.tsv"; \
	    while IFS=$$'\''\t'\'' read -r plugin maxcvss; do \
	      plugin=$${plugin%$$'\''\r'\''}; \
	      maxcvss=$${maxcvss%$$'\''\r'\''}; \
	      j=$$(canary score "$$plugin" --real --json </dev/null | tr -d '\r'); \
	      row=$$(python -c "import json,sys; plugin,maxcvss,raw=sys.argv[1:4]; obj=json.loads(raw); features=obj.get(\"features\") or {}; score=obj.get(\"score\") or 0; advis=features.get(\"advisory_count\") or 0; adv365=features.get(\"advisory_within_365d\") or 0; active=features.get(\"active_security_warning_count\") or 0; deps=features.get(\"dependency_count\") or 0; rel=features.get(\"release_timestamp\") or \"-\"; rel=(rel[:10] if isinstance(rel, str) and len(rel) >= 10 else rel); print(f\"{score}\\t{plugin}\\t{advis}\\t{maxcvss}\\t{adv365}\\t{active}\\t{deps}\\t{rel}\")" "$$plugin" "$$maxcvss" "$$j" 2>/dev/null) || { \
	        fn="canary_bad_json_$${plugin}.txt"; \
	        printf "%s" "$$j" > "$$fn"; \
	        echo "BAD JSON for plugin=$$plugin (wrote $$fn)" >&2; \
	        exit 1; \
	      }; \
	      printf "%s\n" "$$row"; \
	    done < "$$tmp"'; \
	  rm -f $$tmpfile
	  
# Save leaderboard output to a TSV file (docker noise suppressed)
score-top20-tsv:
	@$(MAKE) --no-print-directory score-top20 1> score_top20.tsv 2>/dev/null
	@echo "Wrote score_top20.tsv"
