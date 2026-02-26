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
	docker compose run --rm canary bandit -r canary -q

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


.PHONY: metrics metrics-severity metrics-plugin-severity clean help

# Quick metrics to summarize severity distribution in the collected real advisories.
# Counts are based on CVSS v3.x base_score buckets (None/Low/Medium/High/Critical).
metrics: metrics-severity metrics-plugin-severity

# Distribution across *vulnerability instances* (each advisory may contain multiple vulnerabilities).
metrics-severity:
	@ls data/raw/advisories/*.advisories.real.jsonl >/dev/null 2>&1 || (echo "No files found: data/raw/advisories/*.advisories.real.jsonl" && echo "Run: docker compose run --rm canary canary collect advisories --real --out-dir data/raw/advisories" && exit 1)
	@echo "Vulnerability CVSS severity counts (instances):"
	@cat data/raw/advisories/*.advisories.real.jsonl \
	| jq -r '.vulnerabilities[]? \
		| select(.cvss?.base_score? != null) \
		| (.cvss.base_score) as $$s \
		| if $$s == 0 then "None" \
		  elif $$s < 4 then "Low" \
		  elif $$s < 7 then "Medium" \
		  elif $$s < 9 then "High" \
		  else "Critical" end' \
	| sort | uniq -c

# Distribution across *unique plugins* by their maximum CVSS base score observed in advisories.
metrics-plugin-severity:
	@ls data/raw/advisories/*.advisories.real.jsonl >/dev/null 2>&1 || (echo "No files found: data/raw/advisories/*.advisories.real.jsonl" && echo "Run: docker compose run --rm canary canary collect advisories --real --out-dir data/raw/advisories" && exit 1)
	@echo ""
	@echo "Unique plugins with any CVSS score in advisories:"
	@cat data/raw/advisories/*.advisories.real.jsonl \
	| jq -r 'select(.vulnerabilities[]? | .cvss?.base_score? != null) | .plugin_id' \
	| sort -u | wc -l
	@echo ""
	@echo "Unique plugin severity (max CVSS per plugin):"
	@cat data/raw/advisories/*.advisories.real.jsonl \
	| jq -r '.plugin_id as $$p \
		| ([.vulnerabilities[]? | .cvss?.base_score?] | map(select(. != null)) | max) as $$m \
		| select($$m != null) \
		| (if $$m == 0 then "None" \
		   elif $$m < 4 then "Low" \
		   elif $$m < 7 then "Medium" \
		   elif $$m < 9 then "High" \
		   else "Critical" end) as $$label \
		| $$label' \
	| sort | uniq -c

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
