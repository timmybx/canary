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
	python -m pre_commit run pyright --all-files

reqs:
	python -m piptools compile --output-file requirements.txt pyproject.toml
	python -m piptools compile --extra dev --output-file requirements-dev.txt pyproject.toml

all: ruff security pyright reqs test

demo:
	docker compose run --rm canary canary collect plugin --id cucumber-reports --real
	docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
	docker compose run --rm canary canary score cucumber-reports --data-dir data/raw --json