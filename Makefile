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
	docker compose run --rm canary pip-compile --generate-hashes -o requirements-build.txt requirements-build.in
	docker compose run --rm canary pip-compile --generate-hashes -o requirements.txt pyproject.toml
	docker compose run --rm canary pip-compile --extra=dev --generate-hashes -o requirements-dev.txt pyproject.toml

all: ruff security pyright reqs test

demo:
	docker compose run --rm canary canary collect plugin --id cucumber-reports --real
	docker compose run --rm canary canary collect advisories --plugin cucumber-reports --real --data-dir data/raw --out-dir data/raw/advisories
	docker compose run --rm canary canary score cucumber-reports --data-dir data/raw --json
