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

security: bandit
	docker compose run --rm canary pip-audit

reqs:
	python -m piptools compile --output-file requirements.txt pyproject.toml
	python -m piptools compile --extra dev --output-file requirements-dev.txt pyproject.toml

