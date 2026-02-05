test:
	docker compose run --rm canary pytest -ra

lint:
	docker compose run --rm canary ruff check . --fix

format:
	docker compose run --rm canary ruff format .

audit:
	docker compose run --rm canary pip-audit
