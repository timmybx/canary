# CANARY (starter scaffold)

CLI-first scaffold for the CANARY project.

## Quickstart (Docker)
```bash
docker compose build
docker compose run --rm canary canary --help
docker compose run --rm canary canary collect advisories
docker compose run --rm canary canary score workflow-cps
docker compose run --rm canary pytest
