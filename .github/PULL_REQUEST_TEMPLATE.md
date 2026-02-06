## Summary
Describe what this PR changes and why.

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] Tooling / CI
- [ ] Other (describe): ______________________

## Related issues
Link issues (e.g., `Closes #123`) or describe context.

## Testing
How did you verify this change?
- [ ] `docker compose run --rm canary pytest -ra`
- [ ] `docker compose run --rm canary ruff check .`
- [ ] `docker compose run --rm canary ruff format . --check`
- [ ] `docker compose run --rm canary bandit -r canary -q`
- [ ] `docker compose run --rm canary pip-audit`
- [ ] Other (describe): ______________________

## Data / schema impact (if applicable)
- Does this change the advisory schema or parsing rules?
- Are outputs in `data/processed/` compatible with prior snapshots?

## Notes for reviewers
Anything you’d like reviewers to pay attention to (edge cases, assumptions, tradeoffs).

> **Security note:** If this change relates to a security issue, avoid posting sensitive details publicly.
> Follow `SECURITY.md` for reporting/handling vulnerabilities.
