"""Allow ``python -m canary.cli`` to run the console entry point."""

from canary.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
