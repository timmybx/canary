from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from urllib.error import URLError

import requests

DEFAULT_IGNORE_FILE = ".pip-audit-ignore.txt"
ALLOW_NETWORK_FAILURE_ENV = "CANARY_PIP_AUDIT_ALLOW_NETWORK_FAILURE"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ignore_file_path() -> Path:
    configured = os.environ.get("PIP_AUDIT_IGNORE_FILE", DEFAULT_IGNORE_FILE)
    path = Path(configured)
    if not path.is_absolute():
        path = _repo_root() / path
    return path


def load_ignored_vulns(path: Path | None = None) -> list[str]:
    ignore_path = path or _ignore_file_path()
    if not ignore_path.exists():
        return []

    ignored: list[str] = []
    for raw_line in ignore_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            ignored.append(line)
    return ignored


def build_argv(ignore_ids: list[str] | None = None) -> list[str]:
    command = ["pip-audit"]
    for vuln_id in ignore_ids or load_ignored_vulns():
        command.extend(["--ignore-vuln", vuln_id])
    return command


def main() -> int:
    original_argv = sys.argv[:]
    sys.argv = build_argv()
    try:
        audit = importlib.import_module("pip_audit._cli").audit
        audit()
    except (requests.exceptions.RequestException, URLError) as exc:
        print(f"pip-audit could not reach its vulnerability service: {exc}", file=sys.stderr)
        if os.environ.get(ALLOW_NETWORK_FAILURE_ENV) == "1":
            print(
                "Continuing because "
                f"{ALLOW_NETWORK_FAILURE_ENV}=1. CI still runs pip-audit strictly.",
                file=sys.stderr,
            )
            return 0
        return 1
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 1
    finally:
        sys.argv = original_argv
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
