from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

DEFAULT_IGNORE_FILE = ".pip-audit-ignore.txt"


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
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 1
    finally:
        sys.argv = original_argv
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
