"""
Behavior tests for canary.devtools.pip_audit_wrapper: the ignore-file
contract, argv construction, and main()'s exit-code/network-failure policy.

Consolidates test_pip_audit_wrapper{,_extra,_more}.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest
import requests

from canary.devtools import pip_audit_wrapper
from canary.devtools.pip_audit_wrapper import load_ignored_vulns


def test_load_ignored_vulns_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".pip-audit-ignore.txt"
    ignore_file.write_text(
        "\n".join(
            [
                "# temporary waiver",
                "GHSA-aaaa-bbbb-cccc",
                "",
                "PYSEC-2026-123  # tracked upstream",
            ]
        ),
        encoding="utf-8",
    )

    assert pip_audit_wrapper.load_ignored_vulns(ignore_file) == [
        "GHSA-aaaa-bbbb-cccc",
        "PYSEC-2026-123",
    ]


def test_build_argv_includes_each_ignore_flag() -> None:
    command = pip_audit_wrapper.build_argv(["GHSA-aaaa-bbbb-cccc", "PYSEC-2026-123"])

    assert command == [
        "pip-audit",
        "--ignore-vuln",
        "GHSA-aaaa-bbbb-cccc",
        "--ignore-vuln",
        "PYSEC-2026-123",
    ]


def test_load_ignored_vulns_handles_only_comments(tmp_path: Path):
    p = tmp_path / "ignore.txt"
    p.write_text("# This is a comment\n# Another comment\n", encoding="utf-8")
    assert load_ignored_vulns(p) == []


def test_load_ignored_vulns_missing_file_returns_empty(tmp_path):
    assert pip_audit_wrapper.load_ignored_vulns(tmp_path / "missing.txt") == []


def test_build_argv_uses_configured_ignore_file(monkeypatch, tmp_path):
    ignore_file = tmp_path / "ignore.txt"
    ignore_file.write_text("GHSA-1111-2222-3333\n", encoding="utf-8")
    monkeypatch.setenv("PIP_AUDIT_IGNORE_FILE", str(ignore_file))

    assert pip_audit_wrapper.build_argv() == [
        "pip-audit",
        "--ignore-vuln",
        "GHSA-1111-2222-3333",
    ]


def test_main_returns_zero_when_audit_completes(monkeypatch):
    calls = []

    def fake_import_module(name):
        assert name == "pip_audit._cli"

        def audit():
            calls.append(sys.argv[:])

        return SimpleNamespace(audit=audit)

    original_argv = sys.argv[:]
    monkeypatch.setattr(pip_audit_wrapper.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(pip_audit_wrapper, "build_argv", lambda: ["pip-audit", "--dry-run"])

    assert pip_audit_wrapper.main() == 0
    assert calls == [["pip-audit", "--dry-run"]]
    assert sys.argv == original_argv


def test_main_converts_system_exit_code_to_return_code(monkeypatch):
    def fake_import_module(name):
        def audit():
            raise SystemExit(7)

        return SimpleNamespace(audit=audit)

    monkeypatch.setattr(pip_audit_wrapper.importlib, "import_module", fake_import_module)

    assert pip_audit_wrapper.main() == 7


def test_main_returns_one_for_non_integer_system_exit(monkeypatch):
    def fake_import_module(name):
        def audit():
            raise SystemExit("not an int")

        return SimpleNamespace(audit=audit)

    monkeypatch.setattr(pip_audit_wrapper.importlib, "import_module", fake_import_module)

    assert pip_audit_wrapper.main() == 1


@pytest.mark.parametrize(
    "exc",
    [requests.exceptions.RequestException("offline"), URLError("offline")],
)
def test_main_returns_one_for_network_failure_by_default(monkeypatch, exc):
    def fake_import_module(name):
        def audit():
            raise exc

        return SimpleNamespace(audit=audit)

    monkeypatch.delenv(pip_audit_wrapper.ALLOW_NETWORK_FAILURE_ENV, raising=False)
    monkeypatch.setattr(pip_audit_wrapper.importlib, "import_module", fake_import_module)

    assert pip_audit_wrapper.main() == 1


def test_main_can_allow_network_failure(monkeypatch):
    def fake_import_module(name):
        def audit():
            raise requests.exceptions.RequestException("offline")

        return SimpleNamespace(audit=audit)

    monkeypatch.setenv(pip_audit_wrapper.ALLOW_NETWORK_FAILURE_ENV, "1")
    monkeypatch.setattr(pip_audit_wrapper.importlib, "import_module", fake_import_module)

    assert pip_audit_wrapper.main() == 0


def test_load_ignored_vulns_empty_file_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "ignore.txt"
    f.write_text("", encoding="utf-8")
    assert load_ignored_vulns(f) == []


def test_load_ignored_vulns_single_id(tmp_path: Path) -> None:
    f = tmp_path / "ignore.txt"
    f.write_text("GHSA-1234-5678-abcd\n", encoding="utf-8")
    assert load_ignored_vulns(f) == ["GHSA-1234-5678-abcd"]


def test_load_ignored_vulns_multiple_ids(tmp_path: Path) -> None:
    f = tmp_path / "ignore.txt"
    f.write_text("GHSA-aaaa-bbbb-cccc\nGHSA-dddd-eeee-ffff\n", encoding="utf-8")
    assert load_ignored_vulns(f) == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]


def test_load_ignored_vulns_whitespace_only_lines_skipped(tmp_path: Path) -> None:
    f = tmp_path / "ignore.txt"
    f.write_text("   \nGHSA-abcd-efgh-ijkl\n   \n", encoding="utf-8")
    assert load_ignored_vulns(f) == ["GHSA-abcd-efgh-ijkl"]
