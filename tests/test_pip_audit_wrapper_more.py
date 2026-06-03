"""Extra low-hanging tests for canary.devtools.pip_audit_wrapper."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from urllib.error import URLError

import pytest
import requests

from canary.devtools import pip_audit_wrapper


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
