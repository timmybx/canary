"""Additional tests for canary.devtools.pip_audit_wrapper."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from canary.devtools.pip_audit_wrapper import build_argv, load_ignored_vulns, main

# ---------------------------------------------------------------------------
# load_ignored_vulns
# ---------------------------------------------------------------------------


def test_load_ignored_vulns_returns_empty_for_missing_file(tmp_path: Path):
    result = load_ignored_vulns(tmp_path / "nonexistent.txt")
    assert result == []


def test_load_ignored_vulns_handles_only_comments(tmp_path: Path):
    p = tmp_path / "ignore.txt"
    p.write_text("# This is a comment\n# Another comment\n", encoding="utf-8")
    assert load_ignored_vulns(p) == []


def test_load_ignored_vulns_inline_comment_stripped(tmp_path: Path):
    p = tmp_path / "ignore.txt"
    p.write_text("GHSA-0000-0000-0000  # reason here\n", encoding="utf-8")
    result = load_ignored_vulns(p)
    assert result == ["GHSA-0000-0000-0000"]


def test_load_ignored_vulns_multiple_entries(tmp_path: Path):
    p = tmp_path / "ignore.txt"
    p.write_text(
        "GHSA-aaaa-bbbb-cccc\nGHSA-dddd-eeee-ffff\n",
        encoding="utf-8",
    )
    result = load_ignored_vulns(p)
    assert result == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]


# ---------------------------------------------------------------------------
# build_argv
# ---------------------------------------------------------------------------


def test_build_argv_empty_list():
    # Passing None uses load_ignored_vulns(); passing an explicit list uses it directly.
    # An empty list is falsy so it falls back to load_ignored_vulns(); use None check.
    result = build_argv(["ONLY-THIS"])
    assert result == ["pip-audit", "--ignore-vuln", "ONLY-THIS"]


def test_build_argv_multiple_ids():
    result = build_argv(["GHSA-1111-2222-3333", "PYSEC-2025-001"])
    assert result == [
        "pip-audit",
        "--ignore-vuln", "GHSA-1111-2222-3333",
        "--ignore-vuln", "PYSEC-2025-001",
    ]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_returns_0_on_success():
    mock_audit = MagicMock()
    mock_cli = MagicMock()
    mock_cli.audit = mock_audit

    with patch.dict("sys.modules", {"pip_audit._cli": mock_cli}):
        with patch(
            "canary.devtools.pip_audit_wrapper.load_ignored_vulns",
            return_value=[],
        ):
            result = main()

    assert result == 0
    mock_audit.assert_called_once()


def test_main_restores_argv_after_run():
    original_argv = sys.argv[:]
    mock_cli = MagicMock()
    mock_cli.audit = MagicMock()

    with patch.dict("sys.modules", {"pip_audit._cli": mock_cli}):
        with patch(
            "canary.devtools.pip_audit_wrapper.load_ignored_vulns",
            return_value=[],
        ):
            main()

    assert sys.argv == original_argv


def test_main_returns_1_on_system_exit_with_non_int_code():
    mock_cli = MagicMock()
    mock_cli.audit = MagicMock(side_effect=SystemExit("error"))

    with patch.dict("sys.modules", {"pip_audit._cli": mock_cli}):
        with patch(
            "canary.devtools.pip_audit_wrapper.load_ignored_vulns",
            return_value=[],
        ):
            result = main()

    assert result == 1


def test_main_returns_exit_code_from_system_exit():
    mock_cli = MagicMock()
    mock_cli.audit = MagicMock(side_effect=SystemExit(2))

    with patch.dict("sys.modules", {"pip_audit._cli": mock_cli}):
        with patch(
            "canary.devtools.pip_audit_wrapper.load_ignored_vulns",
            return_value=[],
        ):
            result = main()

    assert result == 2
