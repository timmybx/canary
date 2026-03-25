from __future__ import annotations

from pathlib import Path

from canary.devtools import pip_audit_wrapper


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
