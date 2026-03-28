"""Additional edge-case tests for canary.build.advisories_events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.build.advisories_events import build_advisories_events


def _write_jsonl(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# build_advisories_events edge cases
# ---------------------------------------------------------------------------


def test_build_advisories_events_raises_when_dir_missing(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="Advisories directory"):
        build_advisories_events(
            data_raw_dir=tmp_path / "nonexistent",
            out_path=tmp_path / "out.jsonl",
        )


def test_build_advisories_events_empty_dir(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    advisories_dir.mkdir()
    out_path = tmp_path / "out.jsonl"

    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)

    assert records == []
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == ""


def test_build_advisories_events_skips_blank_lines(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "test-plugin",
        "advisory_id": "2025-01-01",
        "published_date": "2025-01-01",
        "title": "Test Advisory",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
    }
    _write_jsonl(
        advisories_dir / "test.jsonl",
        ["", json.dumps(rec), "  ", json.dumps(rec)],
    )

    out_path = tmp_path / "out.jsonl"
    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)

    # Deduplication: two identical records should merge to one
    assert len(records) == 1


def test_build_advisories_events_skips_malformed_json(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    good_rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "good-plugin",
        "advisory_id": "2025-02-01",
        "published_date": "2025-02-01",
        "title": "Good Advisory",
        "url": "https://www.jenkins.io/security/advisory/2025-02-01/",
    }
    _write_jsonl(
        advisories_dir / "mixed.jsonl",
        [
            json.dumps(good_rec),
            "this is not json {{",
            json.dumps(good_rec),
        ],
    )

    out_path = tmp_path / "out.jsonl"
    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)

    # Malformed lines skipped, good record deduplicated to 1
    assert len(records) == 1


def test_build_advisories_events_skips_non_jenkins_records(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    non_jenkins = {
        "source": "other",
        "type": "advisory",
        "plugin_id": "some-plugin",
        "advisory_id": "2025-01-01",
    }
    wrong_type = {
        "source": "jenkins",
        "type": "security_warning",
        "plugin_id": "some-plugin",
        "advisory_id": "2025-01-02",
    }
    _write_jsonl(
        advisories_dir / "other.jsonl",
        [json.dumps(non_jenkins), json.dumps(wrong_type)],
    )

    out_path = tmp_path / "out.jsonl"
    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)
    assert records == []


def test_build_advisories_events_creates_parent_dirs(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    advisories_dir.mkdir()
    out_path = tmp_path / "deep" / "nested" / "dir" / "out.jsonl"

    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)

    assert out_path.exists()


def test_build_advisories_events_sorted_output(tmp_path: Path):
    advisories_dir = tmp_path / "advisories"
    recs = [
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "z-plugin",
            "advisory_id": "2025-01-01",
            "published_date": "2025-01-01",
            "title": "Z Advisory",
            "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        },
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "a-plugin",
            "advisory_id": "2025-01-01",
            "published_date": "2025-01-01",
            "title": "A Advisory",
            "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        },
    ]
    _write_jsonl(advisories_dir / "test.jsonl", [json.dumps(r) for r in recs])

    out_path = tmp_path / "out.jsonl"
    records = build_advisories_events(data_raw_dir=tmp_path, out_path=out_path)

    # Output should be sorted by (published_date, plugin_id)
    assert records[0]["plugin_id"] == "a-plugin"
    assert records[1]["plugin_id"] == "z-plugin"
