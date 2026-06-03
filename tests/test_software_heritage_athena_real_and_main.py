"""Additional focused tests for Software Heritage Athena collector entry points.

These cover the repo-to-plugin wrapper and CLI main() without making network/AWS calls.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest  # pyright: ignore[reportMissingImports]

import canary.collectors.software_heritage_athena as swh_athena


def _write_snapshot(data_dir: Path, plugin_id: str, payload: dict) -> Path:
    snap_dir = data_dir / "plugins"
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_path = snap_dir / f"{plugin_id}.snapshot.json"
    snap_path.write_text(json.dumps(payload), encoding="utf-8")
    return snap_path


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_collect_real_raises_when_snapshot_has_no_repo_url(tmp_path: Path):
    data_dir = tmp_path / "raw"
    _write_snapshot(data_dir, "missing-repo", {"name": "missing-repo"})

    with pytest.raises(RuntimeError, match="No repo_url/scm_url found"):
        swh_athena.collect_software_heritage_athena_real(
            plugin_id="missing-repo",
            data_dir=str(data_dir),
            out_dir=tmp_path / "swh",
            verbose=False,
        )


def test_collect_real_writes_index_and_visit_records(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "raw"
    out_dir = tmp_path / "swh"
    _write_snapshot(
        data_dir,
        "demo-plugin",
        {"repo_url": "https://github.com/example/demo-plugin"},
    )

    fetched_records = [
        {
            "source": "software_heritage_athena",
            "repo_url": "https://github.com/example/demo-plugin",
            "visit": 1,
            "visit_date": "2024-01-01",
            "snapshot_id": "snap-001",
        }
    ]

    def fake_collect_repo(**kwargs):
        assert kwargs["repo_url"] == "https://github.com/example/demo-plugin"
        assert kwargs["database"] == "swh"
        assert kwargs["max_visits"] == 7
        assert kwargs["directory_batch_size"] == 3
        assert kwargs["max_directories"] == 11
        return fetched_records

    monkeypatch.setattr(swh_athena, "collect_software_heritage_athena_repo", fake_collect_repo)
    monkeypatch.setattr(swh_athena, "_utc_now_iso", lambda: "2026-01-02T03:04:05+00:00")

    result = swh_athena.collect_software_heritage_athena_real(
        plugin_id="demo-plugin",
        data_dir=str(data_dir),
        out_dir=out_dir,
        overwrite=True,
        database="swh",
        output_location="s3://bucket/staging/",
        max_visits=7,
        directory_batch_size=3,
        max_directories=11,
        verbose=False,
    )

    visits_path = out_dir / "demo-plugin.swh_athena_visits.jsonl"
    index_path = out_dir / "demo-plugin.swh_athena_index.json"

    assert result["plugin_id"] == "demo-plugin"
    assert result["repo_url"] == "https://github.com/example/demo-plugin"
    assert result["written"] == 1
    assert result["record_count"] == 1
    assert Path(result["files"]["visits"]) == visits_path
    assert Path(result["files"]["index"]) == index_path

    assert _read_jsonl(visits_path) == fetched_records
    index_payload = json.loads(index_path.read_text(encoding="utf-8"))
    assert index_payload == {
        "plugin_id": "demo-plugin",
        "repo_url": "https://github.com/example/demo-plugin",
        "backend": "athena",
        "database": "swh",
        "collected_at": "2026-01-02T03:04:05+00:00",
        "record_count": 1,
        "files": {"visits": str(visits_path)},
    }


def test_collect_real_merges_existing_records_when_not_overwriting(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "raw"
    out_dir = tmp_path / "swh"
    out_dir.mkdir()
    _write_snapshot(
        data_dir,
        "demo-plugin",
        {"plugin_api": {"scm": {"link": "https://github.com/example/demo-plugin"}}},
    )

    visits_path = out_dir / "demo-plugin.swh_athena_visits.jsonl"
    swh_athena.write_jsonl(
        [
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 1,
                "visit_date": "2024-01-01",
                "snapshot_id": "snap-existing",
                "has_readme": False,
            }
        ],
        visits_path,
    )

    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo",
        lambda **_: [
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 1,
                "visit_date": "2024-01-01",
                "snapshot_id": "snap-existing",
                "has_readme": True,
            },
            {
                "source": "software_heritage_athena",
                "repo_url": "https://github.com/example/demo-plugin",
                "visit": 2,
                "visit_date": "2024-02-01",
                "snapshot_id": "snap-new",
            },
        ],
    )

    result = swh_athena.collect_software_heritage_athena_real(
        plugin_id="demo-plugin",
        data_dir=str(data_dir),
        out_dir=out_dir,
        overwrite=False,
        verbose=False,
    )

    merged = _read_jsonl(visits_path)
    assert result["record_count"] == 2
    assert result["fetched_record_count"] == 2
    assert [row["visit"] for row in merged] == [1, 2]
    # New fetched record replaces the existing duplicate visit key during merge.
    assert merged[0]["has_readme"] is True


def test_main_returns_zero_and_prints_output_path(monkeypatch, capsys, tmp_path: Path):
    expected_path = tmp_path / "repo.software_heritage.jsonl"

    def fake_to_file(**kwargs):
        assert kwargs["repo_url"] == "https://github.com/example/repo"
        assert kwargs["database"] == "swh"
        assert kwargs["out_dir"] == str(tmp_path)
        assert kwargs["poll_initial_seconds"] == 0.25
        assert kwargs["poll_max_seconds"] == 2.5
        assert kwargs["max_visits"] == 4
        assert kwargs["directory_batch_size"] == 5
        assert kwargs["max_directories"] == 6
        assert kwargs["verbose"] is False
        return expected_path

    monkeypatch.setattr(swh_athena, "collect_software_heritage_athena_repo_to_file", fake_to_file)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "software_heritage_athena",
            "--repo-url",
            "https://github.com/example/repo",
            "--database",
            "swh",
            "--out-dir",
            str(tmp_path),
            "--poll-initial-seconds",
            "0.25",
            "--poll-max-seconds",
            "2.5",
            "--max-visits",
            "4",
            "--directory-batch-size",
            "5",
            "--max-directories",
            "6",
            "--quiet",
        ],
    )

    assert swh_athena.main() == 0
    captured = capsys.readouterr()
    assert f"Wrote Software Heritage Athena records to {expected_path}" in captured.out


@pytest.mark.parametrize("exc", [ValueError("bad repo"), RuntimeError("athena failed")])
def test_main_returns_one_for_expected_errors(monkeypatch, capsys, exc):
    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo_to_file",
        lambda **_: (_ for _ in ()).throw(exc),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["software_heritage_athena", "--repo-url", "https://github.com/example/repo"],
    )

    assert swh_athena.main() == 1
    captured = capsys.readouterr()
    assert f"[ERROR] {exc}" in captured.out


def test_main_returns_one_for_unexpected_errors(monkeypatch, capsys):
    monkeypatch.setattr(
        swh_athena,
        "collect_software_heritage_athena_repo_to_file",
        lambda **_: (_ for _ in ()).throw(Exception("surprise")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["software_heritage_athena", "--repo-url", "https://github.com/example/repo"],
    )

    assert swh_athena.main() == 1
    captured = capsys.readouterr()
    assert "[ERROR] surprise" in captured.out
