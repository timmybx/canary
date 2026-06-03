from __future__ import annotations

import json
from pathlib import Path

from canary.build.monthly_features import _load_software_heritage_monthly_features


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_athena_swh_monthly_features_recompute_commit_age_and_copy_snapshot_metrics(
    tmp_path: Path,
) -> None:
    """Athena SWH rows should be converted into leakage-safe month-level features."""
    swh_dir = tmp_path / "software_heritage_athena"
    swh_dir.mkdir(parents=True)

    for plugin_id in ["alpha-plugin", "beta-plugin"]:
        (swh_dir / f"{plugin_id}.swh_athena_index.json").write_text(
            json.dumps({"backend": "athena", "record_count": 1}),
            encoding="utf-8",
        )

    _write_jsonl(
        swh_dir / "alpha-plugin.swh_athena_visits.jsonl",
        [
            {
                "date": "2025-05-10",
                "visit_date": "2025-05-10",
                "has_readme": True,
                "has_security_md": False,
                "has_tests_directory": True,
                "top_level_entry_count": 12,
                "commit_count": 7,
                "timezone_diversity": 3,
                "security_fix_commit_count": 2,
                "days_since_last_commit": 2,
                "author_committer_lag_p50_hours": "1.5",
                "weekend_commit_fraction": 0.25,
                "merge_commit_fraction": "0.5",
            }
        ],
    )
    _write_jsonl(
        swh_dir / "beta-plugin.swh_athena_visits.jsonl",
        [
            {
                "date": "2025-05-12",
                "visit_date": "not-a-date",
                "has_readme": False,
                "commit_count": None,
                "days_since_last_commit": "not-a-number",
                "author_committer_lag_p50_hours": None,
            }
        ],
    )

    rows = _load_software_heritage_monthly_features(
        tmp_path,
        ["alpha-plugin", "beta-plugin"],
        [
            {
                "month": "2025-05",
                "window_start": "2025-05-01",
                "window_end": "2025-05-31",
            }
        ],
        backend="athena",
    )

    alpha = rows[("alpha-plugin", "2025-05")]
    assert alpha["swh_present_any"] is True
    assert alpha["swh_origin_found"] is True
    assert alpha["swh_has_snapshot_to_date"] is True
    assert alpha["swh_visit_count_to_date"] == 1
    assert alpha["swh_latest_visit_date_to_date"] == "2025-05-10"
    assert alpha["swh_has_readme"] is True
    assert alpha["swh_has_security_md"] is False
    assert alpha["swh_has_tests_directory"] is True
    assert alpha["swh_top_level_entry_count"] == 12
    assert alpha["swh_commit_count"] == 7
    assert alpha["swh_timezone_diversity"] == 3
    assert alpha["swh_security_fix_commit_count"] == 2
    # The stored visit said the last commit was 2 days before 2025-05-10,
    # so relative to the 2025-05 observation boundary it is 23 days old.
    assert alpha["swh_days_since_last_commit"] == 23.0
    assert alpha["swh_author_committer_lag_p50_hours"] == 1.5
    assert alpha["swh_weekend_commit_fraction"] == 0.25
    assert alpha["swh_merge_commit_fraction"] == 0.5

    beta = rows[("beta-plugin", "2025-05")]
    assert beta["swh_has_readme"] is False
    assert beta["swh_commit_count"] == 0
    assert beta["swh_days_since_last_commit"] is None
    assert beta["swh_author_committer_lag_p50_hours"] is None
