from __future__ import annotations

import json
from pathlib import Path

from canary.build.features_bundle import build_feature_bundle


def test_build_feature_bundle_loads_software_heritage_features(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    github_dir = data_raw / "github"
    swh_dir = data_raw / "software_heritage"
    health_dir = data_raw / "healthscore" / "plugins"

    for p in [registry_dir, plugins_dir, github_dir, swh_dir, health_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo"}) + "\n",
        encoding="utf-8",
    )

    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "repo_url": "https://github.com/jenkinsci/demo-plugin",
                "plugin_api": {"maintainers": [], "dependencies": []},
            }
        ),
        encoding="utf-8",
    )

    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-22T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 75},
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_index.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "origin_found": True,
                "snapshot_found": True,
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_visits.json").write_text(
        json.dumps(
            {
                "results": [
                    {"date": "2025-03-10T12:00:00+00:00"},
                    {"date": "2025-06-15T12:00:00+00:00"},
                ]
            }
        ),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_latest_visit.json").write_text(
        json.dumps({"visit": {"status": "full", "type": "git"}}),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_snapshot.json").write_text(
        json.dumps({"branches": {"refs/heads/main": {}, "refs/heads/dev": {}}}),
        encoding="utf-8",
    )

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
    )

    row = rows[0]
    assert row["swh_present"] is True
    assert row["swh_origin_found"] is True
    assert row["swh_has_snapshot"] is True
    assert row["swh_visit_count"] == 2
    assert row["swh_first_visit_date"] == "2025-03-10"
    assert row["swh_latest_visit_date"] == "2025-06-15"
    assert row["swh_latest_visit_status"] == "full"
    assert row["swh_latest_visit_type"] == "git"
    assert row["swh_snapshot_branch_count"] == 2


def test_build_feature_bundle_writes_joined_outputs(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"
    gharchive_dir = data_raw / "gharchive" / "plugins"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir, gharchive_dir]:
        p.mkdir(parents=True, exist_ok=True)

    registry_path = registry_dir / "plugins.jsonl"
    registry_path.write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "plugin_site_url": "https://plugins.jenkins.io/demo-plugin/",
                "plugin_api_url": "https://plugins.jenkins.io/api/plugin/demo-plugin/",
                "title": "Demo Plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    snapshot = {
        "plugin_id": "demo-plugin",
        "collected_at": "2026-03-15T00:00:00+00:00",
        "current_version": "1.2.3",
        "repo_url": "https://github.com/jenkinsci/demo-plugin",
        "plugin_api": {
            "requiredCore": "2.479.3",
            "labels": ["report"],
            "categories": ["buildManagement"],
            "maintainers": [{"id": "alice"}, {"id": "bob"}],
            "dependencies": [{"name": "structs"}, {"name": "workflow-step-api"}],
            "securityWarnings": [{"id": "SECURITY-1", "active": True}],
            "releaseTimestamp": "2026-01-13T07:44:00.00Z",
            "stats": {"installations": [{"timestamp": 1, "total": 1234}]},
        },
    }
    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8"
    )

    advisories = [
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "demo-plugin",
            "advisory_id": "2026-01-01",
            "published_date": "2026-01-01",
            "title": "Demo issue",
            "url": "https://www.jenkins.io/security/advisory/2026-01-01/",
            "severity_summary": {"max_cvss_base_score": 7.5},
            "cve_ids": ["CVE-2026-0001"],
        }
    ]
    with (advisories_dir / "demo-plugin.advisories.real.jsonl").open("w", encoding="utf-8") as f:
        for rec in advisories:
            f.write(json.dumps(rec) + "\n")

    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 88},
            }
        ),
        encoding="utf-8",
    )

    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "repo_full_name": "jenkinsci/demo-plugin",
                "repo_url": "https://github.com/jenkinsci/demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.repo.json").write_text(
        json.dumps(
            {
                "stargazers_count": 42,
                "forks_count": 5,
                "watchers_count": 42,
                "open_issues_count": 3,
                "subscribers_count": 4,
                "archived": False,
                "default_branch": "main",
                "license": {"spdx_id": "MIT"},
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.releases.json").write_text(
        json.dumps([{"published_at": "2026-01-13T07:44:00.00Z"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.tags.json").write_text(
        json.dumps([{"name": "v1.2.3"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.contributors.json").write_text(
        json.dumps([{"login": "alice", "contributions": 8}, {"login": "bob", "contributions": 2}]),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.open_issues.json").write_text(
        json.dumps([{"id": 1}, {"id": 2}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.open_pulls.json").write_text(
        json.dumps([{"id": 3}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.workflows_dir.json").write_text(
        json.dumps([{"name": "ci.yml"}]), encoding="utf-8"
    )
    (github_dir / "demo-plugin.commits_365d.json").write_text(
        json.dumps([{"sha": "a"}, {"sha": "b"}]), encoding="utf-8"
    )

    with (gharchive_dir / "demo-plugin.gharchive.jsonl").open("w", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "plugin_id": "demo-plugin",
                    "window_start_yyyymmdd": "20250101",
                    "window_end_yyyymmdd": "20250130",
                    "sample_percent": 1.0,
                    "events_total": 10,
                    "actors_unique": 3,
                    "pushes": 4,
                    "committers_unique": 2,
                    "push_days_active": 2,
                    "prs_opened": 1,
                    "prs_closed": 1,
                    "prs_merged": 1,
                    "prs_closed_unmerged": 0,
                    "pr_reviewed_ratio": 1.0,
                    "pr_merge_time_p50_hours": 12,
                    "pr_close_without_merge_ratio": 0.0,
                    "issues_opened": 1,
                    "issues_closed": 1,
                    "issues_reopened": 0,
                    "issue_reopen_rate": 0.0,
                    "issue_close_time_p50_hours": 24,
                    "releases": 1,
                    "days_since_last_release": 60,
                    "hotfix_proxy": 0.0,
                    "security_label_proxy": 1,
                    "churn_intensity": 1.67,
                    "owner_concentration": 0.75,
                }
            )
            + "\n"
        )

    out_path = tmp_path / "data" / "processed" / "features" / "plugins.features.jsonl"
    out_csv = tmp_path / "data" / "processed" / "features" / "plugins.features.csv"
    summary_path = tmp_path / "data" / "processed" / "features" / "plugins.features.summary.json"

    rows = build_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_path,
        out_path=out_path,
        out_csv_path=out_csv,
        summary_path=summary_path,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row["plugin_id"] == "demo-plugin"
    assert row["snapshot_present"] is True
    assert row["snapshot_dependencies_count"] == 2
    assert row["advisory_count"] == 1
    assert row["advisory_max_cvss"] == 7.5
    assert row["healthscore_value"] == 88.0
    assert row["github_present"] is True
    assert row["github_stargazers_count"] == 42
    assert row["gharchive_present"] is True
    assert row["gharchive_events_total_sum"] == 10.0
    assert row["gharchive_latest_window_end"] == "20250130"

    assert out_path.exists()
    assert out_csv.exists()
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["plugins_total"] == 1
    assert summary["plugins_with_gharchive"] == 1
