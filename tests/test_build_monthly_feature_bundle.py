from __future__ import annotations

import json
from pathlib import Path

from canary.build.monthly_features import build_monthly_feature_bundle


def test_build_monthly_feature_bundle_swh_to_date_is_leakage_safe(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    github_dir = data_raw / "github"
    health_dir = data_raw / "healthscore" / "plugins"
    swh_dir = data_raw / "software_heritage"

    for p in [registry_dir, plugins_dir, github_dir, health_dir, swh_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo"}) + "\n",
        encoding="utf-8",
    )

    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps({"plugin_api": {"maintainers": [], "dependencies": []}}),
        encoding="utf-8",
    )

    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 80},
            }
        ),
        encoding="utf-8",
    )

    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps({"plugin_id": "demo-plugin", "repo_full_name": "jenkinsci/demo-plugin"}),
        encoding="utf-8",
    )

    (swh_dir / "demo-plugin.swh_index.json").write_text(
        json.dumps({"plugin_id": "demo-plugin", "origin_found": True, "snapshot_found": True}),
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

    rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        start_month="2025-03",
        end_month="2025-06",
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
    )

    april = next(r for r in rows if r["month"] == "2025-04")
    june = next(r for r in rows if r["month"] == "2025-06")

    assert april["swh_visit_count_to_date"] == 1
    assert april["swh_visits_this_month"] == 0
    assert april["swh_latest_visit_date_to_date"] == "2025-03-10"

    assert june["swh_visit_count_to_date"] == 2
    assert june["swh_visits_this_month"] == 1
    assert june["swh_latest_visit_date_to_date"] == "2025-06-15"


def test_build_monthly_feature_bundle_dense_grid(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"
    gharchive_dir = data_raw / "gharchive" / "normalized-events"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir, gharchive_dir]:
        p.mkdir(parents=True, exist_ok=True)

    registry_rows = [
        {
            "plugin_id": "alpha-plugin",
            "plugin_site_url": "https://plugins.jenkins.io/alpha-plugin/",
            "plugin_api_url": "https://plugins.jenkins.io/api/plugin/alpha-plugin/",
            "title": "Alpha Plugin",
            "collected_at": "2026-03-15T00:00:00+00:00",
        },
        {
            "plugin_id": "beta-plugin",
            "plugin_site_url": "https://plugins.jenkins.io/beta-plugin/",
            "plugin_api_url": "https://plugins.jenkins.io/api/plugin/beta-plugin/",
            "title": "Beta Plugin",
            "collected_at": "2026-03-15T00:00:00+00:00",
        },
    ]
    (registry_dir / "plugins.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in registry_rows), encoding="utf-8"
    )

    for plugin_id in ["alpha-plugin", "beta-plugin"]:
        (plugins_dir / f"{plugin_id}.snapshot.json").write_text(
            json.dumps(
                {
                    "plugin_id": plugin_id,
                    "collected_at": "2026-03-15T00:00:00+00:00",
                    "current_version": "1.0",
                    "plugin_api": {
                        "requiredCore": "2.479.3",
                        "maintainers": [{"id": "alice"}],
                        "dependencies": [{"name": "structs"}],
                        "labels": ["misc"],
                        "categories": ["buildManagement"],
                        "securityWarnings": [],
                        "stats": {"installations": [{"timestamp": 1, "total": 10}]},
                    },
                }
            ),
            encoding="utf-8",
        )
        (health_dir / f"{plugin_id}.healthscore.json").write_text(
            json.dumps(
                {
                    "plugin_id": plugin_id,
                    "collected_at": "2026-03-15T00:00:00+00:00",
                    "record": {"plugin_id": plugin_id, "value": 77},
                }
            ),
            encoding="utf-8",
        )
        (github_dir / f"{plugin_id}.github_index.json").write_text(
            json.dumps(
                {
                    "plugin_id": plugin_id,
                    "repo_full_name": f"jenkinsci/{plugin_id}",
                    "repo_url": f"https://github.com/jenkinsci/{plugin_id}",
                    "collected_at": "2026-03-15T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        (github_dir / f"{plugin_id}.repo.json").write_text(
            json.dumps({"stargazers_count": 1, "forks_count": 1, "watchers_count": 1}),
            encoding="utf-8",
        )

    (gharchive_dir / "2025-01.gharchive.events.jsonl").write_text(
        "".join(
            json.dumps(rec) + "\n"
            for rec in [
                {
                    "plugin_id": "alpha-plugin",
                    "event_yyyymm": "2025-01",
                    "event_date": "2025-01-03",
                    "event_type": "PushEvent",
                    "actor_login": "alice",
                    "sample_percent": 1.0,
                    "source_window_start_yyyymmdd": "20250101",
                    "source_window_end_yyyymmdd": "20250131",
                },
                {
                    "plugin_id": "alpha-plugin",
                    "event_yyyymm": "2025-01",
                    "event_date": "2025-01-03",
                    "event_type": "PushEvent",
                    "actor_login": "bob",
                    "sample_percent": 1.0,
                    "source_window_start_yyyymmdd": "20250101",
                    "source_window_end_yyyymmdd": "20250131",
                },
                {
                    "plugin_id": "alpha-plugin",
                    "event_yyyymm": "2025-01",
                    "event_date": "2025-01-10",
                    "event_type": "PullRequestEvent",
                    "action": "opened",
                    "actor_login": "alice",
                    "sample_percent": 1.0,
                    "source_window_start_yyyymmdd": "20250101",
                    "source_window_end_yyyymmdd": "20250131",
                },
                {
                    "plugin_id": "alpha-plugin",
                    "event_yyyymm": "2025-01",
                    "event_date": "2025-01-20",
                    "event_type": "IssuesEvent",
                    "action": "opened",
                    "actor_login": "carol",
                    "sample_percent": 1.0,
                    "source_window_start_yyyymmdd": "20250101",
                    "source_window_end_yyyymmdd": "20250131",
                },
                {
                    "plugin_id": "alpha-plugin",
                    "event_yyyymm": "2025-01",
                    "event_date": "2025-01-21",
                    "event_type": "ReleaseEvent",
                    "actor_login": "carol",
                    "sample_percent": 1.0,
                    "source_window_start_yyyymmdd": "20250101",
                    "source_window_end_yyyymmdd": "20250131",
                },
            ]
        ),
        encoding="utf-8",
    )

    out_path = tmp_path / "data" / "processed" / "features" / "plugins.monthly.features.jsonl"
    out_csv = tmp_path / "data" / "processed" / "features" / "plugins.monthly.features.csv"
    summary_path = (
        tmp_path / "data" / "processed" / "features" / "plugins.monthly.features.summary.json"
    )

    rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        start_month="2025-01",
        end_month="2025-03",
        out_path=out_path,
        out_csv_path=out_csv,
        summary_path=summary_path,
    )

    assert len(rows) == 6
    alpha_jan = next(
        r for r in rows if r["plugin_id"] == "alpha-plugin" and r["month"] == "2025-01"
    )
    beta_feb = next(r for r in rows if r["plugin_id"] == "beta-plugin" and r["month"] == "2025-02")

    assert alpha_jan["gharchive_present"] is True
    assert alpha_jan["gharchive_events_total"] == 5
    assert alpha_jan["gharchive_push_events"] == 2
    assert "healthscore_value" not in alpha_jan
    assert "github_present" not in alpha_jan
    assert "snapshot_present" not in alpha_jan

    assert beta_feb["gharchive_present"] is False
    assert beta_feb["gharchive_events_total"] == 0
    assert "healthscore_present" not in beta_feb

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["plugins_total"] == 2
    assert summary["months_total"] == 3
    assert summary["rows_total"] == 6
    assert out_path.exists()
    assert out_csv.exists()


def test_build_monthly_feature_bundle_advisory_to_date_is_leakage_safe(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    registry_dir = data_raw / "registry"
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    health_dir = data_raw / "healthscore" / "plugins"
    github_dir = data_raw / "github"

    for p in [registry_dir, plugins_dir, advisories_dir, health_dir, github_dir]:
        p.mkdir(parents=True, exist_ok=True)

    (registry_dir / "plugins.jsonl").write_text(
        json.dumps({"plugin_id": "demo-plugin", "title": "Demo"}) + "\n",
        encoding="utf-8",
    )
    (plugins_dir / "demo-plugin.snapshot.json").write_text(
        json.dumps({"plugin_api": {"maintainers": [], "dependencies": []}}), encoding="utf-8"
    )
    (health_dir / "demo-plugin.healthscore.json").write_text(
        json.dumps(
            {
                "plugin_id": "demo-plugin",
                "collected_at": "2026-03-15T00:00:00+00:00",
                "record": {"plugin_id": "demo-plugin", "value": 80},
            }
        ),
        encoding="utf-8",
    )
    (github_dir / "demo-plugin.github_index.json").write_text(
        json.dumps({"plugin_id": "demo-plugin", "repo_full_name": "jenkinsci/demo-plugin"}),
        encoding="utf-8",
    )

    advisories = [
        {
            "plugin_id": "demo-plugin",
            "published_date": "2025-03-10",
            "severity_summary": {"max_cvss_base_score": 5.0},
            "cve_ids": ["CVE-2025-0001"],
        },
        {
            "plugin_id": "demo-plugin",
            "published_date": "2025-06-15",
            "severity_summary": {"max_cvss_base_score": 8.0},
            "cve_ids": ["CVE-2025-0002"],
        },
    ]
    with (advisories_dir / "demo-plugin.advisories.real.jsonl").open("w", encoding="utf-8") as f:
        for rec in advisories:
            f.write(json.dumps(rec) + "\n")

    rows = build_monthly_feature_bundle(
        data_raw_dir=data_raw,
        registry_path=registry_dir / "plugins.jsonl",
        start_month="2025-03",
        end_month="2025-06",
        out_path=tmp_path / "out.jsonl",
        out_csv_path=None,
        summary_path=None,
    )

    april = next(r for r in rows if r["month"] == "2025-04")
    june = next(r for r in rows if r["month"] == "2025-06")

    assert april["advisory_count_to_date"] == 1
    assert april["advisory_count_this_month"] == 0
    assert april["advisory_cve_count_to_date"] == 1
    assert april["advisory_max_cvss_to_date"] == 5.0
    assert april["had_advisory_this_month"] is False

    assert june["advisory_count_to_date"] == 2
    assert june["advisory_count_this_month"] == 1
    assert june["advisory_cve_count_to_date"] == 2
    assert june["advisory_max_cvss_to_date"] == 8.0
    assert june["had_advisory_this_month"] is True
