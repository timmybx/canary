"""Additional tests for canary.collectors.plugin_snapshot."""

from __future__ import annotations

from canary.collectors.plugin_snapshot import (
    _extract_historical_plugin_ids,
    collect_plugin_snapshot,
)

# ---------------------------------------------------------------------------
# _extract_historical_plugin_ids
# ---------------------------------------------------------------------------


def test_extract_historical_plugin_ids_previous_names_list():
    api = {"previousNames": ["old-name-1", "old-name-2"]}
    result = _extract_historical_plugin_ids(api)
    assert result == ["old-name-1", "old-name-2"]


def test_extract_historical_plugin_ids_previous_names_string():
    api = {"previousNames": "single-old-name"}
    result = _extract_historical_plugin_ids(api)
    assert result == ["single-old-name"]


def test_extract_historical_plugin_ids_aliases():
    api = {"aliases": ["alias-1", "alias-2"]}
    result = _extract_historical_plugin_ids(api)
    assert result == ["alias-1", "alias-2"]


def test_extract_historical_plugin_ids_deduplicates():
    api = {"previousNames": ["dup-name"], "aliases": ["dup-name", "other-name"]}
    result = _extract_historical_plugin_ids(api)
    assert result.count("dup-name") == 1


def test_extract_historical_plugin_ids_empty():
    assert _extract_historical_plugin_ids({}) == []


def test_extract_historical_plugin_ids_skips_empty_strings():
    api = {"previousNames": ["", "  ", "valid-name"]}
    result = _extract_historical_plugin_ids(api)
    assert result == ["valid-name"]


def test_extract_historical_plugin_ids_multiple_keys():
    api = {
        "previousNames": ["prev-1"],
        "formerNames": ["former-1"],
        "legacyNames": ["legacy-1"],
    }
    result = _extract_historical_plugin_ids(api)
    assert "prev-1" in result
    assert "former-1" in result
    assert "legacy-1" in result


# ---------------------------------------------------------------------------
# collect_plugin_snapshot — sample/offline mode
# ---------------------------------------------------------------------------


def test_collect_plugin_snapshot_sample_returns_dict():
    snap = collect_plugin_snapshot(plugin_id="cucumber-reports", real=False)
    assert isinstance(snap, dict)
    assert snap["plugin_id"] == "cucumber-reports"
    assert "collected_at" in snap
    assert "plugin_site_url" in snap


def test_collect_plugin_snapshot_sample_has_advisory_urls():
    snap = collect_plugin_snapshot(plugin_id="cucumber-reports", real=False)
    assert isinstance(snap["security_advisory_urls"], list)
    assert len(snap["security_advisory_urls"]) >= 1


def test_collect_plugin_snapshot_sample_plugin_api_is_none():
    snap = collect_plugin_snapshot(plugin_id="cucumber-reports", real=False)
    assert snap["plugin_api"] is None


def test_collect_plugin_snapshot_unknown_plugin_returns_dict():
    snap = collect_plugin_snapshot(plugin_id="totally-unknown-plugin-xyz", real=False)
    assert isinstance(snap, dict)
    assert snap["plugin_id"] == "totally-unknown-plugin-xyz"


def test_collect_plugin_snapshot_custom_repo_url():
    snap = collect_plugin_snapshot(
        plugin_id="cucumber-reports",
        repo_url="https://github.com/custom/repo",
        real=False,
    )
    assert snap["repo_url"] == "https://github.com/custom/repo"


# ---------------------------------------------------------------------------
# collect_plugin_snapshot — real=True with mocked API
# ---------------------------------------------------------------------------


def test_collect_plugin_snapshot_real_enriches_fields(monkeypatch):
    fixture = {
        "name": "cucumber-reports",
        "title": "Cucumber Reports",
        "excerpt": "Nice plugin",
        "labels": ["reporting"],
        "currentRelease": {"version": "5.0", "timestamp": 1700000000},
        "securityWarnings": [],
    }

    monkeypatch.setattr(
        "canary.collectors.plugin_snapshot._fetch_plugin_api_json",
        lambda pid, timeout_s=15.0: fixture,
    )
    # Avoid GitHub API calls
    monkeypatch.setattr(
        "canary.collectors.github_repo.parse_github_owner_repo",
        lambda url: None,
    )

    snap = collect_plugin_snapshot(plugin_id="cucumber-reports", real=True)

    assert snap["plugin_api"] is not None
    assert snap["plugin_title"] == "Cucumber Reports"
    assert snap["current_version"] == "5.0"
    assert snap["plugin_labels"] == ["reporting"]
    assert snap["github_repo"] is None


def test_collect_plugin_snapshot_real_with_github_signals(monkeypatch):
    fixture = {
        "name": "cucumber-reports",
        "title": "Cucumber Reports",
        "excerpt": "Reports plugin",
        "labels": [],
        "currentRelease": {"version": "3.0", "timestamp": 1700000000},
        "scm": "https://github.com/jenkinsci/cucumber-reports-plugin",
    }

    monkeypatch.setattr(
        "canary.collectors.plugin_snapshot._fetch_plugin_api_json",
        lambda pid, timeout_s=15.0: fixture,
    )

    # Mock GitHub data
    fake_repo = {
        "stargazers_count": 42,
        "forks_count": 10,
        "open_issues_count": 5,
        "pushed_at": "2024-01-01T00:00:00Z",
    }
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_repo",
        lambda owner, repo, timeout_s=15.0: fake_repo,
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_releases",
        lambda *a, **kw: [
            {
                "tag_name": "v3.0",
                "published_at": "2024-01-01T00:00:00Z",
                "prerelease": False,
                "draft": False,
                "name": "v3.0",
            }
        ],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_tags",
        lambda *a, **kw: [{"name": "v3.0"}, {"name": "v2.0"}],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_commits_since",
        lambda *a, **kw: [{"sha": "abc"}] * 5,
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_contributors",
        lambda *a, **kw: [{"login": "alice", "contributions": 100}],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_open_pulls",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_open_issues",
        lambda *a, **kw: [{"id": 1}, {"id": 2, "pull_request": {}}],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_workflows_dir",
        lambda *a, **kw: [{"name": "ci.yml"}],
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_codeowners",
        lambda *a, **kw: {"name": "CODEOWNERS"},
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_security_policy",
        lambda *a, **kw: {"name": "SECURITY.md"},
    )
    monkeypatch.setattr(
        "canary.collectors.github_repo.fetch_github_dependabot_config",
        lambda *a, **kw: {"name": "dependabot.yml"},
    )

    snap = collect_plugin_snapshot(
        plugin_id="cucumber-reports",
        repo_url="https://github.com/jenkinsci/cucumber-reports-plugin",
        real=True,
    )

    assert snap["github_stars"] == 42
    assert snap["github_forks"] == 10
    assert snap["github_release_count"] == 1
    assert snap["github_tag_count_sampled"] == 2
    assert snap["github_has_ci_workflows"] is True
    assert snap["github_open_prs"] == 0
    assert snap["github_open_issues_only"] == 1
    assert snap["github_top_contributor_share"] == 1.0
