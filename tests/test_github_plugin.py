"""Tests for canary.collectors.github_plugin."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary.collectors.github_plugin import (
    _infer_repo_url,
    _scm_to_url,
    backfill_github_identities_from_indexes,
    collect_github_plugin_real,
)


# ---------------------------------------------------------------------------
# _scm_to_url
# ---------------------------------------------------------------------------


def test_scm_to_url_none():
    assert _scm_to_url(None) is None


def test_scm_to_url_plain_string():
    assert _scm_to_url("https://github.com/org/repo") == "https://github.com/org/repo"


def test_scm_to_url_blank_string():
    assert _scm_to_url("") is None
    assert _scm_to_url("  ") is None


def test_scm_to_url_dict_with_link():
    assert _scm_to_url({"link": "https://github.com/org/repo"}) == "https://github.com/org/repo"


def test_scm_to_url_dict_with_empty_link():
    assert _scm_to_url({"link": ""}) is None


def test_scm_to_url_dict_without_link():
    assert _scm_to_url({"other": "value"}) is None


def test_scm_to_url_unsupported_type():
    assert _scm_to_url(123) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _infer_repo_url
# ---------------------------------------------------------------------------


def test_infer_repo_url_from_explicit_repo_url():
    snap = {"repo_url": "https://github.com/org/repo"}
    assert _infer_repo_url(snap) == "https://github.com/org/repo"


def test_infer_repo_url_from_scm_url_string():
    snap = {"scm_url": "https://github.com/org/repo2"}
    assert _infer_repo_url(snap) == "https://github.com/org/repo2"


def test_infer_repo_url_from_scm_url_dict():
    snap = {"scm_url": {"link": "https://github.com/org/repo3"}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo3"


def test_infer_repo_url_from_scm_url_dict_url_key():
    snap = {"scm_url": {"url": "https://github.com/org/repo4"}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo4"


def test_infer_repo_url_from_plugin_api_scm_string():
    snap = {"plugin_api": {"scm": "https://github.com/org/repo5"}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo5"


def test_infer_repo_url_from_plugin_api_scm_dict():
    snap = {"plugin_api": {"scm": {"link": "https://github.com/org/repo6"}}}
    assert _infer_repo_url(snap) == "https://github.com/org/repo6"


def test_infer_repo_url_returns_none_for_empty_snap():
    assert _infer_repo_url({}) is None


def test_infer_repo_url_returns_none_for_null_fields():
    snap = {"repo_url": None, "scm_url": None, "plugin_api": None}
    assert _infer_repo_url(snap) is None


# ---------------------------------------------------------------------------
# backfill_github_identities_from_indexes
# ---------------------------------------------------------------------------


def _write_index(out_dir: Path, plugin_id: str, index: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{plugin_id}.github_index.json").write_text(
        json.dumps(index), encoding="utf-8"
    )


def test_backfill_creates_identity_json(tmp_path: Path):
    out_dir = tmp_path / "github"
    _write_index(
        out_dir,
        "my-plugin",
        {
            "plugin_id": "my-plugin",
            "repo_full_name": "org/my-plugin",
            "repo_url": "https://github.com/org/my-plugin",
            "collected_at": "2024-01-01T00:00:00+00:00",
        },
    )

    result = backfill_github_identities_from_indexes(out_dir=str(out_dir), overwrite=True)

    assert result["processed"] == 1
    assert result["written"] == 1
    identity_path = out_dir / "plugins" / "my-plugin" / "identity.json"
    assert identity_path.exists()
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    assert identity["github_owner"] == "org"
    assert identity["github_repo"] == "my-plugin"
    assert identity["plugin_id"] == "my-plugin"


def test_backfill_skips_when_identity_exists_no_overwrite(tmp_path: Path):
    out_dir = tmp_path / "github"
    _write_index(
        out_dir,
        "cached-plugin",
        {"repo_full_name": "org/cached-plugin"},
    )
    # Pre-create identity
    identity_path = out_dir / "plugins" / "cached-plugin" / "identity.json"
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text('{"exists": true}', encoding="utf-8")

    result = backfill_github_identities_from_indexes(out_dir=str(out_dir), overwrite=False)
    assert result["skipped"] == 1
    assert result["written"] == 0


def test_backfill_overwrites_when_flag_set(tmp_path: Path):
    out_dir = tmp_path / "github"
    _write_index(
        out_dir,
        "overwrite-plugin",
        {"repo_full_name": "org/overwrite-plugin"},
    )
    identity_path = out_dir / "plugins" / "overwrite-plugin" / "identity.json"
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    identity_path.write_text('{"exists": true}', encoding="utf-8")

    result = backfill_github_identities_from_indexes(out_dir=str(out_dir), overwrite=True)
    assert result["written"] == 1


def test_backfill_errors_on_missing_full_name(tmp_path: Path):
    out_dir = tmp_path / "github"
    _write_index(out_dir, "bad-plugin", {"plugin_id": "bad-plugin"})

    result = backfill_github_identities_from_indexes(out_dir=str(out_dir), overwrite=True)
    assert "bad-plugin" in result["errors"]


def test_backfill_empty_dir_returns_zero_counts(tmp_path: Path):
    out_dir = tmp_path / "github"
    out_dir.mkdir()
    result = backfill_github_identities_from_indexes(out_dir=str(out_dir))
    assert result["processed"] == 0
    assert result["written"] == 0


# ---------------------------------------------------------------------------
# collect_github_plugin_real
# ---------------------------------------------------------------------------


def _make_plugin_snapshot(data_dir: Path, plugin_id: str, snap: dict) -> None:
    plugins_dir = data_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / f"{plugin_id}.snapshot.json").write_text(
        json.dumps(snap), encoding="utf-8"
    )


def test_collect_github_plugin_raises_when_snapshot_missing(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        collect_github_plugin_real(
            plugin_id="no-such-plugin",
            data_dir=str(tmp_path),
        )


def test_collect_github_plugin_raises_when_no_repo_url(tmp_path: Path):
    _make_plugin_snapshot(
        tmp_path,
        "no-url-plugin",
        {"plugin_id": "no-url-plugin", "plugin_api": {}},
    )
    with pytest.raises(RuntimeError, match="No GitHub repo_url"):
        collect_github_plugin_real(
            plugin_id="no-url-plugin",
            data_dir=str(tmp_path),
        )


def test_collect_github_plugin_raises_when_non_github_url(tmp_path: Path):
    _make_plugin_snapshot(
        tmp_path,
        "gitlab-plugin",
        {"plugin_id": "gitlab-plugin", "repo_url": "https://gitlab.com/org/repo"},
    )
    with pytest.raises(RuntimeError, match="not a supported GitHub repo URL"):
        collect_github_plugin_real(
            plugin_id="gitlab-plugin",
            data_dir=str(tmp_path),
        )


def test_collect_github_plugin_fetches_and_writes(tmp_path: Path, monkeypatch):
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "github"
    _make_plugin_snapshot(
        data_dir,
        "good-plugin",
        {"plugin_id": "good-plugin", "repo_url": "https://github.com/org/good-plugin"},
    )

    def fake_fetch_repo(owner, repo, *, timeout_s=15.0):
        return {"full_name": f"{owner}/{repo}", "stargazers_count": 5}

    def fake_fetch_list(*args, **kwargs):
        return [{"id": 1}]

    monkeypatch.setattr("canary.collectors.github_plugin.fetch_github_repo", fake_fetch_repo)
    monkeypatch.setattr("canary.collectors.github_plugin.fetch_github_releases", fake_fetch_list)
    monkeypatch.setattr("canary.collectors.github_plugin.fetch_github_tags", fake_fetch_list)
    monkeypatch.setattr(
        "canary.collectors.github_plugin.fetch_github_contributors", fake_fetch_list
    )
    monkeypatch.setattr(
        "canary.collectors.github_plugin.fetch_github_open_issues", fake_fetch_list
    )
    monkeypatch.setattr(
        "canary.collectors.github_plugin.fetch_github_open_pulls", fake_fetch_list
    )
    monkeypatch.setattr(
        "canary.collectors.github_plugin.fetch_github_commits_since", fake_fetch_list
    )
    monkeypatch.setattr(
        "canary.collectors.github_plugin.fetch_github_workflows_dir",
        lambda *a, **kw: [{"name": "ci.yml"}],
    )

    result = collect_github_plugin_real(
        plugin_id="good-plugin",
        data_dir=str(data_dir),
        out_dir=str(out_dir),
        overwrite=True,
    )

    assert result["plugin_id"] == "good-plugin"
    assert result["repo_full_name"] == "org/good-plugin"
    assert "repo" in result["files"]
    assert "releases" in result["files"]
    assert not result["errors"]

    # Index file should be written
    index_path = out_dir / "good-plugin.github_index.json"
    assert index_path.exists()


def test_collect_github_plugin_skips_existing_files(tmp_path: Path, monkeypatch):
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "github"
    _make_plugin_snapshot(
        data_dir,
        "skip-plugin",
        {"plugin_id": "skip-plugin", "repo_url": "https://github.com/org/skip-plugin"},
    )

    # Pre-create all the output files
    out_dir.mkdir(parents=True)
    for name in [
        "repo", "releases", "tags", "contributors",
        "open_issues", "open_pulls", "commits_365d", "workflows_dir",
    ]:
        (out_dir / f"skip-plugin.{name}.json").write_text('{"cached": true}', encoding="utf-8")

    fetch_calls: list[str] = []

    def recording_fetch(*args, **kwargs):
        fetch_calls.append("called")
        return {}

    monkeypatch.setattr("canary.collectors.github_plugin.fetch_github_repo", recording_fetch)

    collect_github_plugin_real(
        plugin_id="skip-plugin",
        data_dir=str(data_dir),
        out_dir=str(out_dir),
        overwrite=False,
    )

    assert fetch_calls == [], "Should not call fetch when files exist and overwrite=False"
