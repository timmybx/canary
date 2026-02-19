# tests/test_plugin_snapshot.py
import json
from pathlib import Path

from canary.collectors.plugin_snapshot import collect_plugin_snapshot


def test_collect_plugin_snapshot_real_uses_api_fixture(monkeypatch):
    fixture_path = (
        Path(__file__).resolve().parent / "fixtures" / "plugins_api_cucumber-reports.json"
    )

    # Helpful failure message if the fixture wasn't added/committed yet
    assert fixture_path.exists(), (
        f"Missing fixture: {fixture_path}\n"
        "Create it by saving a real plugins API response JSON to that path.\n"
        "Tip: you can copy the 'plugin_api' object from data/raw/plugins/"
        "cucumber-reports.snapshot.json into this fixture file."
    )

    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))

    def fake_fetch(plugin_id: str, timeout_s: float = 15.0):
        assert plugin_id == "cucumber-reports"
        return fixture

    monkeypatch.setattr("canary.collectors.plugin_snapshot._fetch_plugin_api_json", fake_fetch)

    # Avoid any real GitHub network calls during this unit test.
    # The snapshot collector opportunistically enriches GitHub signals when
    # repo_url points at github.com, which can be rate-limited in CI.
    monkeypatch.setattr(
        "canary.collectors.github_repo.parse_github_owner_repo",
        lambda _url: None,
    )

    snap = collect_plugin_snapshot(plugin_id="cucumber-reports", real=True)

    assert snap["plugin_id"] == "cucumber-reports"
    assert snap["plugin_api"] is not None
    assert "current_version" in snap
