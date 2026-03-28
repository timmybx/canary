"""Additional tests for canary.collectors.plugins_registry."""

from __future__ import annotations

import pytest

from canary.collectors.plugins_registry import (
    _extract_plugin_id,
    _plugin_to_registry_record,
    collect_plugins_registry_real,
    collect_plugins_registry_sample,
)

# ---------------------------------------------------------------------------
# _extract_plugin_id
# ---------------------------------------------------------------------------


def test_extract_plugin_id_from_name():
    assert _extract_plugin_id({"name": "cucumber-reports"}) == "cucumber-reports"


def test_extract_plugin_id_from_pluginId():
    assert _extract_plugin_id({"pluginId": "workflow-cps"}) == "workflow-cps"


def test_extract_plugin_id_from_id():
    assert _extract_plugin_id({"id": "some-id"}) == "some-id"


def test_extract_plugin_id_from_artifactId():
    assert _extract_plugin_id({"artifactId": "artifact"}) == "artifact"


def test_extract_plugin_id_returns_none_when_missing():
    assert _extract_plugin_id({}) is None


def test_extract_plugin_id_skips_empty_strings():
    assert _extract_plugin_id({"name": "  ", "id": "real-id"}) == "real-id"


# ---------------------------------------------------------------------------
# _plugin_to_registry_record
# ---------------------------------------------------------------------------


def test_plugin_to_registry_record_basic():
    obj = {"name": "cucumber-reports", "title": "Cucumber Reports"}
    rec = _plugin_to_registry_record(obj)
    assert rec is not None
    assert rec["plugin_id"] == "cucumber-reports"
    assert rec["plugin_site_url"] == "https://plugins.jenkins.io/cucumber-reports/"
    assert rec["plugin_api_url"] == "https://plugins.jenkins.io/api/plugin/cucumber-reports"
    assert rec["plugin_title"] == "Cucumber Reports"


def test_plugin_to_registry_record_returns_none_without_id():
    assert _plugin_to_registry_record({}) is None
    assert _plugin_to_registry_record({"title": "No ID"}) is None


def test_plugin_to_registry_record_optional_fields():
    obj = {
        "name": "test-plugin",
        "excerpt": "A test plugin",
        "labels": ["testing"],
        "previousNames": ["old-test"],
        "aliases": ["t-plugin"],
    }
    rec = _plugin_to_registry_record(obj)
    assert rec is not None
    assert rec["plugin_excerpt"] == "A test plugin"
    assert rec["plugin_labels"] == ["testing"]
    assert rec["historical_plugin_ids"] == ["old-test"]
    assert rec["aliases"] == ["t-plugin"]


def test_plugin_to_registry_record_previous_names_key():
    obj = {"name": "test-plugin", "previous_names": ["old-name"]}
    rec = _plugin_to_registry_record(obj)
    assert rec is not None
    assert rec["historical_plugin_ids"] == ["old-name"]


# ---------------------------------------------------------------------------
# collect_plugins_registry_sample
# ---------------------------------------------------------------------------


def test_collect_plugins_registry_sample_returns_list():
    result = collect_plugins_registry_sample()
    assert isinstance(result, list)
    assert len(result) >= 2
    assert all("plugin_id" in r for r in result)
    assert all("plugin_site_url" in r for r in result)
    assert all("plugin_api_url" in r for r in result)


# ---------------------------------------------------------------------------
# collect_plugins_registry_real — mocked HTTP
# ---------------------------------------------------------------------------


def _make_fake_fetch(pages: list):
    """Return a fake _fetch_json that cycles through canned page responses."""
    call_count = {"n": 0}

    def fake_fetch(url: str, *, timeout_s: float = 30.0):
        idx = call_count["n"]
        call_count["n"] += 1
        if idx >= len(pages):
            raise RuntimeError("Unexpected extra page fetch")
        return pages[idx]

    return fake_fetch


def test_collect_plugins_registry_real_single_page(monkeypatch):
    page = {
        "plugins": [
            {"name": "cucumber-reports", "title": "Cucumber Reports"},
            {"name": "workflow-cps", "title": "Workflow CPS"},
        ],
        "total": 2,
    }
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch([page]),
    )

    registry, raw_pages = collect_plugins_registry_real(page_size=100)
    assert len(registry) == 2
    assert registry[0]["plugin_id"] == "cucumber-reports"
    assert len(raw_pages) == 1


def test_collect_plugins_registry_real_follows_next_link(monkeypatch):
    page1 = {
        "plugins": [{"name": "plugin-a"}],
        "next": "https://plugins.jenkins.io/api/plugins?limit=1&offset=999",
    }
    # Page 2 returns fewer results than page_size so offset loop terminates
    page2 = {
        "plugins": [],
    }
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch([page1, page2]),
    )

    registry, raw_pages = collect_plugins_registry_real(page_size=1)
    assert len(registry) == 1
    assert registry[0]["plugin_id"] == "plugin-a"
    assert len(raw_pages) == 2


def test_collect_plugins_registry_real_list_payload(monkeypatch):
    """Registry can also return a raw list."""
    payload = [
        {"name": "list-plugin-a"},
        {"name": "list-plugin-b"},
    ]
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch([payload]),
    )

    registry, raw_pages = collect_plugins_registry_real(page_size=100)
    assert len(registry) == 2


def test_collect_plugins_registry_real_max_plugins(monkeypatch):
    page = {
        "plugins": [{"name": f"plugin-{i}"} for i in range(10)],
        "total": 100,
    }
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch([page]),
    )

    registry, _ = collect_plugins_registry_real(page_size=100, max_plugins=3)
    assert len(registry) == 3


def test_collect_plugins_registry_real_invalid_page_size():
    with pytest.raises(ValueError, match="page_size"):
        collect_plugins_registry_real(page_size=0)

    with pytest.raises(ValueError, match="page_size"):
        collect_plugins_registry_real(page_size=6000)


def test_collect_plugins_registry_real_raises_on_unexpected_shape(monkeypatch):
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch(["unexpected_string"]),
    )

    with pytest.raises(RuntimeError, match="Unexpected registry payload shape"):
        collect_plugins_registry_real(page_size=100)


def test_collect_plugins_registry_real_repeated_url_raises(monkeypatch):
    """If pagination returns the same next URL twice, we should bail out."""
    # Page 1 returns a `next` link that points back to a URL that will be seen again.
    # We simulate this by always returning the same page with a next link.
    call_count = {"n": 0}

    def infinite_next(url: str, *, timeout_s: float = 30.0):
        call_count["n"] += 1
        return {
            "plugins": [{"name": "plugin-a"}],
            "next": "https://plugins.jenkins.io/api/plugins?limit=1&offset=1",
        }

    monkeypatch.setattr("canary.collectors.plugins_registry._fetch_json", infinite_next)

    with pytest.raises(RuntimeError, match="did not advance"):
        collect_plugins_registry_real(page_size=1)


def test_collect_plugins_registry_real_skips_non_dict_plugins(monkeypatch):
    page = {
        "plugins": [
            {"name": "good-plugin"},
            "not-a-dict",
            42,
            None,
        ],
        "total": 4,
    }
    monkeypatch.setattr(
        "canary.collectors.plugins_registry._fetch_json",
        _make_fake_fetch([page]),
    )

    registry, _ = collect_plugins_registry_real(page_size=100)
    assert len(registry) == 1
    assert registry[0]["plugin_id"] == "good-plugin"
