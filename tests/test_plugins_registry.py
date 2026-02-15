from canary.collectors.plugins_registry import (
    collect_plugins_registry_real,
    collect_plugins_registry_sample,
)


def test_registry_sample_shape():
    records = collect_plugins_registry_sample()
    assert isinstance(records, list)
    assert len(records) >= 1

    rec = records[0]
    assert "plugin_id" in rec
    assert rec["plugin_id"].strip()
    assert rec["plugin_site_url"].startswith("https://plugins.jenkins.io/")
    assert rec["plugin_api_url"].startswith("https://plugins.jenkins.io/api/plugin/")
    assert "collected_at" in rec


def test_registry_real_paginates_and_is_resilient_to_payload_shape(monkeypatch):
    # Fake 2 pages using the common {plugins: [...], total: N} shape.
    pages = [
        {
            "plugins": [
                {"name": "a", "title": "A"},
                {"name": "b", "title": "B"},
            ],
            "total": 3,
        },
        {
            "plugins": [
                {"name": "c", "title": "C"},
            ],
            "total": 3,
        },
    ]
    calls = {"n": 0}

    def fake_fetch(url: str, timeout_s: float = 30.0):
        i = calls["n"]
        calls["n"] += 1
        return pages[i]

    monkeypatch.setattr("canary.collectors.plugins_registry._fetch_json", fake_fetch)

    registry, raw_pages = collect_plugins_registry_real(page_size=2)

    assert len(raw_pages) == 2
    assert [r["plugin_id"] for r in registry] == ["a", "b", "c"]
