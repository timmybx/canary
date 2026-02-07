from canary.collectors.jenkins_advisories import collect_advisories_real


def test_collect_advisories_real_uses_snapshot_and_parses_advisory(monkeypatch):
    plugin_id = "cucumber-reports"
    advisory_url = "https://www.jenkins.io/security/advisory/2016-07-27/"

    # 1) Fake snapshot: what collect_advisories_real reads from disk
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [
                {"id": "SECURITY-309", "url": advisory_url, "active": False},
            ]
        },
    }

    monkeypatch.setattr(
        "canary.collectors.jenkins_advisories._load_plugin_snapshot",
        lambda pid, data_dir: fake_snapshot,
    )

    # 2) Fake HTML fetch: no network
    fake_html = "<html><head><title>Jenkins Security Advisory 2016-07-27</title></head></html>"
    monkeypatch.setattr(
        "canary.collectors.jenkins_advisories._fetch_text",
        lambda url, timeout_s=15.0: fake_html,
    )

    records = collect_advisories_real(plugin_id, data_dir="data/raw")

    assert len(records) == 1
    rec = records[0]

    assert rec["plugin_id"] == plugin_id
    assert rec["url"] == advisory_url
    assert rec["advisory_id"] == "2016-07-27"
    assert rec["published_date"] == "2016-07-27"
    assert rec["title"] == "Jenkins Security Advisory 2016-07-27"
    assert rec["security_warning_ids"] == ["SECURITY-309"]
    assert rec["active_security_warning"] is False
