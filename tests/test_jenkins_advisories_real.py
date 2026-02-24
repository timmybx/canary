from canary.collectors.jenkins_advisories import _canonicalize_jenkins_url, collect_advisories_real


def test_canonicalize_jenkins_url_invalid_ipv6_does_not_crash():
    assert _canonicalize_jenkins_url("//[\n") is None


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
    # Include a severity line + a FIRST CVSS calculator link so we can parse both.
    fake_html = (
        "<html><head><title>Jenkins Security Advisory 2016-07-27</title></head>"
        "<body>"
        "<h2>Severity</h2><p>SECURITY-309 is considered medium.</p>"
        "<h3 id='SECURITY-309'>SECURITY-309</h3>"
        "<a href='https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N'>CVSS</a>"
        "</body></html>"
    )
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

    # New: severity/CVSS enrichment
    assert rec["vulnerabilities"][0]["security_warning_id"] == "SECURITY-309"
    assert rec["vulnerabilities"][0]["severity_label"] == "medium"
    assert rec["vulnerabilities"][0]["cvss"]["version"] == "3.0"
    assert (
        rec["vulnerabilities"][0]["cvss"]["vector"]
        == "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
    )
    assert rec["vulnerabilities"][0]["cvss"]["base_score"] == 4.4
    assert rec["severity_summary"]["max_severity_label"] == "medium"
    assert rec["severity_summary"]["max_cvss_base_score"] == 4.4


def test_collect_advisories_real_normalizes_fragment_urls_and_derives_ids(monkeypatch):
    plugin_id = "testlink"
    advisory_url = "https://www.jenkins.io/security/advisory/2018-02-26/#SECURITY-731"

    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [
                {"id": "SECURITY-731", "url": advisory_url, "active": True},
            ]
        },
    }

    monkeypatch.setattr(
        "canary.collectors.jenkins_advisories._load_plugin_snapshot",
        lambda pid, data_dir: fake_snapshot,
    )

    fake_html = (
        "<html><head><title>Jenkins Security Advisory 2018-02-26</title></head>"
        "<body><h2>Severity</h2><p>SECURITY-731 is considered medium.</p></body></html>"
    )
    monkeypatch.setattr(
        "canary.collectors.jenkins_advisories._fetch_text",
        lambda url, timeout_s=15.0: fake_html,
    )

    records = collect_advisories_real(plugin_id, data_dir="data/raw")
    assert len(records) == 1
    rec = records[0]

    # URL stored without fragment, but url_fragment is preserved per vulnerability
    assert rec["url"] == "https://www.jenkins.io/security/advisory/2018-02-26/"
    assert rec["advisory_id"] == "2018-02-26"
    assert rec["published_date"] == "2018-02-26"
    assert rec["vulnerabilities"][0]["url_fragment"].endswith("#SECURITY-731")
