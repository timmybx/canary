import pytest

from canary.collectors import jenkins_advisories as ja
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


def test_collect_advisories_real_uses_curated_urls_and_skips_invalid_warning_urls(monkeypatch):
    plugin_id = "demo"
    curated = "https://jenkins.io/security/advisory/2022-01-10/?x=1#frag"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [curated],
        "plugin_api": {
            "securityWarnings": [
                {"id": "SECURITY-111", "url": None, "active": True},
                {"id": "SECURITY-112", "url": "", "active": False},
            ]
        },
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)
    monkeypatch.setattr(
        ja,
        "_fetch_text",
        lambda url, timeout_s=15.0: "<html><title>Adv</title><body>SECURITY-111</body></html>",
    )

    records = collect_advisories_real(plugin_id, data_dir="data/raw")
    assert len(records) == 1
    rec = records[0]
    assert rec["url"] == "https://www.jenkins.io/security/advisory/2022-01-10/"
    assert rec["security_warning_ids"] == []


def test_collect_advisories_real_retries_on_runtime_error_then_succeeds(monkeypatch):
    plugin_id = "retry-plugin"
    advisory_url = "https://www.jenkins.io/security/advisory/2021-01-01/"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [{"id": "SECURITY-500", "url": advisory_url, "active": True}]
        },
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)
    monkeypatch.setattr(ja.time, "sleep", lambda _s: None)

    calls = {"n": 0}

    def _fetch(url, timeout_s=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError(
                "Fetch failed (network) for https://www.jenkins.io/security/advisory/2021-01-01/"
            )
        return (
            "<html><title>Retry OK</title>"
            "<body>SECURITY-500 "
            "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            "</body></html>"
        )

    monkeypatch.setattr(ja, "_fetch_text", _fetch)

    records = collect_advisories_real(plugin_id, data_dir="data/raw")
    assert calls["n"] == 2
    assert len(records) == 1
    assert records[0]["title"] == "Retry OK"


def test_collect_advisories_real_skips_404_without_retry(monkeypatch):
    plugin_id = "dead-link"
    advisory_url = "https://www.jenkins.io/security/advisory/2020-01-01/"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [{"id": "SECURITY-404", "url": advisory_url, "active": False}]
        },
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)

    def _sleep_should_not_run(_s: float):
        raise AssertionError("sleep not expected")

    monkeypatch.setattr(
        ja.time,
        "sleep",
        _sleep_should_not_run,
    )

    def _fetch(url, timeout_s=15.0):
        raise RuntimeError(
            "Fetch failed (404) for https://www.jenkins.io/security/advisory/2020-01-01/"
        )

    monkeypatch.setattr(ja, "_fetch_text", _fetch)
    assert collect_advisories_real(plugin_id, data_dir="data/raw") == []


def test_collect_advisories_real_retries_on_generic_exception(monkeypatch):
    plugin_id = "generic-retry"
    advisory_url = "https://www.jenkins.io/security/advisory/2019-01-01/"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {"securityWarnings": [{"id": "", "url": advisory_url, "active": False}]},
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)
    monkeypatch.setattr(ja.time, "sleep", lambda _s: None)

    calls = {"n": 0}

    def _fetch(url, timeout_s=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("temporary parse issue")
        return "<html><title>Done</title><body>SECURITY-900</body></html>"

    monkeypatch.setattr(ja, "_fetch_text", _fetch)
    records = collect_advisories_real(plugin_id, data_dir="data/raw")
    assert calls["n"] == 2
    assert records[0]["security_warning_ids"] == []


def test_collect_advisories_real_derives_severity_from_cvss(monkeypatch):
    plugin_id = "cvss-derived"
    advisory_url = "https://www.jenkins.io/security/advisory/2018-01-01/"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [
                {"id": "SECURITY-700", "url": advisory_url, "active": True},
                {"id": "SECURITY-701", "url": advisory_url, "active": True},
                {"id": None, "url": advisory_url, "active": True},
            ]
        },
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)
    monkeypatch.setattr(
        ja,
        "_fetch_text",
        lambda url, timeout_s=15.0: (
            "<html><title>Derived severity</title><body>"
            "SECURITY-700 "
            "https://www.first.org/cvss/calculator/3.1#"
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N "
            "SECURITY-701 "
            "https://www.first.org/cvss/calculator/3.1#not-cvss"
            "</body></html>"
        ),
    )

    records = collect_advisories_real(plugin_id, data_dir="data/raw")
    rec = records[0]
    vulns = {v["security_warning_id"]: v for v in rec["vulnerabilities"]}
    assert vulns["SECURITY-700"]["severity_label"] == "medium"
    assert vulns["SECURITY-700"]["severity_source"] == "cvss_v3_derived"
    assert vulns["SECURITY-701"]["severity_label"] is None
    assert rec["severity_summary"]["max_severity_label"] == "medium"


def test_collect_advisories_real_retry_failure_bubbles(monkeypatch):
    plugin_id = "retry-fails"
    advisory_url = "https://www.jenkins.io/security/advisory/2017-01-01/"
    fake_snapshot = {
        "plugin_id": plugin_id,
        "security_advisory_urls": [],
        "plugin_api": {
            "securityWarnings": [{"id": "SECURITY-999", "url": advisory_url, "active": True}]
        },
    }
    monkeypatch.setattr(ja, "_load_plugin_snapshot", lambda pid, data_dir: fake_snapshot)
    monkeypatch.setattr(ja.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        ja,
        "_fetch_text",
        _always_runtime_error_fetch,
    )

    with pytest.raises(RuntimeError, match="Fetch failed"):
        collect_advisories_real(plugin_id, data_dir="data/raw")


def _always_runtime_error_fetch(url: str, timeout_s: float = 15.0) -> str:
    raise RuntimeError("Fetch failed (network) for x")
