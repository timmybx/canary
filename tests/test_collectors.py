from canary.collectors.jenkins_advisories import collect_advisories_sample


def test_collector_returns_records():
    records = collect_advisories_sample()
    assert len(records) >= 1
    assert "plugin_id" in records[0]
    assert "advisory_id" in records[0]
