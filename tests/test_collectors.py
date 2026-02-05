from datetime import date

from canary.collectors.jenkins_advisories import collect_advisories_sample

REQUIRED_KEYS = {
    "source",
    "type",
    "advisory_id",
    "published_date",
    "plugin_id",
    "title",
    "url",
}


def test_collector_returns_records():
    records = collect_advisories_sample()
    assert isinstance(records, list)
    assert len(records) >= 1
    assert isinstance(records[0], dict)


def test_collector_record_shape_and_types():
    rec = collect_advisories_sample()[0]

    missing = REQUIRED_KEYS - rec.keys()
    assert not missing, f"Missing keys: {missing}"

    assert rec["source"] == "jenkins"
    assert rec["type"] == "advisory"

    assert isinstance(rec["plugin_id"], str) and rec["plugin_id"].strip()
    assert isinstance(rec["advisory_id"], str) and rec["advisory_id"].strip()
    assert isinstance(rec["title"], str) and rec["title"].strip()
    assert isinstance(rec["url"], str) and rec["url"].startswith("http")

    # published_date should be ISO YYYY-MM-DD
    assert isinstance(rec["published_date"], str)
    date.fromisoformat(rec["published_date"])  # raises ValueError if invalid


def test_collector_optional_fields_are_sane_if_present():
    rec = collect_advisories_sample()[0]

    # Optional fields you may include as you expand
    if "cve_ids" in rec:
        assert isinstance(rec["cve_ids"], list)
        assert all(isinstance(x, str) for x in rec["cve_ids"])

    if "cwe_ids" in rec:
        assert isinstance(rec["cwe_ids"], list)
        assert all(isinstance(x, str) for x in rec["cwe_ids"])

    if "cvss" in rec and rec["cvss"] is not None:
        assert isinstance(rec["cvss"], (int, float))
        assert 0.0 <= float(rec["cvss"]) <= 10.0
