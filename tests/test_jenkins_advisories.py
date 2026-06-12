"""
Behavior tests for canary.collectors.jenkins_advisories.

Contract helpers (CVSS v3 scoring, severity bucketing, URL canonicalization,
advisory merging) are tested directly on purpose: they implement fiddly
numeric/parsing contracts that downstream features depend on.  The
collect_advisories_real tests exercise the full collector with the network
boundary (_fetch_text) and snapshot loading mocked — no live calls.

Consolidates test_jenkins_advisories_helpers.py and
test_jenkins_advisories_real.py.
"""

from __future__ import annotations

import urllib.error
from email.message import Message

import pytest

from canary.collectors import jenkins_advisories as ja
from canary.collectors.jenkins_advisories import (
    _allowlisted_url,
    _canonicalize_jenkins_url,
    _cvss3_base_score,
    _cvss_base_score_to_severity_label,
    _date_from_advisory_url,
    _extract_cvss_by_security_id,
    _extract_security_sections,
    _extract_severity_labels,
    _extract_title,
    _fetch_text,
    _load_plugin_snapshot,
    _max_severity_label,
    _normalize_advisory_url,
    _parse_cvss_vector_from_url,
    _strip_query_fragment,
    collect_advisories_real,
    collect_advisories_sample,
    merge_advisory_records,
)


def test_cvss_severity_none_score():
    assert _cvss_base_score_to_severity_label(None) is None


def test_cvss_severity_zero():
    assert _cvss_base_score_to_severity_label(0.0) == "none"


def test_cvss_severity_boundary_none_low():
    # boundary: 0.0 is "none", 0.1 is "low"
    assert _cvss_base_score_to_severity_label(0.1) == "low"


def test_cvss_severity_low():
    assert _cvss_base_score_to_severity_label(2.5) == "low"


def test_cvss_severity_boundary_low_medium():
    assert _cvss_base_score_to_severity_label(3.9) == "low"
    assert _cvss_base_score_to_severity_label(4.0) == "medium"


def test_cvss_severity_medium():
    assert _cvss_base_score_to_severity_label(6.5) == "medium"


def test_cvss_severity_boundary_medium_high():
    assert _cvss_base_score_to_severity_label(6.9) == "medium"
    assert _cvss_base_score_to_severity_label(7.0) == "high"


def test_cvss_severity_high():
    assert _cvss_base_score_to_severity_label(8.0) == "high"


def test_cvss_severity_boundary_high_critical():
    assert _cvss_base_score_to_severity_label(8.9) == "high"
    assert _cvss_base_score_to_severity_label(9.0) == "critical"


def test_cvss_severity_critical():
    assert _cvss_base_score_to_severity_label(10.0) == "critical"


def test_cvss_severity_invalid_string():
    assert _cvss_base_score_to_severity_label("not-a-number") is None  # type: ignore[arg-type]


def test_cvss_severity_coerces_string_float():
    # "7.5" should coerce to 7.5 -> "high"
    assert _cvss_base_score_to_severity_label("7.5") == "high"  # type: ignore[arg-type]


def test_allowlisted_url_valid_jenkins():
    # Should not raise
    _allowlisted_url("https://www.jenkins.io/security/advisory/2025-01-01/")
    _allowlisted_url("https://jenkins.io/security/advisory/2025-01-01/")


def test_allowlisted_url_rejects_http():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("http://www.jenkins.io/security/advisory/2025-01-01/")


def test_allowlisted_url_rejects_unknown_domain():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("https://evil.com/security/advisory/2025-01-01/")


def test_allowlisted_url_rejects_file_scheme():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("file:///etc/passwd")


def test_canonicalize_jenkins_url_normalizes_http_to_https():
    result = _canonicalize_jenkins_url("http://www.jenkins.io/security/advisory/2025-01-01/")
    assert result is not None
    assert result.startswith("https://")


def test_canonicalize_jenkins_url_normalizes_jenkins_io_to_www():
    from urllib.parse import urlparse

    result = _canonicalize_jenkins_url("https://jenkins.io/security/advisory/2025-01-01/")
    assert result is not None
    assert urlparse(result).netloc == "www.jenkins.io"


def test_canonicalize_jenkins_url_keeps_www_unchanged():
    url = "https://www.jenkins.io/security/advisory/2025-01-01/"
    result = _canonicalize_jenkins_url(url)
    assert result == url


def test_canonicalize_jenkins_url_empty_string():
    result = _canonicalize_jenkins_url("")
    assert result == "" or result is None


def test_canonicalize_jenkins_url_none_returns_none():
    assert _canonicalize_jenkins_url(None) is None  # type: ignore[arg-type]


def test_canonicalize_jenkins_url_preserves_path():
    result = _canonicalize_jenkins_url("https://www.jenkins.io/path/to/advisory")
    assert result is not None
    assert "/path/to/advisory" in result


def test_strip_query_fragment_removes_query():
    url = "https://www.jenkins.io/security/advisory/2025-01-01/?foo=bar"
    result = _strip_query_fragment(url)
    assert "?" not in result
    assert "foo" not in result


def test_strip_query_fragment_removes_fragment():
    url = "https://www.jenkins.io/security/advisory/2025-01-01/#SECURITY-123"
    result = _strip_query_fragment(url)
    assert "#" not in result
    assert "SECURITY-123" not in result


def test_strip_query_fragment_keeps_path():
    url = "https://www.jenkins.io/security/advisory/2025-01-01/"
    result = _strip_query_fragment(url)
    assert result == url


def test_strip_query_fragment_handles_malformed():
    # Should not crash
    url = "not a url"
    result = _strip_query_fragment(url)
    assert isinstance(result, str)


def test_strip_query_fragment_returns_original_when_urlparse_raises(monkeypatch):
    def _raise_value_error(_url: str):
        raise ValueError("bad")

    monkeypatch.setattr(ja, "urlparse", _raise_value_error)
    url = "https://www.jenkins.io/security/advisory/2025-01-01/?x=1#frag"
    assert _strip_query_fragment(url) == url


def test_normalize_advisory_url_removes_query_and_fragment():
    url = "http://jenkins.io/security/advisory/2025-01-01/?q=1#SECURITY-1"
    result = _normalize_advisory_url(url)
    assert "?" not in result
    assert "#" not in result
    assert result.startswith("https://")


def test_extract_title_basic():
    html = "<html><head><title>Jenkins Security Advisory 2025-01-01</title></head></html>"
    assert _extract_title(html) == "Jenkins Security Advisory 2025-01-01"


def test_extract_title_case_insensitive():
    html = "<html><TITLE>My Title</TITLE></html>"
    assert _extract_title(html) == "My Title"


def test_extract_title_multiline():
    html = "<html><title>\n  Security Advisory\n  2025-01\n</title></html>"
    result = _extract_title(html)
    assert result is not None
    assert "Security Advisory" in result
    # Should collapse whitespace
    assert "\n" not in result


def test_extract_title_missing():
    html = "<html><body>No title here</body></html>"
    assert _extract_title(html) is None


def test_extract_title_empty():
    assert _extract_title("") is None


def test_date_from_advisory_url_valid():
    from datetime import date

    url = "https://www.jenkins.io/security/advisory/2025-01-15/"
    result = _date_from_advisory_url(url)
    assert result == date(2025, 1, 15)


def test_date_from_advisory_url_without_trailing_slash():
    from datetime import date

    url = "https://www.jenkins.io/security/advisory/2025-03-20"
    result = _date_from_advisory_url(url)
    assert result == date(2025, 3, 20)


def test_date_from_advisory_url_invalid():
    url = "https://www.jenkins.io/security/advisory/"
    assert _date_from_advisory_url(url) is None


def test_date_from_advisory_url_no_date_in_path():
    url = "https://www.jenkins.io/security/2025/"
    assert _date_from_advisory_url(url) is None


def test_date_from_advisory_url_invalid_date():
    # Not a real date
    url = "https://www.jenkins.io/security/advisory/2025-13-45/"
    assert _date_from_advisory_url(url) is None


def test_date_from_advisory_url_strips_query_fragment():
    from datetime import date

    url = "https://www.jenkins.io/security/advisory/2025-06-15/?foo=bar#SECURITY-1"
    result = _date_from_advisory_url(url)
    assert result == date(2025, 6, 15)


def test_extract_severity_labels_basic():
    html = "SECURITY-123 is considered high severity"
    result = _extract_severity_labels(html)
    assert result.get("SECURITY-123") == "high"


def test_extract_severity_labels_case_insensitive():
    html = "security-456 is considered MEDIUM severity"
    result = _extract_severity_labels(html)
    assert "SECURITY-456" in result
    assert result["SECURITY-456"] == "medium"


def test_extract_severity_labels_multiple():
    html = (
        "SECURITY-100 is considered low. "
        "SECURITY-200 is considered critical. "
        "SECURITY-300 is considered medium."
    )
    result = _extract_severity_labels(html)
    assert result["SECURITY-100"] == "low"
    assert result["SECURITY-200"] == "critical"
    assert result["SECURITY-300"] == "medium"


def test_extract_severity_labels_no_matches():
    html = "<html>No severity labels here</html>"
    assert _extract_severity_labels(html) == {}


def test_extract_severity_labels_all_severity_levels():
    html = (
        "SECURITY-1 is considered low. "
        "SECURITY-2 is considered medium. "
        "SECURITY-3 is considered high. "
        "SECURITY-4 is considered critical."
    )
    result = _extract_severity_labels(html)
    assert result["SECURITY-1"] == "low"
    assert result["SECURITY-2"] == "medium"
    assert result["SECURITY-3"] == "high"
    assert result["SECURITY-4"] == "critical"


def test_extract_security_sections_basic():
    html = "intro SECURITY-123 some text SECURITY-456 more text"
    sections = _extract_security_sections(html)
    assert "SECURITY-123" in sections
    assert "SECURITY-456" in sections


def test_extract_security_sections_no_sections():
    html = "No security warnings here"
    assert _extract_security_sections(html) == {}


def test_extract_security_sections_single():
    html = "prefix SECURITY-999 content at end"
    sections = _extract_security_sections(html)
    assert "SECURITY-999" in sections
    assert "SECURITY-999" in sections["SECURITY-999"]


def test_parse_cvss_vector_from_url_valid_cvss3():
    url = "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    version, vector = _parse_cvss_vector_from_url(url)
    assert version == "3.1"
    assert vector is not None
    assert vector.startswith("CVSS:3.1")


def test_parse_cvss_vector_from_url_no_fragment():
    url = "https://www.first.org/cvss/calculator/3.1"
    version, vector = _parse_cvss_vector_from_url(url)
    assert version is None
    assert vector is None


def test_parse_cvss_vector_from_url_non_cvss_fragment():
    url = "https://www.first.org/cvss/calculator/3.1#not-cvss"
    version, vector = _parse_cvss_vector_from_url(url)
    assert version is None
    assert vector is None


def test_parse_cvss_vector_from_url_empty():
    version, vector = _parse_cvss_vector_from_url("")
    assert version is None
    assert vector is None


def test_parse_cvss_vector_from_url_value_error(monkeypatch):
    def _raise_value_error(_url: str):
        raise ValueError("bad parse")

    monkeypatch.setattr(ja, "urlparse", _raise_value_error)
    version, vector = _parse_cvss_vector_from_url("https://www.first.org/cvss/calculator/3.1#x")
    assert version is None
    assert vector is None


def test_cvss3_base_score_high_score():
    # Critical: AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:H, A:H
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = _cvss3_base_score(vector)
    assert score is not None
    assert score == 9.8


def test_cvss3_base_score_low_score():
    # Low: AV:P, AC:H, PR:H, UI:R, S:U, C:L, I:N, A:N
    vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    score = _cvss3_base_score(vector)
    assert score is not None
    assert 0 < score < 3.0


def test_cvss3_base_score_non_cvss3_returns_none():
    vector = "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"
    assert _cvss3_base_score(vector) is None


def test_cvss3_base_score_changed_scope():
    # Changed scope (S:C) uses different formula; result should be Critical (>=9.0)
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score = _cvss3_base_score(vector)
    assert score is not None
    assert score >= 9.0


def test_cvss3_base_score_missing_metric():
    # Missing required metric key
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"
    # Missing A metric
    score = _cvss3_base_score(vector)
    assert score is None


def test_cvss3_base_score_no_impact():
    # If all CIA are N (None), impact = 0, score = 0.0
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    score = _cvss3_base_score(vector)
    assert score == 0.0


def test_cvss3_base_score_ignores_parts_without_colon():
    vector = "CVSS:3.1/AV:N/BAD/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = _cvss3_base_score(vector)
    assert score == 9.8


def test_cvss3_base_score_returns_none_on_split_exception():
    class BadSplit(str):
        def split(self, sep=None, maxsplit=-1):  # type: ignore[override]
            raise RuntimeError("boom")

    assert _cvss3_base_score(BadSplit("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) is None


def test_extract_cvss_by_security_id_finds_cvss():
    html = (
        "SECURITY-123 vulnerability\n"
        "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
        "SECURITY-456 other"
    )
    result = _extract_cvss_by_security_id(html)
    assert "SECURITY-123" in result
    cvss = result["SECURITY-123"]
    assert cvss["version"] == "3.1"
    assert cvss["base_score"] is not None


def test_extract_cvss_by_security_id_no_cvss():
    html = "SECURITY-999 vulnerability with no CVSS link"
    result = _extract_cvss_by_security_id(html)
    assert result == {}


def test_extract_cvss_by_security_id_empty():
    assert _extract_cvss_by_security_id("") == {}


def test_max_severity_label_empty():
    assert _max_severity_label([]) is None


def test_max_severity_label_single():
    assert _max_severity_label(["high"]) == "high"


def test_max_severity_label_picks_highest():
    assert _max_severity_label(["low", "critical", "medium"]) == "critical"


def test_max_severity_label_all_same():
    assert _max_severity_label(["medium", "medium"]) == "medium"


def test_max_severity_label_order():
    # Order: none < low < medium < high < critical
    assert _max_severity_label(["none", "low"]) == "low"
    assert _max_severity_label(["low", "medium"]) == "medium"
    assert _max_severity_label(["medium", "high"]) == "high"
    assert _max_severity_label(["high", "critical"]) == "critical"


def test_max_severity_label_unknown_ignored():
    # Unknown label should have lowest priority
    result = _max_severity_label(["unknown_sev", "low"])
    assert result == "low"


def test_merge_advisory_records_deduplicates():
    rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "published_date": "2025-01-01",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
    }
    result = merge_advisory_records([rec, rec])
    assert len(result) == 1


def test_merge_advisory_records_merges_security_warning_ids():
    rec1 = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        "security_warning_ids": ["SECURITY-100"],
    }
    rec2 = dict(rec1)
    rec2["security_warning_ids"] = ["SECURITY-200"]

    result = merge_advisory_records([rec1, rec2])
    assert len(result) == 1
    merged = result[0]
    assert "SECURITY-100" in merged["security_warning_ids"]
    assert "SECURITY-200" in merged["security_warning_ids"]


def test_merge_advisory_records_keeps_earliest_date():
    rec1 = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "published_date": "2025-01-10",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
    }
    rec2 = dict(rec1)
    rec2["published_date"] = "2025-01-05"

    result = merge_advisory_records([rec1, rec2])
    assert len(result) == 1
    assert result[0]["published_date"] == "2025-01-05"


def test_merge_advisory_records_prefers_www_url():
    rec1 = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "https://jenkins.io/security/advisory/2025-01-01/",
    }
    rec2 = dict(rec1)
    rec2["url"] = "https://www.jenkins.io/security/advisory/2025-01-01/"

    result = merge_advisory_records([rec1, rec2])
    assert len(result) == 1
    from urllib.parse import urlparse

    assert urlparse(result[0]["url"]).netloc == "www.jenkins.io"


def test_merge_advisory_records_active_security_warning_or():
    rec1 = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        "active_security_warning": False,
    }
    rec2 = dict(rec1)
    rec2["active_security_warning"] = True

    result = merge_advisory_records([rec1, rec2])
    assert result[0]["active_security_warning"] is True


def test_merge_advisory_records_prefers_non_empty_title():
    rec1 = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        "title": "",
    }
    rec2 = dict(rec1)
    rec2["title"] = "Security Advisory Title"

    result = merge_advisory_records([rec1, rec2])
    assert result[0]["title"] == "Security Advisory Title"


def test_merge_advisory_records_distinct_records_kept_separate():
    recs = [
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "plugin-a",
            "advisory_id": "2025-01-01",
            "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        },
        {
            "source": "jenkins",
            "type": "advisory",
            "plugin_id": "plugin-b",
            "advisory_id": "2025-01-01",
            "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        },
    ]
    result = merge_advisory_records(recs)
    assert len(result) == 2


def test_merge_advisory_records_adds_merged_from_count():
    rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
    }
    result = merge_advisory_records([rec, rec, rec])
    assert result[0]["_merged_from_count"] == 3


def test_merge_advisory_records_derives_advisory_id_from_url():
    rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "",
        "published_date": "",
        "url": "https://www.jenkins.io/security/advisory/2025-06-15/",
    }
    result = merge_advisory_records([rec])
    assert len(result) == 1
    assert result[0]["advisory_id"] == "2025-06-15"
    assert result[0]["published_date"] == "2025-06-15"


def test_merge_advisory_records_empty_input():
    assert merge_advisory_records([]) == []


def test_merge_advisory_records_normalizes_url():
    rec = {
        "source": "jenkins",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "url": "http://jenkins.io/security/advisory/2025-01-01/?foo=bar",
    }
    result = merge_advisory_records([rec])
    url = result[0]["url"]
    assert url.startswith("https://")
    assert "?" not in url


def test_merge_advisory_records_merges_vulnerabilities_and_dates():
    rec1 = {
        "source": "other",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "published_date": "",
        "url": None,
        "security_warning_ids": ["SECURITY-9"],
        "vulnerabilities": [
            "bad-entry",
            {"security_warning_id": ""},
            {
                "security_warning_id": "SECURITY-9",
                "severity_label": "",
                "cvss": {"base_score": None},
            },
        ],
    }
    rec2 = {
        "source": "other",
        "type": "advisory",
        "plugin_id": "my-plugin",
        "advisory_id": "2025-01-01",
        "published_date": "2025-01-02",
        "url": "https://www.jenkins.io/security/advisory/2025-01-01/",
        "security_warning_ids": ["SECURITY-10"],
        "vulnerabilities": [
            {
                "security_warning_id": "SECURITY-9",
                "severity_label": "high",
                "url_fragment": "#SECURITY-9",
                "cvss": {"base_score": 7.5, "vector": "CVSS:3.1/..."},
            },
            {"security_warning_id": "SECURITY-10", "severity_label": "medium"},
        ],
    }

    result = merge_advisory_records([rec1, rec2])
    assert len(result) == 1
    merged = result[0]
    assert merged["published_date"] == "2025-01-02"
    assert merged["url"] == "https://www.jenkins.io/security/advisory/2025-01-01/"
    assert merged["security_warning_ids"] == ["SECURITY-10", "SECURITY-9"]
    assert [v["security_warning_id"] for v in merged["vulnerabilities"]] == [
        "SECURITY-10",
        "SECURITY-9",
    ]
    sec9 = merged["vulnerabilities"][1]
    assert sec9["severity_label"] == "high"
    assert sec9["url_fragment"] == "#SECURITY-9"
    assert sec9["cvss"]["base_score"] == 7.5


def test_fetch_text_success(monkeypatch):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b"ok-body"

    monkeypatch.setattr(ja, "_allowlisted_url", lambda _url: None)
    monkeypatch.setattr(ja.urllib.request, "urlopen", lambda req, timeout: _Resp())
    text = _fetch_text("https://www.jenkins.io/security/advisory/2025-01-01/")
    assert text == "ok-body"


def test_fetch_text_http_error_raises_runtime_error(monkeypatch):
    monkeypatch.setattr(ja, "_allowlisted_url", lambda _url: None)

    def _raise(_req, timeout):
        raise urllib.error.HTTPError("https://x", 500, "fail", hdrs=Message(), fp=None)

    monkeypatch.setattr(ja.urllib.request, "urlopen", _raise)
    with pytest.raises(RuntimeError, match="Fetch failed \\(500\\)"):
        _fetch_text("https://www.jenkins.io/security/advisory/2025-01-01/")


def test_fetch_text_url_error_raises_runtime_error(monkeypatch):
    monkeypatch.setattr(ja, "_allowlisted_url", lambda _url: None)

    def _raise(_req, timeout):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(ja.urllib.request, "urlopen", _raise)
    with pytest.raises(RuntimeError, match="Fetch failed \\(network\\)"):
        _fetch_text("https://www.jenkins.io/security/advisory/2025-01-01/")


def test_load_plugin_snapshot_reads_expected_file(tmp_path):
    data_dir = tmp_path / "raw"
    plugins_dir = data_dir / "plugins"
    plugins_dir.mkdir(parents=True)
    snapshot_path = plugins_dir / "my-plugin.snapshot.json"
    snapshot_path.write_text('{"plugin_id":"my-plugin"}', encoding="utf-8")

    result = _load_plugin_snapshot("my-plugin", data_dir)
    assert result["plugin_id"] == "my-plugin"


def test_load_plugin_snapshot_rejects_unsafe_plugin_id(tmp_path):
    with pytest.raises(ValueError, match="Invalid plugin_id"):
        _load_plugin_snapshot("../bad", tmp_path)


def test_collect_advisories_sample_returns_list():
    result = collect_advisories_sample()
    assert isinstance(result, list)
    assert len(result) >= 1


def test_collect_advisories_sample_record_shape():
    result = collect_advisories_sample()
    for record in result:
        assert "plugin_id" in record
        assert "source" in record
        assert record["source"] == "jenkins"
        assert "url" in record


def test_collect_advisories_sample_filter_by_plugin_id():
    result = collect_advisories_sample(plugin_id="cucumber-reports")
    assert all(r["plugin_id"] == "cucumber-reports" for r in result)
    assert len(result) >= 1


def test_collect_advisories_sample_filter_no_match():
    result = collect_advisories_sample(plugin_id="no-such-plugin-xyz")
    assert result == []


def test_collect_advisories_sample_none_returns_all():
    all_records = collect_advisories_sample(plugin_id=None)
    filtered = collect_advisories_sample(plugin_id="cucumber-reports")
    assert len(all_records) >= len(filtered)


# ---------------------------------------------------------------------------
# collect_advisories_real — full collector with network/snapshot mocked
# ---------------------------------------------------------------------------


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
