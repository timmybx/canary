"""Tests for jenkins_advisories.py helper functions."""

from __future__ import annotations

import pytest

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
    _max_severity_label,
    _normalize_advisory_url,
    _parse_cvss_vector_from_url,
    _strip_query_fragment,
    merge_advisory_records,
)


# ---------------------------------------------------------------------------
# _cvss_base_score_to_severity_label
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _allowlisted_url
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _canonicalize_jenkins_url
# ---------------------------------------------------------------------------


def test_canonicalize_jenkins_url_normalizes_http_to_https():
    result = _canonicalize_jenkins_url("http://www.jenkins.io/security/advisory/2025-01-01/")
    assert result is not None
    assert result.startswith("https://")


def test_canonicalize_jenkins_url_normalizes_jenkins_io_to_www():
    result = _canonicalize_jenkins_url("https://jenkins.io/security/advisory/2025-01-01/")
    assert result is not None
    assert "www.jenkins.io" in result


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


# ---------------------------------------------------------------------------
# _strip_query_fragment
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _normalize_advisory_url
# ---------------------------------------------------------------------------


def test_normalize_advisory_url_removes_query_and_fragment():
    url = "http://jenkins.io/security/advisory/2025-01-01/?q=1#SECURITY-1"
    result = _normalize_advisory_url(url)
    assert "?" not in result
    assert "#" not in result
    assert result.startswith("https://")


# ---------------------------------------------------------------------------
# _extract_title
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _date_from_advisory_url
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _extract_severity_labels
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _extract_security_sections
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _parse_cvss_vector_from_url
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _cvss3_base_score
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _extract_cvss_by_security_id
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _max_severity_label
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# merge_advisory_records
# ---------------------------------------------------------------------------


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
    assert "www.jenkins.io" in result[0]["url"]


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
