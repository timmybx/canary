from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from canary.collectors.gharchive_history import (
    _build_raw_event_query_with_sampling,
    _coerce_bool_or_none,
    _event_yyyymm_from_value,
    _normalize_date_value,
    _normalize_timestamp_value,
    _split_repo_full_name,
)

# ---------------------------------------------------------------------------
# _coerce_bool_or_none
# ---------------------------------------------------------------------------


def test_coerce_bool_true_returns_true():
    assert _coerce_bool_or_none(True) is True


def test_coerce_bool_false_returns_false():
    assert _coerce_bool_or_none(False) is False


def test_coerce_bool_string_true():
    assert _coerce_bool_or_none("true") is True
    assert _coerce_bool_or_none("True") is True
    assert _coerce_bool_or_none("TRUE") is True
    assert _coerce_bool_or_none("  true  ") is True


def test_coerce_bool_string_false():
    assert _coerce_bool_or_none("false") is False
    assert _coerce_bool_or_none("False") is False
    assert _coerce_bool_or_none("FALSE") is False


def test_coerce_bool_other_string_returns_none():
    assert _coerce_bool_or_none("yes") is None
    assert _coerce_bool_or_none("no") is None
    assert _coerce_bool_or_none("1") is None
    assert _coerce_bool_or_none("") is None


def test_coerce_bool_non_bool_non_string_returns_none():
    assert _coerce_bool_or_none(1) is None
    assert _coerce_bool_or_none(0) is None
    assert _coerce_bool_or_none(None) is None
    assert _coerce_bool_or_none(3.14) is None
    assert _coerce_bool_or_none(["list"]) is None


# ---------------------------------------------------------------------------
# _event_yyyymm_from_value
# ---------------------------------------------------------------------------


def test_event_yyyymm_from_value_none_returns_none():
    assert _event_yyyymm_from_value(None) is None


def test_event_yyyymm_from_value_datetime():
    dt = datetime(2025, 7, 18, 12, 34, 56, tzinfo=UTC)
    assert _event_yyyymm_from_value(dt) == "2025-07"


def test_event_yyyymm_from_value_date():
    d = date(2024, 3, 5)
    assert _event_yyyymm_from_value(d) == "2024-03"


def test_event_yyyymm_from_value_iso_timestamp_string():
    assert _event_yyyymm_from_value("2026-01-15T10:20:30Z") == "2026-01"


def test_event_yyyymm_from_value_string_starts_with_yyyy_dash():
    assert _event_yyyymm_from_value("2023-11-01") == "2023-11"
    assert _event_yyyymm_from_value("2023-11") == "2023-11"


def test_event_yyyymm_from_value_empty_string_returns_none():
    assert _event_yyyymm_from_value("") is None
    assert _event_yyyymm_from_value("   ") is None


def test_event_yyyymm_from_value_non_string_non_date_returns_none():
    assert _event_yyyymm_from_value(42) is None
    assert _event_yyyymm_from_value(3.14) is None


# ---------------------------------------------------------------------------
# _normalize_timestamp_value
# ---------------------------------------------------------------------------


def test_normalize_timestamp_none_returns_none():
    assert _normalize_timestamp_value(None) is None


def test_normalize_timestamp_datetime_with_tz():
    dt = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
    result = _normalize_timestamp_value(dt)
    assert result == "2025-01-15T12:00:00Z"


def test_normalize_timestamp_datetime_without_tz_gets_utc():
    dt = datetime(2025, 6, 20, 8, 30, 0)
    result = _normalize_timestamp_value(dt)
    assert result == "2025-06-20T08:30:00Z"


def test_normalize_timestamp_z_terminated_string():
    result = _normalize_timestamp_value("2025-03-10T14:22:00Z")
    assert result == "2025-03-10T14:22:00Z"


def test_normalize_timestamp_iso_string_without_z():
    result = _normalize_timestamp_value("2025-03-10T14:22:00+00:00")
    assert result == "2025-03-10T14:22:00Z"


def test_normalize_timestamp_non_iso_string_returned_as_is():
    result = _normalize_timestamp_value("not-a-timestamp")
    assert result == "not-a-timestamp"


def test_normalize_timestamp_empty_string_returns_none():
    assert _normalize_timestamp_value("") is None
    assert _normalize_timestamp_value("   ") is None


# ---------------------------------------------------------------------------
# _normalize_date_value
# ---------------------------------------------------------------------------


def test_normalize_date_none_returns_none():
    assert _normalize_date_value(None) is None


def test_normalize_date_datetime_object():
    dt = datetime(2025, 8, 5, 10, 0, 0, tzinfo=UTC)
    assert _normalize_date_value(dt) == "2025-08-05"


def test_normalize_date_date_object():
    d = date(2024, 12, 31)
    assert _normalize_date_value(d) == "2024-12-31"


def test_normalize_date_iso_date_string():
    assert _normalize_date_value("2025-07-04") == "2025-07-04"


def test_normalize_date_timestamp_string_with_T():
    assert _normalize_date_value("2025-07-04T15:30:00Z") == "2025-07-04"


def test_normalize_date_invalid_string_returns_none():
    assert _normalize_date_value("not-a-date") is None


def test_normalize_date_empty_string_returns_none():
    assert _normalize_date_value("") is None
    assert _normalize_date_value("   ") is None


# ---------------------------------------------------------------------------
# _build_raw_event_query_with_sampling
# ---------------------------------------------------------------------------


def test_build_query_raises_for_zero_sample_percent():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=0.0,
        )


def test_build_query_raises_for_negative_sample_percent():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=-5.0,
        )


def test_build_query_raises_for_sample_percent_over_100():
    with pytest.raises(ValueError, match="sample_percent"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20260101"},
            sample_percent=101.0,
        )


def test_build_query_raises_for_no_matching_tables():
    with pytest.raises(ValueError, match="No GH Archive"):
        _build_raw_event_query_with_sampling(
            start_yyyymmdd="20260101",
            end_yyyymmdd="20260102",
            available_tables={"20251201"},  # outside range
            sample_percent=5.0,
        )


def test_build_query_100_percent_omits_tablesample():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260101",
        available_tables={"20260101"},
        sample_percent=100.0,
    )
    assert "TABLESAMPLE" not in sql


def test_build_query_less_than_100_includes_tablesample():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260101",
        available_tables={"20260101"},
        sample_percent=10.0,
    )
    assert "TABLESAMPLE SYSTEM (10.0 PERCENT)" in sql


def test_build_query_unions_multiple_tables():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260103",
        available_tables={"20260101", "20260102", "20260103"},
        sample_percent=100.0,
    )
    assert sql.count("UNION ALL") == 2
    assert "githubarchive.day.20260101" in sql
    assert "githubarchive.day.20260102" in sql
    assert "githubarchive.day.20260103" in sql


def test_build_query_only_includes_available_tables():
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd="20260101",
        end_yyyymmdd="20260103",
        available_tables={"20260102"},  # only day 2 is available
        sample_percent=100.0,
    )
    assert "githubarchive.day.20260101" not in sql
    assert "githubarchive.day.20260102" in sql
    assert "githubarchive.day.20260103" not in sql


# ---------------------------------------------------------------------------
# _split_repo_full_name
# ---------------------------------------------------------------------------


def test_split_repo_full_name_valid():
    owner, repo = _split_repo_full_name("jenkinsci/my-plugin")
    assert owner == "jenkinsci"
    assert repo == "my-plugin"


def test_split_repo_full_name_empty_string():
    owner, repo = _split_repo_full_name("")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_no_slash():
    owner, repo = _split_repo_full_name("noslash")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_strips_whitespace():
    owner, repo = _split_repo_full_name("  jenkinsci / my-plugin  ")
    assert owner == "jenkinsci"
    assert repo == "my-plugin"


def test_split_repo_full_name_empty_parts_become_none():
    owner, repo = _split_repo_full_name("/")
    assert owner is None
    assert repo is None


def test_split_repo_full_name_only_slash_in_owner():
    owner, repo = _split_repo_full_name("/repo")
    assert owner is None
    assert repo == "repo"
