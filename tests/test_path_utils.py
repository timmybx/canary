"""Tests for canary.collectors._path_utils."""

from __future__ import annotations

from pathlib import Path

import pytest

from canary.collectors._path_utils import safe_join_under, safe_plugin_id

# ---------------------------------------------------------------------------
# safe_plugin_id
# ---------------------------------------------------------------------------


def test_safe_plugin_id_valid_names():
    assert safe_plugin_id("cucumber-reports") == "cucumber-reports"
    assert safe_plugin_id("workflow_cps") == "workflow_cps"
    assert safe_plugin_id("plugin1.test") == "plugin1.test"
    assert safe_plugin_id("A1") == "A1"


def test_safe_plugin_id_strips_surrounding_whitespace():
    assert safe_plugin_id("  my-plugin  ") == "my-plugin"


def test_safe_plugin_id_empty_returns_none():
    assert safe_plugin_id("") is None
    assert safe_plugin_id("   ") is None


def test_safe_plugin_id_path_traversal_returns_none():
    assert safe_plugin_id("../etc/passwd") is None
    assert safe_plugin_id("../../secret") is None


def test_safe_plugin_id_slash_returns_none():
    assert safe_plugin_id("plugin/subdir") is None


def test_safe_plugin_id_space_returns_none():
    assert safe_plugin_id("plugin name") is None


def test_safe_plugin_id_starts_with_invalid_char_returns_none():
    # First char must be alphanumeric
    assert safe_plugin_id("-bad-start") is None
    assert safe_plugin_id(".bad-start") is None
    assert safe_plugin_id("_bad-start") is None


def test_safe_plugin_id_single_alphanumeric_char():
    assert safe_plugin_id("a") == "a"
    assert safe_plugin_id("1") == "1"


# ---------------------------------------------------------------------------
# safe_join_under
# ---------------------------------------------------------------------------


def test_safe_join_under_returns_path_inside_base(tmp_path: Path):
    result = safe_join_under(tmp_path, "subdir", "file.json")
    assert result == (tmp_path / "subdir" / "file.json").resolve()


def test_safe_join_under_direct_child(tmp_path: Path):
    result = safe_join_under(tmp_path, "file.json")
    assert result.parent == tmp_path.resolve()


def test_safe_join_under_escape_via_dotdot_raises(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes base directory"):
        safe_join_under(tmp_path, "..", "etc", "passwd")


def test_safe_join_under_escape_absolute_part_raises(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes base directory"):
        safe_join_under(tmp_path, "/etc/passwd")


def test_safe_join_under_deeply_nested_is_allowed(tmp_path: Path):
    result = safe_join_under(tmp_path, "a", "b", "c", "file.json")
    assert str(result).startswith(str(tmp_path.resolve()))
