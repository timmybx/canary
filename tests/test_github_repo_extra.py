"""Additional tests for canary.collectors.github_repo."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from canary.collectors.github_repo import (
    _allowlisted_url,
    _parse_link_header,
    _url_with_params,
    parse_github_owner_repo,
    fetch_github_workflows_dir,
)


# ---------------------------------------------------------------------------
# _url_with_params
# ---------------------------------------------------------------------------


def test_url_with_params_none():
    assert _url_with_params("https://api.github.com/repos", None) == "https://api.github.com/repos"


def test_url_with_params_empty_dict():
    url = "https://api.github.com/repos"
    assert _url_with_params(url, {}) == url


def test_url_with_params_adds_query():
    result = _url_with_params("https://api.github.com/repos", {"per_page": 100})
    assert "per_page=100" in result


def test_url_with_params_appends_to_existing_query():
    result = _url_with_params("https://api.github.com/repos?state=open", {"per_page": 50})
    assert "state=open" in result
    assert "per_page=50" in result
    assert result.count("?") == 1


# ---------------------------------------------------------------------------
# _allowlisted_url
# ---------------------------------------------------------------------------


def test_allowlisted_url_valid():
    # Should not raise
    _allowlisted_url("https://api.github.com/repos/org/repo")


def test_allowlisted_url_wrong_scheme():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("http://api.github.com/repos/org/repo")


def test_allowlisted_url_wrong_host():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("https://evil.example.com/repos")


def test_allowlisted_url_file_scheme():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("file:///etc/passwd")


# ---------------------------------------------------------------------------
# _parse_link_header
# ---------------------------------------------------------------------------


def test_parse_link_header_none():
    assert _parse_link_header(None) == {}


def test_parse_link_header_empty_string():
    assert _parse_link_header("") == {}


def test_parse_link_header_next_only():
    link = '<https://api.github.com/repos?page=2>; rel="next"'
    result = _parse_link_header(link)
    assert result["next"] == "https://api.github.com/repos?page=2"


def test_parse_link_header_next_and_last():
    link = (
        '<https://api.github.com/repos?page=2>; rel="next", '
        '<https://api.github.com/repos?page=5>; rel="last"'
    )
    result = _parse_link_header(link)
    assert result["next"] == "https://api.github.com/repos?page=2"
    assert result["last"] == "https://api.github.com/repos?page=5"


def test_parse_link_header_all_rels():
    link = (
        '<https://api.github.com/repos?page=1>; rel="first", '
        '<https://api.github.com/repos?page=2>; rel="next", '
        '<https://api.github.com/repos?page=4>; rel="prev", '
        '<https://api.github.com/repos?page=5>; rel="last"'
    )
    result = _parse_link_header(link)
    assert len(result) == 4


# ---------------------------------------------------------------------------
# parse_github_owner_repo (additional edge cases)
# ---------------------------------------------------------------------------


def test_parse_github_owner_repo_https():
    result = parse_github_owner_repo("https://github.com/jenkinsci/workflow-cps-plugin")
    assert result == ("jenkinsci", "workflow-cps-plugin")


def test_parse_github_owner_repo_git_suffix():
    result = parse_github_owner_repo("https://github.com/jenkinsci/workflow-cps-plugin.git")
    assert result == ("jenkinsci", "workflow-cps-plugin")


def test_parse_github_owner_repo_http():
    result = parse_github_owner_repo("http://github.com/org/repo")
    assert result == ("org", "repo")


def test_parse_github_owner_repo_invalid_host():
    assert parse_github_owner_repo("https://gitlab.com/org/repo") is None


def test_parse_github_owner_repo_too_short():
    assert parse_github_owner_repo("https://github.com/only-owner") is None


def test_parse_github_owner_repo_non_http():
    assert parse_github_owner_repo("git://github.com/org/repo") is None


# ---------------------------------------------------------------------------
# fetch_github_workflows_dir — mocked HTTP
# ---------------------------------------------------------------------------


def _make_urlopen_mock(payload, headers_dict=None):
    """Return a context manager mock that yields a response with given payload."""
    data = json.dumps(payload).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = data
    resp.headers.items.return_value = list((headers_dict or {}).items())
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_fetch_github_workflows_dir_returns_list(monkeypatch):
    payload = [
        {"name": "ci.yml", "type": "file"},
        {"name": "release.yml", "type": "file"},
    ]
    resp = _make_urlopen_mock(payload)

    with patch("canary.collectors.github_repo.urllib.request.urlopen", return_value=resp):
        result = fetch_github_workflows_dir("org", "repo")

    assert isinstance(result, list)
    assert len(result) == 2


def test_fetch_github_workflows_dir_returns_none_on_404(monkeypatch):
    err = HTTPError(
        url="https://api.github.com/repos/org/repo/contents/.github/workflows",
        code=404,
        msg="Not Found",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,  # type: ignore[arg-type]
    )
    with patch(
        "canary.collectors.github_repo.urllib.request.urlopen",
        side_effect=err,
    ):
        result = fetch_github_workflows_dir("org", "repo")

    assert result is None


def test_fetch_github_workflows_dir_reraises_non_404(monkeypatch):
    err = HTTPError(
        url="https://api.github.com/repos/org/repo/contents/.github/workflows",
        code=403,
        msg="Forbidden",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,  # type: ignore[arg-type]
    )
    with patch(
        "canary.collectors.github_repo.urllib.request.urlopen",
        side_effect=err,
    ):
        with pytest.raises(RuntimeError, match="403"):
            fetch_github_workflows_dir("org", "repo")
