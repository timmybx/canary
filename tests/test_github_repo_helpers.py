from __future__ import annotations

import json
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from canary.collectors.github_repo import (
    _allowlisted_url,
    _fetch_all_pages,
    _fetch_json,
    _fetch_json_any,
    _github_headers,
    _parse_link_header,
    _url_with_params,
    fetch_github_codeowners,
    fetch_github_contents_path,
    fetch_github_dependabot_config,
    fetch_github_security_policy,
    fetch_github_workflows_dir,
)

# ---------------------------------------------------------------------------
# _allowlisted_url
# ---------------------------------------------------------------------------


def test_allowlisted_url_accepts_valid_https_api_github():
    _allowlisted_url("https://api.github.com/repos/owner/repo")


def test_allowlisted_url_rejects_http():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("http://api.github.com/repos/owner/repo")


def test_allowlisted_url_rejects_non_github_netloc():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("https://evil.example.com/repos/owner/repo")


def test_allowlisted_url_rejects_file_scheme():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("file:///etc/passwd")


def test_allowlisted_url_rejects_empty_netloc():
    with pytest.raises(ValueError, match="Refusing"):
        _allowlisted_url("https:///repos/owner/repo")


# ---------------------------------------------------------------------------
# _github_headers
# ---------------------------------------------------------------------------


def test_github_headers_always_has_accept_and_user_agent():
    with patch.dict("os.environ", {}, clear=True):
        headers = _github_headers()
    assert "Accept" in headers
    assert "User-Agent" in headers
    assert "Authorization" not in headers


def test_github_headers_includes_authorization_when_token_set():
    with patch.dict("os.environ", {"GITHUB_TOKEN": "mytoken123"}):
        headers = _github_headers()
    assert headers["Authorization"] == "Bearer mytoken123"


def test_github_headers_no_authorization_when_token_empty():
    with patch.dict("os.environ", {"GITHUB_TOKEN": ""}, clear=True):
        headers = _github_headers()
    assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# _url_with_params
# ---------------------------------------------------------------------------


def test_url_with_params_none_returns_unchanged():
    url = "https://api.github.com/repos/owner/repo"
    assert _url_with_params(url, None) == url


def test_url_with_params_empty_dict_returns_unchanged():
    url = "https://api.github.com/repos/owner/repo"
    assert _url_with_params(url, {}) == url


def test_url_with_params_adds_query_string_to_bare_url():
    url = "https://api.github.com/repos/owner/repo"
    result = _url_with_params(url, {"per_page": 100})
    assert result == "https://api.github.com/repos/owner/repo?per_page=100"


def test_url_with_params_appends_to_existing_query_string():
    url = "https://api.github.com/repos/owner/repo?page=2"
    result = _url_with_params(url, {"per_page": 50})
    assert result == "https://api.github.com/repos/owner/repo?page=2&per_page=50"


def test_url_with_params_handles_multiple_params():
    url = "https://api.github.com/list"
    result = _url_with_params(url, {"a": "1", "b": "2"})
    assert "a=1" in result
    assert "b=2" in result
    assert result.startswith(url + "?")


# ---------------------------------------------------------------------------
# _parse_link_header
# ---------------------------------------------------------------------------


def test_parse_link_header_none_returns_empty():
    assert _parse_link_header(None) == {}


def test_parse_link_header_empty_string_returns_empty():
    assert _parse_link_header("") == {}


def test_parse_link_header_parses_next_rel():
    link = '<https://api.github.com/repos?page=2>; rel="next"'
    result = _parse_link_header(link)
    assert result == {"next": "https://api.github.com/repos?page=2"}


def test_parse_link_header_parses_multiple_rels():
    link = (
        '<https://api.github.com/repos?page=2>; rel="next",'
        ' <https://api.github.com/repos?page=5>; rel="last"'
    )
    result = _parse_link_header(link)
    assert result["next"] == "https://api.github.com/repos?page=2"
    assert result["last"] == "https://api.github.com/repos?page=5"


def test_parse_link_header_parses_prev_and_next():
    link = (
        '<https://api.github.com/repos?page=1>; rel="prev",'
        ' <https://api.github.com/repos?page=3>; rel="next"'
    )
    result = _parse_link_header(link)
    assert result["prev"] == "https://api.github.com/repos?page=1"
    assert result["next"] == "https://api.github.com/repos?page=3"


# ---------------------------------------------------------------------------
# _fetch_json_any
# ---------------------------------------------------------------------------


def _make_mock_response(body: bytes, headers: dict[str, str]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = body
    resp.headers.items.return_value = list(headers.items())
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_fetch_json_any_success():
    payload = {"id": 1, "name": "repo"}
    body = json.dumps(payload).encode("utf-8")
    mock_resp = _make_mock_response(body, {"Content-Type": "application/json"})

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result_payload, result_headers = _fetch_json_any("https://api.github.com/repos/o/r")

    assert result_payload == payload
    assert result_headers["Content-Type"] == "application/json"


def test_fetch_json_any_http_error_raises_runtime_error():
    err = urllib.error.HTTPError(
        url="https://api.github.com/repos/o/r",
        code=403,
        msg="Forbidden",
        hdrs=None,
        fp=None,
    )
    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(RuntimeError, match="403"):
            _fetch_json_any("https://api.github.com/repos/o/r")


def test_fetch_json_any_url_error_raises_runtime_error():
    err = urllib.error.URLError(reason="connection refused")
    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(RuntimeError, match="network"):
            _fetch_json_any("https://api.github.com/repos/o/r")


def test_fetch_json_any_invalid_json_raises_runtime_error():
    mock_resp = _make_mock_response(b"not-json{{", {})
    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(RuntimeError, match="not valid JSON"):
            _fetch_json_any("https://api.github.com/repos/o/r")


def test_fetch_json_any_non_allowlisted_url_raises_value_error():
    with pytest.raises(ValueError, match="Refusing"):
        _fetch_json_any("https://evil.example.com/data")


def test_fetch_json_any_passes_params_in_url():
    payload = []
    body = json.dumps(payload).encode("utf-8")
    mock_resp = _make_mock_response(body, {})

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
        _fetch_json_any("https://api.github.com/list", params={"per_page": 10})
        called_req = mock_open.call_args[0][0]
        assert "per_page=10" in called_req.full_url


# ---------------------------------------------------------------------------
# _fetch_json
# ---------------------------------------------------------------------------


def test_fetch_json_returns_dict_payload():
    payload = {"key": "value"}
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(payload, {}),
    ):
        result = _fetch_json("https://api.github.com/repos/o/r")
    assert result == payload


def test_fetch_json_raises_for_non_dict_payload():
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(["list", "not", "dict"], {}),
    ):
        with pytest.raises(RuntimeError, match="Expected JSON object"):
            _fetch_json("https://api.github.com/repos/o/r")


# ---------------------------------------------------------------------------
# _fetch_all_pages
# ---------------------------------------------------------------------------


def test_fetch_all_pages_single_page_no_next():
    items = [{"id": 1}, {"id": 2}]
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(items, {}),
    ):
        result = _fetch_all_pages("https://api.github.com/list")
    assert result == items


def test_fetch_all_pages_multi_page_follows_next():
    page1 = [{"id": 1}]
    page2 = [{"id": 2}]
    link_header = '<https://api.github.com/list?page=2>; rel="next"'

    call_count = 0

    def side_effect(url, *, params=None, timeout_s=15.0):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return page1, {"Link": link_header}
        return page2, {}

    with patch("canary.collectors.github_repo._fetch_json_any", side_effect=side_effect):
        result = _fetch_all_pages("https://api.github.com/list")

    assert result == [{"id": 1}, {"id": 2}]


def test_fetch_all_pages_stops_at_max_pages():
    link_header = '<https://api.github.com/list?page={n}>; rel="next"'

    call_count = 0

    def always_next(url, *, params=None, timeout_s=15.0):
        nonlocal call_count
        call_count += 1
        return [{"id": call_count}], {"Link": link_header.format(n=call_count + 1)}

    with patch("canary.collectors.github_repo._fetch_json_any", side_effect=always_next):
        result = _fetch_all_pages("https://api.github.com/list", max_pages=3)

    assert len(result) == 3
    assert call_count == 3


def test_fetch_all_pages_non_list_payload_appended():
    payload = {"single": "object"}
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(payload, {}),
    ):
        result = _fetch_all_pages("https://api.github.com/single")
    assert result == [payload]


# ---------------------------------------------------------------------------
# fetch_github_contents_path
# ---------------------------------------------------------------------------


def test_fetch_github_contents_path_empty_raises():
    with pytest.raises(ValueError, match="non-empty"):
        fetch_github_contents_path("owner", "repo", "")


def test_fetch_github_contents_path_slash_only_raises():
    with pytest.raises(ValueError, match="non-empty"):
        fetch_github_contents_path("owner", "repo", "///")


def test_fetch_github_contents_path_404_returns_none():
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        side_effect=RuntimeError("GitHub API request failed (404) for https://api.github.com/..."),
    ):
        result = fetch_github_contents_path("owner", "repo", "README.md")
    assert result is None


def test_fetch_github_contents_path_other_error_raises():
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        side_effect=RuntimeError("GitHub API request failed (500) for https://api.github.com/..."),
    ):
        with pytest.raises(RuntimeError, match="500"):
            fetch_github_contents_path("owner", "repo", "README.md")


def test_fetch_github_contents_path_list_payload_filters_dicts():
    payload = [{"name": "file.yml"}, "not-a-dict", {"name": "other.yml"}]
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(payload, {}),
    ):
        result = fetch_github_contents_path("owner", "repo", ".github/workflows")
    assert result == [{"name": "file.yml"}, {"name": "other.yml"}]


def test_fetch_github_contents_path_dict_payload_returns_dict():
    payload = {"name": "README.md", "content": "base64..."}
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(payload, {}),
    ):
        result = fetch_github_contents_path("owner", "repo", "README.md")
    assert result == payload


def test_fetch_github_contents_path_unexpected_type_returns_none():
    with patch(
        "canary.collectors.github_repo._fetch_json_any",
        return_value=(42, {}),
    ):
        result = fetch_github_contents_path("owner", "repo", "README.md")
    assert result is None


# ---------------------------------------------------------------------------
# fetch_github_workflows_dir
# ---------------------------------------------------------------------------


def test_fetch_github_workflows_dir_returns_list():
    workflows = [{"name": "ci.yml"}, {"name": "release.yml"}]
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=workflows,
    ):
        result = fetch_github_workflows_dir("owner", "repo")
    assert result == workflows


def test_fetch_github_workflows_dir_returns_none_when_dict():
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value={"name": "workflows"},
    ):
        result = fetch_github_workflows_dir("owner", "repo")
    assert result is None


def test_fetch_github_workflows_dir_returns_none_when_none():
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=None,
    ):
        result = fetch_github_workflows_dir("owner", "repo")
    assert result is None


# ---------------------------------------------------------------------------
# fetch_github_codeowners
# ---------------------------------------------------------------------------


def test_fetch_github_codeowners_returns_first_found():
    codeowners = {"name": "CODEOWNERS", "content": "base64..."}
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=codeowners,
    ):
        result = fetch_github_codeowners("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == "CODEOWNERS"


def test_fetch_github_codeowners_tries_dotgithub_path():
    dotgithub = {"name": "CODEOWNERS", "content": "base64..."}

    def side_effect(owner, repo, path, **kwargs):
        if path == "CODEOWNERS":
            return None
        if path == ".github/CODEOWNERS":
            return dict(dotgithub)
        return None

    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        side_effect=side_effect,
    ):
        result = fetch_github_codeowners("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == ".github/CODEOWNERS"


def test_fetch_github_codeowners_returns_none_when_not_found():
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=None,
    ):
        result = fetch_github_codeowners("owner", "repo")
    assert result is None


def test_fetch_github_codeowners_skips_list_payloads():
    # Lists are not dicts, so they shouldn't be returned
    def side_effect(owner, repo, path, **kwargs):
        return [{"name": "CODEOWNERS"}]

    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        side_effect=side_effect,
    ):
        result = fetch_github_codeowners("owner", "repo")
    assert result is None


def test_fetch_github_codeowners_does_not_overwrite_existing_resolved_path():
    payload = {"name": "CODEOWNERS", "_resolved_path": "pre-set"}
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=payload,
    ):
        result = fetch_github_codeowners("owner", "repo")
    # setdefault means pre-existing value is preserved
    assert result["_resolved_path"] == "pre-set"


# ---------------------------------------------------------------------------
# fetch_github_security_policy
# ---------------------------------------------------------------------------


def test_fetch_github_security_policy_returns_first_found():
    security = {"name": "SECURITY.md", "content": "base64..."}
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=security,
    ):
        result = fetch_github_security_policy("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == "SECURITY.md"


def test_fetch_github_security_policy_tries_dotgithub_path():
    def side_effect(owner, repo, path, **kwargs):
        if path == "SECURITY.md":
            return None
        if path == ".github/SECURITY.md":
            return {"name": "SECURITY.md", "content": "base64..."}
        return None

    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        side_effect=side_effect,
    ):
        result = fetch_github_security_policy("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == ".github/SECURITY.md"


def test_fetch_github_security_policy_returns_none_when_not_found():
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=None,
    ):
        result = fetch_github_security_policy("owner", "repo")
    assert result is None


def test_fetch_github_security_policy_tries_lowercase_paths():
    call_paths: list[str] = []

    def side_effect(owner, repo, path, **kwargs):
        call_paths.append(path)
        return None

    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        side_effect=side_effect,
    ):
        fetch_github_security_policy("owner", "repo")

    assert "security.md" in call_paths
    assert ".github/security.md" in call_paths


# ---------------------------------------------------------------------------
# fetch_github_dependabot_config
# ---------------------------------------------------------------------------


def test_fetch_github_dependabot_config_returns_yml_first():
    config = {"name": "dependabot.yml", "content": "base64..."}
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=config,
    ):
        result = fetch_github_dependabot_config("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == ".github/dependabot.yml"


def test_fetch_github_dependabot_config_falls_back_to_yaml():
    def side_effect(owner, repo, path, **kwargs):
        if path == ".github/dependabot.yml":
            return None
        if path == ".github/dependabot.yaml":
            return {"name": "dependabot.yaml", "content": "base64..."}
        return None

    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        side_effect=side_effect,
    ):
        result = fetch_github_dependabot_config("owner", "repo")
    assert result is not None
    assert result["_resolved_path"] == ".github/dependabot.yaml"


def test_fetch_github_dependabot_config_returns_none_when_not_found():
    with patch(
        "canary.collectors.github_repo.fetch_github_contents_path",
        return_value=None,
    ):
        result = fetch_github_dependabot_config("owner", "repo")
    assert result is None
