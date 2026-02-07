from canary.collectors.github_repo import parse_github_owner_repo


def test_parse_github_owner_repo():
    assert parse_github_owner_repo("https://github.com/jenkinsci/cucumber-reports-plugin") == (
        "jenkinsci",
        "cucumber-reports-plugin",
    )

    assert parse_github_owner_repo("https://github.com/jenkinsci/cucumber-reports-plugin.git") == (
        "jenkinsci",
        "cucumber-reports-plugin",
    )

    assert parse_github_owner_repo("https://example.com/foo/bar") is None
