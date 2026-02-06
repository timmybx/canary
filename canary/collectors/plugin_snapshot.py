# canary/collectors/plugin_snapshot.py

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def collect_plugin_snapshot(
    *,
    plugin_id: str,
    repo_url: str | None = None,
    real: bool = False,
) -> dict[str, Any]:
    """
    Return a single 'snapshot' record for a Jenkins plugin.

    v0 goal: produce a stable, repeatable artifact with canonical URLs and any
    known security advisory linkages for the pilot plugin(s).
    """

    plugin_site_url = f"https://plugins.jenkins.io/{plugin_id}/"

    # v0: curated mapping for the pilot plugin
    if repo_url is None and plugin_id == "cucumber-reports":
        repo_url = "https://github.com/jenkinsci/cucumber-reports-plugin"

    # v0: start with a curated advisory URL list for the pilot
    advisory_urls: list[str] = []
    if plugin_id == "cucumber-reports":
        advisory_urls.append("https://www.jenkins.io/security/advisory/2016-07-27/")

    # TODO(v1): if real=True, fetch plugin site + search advisories index to discover mentions
    _ = real  # placeholder so linting doesn't complain

    return {
        "plugin_id": plugin_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "plugin_site_url": plugin_site_url,
        "repo_url": repo_url,
        "security_advisory_urls": advisory_urls,
    }
