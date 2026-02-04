from __future__ import annotations

from datetime import date
from typing import Any


def collect_advisories_sample() -> list[dict[str, Any]]:
    """
    Starter stub: returns a few records in the shape you’ll likely want.
    Replace this with a real collector that pulls from Jenkins advisories/issues pages.
    """
    return [
        {
            "source": "jenkins",
            "type": "advisory",
            "advisory_id": "2025-01-001",
            "published_date": str(date(2025, 1, 10)),
            "plugin_id": "workflow-cps",
            "title": "Sample advisory record (replace with real data)",
            "url": "https://www.jenkins.io/security/advisory/2025-01-001/",
            "fixed_version": "3.0",
            "affected_versions": "<= 2.9",
            "notes": "This is placeholder data so the pipeline works end-to-end.",
        },
        {
            "source": "jenkins",
            "type": "advisory",
            "advisory_id": "2025-02-002",
            "published_date": str(date(2025, 2, 20)),
            "plugin_id": "git",
            "title": "Another sample advisory record",
            "url": "https://www.jenkins.io/security/advisory/2025-02-002/",
            "fixed_version": "5.2.1",
            "affected_versions": "< 5.2.1",
            "notes": "Placeholder",
        },
        {
            "source": "jenkins",
            "type": "advisory",
            "advisory_id": "2024-11-003",
            "published_date": str(date(2024, 11, 3)),
            "plugin_id": "credentials",
            "title": "Sample advisory record",
            "url": "https://www.jenkins.io/security/advisory/2024-11-003/",
            "fixed_version": "1321.v000000",
            "affected_versions": "< 1321.v000000",
            "notes": "Placeholder",
        },
    ]
