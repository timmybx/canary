from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
from typing import Any


@dataclass(frozen=True)
class AdvisoryRecord:
    source: str
    type: str
    advisory_id: str
    published_date: date
    plugin_id: str
    title: str
    url: str
    fixed_version: str | None = None
    affected_versions: str | None = None
    cve_ids: list[str] = None  # set in __post_init__ if you want strict immutability
    cwe_ids: list[str] = None
    severity: str | None = None
    cvss: float | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["published_date"] = self.published_date.isoformat()
        d["cve_ids"] = d["cve_ids"] or []
        d["cwe_ids"] = d["cwe_ids"] or []
        return d


def collect_advisories_sample() -> list[dict[str, Any]]:
    records = [
        AdvisoryRecord(
            source="jenkins",
            type="advisory",
            advisory_id="2025-01-001",
            published_date=date(2025, 1, 10),
            plugin_id="workflow-cps",
            title="Sample advisory record (replace with real data)",
            url="https://www.jenkins.io/security/advisory/2025-01-001/",
            fixed_version="3.0",
            affected_versions="<= 2.9",
            notes="Placeholder data so the pipeline works end-to-end.",
        ),
        # ...
    ]
    return [r.to_dict() for r in records]
