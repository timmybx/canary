from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScoreResult:
    plugin: str
    score: int
    reasons: tuple[str, ...]
    features: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "score": self.score,
            "reasons": list(self.reasons),
            "features": self.features,
        }


def _parse_date(value: str) -> date | None:
    """
    Parse ISO-ish dates like:
      - '2016-07-27'
      - '2016-07-27T00:00:00Z' (tolerated)
    """
    if not value:
        return None
    v = value.strip()
    try:
        # common case in your JSONL: YYYY-MM-DD
        return date.fromisoformat(v[:10])
    except ValueError:
        return None


def _load_advisories_for_plugin(
    plugin_id: str,
    data_dir: Path,
) -> list[dict[str, Any]]:
    """
    Load advisories JSONL for a plugin.

    We look for the file you’re currently writing:
      data/raw/advisories/<plugin>.advisories.sample.jsonl

    Later, when you switch to real collection, you can also write:
      <plugin>.advisories.jsonl
    and this loader will still find it.
    """
    candidates = [
        data_dir / "advisories" / f"{plugin_id}.advisories.jsonl",
        data_dir / "advisories" / f"{plugin_id}.advisories.sample.jsonl",
    ]

    for path in candidates:
        if path.exists():
            records: list[dict[str, Any]] = []
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
            return records

    return []


def score_plugin_baseline(plugin: str, *, data_dir: str | Path = "data/raw") -> ScoreResult:
    """
    Baseline scoring:
    - Name-keyword heuristics (existing)
    - Advisory features from collected data (new, minimal)

    data_dir should point at the directory that contains:
      advisories/<plugin>.advisories*.jsonl
    """
    name = plugin.lower().strip()
    score = 0
    reasons: list[str] = []
    features: dict[str, Any] = {"matched_core_keywords": [], "matched_scm_keywords": []}

    # --- Existing heuristics ---
    core_keywords = ("credentials", "security", "auth", "oauth", "saml", "ldap")
    scm_keywords = ("git", "svn", "scm", "github", "bitbucket")

    matched_core = [k for k in core_keywords if k in name]
    matched_scm = [k for k in scm_keywords if k in name]
    features["matched_core_keywords"] = matched_core
    features["matched_scm_keywords"] = matched_scm

    if matched_core:
        score += 20
        reasons.append("Name suggests auth/security surface area (baseline heuristic).")

    if matched_scm:
        score += 10
        reasons.append("Name suggests SCM/integration surface area (baseline heuristic).")

    # --- New: advisory-backed signals ---
    plugin_id = name  # for now, plugin arg is the id
    advisories = _load_advisories_for_plugin(plugin_id, Path(data_dir))
    advisory_count = len(advisories)
    features["advisory_count"] = advisory_count

    latest_date: date | None = None
    for rec in advisories:
        d = _parse_date(str(rec.get("published_date", "")).strip())
        if d and (latest_date is None or d > latest_date):
            latest_date = d

    features["latest_advisory_date"] = latest_date.isoformat() if latest_date else None

    today = datetime.now(UTC).date()
    days_since_latest: int | None = None
    if latest_date:
        days_since_latest = (today - latest_date).days
    features["days_since_latest_advisory"] = days_since_latest
    features["had_advisory_within_365d"] = (
        days_since_latest is not None and days_since_latest <= 365
    )

    if advisory_count > 0:
        reasons.append(f"{advisory_count} advisory record(s) found for this plugin.")

        # Tiny scoring nudge (tweak later once you have real data)
        # - More advisories => more risk
        score += min(30, advisory_count * 10)

        if days_since_latest is not None:
            if days_since_latest <= 365:
                score += 20
                reasons.append("Recent advisory activity (<= 365 days).")
            else:
                reasons.append("No advisory activity in the last 365 days.")
    else:
        reasons.append("No advisories found in local dataset (yet).")

    if score == 0:
        score = 5
        reasons.append("No heuristics matched (baseline default).")

    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin, score=score, reasons=tuple(reasons), features=features)
