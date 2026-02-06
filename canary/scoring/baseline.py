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


def _load_plugin_snapshot(plugin_id: str, data_dir: Path) -> dict[str, Any] | None:
    path = data_dir / "plugins" / f"{plugin_id}.snapshot.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_iso_datetime(value: str) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    # tolerate Z
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


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
    - Plugin snapshot features from plugins API (new)

    data_dir should point at the directory that contains:
      advisories/<plugin>.advisories*.jsonl
      plugins/<plugin>.snapshot.json
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

    today = datetime.now(tz=UTC).date()
    days_since_latest: int | None = None
    if latest_date:
        days_since_latest = (today - latest_date).days
    features["days_since_latest_advisory"] = days_since_latest
    features["had_advisory_within_365d"] = (
        days_since_latest is not None and days_since_latest <= 365
    )

    if advisory_count > 0:
        reasons.append(f"{advisory_count} advisory record(s) found for this plugin.")

        # Recency-weighted advisory risk:
        # - Old advisories still matter (history), but much less than recent ones.
        per_advisory_points = 2  # default for "ancient"
        if days_since_latest is not None:
            if days_since_latest <= 30:
                per_advisory_points = 15
            elif days_since_latest <= 90:
                per_advisory_points = 12
            elif days_since_latest <= 365:
                per_advisory_points = 10
            else:
                per_advisory_points = 2

        advisory_points = min(30, advisory_count * per_advisory_points)
        score += advisory_points

        reasons.append(
            f"Advisory risk is weighted by recency (+{advisory_points} point(s); "
            f"{per_advisory_points}/advisory)."
        )

        if days_since_latest is not None:
            if days_since_latest <= 365:
                reasons.append("Recent advisory activity (<= 365 days).")
            else:
                reasons.append("No advisory activity in the last 365 days.")
    else:
        reasons.append("No advisories found in local dataset (yet).")

    # --- New: plugin snapshot signals (plugins API) ---
    snapshot = _load_plugin_snapshot(plugin_id, Path(data_dir))
    features["has_plugin_snapshot"] = snapshot is not None

    # defaults so JSON always has keys
    features.setdefault("required_core", None)
    features.setdefault("dependency_count", 0)
    features.setdefault("security_warning_count", 0)
    features.setdefault("active_security_warning_count", 0)
    features.setdefault("release_timestamp", None)
    features.setdefault("days_since_release", None)

    if snapshot and isinstance(snapshot, dict):
        api = snapshot.get("plugin_api") or {}

        required_core = api.get("requiredCore")
        deps = api.get("dependencies") or []
        sec_warnings = api.get("securityWarnings") or []

        features["required_core"] = required_core
        features["dependency_count"] = _safe_int(len(deps), default=0)
        features["security_warning_count"] = _safe_int(len(sec_warnings), default=0)
        features["active_security_warning_count"] = _safe_int(
            sum(1 for w in sec_warnings if (w or {}).get("active") is True),
            default=0,
        )

        release_ts = _parse_iso_datetime(str(api.get("releaseTimestamp", "")).strip())
        features["release_timestamp"] = release_ts.isoformat() if release_ts else None
        if release_ts:
            features["days_since_release"] = (datetime.now(UTC) - release_ts).days

        # Human-readable reasons
        if required_core:
            reasons.append(f"Requires Jenkins core {required_core} (from plugins API).")

        dep_count = len(deps)
        if dep_count > 0:
            reasons.append(f"Declares {dep_count} plugin dependency(ies) (surface area).")

        warn_count = len(sec_warnings)
        if warn_count > 0:
            active_warn = features["active_security_warning_count"]
            if active_warn == 0:
                reasons.append(f"{warn_count} security warning(s) listed (none active).")
            else:
                reasons.append(f"{warn_count} security warning(s) listed (active: {active_warn}).")

        if release_ts:
            reasons.append(f"Latest release is {release_ts.date().isoformat()}.")

        # Conservative scoring nudges:
        # - Active security warnings should matter.
        active_warn = features["active_security_warning_count"]
        score += min(60, active_warn * 20)
        if active_warn > 0:
            reasons.append("Active security warning(s) significantly increase risk.")

        # - Lots of dependencies adds surface area (small bump)
        if dep_count >= 10:
            score += 5
        elif dep_count >= 5:
            score += 3

        # - Recent release activity suggests maintenance (slight risk reduction)
        dsr = features.get("days_since_release")
        if isinstance(dsr, int) and dsr <= 180:
            reasons.append("Recent release activity suggests active maintenance.")
            score = max(0, score - 3)

    if score == 0:
        score = 5
        reasons.append("No heuristics matched (baseline default).")

    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin, score=score, reasons=tuple(reasons), features=features)
