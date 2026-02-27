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


def _cvss_base_score_to_label(score: float | int | None) -> str | None:
    """Map CVSS v3.x base score to a severity label."""
    if score is None:
        return None
    try:
        s = float(score)
    except Exception:
        return None
    if s == 0.0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


_SEVERITY_BONUS = {
    "None": 0,
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10,
}


def _advisory_record_max_cvss(rec: dict[str, Any]) -> float | None:
    """Return the maximum CVSS base score found in a single advisory record."""
    max_score: float | None = None
    vulns = rec.get("vulnerabilities") or []
    if isinstance(vulns, list):
        for v in vulns:
            if not isinstance(v, dict):
                continue
            cvss = v.get("cvss") or {}
            if not isinstance(cvss, dict):
                continue
            bs = cvss.get("base_score")
            if not isinstance(bs, (int, float, str)):
                continue
            try:
                s = float(bs)
            except ValueError:
                continue
            if max_score is None or s > max_score:
                max_score = s
    # fall back to summary if present
    if max_score is None:
        summ = rec.get("severity_summary") or {}
        if isinstance(summ, dict):
            bs = summ.get("max_cvss_base_score")
            if isinstance(bs, (int, float, str)):
                try:
                    max_score = float(bs)
                except ValueError:
                    max_score = None
    return max_score


def _load_advisories_for_plugin(
    plugin_id: str,
    data_dir: Path,
    *,
    prefer_real: bool = False,
) -> list[dict[str, Any]]:
    """
    Load advisories JSONL for a plugin.

    We look for these per-plugin files (first match wins):
      data/raw/advisories/<plugin>.advisories.real.jsonl
      data/raw/advisories/<plugin>.advisories.sample.jsonl
      data/raw/advisories/<plugin>.advisories.jsonl (back-compat)

    Use prefer_real=True to prefer the *.real.jsonl file when both exist.
    """
    candidates = [
        # Prefer exact suffix matches first so unit tests can use sample while
        # real pipelines can opt into real data explicitly.
        data_dir / "advisories" / f"{plugin_id}.advisories.real.jsonl",
        data_dir / "advisories" / f"{plugin_id}.advisories.sample.jsonl",
        # Back-compat / alternate naming
        data_dir / "advisories" / f"{plugin_id}.advisories.jsonl",
    ]

    if not prefer_real:
        # In sample mode, prefer sample over real if both exist.
        candidates = [
            data_dir / "advisories" / f"{plugin_id}.advisories.sample.jsonl",
            data_dir / "advisories" / f"{plugin_id}.advisories.real.jsonl",
            data_dir / "advisories" / f"{plugin_id}.advisories.jsonl",
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


def score_plugin_baseline(
    plugin: str,
    *,
    data_dir: str | Path = "data/raw",
    real: bool = False,
) -> ScoreResult:
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
    advisories = _load_advisories_for_plugin(plugin_id, Path(data_dir), prefer_real=real)
    advisory_count = len(advisories)
    features["advisory_count"] = advisory_count

    today = datetime.now(tz=UTC).date()

    # Dates + recency buckets
    advisory_dates: list[date] = []
    for rec in advisories:
        d = _parse_date(str(rec.get("published_date", "")).strip())
        if d:
            advisory_dates.append(d)

    latest_date: date | None = max(advisory_dates) if advisory_dates else None
    features["latest_advisory_date"] = latest_date.isoformat() if latest_date else None

    days_since_latest: int | None = (today - latest_date).days if latest_date else None
    features["days_since_latest_advisory"] = days_since_latest

    within_90 = sum(1 for d in advisory_dates if (today - d).days <= 90)
    within_365 = sum(1 for d in advisory_dates if (today - d).days <= 365)
    features["advisory_within_90d"] = within_90
    features["advisory_within_365d"] = within_365
    features["had_advisory_within_365d"] = within_365 > 0

    # Severity summary across advisories (best observed in the local dataset)
    max_cvss_overall: float | None = None
    for rec in advisories:
        ms = _advisory_record_max_cvss(rec)
        if ms is not None and (max_cvss_overall is None or ms > max_cvss_overall):
            max_cvss_overall = ms
    features["max_cvss_base_score_observed"] = max_cvss_overall
    features["max_cvss_severity_label_observed"] = (
        _cvss_base_score_to_label(max_cvss_overall) if max_cvss_overall is not None else None
    )

    if advisory_count > 0:
        reasons.append(f"{advisory_count} advisory record(s) found for this plugin.")

        # Advisory points are split into:
        #  1) Base history (old advisories still matter)
        #  2) Recency bonus (recent advisories matter much more)
        #  3) Severity bonus (CVSS-based, per advisory)
        base_points = min(20, advisory_count * 2)  # +2/advisory, capped
        recency_points = min(40, within_90 * 20 + max(0, within_365 - within_90) * 10)
        severity_points_raw = 0
        for rec in advisories:
            label = _cvss_base_score_to_label(_advisory_record_max_cvss(rec))
            severity_points_raw += _SEVERITY_BONUS.get(str(label), 0)
        severity_points = min(30, severity_points_raw)

        advisory_points = base_points + recency_points + severity_points
        score += advisory_points

        reasons.append(f"Advisory history: +{base_points} point(s) (2/advisory, capped at 20).")

        if within_365 > 0:
            if within_90 > 0:
                reasons.append(
                    f"Recent advisories: +{recency_points} point(s) "
                    f"({within_90} within 90d @20, "
                    f"{within_365 - within_90} within 365d @10; capped at 40)."
                )
            else:
                reasons.append(
                    f"Recent advisories: +{recency_points} point(s) "
                    f"({within_365} within 365d @10; capped at 40)."
                )
            reasons.append("Recent advisory activity (<= 365 days).")
        else:
            reasons.append("No advisory activity in the last 365 days (recency bonus = 0).")

        if severity_points > 0:
            sev_label = features.get("max_cvss_severity_label_observed")
            if sev_label:
                reasons.append(
                    f"Advisory severity (CVSS): +{severity_points} point(s) "
                    f"(max observed: {sev_label}, CVSS {max_cvss_overall:.1f}; capped at 30)."
                )
            else:
                reasons.append(
                    f"Advisory severity (CVSS): +{severity_points} point(s) (capped at 30)."
                )
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
