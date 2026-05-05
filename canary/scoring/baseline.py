from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from canary.plugin_aliases import alias_candidates, canonicalize_plugin_id

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA_ROOT = (_REPO_ROOT / "data" / "raw").resolve()


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


_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _safe_plugin_id(plugin_id: str) -> str | None:
    """Return a filesystem-safe plugin id or None when invalid."""
    candidate = plugin_id.strip()
    if not candidate:
        return None
    if not _PLUGIN_ID_RE.fullmatch(candidate):
        return None
    return candidate


def _safe_plugin_filename(plugin_id: str, suffix: str) -> str | None:
    safe_id = _safe_plugin_id(plugin_id)
    if safe_id is None:
        return None
    return f"{safe_id}{suffix}"


def _resolved_base_dir() -> Path:
    base = _DATA_ROOT
    if not base.exists() or not base.is_dir():
        raise ValueError("Invalid data directory")
    return base


def _safe_join_under(base: Path, *parts: str) -> Path:
    candidate = (base.joinpath(*parts)).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("Resolved path escapes data directory") from exc
    return candidate


def _advisory_candidates(data_dir: Path, plugin_id: str, *, prefer_real: bool) -> list[Path]:
    suffixes = (
        (
            ".advisories.real.jsonl",
            ".advisories.sample.jsonl",
            ".advisories.jsonl",
        )
        if prefer_real
        else (
            ".advisories.sample.jsonl",
            ".advisories.real.jsonl",
            ".advisories.jsonl",
        )
    )

    out: list[Path] = []
    seen: set[str] = set()
    for candidate_id in alias_candidates(plugin_id, data_dir=data_dir):
        safe_id = _safe_plugin_id(candidate_id)
        if safe_id is None or safe_id in seen:
            continue
        seen.add(safe_id)
        for suffix in suffixes:
            out.append(_safe_join_under(data_dir, "advisories", f"{safe_id}{suffix}"))
    return out


def _load_plugin_snapshot(plugin_id: str, data_dir: Path) -> dict[str, Any] | None:
    safe_id = _safe_plugin_id(plugin_id)
    if safe_id is None:
        return None

    path = _safe_join_under(data_dir, "plugins", f"{safe_id}.snapshot.json")
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_dependency_plugin_ids(snapshot: dict[str, Any]) -> list[str]:
    """Extract Jenkins *plugin* dependency IDs from a plugin snapshot.

    The Jenkins plugins API typically returns dependency objects like:
      {"name": "token-macro", "version": "...", ...}

    We treat the dependency "name" as the dependent plugin_id.
    """
    api = snapshot.get("plugin_api") or {}
    deps = api.get("dependencies") or []
    out: list[str] = []
    if isinstance(deps, list):
        for d in deps:
            if not isinstance(d, dict):
                continue
            pid = d.get("name")
            if isinstance(pid, str):
                safe_id = _safe_plugin_id(pid)
                if safe_id:
                    out.append(safe_id)
    # stable output for deterministic JSON/testing
    return sorted(set(out))


def _dependency_points(
    dep_id: str,
    *,
    data_dir: Path,
    today: date,
    prefer_real: bool,
) -> tuple[int, dict[str, Any]]:
    """Compute per-dependency risk points plus a compact details blob."""
    # Advisories
    advisories = _load_advisories_for_plugin(dep_id, data_dir, prefer_real=prefer_real)
    advisory_count = len(advisories)

    advisory_dates: list[date] = []
    for rec in advisories:
        d = _parse_date(str(rec.get("published_date", "")).strip())
        if d:
            advisory_dates.append(d)

    latest_adv = max(advisory_dates) if advisory_dates else None
    recent_365 = bool(latest_adv and (today - latest_adv).days <= 365)

    max_cvss: float | None = None
    for rec in advisories:
        ms = _advisory_record_max_cvss(rec)
        if ms is not None and (max_cvss is None or ms > max_cvss):
            max_cvss = ms

    # Dependency plugin snapshot (optional) for warnings/maintenance
    dep_snapshot = _load_plugin_snapshot(dep_id, data_dir)
    active_warn = 0
    total_warn = 0
    if dep_snapshot and isinstance(dep_snapshot, dict):
        api = dep_snapshot.get("plugin_api") or {}
        sec_warnings = api.get("securityWarnings") or []
        if isinstance(sec_warnings, list):
            total_warn = len(sec_warnings)
            active_warn = sum(
                1 for w in sec_warnings if isinstance(w, dict) and w.get("active") is True
            )

    # Healthscore (optional)
    hs = _load_healthscore_record(dep_id, data_dir)
    hs_value = hs.get("value") if isinstance(hs, dict) else None

    # Points (simple + explainable, capped later at the aggregate level)
    points = 0
    reasons: list[str] = []

    if advisory_count:
        adv_pts = min(10, advisory_count * 2)  # +2/advisory, cap 10
        points += adv_pts
        reasons.append(f"{advisory_count} advisories (+{adv_pts}).")

    if max_cvss is not None:
        sev_pts = 0
        if max_cvss >= 9.0:
            sev_pts = 6
        elif max_cvss >= 7.0:
            sev_pts = 4
        elif max_cvss >= 4.0:
            sev_pts = 2
        points += sev_pts
        if sev_pts:
            reasons.append(f"Max CVSS {max_cvss:.1f} (+{sev_pts}).")

    if recent_365:
        points += 3
        reasons.append("Recent advisory within 365d (+3).")

    if active_warn:
        warn_pts = min(10, active_warn * 5)
        points += warn_pts
        reasons.append(f"Active security warnings: {active_warn} (+{warn_pts}).")

    if hs_value is not None:
        try:
            hv = float(hs_value)
            hv = max(0.0, min(100.0, hv))
            hs_pts = int(round((100.0 - hv) / 25.0))  # 0..4
            hs_pts = max(0, min(4, hs_pts))
            if hs_pts:
                points += hs_pts
                reasons.append(f"Health score {hv:.0f} (+{hs_pts}).")
        except (TypeError, ValueError):
            hv = None

    details: dict[str, Any] = {
        "plugin_id": dep_id,
        "advisory_count": advisory_count,
        "latest_advisory_date": latest_adv.isoformat() if latest_adv else None,
        "recent_advisory_365d": recent_365,
        "max_cvss": max_cvss,
        "security_warning_count": total_warn,
        "active_security_warning_count": active_warn,
        "healthscore": hs_value,
        "risk_points": points,
        "reasons": reasons,
    }
    return points, details


def _load_healthscore_record(plugin_id: str, data_dir: Path) -> dict[str, Any] | None:
    safe_id = _safe_plugin_id(plugin_id)
    if safe_id is None:
        return None

    base = _safe_join_under(data_dir, "healthscore")

    per_plugin = _safe_join_under(base, "plugins", f"{safe_id}.healthscore.json")
    if per_plugin.exists():
        try:
            payload = json.loads(per_plugin.read_text(encoding="utf-8"))
            rec = payload.get("record") if isinstance(payload, dict) else None
            if isinstance(rec, dict):
                return {
                    "value": rec.get("value") if "value" in rec else rec.get("score"),
                    "date": rec.get("date") or rec.get("updated") or rec.get("timestamp"),
                    "details": rec.get("details") if "details" in rec else rec,
                    "collected_at": payload.get("collected_at"),
                }
        except (OSError, json.JSONDecodeError):
            return None

    agg_candidates = [
        _safe_join_under(base, "plugins.healthscore.json"),
        _safe_join_under(base, "plugins", "plugins.healthscore.json"),
    ]
    for agg in agg_candidates:
        if not agg.exists():
            continue
        try:
            payload = json.loads(agg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = None
        if not isinstance(payload, dict):
            continue
        recmap = payload.get("record")
        if isinstance(recmap, dict):
            r = recmap.get(safe_id)
            if isinstance(r, dict):
                return {
                    "value": r.get("value") if "value" in r else r.get("score"),
                    "date": r.get("date") or r.get("updated") or r.get("timestamp"),
                    "details": r.get("details") if "details" in r else r,
                    "collected_at": payload.get("collected_at"),
                }

    return None


def _healthscore_to_risk_points(value: Any) -> int | None:
    """Convert a 0..100 health score (higher is healthier) into 0..20 risk points."""
    try:
        v = float(value)
    except Exception:
        return None
    # clamp to sane range
    if v < 0:
        v = 0.0
    if v > 100:
        v = 100.0
    # 100 -> 0 pts, 0 -> 20 pts (linear)
    pts = int(round((100.0 - v) / 5.0))
    return max(0, min(20, pts))


# ---------------------------------------------------------------------------
# Component score ceilings — each domain contributes at most this many points.
# The ceilings sum to 100, making the score directly interpretable.
# ---------------------------------------------------------------------------

_CAP_ADVISORY_HISTORY = 30  # prior advisory count + recency
_CAP_ADVISORY_SEVERITY = 15  # CVSS-based severity across advisories
_CAP_STALENESS = 20  # commit + release staleness
_CAP_ACTIVE_WARNINGS = 15  # active Jenkins security warnings
_CAP_GOVERNANCE = 10  # presence/absence of governance artifacts
_CAP_DEPENDENCY = 5  # dependency risk (reduced — secondary signal)
_CAP_HEALTH_SCORE = 5  # Jenkins plugin health score (now a minor signal)
# Total ceiling: 100


def _load_swh_features(plugin_id: str, data_dir: Path) -> dict[str, Any]:
    """Load SWH Athena features for a plugin, returning an empty dict on failure."""
    try:
        from canary.build.features_bundle import _load_software_heritage_features

        return _load_software_heritage_features(plugin_id, data_dir, backend="athena")
    except Exception:
        return {}


def _staleness_points(
    days_since_commit: int | float | None,
    days_since_release: int | float | None,
) -> tuple[int, list[str]]:
    """
    Compute staleness risk points (0.._CAP_STALENESS) and reasons.

    Uses whichever staleness signal is available and most informative.
    Commit staleness is weighted more heavily than release staleness because
    a plugin can ship infrequent releases while still being actively maintained,
    but no commits at all is a strong signal of abandonment.
    """
    reasons: list[str] = []
    points = 0

    # Commit staleness (primary signal — strongest predictor per ablation results)
    if days_since_commit is not None:
        try:
            dsc = int(days_since_commit)
        except (TypeError, ValueError):
            dsc = None
        if dsc is not None:
            if dsc > 1825:  # > 5 years
                pts = 16
                label = f"{dsc // 365} years"
            elif dsc > 1095:  # > 3 years
                pts = 12
                label = f"{dsc // 365} years"
            elif dsc > 730:  # > 2 years
                pts = 9
                label = f"{dsc // 365} years"
            elif dsc > 365:  # > 1 year
                pts = 6
                label = f"{dsc // 30} months"
            elif dsc > 180:  # 6-12 months
                pts = 3
                label = f"{dsc // 30} months"
            else:
                pts = 0
                label = f"{dsc} days"

            if pts > 0:
                reasons.append(
                    f"Last commit was {label} ago — elevated maintenance staleness risk (+{pts})."
                )
            else:
                reasons.append(f"Recent commit activity ({label} ago) suggests active maintenance.")
            points += pts

    # Release staleness (secondary signal — penalises only extreme inactivity
    # and only when commit data is unavailable or also stale)
    if days_since_release is not None:
        try:
            dsr = int(days_since_release)
        except (TypeError, ValueError):
            dsr = None
        if dsr is not None and dsr > 730:  # > 2 years without a release
            # Only add release staleness points if they exceed what commits already gave us
            rel_pts = min(8, dsr // 365 * 3)
            if rel_pts > points:  # avoid double-counting
                bonus = rel_pts - points
                if bonus > 0:
                    points += bonus
                    reasons.append(
                        f"No release in over {dsr // 365} year(s) (+{bonus} additional staleness)."
                    )
        elif days_since_release is not None:
            try:
                dsr2 = int(days_since_release)
                if dsr2 <= 180:
                    reasons.append("Recent release activity supports active maintenance.")
            except (TypeError, ValueError):
                pass

    return min(_CAP_STALENESS, points), reasons


def _governance_points(swh: dict[str, Any]) -> tuple[int, list[str]]:
    """
    Compute governance risk points (0.._CAP_GOVERNANCE) from SWH flags.

    Missing governance artifacts are risk indicators, especially for plugins
    that handle sensitive operations (auth, credentials, SCM integration).
    Points are awarded for *absence* of protective artifacts.
    """
    if not swh.get("swh_present"):
        return 0, []

    reasons: list[str] = []
    points = 0

    # Absence of a SECURITY.md means no disclosed vulnerability reporting process
    if not swh.get("swh_has_security_md"):
        points += 3
        reasons.append("No SECURITY.md — vulnerability reporting process undocumented (+3).")

    # Absence of automated dependency management (Dependabot / GitHub Actions)
    has_automation = swh.get("swh_has_dependabot") or swh.get("swh_has_github_actions")
    if not has_automation:
        points += 3
        reasons.append(
            "No Dependabot or GitHub Actions detected — limited automated maintenance (+3)."
        )

    # Absence of a test directory is a code quality / review-discipline signal
    if not swh.get("swh_has_tests_directory"):
        points += 2
        reasons.append("No test directory detected — reduced code review discipline signal (+2).")

    # Absence of a changelog makes it harder to audit what changed between releases
    if not swh.get("swh_has_changelog"):
        points += 2
        reasons.append("No changelog detected — release transparency limited (+2).")

    return min(_CAP_GOVERNANCE, points), reasons


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
        *_advisory_candidates(data_dir, plugin_id, prefer_real=True),
    ]

    if not prefer_real:
        # In sample mode, prefer sample over real if both exist.
        candidates = _advisory_candidates(data_dir, plugin_id, prefer_real=False)

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
    real: bool = False,
) -> ScoreResult:
    """
    Heuristic risk scorer for a Jenkins plugin.

    Score is the sum of six capped components, each with a defined ceiling
    that together sum to 100.  This makes the score directly interpretable:
    the reasons list identifies which components contributed and how much.

    Components and ceilings:
      Advisory history & recency  — up to 30 pts
      Advisory severity (CVSS)    — up to 15 pts
      Maintenance staleness        — up to 20 pts
      Active security warnings     — up to 15 pts
      Governance signals           — up to 10 pts
      Dependency risk              — up to  5 pts
      Health score                 — up to  5 pts
    """
    plugin_id = _safe_plugin_id(
        canonicalize_plugin_id(plugin.lower().strip(), data_dir=_resolved_base_dir())
    )
    if plugin_id is None:
        raise ValueError(f"Invalid plugin id: {plugin!r}")

    base_dir = _resolved_base_dir()
    today = datetime.now(tz=UTC).date()
    reasons: list[str] = []
    features: dict[str, Any] = {}

    # ── 1. Advisory history & recency (cap: _CAP_ADVISORY_HISTORY = 30) ──────
    advisories = _load_advisories_for_plugin(plugin_id, base_dir, prefer_real=real)
    advisory_count = len(advisories)
    features["advisory_count"] = advisory_count

    advisory_dates: list[date] = []
    for rec in advisories:
        d = _parse_date(str(rec.get("published_date", "")).strip())
        if d:
            advisory_dates.append(d)

    latest_date: date | None = max(advisory_dates) if advisory_dates else None
    features["latest_advisory_date"] = latest_date.isoformat() if latest_date else None
    features["days_since_latest_advisory"] = (today - latest_date).days if latest_date else None

    within_90 = sum(1 for d in advisory_dates if (today - d).days <= 90)
    within_365 = sum(1 for d in advisory_dates if (today - d).days <= 365)
    features["advisory_within_90d"] = within_90
    features["advisory_within_365d"] = within_365
    features["had_advisory_within_365d"] = within_365 > 0

    if advisory_count > 0:
        history_pts = min(15, advisory_count * 2)  # +2 per advisory, cap 15
        recency_pts = min(15, within_90 * 10 + max(0, within_365 - within_90) * 5)
        advisory_history_pts = min(_CAP_ADVISORY_HISTORY, history_pts + recency_pts)
        score_advisory_history = advisory_history_pts

        reasons.append(
            f"{advisory_count} prior advisory record(s) — "
            f"history +{history_pts}, recency +{recency_pts} "
            f"({within_90} within 90d, {within_365} within 365d); "
            f"component total +{advisory_history_pts} (cap {_CAP_ADVISORY_HISTORY})."
        )
    else:
        score_advisory_history = 0
        reasons.append("No advisories found in local dataset.")

    # ── 2. Advisory severity / CVSS (cap: _CAP_ADVISORY_SEVERITY = 15) ───────
    max_cvss_overall: float | None = None
    severity_raw = 0
    for rec in advisories:
        ms = _advisory_record_max_cvss(rec)
        if ms is not None and (max_cvss_overall is None or ms > max_cvss_overall):
            max_cvss_overall = ms
        label = _cvss_base_score_to_label(_advisory_record_max_cvss(rec))
        severity_raw += _SEVERITY_BONUS.get(str(label), 0)

    features["max_cvss_base_score_observed"] = max_cvss_overall
    features["max_cvss_severity_label_observed"] = (
        _cvss_base_score_to_label(max_cvss_overall) if max_cvss_overall is not None else None
    )

    score_advisory_severity = min(_CAP_ADVISORY_SEVERITY, severity_raw)
    if score_advisory_severity > 0:
        sev_label = features["max_cvss_severity_label_observed"]
        reasons.append(
            f"Advisory severity (max CVSS {max_cvss_overall:.1f} — {sev_label}): "
            f"+{score_advisory_severity} (cap {_CAP_ADVISORY_SEVERITY})."
        )

    # ── 3. Maintenance staleness (cap: _CAP_STALENESS = 20) ──────────────────
    # Load SWH data — primary staleness signal
    swh = _load_swh_features(plugin_id, base_dir)
    features["swh_present"] = swh.get("swh_present", False)
    features["swh_days_since_last_commit"] = swh.get("swh_days_since_last_commit")
    features["swh_commit_count"] = swh.get("swh_commit_count", 0)
    features["swh_has_security_md"] = swh.get("swh_has_security_md", False)
    features["swh_has_dependabot"] = swh.get("swh_has_dependabot", False)
    features["swh_has_github_actions"] = swh.get("swh_has_github_actions", False)
    features["swh_has_tests_directory"] = swh.get("swh_has_tests_directory", False)
    features["swh_has_changelog"] = swh.get("swh_has_changelog", False)
    features["swh_security_fix_commit_count"] = swh.get("swh_security_fix_commit_count", 0)

    # Load snapshot for release staleness (secondary signal)
    snapshot = _load_plugin_snapshot(plugin_id, base_dir)
    features["has_plugin_snapshot"] = snapshot is not None

    days_since_release: int | None = None
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
            sum(1 for w in sec_warnings if (w or {}).get("active") is True), default=0
        )

        release_ts = _parse_iso_datetime(str(api.get("releaseTimestamp", "")).strip())
        features["release_timestamp"] = release_ts.isoformat() if release_ts else None
        if release_ts:
            days_since_release = (datetime.now(UTC) - release_ts).days
            features["days_since_release"] = days_since_release
            reasons.append(f"Latest release: {release_ts.date().isoformat()}.")

    score_staleness, staleness_reasons = _staleness_points(
        swh.get("swh_days_since_last_commit"), days_since_release
    )
    reasons.extend(staleness_reasons)

    # ── 4. Active security warnings (cap: _CAP_ACTIVE_WARNINGS = 15) ─────────
    active_warn = features.get("active_security_warning_count", 0)
    score_active_warnings = min(_CAP_ACTIVE_WARNINGS, active_warn * 8)
    if active_warn > 0:
        reasons.append(
            f"{active_warn} active Jenkins security warning(s): "
            f"+{score_active_warnings} (cap {_CAP_ACTIVE_WARNINGS})."
        )
    elif features.get("security_warning_count", 0) > 0:
        reasons.append(
            f"{features['security_warning_count']} historical security warning(s) — "
            "none currently active."
        )

    # ── 5. Governance signals (cap: _CAP_GOVERNANCE = 10) ────────────────────
    score_governance, governance_reasons = _governance_points(swh)
    reasons.extend(governance_reasons)

    # ── 6. Dependency risk (cap: _CAP_DEPENDENCY = 5) ────────────────────────
    features.setdefault("dependency_plugins", [])
    features.setdefault("dependency_total", 0)
    features.setdefault("dependency_risk_points", 0)
    features.setdefault(
        "dependency_risk_summary",
        {
            "deps_with_any_advisory": 0,
            "deps_with_recent_advisory_365d": 0,
            "deps_with_active_warning": 0,
            "worst_dep_max_cvss": None,
            "worst_dep_id": None,
            "worst_dep_latest_advisory_date": None,
        },
    )
    features.setdefault(
        "dependency_missing_data",
        {
            "snapshot_missing": 0,
            "advisories_missing": 0,
            "healthscore_missing": 0,
        },
    )
    features.setdefault("dependency_details_top", [])

    raw_dep_points = 0
    if snapshot and isinstance(snapshot, dict):
        dep_ids = _extract_dependency_plugin_ids(snapshot)
        features["dependency_plugins"] = dep_ids
        features["dependency_total"] = len(dep_ids)

        dep_points_pairs: list[tuple[int, dict[str, Any]]] = []
        missing_snap = missing_adv = missing_hs = 0
        worst_dep_id: str | None = None
        worst_dep_cvss: float | None = None
        worst_dep_latest: str | None = None
        deps_with_any_adv = deps_with_recent_adv = deps_with_active_warn = 0

        for dep_id in dep_ids:
            pts, det = _dependency_points(dep_id, data_dir=base_dir, today=today, prefer_real=real)
            dep_points_pairs.append((pts, det))
            if _load_plugin_snapshot(dep_id, base_dir) is None:
                missing_snap += 1
            adv_candidates = _advisory_candidates(base_dir, dep_id, prefer_real=real)
            if adv_candidates and not any(p.exists() for p in adv_candidates):
                missing_adv += 1
            if _load_healthscore_record(dep_id, base_dir) is None:
                missing_hs += 1
            if int(det.get("advisory_count", 0)) > 0:
                deps_with_any_adv += 1
            if det.get("recent_advisory_365d") is True:
                deps_with_recent_adv += 1
            if int(det.get("active_security_warning_count", 0) or 0) > 0:
                deps_with_active_warn += 1
            mcv = det.get("max_cvss")
            if isinstance(mcv, (int, float)) and (
                worst_dep_cvss is None or float(mcv) > worst_dep_cvss
            ):
                worst_dep_cvss = float(mcv)
                worst_dep_id = dep_id
                worst_dep_latest = det.get("latest_advisory_date")

        dep_points_pairs.sort(key=lambda x: (x[0], x[1].get("max_cvss") or 0), reverse=True)
        top_n = 5
        dep_details = [
            d for _, d in dep_points_pairs[:top_n] if int(d.get("risk_points", 0) or 0) > 0
        ]
        raw_dep_points = sum(int(p) for p, _ in dep_points_pairs[:top_n])

        features["dependency_risk_points"] = raw_dep_points
        features["dependency_risk_summary"] = {
            "deps_with_any_advisory": deps_with_any_adv,
            "deps_with_recent_advisory_365d": deps_with_recent_adv,
            "deps_with_active_warning": deps_with_active_warn,
            "worst_dep_max_cvss": worst_dep_cvss,
            "worst_dep_id": worst_dep_id,
            "worst_dep_latest_advisory_date": worst_dep_latest,
        }
        features["dependency_missing_data"] = {
            "snapshot_missing": missing_snap,
            "advisories_missing": missing_adv,
            "healthscore_missing": missing_hs,
        }
        features["dependency_details_top"] = dep_details

        if dep_ids and (deps_with_any_adv or deps_with_active_warn):
            dep_msg = f"{deps_with_any_adv} of {len(dep_ids)} dep(s) have advisories"
            if worst_dep_id and worst_dep_cvss is not None:
                dep_msg += f"; worst: {worst_dep_id} (CVSS {worst_dep_cvss:.1f})"
            reasons.append(f"Dependency risk: {dep_msg}.")

    score_dependency = min(_CAP_DEPENDENCY, raw_dep_points // 4)

    # ── 7. Health score (cap: _CAP_HEALTH_SCORE = 5) ─────────────────────────
    features.setdefault("healthscore_value", None)
    features.setdefault("healthscore_date", None)
    features.setdefault("healthscore_collected_at", None)

    hs = _load_healthscore_record(plugin_id, base_dir)
    score_health = 0
    if hs is not None:
        features["healthscore_value"] = hs.get("value")
        features["healthscore_date"] = hs.get("date")
        features["healthscore_collected_at"] = hs.get("collected_at")
        raw_hs_pts = _healthscore_to_risk_points(hs.get("value"))
        if raw_hs_pts is not None:
            # Scale the 0-20 raw points down to the new 0-5 ceiling
            score_health = min(_CAP_HEALTH_SCORE, raw_hs_pts // 4)
            if score_health > 0:
                reasons.append(
                    f"Plugin health score {hs.get('value')}/100 — "
                    f"below-average maintenance posture (+{score_health})."
                )
            else:
                reasons.append(
                    f"Plugin health score {hs.get('value')}/100 — acceptable maintenance posture."
                )

    # ── Final score ───────────────────────────────────────────────────────────
    score = (
        score_advisory_history
        + score_advisory_severity
        + score_staleness
        + score_active_warnings
        + score_governance
        + score_dependency
        + score_health
    )

    # Record component breakdown in features for UI display
    features["score_components"] = {
        "advisory_history": score_advisory_history,
        "advisory_severity": score_advisory_severity,
        "staleness": score_staleness,
        "active_warnings": score_active_warnings,
        "governance": score_governance,
        "dependency": score_dependency,
        "health_score": score_health,
    }

    if score == 0:
        score = 5
        reasons.append("No risk signals matched — baseline default applied.")

    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin_id, score=score, reasons=tuple(reasons), features=features)
