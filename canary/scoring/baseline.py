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
                pid = pid.strip()
                if pid:
                    out.append(pid)
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
    """Load a healthscore record for a plugin.

    Supports two layouts:
      1) Per-plugin files (collector output):
         <data_dir>/healthscore/plugins/<plugin_id>.healthscore.json
         { "plugin_id": ..., "collected_at": ..., "record": {...} }

      2) Aggregated file (optional / imported):
         <data_dir>/healthscore/plugins.healthscore.json
         { "collected_at": ..., "plugin_id": "plugins", "record": { "<plugin_id>": {...}, ... } }

    Returns a dict with keys:
      - value: int|float|None (0..100-ish)
      - date: str|None
      - details: Any
      - collected_at: str|None
    """
    base = data_dir / "healthscore"

    # 1) Per-plugin
    per_plugin = base / "plugins" / f"{plugin_id}.healthscore.json"
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
        except Exception:
            return None

    # 2) Aggregated
    # Support both:
    #   <data_dir>/healthscore/plugins.healthscore.json
    #   <data_dir>/healthscore/plugins/plugins.healthscore.json   (common collector output)
    agg_candidates = [
        base / "plugins.healthscore.json",
        base / "plugins" / "plugins.healthscore.json",
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
            r = recmap.get(plugin_id)
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

    # Dependency-risk defaults (present even if snapshot is missing)
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

        # --- New: dependency plugin risk (from local datasets) ---
        dep_ids = _extract_dependency_plugin_ids(snapshot)
        features["dependency_plugins"] = dep_ids
        features["dependency_total"] = len(dep_ids)

        dep_details: list[dict[str, Any]] = []
        missing_snap = 0
        missing_adv = 0
        missing_hs = 0

        worst_dep_id: str | None = None
        worst_dep_cvss: float | None = None
        worst_dep_latest: str | None = None
        deps_with_any_adv = 0
        deps_with_recent_adv_365d = 0
        deps_with_active_warn = 0

        dep_points_pairs: list[tuple[int, dict[str, Any]]] = []
        for dep_id in dep_ids:
            pts, det = _dependency_points(
                dep_id,
                data_dir=Path(data_dir),
                today=today,
                prefer_real=real,
            )
            dep_points_pairs.append((pts, det))

            # missing-data counts (best-effort)
            if _load_plugin_snapshot(dep_id, Path(data_dir)) is None:
                missing_snap += 1
            if not _load_advisories_for_plugin(dep_id, Path(data_dir), prefer_real=real):
                # Note: empty list can mean "no advisories" OR "missing file".
                # We treat it as missing if the expected file doesn't exist.
                adv_path_real = Path(data_dir) / "advisories" / f"{dep_id}.advisories.real.jsonl"
                adv_path_sample = (
                    Path(data_dir) / "advisories" / f"{dep_id}.advisories.sample.jsonl"
                )
                adv_path_alt = Path(data_dir) / "advisories" / f"{dep_id}.advisories.jsonl"
                if not (
                    adv_path_real.exists() or adv_path_sample.exists() or adv_path_alt.exists()
                ):
                    missing_adv += 1
            if _load_healthscore_record(dep_id, Path(data_dir)) is None:
                missing_hs += 1

            if det.get("advisory_count", 0) and int(det.get("advisory_count", 0)) > 0:
                deps_with_any_adv += 1
            if det.get("recent_advisory_365d") is True:
                deps_with_recent_adv_365d += 1
            if int(det.get("active_security_warning_count", 0) or 0) > 0:
                deps_with_active_warn += 1

            mcv = det.get("max_cvss")
            if isinstance(mcv, (int, float)):
                if worst_dep_cvss is None or float(mcv) > worst_dep_cvss:
                    worst_dep_cvss = float(mcv)
                    worst_dep_id = dep_id
                    worst_dep_latest = det.get("latest_advisory_date")

        # Summarize + cap: only count top-N risky deps to avoid explosion.
        dep_points_pairs.sort(key=lambda x: (x[0], x[1].get("max_cvss") or 0), reverse=True)
        top_n = 5
        dep_details = [
            d for _, d in dep_points_pairs[:top_n] if int(d.get("risk_points", 0) or 0) > 0
        ]

        dep_points_sum = sum(int(p) for p, _ in dep_points_pairs[:top_n])
        dep_points = max(0, min(20, dep_points_sum))
        features["dependency_risk_points"] = dep_points
        features["dependency_risk_summary"] = {
            "deps_with_any_advisory": deps_with_any_adv,
            "deps_with_recent_advisory_365d": deps_with_recent_adv_365d,
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

        # Score contribution
        score += dep_points

        # Human-readable reasons (keep it tight)
        if dep_ids:
            reasons.append(f"Dependency plugins: {len(dep_ids)} declared.")
            if deps_with_any_adv or deps_with_active_warn:
                if worst_dep_id and worst_dep_cvss is not None:
                    reasons.append(
                        f"Dependency risk: {deps_with_any_adv} deps have advisories; "
                        f"worst is {worst_dep_id} (CVSS {worst_dep_cvss:.1f}"
                        + (f", latest {worst_dep_latest}" if worst_dep_latest else "")
                        + ")."
                    )
                else:
                    reasons.append(
                        f"Dependency risk: {deps_with_any_adv} deps have advisories; "
                        f"{deps_with_active_warn} deps have active warnings."
                    )
            if dep_points > 0:
                reasons.append(
                    f"Dependency risk contribution: +{dep_points} point(s) "
                    f"(cap 20; top {top_n} deps)."
                )

    # --- New: plugin health score (plugin-health.jenkins.io) ---
    features.setdefault("healthscore_value", None)
    features.setdefault("healthscore_date", None)
    features.setdefault("healthscore_collected_at", None)

    hs = _load_healthscore_record(plugin_id, Path(data_dir))
    if hs is not None:
        features["healthscore_value"] = hs.get("value")
        features["healthscore_date"] = hs.get("date")
        features["healthscore_collected_at"] = hs.get("collected_at")

        pts = _healthscore_to_risk_points(hs.get("value"))
        if pts is not None:
            score += pts
            reasons.append(
                f"Health score: {hs.get('value')} "
                f"(higher is healthier; +{pts} risk point(s), max 20)."
            )
        else:
            reasons.append("Health score record present but value was not parseable.")
    else:
        reasons.append("No health score record found in local dataset (yet).")
    if score == 0:
        score = 5
        reasons.append("No heuristics matched (baseline default).")

    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin, score=score, reasons=tuple(reasons), features=features)
