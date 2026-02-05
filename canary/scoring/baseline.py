from __future__ import annotations

from dataclasses import dataclass
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


def score_plugin_baseline(plugin: str) -> ScoreResult:
    name = plugin.lower().strip()
    score = 0
    reasons: list[str] = []
    features: dict[str, Any] = {"matched_core_keywords": [], "matched_scm_keywords": []}

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

    if score == 0:
        score = 5
        reasons.append("No heuristics matched (baseline default).")

    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin, score=score, reasons=tuple(reasons), features=features)
