from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScoreResult:
    plugin: str
    score: int
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"plugin": self.plugin, "score": self.score, "reasons": self.reasons}


def score_plugin_baseline(plugin: str) -> dict[str, Any]:
    """
    Transparent baseline scoring.
    Replace/add features as you start collecting real signals.

    Current baseline (demo):
    - If plugin name suggests core/security-critical keywords: +20
    - If plugin name suggests SCM/integration: +10
    - Otherwise: +5
    """
    name = plugin.lower().strip()
    score = 0
    reasons: list[str] = []

    core_keywords = ("credentials", "security", "auth", "oauth", "saml", "ldap")
    scm_keywords = ("git", "svn", "scm", "github", "bitbucket")

    if any(k in name for k in core_keywords):
        score += 20
        reasons.append("Plugin name suggests auth/security surface area (baseline heuristic).")

    if any(k in name for k in scm_keywords):
        score += 10
        reasons.append("Plugin name suggests source control/integration surface area (baseline heuristic).")

    if score == 0:
        score = 5
        reasons.append("No special heuristics matched (baseline default).")

    # Clamp to 0–100
    score = max(0, min(100, score))
    return ScoreResult(plugin=plugin, score=score, reasons=reasons).to_dict()
