"""Shared path-safety helpers for the canary collectors package.

These utilities enforce path traversal prevention by:
  1. Validating plugin identifiers against an allowlist regex before use in
     file-name construction.
  2. Resolving constructed paths and checking they remain under their intended
     base directory.
"""

from __future__ import annotations

import re
from pathlib import Path

_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def safe_plugin_id(plugin_id: str) -> str | None:
    """Return a filesystem-safe plugin id or None when the value is invalid."""
    candidate = plugin_id.strip()
    if not candidate:
        return None
    if not _PLUGIN_ID_RE.fullmatch(candidate):
        return None
    return candidate


def safe_join_under(base: Path, *parts: str) -> Path:
    """Join *parts* under *base*, raising ``ValueError`` if the resolved path escapes *base*."""
    base_resolved = base.resolve()
    candidate = base_resolved.joinpath(*parts).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError("Resolved path escapes base directory") from exc
    return candidate
