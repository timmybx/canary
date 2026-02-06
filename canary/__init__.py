"""CANARY package.

This file intentionally keeps side effects to a minimum.

The CLI lives in :mod:`canary.cli` (invoked via the ``canary`` console script).
Here we only expose a small public API for programmatic use.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .scoring.baseline import ScoreResult, score_plugin_baseline

try:
    __version__ = version("canary")
except PackageNotFoundError:  # pragma: no cover
    # Package metadata may be unavailable when running from source without installation.
    __version__ = "0.0.0"

__all__ = [
    "__version__",
    "ScoreResult",
    "score_plugin_baseline",
]
