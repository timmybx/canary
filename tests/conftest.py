"""
Shared pytest fixtures for the canary test suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixture_data_dir() -> Path:
    """Return the path to tests/fixtures/data/raw.

    This directory contains trimmed, committed copies of real data files so
    that tests which exercise the full scoring pipeline do not depend on the
    gitignored ``data/raw/`` tree.
    """
    here = Path(__file__).parent
    path = here / "fixtures" / "data" / "raw"
    assert path.is_dir(), f"Fixture data directory not found: {path}"
    return path
