"""
crossval/pypi/02_build_monthly.py
==================================
Build a monthly labeled dataset from:
  - data/pypi/raw/package_universe.jsonl  (produced by 00_collect_universe.py)
  - data/pypi/raw/advisories.jsonl        (produced by 01_collect_osv.py)

The package universe determines which packages are included (top-N by
downloads that have a resolvable GitHub URL).  Advisory history is then
joined in — packages with no prior advisories get zero values for all
advisory features, exactly as unseen plugins behave in the Jenkins dataset.

This design eliminates the selection bias from the previous approach, which
only included packages that appeared in at least one OSV advisory.  Filtering
on "has a GitHub URL" is a data-availability criterion, not a risk criterion,
so it does not inflate the positive rate or distort the label distribution.

Usage
-----
    python crossval/pypi/02_build_monthly.py

Input
-----
    data/pypi/raw/package_universe.jsonl   — package registry (from 00_...)
    data/pypi/raw/advisories.jsonl         — OSV advisories  (from 01_...)

Output
------
    data/pypi/processed/monthly_labeled.jsonl

Dataset design
--------------
Unit of analysis  : (package_id, month)
Package universe  : all packages in package_universe.jsonl
                    (top-N PyPI packages by downloads with a GitHub URL)
Month range       : TRAIN_START (2018-01) to TEST_END (2025-10).
                    The last six months (2025-05 to 2025-10) serve as the
                    test window, matching the Jenkins evaluation design.
Features (all strictly ≤ observation month, no future leakage)
    advisory_count_to_date     int   — cumulative advisories published before
                                       the start of this month
    advisory_cve_count_to_date int   — cumulative distinct CVEs before this month
    advisory_max_cvss_to_date  float | None — highest CVSS score seen to date
Label
    label_advisory_within_6m   int (0/1) — any advisory in (month, month+6]
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration — match Jenkins evaluation parameters
# ---------------------------------------------------------------------------

TRAIN_START = (2018, 1)  # first observation month (inclusive)
TEST_END = (2025, 10)  # last observation month (inclusive)
HORIZON_M = 6  # prediction horizon in months

UNIVERSE_PATH = Path("data/pypi/raw/package_universe.jsonl")
ADV_PATH = Path("data/pypi/raw/advisories.jsonl")
OUT_PATH = Path("data/pypi/processed/monthly_labeled.jsonl")


# ---------------------------------------------------------------------------
# Month arithmetic
# ---------------------------------------------------------------------------


def _month_range(start: tuple[int, int], end: tuple[int, int]) -> list[tuple[int, int]]:
    months = []
    y, m = start
    ey, em = end
    while (y, m) <= (ey, em):
        months.append((y, m))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return months


def _add_months(ym: tuple[int, int], n: int) -> tuple[int, int]:
    y, m = ym
    m += n
    while m > 12:
        m -= 12
        y += 1
    return (y, m)


def _month_key(ym: tuple[int, int]) -> str:
    return f"{ym[0]:04d}-{ym[1]:02d}"


def _date_to_ym(d: str) -> tuple[int, int] | None:
    """Parse YYYY-MM-DD into (year, month). Returns None on failure."""
    try:
        dt = date.fromisoformat(d)
        return (dt.year, dt.month)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------


def _build_advisory_timeline(
    advisories: list[dict[str, Any]],
) -> dict[str, list[tuple[tuple[int, int], float | None, list[str]]]]:
    """
    For each package return a sorted list of (month, cvss, cve_ids) tuples,
    one entry per advisory.  Only packages with at least one advisory appear;
    packages in the universe with no advisories simply won't be in this dict
    (and will get zero feature values in the monthly builder).
    """
    timeline: dict[str, list[tuple[tuple[int, int], float | None, list[str]]]] = defaultdict(list)
    for rec in advisories:
        pkg = rec.get("package_id")
        pub = rec.get("published_date")
        if not pkg or not pub:
            continue
        ym = _date_to_ym(pub)
        if ym is None:
            continue
        cvss = rec.get("cvss")
        cvss = float(cvss) if isinstance(cvss, (int, float)) else None
        cves: list[str] = rec.get("cve_ids") or []
        timeline[pkg].append((ym, cvss, cves))

    for pkg in timeline:
        timeline[pkg].sort(key=lambda x: x[0])

    return dict(timeline)


def _advisory_features_to_date(
    entries: list[tuple[tuple[int, int], float | None, list[str]]],
    before_ym: tuple[int, int],
) -> dict[str, Any]:
    """
    Compute advisory features using only entries strictly before *before_ym*.
    Returns zero values when *entries* is empty (no advisory history).
    """
    count = 0
    max_cvss: float | None = None
    all_cves: set[str] = set()

    for ym, cvss, cves in entries:
        if ym >= before_ym:
            break
        count += 1
        all_cves.update(cves)
        if cvss is not None:
            max_cvss = cvss if max_cvss is None else max(max_cvss, cvss)

    return {
        "advisory_count_to_date": count,
        "advisory_cve_count_to_date": len(all_cves),
        "advisory_max_cvss_to_date": max_cvss,
    }


def _label(
    entries: list[tuple[tuple[int, int], float | None, list[str]]],
    obs_ym: tuple[int, int],
    horizon: int,
) -> int:
    """
    Return 1 if any advisory falls in (obs_ym, obs_ym + horizon] (exclusive
    of observation month, inclusive of horizon end month).
    """
    horizon_end = _add_months(obs_ym, horizon)
    for ym, _, __ in entries:
        if obs_ym < ym <= horizon_end:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    # --- Load package universe ---
    if not UNIVERSE_PATH.exists():
        raise FileNotFoundError(
            f"Universe file not found: {UNIVERSE_PATH}\nRun 00_collect_universe.py first."
        )

    universe: list[dict[str, Any]] = []
    with UNIVERSE_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                universe.append(json.loads(line))

    all_packages = sorted(r["package_id"] for r in universe)
    print(f"Universe: {len(all_packages):,} packages (from {UNIVERSE_PATH})")

    # --- Load advisories ---
    if not ADV_PATH.exists():
        raise FileNotFoundError(
            f"Advisory file not found: {ADV_PATH}\nRun 01_collect_osv.py first."
        )

    print(f"Reading {ADV_PATH} ...")
    advisories: list[dict[str, Any]] = []
    with ADV_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                advisories.append(json.loads(line))

    print(f"  {len(advisories):,} advisory records loaded")

    # Build per-package timelines (only for packages that have advisories)
    timeline = _build_advisory_timeline(advisories)

    # How many universe packages have at least one advisory?
    with_advisory = sum(1 for p in all_packages if p in timeline)
    without_advisory = len(all_packages) - with_advisory
    print(
        f"  {with_advisory:,} universe packages have >=1 advisory "
        f"({with_advisory / len(all_packages) * 100:.1f}%)"
    )
    print(
        f"  {without_advisory:,} universe packages have no advisory history "
        f"(all advisory features will be 0)"
    )

    # Generate all observation months
    months = _month_range(TRAIN_START, TEST_END)
    print(f"\nGenerating {len(months)} monthly observations × {len(all_packages):,} packages ...")
    print(f"  Estimated output rows: {len(months) * len(all_packages):,}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    total_rows = 0
    total_positives = 0
    _EMPTY: list[tuple[tuple[int, int], float | None, list[str]]] = []

    with OUT_PATH.open("w", encoding="utf-8") as f_out:
        for pkg in all_packages:
            # Packages with no advisory history get an empty timeline
            entries = timeline.get(pkg, _EMPTY)

            for obs_ym in months:
                features = _advisory_features_to_date(entries, obs_ym)
                label = _label(entries, obs_ym, HORIZON_M)

                row: dict[str, Any] = {
                    "package_id": pkg,
                    "month": _month_key(obs_ym),
                    **features,
                    f"label_advisory_within_{HORIZON_M}m": label,
                }
                f_out.write(json.dumps(row) + "\n")
                total_rows += 1
                total_positives += label

            if (all_packages.index(pkg) + 1) % 1000 == 0:
                pct = (all_packages.index(pkg) + 1) / len(all_packages) * 100
                print(
                    f"  [{all_packages.index(pkg) + 1:>5}/{len(all_packages)}  {pct:5.1f}%]  "
                    f"rows={total_rows:,}  positives={total_positives:,}"
                )

    print("\nDone.")
    print(f"  Rows written       : {total_rows:,}")
    print(f"  Positive labels    : {total_positives:,}")
    if total_rows:
        print(f"  Base rate          : {total_positives / total_rows:.4f}")
    print(f"  Output             : {OUT_PATH}")
    print(
        "\n  Note: base rate reflects full ecosystem (not pre-filtered to "
        "packages with advisory history).  Expected to be lower than the "
        "previous advisory-universe approach but more comparable to Jenkins."
    )


if __name__ == "__main__":
    main()
