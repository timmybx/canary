"""
tools/h1_odds_ratio.py
=======================
Direct empirical test of hypothesis H1.

H1 states: "Infrequent releases or small contributor teams raise six month
vulnerability odds by at least fifty percent."  The SHAP analysis in Chapter 4
establishes association and direction, but not an odds ratio.  This tool
computes the odds ratio directly from the labeled monthly dataset using
simple 2x2 contingency tables, so H1 can be adjudicated against its own
stated criterion (OR >= 1.5).

Factors tested (each as exposed vs. unexposed):
    releases    gharchive_months_since_release_tag >= --release-months (default 12)
    team        gharchive_unique_human_actors_trailing_6m <= --team-size (default 2)
    either      the H1 disjunction (releases OR team), over rows where both
                factors are observable
    commits     swh_days_since_last_commit >= --commit-days (default 365)
                (supplementary: commit staleness is not literally in H1 but is
                the maintenance signal SHAP ranks highest)

Rows where a factor's value is missing (None) are excluded from that factor's
table and counted in the output, so "not observed" is never treated as
"not present".

The dataset is streamed line by line (it is ~1.3 GB), accumulating counts in
a single pass; memory use is constant.

Odds ratios use the Woolf method for 95% confidence intervals, with a
Haldane-Anscombe correction (+0.5 to all cells) when any cell is zero.

Usage
-----
    # inside the container
    python tools/h1_odds_ratio.py

    # custom thresholds or dataset
    python tools/h1_odds_ratio.py --release-months 6 --team-size 1
    python tools/h1_odds_ratio.py --json data/processed/results/h1_odds.json

Output
------
    Per factor and per window (train / test / all): 2x2 cell counts,
    exposed and unexposed advisory rates, odds ratio, 95% CI, and whether
    the H1 criterion (OR >= 1.5) is met.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
TARGET_COL = "label_advisory_within_6m"
TEST_START = "2025-05"
H1_CRITERION = 1.5

RELEASE_COL = "gharchive_months_since_release_tag"
TEAM_COL = "gharchive_unique_human_actors_trailing_6m"
COMMIT_COL = "swh_days_since_last_commit"


class Table:
    """2x2 contingency counts for one factor in one window."""

    __slots__ = ("a", "b", "c", "d", "missing")

    def __init__(self) -> None:
        self.a = self.b = self.c = self.d = self.missing = 0

    def add(self, exposed: bool | None, positive: bool) -> None:
        if exposed is None:
            self.missing += 1
        elif exposed:
            if positive:
                self.a += 1
            else:
                self.b += 1
        elif positive:
            self.c += 1
        else:
            self.d += 1


def _odds_ratio(a: int, b: int, c: int, d: int) -> tuple[float, float, float]:
    """OR and Woolf 95% CI, with Haldane-Anscombe correction on zero cells."""
    if 0 in (a, b, c, d):
        a2, b2, c2, d2 = a + 0.5, b + 0.5, c + 0.5, d + 0.5
    else:
        a2, b2, c2, d2 = float(a), float(b), float(c), float(d)
    or_ = (a2 * d2) / (b2 * c2)
    se = math.sqrt(1 / a2 + 1 / b2 + 1 / c2 + 1 / d2)
    lo = math.exp(math.log(or_) - 1.96 * se)
    hi = math.exp(math.log(or_) + 1.96 * se)
    return or_, lo, hi


def _summarize(name: str, window: str, t: Table, n_rows: int) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "factor": name,
        "window": window,
        "n_rows": n_rows,
        "exposed_pos": t.a,
        "exposed_neg": t.b,
        "unexposed_pos": t.c,
        "unexposed_neg": t.d,
        "rows_excluded_missing": t.missing,
    }
    if min(t.a + t.b, t.c + t.d) == 0:
        entry["error"] = "empty exposure arm; odds ratio undefined"
        return entry
    or_, lo, hi = _odds_ratio(t.a, t.b, t.c, t.d)
    entry.update(
        exposed_rate=round(t.a / (t.a + t.b), 5),
        unexposed_rate=round(t.c / (t.c + t.d), 5),
        odds_ratio=round(or_, 3),
        ci_low=round(lo, 3),
        ci_high=round(hi, 3),
        h1_criterion_met=bool(lo >= 1.0 and or_ >= H1_CRITERION),
        note="criterion: OR >= 1.5 with CI excluding 1.0",
    )
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(description="Direct odds ratio test of hypothesis H1.")
    parser.add_argument("--data", default=IN_PATH, help="labeled monthly JSONL")
    parser.add_argument("--test-start", default=TEST_START, help="first test month (YYYY-MM)")
    parser.add_argument("--release-months", type=float, default=12.0)
    parser.add_argument("--team-size", type=float, default=2.0)
    parser.add_argument("--commit-days", type=float, default=365.0)
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    factor_names = [
        f"releases (>= {args.release_months:g} months since release tag)",
        f"team (<= {args.team_size:g} human actors, trailing 6m)",
        "either (H1 disjunction, both factors observable)",
        f"commits (>= {args.commit_days:g} days since last commit, supplementary)",
    ]
    tables: dict[str, list[Table]] = {w: [Table() for _ in factor_names] for w in ("train", "test")}
    n_rows = {"train": 0, "test": 0}

    with Path(args.data).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            window = "train" if str(r.get("month", "")) < args.test_start else "test"
            n_rows[window] += 1
            positive = int(r.get(TARGET_COL) or 0) == 1

            rel = r.get(RELEASE_COL)
            team = r.get(TEAM_COL)
            com = r.get(COMMIT_COL)

            rel_exp = None if rel is None else float(rel) >= args.release_months
            team_exp = None if team is None else float(team) <= args.team_size
            either_exp = None if rel is None or team is None else bool(rel_exp) or bool(team_exp)
            com_exp = None if com is None else float(com) >= args.commit_days

            for t, exp in zip(
                tables[window], (rel_exp, team_exp, either_exp, com_exp), strict=True
            ):
                t.add(exp, positive)

    results: list[dict[str, Any]] = []
    for window in ("train", "test"):
        for name, t in zip(factor_names, tables[window], strict=True):
            results.append(_summarize(name, window, t, n_rows[window]))
    # "all" = train + test, summed
    for i, name in enumerate(factor_names):
        combined = Table()
        for w in ("train", "test"):
            src = tables[w][i]
            combined.a += src.a
            combined.b += src.b
            combined.c += src.c
            combined.d += src.d
            combined.missing += src.missing
        results.append(_summarize(name, "all", combined, sum(n_rows.values())))

    header = (
        f"{'window':<6} {'factor':<52} {'OR':>7} {'95% CI':>16} "
        f"{'exp rate':>9} {'unexp':>7} {'H1?':>4}"
    )
    print(header)
    print("-" * len(header))
    for e in results:
        if "error" in e:
            print(f"{e['window']:<6} {e['factor']:<52} {e['error']}")
            continue
        ci = f"[{e['ci_low']}, {e['ci_high']}]"
        met = "yes" if e["h1_criterion_met"] else "no"
        print(
            f"{e['window']:<6} {e['factor']:<52} {e['odds_ratio']:>7} {ci:>16} "
            f"{e['exposed_rate']:>9} {e['unexposed_rate']:>7} {met:>4}"
        )
    print(
        "\nCells are plugin-month observations; exposed/unexposed rates are "
        f"P({TARGET_COL}=1). Missing factor values are excluded per factor."
    )

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Saved: {out}")


if __name__ == "__main__":
    main()
