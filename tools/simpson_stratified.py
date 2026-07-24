"""
tools/simpson_stratified.py
============================
Stratified companion to the H1 odds ratio test: test whether the marginal
reversal has a Simpson's-paradox structure under a single attention proxy.
(Result: it does not flip within strata; it attenuates monotonically —
see tools/README.md for the interpretation.)

The marginal test (tools/h1_odds_ratio.py) shows staleness is associated with
*lower* advisory odds. The proposed mechanism is surveillance bias: advisory
publication requires attention, and stale plugins concentrate where attention
is absent. If that mechanism is right, then *within* strata of comparable
attention the association should weaken or reverse, while the pooled view
shows the protective direction.

This tool stratifies plugin-months by an attention proxy
(gharchive_unique_actors: distinct GitHub actors observed for the plugin's
repository in that month) into three strata:

    none    no observed actors (unwatched)
    lower   nonzero, at or below the median of nonzero values
    higher  above the median of nonzero values

and reports exposed (stale) vs unexposed advisory rates, rate ratios, and
odds ratios per stratum and pooled.

Usage
-----
    # inside the container
    python tools/simpson_stratified.py --json data/processed/results/simpson_stratified.json

    # commit staleness instead of release staleness
    python tools/simpson_stratified.py --factor commits

Output feeds tools/make_figures.py (figure: simpson).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
TARGET_COL = "label_advisory_within_6m"
ATTENTION_COL = "gharchive_unique_actors"
TEST_START = "2025-05"

FACTORS = {
    "releases": ("gharchive_months_since_release_tag", 12.0, ">="),
    "commits": ("swh_days_since_last_commit", 365.0, ">="),
}


def _odds_ratio(a: int, b: int, c: int, d: int) -> tuple[float, float, float]:
    if 0 in (a, b, c, d):
        a2, b2, c2, d2 = a + 0.5, b + 0.5, c + 0.5, d + 0.5
    else:
        a2, b2, c2, d2 = float(a), float(b), float(c), float(d)
    or_ = (a2 * d2) / (b2 * c2)
    se = math.sqrt(1 / a2 + 1 / b2 + 1 / c2 + 1 / d2)
    return or_, math.exp(math.log(or_) - 1.96 * se), math.exp(math.log(or_) + 1.96 * se)


def _summarize(name: str, cells: list[int]) -> dict[str, Any]:
    a, b, c, d = cells  # exposed_pos, exposed_neg, unexposed_pos, unexposed_neg
    entry: dict[str, Any] = {
        "stratum": name,
        "exposed_pos": a,
        "exposed_neg": b,
        "unexposed_pos": c,
        "unexposed_neg": d,
        "n": a + b + c + d,
    }
    if min(a + b, c + d) == 0:
        entry["error"] = "empty exposure arm"
        return entry
    exp_rate = a / (a + b)
    unexp_rate = c / (c + d)
    or_, lo, hi = _odds_ratio(a, b, c, d)
    entry.update(
        exposed_rate=round(exp_rate, 5),
        unexposed_rate=round(unexp_rate, 5),
        rate_ratio=round(exp_rate / unexp_rate, 3) if unexp_rate else None,
        odds_ratio=round(or_, 3),
        ci_low=round(lo, 3),
        ci_high=round(hi, 3),
    )
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attention-stratified staleness vs advisory rates (Simpson's paradox check)."
    )
    parser.add_argument("--data", default=IN_PATH)
    parser.add_argument("--factor", choices=sorted(FACTORS), default="releases")
    parser.add_argument("--window", choices=("train", "test", "all"), default="train")
    parser.add_argument("--test-start", default=TEST_START)
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    col, threshold, _ = FACTORS[args.factor]

    # Pass 1 (streaming): keep only the minimal tuple per usable row.
    rows: list[tuple[float, bool, bool]] = []  # (attention, exposed, positive)
    skipped_missing = 0
    with Path(args.data).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            month = str(r.get("month", ""))
            in_test = month >= args.test_start
            if (args.window == "train" and in_test) or (args.window == "test" and not in_test):
                continue
            val = r.get(col)
            if val is None:
                skipped_missing += 1
                continue
            attention = float(r.get(ATTENTION_COL) or 0)
            exposed = float(val) >= threshold
            positive = int(r.get(TARGET_COL) or 0) == 1
            rows.append((attention, exposed, positive))

    nonzero = sorted(att for att, _, _ in rows if att > 0)
    median_nonzero = nonzero[len(nonzero) // 2] if nonzero else 0.0

    def stratum_of(attention: float) -> str:
        if attention <= 0:
            return "none"
        return "lower" if attention <= median_nonzero else "higher"

    labels = ("none", "lower", "higher")
    cells = {s: [0, 0, 0, 0] for s in (*labels, "pooled")}
    for attention, exposed, positive in rows:
        for s in (stratum_of(attention), "pooled"):
            idx = (0 if positive else 1) if exposed else (2 if positive else 3)
            cells[s][idx] += 1

    results = {
        "factor": f"{col} >= {threshold:g}",
        "attention_col": ATTENTION_COL,
        "median_nonzero_attention": median_nonzero,
        "window": args.window,
        "n_rows": len(rows),
        "rows_skipped_missing_factor": skipped_missing,
        "strata": [_summarize(s, cells[s]) for s in labels],
        "pooled": _summarize("pooled", cells["pooled"]),
    }

    header = (
        f"{'stratum':<8} {'n':>7} {'stale rate':>11} {'fresh rate':>11} "
        f"{'rate ratio':>11} {'OR':>7} {'95% CI':>16}"
    )
    print(
        f"Factor: {results['factor']} | attention: {ATTENTION_COL} "
        f"(median nonzero = {median_nonzero:g}) | window: {args.window}\n"
    )
    print(header)
    print("-" * len(header))
    for e in (*results["strata"], results["pooled"]):
        if "error" in e:
            print(f"{e['stratum']:<8} {e['n']:>7} {e['error']}")
            continue
        ci = f"[{e['ci_low']}, {e['ci_high']}]"
        print(
            f"{e['stratum']:<8} {e['n']:>7} {e['exposed_rate']:>11.4f} "
            f"{e['unexposed_rate']:>11.4f} {e['rate_ratio']:>11} {e['odds_ratio']:>7} {ci:>16}"
        )
    print(
        "\nSimpson's pattern is present when within-stratum rate ratios exceed 1 "
        "(or exceed the pooled ratio) while the pooled ratio is below 1."
    )

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Saved: {out}")


if __name__ == "__main__":
    main()
