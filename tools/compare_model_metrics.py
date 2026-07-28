"""
tools/compare_model_metrics.py
===============================
Compare model metrics before and after a pipeline change (e.g. the advisory
zero-fill imputation correction), so the effect of a retrain is measured
rather than eyeballed.

Workflow
--------
1. BEFORE retraining, snapshot the small artifacts:

       tar czf models_backup_$(date +%Y%m%d).tgz \\
           data/processed/models/*/metrics.json \\
           data/processed/models/*/feature_selection.json \\
           data/processed/models/*/precision_at_k.json

2. Retrain, then extract the snapshot somewhere (e.g. /tmp/before/) and run:

       python tools/compare_model_metrics.py \\
           --before /tmp/before/data/processed/models \\
           --after  data/processed/models

Reports per model: average precision, ROC-AUC, and the delta, plus the
largest movers, so the praxis can state precisely how much the correction
changed reported results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

METRIC_KEYS = ("average_precision", "roc_auc")


def _load(models_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for d in sorted(models_dir.iterdir()):
        m = d / "metrics.json"
        if m.exists():
            j = json.loads(m.read_text(encoding="utf-8"))
            out[d.name] = {k: j.get(k) for k in METRIC_KEYS}
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Diff model metrics across two artifact trees.")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    before = _load(Path(args.before))
    after = _load(Path(args.after))
    names = sorted(set(before) | set(after))

    rows: list[dict[str, Any]] = []
    header = (
        f"{'model':<38} {'AP before':>10} {'AP after':>10} {'dAP':>8} "
        f"{'AUC before':>11} {'AUC after':>10} {'dAUC':>8}"
    )
    print(header)
    print("-" * len(header))
    for n in names:
        b, a = before.get(n, {}), after.get(n, {})
        entry: dict[str, Any] = {"model": n}
        cells = []
        for k in ("average_precision", "roc_auc"):
            bv, av = b.get(k), a.get(k)
            d = (av - bv) if (bv is not None and av is not None) else None
            entry[f"{k}_before"] = bv
            entry[f"{k}_after"] = av
            entry[f"{k}_delta"] = round(d, 4) if d is not None else None
            fmt = lambda v: f"{v:.4f}" if v is not None else "-"  # noqa: E731
            cells.append((fmt(bv), fmt(av), f"{d:+.4f}" if d is not None else "-"))
        (apb, apa, apd), (aucb, auca, aucd) = cells
        print(f"{n:<38} {apb:>10} {apa:>10} {apd:>8} {aucb:>11} {auca:>10} {aucd:>8}")
        rows.append(entry)

    movers = sorted(
        (r for r in rows if r.get("average_precision_delta") is not None),
        key=lambda r: -abs(r["average_precision_delta"]),
    )[:5]
    if movers:
        print("\nLargest AP movers:")
        for r in movers:
            print(f"  {r['model']:<38} dAP {r['average_precision_delta']:+.4f}")
    deltas = [
        r["average_precision_delta"] for r in rows if r.get("average_precision_delta") is not None
    ]
    if deltas:
        print(
            f"\nAcross {len(deltas)} models: max |dAP| = "
            f"{max(abs(d) for d in deltas):.4f}, mean dAP = {sum(deltas) / len(deltas):+.4f}"
        )

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"Saved: {out}")


if __name__ == "__main__":
    main()
