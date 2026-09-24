"""
tools/latest_forecast.py
========================
Apply the frozen champion fold model to the newest month of the panel and
write the forecast the web console's Score tab shows.

This is inference with a recorded model: nothing is trained, no label is
read, and no recorded result changes. The default model is the champion's
last out-of-time fold (trained on months before 2025-11, labels as known
2025-12); the panel defaults to the one that run recorded in its
rolling_backtest.json.

Usage
-----
    docker compose run --rm canary python tools/latest_forecast.py

    # score a specific month, or a newer unlabeled panel file
    python tools/latest_forecast.py --month 2026-06
    python tools/latest_forecast.py \\
        --in-path data/processed/features/plugins.monthly.features.enriched.jsonl

Output: data/processed/results/latest_forecast.json (override with --out).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from canary.train import forecast as fc  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--model-dir", default=fc.DEFAULT_MODEL_DIR)
    ap.add_argument("--in-path", default=None, help="panel JSONL (default: the run's own)")
    ap.add_argument("--month", default=None, help="YYYY-MM (default: newest month in the panel)")
    ap.add_argument("--out", default=fc.DEFAULT_OUT_PATH)
    args = ap.parse_args()

    model_dir = Path(args.model_dir)
    if not (model_dir / "model.joblib").is_file():
        print(f"no model.joblib under {model_dir}", file=sys.stderr)
        return 2
    in_path = Path(args.in_path or fc.run_in_path(model_dir) or "")
    if not in_path.is_file():
        print(f"panel not found: {in_path!s} (pass --in-path)", file=sys.stderr)
        return 2

    payload = fc.forecast_month(model_dir, in_path, args.month)
    fc.write_forecast(payload, Path(args.out))
    print(
        f"forecast for {payload['month']} from {payload['run_name']}/fold_{payload['fold']} "
        f"({payload['model_name']}): {payload['n_plugins']} plugins scored; "
        f"panel months {payload['panel_months'][0]}..{payload['panel_months'][1]}"
    )
    top = sorted(payload["scores"].items(), key=lambda kv: kv[1]["rank"])[:10]
    for pid, entry in top:
        print(f"  {entry['rank']:>4}  {entry['prob']:.3f}  {pid}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
