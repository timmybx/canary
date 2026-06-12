"""``canary score`` / ``score-ml`` — plugin scoring commands."""

from __future__ import annotations

import argparse
import json
from typing import Any

from canary.scoring.baseline import score_plugin_baseline


def _cmd_score(args: argparse.Namespace) -> int:
    plugin = args.plugin.strip()
    result = score_plugin_baseline(plugin, real=bool(args.real))

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"Plugin: {result.plugin}")
        print(f"Score:  {result.score}/100")
        print("Why:")
        for line in result.reasons:
            print(f" - {line}")
    return 0


def _cmd_score_ml(args: argparse.Namespace) -> int:
    """CLI handler for `canary score-ml <plugin>`."""
    from canary.scoring.ml import load_ml_scorer, score_plugin_ml

    plugin = args.plugin.strip()
    model_dir = args.model_dir

    # Load the scorer — give a clear message if training hasn't been run yet
    try:
        scorer = load_ml_scorer(model_dir)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", flush=True)
        print("Tip: run `canary train baseline` first to produce a trained model.")
        return 1

    # Score the plugin
    try:
        result = score_plugin_ml(
            plugin,
            scorer=scorer,
            data_raw_dir=args.data_dir,
            top_drivers=args.top_drivers,
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0

    # Human-readable output
    risk_icons = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
    icon = risk_icons.get(result.risk_category, "⚪")

    print(f"Plugin:        {result.plugin}")
    print(f"ML Score:      {result.probability:.4f}  ({result.probability * 100:.1f}%)")
    print(f"Risk category: {icon}  {result.risk_category}")
    print(f"Model:         {result.model_dir}")
    print(f"Scored at:     {result.scored_at}")
    print()

    if result.drivers:
        print("Top contributing features:")
        dir_icons = {"increases_risk": "▲", "decreases_risk": "▼", "neutral": "—"}
        for d in result.drivers:
            arrow = dir_icons.get(d.direction, "—")
            val_str = f"{d.value:.4g}" if d.value is not None else "n/a"
            print(f"  {arrow}  {d.name:<55}  {val_str}")
    else:
        print("No driver information available.")

    return 0


def register(subparsers: Any) -> None:
    """Register the ``score`` and ``score-ml`` commands."""
    score = subparsers.add_parser("score", help="Score a component/plugin")
    score.add_argument("plugin", help="Plugin short name (e.g. workflow-cps)")
    score.add_argument("--json", action="store_true", help="Output JSON instead of text")
    score.add_argument(
        "--data-dir", default="data/raw", help="Directory containing collected datasets"
    )
    score.add_argument(
        "--real", action="store_true", help="Prefer *.advisories.real.jsonl if present"
    )
    score.set_defaults(func=_cmd_score)

    score_ml = subparsers.add_parser(
        "score-ml",
        help="Score a plugin using the trained ML model",
    )
    score_ml.add_argument("plugin", help="Plugin short name (e.g. cucumber-reports)")
    score_ml.add_argument(
        "--model-dir",
        default="data/processed/models/baseline_6m",
        help=(
            "Directory containing model.joblib and feature_columns.json "
            "(default: data/processed/models/baseline_6m)"
        ),
    )
    score_ml.add_argument(
        "--data-dir",
        default="data/raw",
        help="Root directory of collected raw data (default: data/raw)",
    )
    score_ml.add_argument(
        "--top-drivers",
        type=int,
        default=10,
        help="Number of top contributing features to display (default: 10)",
    )
    score_ml.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON instead of human-readable text",
    )
    score_ml.set_defaults(func=_cmd_score_ml)
