"""``canary train`` — model training command group."""

from __future__ import annotations

import argparse
from typing import Any

from canary.train.baseline import train_baseline


def _cmd_train_baseline(args: argparse.Namespace) -> int:
    extra_exclude = set()
    if args.exclude_cols:
        extra_exclude = {col.strip() for col in args.exclude_cols.split(",") if col.strip()}

    include_prefixes: tuple[str, ...] | None = None
    if args.include_prefixes:
        include_prefixes = tuple(
            prefix.strip() for prefix in args.include_prefixes.split(",") if prefix.strip()
        )

    metrics = train_baseline(
        in_path=args.in_path,
        target_col=args.target_col,
        out_dir=args.out_dir,
        test_start_month=args.test_start_month,
        extra_exclude=extra_exclude,
        include_prefixes=include_prefixes,
        model_name=args.model,
        split_strategy=args.split_strategy,
        group_col=args.group_col,
        test_fraction=args.test_fraction,
        random_seed=args.random_seed,
    )

    print(f"Trained baseline for target {metrics['target_col']}")
    print(f"Model:      {metrics['model_name']}")
    print(f"Train rows: {metrics['train_row_count']}  positives: {metrics['train_positive_count']}")
    print(f"Test rows:  {metrics['test_row_count']}  positives: {metrics['test_positive_count']}")
    print(f"Features:   {metrics['feature_count']}")
    print(f"ROC-AUC:    {metrics['roc_auc']}")
    print(f"AvgPrec:    {metrics['average_precision']}")
    print(f"Wrote metrics to {args.out_dir}/metrics.json")
    print(f"Wrote predictions to {args.out_dir}/test_predictions.csv")

    return 0


def _cmd_train_feature_select(args: argparse.Namespace) -> int:
    """CLI handler for `canary train feature-select`."""
    import logging

    from canary.train.feature_selection import DEFAULT_SUBSET_SIZES, run_feature_selection

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    subset_sizes: tuple[int, ...] = DEFAULT_SUBSET_SIZES
    if args.subset_sizes:
        try:
            subset_sizes = tuple(int(s.strip()) for s in args.subset_sizes.split(",") if s.strip())
        except ValueError as exc:
            print(f"Error: --subset-sizes must be comma-separated integers: {exc}")
            return 1

    print(f"Running feature selection study on model: {args.model_dir}")
    print(f"Dataset: {args.in_path}")
    print(f"Subset sizes: {subset_sizes} + full")
    print()

    result = run_feature_selection(
        model_dir=args.model_dir,
        in_path=args.in_path,
        target_col=args.target_col,
        test_start_month=args.test_start_month,
        split_strategy=args.split_strategy,
        subset_sizes=subset_sizes,
        group_col=args.group_col,
        test_fraction=args.test_fraction,
        random_seed=args.random_seed,
    )

    # Print summary
    full_ap = result.get("full_model_average_precision")
    full_n = result.get("full_model_feature_count")
    print()
    print(f"Full model: {full_n} features, AP = {full_ap:.4f}")
    print()
    header = (
        f"{'Subset':<12} {'Features':>8} {'Avg Precision':>14} {'% of Full':>10} {'H3 (≥90%)':>10}"
    )
    print(header)
    print("-" * 60)
    for res in result.get("subset_results", []):
        label = res.get("subset_label", "?")
        n = res.get("actual_feature_count", "?")
        ap = res.get("average_precision")
        ret = res.get("ap_retention_vs_full")
        h3 = res.get("meets_h3_threshold")
        ap_str = f"{ap:.4f}" if ap is not None else "  n/a"
        ret_str = f"{ret * 100:.1f}%" if ret is not None else "   —"
        h3_str = "✓" if h3 is True else ("—" if h3 is False else " ")
        print(f"{label:<12} {str(n):>8} {ap_str:>14} {ret_str:>10} {h3_str:>10}")

    print()
    h3_ok = result.get("h3_satisfied")
    h3_info = result.get("h3_smallest_qualifying_subset")
    if h3_ok and h3_info:
        print(
            f"H3 SATISFIED: {h3_info['size']}-feature model retains "
            f"{h3_info['ap_retention'] * 100:.1f}% of full-model AP "
            f"(AP = {h3_info['average_precision']:.4f})"
        )
    else:
        print("H3 NOT satisfied at any evaluated subset size.")

    print()
    print(f"Full results written to: {args.model_dir}/feature_selection.json")
    return 0


def register(subparsers: Any) -> None:
    """Register the ``train`` command group."""
    train_parser = subparsers.add_parser("train", help="Train models")
    train_subparsers = train_parser.add_subparsers(dest="train_command", required=True)

    train_baseline_parser = train_subparsers.add_parser(
        "baseline",
        help="Train a logistic regression baseline on labeled monthly plugin data",
    )
    train_baseline_parser.add_argument(
        "--in-path",
        default="data/processed/features/plugins.monthly.labeled.jsonl",
        help="Input labeled JSONL",
    )
    train_baseline_parser.add_argument(
        "--target-col",
        default="label_advisory_within_6m",
        help="Target label column",
    )
    train_baseline_parser.add_argument(
        "--out-dir",
        default="data/processed/models/baseline_6m",
        help="Directory for metrics/predictions outputs",
    )
    train_baseline_parser.add_argument(
        "--test-start-month",
        default="2025-10",
        help="First month to include in test split (YYYY-MM)",
    )
    train_baseline_parser.add_argument(
        "--exclude-cols",
        default="",
        help="Comma-separated additional columns to exclude from training",
    )
    train_baseline_parser.add_argument(
        "--include-prefixes",
        default="",
        help="Comma-separated feature name prefixes to include (for example: gharchive_,window_)",
    )
    train_baseline_parser.add_argument(
        "--model",
        default="logistic",
        help=(
            "Model to train. Available: logistic, random_forest, xgboost, lightgbm. "
            "xgboost and lightgbm require optional dependencies to be installed. "
            "(default: logistic)"
        ),
    )
    train_baseline_parser.add_argument(
        "--split-strategy",
        choices=["time", "group", "group_time"],
        default="time",
    )
    train_baseline_parser.add_argument("--group-col", default="plugin_id")
    train_baseline_parser.add_argument("--test-fraction", type=float, default=0.2)
    train_baseline_parser.add_argument("--random-seed", type=int, default=42)

    train_baseline_parser.set_defaults(func=_cmd_train_baseline)

    # ── feature-select subcommand ───────────────────────────────────────────
    fs_parser = train_subparsers.add_parser(
        "feature-select",
        help=(
            "Principled feature selection: rank features by SHAP global importance "
            "and evaluate AP retention across top-N subsets.  Provides an empirical "
            "test of H3."
        ),
    )
    fs_parser.add_argument(
        "--model-dir",
        default="data/processed/models/baseline_6m",
        help="Directory containing a trained model.joblib and feature_columns.json",
    )
    fs_parser.add_argument(
        "--in-path",
        default="data/processed/features/plugins.monthly.labeled.jsonl",
        help="Input labeled JSONL (same file used during training)",
    )
    fs_parser.add_argument(
        "--target-col",
        default="label_advisory_within_6m",
        help="Target label column (must match original training run)",
    )
    fs_parser.add_argument(
        "--test-start-month",
        default="2025-10",
        help="Test cutoff month YYYY-MM (must match original training run)",
    )
    fs_parser.add_argument(
        "--split-strategy",
        choices=["time", "group", "group_time"],
        default="time",
        help="Split strategy (must match original training run)",
    )
    fs_parser.add_argument(
        "--subset-sizes",
        default="",
        help=(
            "Comma-separated top-N subset sizes to evaluate "
            "(default: 5,10,15,20,30,50). Full feature set is always added."
        ),
    )
    fs_parser.add_argument("--group-col", default="plugin_id")
    fs_parser.add_argument("--test-fraction", type=float, default=0.2)
    fs_parser.add_argument("--random-seed", type=int, default=42)
    fs_parser.set_defaults(func=_cmd_train_feature_select)
