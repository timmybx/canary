"""``canary build`` — dataset building command group."""

from __future__ import annotations

import argparse
from typing import Any

from canary.build.advisories_events import build_advisories_events
from canary.build.features_bundle import build_feature_bundle
from canary.build.monthly_features import build_monthly_feature_bundle
from canary.build.monthly_labels import build_monthly_labels


def _cmd_build_advisories_events(args: argparse.Namespace) -> int:
    _ = build_advisories_events(
        data_raw_dir=args.data_raw_dir,
        out_path=args.out,
    )
    print(f"Wrote advisory events to {args.out}")
    return 0


def _cmd_build_feature_bundle(args: argparse.Namespace) -> int:
    records = build_feature_bundle(
        data_raw_dir=args.data_raw_dir,
        registry_path=args.registry,
        out_path=args.out,
        out_csv_path=args.out_csv,
        summary_path=args.summary_out,
        software_heritage_backend=args.software_heritage_backend,
    )
    print(f"Wrote {len(records)} feature rows to {args.out}")
    if args.out_csv:
        print(f"Wrote feature CSV to {args.out_csv}")
    if args.summary_out:
        print(f"Wrote feature summary to {args.summary_out}")
    return 0


def _cmd_build_monthly_feature_bundle(args: argparse.Namespace) -> int:
    records = build_monthly_feature_bundle(
        data_raw_dir=args.data_raw_dir,
        registry_path=args.registry,
        start_month=args.start,
        end_month=args.end,
        out_path=args.out,
        out_csv_path=args.out_csv,
        summary_path=args.summary_out,
        software_heritage_backend=args.software_heritage_backend,
    )
    print(f"Wrote {len(records)} monthly feature rows to {args.out}")
    print(f"Wrote monthly feature CSV to {args.out_csv}")
    print(f"Wrote monthly feature summary to {args.summary_out}")
    return 0


def _cmd_build_monthly_labels(args: argparse.Namespace) -> int:
    horizons = tuple(int(x.strip()) for x in args.horizons.split(",") if x.strip())

    rows = build_monthly_labels(
        in_path=args.in_path,
        out_path=args.out_path,
        out_csv_path=args.out_csv_path,
        summary_path=args.summary_path,
        horizons=horizons,
    )

    print(f"Wrote {len(rows)} labeled monthly rows to {args.out_path}")
    if args.out_csv_path:
        print(f"Wrote labeled monthly CSV to {args.out_csv_path}")
    if args.summary_path:
        print(f"Wrote labeled monthly summary to {args.summary_path}")

    return 0


def register(subparsers: Any) -> None:
    """Register the ``build`` command group."""
    build = subparsers.add_parser("build", help="Build processed datasets from raw data")
    build_subparsers = build.add_subparsers(dest="build_cmd", required=True)

    adv_events = build_subparsers.add_parser(
        "advisories-events",
        help="Normalize/dedupe advisories JSONL files into a single events stream",
    )
    adv_events.add_argument(
        "--data-raw-dir", default="data/raw", help="Raw data root containing advisories/"
    )
    adv_events.add_argument(
        "--out",
        default="data/processed/events/advisories.jsonl",
        help="Output path for deduped events JSONL",
    )
    adv_events.set_defaults(func=_cmd_build_advisories_events)

    features = build_subparsers.add_parser(
        "features",
        help="Join raw collector outputs into a unified per-plugin feature bundle",
    )
    features.add_argument(
        "--data-raw-dir", default="data/raw", help="Raw data root containing collected artifacts"
    )
    features.add_argument(
        "--registry",
        default="data/raw/registry/plugins.jsonl",
        help="Registry JSONL used as the plugin universe",
    )
    features.add_argument(
        "--out",
        default="data/processed/features/plugins.features.jsonl",
        help="Output JSONL path for unified plugin feature rows",
    )
    features.add_argument(
        "--out-csv",
        default="data/processed/features/plugins.features.csv",
        help="Optional CSV companion output path",
    )
    features.add_argument(
        "--summary-out",
        default="data/processed/features/plugins.features.summary.json",
        help="Optional summary JSON path",
    )
    features.add_argument(
        "--software-heritage-backend",
        choices=["athena", "api"],
        default="athena",
        help="Software Heritage backend to read from",
    )
    features.set_defaults(func=_cmd_build_feature_bundle)

    build_monthly_labels_parser = build_subparsers.add_parser(
        "monthly-labels",
        help="Build future advisory labels for monthly plugin feature rows",
    )
    build_monthly_labels_parser.add_argument(
        "--in-path",
        default="data/processed/features/plugins.monthly.features.jsonl",
        help="Input monthly feature JSONL",
    )
    build_monthly_labels_parser.add_argument(
        "--out-path",
        default="data/processed/features/plugins.monthly.labeled.jsonl",
        help="Output labeled JSONL",
    )
    build_monthly_labels_parser.add_argument(
        "--out-csv-path",
        default="data/processed/features/plugins.monthly.labeled.csv",
        help="Optional output labeled CSV",
    )
    build_monthly_labels_parser.add_argument(
        "--summary-path",
        default="data/processed/features/plugins.monthly.labeled.summary.json",
        help="Optional output summary JSON",
    )
    build_monthly_labels_parser.add_argument(
        "--horizons",
        default="1,3,6,12",
        help="Comma-separated advisory horizons in months",
    )
    build_monthly_labels_parser.set_defaults(func=_cmd_build_monthly_labels)

    monthly_features = build_subparsers.add_parser(
        "monthly-features",
        help="Build a dense per-plugin-per-month feature dataset from collected artifacts",
    )
    monthly_features.add_argument(
        "--data-raw-dir", default="data/raw", help="Raw data root containing collected artifacts"
    )
    monthly_features.add_argument(
        "--registry",
        default="data/raw/registry/plugins.jsonl",
        help="Registry JSONL used as the plugin universe",
    )
    monthly_features.add_argument(
        "--start",
        required=True,
        help="Start month in YYYY-MM format",
    )
    monthly_features.add_argument(
        "--end",
        required=True,
        help="End month in YYYY-MM format",
    )
    monthly_features.add_argument(
        "--out",
        default="data/processed/features/plugins.monthly.features.jsonl",
        help="Output JSONL path for unified monthly feature rows",
    )
    monthly_features.add_argument(
        "--out-csv",
        default="data/processed/features/plugins.monthly.features.csv",
        help="Optional CSV companion output path",
    )
    monthly_features.add_argument(
        "--summary-out",
        default="data/processed/features/plugins.monthly.features.summary.json",
        help="Optional summary JSON path",
    )
    monthly_features.add_argument(
        "--software-heritage-backend",
        choices=["athena", "api"],
        default="athena",
        help="Software Heritage backend to read from",
    )
    monthly_features.set_defaults(func=_cmd_build_monthly_feature_bundle)
