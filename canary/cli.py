# cli.py

from __future__ import annotations

import argparse
import json
from pathlib import Path

from canary.collectors.jenkins_advisories import collect_advisories_real, collect_advisories_sample
from canary.collectors.plugin_snapshot import collect_plugin_snapshot  # NEW
from canary.scoring.baseline import score_plugin_baseline


def _cmd_collect_advisories(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plugin = args.plugin.strip() if args.plugin else None

    # Real mode currently requires a plugin id because it reads the plugin snapshot.
    if args.real and not plugin:
        raise SystemExit("ERROR: --real currently requires --plugin <plugin-id>")

    suffix = "real" if args.real else "sample"
    out_name = (
        f"{plugin}.advisories.{suffix}.jsonl" if plugin else f"jenkins_advisories.{suffix}.jsonl"
    )
    out_path = out_dir / out_name

    if args.real:
        if plugin is None:
            raise SystemExit("ERROR: --real currently requires --plugin <plugin-id>")
        plugin_id = plugin  # now a real str
        records = collect_advisories_real(plugin_id=plugin_id, data_dir=args.data_dir)
    else:
        records = collect_advisories_sample(plugin_id=plugin)

    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Wrote {len(records)} records to {out_path}")
    return 0


def _cmd_collect_plugin(args: argparse.Namespace) -> int:
    plugin_id = args.id.strip()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    snapshot = collect_plugin_snapshot(
        plugin_id=plugin_id,
        repo_url=args.repo_url,
        real=args.real,
    )

    out_path = out_dir / f"{plugin_id}.snapshot.json"
    out_path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Wrote snapshot to {out_path}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    plugin = args.plugin.strip()
    result = score_plugin_baseline(plugin, data_dir=args.data_dir)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(f"Plugin: {result.plugin}")
        print(f"Score:  {result.score}/100")
        print("Why:")
        for line in result.reasons:
            print(f" - {line}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="canary",
        description="CANARY: Component Anomaly & Near-term Advisory Risk Yardstick",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    collect = sub.add_parser("collect", help="Collect raw/processed data")
    collect_sub = collect.add_subparsers(dest="collect_cmd", required=True)

    advisories = collect_sub.add_parser(
        "advisories", help="Collect Jenkins advisories (sample stub)"
    )
    advisories.add_argument(
        "--plugin",
        default=None,
        help="Filter advisories to a single plugin id (e.g., cucumber-reports)",
    )
    advisories.add_argument(
        "--data-dir",
        default="data/raw",
        help="Dataset root (expects plugins/<id>.snapshot.json when using --real)",
    )
    advisories.add_argument("--out-dir", default="data/raw/advisories", help="Output directory")
    advisories.add_argument(
        "--real", action="store_true", help="Fetch live data from Jenkins (network)"
    )
    advisories.set_defaults(func=_cmd_collect_advisories)

    # NEW: collect plugin
    plugin = collect_sub.add_parser("plugin", help="Collect a plugin snapshot (pilot)")
    plugin.add_argument("--id", required=True, help="Plugin short name (e.g., cucumber-reports)")
    plugin.add_argument(
        "--out-dir",
        default="data/raw/plugins",
        help="Output directory for snapshot JSON",
    )
    plugin.add_argument(
        "--repo-url",
        default=None,
        help="GitHub repo URL (optional; can be inferred/curated for pilots)",
    )
    plugin.add_argument(
        "--real",
        action="store_true",
        help="Fetch live data (network). If omitted, returns a minimal curated snapshot.",
    )
    plugin.set_defaults(func=_cmd_collect_plugin)

    score = sub.add_parser("score", help="Score a component/plugin")
    score.add_argument("plugin", help="Plugin short name (e.g. workflow-cps)")
    score.add_argument("--json", action="store_true", help="Output JSON instead of text")
    score.add_argument(
        "--data-dir",
        default="data/raw",
        help="Directory containing collected datasets (e.g., advisories/...)",
    )

    score.set_defaults(func=_cmd_score)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
