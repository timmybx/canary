from __future__ import annotations

import argparse
import json
from pathlib import Path

from canary.collectors.jenkins_advisories import collect_advisories_sample
from canary.scoring.baseline import score_plugin_baseline


def _cmd_collect_advisories(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "jenkins_advisories.sample.jsonl"
    records = collect_advisories_sample()

    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Wrote {len(records)} records to {out_path}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    plugin = args.plugin.strip()
    result = score_plugin_baseline(plugin)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Plugin: {result['plugin']}")
        print(f"Score:  {result['score']}/100")
        print("Why:")
        for line in result["reasons"]:
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

    advisories = collect_sub.add_parser("advisories", help="Collect Jenkins advisories")
    advisories.add_argument("--out-dir", default="data/processed", help="Output directory")
    advisories.set_defaults(func=_cmd_collect_advisories)

    score = sub.add_parser("score", help="Score a component/plugin")
    score.add_argument("plugin", help="Plugin short name (e.g., workflow-cps)")
    score.add_argument("--json", action="store_true", help="Output JSON instead of text")
    score.set_defaults(func=_cmd_score)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
