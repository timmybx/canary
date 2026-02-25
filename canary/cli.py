# cli.py

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Iterable
from pathlib import Path

from canary.build.advisories_events import build_advisories_events
from canary.collectors.github_plugin import collect_github_plugin_real
from canary.collectors.jenkins_advisories import collect_advisories_real, collect_advisories_sample
from canary.collectors.plugin_snapshot import collect_plugin_snapshot
from canary.collectors.plugins_registry import (
    collect_plugins_registry_real,
    collect_plugins_registry_sample,
)
from canary.scoring.baseline import score_plugin_baseline


def _nonempty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _iter_registry_plugin_ids(registry_path: Path) -> Iterable[str]:
    with registry_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            pid = (rec.get("plugin_id") or "").strip()
            if pid:
                yield pid


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


def _cmd_collect_registry(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / args.out_name
    raw_path = (out_dir / args.raw_out) if args.raw_out else None

    if args.real:
        registry, raw_pages = collect_plugins_registry_real(
            page_size=int(args.page_size),
            max_plugins=(int(args.max_plugins) if args.max_plugins is not None else None),
            timeout_s=float(args.timeout_s),
        )
        if raw_path is not None:
            raw_path.write_text(
                json.dumps(raw_pages, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    else:
        registry = collect_plugins_registry_sample()

    with out_path.open("w", encoding="utf-8") as f:
        for rec in registry:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"Wrote {len(registry)} plugin registry records to {out_path}")
    if raw_path is not None and args.real:
        print(f"Wrote raw registry pages to {raw_path}")
    return 0


def _cmd_collect_github(args: argparse.Namespace) -> int:
    plugin_id = args.plugin.strip()
    result = collect_github_plugin_real(
        plugin_id=plugin_id,
        data_dir=args.data_dir,
        out_dir=args.out_dir,
        timeout_s=float(args.timeout_s),
        max_pages=int(args.max_pages),
        commits_days=int(args.commits_days),
        overwrite=bool(args.overwrite),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_collect_enrich(args: argparse.Namespace) -> int:
    registry_path = Path(args.registry)

    if not registry_path.exists():
        raise SystemExit(f"ERROR: registry file not found: {registry_path}")

    data_raw = Path(args.data_dir)
    plugins_dir = data_raw / "plugins"
    advisories_dir = data_raw / "advisories"
    github_dir = data_raw / "github"

    plugins_dir.mkdir(parents=True, exist_ok=True)
    advisories_dir.mkdir(parents=True, exist_ok=True)
    github_dir.mkdir(parents=True, exist_ok=True)

    only = args.only
    do_snapshot = (only is None) or (only == "snapshot")
    do_advisories = (only is None) or (only == "advisories")
    do_github = (only is None) or (only == "github")

    max_plugins = int(args.max_plugins) if args.max_plugins is not None else None
    sleep_s = float(args.sleep)

    processed = 0
    snap_written = 0
    adv_written = 0
    gh_written = 0
    snap_skipped = 0
    adv_skipped = 0
    gh_skipped = 0
    errors = 0

    for plugin_id in _iter_registry_plugin_ids(registry_path):
        if max_plugins is not None and processed >= max_plugins:
            break

        processed += 1

        try:
            snapshot_path = plugins_dir / f"{plugin_id}.snapshot.json"
            if do_snapshot:
                if _nonempty(snapshot_path):
                    snap_skipped += 1
                else:
                    snapshot = collect_plugin_snapshot(
                        plugin_id=plugin_id,
                        repo_url=None,
                        real=args.real,
                    )
                    snapshot_path.write_text(
                        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8",
                    )
                    snap_written += 1

            advisories_path = advisories_dir / f"{plugin_id}.advisories.real.jsonl"
            if do_advisories:
                if _nonempty(advisories_path):
                    adv_skipped += 1
                else:
                    if not args.real:
                        raise SystemExit(
                            "ERROR: enrich advisories currently requires --real "
                            "(it fetches live advisory pages)"
                        )
                    records = collect_advisories_real(plugin_id=plugin_id, data_dir=str(data_raw))
                    with advisories_path.open("w", encoding="utf-8") as f:
                        for rec in records:
                            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    adv_written += 1

            # GitHub collection requires snapshot mapping (repo_url/scm_url)
            gh_index_path = github_dir / f"{plugin_id}.github_index.json"
            if do_github:
                if _nonempty(gh_index_path):
                    gh_skipped += 1
                else:
                    if not args.real:
                        raise SystemExit("ERROR: enrich github currently requires --real")
                    collect_github_plugin_real(
                        plugin_id=plugin_id,
                        data_dir=str(data_raw),
                        out_dir=str(github_dir),
                        timeout_s=float(args.github_timeout_s),
                        max_pages=int(args.github_max_pages),
                        commits_days=int(args.github_commits_days),
                        overwrite=False,
                    )
                    gh_written += 1

        except Exception as e:
            errors += 1
            print(f"[ERROR] {plugin_id}: {e}")

        if sleep_s > 0:
            time.sleep(sleep_s)

    print("Enrich summary")
    print(f"  Plugins processed:   {processed}")
    if do_snapshot:
        print(f"  Snapshots written:   {snap_written}")
        print(f"  Snapshots skipped:   {snap_skipped}")
    if do_advisories:
        print(f"  Advisories written:  {adv_written}")
        print(f"  Advisories skipped:  {adv_skipped}")
    if do_github:
        print(f"  GitHub written:      {gh_written}")
        print(f"  GitHub skipped:      {gh_skipped}")
    print(f"  Errors:              {errors}")

    return 0 if errors == 0 else 2


def _cmd_build_advisories_events(args: argparse.Namespace) -> int:
    _ = build_advisories_events(
        data_raw_dir=args.data_raw_dir,
        out_path=args.out,
    )
    print(f"Wrote advisory events to {args.out}")
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

    advisories = collect_sub.add_parser("advisories", help="Collect Jenkins advisories")
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
    advisories.add_argument("--real", action="store_true", help="Fetch live data from Jenkins")
    advisories.set_defaults(func=_cmd_collect_advisories)

    plugin = collect_sub.add_parser("plugin", help="Collect a plugin snapshot")
    plugin.add_argument("--id", required=True, help="Plugin short name (e.g., cucumber-reports)")
    plugin.add_argument("--out-dir", default="data/raw/plugins", help="Output directory")
    plugin.add_argument(
        "--repo-url",
        default=None,
        help="GitHub repo URL (optional; can be inferred/curated for pilots)",
    )
    plugin.add_argument("--real", action="store_true", help="Fetch live data (network)")
    plugin.set_defaults(func=_cmd_collect_plugin)

    registry = collect_sub.add_parser(
        "registry",
        help="Collect the current Jenkins plugin registry (the universe snapshot)",
    )
    registry.add_argument("--out-dir", default="data/raw/registry", help="Output directory")
    registry.add_argument("--out-name", default="plugins.jsonl", help="Output filename (JSONL)")
    registry.add_argument(
        "--raw-out", default=None, help="Optional filename to store raw pages (JSON)"
    )
    registry.add_argument("--page-size", default=500, help="Registry paging size (default: 500)")
    registry.add_argument("--max-plugins", default=None, help="Optional cap for quick tests")
    registry.add_argument("--timeout-s", default=30.0, help="Network timeout per request")
    registry.add_argument(
        "--real", action="store_true", help="Fetch live data from plugins.jenkins.io"
    )
    registry.set_defaults(func=_cmd_collect_registry)

    github = collect_sub.add_parser(
        "github",
        help="Collect raw GitHub API payloads for a plugin (requires plugin snapshot mapping)",
    )
    github.add_argument("--plugin", required=True, help="Plugin short name (e.g. workflow-cps)")
    github.add_argument(
        "--data-dir", default="data/raw", help="Raw dataset root (reads plugins/<id>.snapshot.json)"
    )
    github.add_argument(
        "--out-dir", default="data/raw/github", help="Output directory for GitHub JSON files"
    )
    github.add_argument("--timeout-s", default=20.0, help="Network timeout per request")
    github.add_argument(
        "--max-pages", default=5, help="Max pages for paginated endpoints (default: 5)"
    )
    github.add_argument(
        "--commits-days", default=365, help="Days back for commits list (default: 365)"
    )
    github.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing GitHub JSON files"
    )
    github.set_defaults(func=_cmd_collect_github)

    enrich = collect_sub.add_parser(
        "enrich",
        help="Batch-enrich plugins from the registry (snapshot + advisories + github) with resume",
    )
    enrich.add_argument(
        "--registry",
        default="data/raw/registry/plugins.jsonl",
        help="Path to registry JSONL",
    )
    enrich.add_argument(
        "--data-dir",
        default="data/raw",
        help="Raw data root (writes plugins/, advisories/, github/ beneath this)",
    )
    enrich.add_argument(
        "--only",
        choices=["snapshot", "advisories", "github"],
        default=None,
        help="Run only one stage (default: run all stages)",
    )
    enrich.add_argument("--max-plugins", default=None, help="Optional cap for quick tests")
    enrich.add_argument("--sleep", default=0.15, help="Sleep seconds between plugins")
    enrich.add_argument("--real", action="store_true", help="Fetch live data (recommended)")
    # GitHub tuning for batch runs
    enrich.add_argument("--github-timeout-s", default=20.0, help="GitHub timeout per request")
    enrich.add_argument("--github-max-pages", default=5, help="GitHub max pages per endpoint")
    enrich.add_argument("--github-commits-days", default=365, help="GitHub commits lookback days")
    enrich.set_defaults(func=_cmd_collect_enrich)

    build = sub.add_parser("build", help="Build processed datasets from raw data")
    build_sub = build.add_subparsers(dest="build_cmd", required=True)

    adv_events = build_sub.add_parser(
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

    score = sub.add_parser("score", help="Score a component/plugin")
    score.add_argument("plugin", help="Plugin short name (e.g. workflow-cps)")
    score.add_argument("--json", action="store_true", help="Output JSON instead of text")
    score.add_argument(
        "--data-dir", default="data/raw", help="Directory containing collected datasets"
    )
    score.set_defaults(func=_cmd_score)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
