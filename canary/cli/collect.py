"""``canary collect`` — data collection command group."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from canary.cli._common import _iter_registry_plugin_ids, _nonempty, bulk_collect_loop
from canary.collectors.gharchive_history import collect_gharchive_history_real
from canary.collectors.github_plugin import collect_github_plugin_real
from canary.collectors.healthscore import collect_health_scores
from canary.collectors.jenkins_advisories import collect_advisories_real, collect_advisories_sample
from canary.collectors.plugin_snapshot import collect_plugin_snapshot
from canary.collectors.plugins_registry import (
    collect_plugins_registry_real,
    collect_plugins_registry_sample,
)
from canary.collectors.software_heritage_backend import (
    collect_software_heritage,
    default_out_dir_for_backend,
)


def _cmd_collect_advisories(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plugin = args.plugin.strip() if args.plugin else None
    suffix = "real" if args.real else "sample"

    # Single-plugin mode (backwards compatible).
    if plugin is not None:
        out_path = out_dir / f"{plugin}.advisories.{suffix}.jsonl"
        if args.real:
            records = collect_advisories_real(plugin_id=plugin, data_dir=args.data_dir)
        else:
            records = collect_advisories_sample(plugin_id=plugin)
        with out_path.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"Wrote {len(records)} records to {out_path}")
        return 0

    # Bulk mode
    if not args.real:
        # Keep the existing behavior: sample bulk output as a single file.
        out_path = out_dir / "jenkins_advisories.sample.jsonl"
        records = collect_advisories_sample(plugin_id=None)
        with out_path.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"Wrote {len(records)} records to {out_path}")
        return 0

    # Real bulk mode: iterate registry and write per-plugin files.
    registry_path = Path(args.registry_path)
    if not registry_path.exists():
        raise SystemExit(f"ERROR: registry file not found: {registry_path}")

    plugins_dir = Path(args.data_dir) / "plugins"

    def _collect_one(plugin_id: str, out_path: Path) -> None:
        records = collect_advisories_real(plugin_id=plugin_id, data_dir=args.data_dir)
        with out_path.open("w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    counts = bulk_collect_loop(
        registry_path=registry_path,
        max_plugins=int(args.max_plugins) if args.max_plugins is not None else None,
        sleep_s=float(args.sleep),
        overwrite=bool(args.overwrite),
        out_path_for=lambda pid: out_dir / f"{pid}.advisories.real.jsonl",
        collect_one=_collect_one,
        # collect_advisories_real expects snapshot metadata to exist for core/version context.
        precondition=lambda pid: _nonempty(plugins_dir / f"{pid}.snapshot.json"),
    )

    print("Advisories summary")
    print(f"  Plugins processed:  {counts['processed']}")
    print(f"  Advisories written: {counts['written']}")
    print(f"  Advisories skipped: {counts['skipped']}")
    print(f"  No snapshot:        {counts['precondition_failed']}")
    print(f"  Errors:             {counts['errors']}")
    return 0 if counts["errors"] == 0 else 2


def _cmd_collect_plugin(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Single-plugin mode (backwards compatible).
    if args.id:
        plugin_id = args.id.strip()
        snapshot = collect_plugin_snapshot(
            plugin_id=plugin_id,
            repo_url=args.repo_url,
            real=args.real,
        )
        out_path = out_dir / f"{plugin_id}.snapshot.json"
        out_path.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote snapshot to {out_path}")
        return 0

    # Bulk mode: iterate registry and write missing snapshots.
    registry_path = Path(args.registry_path)
    if not registry_path.exists():
        raise SystemExit(f"ERROR: registry file not found: {registry_path}")

    def _collect_one(plugin_id: str, out_path: Path) -> None:
        snapshot = collect_plugin_snapshot(
            plugin_id=plugin_id,
            repo_url=None,
            real=args.real,
        )
        out_path.write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    counts = bulk_collect_loop(
        registry_path=registry_path,
        max_plugins=int(args.max_plugins) if args.max_plugins is not None else None,
        sleep_s=float(args.sleep),
        overwrite=bool(args.overwrite),
        out_path_for=lambda pid: out_dir / f"{pid}.snapshot.json",
        collect_one=_collect_one,
    )

    print("Plugin snapshot summary")
    print(f"  Plugins processed: {counts['processed']}")
    print(f"  Snapshots written: {counts['written']}")
    print(f"  Snapshots skipped: {counts['skipped']}")
    print(f"  Errors:            {counts['errors']}")
    return 0 if counts["errors"] == 0 else 2


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


def _cmd_collect_software_heritage(args: argparse.Namespace) -> int:
    out_dir = args.out_dir
    if out_dir is None:
        out_dir = default_out_dir_for_backend(args.backend)

    result = collect_software_heritage(
        plugin_id=args.plugin,
        data_dir=args.data_dir,
        out_dir=out_dir,
        backend=args.backend,
        timeout_s=float(args.timeout_s),
        overwrite=bool(args.overwrite),
        database=args.database,
        output_location=args.output_location,
        max_visits=int(args.max_visits),
        directory_batch_size=int(args.directory_batch_size),
        max_directories=int(args.max_directories),
        verbose=not bool(args.quiet),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_collect_gharchive(args: argparse.Namespace) -> int:
    result = collect_gharchive_history_real(
        data_dir=args.data_dir,
        registry_path=args.registry_path,
        out_dir=args.out_dir,
        plugin_id=args.plugin,
        start_yyyymmdd=str(args.start),
        end_yyyymmdd=str(args.end),
        bucket_days=int(args.bucket_days),
        sample_percent=float(args.sample_percent),
        max_bytes_billed=int(args.max_bytes_billed),
        overwrite=bool(args.overwrite),
        allow_jenkinsci_fallback=bool(args.allow_jenkinsci_fallback),
        dry_run=bool(args.dry_run),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _cmd_collect_healthscore(args: argparse.Namespace) -> int:
    result = collect_health_scores(
        data_dir=args.data_dir,
        timeout_s=float(args.timeout_s),
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
    health_dir = data_raw / "healthscore"
    swh_backend = args.software_heritage_backend
    swh_dir = data_raw / (
        "software_heritage_athena" if swh_backend == "athena" else "software_heritage_api"
    )

    plugins_dir.mkdir(parents=True, exist_ok=True)
    advisories_dir.mkdir(parents=True, exist_ok=True)
    github_dir.mkdir(parents=True, exist_ok=True)
    health_dir.mkdir(parents=True, exist_ok=True)
    swh_dir.mkdir(parents=True, exist_ok=True)

    only = args.only
    do_snapshot = (only is None) or (only == "snapshot")
    do_advisories = (only is None) or (only == "advisories")
    do_github = (only is None) or (only == "github")
    do_healthscore = (only is None) or (only == "healthscore")
    do_software_heritage = (only is None) or (only == "software-heritage")

    max_plugins = int(args.max_plugins) if args.max_plugins is not None else None
    sleep_s = float(args.sleep)

    processed = 0
    snap_written = 0
    adv_written = 0
    gh_written = 0
    hs_written = 0
    swh_written = 0

    snap_skipped = 0
    adv_skipped = 0
    gh_skipped = 0
    hs_skipped = 0
    swh_skipped = 0

    errors = 0

    # Healthscore is a bulk dataset; fetch it once per enrich run (no per-plugin API calls).
    if do_healthscore:
        try:
            hs_result = collect_health_scores(
                data_dir=str(data_raw),
                timeout_s=float(args.healthscore_timeout_s),
                overwrite=False,
            )
            hs_written += int(hs_result.get("written", 0))
            hs_skipped += int(hs_result.get("skipped", 0))
        except Exception as e:
            errors += 1
            print(f"[ERROR] healthscore: {e}")

        # If the user asked for ONLY healthscore, we can stop here.
        if only == "healthscore":
            print("Enrich summary")
            print("  Plugins processed:   0")
            print(f"  Healthscore written: {hs_written}")
            print(f"  Healthscore skipped: {hs_skipped}")
            print(f"  Errors:              {errors}")
            return 0 if errors == 0 else 2

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

            if swh_backend == "athena":
                swh_index_path = swh_dir / f"{plugin_id}.swh_athena_index.json"
            else:
                swh_index_path = swh_dir / f"{plugin_id}.swh_index.json"

            if do_software_heritage:
                if not args.real:
                    raise SystemExit("ERROR: enrich software-heritage requires --real")

                # For Athena, do not skip solely because an index file already exists.
                # The Athena collector can merge existing visit records when overwrite=False,
                # so we allow it to revisit plugins and augment historical coverage.
                if swh_backend == "athena":
                    collect_software_heritage(
                        plugin_id=plugin_id,
                        data_dir=str(data_raw),
                        out_dir=str(swh_dir),
                        backend=swh_backend,
                        timeout_s=float(args.software_heritage_timeout_s),
                        overwrite=False,
                        database=args.software_heritage_athena_database,
                        output_location=args.software_heritage_athena_output_location,
                        max_visits=int(args.software_heritage_athena_max_visits),
                        directory_batch_size=int(
                            args.software_heritage_athena_directory_batch_size
                        ),
                        max_directories=int(args.software_heritage_athena_max_directories),
                        verbose=not bool(args.software_heritage_quiet),
                    )
                    swh_written += 1
                else:
                    # Keep the existing skip behavior for the API backend.
                    if _nonempty(swh_index_path):
                        swh_skipped += 1
                    else:
                        collect_software_heritage(
                            plugin_id=plugin_id,
                            data_dir=str(data_raw),
                            out_dir=str(swh_dir),
                            backend=swh_backend,
                            timeout_s=float(args.software_heritage_timeout_s),
                            overwrite=False,
                            database=args.software_heritage_athena_database,
                            output_location=args.software_heritage_athena_output_location,
                            max_visits=int(args.software_heritage_athena_max_visits),
                            directory_batch_size=int(
                                args.software_heritage_athena_directory_batch_size
                            ),
                            max_directories=int(args.software_heritage_athena_max_directories),
                            verbose=not bool(args.software_heritage_quiet),
                        )
                        swh_written += 1

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
    if do_healthscore:
        print(f"  Healthscore written: {hs_written}")
        print(f"  Healthscore skipped: {hs_skipped}")
    if do_software_heritage:
        print(f"  SWH written:         {swh_written}")
        print(f"  SWH skipped:         {swh_skipped}")
    print(f"  Errors:              {errors}")

    return 0 if errors == 0 else 2


def register(subparsers: Any) -> None:
    """Register the ``collect`` command group."""
    collect = subparsers.add_parser("collect", help="Collect raw/processed data")
    collect_subparsers = collect.add_subparsers(dest="collect_cmd", required=True)

    advisories = collect_subparsers.add_parser("advisories", help="Collect Jenkins advisories")
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
    advisories.add_argument(
        "--registry-path",
        default="data/raw/registry/plugins.jsonl",
        help="Plugin registry JSONL (used for bulk real collection when --plugin is omitted)",
    )
    advisories.add_argument(
        "--max-plugins",
        default=None,
        help="Optional limit for bulk collection (debugging)",
    )
    advisories.add_argument(
        "--sleep",
        default="0",
        help="Seconds to sleep between plugins in bulk mode (rate limiting)",
    )
    advisories.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing per-plugin files in bulk mode",
    )
    advisories.set_defaults(func=_cmd_collect_advisories)

    plugin = collect_subparsers.add_parser("plugin", help="Collect a plugin snapshot")
    plugin.add_argument(
        "--id",
        required=False,
        default=None,
        help="Plugin short name (e.g., cucumber-reports). "
        "If omitted, run in bulk mode using --registry-path.",
    )
    plugin.add_argument("--out-dir", default="data/raw/plugins", help="Output directory")
    plugin.add_argument(
        "--repo-url",
        default=None,
        help="GitHub repo URL (optional; can be inferred/curated for pilots)",
    )
    plugin.add_argument("--real", action="store_true", help="Fetch live data (network)")
    plugin.add_argument(
        "--registry-path",
        default="data/raw/registry/plugins.jsonl",
        help="Plugin registry JSONL (used for bulk collection when --id is omitted)",
    )
    plugin.add_argument(
        "--max-plugins",
        default=None,
        help="Optional limit for bulk collection (debugging)",
    )
    plugin.add_argument(
        "--sleep",
        default="0",
        help="Seconds to sleep between plugins in bulk mode (rate limiting)",
    )
    plugin.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing snapshot files in bulk mode",
    )
    plugin.set_defaults(func=_cmd_collect_plugin)

    registry = collect_subparsers.add_parser(
        "registry",
        help="Collect the current Jenkins plugin registry (the universe snapshot)",
    )
    registry.add_argument("--out-dir", default="data/raw/registry", help="Output directory")
    registry.add_argument("--out-name", default="plugins.jsonl", help="Output filename (JSONL)")
    registry.add_argument(
        "--raw-out", default=None, help="Optional filename to store raw pages (JSON)"
    )
    registry.add_argument("--page-size", default=2500, help="Registry paging size (default: 2500)")
    registry.add_argument("--max-plugins", default=None, help="Optional cap for quick tests")
    registry.add_argument("--timeout-s", default=30.0, help="Network timeout per request")
    registry.add_argument(
        "--real", action="store_true", help="Fetch live data from plugins.jenkins.io"
    )
    registry.set_defaults(func=_cmd_collect_registry)

    github = collect_subparsers.add_parser(
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

    gharchive = collect_subparsers.add_parser(
        "gharchive",
        help=(
            "Collect historical GitHub activity windows for Jenkins plugins "
            "from GH Archive/BigQuery"
        ),
    )
    gharchive.add_argument(
        "--plugin",
        default=None,
        help="Optional single plugin id (default: bulk mode using --registry-path)",
    )
    gharchive.add_argument(
        "--data-dir",
        default="data/raw",
        help="Raw dataset root (reads plugins/<id>.snapshot.json)",
    )
    gharchive.add_argument(
        "--registry-path",
        default="data/raw/registry/plugins.jsonl",
        help="Plugin registry JSONL used in bulk mode",
    )
    gharchive.add_argument(
        "--out-dir",
        default="data/raw/gharchive",
        help="Output directory for GH Archive JSON artifacts",
    )
    gharchive.add_argument("--start", required=True, help="Start date in YYYYMMDD")
    gharchive.add_argument("--end", required=True, help="End date in YYYYMMDD")
    gharchive.add_argument(
        "--bucket-days",
        default=30,
        help="Window size in days for historical feature buckets (default: 30)",
    )
    gharchive.add_argument(
        "--sample-percent",
        default=5.0,
        help="Percent of each GH Archive day table to scan (default: 5)",
    )
    gharchive.add_argument(
        "--max-bytes-billed",
        default=2_000_000_000,
        help="BigQuery maximum bytes billed per window query",
    )
    gharchive.add_argument(
        "--allow-jenkinsci-fallback",
        action="store_true",
        help="Fall back to jenkinsci/<plugin>-plugin when a snapshot lacks repo mapping",
    )
    gharchive.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing GH Archive window files",
    )
    gharchive.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimate bytes scanned and return planned windows without writing output files",
    )

    gharchive.set_defaults(func=_cmd_collect_gharchive)

    healthscore = collect_subparsers.add_parser(
        "healthscore",
        help="Collect Jenkins plugin Health Score dataset (bulk) from plugin-health.jenkins.io",
    )
    healthscore.add_argument(
        "--data-dir",
        default="data/raw",
        help="Raw data root (writes healthscore/ beneath this)",
    )
    healthscore.add_argument(
        "--timeout-s",
        default=30.0,
        help="Network timeout for healthscore fetch",
    )
    healthscore.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing healthscore files",
    )
    healthscore.set_defaults(func=_cmd_collect_healthscore)

    software_heritage = collect_subparsers.add_parser(
        "software-heritage",
        help="Collect Software Heritage archival metadata for a plugin",
    )
    software_heritage.add_argument(
        "--plugin",
        required=True,
        help="Plugin short name (e.g. workflow-cps)",
    )
    software_heritage.add_argument(
        "--data-dir",
        default="data/raw",
        help="Raw dataset root (reads plugins/<id>.snapshot.json)",
    )
    software_heritage.add_argument(
        "--backend",
        choices=["athena", "api"],
        default="athena",
        help="Software Heritage backend to use",
    )
    software_heritage.add_argument(
        "--out-dir",
        default=None,
        help="Output directory (defaults by backend)",
    )
    software_heritage.add_argument(
        "--timeout-s",
        default=20.0,
        help="Network timeout per request (API backend)",
    )
    software_heritage.add_argument(
        "--database",
        default="swh_jenkins",
        help="Athena database (Athena backend)",
    )
    software_heritage.add_argument(
        "--output-location",
        default=None,
        help="Athena staging S3 path (Athena backend)",
    )
    software_heritage.add_argument(
        "--max-visits",
        default=1,
        help="Max visits to retrieve (Athena backend)",
    )
    software_heritage.add_argument(
        "--directory-batch-size",
        default=20,
        help="Directory batch size (Athena backend)",
    )
    software_heritage.add_argument(
        "--max-directories",
        default=100,
        help="Max directories per snapshot (Athena backend)",
    )
    software_heritage.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce Athena logging",
    )
    software_heritage.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing Software Heritage files",
    )
    software_heritage.set_defaults(func=_cmd_collect_software_heritage)

    enrich = collect_subparsers.add_parser(
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
        choices=["snapshot", "advisories", "github", "healthscore", "software-heritage"],
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
    enrich.add_argument(
        "--healthscore-timeout-s",
        default=30.0,
        help="Healthscore timeout per request",
    )
    enrich.add_argument(
        "--software-heritage-timeout-s",
        default=20.0,
        help="Software Heritage timeout per request",
    )
    enrich.add_argument(
        "--software-heritage-backend",
        choices=["athena", "api"],
        default="athena",
        help="Software Heritage backend to use during enrich",
    )
    enrich.add_argument(
        "--software-heritage-athena-database",
        default="swh_jenkins",
        help="Athena database for software heritage enrich",
    )
    enrich.add_argument(
        "--software-heritage-athena-output-location",
        default=None,
        help="Athena staging S3 path for software heritage enrich",
    )
    enrich.add_argument(
        "--software-heritage-athena-max-visits",
        default=1,
        help="Athena max visits per plugin",
    )
    enrich.add_argument(
        "--software-heritage-athena-directory-batch-size",
        default=20,
        help="Athena directory batch size",
    )
    enrich.add_argument(
        "--software-heritage-athena-max-directories",
        default=100,
        help="Athena max directories per snapshot",
    )
    enrich.add_argument(
        "--software-heritage-quiet",
        action="store_true",
        help="Reduce Athena logging during enrich",
    )
    enrich.set_defaults(func=_cmd_collect_enrich)
