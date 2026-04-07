"""extract_jenkins_swh_subset.py

One-time ETL that extracts a small Jenkins-plugin-only subset from the full
Software Heritage Athena dataset into three compact tables in your own bucket.

After this script completes, your collector queries run against tiny local
tables instead of the multi-TB public SWH dataset.

What gets extracted
-------------------
jenkins_plugin_urls     A tiny reference table of the 2053 plugin URLs.
                        Used as a join key in subsequent steps.

jenkins_visits          One row per (plugin, month) for 2018-01-01 to
                        2019-12-31 (the dataset snapshot date), keeping only
                        the most recent visit per calendar month so you get
                        ~12-15 data points per plugin rather than every
                        individual visit.

jenkins_snapshot_branch snapshot_branch rows for only the snapshots that
                        appear in jenkins_visits.

jenkins_directory_entry directory_entry rows for only the root directories
                        reachable from jenkins_snapshot_branch via revision.

Estimated output sizes (very rough)
------------------------------------
jenkins_visits          ~50 MB   (2053 plugins × ~13 months × small row)
jenkins_snapshot_branch ~2 GB    (one snapshot_branch scan filtered by join)
jenkins_directory_entry ~5-10 GB (one directory_entry scan filtered by join)

Estimated Athena scan costs (one-time)
----------------------------------------
Step 1 (visits)          ~12 GB   (full origin_visit_status scan)
Step 2 (snapshot_branch) ~93 GB   (full snapshot_branch scan)
Step 3 (directory_entry) ~6.5 TB  (full directory_entry scan — unavoidable
                                    without partitioning, but only done once)

After this runs, all future collector queries scan only your small extracted
tables — effectively free compared to hitting the public dataset repeatedly.

Usage
-----
    python extract_jenkins_swh_subset.py \\
        --database        swh_graph_2025_10_08 \\
        --plugins-jsonl   data/plugins.jsonl \\
        --dest-bucket     s3://canary-athena-east-bucket-results \\
        --output-location s3://canary-athena-east-bucket-results/athena-results/

Optional flags
--------------
    --dest-prefix   swh_jenkins          S3 key prefix under dest-bucket
                                         (default: swh_jenkins)
    --dest-database swh_jenkins          Glue database for extracted tables
                                         (default: swh_jenkins; created if absent)
    --dry-run                            Print SQL without executing
    --only          visits|snapshot_branch|directory_entry
                                         Run one step only (for resuming)
    --drop-existing                      DROP extracted tables before recreating
                                         (safe to rerun from scratch)
"""

from __future__ import annotations

import argparse
import json
import os
import time

import boto3  # pyright: ignore[reportMissingImports]
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

load_dotenv()

DEFAULT_REGION = "us-east-1"
DEFAULT_DEST_PREFIX = "swh_jenkins"
DEFAULT_DEST_DATABASE = "swh_jenkins"
DEFAULT_POLL_INITIAL = 2.0
DEFAULT_POLL_MAX = 30.0
DEFAULT_POLL_BACKOFF = 1.6


# ---------------------------------------------------------------------------
# Boto3 client
# ---------------------------------------------------------------------------


def _athena_client():
    return boto3.client(
        "athena",
        region_name=os.getenv("AWS_REGION", DEFAULT_REGION),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID") or None,
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY") or None,
        aws_session_token=os.getenv("AWS_SESSION_TOKEN") or None,
    )


# ---------------------------------------------------------------------------
# Query runner
# ---------------------------------------------------------------------------


def _poll_until_done(client, qid: str) -> dict:
    delay = DEFAULT_POLL_INITIAL
    while True:
        resp = client.get_query_execution(QueryExecutionId=qid)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return resp
        time.sleep(delay)
        delay = min(delay * DEFAULT_POLL_BACKOFF, DEFAULT_POLL_MAX)


def _format_bytes(b: int | None) -> str:
    if b is None:
        return "unknown"
    value: float = float(b)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return str(value)


def run_query(
    client,
    query: str,
    *,
    database: str,
    output_location: str,
    label: str = "",
) -> dict:
    tag = f"[{label}] " if label else ""
    print(f"\n{tag}Submitting...")
    resp = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_location},
    )
    qid = resp["QueryExecutionId"]
    print(f"{tag}query_execution_id={qid}")

    started = time.monotonic()
    result = _poll_until_done(client, qid)
    elapsed = time.monotonic() - started

    state = result["QueryExecution"]["Status"]["State"]
    stats = result["QueryExecution"].get("Statistics", {})
    scanned = stats.get("DataScannedInBytes")
    scanned_str = _format_bytes(scanned) if scanned else "unknown"

    if state != "SUCCEEDED":
        reason = result["QueryExecution"]["Status"].get("StateChangeReason", "")
        raise RuntimeError(
            f"{tag}FAILED state={state} elapsed={elapsed:.0f}s reason={reason}\n\nQuery:\n{query}"
        )

    print(f"{tag}SUCCEEDED elapsed={elapsed:.0f}s scanned={scanned_str}")
    return result["QueryExecution"]


# ---------------------------------------------------------------------------
# Plugin URL helpers
# ---------------------------------------------------------------------------
def load_plugin_urls(jsonl_path: str) -> list[str]:
    urls = []
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            plugin_id = record.get("plugin_id", "").strip()
            if plugin_id:
                urls.append(f"https://github.com/jenkinsci/{plugin_id}")
                # SWH often stores repos with -plugin suffix
                if not plugin_id.endswith("-plugin"):
                    urls.append(f"https://github.com/jenkinsci/{plugin_id}-plugin")
    return urls


# ---------------------------------------------------------------------------
# SQL builders
# ---------------------------------------------------------------------------


def _sql_create_database(database: str) -> str:
    return f"CREATE SCHEMA IF NOT EXISTS {database}"


def _sql_drop_table(database: str, table: str) -> str:
    return f"DROP TABLE IF EXISTS {database}.{table}"


def _sql_create_plugin_urls_table(
    src_database: str,
    dest_database: str,
    dest_location: str,
    plugin_urls: list[str],
) -> str:
    """
    Create a tiny reference table of plugin URLs using a VALUES clause.
    ~2053 rows, a few KB on disk.
    The IN clause is ~99KB which is well under Athena's 256KB query limit.
    """
    values = ",\n".join(f"    ('{u}')" for u in plugin_urls)
    return f"""
CREATE TABLE "{dest_database}"."jenkins_plugin_urls"
WITH (
    format            = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dest_location}'
)
AS
SELECT url
FROM (
    VALUES
{values}
) AS t(url)
""".strip()


def _sql_create_jenkins_visits(
    src_database: str,
    dest_database: str,
    dest_location: str,
) -> str:
    """
    Extract one visit per plugin per calendar month for 2018-01-01 to
    2019-12-31 (the dataset snapshot date).

    ROW_NUMBER() picks the latest visit within each (plugin, year, month)
    window, giving ~12-15 data points per plugin rather than every visit.

    Scans: ~12 GB (full origin_visit_status).
    Output: ~50 MB.
    """
    return f"""
CREATE TABLE "{dest_database}"."jenkins_visits"
WITH (
    format            = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dest_location}'
)
AS
WITH ranked AS (
    SELECT
        ovs.origin,
        ovs.visit,
        ovs.date        AS visit_date,
        ovs.snapshot_id,
        ROW_NUMBER() OVER (
            PARTITION BY ovs.origin,
                         year(ovs.date),
                         month(ovs.date)
            ORDER BY ovs.date DESC
        ) AS rn
    FROM "{src_database}"."origin_visit_status" ovs
    INNER JOIN "{dest_database}"."jenkins_plugin_urls" pu
        ON ovs.origin = pu.url
    WHERE ovs.date     >= TIMESTAMP '2018-01-01 00:00:00'
      AND ovs.date < TIMESTAMP '2025-10-01 00:00:00'
      AND ovs.snapshot_id IS NOT NULL
)
SELECT origin, visit, visit_date, snapshot_id
FROM ranked
WHERE rn = 1
ORDER BY origin, visit_date
""".strip()


def _sql_create_jenkins_snapshot_branch(
    src_database: str,
    dest_database: str,
    dest_location: str,
) -> str:
    """
    Extract snapshot_branch rows for only the snapshots in jenkins_visits,
    keeping only revision-type targets (the ones the collector needs).

    Scans: ~93 GB (full snapshot_branch scan with join filter).
    Output: ~2 GB.
    """
    return f"""
CREATE TABLE "{dest_database}"."jenkins_snapshot_branch"
WITH (
    format            = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dest_location}'
)
AS
SELECT DISTINCT
    sb.snapshot_id,
    sb.target
FROM "{src_database}"."snapshot_branch" sb
INNER JOIN "{dest_database}"."jenkins_visits" jv
    ON sb.snapshot_id = jv.snapshot_id
WHERE sb.target_type = 'revision'
""".strip()


def _sql_create_jenkins_directory_entry(
    src_database: str,
    dest_database: str,
    dest_location: str,
) -> str:
    """
    Extract directory_entry rows for the root directories reachable from
    jenkins_snapshot_branch via the revision table.

    This is the expensive step — it scans the full ~6.5 TB directory_entry
    table once.  After this it never needs to happen again.

    Scans: ~6.5 TB (unavoidable without pre-partitioning).
    Output: ~5-10 GB.
    """
    return f"""
CREATE TABLE "{dest_database}"."jenkins_directory_entry"
WITH (
    format            = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dest_location}'
)
AS
SELECT DISTINCT
    de.directory_id,
    from_utf8(de.name, '?') AS entry_name,
    de.type
FROM "{src_database}"."directory_entry" de
INNER JOIN (
    SELECT DISTINCT r.directory
    FROM "{dest_database}"."jenkins_snapshot_branch" jsb
    INNER JOIN "{src_database}"."revision" r
        ON r.id = jsb.target
    WHERE r.directory IS NOT NULL
) root_dirs
    ON de.directory_id = root_dirs.directory
""".strip()


# ---------------------------------------------------------------------------
# Step definitions
# ---------------------------------------------------------------------------

STEPS = ["plugin_urls", "visits", "snapshot_branch", "directory_entry"]

STEP_META = {
    "plugin_urls": {
        "table": "jenkins_plugin_urls",
        "subdir": "plugin_urls",
        "label": "plugin_urls (tiny reference table)",
        "warn": None,
    },
    "visits": {
        "table": "jenkins_visits",
        "subdir": "visits",
        "label": "visits (scans ~12 GB)",
        "warn": None,
    },
    "snapshot_branch": {
        "table": "jenkins_snapshot_branch",
        "subdir": "snapshot_branch",
        "label": "snapshot_branch (scans ~93 GB — takes ~5-10 min)",
        "warn": None,
    },
    "directory_entry": {
        "table": "jenkins_directory_entry",
        "subdir": "directory_entry",
        "label": "directory_entry (scans ~6.5 TB — takes 1-3 hours)",
        "warn": (
            "WARNING: This step scans the full 6.5 TB directory_entry table.\n"
            "It runs once and is never repeated.  Estimated cost: ~$32 at\n"
            "standard Athena pricing ($5/TB).  Estimated time: 1-3 hours.\n"
            "After completion all future queries hit only your small extracted\n"
            "tables and cost effectively nothing."
        ),
    },
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract a Jenkins-plugin-only subset from the SWH Athena dataset "
            "into compact tables in your own bucket."
        )
    )
    parser.add_argument(
        "--database",
        required=True,
        help="Source SWH Athena database, e.g. swh_graph_2025_10_08",
    )
    parser.add_argument(
        "--plugins-jsonl",
        required=True,
        help="Path to plugins.jsonl file.",
    )
    parser.add_argument(
        "--dest-bucket",
        required=True,
        help="S3 bucket for extracted tables, e.g. s3://canary-athena-east-bucket-results",
    )
    parser.add_argument(
        "--output-location",
        default=os.getenv("ATHENA_S3_STAGING_DIR"),
        help="Athena query-results S3 location (or set ATHENA_S3_STAGING_DIR).",
    )
    parser.add_argument(
        "--dest-prefix",
        default=DEFAULT_DEST_PREFIX,
        help=f"S3 key prefix under dest-bucket (default: {DEFAULT_DEST_PREFIX})",
    )
    parser.add_argument(
        "--dest-database",
        default=DEFAULT_DEST_DATABASE,
        help=f"Glue/Athena database for extracted tables (default: {DEFAULT_DEST_DATABASE})",
    )
    parser.add_argument(
        "--only",
        choices=STEPS,
        help="Run only one step (useful for resuming after a failure).",
    )
    parser.add_argument(
        "--drop-existing",
        action="store_true",
        help="Drop extracted tables before recreating (safe full rerun).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print SQL without executing anything.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompts.",
    )
    args = parser.parse_args()

    if not args.output_location:
        raise SystemExit("ERROR: --output-location required (or set ATHENA_S3_STAGING_DIR).")

    dest_bucket = args.dest_bucket.rstrip("/")
    dest_prefix = args.dest_prefix.strip("/")

    plugin_urls = load_plugin_urls(args.plugins_jsonl)
    print(f"Loaded {len(plugin_urls)} plugin URLs from {args.plugins_jsonl}")

    # Build SQL for each step
    def loc(subdir: str) -> str:
        return f"{dest_bucket}/{dest_prefix}/{subdir}/"

    sql_map = {
        "plugin_urls": _sql_create_plugin_urls_table(
            args.database, args.dest_database, loc("plugin_urls"), plugin_urls
        ),
        "visits": _sql_create_jenkins_visits(args.database, args.dest_database, loc("visits")),
        "snapshot_branch": _sql_create_jenkins_snapshot_branch(
            args.database, args.dest_database, loc("snapshot_branch")
        ),
        "directory_entry": _sql_create_jenkins_directory_entry(
            args.database, args.dest_database, loc("directory_entry")
        ),
    }

    steps_to_run = [args.only] if args.only else STEPS

    if args.dry_run:
        for step in steps_to_run:
            meta = STEP_META[step]
            print(f"\n{'=' * 70}")
            print(f"STEP: {meta['label']}")
            print(f"  destination: {loc(meta['subdir'])}")
            print(f"{'=' * 70}")
            if meta["warn"]:
                print(f"\n{meta['warn']}")
            print(f"\n-- SQL:\n{sql_map[step]}")
        print("\nAll done (dry run).")
        return 0

    client = _athena_client()

    # Ensure destination database exists
    print(f"\nEnsuring destination database '{args.dest_database}' exists...")
    run_query(
        client,
        _sql_create_database(args.dest_database),
        database="default",
        output_location=args.output_location,
        label="create_database",
    )

    for step in steps_to_run:
        meta = STEP_META[step]
        print(f"\n{'=' * 70}")
        print(f"STEP: {meta['label']}")
        print(f"  destination: {loc(meta['subdir'])}")
        print(f"{'=' * 70}")

        if meta["warn"] and not args.yes:
            print(f"\n{meta['warn']}")
            confirm = input("\nProceed? [y/N] ").strip().lower()
            if confirm != "y":
                print("Skipped.")
                continue

        if args.drop_existing:
            print(f"\nDropping existing table '{meta['table']}' if present...")
            run_query(
                client,
                _sql_drop_table(args.dest_database, meta["table"]),
                database=args.dest_database,
                output_location=args.output_location,
                label=f"drop_{step}",
            )

        run_query(
            client,
            sql_map[step],
            database=args.dest_database,
            output_location=args.output_location,
            label=step,
        )
        print(f"OK {step} complete.")

    print(f"""
{"=" * 70}
All steps complete.

Your extracted tables are in database '{args.dest_database}':
  jenkins_plugin_urls     — reference table of 2053 plugin URLs
  jenkins_visits          — one visit/month per plugin, 2019-2020
  jenkins_snapshot_branch — snapshot branch rows for those visits
  jenkins_directory_entry — directory entries for those root dirs

Next step: update your collector to query '{args.dest_database}' instead
of '{args.database}'.  The per-repo query time should drop from ~97 seconds
to 1-3 seconds.
{"=" * 70}
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
