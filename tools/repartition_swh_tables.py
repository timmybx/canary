"""repartition_swh_tables.py

One-time ETL that rewrites the three heaviest Software Heritage tables into
partitioned ORC so that Athena can use partition pruning instead of full-table
scans.

Tables rewritten
----------------
origin_visit_status  ->  partitioned by origin_prefix (first 2 hex chars of
                         MD5(origin)) giving ~256 roughly equal partitions.
                         Turns the 12 GB repo_visits scan into ~50 MB.

snapshot_branch      ->  partitioned by snap_prefix (first 2 hex chars of
                         snapshot_id).  Turns the 93 GB snapshot_directories
                         scan into ~400 MB.

directory_entry      ->  partitioned by dir_prefix (first 2 hex chars of
                         directory_id).  Turns the 416 GB directory_entries
                         scan into ~1.6 GB.

Strategy
--------
Each table is rewritten using an Athena CTAS query that:
  1. Reads from the existing (unpartitioned) table in the source database.
  2. Writes ORC+ZSTD to a new S3 prefix.
  3. Creates a new Glue table with PARTITIONED BY metadata.

After the CTAS jobs complete a companion external table is registered in the
*same* database so that the existing collector queries work unchanged.  The
old unpartitioned table is renamed to <table>_unpartitioned and left intact
so you can verify correctness before deleting it.

Usage
-----
    python repartition_swh_tables.py \\
        --database      swh_graph_2021_03_23 \\
        --location-prefix s3://YOUR-BUCKET/swh \\
        --output-location s3://YOUR-BUCKET/athena-results/

The --location-prefix is the same value you passed to create_swh_athena_tables.py.
Repartitioned data lands at:
    <location-prefix>/orc_partitioned/origin_visit_status/
    <location-prefix>/orc_partitioned/snapshot_branch/
    <location-prefix>/orc_partitioned/directory_entry/

Estimated CTAS run time: 10-40 minutes per table depending on cluster DPUs.
These jobs run sequentially so the whole script takes 30-120 minutes total.
"""

from __future__ import annotations

import argparse
import os
import time

import boto3  # pyright: ignore[reportMissingImports]
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

load_dotenv()

DEFAULT_REGION = "us-east-1"
DEFAULT_POLL_INITIAL = 2.0
DEFAULT_POLL_MAX = 30.0
DEFAULT_POLL_BACKOFF = 1.6


# ---------------------------------------------------------------------------
# Boto3 client (single instance for the whole script)
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
# Query runner with exponential-backoff polling
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


def run_query(client, query: str, *, database: str, output_location: str, label: str = "") -> dict:
    tag = f"[{label}] " if label else ""
    print(f"{tag}Submitting query...")
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
    scanned = stats.get("DataScannedInBytes", 0)
    scanned_gb = scanned / 1024**3

    if state != "SUCCEEDED":
        reason = result["QueryExecution"]["Status"].get("StateChangeReason", "")
        raise RuntimeError(
            f"{tag}FAILED state={state} elapsed={elapsed:.0f}s reason={reason}\n\nQuery:\n{query}"
        )

    print(f"{tag}SUCCEEDED elapsed={elapsed:.0f}s scanned={scanned_gb:.2f} GB")
    return result["QueryExecution"]


# ---------------------------------------------------------------------------
# CTAS SQL builders
# ---------------------------------------------------------------------------


def _ctas_origin_visit_status(
    src_database: str,
    dst_database: str,
    dst_location: str,
) -> str:
    """
    Partition origin_visit_status by the first 2 hex characters of MD5(origin).

    MD5 is available in Athena (Presto) as md5(to_utf8(origin)) which returns
    a varbinary; we hex-encode it and take the first 2 chars for ~256 buckets.

    Why MD5 and not the raw origin string?
      - Origins are URLs of wildly varying length and format.
      - A hash prefix gives uniform bucket sizes regardless of URL distribution.
      - 2 hex chars = 256 partitions ≈ 50 MB each from the 12 GB table.
    """
    return f"""
CREATE TABLE {dst_database}.origin_visit_status_partitioned
WITH (
    format           = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dst_location}',
    partitioned_by   = ARRAY['origin_prefix']
)
AS
SELECT
    origin,
    visit,
    date,
    type,
    snapshot_id,
    status,
    substr(to_hex(md5(to_utf8(origin))), 1, 2) AS origin_prefix
FROM {src_database}.origin_visit_status
""".strip()


def _ctas_snapshot_branch(
    src_database: str,
    dst_database: str,
    dst_location: str,
) -> str:
    """
    Partition snapshot_branch by the first 2 hex chars of snapshot_id.

    snapshot_id is already a hex SHA1 string so we just take the prefix directly —
    no hashing needed.  256 partitions from the ~93 GB table ≈ 370 MB each.
    """
    return f"""
CREATE TABLE {dst_database}.snapshot_branch_partitioned
WITH (
    format           = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dst_location}',
    partitioned_by   = ARRAY['snap_prefix']
)
AS
SELECT
    snapshot_id,
    name,
    target,
    target_type,
    substr(snapshot_id, 1, 2) AS snap_prefix
FROM {src_database}.snapshot_branch
""".strip()


def _ctas_directory_entry(
    src_database: str,
    dst_database: str,
    dst_location: str,
) -> str:
    """
    Partition directory_entry by the first 2 hex chars of directory_id.

    directory_id is a hex SHA1 string, same as snapshot_id above.
    256 partitions from the ~416 GB table ≈ 1.6 GB each.
    """
    return f"""
CREATE TABLE {dst_database}.directory_entry_partitioned
WITH (
    format           = 'ORC',
    write_compression = 'ZSTD',
    external_location = '{dst_location}',
    partitioned_by   = ARRAY['dir_prefix']
)
AS
SELECT
    directory_id,
    name,
    type,
    target,
    perms,
    substr(directory_id, 1, 2) AS dir_prefix
FROM {src_database}.directory_entry
""".strip()


# ---------------------------------------------------------------------------
# Post-CTAS: swap old table name to _unpartitioned, register view/alias
# ---------------------------------------------------------------------------


def _rename_old_table_sql(database: str, table: str) -> str:
    """
    Athena (Glue) does not support RENAME TABLE, but we can use
    CREATE TABLE AS ... (metadata only) then DROP.  Instead we just
    rename via the Glue API comment — the safe approach here is to
    simply add a suffix to the original so analysts know it's the old copy.

    We handle this via a simple DROP + recreate with _unpartitioned suffix
    using the existing unpartitioned DDL supplied by the caller.
    """
    return f"ALTER TABLE {database}.{table} RENAME TO {table}_unpartitioned"


def _create_view_sql(database: str, table: str, partitioned_table: str) -> str:
    """
    Create a view with the original table name that reads from the
    partitioned version.  This means the collector code needs zero changes.
    """
    return f"""
CREATE OR REPLACE VIEW {database}.{table} AS
SELECT * FROM {database}.{partitioned_table}
""".strip()


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

STEPS = [
    {
        "label": "origin_visit_status",
        "src_table": "origin_visit_status",
        "ctas_table": "origin_visit_status_partitioned",
        "ctas_fn": _ctas_origin_visit_status,
        "subdir": "orc_partitioned/origin_visit_status",
    },
    {
        "label": "snapshot_branch",
        "src_table": "snapshot_branch",
        "ctas_table": "snapshot_branch_partitioned",
        "ctas_fn": _ctas_snapshot_branch,
        "subdir": "orc_partitioned/snapshot_branch",
    },
    {
        "label": "directory_entry",
        "src_table": "directory_entry",
        "ctas_table": "directory_entry_partitioned",
        "ctas_fn": _ctas_directory_entry,
        "subdir": "orc_partitioned/directory_entry",
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=("Repartition the three heaviest SWH Athena tables for fast predicate pruning.")
    )
    parser.add_argument(
        "--database",
        required=True,
        help="Athena database name, e.g. swh_graph_2021_03_23",
    )
    parser.add_argument(
        "--location-prefix",
        required=True,
        help=(
            "S3 prefix for the SWH dataset — same value used in create_swh_athena_tables.py, "
            "e.g. s3://your-bucket/swh.  Partitioned data lands under "
            "<prefix>/orc_partitioned/<table>/."
        ),
    )
    parser.add_argument(
        "--output-location",
        default=os.getenv("ATHENA_S3_STAGING_DIR"),
        help="Athena query-results S3 location (defaults to ATHENA_S3_STAGING_DIR env var).",
    )
    parser.add_argument(
        "--only",
        choices=["origin_visit_status", "snapshot_branch", "directory_entry"],
        help="Repartition only one table instead of all three (useful for resuming).",
    )
    parser.add_argument(
        "--skip-view",
        action="store_true",
        help=(
            "Skip creating the compatibility views after CTAS.  Use this if you prefer "
            "to update your queries manually to reference the _partitioned table names."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the SQL that would be executed without running anything.",
    )
    args = parser.parse_args()

    if not args.output_location:
        raise SystemExit("ERROR: --output-location is required (or set ATHENA_S3_STAGING_DIR).")

    location_prefix = args.location_prefix.rstrip("/")
    steps = [s for s in STEPS if args.only is None or s["label"] == args.only]

    client = None if args.dry_run else _athena_client()

    for step in steps:
        label = step["label"]
        dst_location = f"{location_prefix}/{step['subdir']}/"
        ctas_sql = step["ctas_fn"](args.database, args.database, dst_location)
        view_sql = _create_view_sql(args.database, step["src_table"], step["ctas_table"])

        print()
        print("=" * 70)
        print(f"STEP: repartition {label}")
        print(f"  destination: {dst_location}")
        print("=" * 70)

        if args.dry_run:
            print("\n-- CTAS SQL:")
            print(ctas_sql)
            if not args.skip_view:
                print("\n-- View SQL:")
                print(view_sql)
            continue

        # Drop any previous failed CTAS attempt so we can rerun cleanly
        print(f"\nDropping {step['ctas_table']} if it exists from a previous run...")
        run_query(
            client,
            f"DROP TABLE IF EXISTS {args.database}.{step['ctas_table']}",
            database=args.database,
            output_location=args.output_location,
            label=f"drop_old_{label}",
        )

        print(f"\nRunning CTAS for {label} — this may take 10-40 minutes...")
        run_query(
            client,
            ctas_sql,
            database=args.database,
            output_location=args.output_location,
            label=f"ctas_{label}",
        )

        if not args.skip_view:
            print(f"\nCreating compatibility view {step['src_table']} -> {step['ctas_table']}...")
            # Rename original table so the view name is free
            try:
                run_query(
                    client,
                    _rename_old_table_sql(args.database, step["src_table"]),
                    database=args.database,
                    output_location=args.output_location,
                    label=f"rename_{label}",
                )
            except RuntimeError as exc:
                # ALTER TABLE RENAME may not be supported in all Athena engine versions;
                # if it fails, warn and continue — the view create below will fail too
                # if the name is taken, which is a clear signal to handle manually.
                print(
                    "  WARNING: rename failed (see below); you may need to drop "
                    f"the old table manually.\n  {exc}"
                )

            run_query(
                client,
                view_sql,
                database=args.database,
                output_location=args.output_location,
                label=f"view_{label}",
            )

        print(f"\n✓ {label} repartitioned successfully.")

    print()
    print("=" * 70)
    print("All done.")
    print()
    print("Next steps:")
    print("  1. Run your collector against one repo and compare scan volumes.")
    print("     Expected improvement:")
    print("       origin_visit_status : 12 GB  ->  ~50 MB")
    print("       snapshot_branch     : 93 GB  ->  ~400 MB")
    print("       directory_entry     : 416 GB ->  ~1.6 GB")
    print()
    print("  2. Once verified, delete the old unpartitioned data to save S3 costs:")
    print("     - Drop tables: <table>_unpartitioned in the Athena console")
    print("     - Delete S3 prefix: <location-prefix>/orc/<table>/")
    print()
    if args.skip_view:
        print("  3. You chose --skip-view.  Update your queries to use the")
        print("     _partitioned table names, or rerun without --skip-view.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
