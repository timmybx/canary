from __future__ import annotations

import argparse
import os
import time
from typing import Final

import boto3  # pyright: ignore[reportMissingImports]
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

# Schema matches swh-export relational.py as of the 2025-10-08 dataset release.
# Key differences from the 2021-03-23 schema:
#   - origin:              added "id" column
#   - origin_visit_status: "snapshot_id" renamed to "snapshot"; column order changed
#   - release:             author/name/message reordered; new date_offset,
#                          date_raw_offset_bytes, raw_manifest columns
#   - revision:            author/committer changed from string to binary;
#                          new date_raw_offset_bytes, committer_date_raw_offset_bytes,
#                          type, and raw_manifest columns added
#   - content:             removed ctime; added data column
#   - skipped_content:     removed ctime and origin columns
#   - directory:           added raw_manifest column
TABLES: Final[dict[str, list[tuple[str, str]]]] = {
    "content": [
        ("sha1", "string"),
        ("sha1_git", "string"),
        ("sha256", "string"),
        ("blake2s256", "string"),
        ("length", "bigint"),
        ("status", "string"),
        ("data", "binary"),
    ],
    "directory": [
        ("id", "string"),
        ("raw_manifest", "binary"),
    ],
    "directory_entry": [
        ("directory_id", "string"),
        ("name", "binary"),
        ("type", "string"),
        ("target", "string"),
        ("perms", "int"),
    ],
    "origin": [
        ("id", "string"),
        ("url", "string"),
    ],
    "origin_visit": [
        ("origin", "string"),
        ("visit", "bigint"),
        ("date", "timestamp"),
        ("type", "string"),
    ],
    "origin_visit_status": [
        ("origin", "string"),
        ("visit", "bigint"),
        ("date", "timestamp"),
        ("status", "string"),
        ("snapshot", "string"),  # was "snapshot_id" in 2021 schema
        ("type", "string"),
    ],
    "release": [
        ("id", "string"),
        ("name", "binary"),
        ("message", "binary"),
        ("target", "string"),
        ("target_type", "string"),
        ("author", "binary"),
        ("date", "timestamp"),
        ("date_offset", "smallint"),
        ("date_raw_offset_bytes", "binary"),
        ("raw_manifest", "binary"),
    ],
    "revision": [
        ("id", "string"),
        ("message", "binary"),
        ("author", "binary"),
        ("date", "timestamp"),
        ("date_offset", "smallint"),
        ("date_raw_offset_bytes", "binary"),
        ("committer", "binary"),
        ("committer_date", "timestamp"),
        ("committer_offset", "smallint"),
        ("committer_date_raw_offset_bytes", "binary"),
        ("directory", "string"),
        ("type", "string"),
        ("raw_manifest", "binary"),
    ],
    "revision_history": [
        ("id", "string"),
        ("parent_id", "string"),
        ("parent_rank", "int"),
    ],
    "skipped_content": [
        ("sha1", "string"),
        ("sha1_git", "string"),
        ("sha256", "string"),
        ("blake2s256", "string"),
        ("length", "bigint"),
        ("status", "string"),
        ("reason", "string"),
    ],
    "snapshot": [
        ("id", "string"),
    ],
    "snapshot_branch": [
        ("snapshot_id", "string"),
        ("name", "binary"),
        ("target", "string"),
        ("target_type", "string"),
    ],
}


def athena_client():
    region = os.getenv("AWS_REGION", "us-east-1")
    return boto3.client(
        "athena",
        region_name=region,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID") or None,
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY") or None,
        aws_session_token=os.getenv("AWS_SESSION_TOKEN") or None,
    )


def run_query(
    client, query: str, *, database: str | None, output_location: str, poll_seconds: float = 1.0
) -> dict:
    request: dict = {
        "QueryString": query,
        "ResultConfiguration": {"OutputLocation": output_location},
    }
    if database:
        request["QueryExecutionContext"] = {"Database": database}

    response = client.start_query_execution(**request)
    qid = response["QueryExecutionId"]

    while True:
        status_response = client.get_query_execution(QueryExecutionId=qid)
        state = status_response["QueryExecution"]["Status"]["State"]
        if state in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            break
        time.sleep(poll_seconds)

    if state != "SUCCEEDED":
        reason = status_response["QueryExecution"]["Status"].get("StateChangeReason", "")
        raise RuntimeError(f"{state}: {reason}\n\nQuery:\n{query}")

    return status_response["QueryExecution"]


def create_database_sql(database_name: str) -> str:
    return f"CREATE DATABASE IF NOT EXISTS {database_name}"


def create_table_sql(database_name: str, table_name: str, location_prefix: str) -> str:
    fields = ",\n".join(f"    `{name}` {type_}" for name, type_ in TABLES[table_name])
    location = f"{location_prefix.rstrip('/')}/orc/{table_name}/"
    return f"""CREATE EXTERNAL TABLE IF NOT EXISTS {database_name}.{table_name} (
{fields}
)
STORED AS ORC
LOCATION '{location}'
TBLPROPERTIES ("orc.compress"="ZSTD")"""


def repair_table_sql(database_name: str, table_name: str) -> str:
    return f"MSCK REPAIR TABLE {database_name}.{table_name}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create Software Heritage Athena tables without installing swh.export."
    )
    parser.add_argument(
        "--database-name",
        required=True,
        help="Athena database name to create, e.g. swh_graph_2025_10_08",
    )
    parser.add_argument(
        "--location-prefix",
        required=True,
        help=(
            "S3 prefix for the Software Heritage dataset, e.g. "
            "s3://softwareheritage/graph/2025-10-08"
        ),
    )
    parser.add_argument(
        "--output-location",
        default=os.getenv("ATHENA_S3_STAGING_DIR"),
        help="Your Athena query-results bucket/prefix",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Drop and recreate supported tables if they already exist",
    )
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    args = parser.parse_args()

    load_dotenv()

    if not args.output_location:
        raise SystemExit("Missing --output-location and ATHENA_S3_STAGING_DIR is not set.")

    client = athena_client()

    print(f"Creating database {args.database_name} ...")
    run_query(
        client,
        create_database_sql(args.database_name),
        database="default",
        output_location=args.output_location,
        poll_seconds=args.poll_seconds,
    )

    if args.replace:
        for table_name in TABLES:
            print(f"Dropping existing table {table_name} ...")
            run_query(
                client,
                f"DROP TABLE IF EXISTS {args.database_name}.{table_name}",
                database=args.database_name,
                output_location=args.output_location,
                poll_seconds=args.poll_seconds,
            )

    for table_name in TABLES:
        print(f"Creating table {table_name} ...")
        run_query(
            client,
            create_table_sql(args.database_name, table_name, args.location_prefix),
            database=args.database_name,
            output_location=args.output_location,
            poll_seconds=args.poll_seconds,
        )

    for table_name in TABLES:
        print(f"Repairing metadata for {table_name} ...")
        run_query(
            client,
            repair_table_sql(args.database_name, table_name),
            database=args.database_name,
            output_location=args.output_location,
            poll_seconds=args.poll_seconds,
        )

    print()
    print("Done. You can now test with:")
    print("  python tools/test_athena_connection.py --named-query list_databases")
    print(
        "  python tools/test_athena_connection.py "
        f"--database {args.database_name} --named-query list_tables"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
