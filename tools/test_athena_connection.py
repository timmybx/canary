from __future__ import annotations

import argparse
import csv
import os
import time
from pathlib import Path

import boto3  # pyright: ignore[reportMissingImports]
import pandas as pd  # pyright: ignore[reportMissingImports]
from botocore.exceptions import (  # pyright: ignore[reportMissingImports]
    BotoCoreError,
    ClientError,
)
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

DEFAULT_REGION = "us-east-1"
DEFAULT_POLL_SECONDS = 1.0

EXPLORATION_QUERIES: dict[str, tuple[str | None, str]] = {
    "list_databases": (
        None,
        "SHOW DATABASES",
    ),
    "list_tables": (
        None,  # filled in at runtime from --database
        "SHOW TABLES IN {database}",
    ),
    "sample_origins": (
        None,  # filled in at runtime from --database
        """
        SELECT url
        FROM origin
        WHERE lower(CAST(url AS varchar)) LIKE '%jenkins%'
        LIMIT 25
        """.strip(),
    ),
    "sample_visits": (
        None,  # filled in at runtime from --database
        """
        SELECT origin, visit, date, type
        FROM origin_visit
        WHERE lower(origin) LIKE '%jenkins%'
        ORDER BY date DESC
        LIMIT 25
        """.strip(),
    ),
    "sample_visit_status": (
        None,  # filled in at runtime from --database
        """
        SELECT origin, visit, date, type, status, snapshot_id
        FROM origin_visit_status
        WHERE lower(origin) LIKE '%jenkins%'
        ORDER BY date DESC
        LIMIT 25
        """.strip(),
    ),
    "readme_probe": (
        None,  # filled in at runtime from --database
        """
        WITH jenkins_revisions AS (
            SELECT DISTINCT sb.target AS revision_id
            FROM origin_visit_status ovs
            JOIN snapshot_branch sb
              ON ovs.snapshot_id = sb.snapshot_id
            WHERE lower(ovs.origin) LIKE '%github.com/jenkinsci/%'
              AND sb.target_type = 'revision'
              AND lower(from_utf8(sb.name, '?')) IN ('head', 'refs/heads/master', 'refs/heads/main')
            LIMIT 200
        ),
        root_dirs AS (
            SELECT DISTINCT r.directory AS directory_id
            FROM revision r
            JOIN jenkins_revisions jr
              ON r.id = jr.revision_id
        )
        SELECT
            de.directory_id,
            from_utf8(de.name, '?') AS entry_name,
            de.type
        FROM directory_entry de
        JOIN root_dirs rd
          ON de.directory_id = rd.directory_id
        WHERE lower(from_utf8(de.name, '?')) IN (
            'readme',
            'readme.md',
            'readme.txt',
            '.github',
            'dependabot.yml'
        )
        LIMIT 100
        """.strip(),
    ),
}


def _athena_client():
    region = os.getenv("AWS_REGION", DEFAULT_REGION)
    return boto3.client(
        "athena",
        region_name=region,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID") or None,
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY") or None,
        aws_session_token=os.getenv("AWS_SESSION_TOKEN") or None,
    )


def _wait_for_query_completion(client, query_execution_id: str, poll_seconds: float) -> str:
    while True:
        response = client.get_query_execution(QueryExecutionId=query_execution_id)
        status = response["QueryExecution"]["Status"]["State"]
        if status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return status
        time.sleep(poll_seconds)


def _get_query_execution_details(client, query_execution_id: str) -> dict[str, object]:
    response = client.get_query_execution(QueryExecutionId=query_execution_id)
    return response["QueryExecution"]


def _results_to_dataframe(client, query_execution_id: str) -> pd.DataFrame:
    paginator = client.get_paginator("get_query_results")
    rows: list[list[str | None]] = []
    column_names: list[str] | None = None

    for page in paginator.paginate(QueryExecutionId=query_execution_id):
        result_set = page["ResultSet"]
        metadata = result_set["ResultSetMetadata"]["ColumnInfo"]
        if column_names is None:
            column_names = [str(col["Name"]) for col in metadata]

        for raw_row in result_set["Rows"]:
            values = [cell.get("VarCharValue") for cell in raw_row.get("Data", [])]
            rows.append(values)

    if not column_names:
        return pd.DataFrame()
    if rows and rows[0] == column_names:
        rows = rows[1:]
    return pd.DataFrame(rows, columns=column_names)


def run_athena_query(
    query: str,
    *,
    database: str | None,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
) -> tuple[str, str, pd.DataFrame | None, dict[str, object]]:
    load_dotenv()
    output_location = os.getenv("ATHENA_S3_STAGING_DIR")
    if not output_location:
        raise ValueError("ATHENA_S3_STAGING_DIR is required in the environment or .env file")

    client = _athena_client()
    request: dict[str, object] = {
        "QueryString": query,
        "ResultConfiguration": {"OutputLocation": output_location},
    }
    if database:
        request["QueryExecutionContext"] = {"Database": database}

    response = client.start_query_execution(**request)
    query_execution_id = response["QueryExecutionId"]
    status = _wait_for_query_completion(client, query_execution_id, poll_seconds)
    query_execution = _get_query_execution_details(client, query_execution_id)
    status_details = query_execution.get("Status")
    reason = (
        str(status_details.get("StateChangeReason") or "").strip()
        if isinstance(status_details, dict)
        else ""
    )

    if status != "SUCCEEDED":
        failure_df = pd.DataFrame([{"status": status, "reason": reason or None}])
        return status, query_execution_id, failure_df, query_execution

    dataframe = _results_to_dataframe(client, query_execution_id)
    return status, query_execution_id, dataframe, query_execution


def _bytes_scanned(details: dict[str, object]) -> int | None:
    stats = details.get("Statistics", {})
    if isinstance(stats, dict):
        value = stats.get("DataScannedInBytes")
        if isinstance(value, int):
            return value
    return None


def _write_csv(df: pd.DataFrame, out_path: str | Path) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)


def _resolve_named_query(name: str, database: str | None) -> tuple[str | None, str]:
    if name not in EXPLORATION_QUERIES:
        valid = ", ".join(sorted(EXPLORATION_QUERIES))
        raise ValueError(f"Unknown named query '{name}'. Valid values: {valid}")

    db_default, query_template = EXPLORATION_QUERIES[name]
    db = database if database is not None else db_default

    if "{database}" in query_template:
        if not database:
            raise ValueError(f"Named query '{name}' requires --database")
        return database, query_template.format(database=database)

    return db, query_template


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Athena proof-of-concept explorer for Software Heritage."
    )
    parser.add_argument(
        "--database",
        default=os.getenv("ATHENA_DATABASE"),
        help="Athena database name. Required for most data queries.",
    )
    parser.add_argument(
        "--query",
        help="Raw SQL query to execute.",
    )
    parser.add_argument(
        "--named-query",
        choices=sorted(EXPLORATION_QUERIES),
        help="Built-in exploration query to execute.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=DEFAULT_POLL_SECONDS,
        help="Polling interval while waiting for query completion.",
    )
    parser.add_argument(
        "--out-csv",
        help="Optional CSV file path for saving results.",
    )
    parser.add_argument(
        "--max-rows-print",
        type=int,
        default=20,
        help="Maximum number of rows to print to stdout.",
    )
    args = parser.parse_args()

    load_dotenv()

    if not os.getenv("AWS_REGION"):
        os.environ["AWS_REGION"] = DEFAULT_REGION

    try:
        if args.query:
            database = args.database
            query = args.query.strip()
        elif args.named_query:
            database, query = _resolve_named_query(args.named_query, args.database)
        else:
            raise ValueError("Provide either --query or --named-query.")
    except ValueError as exc:
        print(exc)
        return 2

    try:
        status, query_execution_id, dataframe, details = run_athena_query(
            query,
            database=database,
            poll_seconds=args.poll_seconds,
        )
    except (BotoCoreError, ClientError, ValueError) as exc:
        print(f"Athena query failed before completion: {exc}")
        return 1

    if status != "SUCCEEDED":
        print(f"Query failed with status: {status}. QueryExecutionId={query_execution_id}")
        if dataframe is not None and not dataframe.empty:
            reason = dataframe.iloc[0].get("reason")
            if reason:
                print(f"Athena reported: {reason}")
        return 1

    scanned = _bytes_scanned(details)
    row_count = 0 if dataframe is None else len(dataframe.index)
    print(f"Query succeeded. QueryExecutionId={query_execution_id}")
    if scanned is not None:
        print(f"Data scanned (bytes): {scanned}")
    print(f"Rows returned: {row_count}")

    if dataframe is not None and not dataframe.empty:
        print()
        print(dataframe.head(args.max_rows_print).to_string(index=False))
        if args.out_csv:
            _write_csv(dataframe, args.out_csv)
            print()
            print(f"Saved CSV: {args.out_csv}")
    else:
        print("No rows returned.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
