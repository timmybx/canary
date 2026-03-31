from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3  # pyright: ignore[reportMissingImports]
from botocore.exceptions import (  # pyright: ignore[reportMissingImports]
    BotoCoreError,
    ClientError,
)
from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]

# Load .env once at import time rather than inside the hot collection path
load_dotenv()

DEFAULT_REGION = "us-east-1"
DEFAULT_DATABASE = os.getenv("ATHENA_DATABASE", "swh_jenkins")
DEFAULT_POLL_INITIAL_SECONDS = 0.5
DEFAULT_POLL_MAX_SECONDS = 5.0
DEFAULT_POLL_BACKOFF_FACTOR = 1.5
DEFAULT_OUT_DIR = Path("data/raw/software_heritage")
DEFAULT_MAX_VISITS = 1
DEFAULT_DIRECTORY_BATCH_SIZE = 20
DEFAULT_MAX_DIRECTORIES = 100


# ---------------------------------------------------------------------------
# Module-level boto3 client cache — one client per region, reused across calls
# ---------------------------------------------------------------------------
_ATHENA_CLIENT_CACHE: dict[str, Any] = {}


def _get_athena_client():
    """Return a cached Athena client for the configured region."""
    region = os.getenv("AWS_REGION", DEFAULT_REGION)
    if region not in _ATHENA_CLIENT_CACHE:
        _ATHENA_CLIENT_CACHE[region] = boto3.client(
            "athena",
            region_name=region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID") or None,
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY") or None,
            aws_session_token=os.getenv("AWS_SESSION_TOKEN") or None,
        )
    return _ATHENA_CLIENT_CACHE[region]


@dataclass(slots=True)
class SwhVisitFeatures:
    source: str
    collected_at: str
    repo_url: str
    visit: int
    visit_date: str
    snapshot_id: str
    has_readme: bool
    has_dot_github: bool
    has_jenkinsfile: bool
    has_travis_yml: bool


@dataclass(slots=True)
class AthenaQueryResult:
    rows: list[dict[str, str | None]]
    query_execution_id: str
    elapsed_s: float
    data_scanned_bytes: int | None


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")


def _normalize_repo_slug(repo_url: str) -> str:
    slug = repo_url.rstrip("/").split("/")[-1].strip()
    if not slug:
        return "unknown-repo"
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in slug)


def _format_bytes(num_bytes: int | None) -> str:
    if num_bytes is None:
        return "unknown"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(num_bytes)
    unit = units[0]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            break
        value /= 1024.0
    return f"{value:.2f} {unit}"


def _log(message: str, *, verbose: bool = True) -> None:
    if verbose:
        print(f"[INFO] {message}")


def _chunked(values: list[str], chunk_size: int) -> list[list[str]]:
    size = max(1, int(chunk_size))
    return [values[i : i + size] for i in range(0, len(values), size)]


def _poll_until_done(
    client: Any,
    query_execution_id: str,
    *,
    initial_seconds: float = DEFAULT_POLL_INITIAL_SECONDS,
    max_seconds: float = DEFAULT_POLL_MAX_SECONDS,
    backoff_factor: float = DEFAULT_POLL_BACKOFF_FACTOR,
) -> dict[str, Any]:
    """
    Poll Athena with exponential backoff instead of a fixed interval.

    Starts at ``initial_seconds``, multiplies by ``backoff_factor`` each
    iteration, and caps at ``max_seconds``.  This cuts the number of
    get_query_execution API calls significantly for typical query durations.
    """
    delay = max(0.1, initial_seconds)
    while True:
        resp = client.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return resp
        time.sleep(delay)
        delay = min(delay * backoff_factor, max_seconds)


def _run_athena_query(
    query: str,
    *,
    database: str,
    output_location: str,
    poll_initial_seconds: float = DEFAULT_POLL_INITIAL_SECONDS,
    poll_max_seconds: float = DEFAULT_POLL_MAX_SECONDS,
    label: str = "query",
    verbose: bool = True,
) -> AthenaQueryResult:
    # Reuse the cached client — no per-call construction overhead
    client = _get_athena_client()
    started = time.monotonic()

    _log(f"Starting Athena {label}...", verbose=verbose)
    response = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_location},
    )
    query_execution_id = response["QueryExecutionId"]
    _log(f"Athena {label} query_execution_id={query_execution_id}", verbose=verbose)

    status_response = _poll_until_done(
        client,
        query_execution_id,
        initial_seconds=poll_initial_seconds,
        max_seconds=poll_max_seconds,
    )

    elapsed_s = time.monotonic() - started
    query_execution = status_response["QueryExecution"]
    state = query_execution["Status"]["State"]
    stats = query_execution.get("Statistics", {})
    data_scanned_bytes = stats.get("DataScannedInBytes")
    if not isinstance(data_scanned_bytes, int):
        data_scanned_bytes = None

    if state != "SUCCEEDED":
        reason = query_execution["Status"].get("StateChangeReason", "")
        raise RuntimeError(
            f"Athena query failed: label={label} state={state} "
            f"query_execution_id={query_execution_id} elapsed_s={elapsed_s:.1f} "
            f"scanned={_format_bytes(data_scanned_bytes)} reason={reason}"
        )

    paginator = client.get_paginator("get_query_results")
    rows: list[list[str | None]] = []
    columns: list[str] | None = None

    for page in paginator.paginate(QueryExecutionId=query_execution_id):
        result_set = page["ResultSet"]
        if columns is None:
            columns = [str(col["Name"]) for col in result_set["ResultSetMetadata"]["ColumnInfo"]]
        for row in result_set["Rows"]:
            rows.append([cell.get("VarCharValue") for cell in row.get("Data", [])])

    if not columns:
        parsed_rows: list[dict[str, str | None]] = []
    else:
        if rows and rows[0] == columns:
            rows = rows[1:]
        parsed_rows = [dict(zip(columns, row, strict=False)) for row in rows]

    _log(
        (
            f"Finished Athena {label}: rows={len(parsed_rows)} "
            f"elapsed_s={elapsed_s:.1f} "
            f"scanned={_format_bytes(data_scanned_bytes)}"
        ),
        verbose=verbose,
    )
    return AthenaQueryResult(
        rows=parsed_rows,
        query_execution_id=query_execution_id,
        elapsed_s=elapsed_s,
        data_scanned_bytes=data_scanned_bytes,
    )


def _repo_visits_query(repo_url: str, *, max_visits: int) -> str:
    repo = _sql_escape(repo_url)
    return f"""
SELECT
    origin AS repo_url,
    visit,
    visit_date,
    snapshot_id
FROM jenkins_visits
WHERE origin = '{repo}'
ORDER BY visit_date DESC
LIMIT {max(1, int(max_visits))}
""".strip()


def _snapshot_directories_query(snapshot_id: str, *, max_directories: int) -> str:
    snap = _sql_escape(snapshot_id)
    return f"""
SELECT DISTINCT r.directory
FROM jenkins_snapshot_branch sb
JOIN jenkins_revision r
  ON sb.target = r.id
WHERE sb.snapshot_id = '{snap}'
  AND r.directory IS NOT NULL
LIMIT {max(1, int(max_directories))}
""".strip()


def _directory_entries_query(directory_ids: list[str]) -> str:
    ids_sql = ", ".join(f"'{_sql_escape(d)}'" for d in directory_ids)
    return f"""
SELECT
    directory_id,
    LOWER(entry_name) AS entry_name,
    type
FROM jenkins_directory_entry
WHERE directory_id IN ({ids_sql})
""".strip()


def _extract_feature_flags(entry_rows: list[dict[str, str | None]]) -> dict[str, bool]:
    names = {
        (row.get("entry_name") or "").strip().lower()
        for row in entry_rows
        if row.get("entry_name") is not None
    }
    return {
        "has_readme": any(name in {"readme", "readme.md", "readme.txt"} for name in names),
        "has_dot_github": ".github" in names,
        "has_jenkinsfile": "jenkinsfile" in names,
        "has_travis_yml": ".travis.yml" in names,
    }


def collect_software_heritage_athena_repo(
    *,
    repo_url: str,
    database: str = DEFAULT_DATABASE,
    output_location: str | None = None,
    poll_initial_seconds: float = DEFAULT_POLL_INITIAL_SECONDS,
    poll_max_seconds: float = DEFAULT_POLL_MAX_SECONDS,
    max_visits: int = DEFAULT_MAX_VISITS,
    directory_batch_size: int = DEFAULT_DIRECTORY_BATCH_SIZE,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    verbose: bool = True,
) -> list[dict[str, Any]]:
    if not output_location:
        output_location = os.getenv("ATHENA_S3_STAGING_DIR")
    if not output_location:
        raise ValueError("ATHENA_S3_STAGING_DIR is required")

    started = time.monotonic()
    _log(
        (
            "Collecting Software Heritage Athena signals for "
            f"repo={repo_url} database={database} max_visits={max_visits} "
            f"directory_batch_size={directory_batch_size} "
            f"max_directories={max_directories}"
        ),
        verbose=verbose,
    )

    visits_result = _run_athena_query(
        _repo_visits_query(repo_url, max_visits=max_visits),
        database=database,
        output_location=output_location,
        poll_initial_seconds=poll_initial_seconds,
        poll_max_seconds=poll_max_seconds,
        label="repo_visits",
        verbose=verbose,
    )
    visit_rows = visits_result.rows

    if not visit_rows:
        _log("No archived visits found with snapshot_id; returning no records.", verbose=verbose)
        return []

    collected_at = _utc_now_iso()
    results: list[dict[str, Any]] = []
    snapshot_cache: dict[str, dict[str, bool]] = {}
    total_scanned_bytes = visits_result.data_scanned_bytes or 0

    for index, visit_row in enumerate(visit_rows, start=1):
        snapshot_id = visit_row.get("snapshot_id") or ""
        if not snapshot_id:
            continue

        if snapshot_id in snapshot_cache:
            feature_flags = snapshot_cache[snapshot_id]
            _log(
                (
                    "Reusing cached snapshot feature flags for "
                    f"snapshot_id={snapshot_id} ({index}/{len(visit_rows)})"
                ),
                verbose=verbose,
            )
        else:
            directories_result = _run_athena_query(
                _snapshot_directories_query(snapshot_id, max_directories=max_directories),
                database=database,
                output_location=output_location,
                poll_initial_seconds=poll_initial_seconds,
                poll_max_seconds=poll_max_seconds,
                label=f"snapshot_directories[{index}/{len(visit_rows)}] snapshot_id={snapshot_id}",
                verbose=verbose,
            )
            total_scanned_bytes += directories_result.data_scanned_bytes or 0
            directory_ids = [
                row.get("directory") or ""
                for row in directories_result.rows
                if (row.get("directory") or "").strip()
            ]
            # DISTINCT is already in the SQL; no need to dedup again in Python

            if not directory_ids:
                _log(
                    (
                        "No root directories found for "
                        f"snapshot_id={snapshot_id}; defaulting feature flags to False."
                    ),
                    verbose=verbose,
                )
                feature_flags = {
                    "has_readme": False,
                    "has_dot_github": False,
                    "has_jenkinsfile": False,
                    "has_travis_yml": False,
                }
            else:
                entry_rows: list[dict[str, str | None]] = []
                batches = _chunked(directory_ids, directory_batch_size)
                _log(
                    (
                        "Fetching directory entries for "
                        f"snapshot_id={snapshot_id}: directories={len(directory_ids)} "
                        f"batches={len(batches)}"
                    ),
                    verbose=verbose,
                )
                for batch_index, batch in enumerate(batches, start=1):
                    entries_result = _run_athena_query(
                        _directory_entries_query(batch),
                        database=database,
                        output_location=output_location,
                        poll_initial_seconds=poll_initial_seconds,
                        poll_max_seconds=poll_max_seconds,
                        label=(
                            "directory_entries["
                            f"{index}/{len(visit_rows)} "
                            f"batch {batch_index}/{len(batches)}] "
                            f"snapshot_id={snapshot_id}"
                        ),
                        verbose=verbose,
                    )
                    total_scanned_bytes += entries_result.data_scanned_bytes or 0
                    entry_rows.extend(entries_result.rows)

                    # Short-circuit: stop fetching batches once all 4 flags are True
                    if _extract_feature_flags(entry_rows) == {
                        "has_readme": True,
                        "has_dot_github": True,
                        "has_jenkinsfile": True,
                        "has_travis_yml": True,
                    }:
                        _log(
                            f"All feature flags found after batch {batch_index}/{len(batches)}; "
                            "skipping remaining batches.",
                            verbose=verbose,
                        )
                        break

                feature_flags = _extract_feature_flags(entry_rows)
                _log(
                    (
                        f"Derived snapshot feature flags for snapshot_id={snapshot_id}: "
                        f"has_readme={feature_flags['has_readme']} "
                        f"has_dot_github={feature_flags['has_dot_github']} "
                        f"has_jenkinsfile={feature_flags['has_jenkinsfile']} "
                        f"has_travis_yml={feature_flags['has_travis_yml']}"
                    ),
                    verbose=verbose,
                )

            snapshot_cache[snapshot_id] = feature_flags

        item = SwhVisitFeatures(
            source="software_heritage_athena",
            collected_at=collected_at,
            repo_url=visit_row.get("repo_url") or repo_url,
            visit=int(visit_row.get("visit") or 0),
            visit_date=visit_row.get("visit_date") or "",
            snapshot_id=snapshot_id,
            has_readme=feature_flags["has_readme"],
            has_dot_github=feature_flags["has_dot_github"],
            has_jenkinsfile=feature_flags["has_jenkinsfile"],
            has_travis_yml=feature_flags["has_travis_yml"],
        )
        results.append(asdict(item))

    elapsed_s = time.monotonic() - started
    _log(
        (
            f"Completed collection for repo={repo_url}: visits={len(visit_rows)} "
            f"records={len(results)} total_elapsed_s={elapsed_s:.1f} "
            f"approximate_scanned={_format_bytes(total_scanned_bytes)} "
            f"unique_snapshots={len(snapshot_cache)}"
        ),
        verbose=verbose,
    )
    return results


def write_jsonl(records: list[dict[str, Any]], out_path: str | Path) -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True) + "\n")


def collect_software_heritage_athena_repo_to_file(
    *,
    repo_url: str,
    database: str = DEFAULT_DATABASE,
    out_dir: str | Path = DEFAULT_OUT_DIR,
    output_location: str | None = None,
    poll_initial_seconds: float = DEFAULT_POLL_INITIAL_SECONDS,
    poll_max_seconds: float = DEFAULT_POLL_MAX_SECONDS,
    max_visits: int = DEFAULT_MAX_VISITS,
    directory_batch_size: int = DEFAULT_DIRECTORY_BATCH_SIZE,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    verbose: bool = True,
) -> Path:
    records = collect_software_heritage_athena_repo(
        repo_url=repo_url,
        database=database,
        output_location=output_location,
        poll_initial_seconds=poll_initial_seconds,
        poll_max_seconds=poll_max_seconds,
        max_visits=max_visits,
        directory_batch_size=directory_batch_size,
        max_directories=max_directories,
        verbose=verbose,
    )
    out_path = Path(out_dir) / f"{_normalize_repo_slug(repo_url)}.software_heritage.jsonl"
    write_jsonl(records, out_path)
    return out_path


def collect_software_heritage_athena_repos_parallel(
    repo_urls: list[str],
    *,
    database: str = DEFAULT_DATABASE,
    out_dir: str | Path = DEFAULT_OUT_DIR,
    output_location: str | None = None,
    poll_initial_seconds: float = DEFAULT_POLL_INITIAL_SECONDS,
    poll_max_seconds: float = DEFAULT_POLL_MAX_SECONDS,
    max_visits: int = DEFAULT_MAX_VISITS,
    directory_batch_size: int = DEFAULT_DIRECTORY_BATCH_SIZE,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    max_workers: int = 8,
    verbose: bool = True,
) -> dict[str, Path | Exception]:
    """
    Collect data for multiple repos concurrently using a thread pool.

    Athena accepts up to 20 concurrent queries per account by default, so
    ``max_workers=8`` is a safe conservative default.

    Returns a mapping of repo_url → output Path (or the Exception raised).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[str, Path | Exception] = {}

    def _collect_one(url: str) -> Path:
        return collect_software_heritage_athena_repo_to_file(
            repo_url=url,
            database=database,
            out_dir=out_dir,
            output_location=output_location,
            poll_initial_seconds=poll_initial_seconds,
            poll_max_seconds=poll_max_seconds,
            max_visits=max_visits,
            directory_batch_size=directory_batch_size,
            max_directories=max_directories,
            verbose=verbose,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_url = {pool.submit(_collect_one, url): url for url in repo_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                results[url] = future.result()
            except Exception as exc:  # noqa: BLE001
                _log(f"Failed to collect {url}: {exc}", verbose=verbose)
                results[url] = exc

    return results


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Collect top-level historical repository indicators from Software Heritage via Athena."
        )
    )
    parser.add_argument("--repo-url", required=True, help="Canonical repository URL to query.")
    parser.add_argument(
        "--database",
        default=DEFAULT_DATABASE,
        help=f"Athena database name (default: {DEFAULT_DATABASE}).",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help=f"Directory for JSONL output (default: {DEFAULT_OUT_DIR}).",
    )
    parser.add_argument(
        "--poll-initial-seconds",
        type=float,
        default=DEFAULT_POLL_INITIAL_SECONDS,
        help=(
            "Initial polling interval for Athena queries "
            f"(default: {DEFAULT_POLL_INITIAL_SECONDS}). "
            "Uses exponential backoff up to --poll-max-seconds."
        ),
    )
    parser.add_argument(
        "--poll-max-seconds",
        type=float,
        default=DEFAULT_POLL_MAX_SECONDS,
        help=f"Maximum polling interval ceiling (default: {DEFAULT_POLL_MAX_SECONDS}).",
    )
    parser.add_argument(
        "--max-visits",
        type=int,
        default=DEFAULT_MAX_VISITS,
        help=f"Maximum number of archived visits to inspect (default: {DEFAULT_MAX_VISITS}).",
    )
    parser.add_argument(
        "--directory-batch-size",
        type=int,
        default=DEFAULT_DIRECTORY_BATCH_SIZE,
        help=(
            "How many directory IDs to include in each jenkins_directory_entry batch "
            f"query (default: {DEFAULT_DIRECTORY_BATCH_SIZE})."
        ),
    )
    parser.add_argument(
        "--max-directories",
        type=int,
        default=DEFAULT_MAX_DIRECTORIES,
        help=(
            "Maximum number of root directories to inspect per snapshot "
            f"(default: {DEFAULT_MAX_DIRECTORIES})."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational logging and print only final status/errors.",
    )
    args = parser.parse_args()

    try:
        out_path = collect_software_heritage_athena_repo_to_file(
            repo_url=args.repo_url,
            database=args.database,
            out_dir=args.out_dir,
            poll_initial_seconds=args.poll_initial_seconds,
            poll_max_seconds=args.poll_max_seconds,
            max_visits=args.max_visits,
            directory_batch_size=args.directory_batch_size,
            max_directories=args.max_directories,
            verbose=not args.quiet,
        )
    except (ValueError, RuntimeError, BotoCoreError, ClientError) as exc:
        print(f"[ERROR] {exc}")
        return 1

    print(f"Wrote Software Heritage Athena records to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
