from __future__ import annotations

import json
import os
import re
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
DEFAULT_OUT_DIR = Path("data/raw/software_heritage_athena")
DEFAULT_MAX_VISITS = 1
DEFAULT_DIRECTORY_BATCH_SIZE = 20
DEFAULT_MAX_DIRECTORIES = 100

# ---------------------------------------------------------------------------
# Commit message keyword sets for revision signal extraction
# ---------------------------------------------------------------------------

_SECURITY_COMMIT_KEYWORDS: frozenset[str] = frozenset(
    {
        "cve",
        "vulnerability",
        "vuln",
        "exploit",
        "security fix",
        "security patch",
        "security update",
        "rce",
        "xss",
        "injection",
        "csrf",
        "ssrf",
        "privilege escalation",
        "path traversal",
        "authentication bypass",
        "arbitrary code",
        "buffer overflow",
        "sanitize",
        "sanitise",
        "information disclosure",
    }
)

_CONVENTIONAL_COMMIT_RE = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+?\))?!?:",
    re.IGNORECASE,
)

_ISSUE_REF_RE = re.compile(r"#\d+")

_MERGE_COMMIT_RE = re.compile(r"^merge\b", re.IGNORECASE)


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
    # --- existing CI / governance flags ---
    has_readme: bool
    has_dot_github: bool
    has_jenkinsfile: bool
    has_travis_yml: bool
    # --- new directory-structure signals (free: same query, more name checks) ---
    has_security_md: bool  # explicit security policy
    has_changelog: bool  # disciplined release tracking
    has_contributing_md: bool  # contributor guidance
    has_dockerfile: bool  # containerisation
    has_pom_xml: bool  # Maven build (standard for Jenkins plugins)
    has_build_gradle: bool  # Gradle build
    has_mvn_wrapper: bool  # reproducible Maven wrapper (.mvn/)
    has_tests_directory: bool  # src/test, tests/, or spec/ present
    has_github_actions: bool  # .github/workflows directory (GitHub Actions)
    has_dependabot: bool  # .github/dependabot.yml automated deps
    has_sonar_config: bool  # sonar-project.properties
    has_snyk_config: bool  # .snyk file
    top_level_entry_count: int  # rough complexity proxy
    # --- revision-based signals (from jenkins_revision_meta) ---
    commit_count: int  # total commits in snapshot
    days_since_last_commit: float | None  # staleness relative to visit date
    author_committer_lag_p50_hours: float | None  # code review proxy (median lag)
    author_committer_lag_p90_hours: float | None  # code review proxy (90th pct)
    timezone_diversity: int  # distinct tz offsets (distributed team proxy)
    weekend_commit_fraction: float | None  # hobbyist vs professional maintenance
    security_fix_commit_count: int  # commits mentioning CVE/vuln/etc
    merge_commit_fraction: float | None  # PR workflow indicator
    conventional_commit_fraction: float | None  # commit message discipline
    issue_reference_rate: float | None  # issue tracker linkage
    empty_message_rate: float | None  # poor discipline signal
    author_committer_mismatch_rate: float | None  # tz offset mismatch as review proxy


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


def _revision_meta_query(snapshot_id: str) -> str:
    """
    Pull all revision metadata for a snapshot from the pre-extracted
    jenkins_revision_meta table.  One row per commit reachable from
    any branch tip in the snapshot.
    """
    snap = _sql_escape(snapshot_id)
    return f"""
SELECT
    jrm.revision_id,
    jrm.author_date,
    jrm.committer_date,
    jrm.author_tz_offset_minutes,
    jrm.committer_tz_offset_minutes,
    jrm.commit_message
FROM jenkins_snapshot_branch jsb
JOIN jenkins_revision_meta jrm
  ON jsb.target = jrm.revision_id
WHERE jsb.snapshot_id = '{snap}'
""".strip()


def _safe_median(values: list[float]) -> float | None:
    """Return the median of a non-empty list, or None."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2.0
    return s[mid]


def _safe_percentile(values: list[float], p: float) -> float | None:
    """Return the p-th percentile (0-100) of a list, or None."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    return s[lo] * (1 - (idx - lo)) + s[hi] * (idx - lo)


def _parse_swh_timestamp(value: str | None) -> datetime | None:
    """Parse SWH timestamp strings into timezone-aware datetimes."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def _extract_revision_signals(
    revision_rows: list[dict[str, str | None]],
    visit_date_str: str,
) -> dict[str, Any]:
    """
    Compute all revision-based signals from the rows returned by
    _revision_meta_query.  Returns a dict ready to unpack into
    SwhVisitFeatures fields.
    """
    _EMPTY: dict[str, Any] = {
        "commit_count": 0,
        "days_since_last_commit": None,
        "author_committer_lag_p50_hours": None,
        "author_committer_lag_p90_hours": None,
        "timezone_diversity": 0,
        "weekend_commit_fraction": None,
        "security_fix_commit_count": 0,
        "merge_commit_fraction": None,
        "conventional_commit_fraction": None,
        "issue_reference_rate": None,
        "empty_message_rate": None,
        "author_committer_mismatch_rate": None,
    }

    if not revision_rows:
        return _EMPTY

    visit_dt = _parse_swh_timestamp(visit_date_str)
    n = len(revision_rows)

    author_dates: list[datetime] = []
    committer_dates: list[datetime] = []
    lag_hours: list[float] = []
    tz_offsets: set[int] = set()
    weekend_commits = 0
    security_commits = 0
    merge_commits = 0
    conventional_commits = 0
    issue_ref_commits = 0
    empty_message_commits = 0
    tz_mismatch_commits = 0

    for row in revision_rows:
        author_dt = _parse_swh_timestamp(row.get("author_date"))
        committer_dt = _parse_swh_timestamp(row.get("committer_date"))

        if author_dt:
            author_dates.append(author_dt)
            # weekend: Saturday=5, Sunday=6
            if author_dt.weekday() >= 5:
                weekend_commits += 1

        if committer_dt:
            committer_dates.append(committer_dt)

        if author_dt and committer_dt and committer_dt >= author_dt:
            lag_h = (committer_dt - author_dt).total_seconds() / 3600.0
            lag_hours.append(lag_h)

        # timezone diversity
        tz_author = row.get("author_tz_offset_minutes")
        tz_committer = row.get("committer_tz_offset_minutes")
        try:
            if tz_author is not None:
                tz_offsets.add(int(tz_author))
        except (ValueError, TypeError):
            pass

        # author/committer tz mismatch as code review proxy
        try:
            if tz_author is not None and tz_committer is not None:
                if int(tz_author) != int(tz_committer):
                    tz_mismatch_commits += 1
        except (ValueError, TypeError):
            pass

        # commit message signals
        msg = (row.get("commit_message") or "").strip()
        msg_lower = msg.lower()

        if not msg or msg in {".", "-", "wip"}:
            empty_message_commits += 1

        if any(kw in msg_lower for kw in _SECURITY_COMMIT_KEYWORDS):
            security_commits += 1

        if _MERGE_COMMIT_RE.match(msg):
            merge_commits += 1

        if _CONVENTIONAL_COMMIT_RE.match(msg):
            conventional_commits += 1

        if _ISSUE_REF_RE.search(msg):
            issue_ref_commits += 1

    # staleness: days between most recent author_date and visit date
    days_since: float | None = None
    if author_dates and visit_dt:
        latest = max(author_dates)
        delta = visit_dt - latest
        days_since = max(0.0, delta.total_seconds() / 86400.0)

    def _round_or_none(value: float | None, ndigits: int) -> float | None:
        return round(value, ndigits) if value is not None else None

    def _rate(count: int) -> float | None:
        return count / n if n > 0 else None

    return {
        "commit_count": n,
        "days_since_last_commit": _round_or_none(days_since, 1),
        "author_committer_lag_p50_hours": _round_or_none(_safe_percentile(lag_hours, 50), 2),
        "author_committer_lag_p90_hours": _round_or_none(_safe_percentile(lag_hours, 90), 2),
        "timezone_diversity": len(tz_offsets),
        "weekend_commit_fraction": _round_or_none(
            weekend_commits / len(author_dates) if author_dates else None, 4
        ),
        "security_fix_commit_count": security_commits,
        "merge_commit_fraction": _round_or_none(_rate(merge_commits), 4),
        "conventional_commit_fraction": _round_or_none(_rate(conventional_commits), 4),
        "issue_reference_rate": _round_or_none(_rate(issue_ref_commits), 4),
        "empty_message_rate": _round_or_none(_rate(empty_message_commits), 4),
        "author_committer_mismatch_rate": _round_or_none(_rate(tz_mismatch_commits), 4),
    }


def _extract_feature_flags(entry_rows: list[dict[str, str | None]]) -> dict[str, Any]:
    names = {
        (row.get("entry_name") or "").strip().lower()
        for row in entry_rows
        if row.get("entry_name") is not None
    }
    return {
        # existing flags
        "has_readme": any(name in {"readme", "readme.md", "readme.txt"} for name in names),
        "has_dot_github": ".github" in names,
        "has_jenkinsfile": "jenkinsfile" in names,
        "has_travis_yml": ".travis.yml" in names,
        # new directory-structure signals
        "has_security_md": any(
            name in {"security.md", "security.txt", "security"} for name in names
        ),
        "has_changelog": any(
            name
            in {
                "changelog",
                "changelog.md",
                "changelog.txt",
                "changes",
                "changes.md",
                "history.md",
            }
            for name in names
        ),
        "has_contributing_md": any(
            name in {"contributing", "contributing.md", "contributing.txt"} for name in names
        ),
        "has_dockerfile": any(name in {"dockerfile", "dockerfile.build"} for name in names),
        "has_pom_xml": "pom.xml" in names,
        "has_build_gradle": any(name in {"build.gradle", "build.gradle.kts"} for name in names),
        "has_mvn_wrapper": ".mvn" in names,
        "has_tests_directory": any(name in {"tests", "test", "spec", "src"} for name in names),
        "has_github_actions": "workflows" in names,  # inside .github — captured as top-level entry
        "has_dependabot": "dependabot.yml" in names,
        "has_sonar_config": any(
            name in {"sonar-project.properties", ".sonarcloud.properties"} for name in names
        ),
        "has_snyk_config": ".snyk" in names,
        "top_level_entry_count": len(names),
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
    revision_cache: dict[str, dict[str, Any]] = {}
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
                    "has_security_md": False,
                    "has_changelog": False,
                    "has_contributing_md": False,
                    "has_dockerfile": False,
                    "has_pom_xml": False,
                    "has_build_gradle": False,
                    "has_mvn_wrapper": False,
                    "has_tests_directory": False,
                    "has_github_actions": False,
                    "has_dependabot": False,
                    "has_sonar_config": False,
                    "has_snyk_config": False,
                    "top_level_entry_count": 0,
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

                    # Short-circuit: stop fetching batches once all boolean flags are True
                    _current_flags = _extract_feature_flags(entry_rows)
                    _all_bool_flags = {
                        k: v for k, v in _current_flags.items() if isinstance(v, bool)
                    }
                    if all(_all_bool_flags.values()):
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
                        f"has_travis_yml={feature_flags['has_travis_yml']} "
                        f"has_pom_xml={feature_flags['has_pom_xml']} "
                        f"has_dockerfile={feature_flags['has_dockerfile']} "
                        f"top_level_entry_count={feature_flags['top_level_entry_count']}"
                    ),
                    verbose=verbose,
                )

            snapshot_cache[snapshot_id] = feature_flags

        # --- revision signals ---
        # Use cached revision signals if we've seen this snapshot before
        revision_signals = revision_cache.get(snapshot_id)
        if revision_signals is None:
            revision_result = _run_athena_query(
                _revision_meta_query(snapshot_id),
                database=database,
                output_location=output_location,
                poll_initial_seconds=poll_initial_seconds,
                poll_max_seconds=poll_max_seconds,
                label=f"revision_meta[{index}/{len(visit_rows)}] snapshot_id={snapshot_id}",
                verbose=verbose,
            )
            total_scanned_bytes += revision_result.data_scanned_bytes or 0
            revision_signals = _extract_revision_signals(
                revision_result.rows,
                visit_row.get("visit_date") or "",
            )
            revision_cache[snapshot_id] = revision_signals
            _log(
                (
                    f"Revision signals for snapshot_id={snapshot_id}: "
                    f"commit_count={revision_signals['commit_count']} "
                    f"days_since_last_commit={revision_signals['days_since_last_commit']} "
                    f"security_fix_commit_count={revision_signals['security_fix_commit_count']} "
                    f"weekend_commit_fraction={revision_signals['weekend_commit_fraction']}"
                ),
                verbose=verbose,
            )

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
            has_security_md=feature_flags["has_security_md"],
            has_changelog=feature_flags["has_changelog"],
            has_contributing_md=feature_flags["has_contributing_md"],
            has_dockerfile=feature_flags["has_dockerfile"],
            has_pom_xml=feature_flags["has_pom_xml"],
            has_build_gradle=feature_flags["has_build_gradle"],
            has_mvn_wrapper=feature_flags["has_mvn_wrapper"],
            has_tests_directory=feature_flags["has_tests_directory"],
            has_github_actions=feature_flags["has_github_actions"],
            has_dependabot=feature_flags["has_dependabot"],
            has_sonar_config=feature_flags["has_sonar_config"],
            has_snyk_config=feature_flags["has_snyk_config"],
            top_level_entry_count=feature_flags["top_level_entry_count"],
            # revision signals
            commit_count=revision_signals["commit_count"],
            days_since_last_commit=revision_signals["days_since_last_commit"],
            author_committer_lag_p50_hours=revision_signals["author_committer_lag_p50_hours"],
            author_committer_lag_p90_hours=revision_signals["author_committer_lag_p90_hours"],
            timezone_diversity=revision_signals["timezone_diversity"],
            weekend_commit_fraction=revision_signals["weekend_commit_fraction"],
            security_fix_commit_count=revision_signals["security_fix_commit_count"],
            merge_commit_fraction=revision_signals["merge_commit_fraction"],
            conventional_commit_fraction=revision_signals["conventional_commit_fraction"],
            issue_reference_rate=revision_signals["issue_reference_rate"],
            empty_message_rate=revision_signals["empty_message_rate"],
            author_committer_mismatch_rate=revision_signals["author_committer_mismatch_rate"],
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


def _nonempty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_plugin_snapshot(plugin_id: str, *, data_dir: str) -> dict[str, Any]:
    snap_path = Path(data_dir) / "plugins" / f"{plugin_id}.snapshot.json"
    if not snap_path.exists():
        raise FileNotFoundError(
            f"Plugin snapshot not found: {snap_path}. "
            f"Run: canary collect plugin --id {plugin_id} --real"
        )
    payload = _read_json(snap_path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid snapshot JSON for plugin '{plugin_id}'")
    return payload


def _scm_to_url(val: object) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        v = val.strip()
        return v or None
    if isinstance(val, dict):
        link = val.get("link") or val.get("url")
        if isinstance(link, str):
            v = link.strip()
            return v or None
    return None


def _infer_repo_url(snapshot: dict[str, Any]) -> str | None:
    url = _scm_to_url(snapshot.get("repo_url"))
    if url:
        return url

    scm = snapshot.get("scm_url")
    url = _scm_to_url(scm)
    if url:
        return url

    plugin_api = snapshot.get("plugin_api")
    if isinstance(plugin_api, dict):
        url = _scm_to_url(plugin_api.get("scm"))
        if url:
            return url

    return None


def _safe_slug(plugin_id: str) -> str:
    return plugin_id.strip().replace("/", "_")


def collect_software_heritage_athena_real(
    *,
    plugin_id: str,
    data_dir: str = "data/raw",
    out_dir: str | Path = "data/raw/software_heritage_athena",
    overwrite: bool = False,
    database: str = DEFAULT_DATABASE,
    output_location: str | None = None,
    max_visits: int = DEFAULT_MAX_VISITS,
    directory_batch_size: int = DEFAULT_DIRECTORY_BATCH_SIZE,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    verbose: bool = True,
) -> dict[str, Any]:
    snapshot = _load_plugin_snapshot(plugin_id, data_dir=data_dir)
    repo_url = _infer_repo_url(snapshot)
    if not repo_url:
        raise RuntimeError(
            f"No repo_url/scm_url found for plugin '{plugin_id}' in its snapshot. "
            "Collect the plugin snapshot first or curate repo_url in the snapshot."
        )

    out_base = Path(out_dir)
    out_base.mkdir(parents=True, exist_ok=True)
    slug = _safe_slug(plugin_id)

    visits_path = out_base / f"{slug}.swh_athena_visits.jsonl"
    index_path = out_base / f"{slug}.swh_athena_index.json"

    if (not overwrite) and _nonempty(index_path) and _nonempty(visits_path):
        return {
            "plugin_id": plugin_id,
            "repo_url": repo_url,
            "backend": "athena",
            "database": database,
            "written": 0,
            "skipped": 1,
            "files": {
                "index": str(index_path),
                "visits": str(visits_path),
            },
        }

    records = collect_software_heritage_athena_repo(
        repo_url=repo_url,
        database=database,
        output_location=output_location,
        max_visits=max_visits,
        directory_batch_size=directory_batch_size,
        max_directories=max_directories,
        verbose=verbose,
    )
    write_jsonl(records, visits_path)

    index_payload = {
        "plugin_id": plugin_id,
        "repo_url": repo_url,
        "backend": "athena",
        "database": database,
        "collected_at": _utc_now_iso(),
        "record_count": len(records),
        "files": {
            "visits": str(visits_path),
        },
    }
    index_path.write_text(
        json.dumps(index_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return {
        "plugin_id": plugin_id,
        "repo_url": repo_url,
        "backend": "athena",
        "database": database,
        "written": 1,
        "skipped": 0,
        "files": {
            "index": str(index_path),
            "visits": str(visits_path),
        },
        "record_count": len(records),
    }


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
