from __future__ import annotations

import argparse
import csv
import importlib
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

RAW_SELECT_TEMPLATE = """
--standardSQL
SELECT
  repo.name AS repo,
  actor.login AS actor_login,
  type AS event_type,
  TIMESTAMP(created_at) AS event_ts,
  DATE(TIMESTAMP(created_at)) AS event_date,
  JSON_EXTRACT_SCALAR(payload, '$.action') AS action,
  JSON_EXTRACT_SCALAR(payload, '$.pull_request.merged') AS pr_merged,
  TIMESTAMP(JSON_EXTRACT_SCALAR(payload, '$.pull_request.created_at')) AS pr_created_ts,
  TIMESTAMP(JSON_EXTRACT_SCALAR(payload, '$.pull_request.closed_at')) AS pr_closed_ts,
  TIMESTAMP(JSON_EXTRACT_SCALAR(payload, '$.issue.created_at')) AS issue_created_ts,
  TIMESTAMP(JSON_EXTRACT_SCALAR(payload, '$.issue.closed_at')) AS issue_closed_ts,
  LOWER(
    CONCAT(
      IFNULL(JSON_EXTRACT_SCALAR(payload, '$.pull_request.title'), ''),
      ' ',
      IFNULL(JSON_EXTRACT_SCALAR(payload, '$.pull_request.body'), ''),
      ' ',
      IFNULL(JSON_EXTRACT_SCALAR(payload, '$.issue.title'), ''),
      ' ',
      IFNULL(JSON_EXTRACT_SCALAR(payload, '$.issue.body'), '')
    )
  ) AS text_blob
FROM `{table_name}` {tablesample_clause}
WHERE STARTS_WITH(repo.name, 'jenkinsci/')
  AND ENDS_WITH(repo.name, '-plugin')
"""


def _import_bigquery() -> Any:
    try:
        return importlib.import_module("google.cloud.bigquery")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "google-cloud-bigquery is not installed. "
            "Install it with: pip install google-cloud-bigquery"
        ) from exc


def _default_date_range() -> tuple[str, str]:
    # Use the last 7 complete UTC days to avoid partial "today" data.
    end = datetime.now(UTC).date() - timedelta(days=1)
    start = end - timedelta(days=6)
    return start.strftime("%Y%m%d"), end.strftime("%Y%m%d")


def _parse_yyyymmdd(value: str) -> date:
    return datetime.strptime(value, "%Y%m%d").date()


def _existing_day_tables(client: Any, start_yyyymmdd: str, end_yyyymmdd: str) -> set[str]:
    bigquery = _import_bigquery()
    sql = """
    SELECT table_name
    FROM `githubarchive.day.INFORMATION_SCHEMA.TABLES`
    WHERE table_name BETWEEN @start_yyyymmdd AND @end_yyyymmdd
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("start_yyyymmdd", "STRING", start_yyyymmdd),
            bigquery.ScalarQueryParameter("end_yyyymmdd", "STRING", end_yyyymmdd),
        ]
    )
    rows = list(client.query(sql, job_config=job_config).result())
    return {str(row["table_name"]) for row in rows}


def _build_query_with_sampling(
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    available_tables: set[str],
    sample_percent: float,
) -> str:
    start_date = _parse_yyyymmdd(start_yyyymmdd)
    end_date = _parse_yyyymmdd(end_yyyymmdd)
    if end_date < start_date:
        raise ValueError("end date must be >= start date (format: YYYYMMDD)")
    if sample_percent <= 0 or sample_percent > 100:
        raise ValueError("sample-percent must be > 0 and <= 100")

    tablesample_clause = ""
    if sample_percent < 100:
        tablesample_clause = f"TABLESAMPLE SYSTEM ({sample_percent} PERCENT)"

    raw_parts: list[str] = []
    current = start_date
    while current <= end_date:
        day = current.strftime("%Y%m%d")
        if day in available_tables:
            raw_parts.append(
                RAW_SELECT_TEMPLATE.format(
                    table_name=f"githubarchive.day.{day}",
                    tablesample_clause=tablesample_clause,
                )
            )
        current += timedelta(days=1)

    if not raw_parts:
        raise ValueError(
            "No GH Archive daily tables found in the requested date range. Try an older range."
        )

    raw_union = "\nUNION ALL\n".join(raw_parts)
    # nosec rationale: SQL identifiers here are derived from validated YYYYMMDD values only.
    return f"""  # nosec
WITH raw AS (
{raw_union}
),
enriched AS (
  SELECT
    raw.*,
    COUNTIF(raw.event_type = 'PushEvent') OVER (
      PARTITION BY raw.repo, raw.actor_login
    ) AS push_events_by_actor,
    COUNTIF(raw.event_type = 'PushEvent') OVER (
      PARTITION BY raw.repo
    ) AS push_events_repo_total,
    MAX(
      IF(raw.event_type = 'IssuesEvent' AND raw.action = 'opened', raw.event_ts, NULL)
    ) OVER (
      PARTITION BY raw.repo
      ORDER BY raw.event_ts
      ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS last_issue_open_ts
  FROM raw
)
SELECT
  e.repo AS repo,
  '{start_yyyymmdd}' AS window_start_yyyymmdd,
  '{end_yyyymmdd}' AS window_end_yyyymmdd,
  COUNT(*) AS events_total,
  COUNT(DISTINCT e.actor_login) AS actors_unique,
  COUNTIF(e.event_type = 'PushEvent') AS pushes,
  COUNT(DISTINCT IF(e.event_type = 'PushEvent', e.actor_login, NULL)) AS committers_unique_30d,
  COUNT(DISTINCT IF(e.event_type = 'PushEvent', e.event_date, NULL)) AS push_days_active_30d,
  COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'opened') AS prs_opened,
  COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'closed') AS prs_closed,
  COUNTIF(
    e.event_type = 'PullRequestEvent' AND e.action = 'closed' AND e.pr_merged = 'true'
  ) AS prs_merged,
  COUNTIF(
    e.event_type = 'PullRequestEvent' AND e.action = 'closed' AND e.pr_merged = 'false'
  ) AS prs_closed_unmerged,
  SAFE_DIVIDE(
    COUNTIF(e.event_type = 'PullRequestReviewEvent'),
    NULLIF(COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'opened'), 0)
  ) AS pr_reviewed_ratio,
  APPROX_QUANTILES(
    IF(
      e.event_type = 'PullRequestEvent'
      AND e.action = 'closed'
      AND e.pr_merged = 'true'
      AND e.pr_created_ts IS NOT NULL
      AND e.pr_closed_ts IS NOT NULL,
      TIMESTAMP_DIFF(e.pr_closed_ts, e.pr_created_ts, HOUR),
      NULL
    ),
    100
  )[OFFSET(50)] AS pr_merge_time_p50_hours,
  SAFE_DIVIDE(
    COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'closed' AND e.pr_merged = 'false'),
    NULLIF(COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'opened'), 0)
  ) AS pr_close_without_merge_ratio,
  COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'opened') AS issues_opened,
  COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'closed') AS issues_closed,
  COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'reopened') AS issues_reopened,
  SAFE_DIVIDE(
    COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'reopened'),
    NULLIF(COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'closed'), 0)
  ) AS issue_reopen_rate,
  APPROX_QUANTILES(
    IF(
      e.event_type = 'IssuesEvent'
      AND e.action = 'closed'
      AND e.issue_created_ts IS NOT NULL
      AND e.issue_closed_ts IS NOT NULL,
      TIMESTAMP_DIFF(e.issue_closed_ts, e.issue_created_ts, HOUR),
      NULL
    ),
    100
  )[OFFSET(50)] AS issue_close_time_p50_hours,
  COUNTIF(e.event_type = 'ReleaseEvent') AS releases_30d,
  DATE_DIFF(
    CURRENT_DATE(),
    DATE(MAX(IF(e.event_type = 'ReleaseEvent', e.event_ts, NULL))),
    DAY
  ) AS days_since_last_release,
  IFNULL(
    SAFE_DIVIDE(
      COUNTIF(
        e.event_type = 'PushEvent'
        AND e.last_issue_open_ts IS NOT NULL
        AND TIMESTAMP_DIFF(e.event_ts, e.last_issue_open_ts, HOUR) BETWEEN 0 AND 48
      ),
      NULLIF(COUNTIF(e.event_type = 'IssuesEvent' AND e.action = 'opened'), 0)
    ),
    0
  ) AS hotfix_proxy,
  COUNTIF(
    REGEXP_CONTAINS(
      e.text_blob,
      r'(security|vuln|cve-|xss|sqli|rce|deserializ|csrf|auth|inject)'
    )
  ) AS security_label_proxy,
  SAFE_DIVIDE(
    COUNTIF(e.event_type = 'PushEvent')
      + COUNTIF(e.event_type = 'PullRequestEvent' AND e.action = 'opened'),
    NULLIF(COUNT(DISTINCT e.actor_login), 0)
  ) AS churn_intensity,
  IFNULL(
    MAX(SAFE_DIVIDE(e.push_events_by_actor, NULLIF(e.push_events_repo_total, 0))),
    0
  ) AS owner_concentration
FROM enriched e
GROUP BY e.repo
ORDER BY events_total DESC
"""


def build_features(
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    out_path: str,
    max_bytes_billed: int = 2_000_000_000,
    sample_percent: float = 5.0,
) -> None:
    bigquery = _import_bigquery()
    client = bigquery.Client()
    available_tables = _existing_day_tables(
        client=client,
        start_yyyymmdd=start_yyyymmdd,
        end_yyyymmdd=end_yyyymmdd,
    )
    sql = _build_query_with_sampling(
        start_yyyymmdd=start_yyyymmdd,
        end_yyyymmdd=end_yyyymmdd,
        available_tables=available_tables,
        sample_percent=sample_percent,
    )
    job_config = bigquery.QueryJobConfig(
        maximum_bytes_billed=max_bytes_billed,
    )

    query_job = client.query(sql, job_config=job_config)
    rows = list(query_job.result())
    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "repo",
        "window_start_yyyymmdd",
        "window_end_yyyymmdd",
        "events_total",
        "actors_unique",
        "pushes",
        "committers_unique_30d",
        "push_days_active_30d",
        "prs_opened",
        "prs_closed",
        "prs_merged",
        "pr_reviewed_ratio",
        "pr_merge_time_p50_hours",
        "prs_closed_unmerged",
        "pr_close_without_merge_ratio",
        "issues_opened",
        "issues_closed",
        "issues_reopened",
        "issue_reopen_rate",
        "issue_close_time_p50_hours",
        "releases_30d",
        "days_since_last_release",
        "hotfix_proxy",
        "security_label_proxy",
        "churn_intensity",
        "owner_concentration",
    ]
    with out_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})

    scanned = query_job.total_bytes_processed or 0
    print(f"Wrote {len(rows)} rows to {out_file} (scanned {scanned / (1024**3):.2f} GiB).")


def main() -> None:
    default_start, default_end = _default_date_range()
    parser = argparse.ArgumentParser(
        description="Build small GH Archive feature samples for Jenkins plugin repos."
    )
    parser.add_argument("--start", default=default_start, help="Start date in YYYYMMDD.")
    parser.add_argument("--end", default=default_end, help="End date in YYYYMMDD.")
    parser.add_argument(
        "--out",
        default="data/processed/gharchive_jenkins_plugins_last_week.csv",
        help="Output CSV path.",
    )
    parser.add_argument(
        "--max-bytes-billed",
        type=int,
        default=2_000_000_000,
        help="BigQuery max bytes billed safety cap (default: 2GB).",
    )
    parser.add_argument(
        "--sample-percent",
        type=float,
        default=5.0,
        help="Percent of each daily table to scan with TABLESAMPLE SYSTEM (default: 5).",
    )
    args = parser.parse_args()

    build_features(
        start_yyyymmdd=args.start,
        end_yyyymmdd=args.end,
        out_path=args.out,
        max_bytes_billed=args.max_bytes_billed,
        sample_percent=args.sample_percent,
    )


if __name__ == "__main__":
    main()
