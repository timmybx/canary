from __future__ import annotations

import importlib
import json
import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from canary.collectors.github_repo import parse_github_owner_repo

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
WHERE repo.name IN UNNEST(@repo_names)
"""


FEATURE_KEYS = [
    "events_total",
    "actors_unique",
    "pushes",
    "committers_unique",
    "push_days_active",
    "prs_opened",
    "prs_closed",
    "prs_merged",
    "prs_closed_unmerged",
    "pr_reviewed_ratio",
    "pr_merge_time_p50_hours",
    "pr_close_without_merge_ratio",
    "issues_opened",
    "issues_closed",
    "issues_reopened",
    "issue_reopen_rate",
    "issue_close_time_p50_hours",
    "releases",
    "days_since_last_release",
    "hotfix_proxy",
    "security_label_proxy",
    "churn_intensity",
    "owner_concentration",
]


def _import_bigquery() -> Any:
    try:
        return importlib.import_module("google.cloud.bigquery")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "google-cloud-bigquery is not installed. Install it with: "
            "pip install google-cloud-bigquery"
        ) from exc


def _parse_yyyymmdd(value: str) -> date:
    return datetime.strptime(value, "%Y%m%d").date()


def _iter_registry_plugin_ids(registry_path: Path) -> list[str]:
    plugin_ids: list[str] = []
    with registry_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            pid = (rec.get("plugin_id") or "").strip()
            if pid:
                plugin_ids.append(pid)
    return plugin_ids


def _scm_to_url(val: object) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        v = val.strip()
        return v or None
    if isinstance(val, dict):
        link = val.get("link")
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

    if isinstance(scm, dict):
        url = _scm_to_url(scm.get("link") or scm.get("url"))
        if url:
            return url

    plugin_api = snapshot.get("plugin_api")
    if isinstance(plugin_api, dict):
        url = _scm_to_url(plugin_api.get("scm"))
        if url:
            return url
        scm2 = plugin_api.get("scm")
        if isinstance(scm2, dict):
            url = _scm_to_url(scm2.get("link") or scm2.get("url"))
            if url:
                return url

    return None


def _load_plugin_snapshot(plugin_id: str, *, data_dir: str) -> dict[str, Any]:
    snap_path = Path(data_dir) / "plugins" / f"{plugin_id}.snapshot.json"
    if not snap_path.exists():
        raise FileNotFoundError(
            f"Plugin snapshot not found: {snap_path}. "
            f"Run: canary collect plugin --id {plugin_id} --real"
        )
    return json.loads(snap_path.read_text(encoding="utf-8"))


def _fallback_repo_names(plugin_id: str) -> list[str]:
    slug = re.sub(r"[^a-z0-9]+", "-", plugin_id.strip().lower()).strip("-")
    if not slug:
        return []
    names = [f"jenkinsci/{slug}-plugin"]
    if not slug.endswith("-plugin"):
        names.append(f"jenkinsci/{slug}")
    return names


def resolve_plugin_repo_targets(
    *,
    data_dir: str = "data/raw",
    registry_path: str = "data/raw/registry/plugins.jsonl",
    plugin_id: str | None = None,
    allow_jenkinsci_fallback: bool = False,
) -> dict[str, str]:
    """Resolve plugin_id -> GitHub repo full name for GH Archive collection.

    Prefer explicit snapshot SCM/repo URLs. Optionally fall back to the common
    jenkinsci/<plugin>-plugin naming convention when a snapshot lacks GitHub metadata.
    """
    targets: dict[str, str] = {}
    plugin_ids = [plugin_id] if plugin_id else _iter_registry_plugin_ids(Path(registry_path))

    for pid in plugin_ids:
        pid = (pid or "").strip()
        if not pid:
            continue

        repo_full_name: str | None = None
        try:
            snapshot = _load_plugin_snapshot(pid, data_dir=data_dir)
            repo_url = _infer_repo_url(snapshot)
            if repo_url:
                parsed = parse_github_owner_repo(repo_url)
                if parsed:
                    owner, repo = parsed
                    repo_full_name = f"{owner}/{repo}"
        except FileNotFoundError:
            repo_full_name = None

        if repo_full_name is None and allow_jenkinsci_fallback:
            fallback_names = _fallback_repo_names(pid)
            if fallback_names:
                repo_full_name = fallback_names[0]

        if repo_full_name:
            targets[pid] = repo_full_name

    return targets


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


def _iter_windows(
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    bucket_days: int,
) -> list[tuple[str, str]]:
    if bucket_days <= 0:
        raise ValueError("bucket_days must be > 0")
    start_date = _parse_yyyymmdd(start_yyyymmdd)
    end_date = _parse_yyyymmdd(end_yyyymmdd)
    if end_date < start_date:
        raise ValueError("end date must be >= start date (format: YYYYMMDD)")

    windows: list[tuple[str, str]] = []
    current = start_date
    while current <= end_date:
        window_end = min(current + timedelta(days=bucket_days - 1), end_date)
        windows.append((current.strftime("%Y%m%d"), window_end.strftime("%Y%m%d")))
        current = window_end + timedelta(days=1)
    return windows


def _build_query_with_sampling(
    *,
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
        raise ValueError("sample_percent must be > 0 and <= 100")

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
    return f"""
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
  COUNT(DISTINCT IF(e.event_type = 'PushEvent', e.actor_login, NULL)) AS committers_unique,
  COUNT(DISTINCT IF(e.event_type = 'PushEvent', e.event_date, NULL)) AS push_days_active,
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
  COUNTIF(e.event_type = 'ReleaseEvent') AS releases,
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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _normalize_bigquery_row(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row.items())
    except Exception:
        keys = list(row.keys())
        return {k: row[k] for k in keys}


def _query_window_rows(
    client: Any,
    *,
    repo_names: list[str],
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    sample_percent: float,
    max_bytes_billed: int,
) -> tuple[list[dict[str, Any]], int]:
    bigquery = _import_bigquery()
    available_tables = _existing_day_tables(client, start_yyyymmdd, end_yyyymmdd)
    sql = _build_query_with_sampling(
        start_yyyymmdd=start_yyyymmdd,
        end_yyyymmdd=end_yyyymmdd,
        available_tables=available_tables,
        sample_percent=sample_percent,
    )
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ArrayQueryParameter("repo_names", "STRING", repo_names),
        ],
        maximum_bytes_billed=max_bytes_billed,
    )
    query_job = client.query(sql, job_config=job_config)
    rows = [_normalize_bigquery_row(r) for r in query_job.result()]
    scanned = int(query_job.total_bytes_processed or 0)
    return rows, scanned


def collect_gharchive_history_real(
    *,
    data_dir: str = "data/raw",
    registry_path: str = "data/raw/registry/plugins.jsonl",
    out_dir: str = "data/raw/gharchive",
    plugin_id: str | None = None,
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    bucket_days: int = 30,
    sample_percent: float = 5.0,
    max_bytes_billed: int = 2_000_000_000,
    overwrite: bool = False,
    allow_jenkinsci_fallback: bool = False,
) -> dict[str, Any]:
    """Collect GH Archive historical features and write CANARY-style JSON artifacts.

    Outputs (default under data/raw/gharchive):
      - windows/<start>_<end>.gharchive.jsonl
      - plugins/<plugin_id>.gharchive.jsonl
      - gharchive_index.json
    """
    bigquery = _import_bigquery()
    client = bigquery.Client()

    targets = resolve_plugin_repo_targets(
        data_dir=data_dir,
        registry_path=registry_path,
        plugin_id=plugin_id,
        allow_jenkinsci_fallback=allow_jenkinsci_fallback,
    )
    if not targets:
        raise RuntimeError(
            "No plugin->GitHub repo mappings were resolved. "
            "Collect plugin snapshots first, or use --allow-jenkinsci-fallback."
        )

    windows = _iter_windows(start_yyyymmdd, end_yyyymmdd, bucket_days)
    out_base = Path(out_dir)
    windows_dir = out_base / "windows"
    plugins_dir = out_base / "plugins"
    windows_dir.mkdir(parents=True, exist_ok=True)
    plugins_dir.mkdir(parents=True, exist_ok=True)

    repo_to_plugin = {repo: pid for pid, repo in targets.items()}
    repo_names = sorted(repo_to_plugin.keys())
    per_plugin_records: dict[str, list[dict[str, Any]]] = defaultdict(list)

    result: dict[str, Any] = {
        "source": "gharchive_bigquery",
        "collected_at": datetime.now(UTC).isoformat(),
        "data_dir": data_dir,
        "registry_path": registry_path,
        "out_dir": str(out_base),
        "plugin_filter": plugin_id,
        "window_start_yyyymmdd": start_yyyymmdd,
        "window_end_yyyymmdd": end_yyyymmdd,
        "bucket_days": bucket_days,
        "sample_percent": sample_percent,
        "max_bytes_billed": max_bytes_billed,
        "targets_resolved": len(targets),
        "windows": [],
        "plugins_written": 0,
        "rows_written": 0,
        "bytes_scanned_total": 0,
        "skipped_windows": 0,
    }

    for window_start, window_end in windows:
        window_path = windows_dir / f"{window_start}_{window_end}.gharchive.jsonl"
        if window_path.exists() and (not overwrite):
            result["skipped_windows"] += 1
            continue

        rows, scanned = _query_window_rows(
            client,
            repo_names=repo_names,
            start_yyyymmdd=window_start,
            end_yyyymmdd=window_end,
            sample_percent=sample_percent,
            max_bytes_billed=max_bytes_billed,
        )
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            repo_full_name = str(row.get("repo") or "").strip()
            plugin = repo_to_plugin.get(repo_full_name)
            if not plugin:
                continue
            rec = {
                "source": "gharchive_bigquery",
                "type": "historical_activity_window",
                "plugin_id": plugin,
                "repo_full_name": repo_full_name,
                "window_start_yyyymmdd": row.get("window_start_yyyymmdd") or window_start,
                "window_end_yyyymmdd": row.get("window_end_yyyymmdd") or window_end,
                "collected_at": result["collected_at"],
                "sample_percent": sample_percent,
            }
            for key in FEATURE_KEYS:
                rec[key] = row.get(key)
            normalized_rows.append(rec)
            per_plugin_records[plugin].append(rec)

        normalized_rows.sort(key=lambda r: (str(r["plugin_id"]), str(r["repo_full_name"])))
        _write_jsonl(window_path, normalized_rows)
        result["windows"].append(
            {
                "window_start_yyyymmdd": window_start,
                "window_end_yyyymmdd": window_end,
                "rows": len(normalized_rows),
                "bytes_scanned": scanned,
                "path": str(window_path),
            }
        )
        result["rows_written"] += len(normalized_rows)
        result["bytes_scanned_total"] += scanned

    for pid, records in per_plugin_records.items():
        records.sort(
            key=lambda r: (
                str(r.get("window_start_yyyymmdd") or ""),
                str(r.get("window_end_yyyymmdd") or ""),
            )
        )
        _write_jsonl(plugins_dir / f"{pid}.gharchive.jsonl", records)
        result["plugins_written"] += 1

    _write_json(out_base / "gharchive_index.json", result)
    return result
