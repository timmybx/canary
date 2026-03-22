from __future__ import annotations

import importlib
import json
import os
import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from canary.collectors.github_repo import parse_github_owner_repo
from canary.plugin_aliases import canonicalize_plugin_id

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
  AND type IN (
    'PushEvent',
    'PullRequestEvent',
    'PullRequestReviewEvent',
    'IssuesEvent',
    'ReleaseEvent'
  )
"""


def _build_raw_event_query_with_sampling(
    *,
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    available_tables: set[str],
    sample_percent: float,
) -> str:
    if sample_percent <= 0 or sample_percent > 100:
        raise ValueError("sample_percent must be > 0 and <= 100")

    tablesample_clause = ""
    if sample_percent < 100:
        tablesample_clause = f"TABLESAMPLE SYSTEM ({sample_percent} PERCENT)"

    start_date = _parse_yyyymmdd(start_yyyymmdd)
    end_date = _parse_yyyymmdd(end_yyyymmdd)

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

    return "\nUNION ALL\n".join(raw_parts)


def _split_repo_full_name(repo_full_name: str) -> tuple[str | None, str | None]:
    repo_full_name = (repo_full_name or "").strip()
    if not repo_full_name or "/" not in repo_full_name:
        return None, None
    owner, repo = repo_full_name.split("/", 1)
    owner = owner.strip() or None
    repo = repo.strip() or None
    return owner, repo


def _coerce_bool_or_none(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
    return None


def _event_yyyymm_from_value(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return f"{value.year:04d}-{value.month:02d}"

    if isinstance(value, date):
        return f"{value.year:04d}-{value.month:02d}"

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        if len(text) >= 7 and text[4] == "-":
            return text[:7]

        ts = _normalize_timestamp_value(text)
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return f"{dt.year:04d}-{dt.month:02d}"
            except ValueError:
                return None

    return None


def _normalize_timestamp_value(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")

    return None


def _normalize_date_value(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.date().isoformat()

    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if "T" in text:
            ts = _normalize_timestamp_value(text)
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    return dt.date().isoformat()
                except ValueError:
                    return None
        try:
            d = date.fromisoformat(text)
            return d.isoformat()
        except ValueError:
            return None

    return None


def _build_normalized_event_row(
    raw_row: dict[str, Any],
    plugin_id: str,
    repo_full_name: str,
    *,
    collected_at: str,
    sample_percent: float,
    registry_path: str,
    source_window_start_yyyymmdd: str,
    source_window_end_yyyymmdd: str,
) -> dict[str, Any]:
    owner, repo_name = _split_repo_full_name(repo_full_name)
    event_ts = _normalize_timestamp_value(raw_row.get("event_ts"))
    event_date = _normalize_date_value(raw_row.get("event_date"))
    event_yyyymm = _event_yyyymm_from_value(event_date) or _event_yyyymm_from_value(event_ts)
    event_year = None
    event_month = None
    if event_yyyymm:
        event_year = int(event_yyyymm[:4])
        event_month = int(event_yyyymm[5:7])

    text_blob = raw_row.get("text_blob")
    if isinstance(text_blob, str):
        text_blob = text_blob.strip() or None
    else:
        text_blob = None if text_blob is None else str(text_blob)

    return {
        "source": "gharchive_bigquery",
        "collected_at": collected_at,
        "sample_percent": sample_percent,
        "registry_path": registry_path,
        "source_window_start_yyyymmdd": source_window_start_yyyymmdd,
        "source_window_end_yyyymmdd": source_window_end_yyyymmdd,
        "plugin_id": plugin_id,
        "repo_full_name": repo_full_name,
        "repo_owner": owner,
        "repo_name": repo_name,
        "event_type": raw_row.get("event_type"),
        "event_ts": event_ts,
        "event_date": event_date,
        "event_year": event_year,
        "event_month": event_month,
        "event_yyyymm": event_yyyymm,
        "actor_login": raw_row.get("actor_login"),
        "action": raw_row.get("action"),
        "pr_merged": _coerce_bool_or_none(raw_row.get("pr_merged")),
        "pr_created_ts": _normalize_timestamp_value(raw_row.get("pr_created_ts")),
        "pr_closed_ts": _normalize_timestamp_value(raw_row.get("pr_closed_ts")),
        "issue_created_ts": _normalize_timestamp_value(raw_row.get("issue_created_ts")),
        "issue_closed_ts": _normalize_timestamp_value(raw_row.get("issue_closed_ts")),
        "text_blob": text_blob,
    }


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
                plugin_ids.append(canonicalize_plugin_id(pid, registry_path=registry_path))
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


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _append_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _normalized_events_month_path(out_base: Path, event_yyyymm: str) -> Path:
    return out_base / "normalized-events" / f"{event_yyyymm}.gharchive.events.jsonl"


def _normalize_bigquery_row(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row.items())
    except Exception:
        keys = list(row.keys())
        return {k: row[k] for k in keys}


def _build_window_job_config(
    *,
    repo_names: list[str],
    max_bytes_billed: int,
    dry_run: bool,
) -> Any:
    bigquery = _import_bigquery()
    kwargs = {
        "query_parameters": [
            bigquery.ArrayQueryParameter("repo_names", "STRING", repo_names),
        ],
        "maximum_bytes_billed": max_bytes_billed,
        "dry_run": dry_run,
        "use_query_cache": not dry_run,
    }
    try:
        return bigquery.QueryJobConfig(**kwargs)
    except TypeError:
        job_config = bigquery.QueryJobConfig(
            query_parameters=kwargs["query_parameters"],
            maximum_bytes_billed=max_bytes_billed,
        )
        if hasattr(job_config, "dry_run"):
            job_config.dry_run = dry_run
        if hasattr(job_config, "use_query_cache"):
            job_config.use_query_cache = not dry_run
        return job_config


def _estimate_window_bytes(
    client: Any,
    *,
    repo_names: list[str],
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    sample_percent: float,
    max_bytes_billed: int,
) -> int:
    available_tables = _existing_day_tables(client, start_yyyymmdd, end_yyyymmdd)
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd=start_yyyymmdd,
        end_yyyymmdd=end_yyyymmdd,
        available_tables=available_tables,
        sample_percent=sample_percent,
    )
    job_config = _build_window_job_config(
        repo_names=repo_names,
        max_bytes_billed=max_bytes_billed,
        dry_run=True,
    )
    query_job = client.query(sql, job_config=job_config)
    return int(query_job.total_bytes_processed or 0)


def _query_window_rows(
    client: Any,
    *,
    repo_names: list[str],
    start_yyyymmdd: str,
    end_yyyymmdd: str,
    sample_percent: float,
    max_bytes_billed: int,
) -> tuple[list[dict[str, Any]], int]:
    available_tables = _existing_day_tables(client, start_yyyymmdd, end_yyyymmdd)
    # Normalized-event collection needs raw event rows, not the older per-repo
    # aggregate query used by the legacy window feature pipeline.
    sql = _build_raw_event_query_with_sampling(
        start_yyyymmdd=start_yyyymmdd,
        end_yyyymmdd=end_yyyymmdd,
        available_tables=available_tables,
        sample_percent=sample_percent,
    )
    job_config = _build_window_job_config(
        repo_names=repo_names,
        max_bytes_billed=max_bytes_billed,
        dry_run=False,
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
    dry_run: bool = False,
) -> dict[str, Any]:
    """Collect GH Archive event history and write normalized CANARY-style monthly JSONL files.

    Outputs (default under data/raw/gharchive):
      - normalized-events/YYYY-MM.gharchive.events.jsonl
      - gharchive_index.json

    Query execution is still batched by date window for cost control, but the collected
    artifacts are written by calendar month based on each normalized event row.
    """
    bigquery = _import_bigquery()
    project = os.getenv("GOOGLE_CLOUD_PROJECT") or None
    try:
        client = bigquery.Client(project=project) if project else bigquery.Client()
    except TypeError:
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
    normalized_dir = out_base / "normalized-events"
    normalized_dir.mkdir(parents=True, exist_ok=True)

    repo_to_plugins: dict[str, list[str]] = defaultdict(list)
    for pid, repo in targets.items():
        repo_to_plugins[repo].append(pid)
    repo_names = sorted(repo_to_plugins.keys())

    result: dict[str, Any] = {
        "source": "gharchive_bigquery",
        "collected_at": datetime.now(UTC).isoformat(),
        "data_dir": data_dir,
        "registry_path": registry_path,
        "out_dir": str(out_base),
        "normalized_events_dir": str(normalized_dir),
        "plugin_filter": plugin_id,
        "window_start_yyyymmdd": start_yyyymmdd,
        "window_end_yyyymmdd": end_yyyymmdd,
        "bucket_days": bucket_days,
        "sample_percent": sample_percent,
        "max_bytes_billed": max_bytes_billed,
        "targets_resolved": len(targets),
        "targets": [
            {"plugin_id": pid, "repo_full_name": repo} for pid, repo in sorted(targets.items())
        ],
        "dry_run": dry_run,
        "windows": [],
        "skipped_window_details": [],
        "plugins_written": 0,
        "rows_written": 0,
        "events_written": 0,
        "months_written": 0,
        "month_files_written": [],
        "bytes_scanned_total": 0,
        "skipped_windows": 0,
    }

    months_cleared: set[str] = set()
    plugins_seen: set[str] = set()
    months_seen: set[str] = set()

    for window_start, window_end in windows:
        if dry_run:
            estimated_bytes = _estimate_window_bytes(
                client,
                repo_names=repo_names,
                start_yyyymmdd=window_start,
                end_yyyymmdd=window_end,
                sample_percent=sample_percent,
                max_bytes_billed=max_bytes_billed,
            )
            result["windows"].append(
                {
                    "window_start_yyyymmdd": window_start,
                    "window_end_yyyymmdd": window_end,
                    "rows": None,
                    "bytes_scanned": 0,
                    "estimated_bytes_scanned": estimated_bytes,
                    "path": None,
                    "dry_run": True,
                }
            )
            result["bytes_scanned_total"] += estimated_bytes
            continue

        rows, scanned = _query_window_rows(
            client,
            repo_names=repo_names,
            start_yyyymmdd=window_start,
            end_yyyymmdd=window_end,
            sample_percent=sample_percent,
            max_bytes_billed=max_bytes_billed,
        )

        rows_by_month: dict[str, list[dict[str, Any]]] = defaultdict(list)
        normalized_count = 0
        for row in rows:
            repo_full_name = str(row.get("repo") or "").strip()
            plugins = repo_to_plugins.get(repo_full_name, [])
            if not plugins:
                continue
            for pid in plugins:
                rec = _build_normalized_event_row(
                    row,
                    pid,
                    repo_full_name,
                    collected_at=result["collected_at"],
                    sample_percent=sample_percent,
                    registry_path=registry_path,
                    source_window_start_yyyymmdd=window_start,
                    source_window_end_yyyymmdd=window_end,
                )
                event_yyyymm = rec.get("event_yyyymm")
                if not isinstance(event_yyyymm, str) or not event_yyyymm:
                    continue
                rows_by_month[event_yyyymm].append(rec)
                plugins_seen.add(pid)
                months_seen.add(event_yyyymm)
                normalized_count += 1

        month_paths: list[str] = []
        for event_yyyymm, month_rows in sorted(rows_by_month.items()):
            month_rows.sort(
                key=lambda r: (
                    str(r.get("plugin_id") or ""),
                    str(r.get("event_ts") or ""),
                    str(r.get("event_type") or ""),
                    str(r.get("actor_login") or ""),
                )
            )
            month_path = _normalized_events_month_path(out_base, event_yyyymm)
            if overwrite and event_yyyymm not in months_cleared and month_path.exists():
                month_path.unlink()
            months_cleared.add(event_yyyymm)
            _append_jsonl(month_path, month_rows)
            month_paths.append(str(month_path))

        result["windows"].append(
            {
                "window_start_yyyymmdd": window_start,
                "window_end_yyyymmdd": window_end,
                "rows": normalized_count,
                "bytes_scanned": scanned,
                "months_touched": sorted(rows_by_month.keys()),
                "paths": month_paths,
            }
        )
        result["rows_written"] += normalized_count
        result["events_written"] += normalized_count
        result["bytes_scanned_total"] += scanned

    result["plugins_written"] = len(plugins_seen)
    result["months_written"] = len(months_seen)
    result["month_files_written"] = [
        str(_normalized_events_month_path(out_base, month)) for month in sorted(months_seen)
    ]

    if dry_run:
        result["note"] = (
            "Dry run only: BigQuery estimated bytes were collected, "
            "but no normalized event files were written."
        )
    elif not overwrite:
        result["note"] = (
            "Normalized monthly event files are appended when overwrite=False. "
            "Use --overwrite on reruns to avoid duplicate rows in month files."
        )

    _write_json(out_base / "gharchive_index.json", result)
    return result
