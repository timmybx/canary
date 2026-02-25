"""Jenkins plugins registry ("universe snapshot").

This collector fetches the current list of plugins from plugins.jenkins.io and
emits a compact registry/manifest record per plugin.

Why a registry?
  - It becomes the stable *spine* for all other collectors (snapshots,
    advisories, GitHub enrichment, BigQuery/GHArchive features).
  - It enables fan-out collection with resume/checkpointing.

Output record shape (JSONL recommended):
  {
    "plugin_id": "cucumber-reports",
    "plugin_site_url": "https://plugins.jenkins.io/cucumber-reports/",
    "plugin_api_url": "https://plugins.jenkins.io/api/plugin/cucumber-reports",
    "collected_at": "2026-02-15T...Z",
    "plugin_name": "cucumber-reports",          # optional
    "plugin_title": "Cucumber Reports",         # optional
  }
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from http.client import IncompleteRead
from typing import Any
from urllib.parse import urlencode, urlparse

_ALLOWED_NETLOCS = {"plugins.jenkins.io"}


def _fetch_json(url: str, *, timeout_s: float = 30.0) -> Any:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc not in _ALLOWED_NETLOCS:
        raise ValueError(f"Refusing to fetch unexpected URL: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            # Avoid compressed responses; reduces the chance of partial reads on flaky connections.
            "Accept-Encoding": "identity",
            "User-Agent": "canary/0.1 (plugins-registry)",
        },
        method="GET",
    )

    # The Jenkins plugins API occasionally closes connections mid-transfer.
    # Retry a few times with backoff to make full-registry pulls reliable.
    last_err: Exception | None = None
    for attempt in range(1, 6):
        try:
            # URL is allowlisted above (prevents file:// and custom schemes).
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec B310
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except urllib.error.HTTPError as e:
            # 4xx/5xx are unlikely to succeed on retry; fail fast.
            raise RuntimeError(f"Registry request failed ({e.code}) for {url}") from e
        except (urllib.error.URLError, IncompleteRead, TimeoutError) as e:
            last_err = e
        except json.JSONDecodeError as e:
            # Sometimes a truncated read yields invalid JSON; retry a couple times.
            last_err = e

        # Backoff (attempt 1 -> 0.5s, then 1s, 2s, 4s, ...)
        time.sleep(0.5 * (2 ** (attempt - 1)))

    raise RuntimeError(f"Registry request failed after retries for {url}") from last_err


def _extract_plugin_id(plugin_obj: dict[str, Any]) -> str | None:
    # The plugins API has changed shapes over time; be permissive.
    for key in ("name", "pluginId", "id", "artifactId"):
        v = plugin_obj.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _plugin_to_registry_record(plugin_obj: dict[str, Any]) -> dict[str, Any] | None:
    plugin_id = _extract_plugin_id(plugin_obj)
    if not plugin_id:
        return None

    rec: dict[str, Any] = {
        "plugin_id": plugin_id,
        "plugin_site_url": f"https://plugins.jenkins.io/{plugin_id}/",
        "plugin_api_url": f"https://plugins.jenkins.io/api/plugin/{plugin_id}",
    }

    # Optional, best-effort metadata (varies by API shape)
    for src_key, dst_key in (
        ("name", "plugin_name"),
        ("title", "plugin_title"),
        ("excerpt", "plugin_excerpt"),
        ("labels", "plugin_labels"),
    ):
        v = plugin_obj.get(src_key)
        if v is not None:
            rec[dst_key] = v

    return rec


def collect_plugins_registry_sample() -> list[dict[str, Any]]:
    """Small offline registry for tests / demos."""
    now = datetime.now(UTC).isoformat()
    return [
        {
            "plugin_id": "cucumber-reports",
            "plugin_site_url": "https://plugins.jenkins.io/cucumber-reports/",
            "plugin_api_url": "https://plugins.jenkins.io/api/plugin/cucumber-reports",
            "collected_at": now,
        },
        {
            "plugin_id": "workflow-cps",
            "plugin_site_url": "https://plugins.jenkins.io/workflow-cps/",
            "plugin_api_url": "https://plugins.jenkins.io/api/plugin/workflow-cps",
            "collected_at": now,
        },
    ]


def collect_plugins_registry_real(
    *,
    page_size: int = 500,
    max_plugins: int | None = None,
    timeout_s: float = 30.0,
) -> tuple[list[dict[str, Any]], list[Any]]:
    """Fetch the full plugin registry from plugins.jenkins.io.

    Returns:
      (registry_records, raw_pages)

    Notes:
      - The plugins API's pagination parameters have historically used
        limit/offset. We use that by default and also attempt to follow a
        `next` link if present.
      - We keep `raw_pages` so you can store the exact upstream responses.
    """

    if page_size <= 0 or page_size > 5000:
        raise ValueError("page_size must be between 1 and 5000")

    collected_at = datetime.now(UTC).isoformat()
    registry: list[dict[str, Any]] = []
    raw_pages: list[Any] = []

    offset = 0
    next_url: str | None = None

    while True:
        if next_url is None:
            qs = urlencode({"limit": str(page_size), "offset": str(offset)})
            url = f"https://plugins.jenkins.io/api/plugins?{qs}"
        else:
            url = next_url

        payload = _fetch_json(url, timeout_s=timeout_s)
        raw_pages.append(payload)

        # Common shape: {"plugins": [...], "total": N, ...}
        plugins_list: list[Any]
        total: int | None = None

        if isinstance(payload, dict) and isinstance(payload.get("plugins"), list):
            plugins_list = payload["plugins"]
            t = payload.get("total")
            total = int(t) if isinstance(t, (int, float, str)) and str(t).isdigit() else None
            n = payload.get("next")
            next_url = n if isinstance(n, str) and n.startswith("https://") else None
        elif isinstance(payload, list):
            plugins_list = payload
            next_url = None
        else:
            raise RuntimeError(
                f"Unexpected registry payload shape from {url}: {type(payload).__name__}"
            )

        # Convert plugins -> registry records
        for obj in plugins_list:
            if not isinstance(obj, dict):
                continue
            rec = _plugin_to_registry_record(obj)
            if rec is None:
                continue
            rec["collected_at"] = collected_at
            registry.append(rec)
            if max_plugins is not None and len(registry) >= max_plugins:
                return registry, raw_pages

        # Termination conditions
        if next_url:
            # If upstream gives an explicit next link, follow it.
            continue

        if total is not None:
            if offset + len(plugins_list) >= total:
                break
        else:
            # Best-effort: if the page came back short, assume we're done.
            if len(plugins_list) < page_size:
                break

        offset += len(plugins_list)

    return registry, raw_pages
