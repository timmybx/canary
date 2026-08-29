"""
Post-hoc feature enrichment for the labeled monthly dataset.

Adds two new feature families to an existing ``plugins.monthly.labeled.jsonl``
without re-running the monthly build:

``advhist_*``
    Advisory-history features computed entirely from columns already present
    in the labeled rows (the dense per-plugin advisory calendar via
    ``advisory_count_this_month``). Everything is as-of the observation
    month: no value depends on advisories published after it.

``ghclock_*``
    Recency clocks (days since last <event kind>, measured at month end)
    computed from the normalized GH Archive event files
    (``data/raw/gharchive/normalized-events/YYYY-MM.gharchive.events.jsonl``).
    The dataset already carries month-granularity ``gharchive_months_since_*``
    staleness signals; these refine them with day precision, finer event
    kinds (human vs. any push via the bot-actor list; PR opened / merged /
    reviewed separately; tag creation), and the no-missing encoding below —
    the existing signals preserve None for "never observed" and rely on
    median imputation. They also supersede the Software Heritage visit-based
    clocks, whose irregular visit schedule makes them stale measurements.

Encoding convention (deliberate — see praxis Section 4.4.6 on imputation
semantics): these families emit NO missing values. A "never happened yet"
recency is encoded as the cap value (``ADVHIST_MONTHS_CAP`` months /
``GHCLOCK_DAYS_CAP`` days) together with an explicit ``*_has_history`` /
``*_has_events`` flag, so imputation never has to guess and zero never
means "just happened" for a plugin with no history. Counts default to 0,
which for these feed-complete sources genuinely means zero.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from canary.build.monthly_features import _is_bot_actor, _parse_iso_date
from canary.build.monthly_labels import (
    _get_month_value,
    _parse_month_key,
    _row_has_advisory_this_month,
)

ADVHIST_MONTHS_CAP = 120
GHCLOCK_DAYS_CAP = 3650

# Event-kind -> ghclock feature stem. Each becomes ghclock_days_since_<stem>.
GHCLOCK_KINDS = (
    "human_push",
    "any_push",
    "release",
    "pr_opened",
    "pr_merged",
    "pr_review",
    "issue_opened",
    "tag_create",
)


def _month_key_of(row: dict[str, Any]) -> tuple[int, int]:
    return _parse_month_key(_get_month_value(row))


def _month_end(key: tuple[int, int]) -> date:
    """Last calendar day of (year, month)."""
    year, month = key
    if month == 12:
        return date(year + 1, 1, 1) - timedelta(days=1)
    return date(year, month + 1, 1) - timedelta(days=1)


def _months_between(earlier: tuple[int, int], later: tuple[int, int]) -> int:
    return (later[0] - earlier[0]) * 12 + (later[1] - earlier[1])


# ---------------------------------------------------------------------------
# advhist_* — advisory-history features from the labeled rows themselves
# ---------------------------------------------------------------------------


def build_advhist_features(
    rows: list[dict[str, Any]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Compute advhist features for every (plugin_id, month) in *rows*.

    Uses only the advisory calendar reconstructible from the rows (the
    ``advisory_count_this_month`` indicator on the dense grid), so every
    value is knowable at the end of the observation month. Returns a mapping
    keyed by (plugin_id, month string).

    Panel-start boundary (known, verified on the real dataset): advisories
    published before the first grid month are invisible to this calendar, so
    a plugin whose only advisories predate the panel reads as no-history
    (capped recency) until its first in-panel advisory. On the real data
    this affects 3,105 of 197,088 rows (1.6%), all in the early panel years,
    and every one of them is exactly this case — no other disagreement with
    the independently computed ``advisory_days_since_latest_to_date`` column
    exists. That column carries pre-panel recency, so models trained with
    both see the full picture.
    """
    by_plugin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_plugin[str(row.get("plugin_id") or "")].append(row)

    # Ecosystem-wide advisory count per month, for batch-size features:
    # how many plugins received an advisory in a given calendar month.
    plugins_hit_in_month: dict[tuple[int, int], int] = defaultdict(int)
    for plugin_rows in by_plugin.values():
        for row in plugin_rows:
            if _row_has_advisory_this_month(row):
                plugins_hit_in_month[_month_key_of(row)] += 1

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for plugin_id, plugin_rows in by_plugin.items():
        plugin_rows = sorted(plugin_rows, key=_month_key_of)
        advisory_months: list[tuple[int, int]] = []  # months with >=1 advisory, ascending
        advisory_count_cum = 0

        for row in plugin_rows:
            month_key = _month_key_of(row)
            if _row_has_advisory_this_month(row):
                advisory_months.append(month_key)
                try:
                    advisory_count_cum += max(1, int(row.get("advisory_count_this_month") or 1))
                except (TypeError, ValueError):
                    advisory_count_cum += 1

            has_history = bool(advisory_months)
            since_last = _months_between(advisory_months[-1], month_key) if has_history else None
            since_first = _months_between(advisory_months[0], month_key) if has_history else None
            count_12m = sum(1 for m in advisory_months if _months_between(m, month_key) < 12)
            count_24m = sum(1 for m in advisory_months if _months_between(m, month_key) < 24)
            gaps = [
                _months_between(a, b)
                for a, b in zip(advisory_months, advisory_months[1:], strict=False)
            ]
            mean_gap = sum(gaps) / len(gaps) if gaps else None
            latest_batch = plugins_hit_in_month[advisory_months[-1]] if has_history else 0

            out[(plugin_id, _get_month_value(row))] = {
                "advhist_has_history": has_history,
                "advhist_months_since_last": (
                    min(since_last, ADVHIST_MONTHS_CAP)
                    if since_last is not None
                    else ADVHIST_MONTHS_CAP
                ),
                "advhist_months_since_first": (
                    min(since_first, ADVHIST_MONTHS_CAP)
                    if since_first is not None
                    else ADVHIST_MONTHS_CAP
                ),
                "advhist_advisory_months_to_date": len(advisory_months),
                "advhist_advisory_count_to_date": advisory_count_cum,
                "advhist_months_with_advisory_last_12m": count_12m,
                "advhist_months_with_advisory_last_24m": count_24m,
                "advhist_mean_gap_months": (
                    min(mean_gap, ADVHIST_MONTHS_CAP)
                    if mean_gap is not None
                    else ADVHIST_MONTHS_CAP
                ),
                "advhist_latest_batch_size": latest_batch,
                "advhist_recency_decay": (
                    math.exp(-since_last / 6.0) if since_last is not None else 0.0
                ),
            }
    return out


# ---------------------------------------------------------------------------
# ghclock_* — recency clocks from normalized GH Archive events
# ---------------------------------------------------------------------------


def _classify_event(event: dict[str, Any]) -> list[str]:
    """Return the GHCLOCK_KINDS this normalized event counts toward."""
    kinds: list[str] = []
    event_type = event.get("event_type")
    action = event.get("action")
    actor = str(event.get("actor_login") or "")

    if event_type == "PushEvent":
        kinds.append("any_push")
        if actor and not _is_bot_actor(actor):
            kinds.append("human_push")
    elif event_type == "ReleaseEvent":
        kinds.append("release")
    elif event_type == "PullRequestEvent":
        if action == "opened":
            kinds.append("pr_opened")
        if bool(event.get("pr_merged")):
            kinds.append("pr_merged")
    elif event_type == "PullRequestReviewEvent":
        kinds.append("pr_review")
    elif event_type == "IssuesEvent":
        if action in (None, "opened"):
            kinds.append("issue_opened")
    elif event_type == "CreateEvent":
        if event.get("ref_type") == "tag":
            kinds.append("tag_create")
    return kinds


def collect_event_dates(
    events_dir: str | Path,
) -> dict[str, dict[str, list[date]]]:
    """
    Stream every ``*.jsonl`` file under *events_dir* and return, per plugin,
    a sorted list of event dates per GHCLOCK kind.
    """
    per_plugin: dict[str, dict[str, set[date]]] = defaultdict(lambda: defaultdict(set))
    paths = sorted(Path(events_dir).glob("*.jsonl"))
    if not paths:
        raise FileNotFoundError(f"No .jsonl event files found under {events_dir}")
    for path in paths:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                kinds = _classify_event(event)
                if not kinds:
                    continue
                when = _parse_iso_date(event.get("event_ts") or event.get("event_date"))
                if when is None:
                    continue
                plugin_id = str(event.get("plugin_id") or "")
                if not plugin_id:
                    continue
                bucket = per_plugin[plugin_id]
                for kind in kinds:
                    bucket[kind].add(when)
    return {
        plugin: {kind: sorted(dates) for kind, dates in kinds.items()}
        for plugin, kinds in per_plugin.items()
    }


def _days_since(dates: list[date], as_of: date) -> int | None:
    """Days from the latest date <= as_of to as_of; None if none qualify."""
    import bisect

    idx = bisect.bisect_right(dates, as_of)
    if idx == 0:
        return None
    return (as_of - dates[idx - 1]).days


def build_ghclock_features(
    rows: list[dict[str, Any]],
    event_dates: dict[str, dict[str, list[date]]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Compute ghclock features for every (plugin_id, month) in *rows*, as-of
    the last day of the observation month.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        plugin_id = str(row.get("plugin_id") or "")
        month = _get_month_value(row)
        as_of = _month_end(_parse_month_key(month))
        plugin_events = event_dates.get(plugin_id, {})

        features: dict[str, Any] = {}
        any_event = False
        for kind in GHCLOCK_KINDS:
            days = _days_since(plugin_events.get(kind, []), as_of)
            if days is not None:
                any_event = True
            features[f"ghclock_days_since_{kind}"] = (
                min(days, GHCLOCK_DAYS_CAP) if days is not None else GHCLOCK_DAYS_CAP
            )
        features["ghclock_has_events"] = any_event
        out[(plugin_id, month)] = features
    return out


# ---------------------------------------------------------------------------
# Enrichment driver
# ---------------------------------------------------------------------------


def enrich_rows(
    rows: list[dict[str, Any]],
    *,
    events_dir: str | Path | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Return copies of *rows* with advhist (and, when *events_dir* is given,
    ghclock) features attached, plus a summary dict. Original columns are
    never modified or dropped; input rows are not mutated.
    """
    advhist = build_advhist_features(rows)
    ghclock: dict[tuple[str, str], dict[str, Any]] = {}
    if events_dir is not None:
        ghclock = build_ghclock_features(rows, collect_event_dates(events_dir))

    enriched: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("plugin_id") or ""), _get_month_value(row))
        new_row = dict(row)
        new_row.update(advhist.get(key, {}))
        if ghclock:
            new_row.update(ghclock.get(key, {}))
        enriched.append(new_row)

    advhist_cols = sorted({k for feats in advhist.values() for k in feats})
    ghclock_cols = sorted({k for feats in ghclock.values() for k in feats})
    summary = {
        "row_count": len(enriched),
        "plugin_count": len({str(r.get("plugin_id") or "") for r in rows}),
        "advhist_columns": advhist_cols,
        "ghclock_columns": ghclock_cols,
        "added_column_count": len(advhist_cols) + len(ghclock_cols),
        "advhist_months_cap": ADVHIST_MONTHS_CAP,
        "ghclock_days_cap": GHCLOCK_DAYS_CAP,
    }
    return enriched, summary
