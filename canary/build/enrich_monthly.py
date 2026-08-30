"""
Post-hoc feature enrichment for the labeled monthly dataset.

Adds six feature families to an existing ``plugins.monthly.labeled.jsonl``
without re-running the monthly build (and without any new data collection):

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

``ghtext_*``
    Security-vocabulary recency and counts from the events' ``text_blob``
    (CVE ids, "vulnerability", "XSS", …; see ``SECURITY_TEXT_RE``). The most
    direct probe of the surveillance/attention channel (praxis H1).

``contagion_*``
    Shared-maintainer graph features. The graph is rebuilt AS-OF each month
    from event actors — never from the static contributor snapshots in
    ``data/raw/github/``, which were collected years later and would leak
    future maintainer knowledge into early rows.

``ghdyn_*``
    Contributor-dynamics: distinct active humans, newcomers, departures,
    turnover rate, and top-actor concentration in trailing windows.

``swhdelta_*``
    Software Heritage visit-to-visit deltas (commit-rate, security-fix
    commits) and governance-adoption events (``has_security_md`` flipping
    on, etc.) from the per-plugin Athena visit files.

``installs_*``
    Install-base scale, trend, and rank from stats.jenkins.io monthly
    installation history (collected by ``canary collect installstats``) —
    the demand-side channel. Publication-lag aware: observation month T
    uses the series only through T-1, since month T's figures publish
    after T ends.

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
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, timedelta
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
GHTEXT_DAYS_CAP = 3650
CONTAGION_MONTHS_CAP = 120
CONTAGION_WINDOW_MONTHS = 24  # trailing window defining an "active maintainer"
SWHDELTA_DAYS_CAP = 3650

# installs_*: stats.jenkins.io publishes month M's numbers shortly AFTER M
# ends, so at scoring time (the first of T+1) month T's figure is typically
# not yet available. Deployment-honest features for observation month T
# therefore use the series only through T-1.
INSTALLS_PUBLICATION_LAG_MONTHS = 1
INSTALLS_GROWTH_CAP = 10.0  # +1000%; relative growth is clamped to [-1, cap]

# Case-insensitive security vocabulary for ghtext_*. Deliberately narrow:
# generic words like "fix" or "bug" would swamp the signal with noise.
SECURITY_TEXT_RE = re.compile(
    r"(?i)(?:\bcve-\d{4}-\d+\b|\bcwe-\d+\b|vulnerab|\bsecurity\b|\bexploit"
    r"|\bxss\b|\bcsrf\b|\bssrf\b|\brce\b|\bsqli\b|\binjection\b|sanitiz"
    r"|\bdisclos|\badvisory\b|deserializ|\bhardening\b|privilege escalation"
    r"|auth(?:entication|orization)? bypass)"
)
CVE_TEXT_RE = re.compile(r"(?i)\bcve-\d{4}-\d+\b")

# SWH directory-listing flags whose False->True flip counts as a
# governance/tooling adoption event for swhdelta_*.
SWHDELTA_GOVERNANCE_FLAGS = (
    "has_security_md",
    "has_dependabot",
    "has_github_actions",
    "has_jenkinsfile",
    "has_readme",
    "has_contributing_md",
    "has_changelog",
    "has_tests_directory",
    "has_snyk_config",
    "has_sonar_config",
    "has_travis_yml",
)

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
# installs_* — Jenkins install statistics (stats.jenkins.io monthly history)
# ---------------------------------------------------------------------------


def _shift_month(key: tuple[int, int], months_back: int) -> tuple[int, int]:
    year, month = key
    month -= months_back
    while month < 1:
        year, month = year - 1, month + 12
    return (year, month)


def collect_install_series(
    stats_dir: str | Path,
) -> dict[str, list[tuple[tuple[int, int], int, float]]]:
    """
    Read ``<plugin>.stats.json`` files collected by
    ``canary collect installstats`` and return, per plugin, an ascending list
    of (month key, installation count, install-share percent). Timestamps in
    the source are epoch milliseconds (UTC, first of the month).
    """
    from datetime import datetime

    out: dict[str, list[tuple[tuple[int, int], int, float]]] = {}
    paths = sorted(Path(stats_dir).glob(f"*{'.stats.json'}"))
    if not paths:
        raise FileNotFoundError(f"No .stats.json files found under {stats_dir}")
    for path in paths:
        plugin_id = path.name[: -len(".stats.json")]
        payload = json.loads(path.read_text(encoding="utf-8"))
        installations = payload.get("installations")
        if not isinstance(installations, dict):
            continue
        percentages = payload.get("installationsPercentage")
        percentages = percentages if isinstance(percentages, dict) else {}
        series: list[tuple[tuple[int, int], int, float]] = []
        for ts_ms, count in installations.items():
            try:
                when = datetime.fromtimestamp(int(ts_ms) / 1000.0, tz=UTC)
                count_i = int(count)
            except (TypeError, ValueError, OSError):
                continue
            try:
                pct = float(percentages.get(ts_ms) or 0.0)
            except (TypeError, ValueError):
                pct = 0.0
            series.append(((when.year, when.month), count_i, pct))
        if series:
            out[plugin_id] = sorted(series)
    return out


def build_installs_features(
    rows: list[dict[str, Any]],
    series: dict[str, list[tuple[tuple[int, int], int, float]]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Install-base (adoption) features per (plugin_id, month) — the demand-side
    channel: every other family measures the supply side (maintainer
    activity, advisories, repo state); this measures who is running the
    plugin. Deployment-honest: observation month T uses the series only
    through T - INSTALLS_PUBLICATION_LAG_MONTHS, because month T's figures
    publish after T ends. Historical values are published once and never
    restated, so there is no embargo interaction.
    """
    import bisect

    # Ecosystem-wide sorted counts per stats month, for percentile ranks.
    counts_by_month: dict[tuple[int, int], list[int]] = defaultdict(list)
    for plugin_series in series.values():
        for month_key, count, _pct in plugin_series:
            counts_by_month[month_key].append(count)
    for counts in counts_by_month.values():
        counts.sort()

    def _rank_pct(month_key: tuple[int, int], count: int) -> float:
        counts = counts_by_month.get(month_key, [])
        if not counts:
            return 0.0
        return round(bisect.bisect_right(counts, count) / len(counts), 4)

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        plugin_id = str(row.get("plugin_id") or "")
        month = _get_month_value(row)
        target = _shift_month(_parse_month_key(month), INSTALLS_PUBLICATION_LAG_MONTHS)
        plugin_series = series.get(plugin_id, [])
        months = [m for m, _c, _p in plugin_series]
        idx = bisect.bisect_right(months, target) - 1

        def _value_at_or_before(
            when: tuple[int, int],
            *,
            _months=months,
            _series=plugin_series,
        ) -> tuple[tuple[int, int], int] | None:
            pos = bisect.bisect_right(_months, when) - 1
            if pos < 0:
                return None
            return _series[pos][0], _series[pos][1]

        def _growth(months_back: int, current: int, *, _target=target) -> float:
            prior = _value_at_or_before(_shift_month(_target, months_back))
            if prior is None or prior[1] <= 0 or current <= 0:
                return 0.0
            return round(max(-1.0, min(current / prior[1] - 1.0, INSTALLS_GROWTH_CAP)), 4)

        if idx < 0:
            out[(plugin_id, month)] = {
                "installs_has_data": False,
                "installs_count": 0,
                "installs_log10_count": 0.0,
                "installs_pct": 0.0,
                "installs_rank_pct": 0.0,
                "installs_growth_3m": 0.0,
                "installs_growth_12m": 0.0,
                "installs_peak_ratio": 0.0,
                "installs_rank_delta_12m": 0.0,
                "installs_months_of_data": 0,
            }
            continue

        stats_month, count, pct = plugin_series[idx]
        peak = max(c for _m, c, _p in plugin_series[: idx + 1])
        rank_now = _rank_pct(stats_month, count)
        prior_12 = _value_at_or_before(_shift_month(target, 12))
        rank_prior = _rank_pct(prior_12[0], prior_12[1]) if prior_12 is not None else None
        out[(plugin_id, month)] = {
            "installs_has_data": True,
            "installs_count": count,
            "installs_log10_count": round(math.log10(count + 1), 4),
            "installs_pct": round(pct, 4),
            "installs_rank_pct": rank_now,
            "installs_growth_3m": _growth(3, count),
            "installs_growth_12m": _growth(12, count),
            "installs_peak_ratio": round(count / peak, 4) if peak > 0 else 0.0,
            "installs_rank_delta_12m": (
                round(rank_now - rank_prior, 4) if rank_prior is not None else 0.0
            ),
            "installs_months_of_data": idx + 1,
        }
    return out


# ---------------------------------------------------------------------------
# Shared single-pass event scan (serves ghclock_, ghtext_, contagion_, ghdyn_)
# ---------------------------------------------------------------------------


@dataclass
class EventScan:
    """Everything the event-based feature families need, from ONE pass."""

    # ghclock_: plugin -> kind -> sorted event dates
    event_dates: dict[str, dict[str, list[date]]] = field(default_factory=dict)
    # ghtext_: plugin -> sorted dates of events whose text matched the vocab
    security_dates: dict[str, list[date]] = field(default_factory=dict)
    cve_dates: dict[str, list[date]] = field(default_factory=dict)
    # ghdyn_: plugin -> month key -> Counter(human actor -> event count)
    monthly_actors: dict[str, dict[tuple[int, int], Counter]] = field(default_factory=dict)
    # contagion_: plugin -> month key -> set of committer-ish human actors
    # (pushed, merged a PR, or cut a release that month)
    monthly_committers: dict[str, dict[tuple[int, int], set[str]]] = field(default_factory=dict)


def scan_events(events_dir: str | Path) -> EventScan:
    """
    Stream every ``*.jsonl`` file under *events_dir* once and return the
    combined per-plugin structures for all event-based families. Replaces
    (and includes) what :func:`collect_event_dates` gathers.
    """
    dates: dict[str, dict[str, set[date]]] = defaultdict(lambda: defaultdict(set))
    sec_dates: dict[str, set[date]] = defaultdict(set)
    cve_dates: dict[str, set[date]] = defaultdict(set)
    monthly_actors: dict[str, dict[tuple[int, int], Counter]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    monthly_committers: dict[str, dict[tuple[int, int], set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )

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
                plugin_id = str(event.get("plugin_id") or "")
                if not plugin_id:
                    continue
                when = _parse_iso_date(event.get("event_ts") or event.get("event_date"))
                if when is None:
                    continue
                month_key = (when.year, when.month)

                kinds = _classify_event(event)
                for kind in kinds:
                    dates[plugin_id][kind].add(when)

                text = event.get("text_blob")
                if isinstance(text, str) and text and SECURITY_TEXT_RE.search(text):
                    sec_dates[plugin_id].add(when)
                    if CVE_TEXT_RE.search(text):
                        cve_dates[plugin_id].add(when)

                actor = str(event.get("actor_login") or "")
                if actor and not _is_bot_actor(actor):
                    monthly_actors[plugin_id][month_key][actor] += 1
                    if "any_push" in kinds or "pr_merged" in kinds or "release" in kinds:
                        monthly_committers[plugin_id][month_key].add(actor)

    return EventScan(
        event_dates={
            plugin: {kind: sorted(ds) for kind, ds in kinds.items()}
            for plugin, kinds in dates.items()
        },
        security_dates={plugin: sorted(ds) for plugin, ds in sec_dates.items()},
        cve_dates={plugin: sorted(ds) for plugin, ds in cve_dates.items()},
        monthly_actors={plugin: dict(months) for plugin, months in monthly_actors.items()},
        monthly_committers={plugin: dict(months) for plugin, months in monthly_committers.items()},
    )


# ---------------------------------------------------------------------------
# ghtext_* — security-vocabulary recency from event text
# ---------------------------------------------------------------------------


def _count_within(dates: list[date], as_of: date, days: int) -> int:
    """Events with as_of - days < d <= as_of (dates sorted ascending)."""
    import bisect

    lo = bisect.bisect_right(dates, as_of - timedelta(days=days))
    hi = bisect.bisect_right(dates, as_of)
    return hi - lo


def build_ghtext_features(
    rows: list[dict[str, Any]],
    security_dates: dict[str, list[date]],
    cve_dates: dict[str, list[date]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Security-vocab activity clocks per (plugin_id, month), as-of month end.
    A "mention" is any GH Archive event whose text_blob matched
    SECURITY_TEXT_RE; the cve_ variants additionally matched a CVE id.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        plugin_id = str(row.get("plugin_id") or "")
        month = _get_month_value(row)
        as_of = _month_end(_parse_month_key(month))
        sec = security_dates.get(plugin_id, [])
        cve = cve_dates.get(plugin_id, [])
        sec_days = _days_since(sec, as_of)
        cve_days = _days_since(cve, as_of)
        out[(plugin_id, month)] = {
            "ghtext_days_since_security_mention": (
                min(sec_days, GHTEXT_DAYS_CAP) if sec_days is not None else GHTEXT_DAYS_CAP
            ),
            "ghtext_security_mentions_90d": _count_within(sec, as_of, 90),
            "ghtext_security_mentions_365d": _count_within(sec, as_of, 365),
            "ghtext_days_since_cve_mention": (
                min(cve_days, GHTEXT_DAYS_CAP) if cve_days is not None else GHTEXT_DAYS_CAP
            ),
            "ghtext_cve_mentions_365d": _count_within(cve, as_of, 365),
            "ghtext_has_security_mentions": sec_days is not None,
            "ghtext_has_cve_mentions": cve_days is not None,
        }
    return out


# ---------------------------------------------------------------------------
# contagion_* — shared-maintainer graph, fully as-of
# ---------------------------------------------------------------------------


def _advisory_calendar(rows: list[dict[str, Any]]) -> dict[str, list[tuple[int, int]]]:
    """Per plugin, ascending list of panel months with >=1 advisory."""
    calendar: dict[str, set[tuple[int, int]]] = defaultdict(set)
    for row in rows:
        if _row_has_advisory_this_month(row):
            calendar[str(row.get("plugin_id") or "")].add(_month_key_of(row))
    return {plugin: sorted(months) for plugin, months in calendar.items()}


def build_contagion_features(
    rows: list[dict[str, Any]],
    monthly_committers: dict[str, dict[tuple[int, int], set[str]]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Shared-maintainer contagion features per (plugin_id, month).

    The maintainer graph is rebuilt AS-OF each month from event actors: a
    plugin's active maintainers at month T are the human actors who pushed,
    merged a PR, or cut a release on it within the trailing
    CONTAGION_WINDOW_MONTHS. This deliberately ignores the static
    contributor snapshots in data/raw/github/ (collected years later — using
    them would leak future maintainer knowledge into early rows). The
    advisory side uses the same in-panel advisory calendar as advhist_*, so
    no value depends on advisories published after the observation month.
    """
    calendar = _advisory_calendar(rows)
    months_in_panel = sorted({_month_key_of(row) for row in rows})
    rows_by_month: dict[tuple[int, int], list[tuple[str, str]]] = defaultdict(list)
    for row in rows:
        rows_by_month[_month_key_of(row)].append(
            (str(row.get("plugin_id") or ""), _get_month_value(row))
        )

    def _window(mk: tuple[int, int], span: int) -> list[tuple[int, int]]:
        year, month = mk
        out = []
        for back in range(span):
            y, m = year, month - back
            while m < 1:
                y, m = y - 1, m + 12
            out.append((y, m))
        return out

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for month_key in months_in_panel:
        window = _window(month_key, CONTAGION_WINDOW_MONTHS)
        # Active maintainer set per plugin at this month, and the inverted
        # actor -> plugins map for neighbor lookups.
        active: dict[str, set[str]] = {}
        by_actor: dict[str, set[str]] = defaultdict(set)
        for plugin_id, months in monthly_committers.items():
            actors: set[str] = set()
            for mk in window:
                actors |= months.get(mk, set())
            if actors:
                active[plugin_id] = actors
                for actor in actors:
                    by_actor[actor].add(plugin_id)

        # Plugins with an advisory in the trailing 12/24 months (as-of), and
        # each plugin's most recent advisory month <= T.
        last_advisory: dict[str, tuple[int, int]] = {}
        hit_12m: set[str] = set()
        hit_24m: set[str] = set()
        for plugin_id, adv_months in calendar.items():
            past = [m for m in adv_months if m <= month_key]
            if not past:
                continue
            last_advisory[plugin_id] = past[-1]
            age = _months_between(past[-1], month_key)
            if age < 12:
                hit_12m.add(plugin_id)
            if age < 24:
                hit_24m.add(plugin_id)

        for plugin_id, month_str in rows_by_month[month_key]:
            actors = active.get(plugin_id, set())
            neighbors: set[str] = set()
            shared = 0
            for actor in actors:
                others = by_actor[actor] - {plugin_id}
                if others:
                    shared += 1
                    neighbors |= others
            neighbor_last: tuple[int, int] | None = None
            for n in neighbors:
                last = last_advisory.get(n)
                if last is not None and (neighbor_last is None or last > neighbor_last):
                    neighbor_last = last
            since_neighbor = (
                _months_between(neighbor_last, month_key) if neighbor_last is not None else None
            )
            out[(plugin_id, month_str)] = {
                "contagion_active_maintainers": len(actors),
                "contagion_shared_maintainers": shared,
                "contagion_neighbor_count": len(neighbors),
                "contagion_neighbors_hit_12m": len(neighbors & hit_12m),
                "contagion_neighbors_hit_24m": len(neighbors & hit_24m),
                "contagion_months_since_neighbor_advisory": (
                    min(since_neighbor, CONTAGION_MONTHS_CAP)
                    if since_neighbor is not None
                    else CONTAGION_MONTHS_CAP
                ),
                "contagion_has_neighbors": bool(neighbors),
                "contagion_has_neighbor_advisory": since_neighbor is not None,
            }
    return out


# ---------------------------------------------------------------------------
# ghdyn_* — contributor turnover / churn / concentration
# ---------------------------------------------------------------------------


def build_ghdyn_features(
    rows: list[dict[str, Any]],
    monthly_actors: dict[str, dict[tuple[int, int], Counter]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Contributor-dynamics features per (plugin_id, month), as-of month end:
    distinct human actors in trailing windows, newcomers (first-ever
    activity inside the window), departures vs. the year before, turnover
    rate, and top-actor concentration.
    """
    # First-ever activity month per (plugin, actor), for newcomer detection.
    first_seen: dict[str, dict[str, tuple[int, int]]] = {}
    for plugin_id, months in monthly_actors.items():
        seen: dict[str, tuple[int, int]] = {}
        for mk in sorted(months):
            for actor in months[mk]:
                if actor not in seen:
                    seen[actor] = mk
        first_seen[plugin_id] = seen

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        plugin_id = str(row.get("plugin_id") or "")
        month = _get_month_value(row)
        month_key = _parse_month_key(month)
        months = monthly_actors.get(plugin_id, {})

        current = Counter()
        prior: set[str] = set()
        recent = Counter()
        for mk, counts in months.items():
            age = _months_between(mk, month_key)
            if age < 0:
                continue
            if age < 12:
                current.update(counts)
                if age < 3:
                    recent.update(counts)
            elif age < 24:
                prior.update(counts.keys())

        actors_12m = set(current)
        new_12m = sum(
            1
            for actor in actors_12m
            if _months_between(first_seen[plugin_id][actor], month_key) < 12
        )
        departed = prior - actors_12m
        turnover = len(departed) / len(prior) if prior else 0.0
        events_12m = sum(current.values())
        top_share = (max(current.values()) / events_12m) if events_12m else 0.0

        out[(plugin_id, month)] = {
            "ghdyn_active_actors_3m": len(recent),
            "ghdyn_active_actors_12m": len(actors_12m),
            "ghdyn_new_actors_12m": new_12m,
            "ghdyn_departed_actors_12m": len(departed),
            "ghdyn_turnover_rate_12m": round(turnover, 4),
            "ghdyn_events_12m": events_12m,
            "ghdyn_top_actor_share_12m": round(top_share, 4),
            "ghdyn_single_actor_12m": len(actors_12m) == 1,
            "ghdyn_has_actors": bool(months),
        }
    return out


# ---------------------------------------------------------------------------
# swhdelta_* — Software Heritage visit-to-visit deltas (no new collection)
# ---------------------------------------------------------------------------


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def collect_swh_visits(swh_dir: str | Path) -> dict[str, list[dict[str, Any]]]:
    """
    Read ``<plugin>.swh_athena_visits.jsonl`` files and return, per plugin,
    visits sorted by date with the fields swhdelta_* needs. Athena exports
    sometimes stringify values, so booleans/ints are coerced defensively.
    """
    suffix = ".swh_athena_visits.jsonl"
    out: dict[str, list[dict[str, Any]]] = {}
    paths = sorted(Path(swh_dir).glob(f"*{suffix}"))
    if not paths:
        raise FileNotFoundError(f"No {suffix} files found under {swh_dir}")
    for path in paths:
        plugin_id = path.name[: -len(suffix)]
        visits: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                when = _parse_iso_date(rec.get("visit_date") or rec.get("date"))
                if when is None:
                    continue
                visits.append(
                    {
                        "date": when,
                        "commit_count": _coerce_int(rec.get("commit_count")),
                        "security_fix_commit_count": _coerce_int(
                            rec.get("security_fix_commit_count")
                        ),
                        "flags": {
                            flag: _coerce_bool(rec.get(flag)) for flag in SWHDELTA_GOVERNANCE_FLAGS
                        },
                    }
                )
        if visits:
            out[plugin_id] = sorted(visits, key=lambda v: v["date"])
    return out


def build_swhdelta_features(
    rows: list[dict[str, Any]],
    visits: dict[str, list[dict[str, Any]]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Visit-to-visit delta features per (plugin_id, month), as-of month end.
    Only visits dated on or before the observation month's end are used.
    Governance "adds" are False->True flips of SWHDELTA_GOVERNANCE_FLAGS
    between consecutive visits (None on either side never counts as a flip).
    """
    import bisect

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        plugin_id = str(row.get("plugin_id") or "")
        month = _get_month_value(row)
        as_of = _month_end(_parse_month_key(month))
        plugin_visits = visits.get(plugin_id, [])
        visit_dates = [v["date"] for v in plugin_visits]
        idx = bisect.bisect_right(visit_dates, as_of)
        latest = plugin_visits[idx - 1] if idx >= 1 else None
        prev = plugin_visits[idx - 2] if idx >= 2 else None

        gov_adds = gov_drops = 0
        commits_delta: int | None = None
        secfix_delta: int | None = None
        days_between: int | None = None
        if latest is not None and prev is not None:
            days_between = (latest["date"] - prev["date"]).days
            if latest["commit_count"] is not None and prev["commit_count"] is not None:
                commits_delta = latest["commit_count"] - prev["commit_count"]
            if (
                latest["security_fix_commit_count"] is not None
                and prev["security_fix_commit_count"] is not None
            ):
                secfix_delta = (
                    latest["security_fix_commit_count"] - prev["security_fix_commit_count"]
                )
            for flag in SWHDELTA_GOVERNANCE_FLAGS:
                before, after = prev["flags"].get(flag), latest["flags"].get(flag)
                if before is False and after is True:
                    gov_adds += 1
                elif before is True and after is False:
                    gov_drops += 1

        # Most recent visit (<= as_of) at which any governance flag flipped on.
        last_add_date: date | None = None
        for pos in range(idx - 1, 0, -1):
            newer, older = plugin_visits[pos], plugin_visits[pos - 1]
            if any(
                older["flags"].get(flag) is False and newer["flags"].get(flag) is True
                for flag in SWHDELTA_GOVERNANCE_FLAGS
            ):
                last_add_date = newer["date"]
                break
        since_add = (as_of - last_add_date).days if last_add_date is not None else None
        since_visit = (as_of - latest["date"]).days if latest is not None else None
        rate = (
            round(commits_delta / days_between * 30.0, 4)
            if commits_delta is not None and days_between
            else 0.0
        )

        out[(plugin_id, month)] = {
            "swhdelta_visits_to_date": idx,
            "swhdelta_days_since_last_visit": (
                min(since_visit, SWHDELTA_DAYS_CAP)
                if since_visit is not None
                else SWHDELTA_DAYS_CAP
            ),
            "swhdelta_days_between_last_visits": (
                min(days_between, SWHDELTA_DAYS_CAP)
                if days_between is not None
                else SWHDELTA_DAYS_CAP
            ),
            "swhdelta_commits_delta": commits_delta if commits_delta is not None else 0,
            "swhdelta_commit_rate_per_month": rate,
            "swhdelta_security_fix_commits_delta": secfix_delta if secfix_delta is not None else 0,
            "swhdelta_governance_adds": gov_adds,
            "swhdelta_governance_drops": gov_drops,
            "swhdelta_days_since_governance_add": (
                min(since_add, SWHDELTA_DAYS_CAP) if since_add is not None else SWHDELTA_DAYS_CAP
            ),
            "swhdelta_has_visits": latest is not None,
            "swhdelta_has_prior_visit": prev is not None,
            "swhdelta_has_governance_add": since_add is not None,
        }
    return out


# ---------------------------------------------------------------------------
# Enrichment driver
# ---------------------------------------------------------------------------


EVENT_FAMILIES = ("ghclock", "ghtext", "contagion", "ghdyn")
ALL_FAMILIES = ("advhist",) + EVENT_FAMILIES + ("swhdelta", "installs")


def build_family_features(
    rows: list[dict[str, Any]],
    *,
    families: tuple[str, ...],
    events_dir: str | Path | None,
    swh_dir: str | Path | None,
    installs_dir: str | Path | None = None,
) -> dict[str, dict[tuple[str, str], dict[str, Any]]]:
    """
    Compute the requested feature families for *rows* and return them keyed
    by family name. Event-based families share ONE pass over *events_dir*;
    a family whose data source argument is None is skipped silently (so
    callers can pass families=ALL_FAMILIES with only some sources on disk
    — but the CLI validates explicitly requested families instead).
    """
    unknown = set(families) - set(ALL_FAMILIES)
    if unknown:
        raise ValueError(f"Unknown feature families: {sorted(unknown)}")

    out: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}
    if "advhist" in families:
        out["advhist"] = build_advhist_features(rows)

    wanted_events = [f for f in families if f in EVENT_FAMILIES]
    if wanted_events and events_dir is not None:
        scan = scan_events(events_dir)
        if "ghclock" in wanted_events:
            out["ghclock"] = build_ghclock_features(rows, scan.event_dates)
        if "ghtext" in wanted_events:
            out["ghtext"] = build_ghtext_features(rows, scan.security_dates, scan.cve_dates)
        if "contagion" in wanted_events:
            out["contagion"] = build_contagion_features(rows, scan.monthly_committers)
        if "ghdyn" in wanted_events:
            out["ghdyn"] = build_ghdyn_features(rows, scan.monthly_actors)

    if "swhdelta" in families and swh_dir is not None:
        out["swhdelta"] = build_swhdelta_features(rows, collect_swh_visits(swh_dir))

    if "installs" in families and installs_dir is not None:
        out["installs"] = build_installs_features(rows, collect_install_series(installs_dir))
    return out


def enrich_rows(
    rows: list[dict[str, Any]],
    *,
    events_dir: str | Path | None,
    swh_dir: str | Path | None = None,
    installs_dir: str | Path | None = None,
    families: tuple[str, ...] = ALL_FAMILIES,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Return copies of *rows* with the requested feature families attached,
    plus a summary dict. Original columns are never modified or dropped;
    input rows are not mutated. Backwards compatible: the default with only
    *events_dir* given yields advhist + all event families.
    """
    by_family = build_family_features(
        rows,
        families=families,
        events_dir=events_dir,
        swh_dir=swh_dir,
        installs_dir=installs_dir,
    )

    enriched: list[dict[str, Any]] = []
    for row in rows:
        key = (str(row.get("plugin_id") or ""), _get_month_value(row))
        new_row = dict(row)
        for family in ALL_FAMILIES:
            feats = by_family.get(family)
            if feats:
                new_row.update(feats.get(key, {}))
        enriched.append(new_row)

    columns = {
        f"{family}_columns": sorted({k for feats in by_family[family].values() for k in feats})
        if family in by_family
        else []
        for family in ALL_FAMILIES
    }
    summary = {
        "row_count": len(enriched),
        "plugin_count": len({str(r.get("plugin_id") or "") for r in rows}),
        **columns,
        "added_column_count": sum(len(cols) for cols in columns.values()),
        "advhist_months_cap": ADVHIST_MONTHS_CAP,
        "ghclock_days_cap": GHCLOCK_DAYS_CAP,
        "ghtext_days_cap": GHTEXT_DAYS_CAP,
        "contagion_months_cap": CONTAGION_MONTHS_CAP,
        "swhdelta_days_cap": SWHDELTA_DAYS_CAP,
    }
    return enriched, summary
