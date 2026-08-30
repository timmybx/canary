"""
Behavior tests for the second-wave enrichment families
(ghtext_/contagion_/ghdyn_/swhdelta_) and the shared single-pass event scan
in canary.build.enrich_monthly.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

from canary.build.enrich_monthly import (
    CONTAGION_MONTHS_CAP,
    GHTEXT_DAYS_CAP,
    SWHDELTA_DAYS_CAP,
    build_contagion_features,
    build_ghdyn_features,
    build_ghtext_features,
    build_swhdelta_features,
    collect_event_dates,
    collect_swh_visits,
    enrich_rows,
    scan_events,
)


def _row(plugin: str, month: str, advisories: int = 0, **extra) -> dict:
    return {
        "plugin_id": plugin,
        "month": month,
        "advisory_count_this_month": advisories,
        "feat_a": 1.0,
        **extra,
    }


def _event(plugin: str, ts: str, event_type: str, **extra) -> dict:
    return {"plugin_id": plugin, "event_ts": ts, "event_type": event_type, **extra}


@pytest.fixture()
def events_dir(tmp_path: Path) -> Path:
    """p1 and p2 share the human committer alice; p3 has only a bot."""
    events = [
        # p1: alice pushes in Jan and Mar; bob opens a PR (not committer-ish).
        _event("p1", "2024-01-10T12:00:00Z", "PushEvent", actor_login="alice"),
        _event(
            "p1",
            "2024-03-05T10:00:00Z",
            "PushEvent",
            actor_login="alice",
            text_blob="fix CVE-2024-1234 sanitize input",
        ),
        _event(
            "p1",
            "2024-03-06T10:00:00Z",
            "PullRequestEvent",
            action="opened",
            actor_login="bob",
            text_blob="improve security hardening of the token store",
        ),
        # p1: a plain-text event that must NOT count as a security mention.
        _event(
            "p1",
            "2024-04-02T10:00:00Z",
            "PushEvent",
            actor_login="bob",
            text_blob="bump parent pom and tidy docs",
        ),
        # p2: alice merges a PR in Feb (shared maintainer with p1).
        _event(
            "p2",
            "2024-02-15T10:00:00Z",
            "PullRequestEvent",
            action="closed",
            pr_merged=True,
            actor_login="alice",
        ),
        # p3: bot-only activity — never a human actor.
        _event("p3", "2024-01-20T10:00:00Z", "PushEvent", actor_login="dependabot[bot]"),
    ]
    path = tmp_path / "events"
    path.mkdir()
    with (path / "2024.gharchive.events.jsonl").open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return path


def _grid(months: list[str], advisories: dict[tuple[str, str], int] | None = None) -> list[dict]:
    advisories = advisories or {}
    return [
        _row(p, m, advisories=advisories.get((p, m), 0)) for m in months for p in ("p1", "p2", "p3")
    ]


# ---------------------------------------------------------------------------
# scan_events — the shared single pass
# ---------------------------------------------------------------------------


def test_scan_events_matches_collect_event_dates(events_dir: Path) -> None:
    assert scan_events(events_dir).event_dates == collect_event_dates(events_dir)


def test_scan_events_actors_and_committers(events_dir: Path) -> None:
    scan = scan_events(events_dir)
    jan, feb, mar = (2024, 1), (2024, 2), (2024, 3)
    # ghdyn view: every human actor, with event counts; bots excluded.
    assert scan.monthly_actors["p1"][jan] == {"alice": 1}
    assert scan.monthly_actors["p1"][mar] == {"alice": 1, "bob": 1}
    assert "p3" not in scan.monthly_actors
    # contagion view: only committer-ish actors (push/merge/release).
    assert scan.monthly_committers["p1"][jan] == {"alice"}
    assert scan.monthly_committers["p2"][feb] == {"alice"}
    assert "bob" not in scan.monthly_committers["p1"].get(mar, set())


def test_scan_events_security_text(events_dir: Path) -> None:
    scan = scan_events(events_dir)
    assert scan.security_dates["p1"] == [date(2024, 3, 5), date(2024, 3, 6)]
    assert scan.cve_dates["p1"] == [date(2024, 3, 5)]  # only the CVE-id event
    assert "p2" not in scan.security_dates  # no text on p2's event


def test_scan_events_requires_files(tmp_path: Path) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        scan_events(empty)


# ---------------------------------------------------------------------------
# ghtext_*
# ---------------------------------------------------------------------------


def test_ghtext_as_of_and_caps(events_dir: Path) -> None:
    scan = scan_events(events_dir)
    rows = [_row("p1", "2024-02"), _row("p1", "2024-03"), _row("p2", "2024-03")]
    feats = build_ghtext_features(rows, scan.security_dates, scan.cve_dates)

    before = feats[("p1", "2024-02")]  # mentions happen in March
    assert before["ghtext_days_since_security_mention"] == GHTEXT_DAYS_CAP
    assert before["ghtext_has_security_mentions"] is False
    assert before["ghtext_security_mentions_365d"] == 0

    after = feats[("p1", "2024-03")]
    assert (
        after["ghtext_days_since_security_mention"] == (date(2024, 3, 31) - date(2024, 3, 6)).days
    )
    assert after["ghtext_days_since_cve_mention"] == (date(2024, 3, 31) - date(2024, 3, 5)).days
    assert after["ghtext_security_mentions_90d"] == 2
    assert after["ghtext_security_mentions_365d"] == 2
    assert after["ghtext_cve_mentions_365d"] == 1
    assert after["ghtext_has_security_mentions"] is True
    assert after["ghtext_has_cve_mentions"] is True

    never = feats[("p2", "2024-03")]
    assert never["ghtext_days_since_security_mention"] == GHTEXT_DAYS_CAP
    assert never["ghtext_has_security_mentions"] is False


# ---------------------------------------------------------------------------
# contagion_*
# ---------------------------------------------------------------------------


def test_contagion_shared_maintainer_and_neighbor_advisory(events_dir: Path) -> None:
    months = [f"2024-{m:02d}" for m in range(1, 7)]
    # p2 is hit in 2024-04; p1 shares alice with p2 from Feb (alice's p2 merge).
    rows = _grid(months, advisories={("p2", "2024-04"): 1})
    feats = build_contagion_features(rows, scan_events(events_dir).monthly_committers)

    jan = feats[("p1", "2024-01")]  # alice not yet active on p2
    assert jan["contagion_active_maintainers"] == 1
    assert jan["contagion_neighbor_count"] == 0
    assert jan["contagion_has_neighbors"] is False
    assert jan["contagion_months_since_neighbor_advisory"] == CONTAGION_MONTHS_CAP

    feb = feats[("p1", "2024-02")]  # link exists, no neighbor advisory yet
    assert feb["contagion_shared_maintainers"] == 1
    assert feb["contagion_neighbor_count"] == 1
    assert feb["contagion_neighbors_hit_12m"] == 0
    assert feb["contagion_has_neighbor_advisory"] is False

    may = feats[("p1", "2024-05")]  # p2 hit one month ago
    assert may["contagion_neighbors_hit_12m"] == 1
    assert may["contagion_neighbors_hit_24m"] == 1
    assert may["contagion_months_since_neighbor_advisory"] == 1
    assert may["contagion_has_neighbor_advisory"] is True

    # The link is symmetric, and a plugin is never its own neighbor.
    assert feats[("p2", "2024-05")]["contagion_neighbor_count"] == 1
    # p3 (bot-only) has no active maintainers and no neighbors.
    p3 = feats[("p3", "2024-05")]
    assert p3["contagion_active_maintainers"] == 0
    assert p3["contagion_neighbor_count"] == 0


def test_contagion_own_advisory_is_not_neighbor_advisory(events_dir: Path) -> None:
    months = [f"2024-{m:02d}" for m in range(1, 7)]
    rows = _grid(months, advisories={("p1", "2024-03"): 1})
    feats = build_contagion_features(rows, scan_events(events_dir).monthly_committers)
    # p1's own advisory must not surface through the neighbor features…
    assert feats[("p1", "2024-04")]["contagion_neighbors_hit_12m"] == 0
    # …but it IS p2's neighbor advisory.
    assert feats[("p2", "2024-04")]["contagion_neighbors_hit_12m"] == 1
    assert feats[("p2", "2024-04")]["contagion_months_since_neighbor_advisory"] == 1


def test_contagion_window_expires() -> None:
    committers = {
        "p1": {(2020, 1): {"alice"}},
        "p2": {(2020, 1): {"alice"}, (2024, 1): {"alice"}},
    }
    months = ["2021-12", "2022-06"]
    rows = [_row(p, m) for m in months for p in ("p1", "p2")]
    feats = build_contagion_features(rows, committers)
    # 2021-12: Jan 2020 is 23 months back — still inside the 24-month window.
    assert feats[("p1", "2021-12")]["contagion_neighbor_count"] == 1
    # 2022-06: the shared activity has aged out; no link remains.
    assert feats[("p1", "2022-06")]["contagion_neighbor_count"] == 0
    assert feats[("p1", "2022-06")]["contagion_active_maintainers"] == 0


# ---------------------------------------------------------------------------
# ghdyn_*
# ---------------------------------------------------------------------------


def test_ghdyn_turnover_newcomers_and_concentration() -> None:
    from collections import Counter

    monthly_actors = {
        "p": {
            (2023, 3): Counter({"old_guard": 4}),
            (2023, 5): Counter({"leaver": 1}),
            (2024, 2): Counter({"old_guard": 3, "newbie": 1}),
            (2024, 11): Counter({"newbie": 2}),
        }
    }
    rows = [_row("p", "2024-12")]
    feats = build_ghdyn_features(rows, monthly_actors)[("p", "2024-12")]

    # Trailing 12m (2024-01..2024-12): old_guard + newbie; 3m: newbie only.
    assert feats["ghdyn_active_actors_12m"] == 2
    assert feats["ghdyn_active_actors_3m"] == 1
    # newbie first appeared 2024-02 (10 months back) -> newcomer; old_guard is not.
    assert feats["ghdyn_new_actors_12m"] == 1
    # Prior year (2023-01..2023-12): {old_guard, leaver}; leaver departed.
    assert feats["ghdyn_departed_actors_12m"] == 1
    assert feats["ghdyn_turnover_rate_12m"] == 0.5
    assert feats["ghdyn_events_12m"] == 6
    assert feats["ghdyn_top_actor_share_12m"] == 0.5
    assert feats["ghdyn_single_actor_12m"] is False
    assert feats["ghdyn_has_actors"] is True


def test_ghdyn_no_activity_and_as_of() -> None:
    from collections import Counter

    monthly_actors = {"p": {(2024, 6): Counter({"alice": 1})}}
    rows = [_row("p", "2024-05"), _row("q", "2024-05")]
    feats = build_ghdyn_features(rows, monthly_actors)
    # June activity is in the future of a May row — everything must read zero.
    may = feats[("p", "2024-05")]
    assert may["ghdyn_active_actors_12m"] == 0
    assert may["ghdyn_events_12m"] == 0
    assert may["ghdyn_top_actor_share_12m"] == 0.0
    assert may["ghdyn_turnover_rate_12m"] == 0.0
    assert may["ghdyn_single_actor_12m"] is False
    # q has no events at all.
    assert feats[("q", "2024-05")]["ghdyn_has_actors"] is False


# ---------------------------------------------------------------------------
# swhdelta_*
# ---------------------------------------------------------------------------


def _visit(when: str, commits, secfix: int | str = 0, **flags) -> dict:
    return {
        "visit_date": when,
        "commit_count": commits,
        "security_fix_commit_count": secfix,
        **flags,
    }


@pytest.fixture()
def swh_dir(tmp_path: Path) -> Path:
    path = tmp_path / "swh"
    path.mkdir()
    visits = [
        # Stringified values on purpose: Athena exports sometimes do this.
        _visit("2023-01-15 08:00:00.000", "100", secfix="1", has_security_md="False"),
        _visit("2023-07-15", 130, secfix=1, has_security_md=False, has_dependabot=False),
        _visit("2024-03-10", 190, secfix=3, has_security_md=True, has_dependabot=False),
    ]
    with (path / "p1.swh_athena_visits.jsonl").open("w", encoding="utf-8") as f:
        for v in visits:
            f.write(json.dumps(v) + "\n")
    with (path / "solo.swh_athena_visits.jsonl").open("w", encoding="utf-8") as f:
        f.write(json.dumps(_visit("2024-01-01", 5)) + "\n")
    return path


def test_collect_swh_visits_coerces_and_sorts(swh_dir: Path) -> None:
    visits = collect_swh_visits(swh_dir)
    assert [v["date"] for v in visits["p1"]] == [
        date(2023, 1, 15),
        date(2023, 7, 15),
        date(2024, 3, 10),
    ]
    first = visits["p1"][0]
    assert first["commit_count"] == 100
    assert first["security_fix_commit_count"] == 1
    assert first["flags"]["has_security_md"] is False
    assert first["flags"]["has_readme"] is None  # absent stays unknown, never False


def test_swhdelta_deltas_and_governance_add(swh_dir: Path) -> None:
    visits = collect_swh_visits(swh_dir)
    rows = [_row("p1", "2024-03"), _row("p1", "2023-06"), _row("none", "2024-03")]
    feats = build_swhdelta_features(rows, visits)

    mar = feats[("p1", "2024-03")]
    assert mar["swhdelta_visits_to_date"] == 3
    assert mar["swhdelta_days_since_last_visit"] == (date(2024, 3, 31) - date(2024, 3, 10)).days
    days_between = (date(2024, 3, 10) - date(2023, 7, 15)).days
    assert mar["swhdelta_days_between_last_visits"] == days_between
    assert mar["swhdelta_commits_delta"] == 60
    assert mar["swhdelta_commit_rate_per_month"] == round(60 / days_between * 30.0, 4)
    assert mar["swhdelta_security_fix_commits_delta"] == 2
    assert mar["swhdelta_governance_adds"] == 1  # has_security_md flipped on
    assert mar["swhdelta_governance_drops"] == 0
    assert mar["swhdelta_days_since_governance_add"] == (date(2024, 3, 31) - date(2024, 3, 10)).days
    assert mar["swhdelta_has_governance_add"] is True

    # As-of 2023-06 only the first visit is visible: no deltas, no adds.
    jun = feats[("p1", "2023-06")]
    assert jun["swhdelta_visits_to_date"] == 1
    assert jun["swhdelta_has_visits"] is True
    assert jun["swhdelta_has_prior_visit"] is False
    assert jun["swhdelta_commits_delta"] == 0
    assert jun["swhdelta_days_between_last_visits"] == SWHDELTA_DAYS_CAP
    assert jun["swhdelta_has_governance_add"] is False

    none = feats[("none", "2024-03")]
    assert none["swhdelta_has_visits"] is False
    assert none["swhdelta_days_since_last_visit"] == SWHDELTA_DAYS_CAP
    assert none["swhdelta_visits_to_date"] == 0


def test_collect_swh_visits_requires_files(tmp_path: Path) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        collect_swh_visits(empty)


# ---------------------------------------------------------------------------
# enrich_rows + CLI with all six families
# ---------------------------------------------------------------------------


def test_enrich_rows_all_families_no_missing_values(events_dir: Path, swh_dir: Path) -> None:
    months = [f"2024-{m:02d}" for m in range(1, 7)]
    rows = _grid(months, advisories={("p2", "2024-04"): 1})
    enriched, summary = enrich_rows(rows, events_dir=events_dir, swh_dir=swh_dir)

    prefixes = ("advhist_", "ghclock_", "ghtext_", "contagion_", "ghdyn_", "swhdelta_")
    expected_keys = {k for row in enriched for k in row if k.startswith(prefixes)}
    for row in enriched:
        missing = expected_keys - set(row)
        assert not missing, f"row {row['plugin_id']}/{row['month']} missing {sorted(missing)}"
        assert all(row[k] is not None for k in expected_keys)
    for family in ("advhist", "ghclock", "ghtext", "contagion", "ghdyn", "swhdelta"):
        assert summary[f"{family}_columns"], family
    assert summary["added_column_count"] == len(expected_keys)


def test_enrich_rows_family_subset(events_dir: Path) -> None:
    rows = _grid(["2024-03"])
    enriched, summary = enrich_rows(rows, events_dir=events_dir, families=("contagion", "ghdyn"))
    assert any(k.startswith("contagion_") for k in enriched[0])
    assert any(k.startswith("ghdyn_") for k in enriched[0])
    assert not any(k.startswith(("advhist_", "ghclock_", "ghtext_")) for k in enriched[0])
    assert summary["advhist_columns"] == []


def test_enrich_rows_rejects_unknown_family(events_dir: Path) -> None:
    with pytest.raises(ValueError, match="Unknown feature families"):
        enrich_rows(_grid(["2024-03"]), events_dir=events_dir, families=("ghclcok",))


def _load_tool(name: str):
    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_enrich_cli_all_six_families(
    tmp_path: Path, events_dir: Path, swh_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    months = [f"2024-{m:02d}" for m in range(1, 7)]
    rows = _grid(months, advisories={("p2", "2024-04"): 1})
    in_path = tmp_path / "labeled.jsonl"
    out_path = tmp_path / "enriched.jsonl"
    with in_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    tool = _load_tool("enrich_monthly_features")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enrich_monthly_features.py",
            "--in-path",
            str(in_path),
            "--out-path",
            str(out_path),
            "--events-dir",
            str(events_dir),
            "--swh-dir",
            str(swh_dir),
        ],
    )
    assert tool.main() == 0

    lines = [json.loads(x) for x in out_path.read_text(encoding="utf-8").splitlines() if x]
    assert len(lines) == len(rows)
    for prefix in ("advhist_", "ghclock_", "ghtext_", "contagion_", "ghdyn_", "swhdelta_"):
        assert any(k.startswith(prefix) for k in lines[0]), prefix
    summary = json.loads((tmp_path / "enriched.jsonl.summary.json").read_text(encoding="utf-8"))
    assert summary["families"] == [
        "advhist",
        "ghclock",
        "ghtext",
        "contagion",
        "ghdyn",
        "swhdelta",
    ]
    assert summary["added_column_count"] == sum(
        len(summary[f"{f}_columns"]) for f in summary["families"]
    )


def test_enrich_cli_rejects_unknown_family(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    in_path = tmp_path / "labeled.jsonl"
    in_path.write_text(json.dumps(_row("p1", "2024-01")) + "\n", encoding="utf-8")
    tool = _load_tool("enrich_monthly_features")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "enrich_monthly_features.py",
            "--in-path",
            str(in_path),
            "--out-path",
            str(tmp_path / "out.jsonl"),
            "--families",
            "advhist,ghclcok",
        ],
    )
    with pytest.raises(SystemExit, match="Unknown families"):
        tool.main()


# ---------------------------------------------------------------------------
# Web console coverage: every enriched column must have a hover tooltip
# ---------------------------------------------------------------------------


def test_every_enriched_column_has_a_feature_tip(events_dir: Path, swh_dir: Path) -> None:
    from canary.web.ui import _FEATURE_TIPS

    rows = _grid([f"2024-{m:02d}" for m in range(1, 7)], advisories={("p2", "2024-04"): 1})
    enriched, _ = enrich_rows(rows, events_dir=events_dir, swh_dir=swh_dir)
    prefixes = ("advhist_", "ghclock_", "ghtext_", "contagion_", "ghdyn_", "swhdelta_")
    columns = {k for row in enriched for k in row if k.startswith(prefixes)}
    missing = sorted(columns - set(_FEATURE_TIPS))
    assert not missing, f"features without a web-console tooltip: {missing}"
