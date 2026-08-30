"""
Behavior tests for the Jenkins install-statistics source: the
stats.jenkins.io collector (canary.collectors.install_stats) and the
installs_* enrichment family (canary.build.enrich_monthly).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from canary.build.enrich_monthly import (
    INSTALLS_GROWTH_CAP,
    build_installs_features,
    collect_install_series,
    enrich_rows,
)
from canary.collectors.install_stats import (
    collect_install_stats,
    validate_install_stats,
)


def _epoch_ms(year: int, month: int) -> str:
    return str(int(datetime(year, month, 1, tzinfo=UTC).timestamp() * 1000))


def _stats_payload(series: dict[tuple[int, int], int], pct: dict[tuple[int, int], float]) -> dict:
    return {
        "name": "x",
        "installations": {_epoch_ms(y, m): c for (y, m), c in series.items()},
        "installationsPercentage": {_epoch_ms(y, m): p for (y, m), p in pct.items()},
    }


def _row(plugin: str, month: str) -> dict:
    return {"plugin_id": plugin, "month": month, "advisory_count_this_month": 0}


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


def test_validate_install_stats() -> None:
    good = {"installations": {"123": 4}}
    assert validate_install_stats(good) is good
    assert validate_install_stats({"installations": {}}) is None
    assert validate_install_stats({"nope": 1}) is None
    assert validate_install_stats([1, 2]) is None


@pytest.fixture()
def registry(tmp_path: Path) -> Path:
    path = tmp_path / "plugins.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for pid in ("alpha", "beta", "gamma"):
            f.write(json.dumps({"plugin_id": pid}) + "\n")
    return path


def test_collect_install_stats_writes_missing_and_resumes(tmp_path: Path, registry: Path) -> None:
    payloads = {
        "alpha": {"installations": {_epoch_ms(2024, 1): 10}},
        "beta": None,  # stats site 404
    }
    calls: list[str] = []

    def fake_fetch(pid: str):
        calls.append(pid)
        if pid == "gamma":
            raise RuntimeError("boom")
        return payloads[pid]

    summary = collect_install_stats(
        data_dir=str(tmp_path),
        registry_path=str(registry),
        sleep_s=0.0,
        fetch=fake_fetch,
        verbose=False,
    )
    assert summary["written"] == 1
    assert summary["missing"] == ["beta"]
    assert summary["error_count"] == 1 and "gamma" in summary["errors"][0]
    out_dir = tmp_path / "jenkins_stats"
    assert json.loads((out_dir / "alpha.stats.json").read_text(encoding="utf-8"))
    assert json.loads((out_dir / "_collection_summary.json").read_text(encoding="utf-8"))

    # Resume: alpha is skipped, beta/gamma retried.
    calls.clear()
    summary2 = collect_install_stats(
        data_dir=str(tmp_path),
        registry_path=str(registry),
        sleep_s=0.0,
        fetch=fake_fetch,
        verbose=False,
    )
    assert summary2["skipped_existing"] == 1
    assert "alpha" not in calls


def test_collect_install_stats_max_plugins(tmp_path: Path, registry: Path) -> None:
    summary = collect_install_stats(
        data_dir=str(tmp_path),
        registry_path=str(registry),
        sleep_s=0.0,
        max_plugins=1,
        fetch=lambda pid: {"installations": {_epoch_ms(2024, 1): 1}},
        verbose=False,
    )
    assert summary["processed"] == 1 and summary["written"] == 1


# ---------------------------------------------------------------------------
# Series parsing
# ---------------------------------------------------------------------------


@pytest.fixture()
def stats_dir(tmp_path: Path) -> Path:
    path = tmp_path / "jenkins_stats"
    path.mkdir()
    # big: steady growth 2023-01..2024-05; small: flat tiny series.
    big_series = {}
    month_keys = [(2023, m) for m in range(1, 13)] + [(2024, m) for m in range(1, 6)]
    for i, key in enumerate(month_keys):
        big_series[key] = 1000 + 100 * i
    (path / "big.stats.json").write_text(
        json.dumps(_stats_payload(big_series, {(2024, 5): 42.5})), encoding="utf-8"
    )
    (path / "small.stats.json").write_text(
        json.dumps(_stats_payload({k: 10 for k in month_keys}, {})), encoding="utf-8"
    )
    # A summary file must be ignored gracefully (no "installations" key).
    (path / "_collection_summary.json.stats.json").write_text("{}", encoding="utf-8")
    return path


def test_collect_install_series_parses_and_sorts(stats_dir: Path) -> None:
    series = collect_install_series(stats_dir)
    assert set(series) == {"big", "small"}
    months = [m for m, _c, _p in series["big"]]
    assert months == sorted(months)
    assert series["big"][0] == ((2023, 1), 1000, 0.0)
    assert series["big"][-1][0] == (2024, 5)
    assert series["big"][-1][2] == 42.5


def test_collect_install_series_requires_files(tmp_path: Path) -> None:
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        collect_install_series(empty)


# ---------------------------------------------------------------------------
# installs_* features
# ---------------------------------------------------------------------------


def test_installs_publication_lag(stats_dir: Path) -> None:
    series = collect_install_series(stats_dir)
    feats = build_installs_features([_row("big", "2023-01"), _row("big", "2023-02")], series)
    # At T=2023-01 only stats through 2022-12 may be used — none exist.
    jan = feats[("big", "2023-01")]
    assert jan["installs_has_data"] is False
    assert jan["installs_count"] == 0
    # At T=2023-02 the 2023-01 figure is available.
    feb = feats[("big", "2023-02")]
    assert feb["installs_has_data"] is True
    assert feb["installs_count"] == 1000
    assert feb["installs_months_of_data"] == 1


def test_installs_growth_peak_and_rank(stats_dir: Path) -> None:
    series = collect_install_series(stats_dir)
    feats = build_installs_features([_row("big", "2024-06"), _row("small", "2024-06")], series)

    big = feats[("big", "2024-06")]
    # T=2024-06 -> stats through 2024-05: count 2600; 3m back (2024-02) 2300;
    # 12m back (2023-05) 1400.
    assert big["installs_count"] == 2600
    assert big["installs_pct"] == 42.5
    assert big["installs_growth_3m"] == round(2600 / 2300 - 1, 4)
    assert big["installs_growth_12m"] == round(2600 / 1400 - 1, 4)
    assert big["installs_peak_ratio"] == 1.0  # monotone growth: current IS the peak
    assert big["installs_rank_pct"] == 1.0  # bigger of the two plugins
    assert big["installs_rank_delta_12m"] == 0.0  # was already rank 1.0
    assert big["installs_months_of_data"] == 17
    assert big["installs_log10_count"] == round(__import__("math").log10(2601), 4)

    small = feats[("small", "2024-06")]
    assert small["installs_rank_pct"] == 0.5
    assert small["installs_growth_12m"] == 0.0  # flat
    assert small["installs_peak_ratio"] == 1.0


def test_installs_growth_is_capped() -> None:
    series = {"p": [((2023, 1), 1, 0.0), ((2024, 1), 1_000_000, 0.0)]}
    feats = build_installs_features([_row("p", "2024-02")], series)
    assert feats[("p", "2024-02")]["installs_growth_12m"] == INSTALLS_GROWTH_CAP


def test_installs_unknown_plugin_is_zero_filled(stats_dir: Path) -> None:
    series = collect_install_series(stats_dir)
    feats = build_installs_features([_row("nope", "2024-06")], series)
    none = feats[("nope", "2024-06")]
    assert none["installs_has_data"] is False
    assert none["installs_count"] == 0
    assert none["installs_rank_pct"] == 0.0
    assert none["installs_peak_ratio"] == 0.0


def test_enrich_rows_installs_family_and_tooltips(stats_dir: Path) -> None:
    from canary.web.ui import _FEATURE_TIPS

    rows = [_row("big", "2024-06"), _row("nope", "2024-06")]
    enriched, summary = enrich_rows(
        rows, events_dir=None, installs_dir=stats_dir, families=("installs",)
    )
    columns = {k for row in enriched for k in row if k.startswith("installs_")}
    assert columns == set(summary["installs_columns"])
    for row in enriched:
        assert all(k in row and row[k] is not None for k in columns)
    missing = sorted(columns - set(_FEATURE_TIPS))
    assert not missing, f"installs_ features without a web-console tooltip: {missing}"


# ---------------------------------------------------------------------------
# Enrichment CLI behavior around the installs source directory
# ---------------------------------------------------------------------------


def _load_tool(name: str):
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_enrich_cli_default_families_skip_missing_installs_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    import sys

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
            "--installs-dir",
            str(tmp_path / "does-not-exist"),
            "--skip-ghclock",
        ],
    )
    assert tool.main() == 0  # default families: installs silently downgraded
    assert "skipping installs_*" in capsys.readouterr().out
    lines = [json.loads(x) for x in (tmp_path / "out.jsonl").read_text().splitlines() if x]
    assert not any(k.startswith("installs_") for k in lines[0])
    assert any(k.startswith("advhist_") for k in lines[0])


def test_enrich_cli_explicit_installs_requires_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

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
            "--installs-dir",
            str(tmp_path / "does-not-exist"),
            "--families",
            "installs",
        ],
    )
    with pytest.raises(SystemExit, match="collect installstats"):
        tool.main()


def test_enrich_cli_with_installs(
    tmp_path: Path, stats_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    in_path = tmp_path / "labeled.jsonl"
    in_path.write_text(json.dumps(_row("big", "2024-06")) + "\n", encoding="utf-8")
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
            "--installs-dir",
            str(stats_dir),
            "--families",
            "advhist,installs",
        ],
    )
    assert tool.main() == 0
    lines = [json.loads(x) for x in (tmp_path / "out.jsonl").read_text().splitlines() if x]
    assert lines[0]["installs_count"] == 2600
    summary = json.loads((tmp_path / "out.jsonl.summary.json").read_text(encoding="utf-8"))
    assert summary["families"] == ["advhist", "installs"]
    assert len(summary["installs_columns"]) == 10
