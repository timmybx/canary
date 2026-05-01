from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from canary.cli import (
    _cmd_build_advisories_events,
    _cmd_build_feature_bundle,
    _cmd_build_monthly_feature_bundle,
    _cmd_build_monthly_labels,
    _cmd_collect_advisories,
    _cmd_collect_enrich,
    _cmd_collect_gharchive,
    _cmd_collect_github,
    _cmd_collect_healthscore,
    _cmd_collect_plugin,
    _cmd_collect_registry,
    _cmd_collect_software_heritage,
    _cmd_score,
    _cmd_train_baseline,
    _iter_registry_plugin_ids,
    _nonempty,
    build_parser,
    main,
)

# ---------------------------------------------------------------------------
# _nonempty
# ---------------------------------------------------------------------------


def test_nonempty_nonexistent(tmp_path: Path) -> None:
    assert _nonempty(tmp_path / "missing.txt") is False


def test_nonempty_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty.txt"
    p.write_text("", encoding="utf-8")
    assert _nonempty(p) is False


def test_nonempty_nonempty_file(tmp_path: Path) -> None:
    p = tmp_path / "data.txt"
    p.write_text("hello", encoding="utf-8")
    assert _nonempty(p) is True


def test_nonempty_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "broken.txt"
    p.write_text("x", encoding="utf-8")

    original_stat = Path.stat

    def bad_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == p:
            raise OSError("permission denied")
        return original_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", bad_stat)
    assert _nonempty(p) is False


# ---------------------------------------------------------------------------
# _iter_registry_plugin_ids
# ---------------------------------------------------------------------------


def _write_registry(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def test_iter_registry_normal(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "matrix-project"}])
    ids = list(_iter_registry_plugin_ids(reg))
    assert "git" in ids
    assert "matrix-project" in ids


def test_iter_registry_skips_blank_lines(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    reg.write_text(
        json.dumps({"plugin_id": "git"}) + "\n\n   \n" + json.dumps({"plugin_id": "ant"}) + "\n",
        encoding="utf-8",
    )
    ids = list(_iter_registry_plugin_ids(reg))
    assert ids == ["git", "ant"]


def test_iter_registry_skips_missing_plugin_id(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"name": "no-id"}, {"plugin_id": "git"}, {"plugin_id": ""}])
    ids = list(_iter_registry_plugin_ids(reg))
    assert ids == ["git"]


def test_iter_registry_multiple_plugins(tmp_path: Path) -> None:
    records = [{"plugin_id": f"plugin-{i}"} for i in range(5)]
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, records)
    ids = list(_iter_registry_plugin_ids(reg))
    assert len(ids) == 5
    assert "plugin-0" in ids
    assert "plugin-4" in ids


# ---------------------------------------------------------------------------
# _cmd_collect_registry
# ---------------------------------------------------------------------------


def test_cmd_collect_registry_sample_creates_file(tmp_path: Path) -> None:
    out_dir = tmp_path / "registry"
    args = argparse.Namespace(
        out_dir=str(out_dir),
        out_name="plugins.jsonl",
        raw_out=None,
        real=False,
        page_size=100,
        max_plugins=None,
        timeout_s=30.0,
    )
    rc = _cmd_collect_registry(args)
    assert rc == 0
    out_file = out_dir / "plugins.jsonl"
    assert out_file.exists()
    assert out_file.stat().st_size > 0
    # Verify it is valid JSONL
    records = [json.loads(line) for line in out_file.read_text(encoding="utf-8").splitlines()]
    assert len(records) >= 1
    assert "plugin_id" in records[0]


# ---------------------------------------------------------------------------
# _cmd_collect_advisories – sample bulk mode (no plugin, no --real)
# ---------------------------------------------------------------------------


def test_cmd_collect_advisories_sample_bulk(tmp_path: Path) -> None:
    out_dir = tmp_path / "advisories"
    args = argparse.Namespace(
        out_dir=str(out_dir),
        plugin=None,
        real=False,
        data_dir=str(tmp_path / "data"),
        registry_path=str(tmp_path / "plugins.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    rc = _cmd_collect_advisories(args)
    assert rc == 0
    out_file = out_dir / "jenkins_advisories.sample.jsonl"
    assert out_file.exists()
    lines = [ln for ln in out_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) >= 1


# ---------------------------------------------------------------------------
# _cmd_collect_advisories – single plugin sample mode
# ---------------------------------------------------------------------------


def test_cmd_collect_advisories_sample_single_plugin(tmp_path: Path) -> None:
    out_dir = tmp_path / "advisories"
    # workflow-cps is the plugin in the sample fixture
    args = argparse.Namespace(
        out_dir=str(out_dir),
        plugin="workflow-cps",
        real=False,
        data_dir=str(tmp_path / "data"),
        registry_path=str(tmp_path / "plugins.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    rc = _cmd_collect_advisories(args)
    assert rc == 0
    # The sample fixture includes workflow-cps, so single-plugin sample mode writes this file.
    out_file = out_dir / "workflow-cps.advisories.sample.jsonl"
    assert out_file.exists()


def test_cmd_collect_advisories_bulk_sample_mode(tmp_path: Path) -> None:
    """Bulk sample mode (plugin=None, real=False) writes the combined sample file."""
    out_dir = tmp_path / "advisories"
    args = argparse.Namespace(
        out_dir=str(out_dir),
        plugin=None,
        real=False,
        data_dir=str(tmp_path / "data"),
        registry_path=str(tmp_path / "plugins.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    rc = _cmd_collect_advisories(args)
    assert rc == 0
    bulk_file = out_dir / "jenkins_advisories.sample.jsonl"
    assert bulk_file.exists()
    lines = [ln for ln in bulk_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) >= 1


# ---------------------------------------------------------------------------
# _cmd_collect_advisories – bulk real mode: missing registry raises SystemExit
# ---------------------------------------------------------------------------


def test_cmd_collect_advisories_bulk_real_missing_registry(tmp_path: Path) -> None:
    out_dir = tmp_path / "advisories"
    args = argparse.Namespace(
        out_dir=str(out_dir),
        plugin=None,
        real=True,
        data_dir=str(tmp_path / "data"),
        registry_path=str(tmp_path / "nonexistent.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    with pytest.raises(SystemExit):
        _cmd_collect_advisories(args)


# ---------------------------------------------------------------------------
# _cmd_collect_advisories – bulk real mode with mocked collector
# ---------------------------------------------------------------------------


def test_cmd_collect_advisories_bulk_real_with_registry(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "ant"}])

    plugins_dir = tmp_path / "data" / "plugins"
    plugins_dir.mkdir(parents=True)
    for pid in ("git", "ant"):
        snap = plugins_dir / f"{pid}.snapshot.json"
        snap.write_text(json.dumps({"plugin_id": pid}), encoding="utf-8")

    out_dir = tmp_path / "advisories"

    fake_record = {"source": "jenkins", "type": "advisory", "plugin_id": "git"}

    with patch("canary.cli.collect_advisories_real", return_value=[fake_record]) as mock_collect:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            plugin=None,
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=True,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 0
    assert mock_collect.call_count == 2
    for pid in ("git", "ant"):
        out_file = out_dir / f"{pid}.advisories.real.jsonl"
        assert out_file.exists()


# ---------------------------------------------------------------------------
# _cmd_collect_plugin – single plugin mode
# ---------------------------------------------------------------------------


def test_cmd_collect_plugin_single(tmp_path: Path) -> None:
    out_dir = tmp_path / "plugins"
    fake_snapshot = {"plugin_id": "git", "version": "4.11.0"}

    with patch("canary.cli.collect_plugin_snapshot", return_value=fake_snapshot) as mock_snap:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            id="git",
            repo_url=None,
            real=False,
            registry_path=str(tmp_path / "plugins.jsonl"),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_plugin(args)

    assert rc == 0
    mock_snap.assert_called_once_with(plugin_id="git", repo_url=None, real=False)
    out_file = out_dir / "git.snapshot.json"
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["plugin_id"] == "git"


# ---------------------------------------------------------------------------
# _cmd_collect_plugin – bulk mode
# ---------------------------------------------------------------------------


def test_cmd_collect_plugin_bulk(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "ant"}])

    out_dir = tmp_path / "plugins"
    fake_snapshot = {"plugin_id": "placeholder"}

    with patch("canary.cli.collect_plugin_snapshot", return_value=fake_snapshot) as mock_snap:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            id=None,
            repo_url=None,
            real=False,
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_plugin(args)

    assert rc == 0
    assert mock_snap.call_count == 2
    assert (out_dir / "git.snapshot.json").exists()
    assert (out_dir / "ant.snapshot.json").exists()


def test_cmd_collect_plugin_bulk_skips_existing(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "ant"}])

    out_dir = tmp_path / "plugins"
    out_dir.mkdir(parents=True)
    existing = out_dir / "git.snapshot.json"
    existing.write_text(json.dumps({"plugin_id": "git"}), encoding="utf-8")

    with patch("canary.cli.collect_plugin_snapshot", return_value={"plugin_id": "x"}) as mock_snap:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            id=None,
            repo_url=None,
            real=False,
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_plugin(args)

    assert rc == 0
    # Only ant should have been fetched; git was skipped
    assert mock_snap.call_count == 1
    call_kwargs = mock_snap.call_args
    assert call_kwargs.kwargs.get("plugin_id") == "ant" or call_kwargs.args[0] == "ant"


def test_cmd_collect_plugin_bulk_handles_errors(tmp_path: Path) -> None:
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "bad-plugin"}])

    out_dir = tmp_path / "plugins"

    with patch("canary.cli.collect_plugin_snapshot", side_effect=RuntimeError("boom")):
        args = argparse.Namespace(
            out_dir=str(out_dir),
            id=None,
            repo_url=None,
            real=False,
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_plugin(args)

    assert rc == 2


# ---------------------------------------------------------------------------
# _cmd_collect_plugin – bulk mode missing registry raises SystemExit
# ---------------------------------------------------------------------------


def test_cmd_collect_plugin_bulk_missing_registry(tmp_path: Path) -> None:
    args = argparse.Namespace(
        out_dir=str(tmp_path / "plugins"),
        id=None,
        repo_url=None,
        real=False,
        registry_path=str(tmp_path / "nonexistent.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    with pytest.raises(SystemExit):
        _cmd_collect_plugin(args)


# ---------------------------------------------------------------------------
# _cmd_train_baseline
# ---------------------------------------------------------------------------


def test_cmd_train_baseline_returns_zero_and_prints(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    fake_metrics = {
        "target_col": "advisory_6m",
        "model_name": "logistic",
        "train_row_count": 800,
        "train_positive_count": 40,
        "test_row_count": 200,
        "test_positive_count": 10,
        "feature_count": 25,
        "roc_auc": 0.82,
        "average_precision": 0.55,
    }

    with patch("canary.cli.train_baseline", return_value=fake_metrics):
        args = argparse.Namespace(
            in_path=str(tmp_path / "features.jsonl"),
            target_col="advisory_6m",
            out_dir=str(tmp_path / "models"),
            test_start_month="2024-01",
            exclude_cols=None,
            include_prefixes=None,
            model="logistic",
            split_strategy="time",
            group_col="plugin_id",
            test_fraction=0.2,
            random_seed=42,
        )
        rc = _cmd_train_baseline(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "advisory_6m" in captured.out
    assert "logistic" in captured.out
    assert "0.82" in captured.out


def test_cmd_train_baseline_extra_exclude_and_prefixes(tmp_path: Path) -> None:
    fake_metrics = {
        "target_col": "t",
        "model_name": "random_forest",
        "train_row_count": 100,
        "train_positive_count": 5,
        "test_row_count": 50,
        "test_positive_count": 2,
        "feature_count": 10,
        "roc_auc": 0.7,
        "average_precision": 0.4,
    }

    with patch("canary.cli.train_baseline", return_value=fake_metrics) as mock_train:
        args = argparse.Namespace(
            in_path=str(tmp_path / "features.jsonl"),
            target_col="t",
            out_dir=str(tmp_path / "models"),
            test_start_month=None,
            exclude_cols="col_a, col_b",
            include_prefixes="gh_, swh_",
            model="random_forest",
            split_strategy="group",
            group_col="plugin_id",
            test_fraction=0.2,
            random_seed=42,
        )
        _cmd_train_baseline(args)

    call_kwargs = mock_train.call_args.kwargs
    assert call_kwargs["extra_exclude"] == {"col_a", "col_b"}
    assert call_kwargs["include_prefixes"] == ("gh_", "swh_")


# ---------------------------------------------------------------------------
# _cmd_build_monthly_labels
# ---------------------------------------------------------------------------


def test_cmd_build_monthly_labels(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    fake_rows = [{"plugin_id": "git", "month": "2024-01", "label_6m": 0}] * 42

    with patch("canary.cli.build_monthly_labels", return_value=fake_rows):
        args = argparse.Namespace(
            in_path=str(tmp_path / "monthly.jsonl"),
            out_path=str(tmp_path / "labeled.jsonl"),
            out_csv_path=str(tmp_path / "labeled.csv"),
            summary_path=str(tmp_path / "summary.json"),
            horizons="3,6,12",
        )
        rc = _cmd_build_monthly_labels(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "42" in captured.out


def test_cmd_build_monthly_labels_no_optional_paths(tmp_path: Path) -> None:
    with patch("canary.cli.build_monthly_labels", return_value=[]):
        args = argparse.Namespace(
            in_path=str(tmp_path / "monthly.jsonl"),
            out_path=str(tmp_path / "labeled.jsonl"),
            out_csv_path=None,
            summary_path=None,
            horizons="6",
        )
        rc = _cmd_build_monthly_labels(args)

    assert rc == 0


# ---------------------------------------------------------------------------
# _cmd_build_feature_bundle
# ---------------------------------------------------------------------------


def test_cmd_build_feature_bundle(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    fake_records = [{"plugin_id": f"p-{i}"} for i in range(7)]

    with patch("canary.cli.build_feature_bundle", return_value=fake_records):
        args = argparse.Namespace(
            data_raw_dir=str(tmp_path / "raw"),
            registry=str(tmp_path / "plugins.jsonl"),
            out=str(tmp_path / "features.jsonl"),
            out_csv=str(tmp_path / "features.csv"),
            summary_out=str(tmp_path / "summary.json"),
            software_heritage_backend="api",
        )
        rc = _cmd_build_feature_bundle(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "7" in captured.out


def test_cmd_build_feature_bundle_no_optional(tmp_path: Path) -> None:
    with patch("canary.cli.build_feature_bundle", return_value=[]):
        args = argparse.Namespace(
            data_raw_dir=str(tmp_path / "raw"),
            registry=str(tmp_path / "plugins.jsonl"),
            out=str(tmp_path / "features.jsonl"),
            out_csv=None,
            summary_out=None,
            software_heritage_backend="api",
        )
        rc = _cmd_build_feature_bundle(args)

    assert rc == 0


# ---------------------------------------------------------------------------
# _cmd_collect_healthscore
# ---------------------------------------------------------------------------


def test_cmd_collect_healthscore(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    fake_result = {"written": 5, "skipped": 1, "errors": 0}

    with patch("canary.cli.collect_health_scores", return_value=fake_result):
        args = argparse.Namespace(
            data_dir=str(tmp_path / "data"),
            timeout_s=30.0,
            overwrite=False,
        )
        rc = _cmd_collect_healthscore(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "written" in captured.out


# ---------------------------------------------------------------------------
# _cmd_collect_github
# ---------------------------------------------------------------------------


def test_cmd_collect_github(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    fake_result = {"plugin_id": "git", "stars": 42, "open_issues": 3}

    with patch("canary.cli.collect_github_plugin_real", return_value=fake_result) as mock_gh:
        args = argparse.Namespace(
            plugin="git",
            data_dir=str(tmp_path / "data"),
            out_dir=str(tmp_path / "github"),
            timeout_s=30.0,
            max_pages=5,
            commits_days=90,
            overwrite=False,
        )
        rc = _cmd_collect_github(args)

    assert rc == 0
    mock_gh.assert_called_once_with(
        plugin_id="git",
        data_dir=str(tmp_path / "data"),
        out_dir=str(tmp_path / "github"),
        timeout_s=30.0,
        max_pages=5,
        commits_days=90,
        overwrite=False,
    )
    captured = capsys.readouterr()
    assert "git" in captured.out
    assert "42" in captured.out


# ---------------------------------------------------------------------------
# _cmd_collect_advisories – additional branch coverage
# ---------------------------------------------------------------------------


def test_cmd_collect_advisories_real_single_plugin(tmp_path: Path) -> None:
    """Real-mode single-plugin path writes a per-plugin advisories file."""
    fake_records = [{"source": "jenkins", "plugin_id": "git"}]

    with patch("canary.cli.collect_advisories_real", return_value=fake_records):
        args = argparse.Namespace(
            out_dir=str(tmp_path / "advisories"),
            plugin="git",
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(tmp_path / "plugins.jsonl"),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 0
    out_file = tmp_path / "advisories" / "git.advisories.real.jsonl"
    assert out_file.exists()


def test_cmd_collect_advisories_bulk_max_plugins_limit(tmp_path: Path) -> None:
    """Bulk real mode respects the max_plugins limit and stops early."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "ant"}, {"plugin_id": "matrix"}])

    plugins_dir = tmp_path / "data" / "plugins"
    plugins_dir.mkdir(parents=True)
    for pid in ("git", "ant", "matrix"):
        snap = plugins_dir / f"{pid}.snapshot.json"
        snap.write_text(json.dumps({"plugin_id": pid}), encoding="utf-8")

    out_dir = tmp_path / "advisories"
    fake_records = [{"plugin_id": "git"}]

    with patch("canary.cli.collect_advisories_real", return_value=fake_records) as mock_collect:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            plugin=None,
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(reg),
            max_plugins=1,
            sleep=0,
            overwrite=True,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 0
    assert mock_collect.call_count == 1


def test_cmd_collect_advisories_bulk_no_snapshot_skip(tmp_path: Path) -> None:
    """Plugins with no snapshot file are silently skipped in bulk mode."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])
    # No snapshot file — plugin should be skipped

    with patch("canary.cli.collect_advisories_real") as mock_collect:
        args = argparse.Namespace(
            out_dir=str(tmp_path / "advisories"),
            plugin=None,
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 0
    mock_collect.assert_not_called()


def test_cmd_collect_advisories_bulk_overwrite_false_skips_existing(tmp_path: Path) -> None:
    """Existing per-plugin file is skipped when overwrite=False."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    plugins_dir = tmp_path / "data" / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "git.snapshot.json").write_text(
        json.dumps({"plugin_id": "git"}), encoding="utf-8"
    )

    out_dir = tmp_path / "advisories"
    out_dir.mkdir(parents=True)
    (out_dir / "git.advisories.real.jsonl").write_text('{"plugin_id": "git"}\n', encoding="utf-8")

    with patch("canary.cli.collect_advisories_real") as mock_collect:
        args = argparse.Namespace(
            out_dir=str(out_dir),
            plugin=None,
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=False,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 0
    mock_collect.assert_not_called()


def test_cmd_collect_advisories_bulk_error_handling(tmp_path: Path) -> None:
    """Per-plugin collection errors are caught and the return code becomes 2."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    plugins_dir = tmp_path / "data" / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "git.snapshot.json").write_text(
        json.dumps({"plugin_id": "git"}), encoding="utf-8"
    )

    with patch("canary.cli.collect_advisories_real", side_effect=RuntimeError("network error")):
        args = argparse.Namespace(
            out_dir=str(tmp_path / "advisories"),
            plugin=None,
            real=True,
            data_dir=str(tmp_path / "data"),
            registry_path=str(reg),
            max_plugins=None,
            sleep=0,
            overwrite=True,
        )
        rc = _cmd_collect_advisories(args)

    assert rc == 2


# ---------------------------------------------------------------------------
# _cmd_collect_registry – real mode
# ---------------------------------------------------------------------------


def test_cmd_collect_registry_real_with_raw_out(tmp_path: Path) -> None:
    """Real-mode registry collection writes plugins.jsonl and an optional raw pages file."""
    fake_registry = [{"plugin_id": "git"}, {"plugin_id": "ant"}]
    fake_raw_pages: list[dict] = [{"page": 1}]

    with patch(
        "canary.cli.collect_plugins_registry_real",
        return_value=(fake_registry, fake_raw_pages),
    ):
        out_dir = tmp_path / "registry"
        args = argparse.Namespace(
            out_dir=str(out_dir),
            out_name="plugins.jsonl",
            raw_out="raw_pages.json",
            real=True,
            page_size=100,
            max_plugins=None,
            timeout_s=30.0,
        )
        rc = _cmd_collect_registry(args)

    assert rc == 0
    assert (out_dir / "plugins.jsonl").exists()
    assert (out_dir / "raw_pages.json").exists()


def test_cmd_collect_registry_real_no_raw_out(tmp_path: Path) -> None:
    """Cover real=True path without raw_out."""
    fake_registry = [{"plugin_id": "git"}]
    fake_raw_pages: list[dict] = []

    with patch(
        "canary.cli.collect_plugins_registry_real",
        return_value=(fake_registry, fake_raw_pages),
    ):
        out_dir = tmp_path / "registry"
        args = argparse.Namespace(
            out_dir=str(out_dir),
            out_name="plugins.jsonl",
            raw_out=None,
            real=True,
            page_size=100,
            max_plugins=None,
            timeout_s=30.0,
        )
        rc = _cmd_collect_registry(args)

    assert rc == 0
    assert (out_dir / "plugins.jsonl").exists()


# ---------------------------------------------------------------------------
# _cmd_collect_software_heritage
# ---------------------------------------------------------------------------


def test_cmd_collect_software_heritage_with_out_dir(tmp_path: Path) -> None:
    """Explicit out_dir is passed through to collect_software_heritage."""
    fake_result = {"plugin_id": "git", "revisions": 5}

    with patch("canary.cli.collect_software_heritage", return_value=fake_result):
        args = argparse.Namespace(
            plugin="git",
            data_dir=str(tmp_path / "data"),
            out_dir=str(tmp_path / "swh"),
            backend="api",
            timeout_s=30.0,
            overwrite=False,
            database=None,
            output_location=None,
            max_visits=1000,
            directory_batch_size=50,
            max_directories=5000,
            quiet=False,
        )
        rc = _cmd_collect_software_heritage(args)

    assert rc == 0


def test_cmd_collect_software_heritage_default_out_dir(tmp_path: Path) -> None:
    """Cover default_out_dir_for_backend branch (out_dir=None)."""
    fake_result = {"plugin_id": "git", "revisions": 5}

    with patch("canary.cli.collect_software_heritage", return_value=fake_result):
        with patch(
            "canary.cli.default_out_dir_for_backend",
            return_value=str(tmp_path / "swh"),
        ) as mock_default:
            args = argparse.Namespace(
                plugin="git",
                data_dir=str(tmp_path / "data"),
                out_dir=None,
                backend="api",
                timeout_s=30.0,
                overwrite=False,
                database=None,
                output_location=None,
                max_visits=1000,
                directory_batch_size=50,
                max_directories=5000,
                quiet=False,
            )
            rc = _cmd_collect_software_heritage(args)

    assert rc == 0
    mock_default.assert_called_once_with("api")


# ---------------------------------------------------------------------------
# _cmd_collect_gharchive
# ---------------------------------------------------------------------------


def test_cmd_collect_gharchive(tmp_path: Path) -> None:
    """All GH Archive arguments are forwarded to collect_gharchive_history_real."""
    fake_result = {"queries": 5, "rows": 100}

    with patch("canary.cli.collect_gharchive_history_real", return_value=fake_result) as mock_gh:
        args = argparse.Namespace(
            data_dir=str(tmp_path / "data"),
            registry_path=str(tmp_path / "plugins.jsonl"),
            out_dir=str(tmp_path / "gharchive"),
            plugin=None,
            start="20230101",
            end="20231231",
            bucket_days=30,
            sample_percent=5.0,
            max_bytes_billed=2_000_000_000,
            overwrite=False,
            allow_jenkinsci_fallback=True,
            dry_run=False,
        )
        rc = _cmd_collect_gharchive(args)

    assert rc == 0
    mock_gh.assert_called_once()


# ---------------------------------------------------------------------------
# _cmd_build_monthly_feature_bundle
# ---------------------------------------------------------------------------


def test_cmd_build_monthly_feature_bundle(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Monthly feature bundle record count is printed after build."""
    fake_records = [{"plugin_id": f"p-{i}"} for i in range(5)]

    with patch("canary.cli.build_monthly_feature_bundle", return_value=fake_records):
        args = argparse.Namespace(
            data_raw_dir=str(tmp_path / "raw"),
            registry=str(tmp_path / "plugins.jsonl"),
            start="2024-01",
            end="2024-12",
            out=str(tmp_path / "monthly.jsonl"),
            out_csv=str(tmp_path / "monthly.csv"),
            summary_out=str(tmp_path / "summary.json"),
            software_heritage_backend="api",
        )
        rc = _cmd_build_monthly_feature_bundle(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "5" in captured.out


# ---------------------------------------------------------------------------
# _cmd_collect_enrich
# ---------------------------------------------------------------------------


def _make_enrich_args(
    tmp_path: Path,
    *,
    only: str | None = None,
    real: bool = False,
    max_plugins: int | None = None,
) -> argparse.Namespace:
    """Build a minimal Namespace for _cmd_collect_enrich tests."""
    reg = tmp_path / "plugins.jsonl"
    return argparse.Namespace(
        registry=str(reg),
        data_dir=str(tmp_path / "data"),
        real=real,
        only=only,
        max_plugins=max_plugins,
        sleep=0,
        software_heritage_backend="api",
        healthscore_timeout_s=30,
        github_timeout_s=20,
        github_max_pages=5,
        github_commits_days=365,
        software_heritage_timeout_s=30,
        software_heritage_quiet=False,
        software_heritage_athena_database=None,
        software_heritage_athena_output_location=None,
        software_heritage_athena_max_visits=1000,
        software_heritage_athena_directory_batch_size=50,
        software_heritage_athena_max_directories=5000,
    )


def test_cmd_collect_enrich_missing_registry(tmp_path: Path) -> None:
    """Missing registry file raises SystemExit before any work is done."""
    args = _make_enrich_args(tmp_path)
    # registry file not created, so it doesn't exist
    with pytest.raises(SystemExit):
        _cmd_collect_enrich(args)


def test_cmd_collect_enrich_only_healthscore(tmp_path: Path) -> None:
    """only='healthscore' fetches bulk health scores and returns without per-plugin iteration."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    with patch(
        "canary.cli.collect_health_scores",
        return_value={"written": 5, "skipped": 2},
    ):
        args = _make_enrich_args(tmp_path, only="healthscore")
        rc = _cmd_collect_enrich(args)

    assert rc == 0


def test_cmd_collect_enrich_healthscore_error(tmp_path: Path) -> None:
    """Health-score collection error increments the errors counter and returns 2."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    # Healthscore raises, but only="healthscore" so we stop after that
    with patch("canary.cli.collect_health_scores", side_effect=RuntimeError("hs fail")):
        args = _make_enrich_args(tmp_path, only="healthscore")
        rc = _cmd_collect_enrich(args)

    assert rc == 2


def test_cmd_collect_enrich_snapshot_only(tmp_path: Path) -> None:
    """only='snapshot' collects and writes per-plugin snapshot files."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    fake_snapshot = {"plugin_id": "git"}

    with patch("canary.cli.collect_plugin_snapshot", return_value=fake_snapshot):
        args = _make_enrich_args(tmp_path, only="snapshot")
        rc = _cmd_collect_enrich(args)

    assert rc == 0
    written = tmp_path / "data" / "plugins" / "git.snapshot.json"
    assert written.exists()


def test_cmd_collect_enrich_snapshot_already_exists(tmp_path: Path) -> None:
    """Existing snapshot is skipped (snap_skipped path)."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    plugins_dir = tmp_path / "data" / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "git.snapshot.json").write_text(
        json.dumps({"plugin_id": "git"}), encoding="utf-8"
    )

    with patch("canary.cli.collect_plugin_snapshot") as mock_snap:
        args = _make_enrich_args(tmp_path, only="snapshot")
        rc = _cmd_collect_enrich(args)

    assert rc == 0
    mock_snap.assert_not_called()


def test_cmd_collect_enrich_max_plugins(tmp_path: Path) -> None:
    """Enrich loop stops after max_plugins plugins have been processed."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}, {"plugin_id": "ant"}])

    with patch("canary.cli.collect_plugin_snapshot", return_value={"plugin_id": "x"}):
        args = _make_enrich_args(tmp_path, only="snapshot", max_plugins=1)
        rc = _cmd_collect_enrich(args)

    assert rc == 0
    # Only first plugin processed
    written_git = tmp_path / "data" / "plugins" / "git.snapshot.json"
    written_ant = tmp_path / "data" / "plugins" / "ant.snapshot.json"
    assert written_git.exists()
    assert not written_ant.exists()


def test_cmd_collect_enrich_plugin_error(tmp_path: Path) -> None:
    """Per-plugin errors are caught, the errors counter is incremented, and return code is 2."""
    reg = tmp_path / "plugins.jsonl"
    _write_registry(reg, [{"plugin_id": "git"}])

    with patch("canary.cli.collect_plugin_snapshot", side_effect=RuntimeError("snap fail")):
        args = _make_enrich_args(tmp_path, only="snapshot")
        rc = _cmd_collect_enrich(args)

    assert rc == 2


# ---------------------------------------------------------------------------
# _cmd_build_advisories_events
# ---------------------------------------------------------------------------


def test_cmd_build_advisories_events(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Advisory events are built and a confirmation message is printed."""
    with patch("canary.cli.build_advisories_events", return_value=42):
        args = argparse.Namespace(
            data_raw_dir=str(tmp_path / "raw"),
            out=str(tmp_path / "events.jsonl"),
        )
        rc = _cmd_build_advisories_events(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "events.jsonl" in captured.out


# ---------------------------------------------------------------------------
# _cmd_score
# ---------------------------------------------------------------------------


def test_cmd_score_text_mode(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Text mode prints the plugin name, score, and reason list."""
    fake_result = MagicMock()
    fake_result.plugin = "git"
    fake_result.score = 75
    fake_result.reasons = ["Reason A", "Reason B"]

    with patch("canary.cli.score_plugin_baseline", return_value=fake_result):
        args = argparse.Namespace(plugin="git", real=False, json=False)
        rc = _cmd_score(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "git" in captured.out
    assert "75" in captured.out
    assert "Reason A" in captured.out


def test_cmd_score_json_mode(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """JSON mode prints a parseable dict from result.to_dict()."""
    fake_result = MagicMock()
    fake_result.to_dict.return_value = {"plugin": "git", "score": 75, "reasons": []}

    with patch("canary.cli.score_plugin_baseline", return_value=fake_result):
        args = argparse.Namespace(plugin="git", real=True, json=True)
        rc = _cmd_score(args)

    assert rc == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["plugin"] == "git"
    assert parsed["score"] == 75


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def test_build_parser_returns_argument_parser() -> None:
    """build_parser() returns a properly configured ArgumentParser."""
    p = build_parser()
    assert isinstance(p, argparse.ArgumentParser)
    assert p.prog == "canary"


def test_build_parser_score_subcommand() -> None:
    """Parser can parse the 'score' sub-command."""
    p = build_parser()
    args = p.parse_args(["score", "workflow-cps"])
    assert args.plugin == "workflow-cps"
    assert args.json is False
    assert args.real is False


def test_build_parser_train_baseline_subcommand() -> None:
    """Parser can parse the 'train baseline' sub-command with defaults."""
    p = build_parser()
    args = p.parse_args(["train", "baseline"])
    assert args.model == "logistic"
    assert args.split_strategy == "time"
    assert args.test_fraction == 0.2
    assert args.random_seed == 42


def test_build_parser_collect_registry_subcommand() -> None:
    """Parser can parse 'collect registry'."""
    p = build_parser()
    args = p.parse_args(["collect", "registry"])
    assert args.out_name == "plugins.jsonl"
    assert args.real is False


def test_build_parser_collect_advisories_subcommand() -> None:
    """Parser can parse 'collect advisories' with optional flags."""
    p = build_parser()
    args = p.parse_args(["collect", "advisories", "--plugin", "git", "--real"])
    assert args.plugin == "git"
    assert args.real is True


def test_build_parser_build_features_subcommand() -> None:
    """Parser can parse 'build features'."""
    p = build_parser()
    args = p.parse_args(["build", "features", "--registry", "reg.jsonl", "--out", "features.jsonl"])
    assert args.registry == "reg.jsonl"
    assert args.out == "features.jsonl"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_dispatches_to_func() -> None:
    """main() builds the parser, parses args, and dispatches to args.func."""
    mock_func = MagicMock(return_value=0)

    with patch("canary.cli.build_parser") as mock_bp:
        mock_args = argparse.Namespace(func=mock_func)
        mock_parser = MagicMock()
        mock_parser.parse_args.return_value = mock_args
        mock_bp.return_value = mock_parser

        rc = main(["placeholder"])

    assert rc == 0
    mock_func.assert_called_once_with(mock_args)
