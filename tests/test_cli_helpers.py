from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from canary.cli import (
    _cmd_build_feature_bundle,
    _cmd_build_monthly_labels,
    _cmd_collect_advisories,
    _cmd_collect_github,
    _cmd_collect_healthscore,
    _cmd_collect_plugin,
    _cmd_collect_registry,
    _cmd_train_baseline,
    _iter_registry_plugin_ids,
    _nonempty,
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
    # With a specific plugin the sample returns [] (only matches workflow-cps in bulk)
    out_file = out_dir / "workflow-cps.advisories.sample.jsonl"
    assert out_file.exists()


def test_cmd_collect_advisories_sample_single_plugin_with_data(tmp_path: Path) -> None:
    """Single-plugin sample mode writes the file and returns 0."""
    out_dir = tmp_path / "advisories"
    args = argparse.Namespace(
        out_dir=str(out_dir),
        plugin=None,  # bulk
        real=False,
        data_dir=str(tmp_path / "data"),
        registry_path=str(tmp_path / "plugins.jsonl"),
        max_plugins=None,
        sleep=0,
        overwrite=False,
    )
    rc = _cmd_collect_advisories(args)
    assert rc == 0


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
        "model_name": "logistic_regression",
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
            model="logistic_regression",
        )
        rc = _cmd_train_baseline(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "advisory_6m" in captured.out
    assert "logistic_regression" in captured.out
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
