"""
CLI coverage gap tests — targets _cmd_score_ml, _cmd_train_feature_select,
and uncovered error/output branches in existing commands.

Covers cli.py lines: 165, 232, 254, 491-537, 630-755, 1389
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from canary.cli import (
    _cmd_collect_advisories,
    _cmd_collect_plugin,
    _cmd_score_ml,
    _cmd_train_feature_select,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**kwargs) -> argparse.Namespace:
    defaults = {
        "real": False,
        "json": False,
        "plugin": "test-plugin",
        "data_dir": "data/raw",
        "model_dir": "models/test",
        "top_drivers": 5,
        "in_path": "data/processed/features/plugins.monthly.labeled.jsonl",
        "subset_sizes": None,
        "random_seed": 42,
        "out_dir": None,
        "horizon": "6m",
        "split": "time",
        "algo": "logistic",
        "feature_set": None,
        "scale_pos_weight": None,
        "max_plugins": None,
        "overwrite": False,
        "sleep": 0,
        "registry_path": None,
        "id": None,
        "repo_url": None,
        # feature_select args
        "target_col": "label_6m",
        "test_start_month": None,
        "split_strategy": "time",
        "group_col": "plugin_id",
        "test_fraction": 0.2,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# _cmd_score_ml — success path (text output)
# ---------------------------------------------------------------------------


class TestCmdScoreMl:
    """Tests for _cmd_score_ml — uses mocks to avoid needing real model files."""

    def _mock_result(self, prob: float = 0.72, risk: str = "High") -> MagicMock:
        driver = MagicMock()
        driver.name = "advisory_max_cvss_to_date"
        driver.value = 7.5
        driver.direction = "increases_risk"

        result = MagicMock()
        result.plugin = "test-plugin"
        result.probability = prob
        result.risk_category = risk
        result.model_dir = "models/test"
        result.scored_at = "2025-05-01T00:00:00"
        result.drivers = [driver]
        result.to_dict.return_value = {
            "plugin": "test-plugin",
            "probability": prob,
            "risk_category": risk,
            "drivers": [],
        }
        return result

    def test_text_output_returns_zero(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="test-plugin", json=False, top_drivers=5)
        mock_result = self._mock_result()
        with (
            patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
            patch("canary.scoring.ml.score_plugin_ml", return_value=mock_result),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "test-plugin" in out
        assert "72.0%" in out

    def test_json_output_returns_zero(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="test-plugin", json=True, top_drivers=5)
        mock_result = self._mock_result()
        with (
            patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
            patch("canary.scoring.ml.score_plugin_ml", return_value=mock_result),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["plugin"] == "test-plugin"

    def test_model_not_found_returns_one(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="test-plugin", json=False)
        with patch(
            "canary.scoring.ml.load_ml_scorer",
            side_effect=FileNotFoundError("model.joblib not found"),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "Error" in out
        assert "canary train baseline" in out

    def test_score_value_error_returns_one(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="unknown-plugin", json=False)
        with (
            patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
            patch(
                "canary.scoring.ml.score_plugin_ml",
                side_effect=ValueError("Plugin not in feature dataset"),
            ),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "Error" in out

    def test_no_drivers_prints_fallback(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="test-plugin", json=False, top_drivers=0)
        mock_result = self._mock_result()
        mock_result.drivers = []
        with (
            patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
            patch("canary.scoring.ml.score_plugin_ml", return_value=mock_result),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "No driver information" in out

    def test_risk_icons_shown_for_each_category(self, capsys: pytest.CaptureFixture) -> None:
        for risk, icon in [("Low", "🟢"), ("Medium", "🟡"), ("High", "🔴")]:
            args = _make_args(plugin="test-plugin", json=False)
            mock_result = self._mock_result(risk=risk)
            with (
                patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
                patch("canary.scoring.ml.score_plugin_ml", return_value=mock_result),
            ):
                _cmd_score_ml(args)
            out = capsys.readouterr().out
            assert icon in out

    def test_unknown_risk_category_uses_default_icon(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(plugin="test-plugin", json=False)
        mock_result = self._mock_result(risk="Unknown")
        with (
            patch("canary.scoring.ml.load_ml_scorer", return_value=MagicMock()),
            patch("canary.scoring.ml.score_plugin_ml", return_value=mock_result),
        ):
            rc = _cmd_score_ml(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "⚪" in out


# ---------------------------------------------------------------------------
# _cmd_train_feature_select
# ---------------------------------------------------------------------------


class TestCmdTrainFeatureSelect:
    """Tests for _cmd_train_feature_select — mocks the heavy feature selection."""

    def _mock_fs_result(self, h3_ok: bool = True) -> dict:
        subset = {
            "subset_label": "top-10",
            "actual_feature_count": 10,
            "average_precision": 0.71,
            "ap_retention_vs_full": 0.92,
            "meets_h3_threshold": h3_ok,
        }
        result: dict = {
            "full_model_average_precision": 0.77,
            "full_model_feature_count": 154,
            "subset_results": [subset],
            "h3_satisfied": h3_ok,
        }
        if h3_ok:
            result["h3_smallest_qualifying_subset"] = {
                "size": 10,
                "ap_retention": 0.92,
                "average_precision": 0.71,
            }
        return result

    def test_h3_satisfied_returns_zero(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(
            model_dir="models/test",
            in_path="data/processed/features.jsonl",
            subset_sizes=None,
            random_seed=42,
        )
        with patch(
            "canary.train.feature_selection.run_feature_selection",
            return_value=self._mock_fs_result(h3_ok=True),
        ):
            rc = _cmd_train_feature_select(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "H3 SATISFIED" in out
        assert "top-10" in out

    def test_h3_not_satisfied_prints_message(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(
            model_dir="models/test",
            in_path="data/processed/features.jsonl",
            subset_sizes=None,
            random_seed=42,
        )
        with patch(
            "canary.train.feature_selection.run_feature_selection",
            return_value=self._mock_fs_result(h3_ok=False),
        ):
            rc = _cmd_train_feature_select(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "H3 NOT satisfied" in out

    def test_custom_subset_sizes_parsed(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(
            model_dir="models/test",
            in_path="data/processed/features.jsonl",
            subset_sizes="5,10,20",
            random_seed=42,
        )
        captured_kwargs: dict = {}

        def mock_run(**kwargs):
            captured_kwargs.update(kwargs)
            return self._mock_fs_result()

        with patch(
            "canary.train.feature_selection.run_feature_selection",
            side_effect=mock_run,
        ):
            rc = _cmd_train_feature_select(args)
        assert rc == 0
        assert captured_kwargs.get("subset_sizes") == (5, 10, 20)

    def test_invalid_subset_sizes_returns_one(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(
            model_dir="models/test",
            in_path="data/processed/features.jsonl",
            subset_sizes="five,ten",
            random_seed=42,
        )
        rc = _cmd_train_feature_select(args)
        assert rc == 1
        out = capsys.readouterr().out
        assert "Error" in out
        assert "comma-separated integers" in out

    def test_subset_ap_none_handled(self, capsys: pytest.CaptureFixture) -> None:
        args = _make_args(
            model_dir="models/test",
            in_path="data/processed/features.jsonl",
            subset_sizes=None,
            random_seed=42,
        )
        result = self._mock_fs_result()
        # Set ap and retention to None to test the n/a and — branches
        result["subset_results"][0]["average_precision"] = None
        result["subset_results"][0]["ap_retention_vs_full"] = None
        result["subset_results"][0]["meets_h3_threshold"] = None
        with patch(
            "canary.train.feature_selection.run_feature_selection",
            return_value=result,
        ):
            rc = _cmd_train_feature_select(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "n/a" in out
        assert "—" in out


# ---------------------------------------------------------------------------
# Error branches in existing commands — previously uncovered
# ---------------------------------------------------------------------------


class TestCmdCollectPluginErrorBranch:
    """Tests for error handling branches in _cmd_collect_plugin."""

    def test_bulk_error_increments_error_count(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        registry = tmp_path / "registry.jsonl"
        registry.write_text(json.dumps({"plugin_id": "bad-plugin"}) + "\n", encoding="utf-8")
        args = _make_args(
            real=False,
            id=None,
            registry_path=str(registry),
            out_dir=str(tmp_path / "plugins"),
            overwrite=True,
            max_plugins=None,
            sleep=0,
        )
        (tmp_path / "plugins").mkdir()

        with patch(
            "canary.cli.collect.collect_plugin_snapshot",
            side_effect=RuntimeError("network error"),
            autospec=True,
        ):
            rc = _cmd_collect_plugin(args)

        out = capsys.readouterr().out
        assert "ERROR" in out
        assert rc == 2  # bulk mode returns 2 when errors > 0

    def test_bulk_sleep_is_called(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        registry = tmp_path / "registry.jsonl"
        registry.write_text(json.dumps({"plugin_id": "sleepy-plugin"}) + "\n", encoding="utf-8")
        out_dir = tmp_path / "plugins"
        out_dir.mkdir()
        args = _make_args(
            real=False,
            id=None,
            registry_path=str(registry),
            out_dir=str(out_dir),
            overwrite=True,
            max_plugins=None,
            sleep=0.001,
        )

        mock_snap = {"plugin_id": "sleepy-plugin", "data": {}}
        with (
            patch(
                "canary.cli.collect.collect_plugin_snapshot",
                return_value=mock_snap,
            ),
            patch("time.sleep") as mock_sleep,
        ):
            _cmd_collect_plugin(args)

        mock_sleep.assert_called_once_with(0.001)


class TestCmdCollectAdvisoriesErrorBranch:
    """Tests for error/exception branches in _cmd_collect_advisories."""

    def test_bulk_error_is_printed(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        # Error branch only fires in real bulk mode (per-plugin iteration)
        registry = tmp_path / "registry.jsonl"
        registry.write_text(json.dumps({"plugin_id": "fail-plugin"}) + "\n", encoding="utf-8")
        out_dir = tmp_path / "advisories"
        out_dir.mkdir()
        args = _make_args(
            real=True,
            plugin=None,
            registry_path=str(registry),
            out_dir=str(out_dir),
            overwrite=True,
            max_plugins=None,
            sleep=0,
        )

        # Must create a snapshot file so the loop doesn't skip due to no_snapshot
        plugins_dir = tmp_path / "data" / "raw" / "plugins"
        plugins_dir.mkdir(parents=True)
        (plugins_dir / "fail-plugin.snapshot.json").write_text(
            json.dumps({"plugin_id": "fail-plugin"}), encoding="utf-8"
        )
        args.data_dir = str(tmp_path / "data" / "raw")

        with patch(
            "canary.cli.collect.collect_advisories_real",
            side_effect=RuntimeError("parse error"),
            autospec=True,
        ):
            rc = _cmd_collect_advisories(args)

        out = capsys.readouterr().out
        assert "ERROR" in out
        assert rc == 2  # returns 2 when errors > 0
