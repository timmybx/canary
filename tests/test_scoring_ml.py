"""Tests for canary.scoring.ml."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from canary.scoring.ml import (
    FeatureDriver,
    MLScorer,
    MLScoreResult,
    _extract_drivers,
    _risk_category,
    _window_features,
    load_ml_scorer,
    score_plugin_ml,
)

# ---------------------------------------------------------------------------
# FeatureDriver
# ---------------------------------------------------------------------------


def test_feature_driver_creation():
    fd = FeatureDriver(name="feat_a", value=1.5, direction="increases_risk", rank=1)
    assert fd.name == "feat_a"
    assert fd.value == 1.5
    assert fd.direction == "increases_risk"
    assert fd.rank == 1


def test_feature_driver_none_value():
    fd = FeatureDriver(name="feat_b", value=None, direction="neutral", rank=2)
    assert fd.value is None


def test_feature_driver_is_frozen():
    fd = FeatureDriver(name="feat_a", value=1.0, direction="increases_risk", rank=1)
    with pytest.raises((AttributeError, TypeError)):
        fd.name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# MLScoreResult.to_dict
# ---------------------------------------------------------------------------


def _make_result(probability: float = 0.1) -> MLScoreResult:
    drivers = [
        FeatureDriver(name="feat_a", value=1.0, direction="increases_risk", rank=1),
    ]
    return MLScoreResult(
        plugin="test-plugin",
        probability=probability,
        canary_score=probability,
        risk_category=_risk_category(probability),
        drivers=drivers,
        feature_vector={"feat_a": 1.0},
        model_dir="/tmp/model",
        scored_at="2025-01-01T00:00:00+00:00",
    )


def test_ml_score_result_to_dict_keys():
    result = _make_result(0.1)
    d = result.to_dict()
    assert d["plugin"] == "test-plugin"
    assert d["probability"] == 0.1
    assert d["canary_score"] == 0.1
    assert isinstance(d["drivers"], list)
    assert len(d["drivers"]) == 1
    assert d["drivers"][0]["name"] == "feat_a"
    assert d["drivers"][0]["rank"] == 1


def test_ml_score_result_to_dict_driver_structure():
    result = _make_result()
    d = result.to_dict()
    driver = d["drivers"][0]
    assert "name" in driver
    assert "value" in driver
    assert "direction" in driver
    assert "rank" in driver


def test_ml_score_result_to_dict_feature_vector():
    result = _make_result()
    d = result.to_dict()
    assert "feature_vector" in d
    assert d["feature_vector"] == {"feat_a": 1.0}


# ---------------------------------------------------------------------------
# _risk_category
# ---------------------------------------------------------------------------


def test_risk_category_low():
    assert _risk_category(0.0) == "Low"
    assert _risk_category(0.04) == "Low"


def test_risk_category_at_low_threshold():
    assert _risk_category(0.05) == "Medium"


def test_risk_category_medium():
    assert _risk_category(0.10) == "Medium"
    assert _risk_category(0.19) == "Medium"


def test_risk_category_at_high_threshold():
    assert _risk_category(0.20) == "High"


def test_risk_category_high():
    assert _risk_category(0.50) == "High"
    assert _risk_category(0.99) == "High"


# ---------------------------------------------------------------------------
# _window_features
# ---------------------------------------------------------------------------


def test_window_features_has_expected_keys():
    result = _window_features()
    assert "window_year" in result
    assert "window_month" in result
    assert "window_index" in result


def test_window_features_reasonable_values():
    result = _window_features()
    assert result["window_year"] >= 2025.0
    assert 1.0 <= result["window_month"] <= 12.0
    assert result["window_index"] >= 0.0


def test_window_features_fixed_date():
    d = date(2025, 1, 1)
    result = _window_features(today=d)
    assert result["window_year"] == 2025.0
    assert result["window_month"] == 1.0
    # 2025-01 is 60 months after 2020-01
    assert result["window_index"] == 60.0


def test_window_features_epoch():
    d = date(2020, 1, 1)
    result = _window_features(today=d)
    assert result["window_index"] == 0.0


def test_window_features_different_dates():
    d1 = date(2020, 6, 1)
    d2 = date(2021, 6, 1)
    r1 = _window_features(today=d1)
    r2 = _window_features(today=d2)
    assert r2["window_index"] == r1["window_index"] + 12.0


# ---------------------------------------------------------------------------
# load_ml_scorer
# ---------------------------------------------------------------------------


def test_load_ml_scorer_missing_model(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="No trained model"):
        load_ml_scorer(tmp_path)


def test_load_ml_scorer_missing_feature_columns(tmp_path: Path):
    import joblib
    from sklearn.linear_model import LogisticRegression

    model_path = tmp_path / "model.joblib"
    joblib.dump(LogisticRegression(), str(model_path))

    with pytest.raises(FileNotFoundError, match="No feature column"):
        load_ml_scorer(tmp_path)


def test_load_ml_scorer_success(tmp_path: Path):
    import joblib
    from sklearn.linear_model import LogisticRegression

    model = LogisticRegression()
    X = np.array([[0, 1], [1, 0], [0, 0], [1, 1]])
    y = np.array([0, 1, 0, 1])
    model.fit(X, y)

    model_path = tmp_path / "model.joblib"
    cols_path = tmp_path / "feature_columns.json"
    joblib.dump(model, str(model_path))
    cols_path.write_text(json.dumps(["feat_a", "feat_b"]), encoding="utf-8")

    scorer = load_ml_scorer(tmp_path)
    assert scorer.feature_columns == ["feat_a", "feat_b"]
    assert scorer.model_dir == str(tmp_path)
    assert isinstance(scorer.pipeline, LogisticRegression)


def test_load_ml_scorer_accepts_string_path(tmp_path: Path):
    import joblib
    from sklearn.linear_model import LogisticRegression

    model = LogisticRegression()
    X = np.array([[0, 1], [1, 0]])
    y = np.array([0, 1])
    model.fit(X, y)

    (tmp_path / "model.joblib").write_bytes(b"")  # placeholder
    joblib.dump(model, str(tmp_path / "model.joblib"))
    (tmp_path / "feature_columns.json").write_text(json.dumps(["f1", "f2"]), encoding="utf-8")

    scorer = load_ml_scorer(str(tmp_path))
    assert scorer.feature_columns == ["f1", "f2"]


# ---------------------------------------------------------------------------
# _extract_drivers  — fallback path (no SHAP)
# ---------------------------------------------------------------------------


def _clf_with_coef(coef_values: list[float]) -> MagicMock:
    """Minimal mock with coef_ only (logistic-regression-like fallback)."""
    mock = MagicMock(spec=[])
    mock.coef_ = np.array([coef_values])
    return mock


def _clf_with_importances(imp_values: list[float]) -> MagicMock:
    """Minimal mock with feature_importances_ only (tree-model-like fallback)."""
    mock = MagicMock(spec=[])
    mock.feature_importances_ = np.array(imp_values)
    return mock


def _pipeline_with_named_steps(clf: MagicMock) -> MagicMock:
    """Minimal mock pipeline whose last named_step is clf."""
    mock = MagicMock(spec=[])
    mock.named_steps = {"impute": MagicMock(spec=[]), "model": clf}
    return mock


def test_extract_drivers_coef_direction_increases():
    cols = ["feat_a", "feat_b"]
    vec = {"feat_a": 1.0, "feat_b": 0.5}
    clf = _clf_with_coef([0.8, -0.2])
    drivers = _extract_drivers(clf, cols, vec, top_n=2)
    assert any(d.direction == "increases_risk" for d in drivers)
    assert any(d.direction == "decreases_risk" for d in drivers)


def test_extract_drivers_coef_neutral():
    cols = ["feat_a"]
    vec = {"feat_a": 0.0}
    clf = _clf_with_coef([1.0])
    drivers = _extract_drivers(clf, cols, vec, top_n=5)
    # coef=1.0 * val=0.0 → score=0.0 → neutral
    assert drivers[0].direction == "neutral"


def test_extract_drivers_coef_top_n():
    cols = ["a", "b", "c", "d"]
    vec = {c: 1.0 for c in cols}
    clf = _clf_with_coef([0.4, 0.3, 0.2, 0.1])
    drivers = _extract_drivers(clf, cols, vec, top_n=2)
    assert len(drivers) == 2
    assert drivers[0].rank == 1
    assert drivers[1].rank == 2


def test_extract_drivers_feature_importances():
    cols = ["feat_a", "feat_b", "feat_c"]
    vec = {"feat_a": 1.0, "feat_b": 0.5, "feat_c": None}
    clf = _clf_with_importances([0.6, 0.3, 0.1])
    drivers = _extract_drivers(clf, cols, vec, top_n=3)
    assert len(drivers) == 3
    assert drivers[0].name == "feat_a"
    assert drivers[0].direction == "increases_risk"


def test_extract_drivers_no_coef_or_importances():
    """Pipeline with neither coef_ nor feature_importances_ returns empty list."""
    clf = MagicMock(spec=[])
    drivers = _extract_drivers(clf, ["feat_a"], {"feat_a": 1.0}, top_n=5)
    assert drivers == []


def test_extract_drivers_pipeline_named_steps_unwraps():
    """Pipeline with named_steps unwraps to last step for fallback drivers."""
    clf = _clf_with_coef([0.5, -0.3])
    pipeline = _pipeline_with_named_steps(clf)
    cols = ["feat_a", "feat_b"]
    vec = {"feat_a": 1.0, "feat_b": 1.0}
    drivers = _extract_drivers(pipeline, cols, vec, top_n=5)
    assert len(drivers) == 2


def test_extract_drivers_none_values_treated_as_zero():
    """None feature values are treated as 0.0 in coef-based scoring."""
    cols = ["feat_a"]
    vec = {"feat_a": None}
    clf = _clf_with_coef([1.0])
    drivers = _extract_drivers(clf, cols, vec, top_n=5)
    assert drivers[0].value is None
    assert drivers[0].direction == "neutral"


# ---------------------------------------------------------------------------
# _build_feature_vector
# ---------------------------------------------------------------------------


def _patch_all_loaders(
    snapshot: dict | None = None,
    advisory: dict | None = None,
    healthscore: dict | None = None,
    swh: dict | None = None,
    github: dict | None = None,
    gharchive: dict | None = None,
):
    """Context manager that patches all six feature loader functions."""
    from contextlib import ExitStack

    stack = ExitStack()
    base = "canary.build.features_bundle"
    stack.enter_context(patch(f"{base}._load_snapshot_features", return_value=snapshot or {}))
    stack.enter_context(patch(f"{base}._load_advisory_features", return_value=advisory or {}))
    stack.enter_context(patch(f"{base}._load_healthscore_features", return_value=healthscore or {}))
    stack.enter_context(patch(f"{base}._load_software_heritage_features", return_value=swh or {}))
    stack.enter_context(patch(f"{base}._load_github_features", return_value=github or {}))
    stack.enter_context(patch(f"{base}._load_gharchive_features", return_value=gharchive or {}))
    return stack


def test_build_feature_vector_bundle_to_model_name_mapping(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders(
        snapshot={"swh_present": True},
        advisory={"advisory_count": 3, "advisories_present": False},
    ):
        cols = [
            "swh_present_any",
            "advisory_count_to_date",
            "advisories_present_any",
            "window_year",
            "window_month",
            "window_index",
        ]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["swh_present_any"] == 1.0  # bool True → 1.0
    assert vec["advisory_count_to_date"] == 3.0  # int → float
    assert vec["advisories_present_any"] == 0.0  # bool False → 0.0


def test_build_feature_vector_window_features_present(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders():
        cols = ["window_year", "window_month", "window_index"]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["window_year"] is not None
    assert vec["window_month"] is not None
    assert vec["window_index"] is not None


def test_build_feature_vector_missing_column_is_none(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders():
        cols = ["totally_unknown_col", "window_year", "window_month", "window_index"]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["totally_unknown_col"] is None


def test_build_feature_vector_non_numeric_becomes_none(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders(snapshot={"some_text_col": "hello"}):
        cols = ["some_text_col", "window_year", "window_month", "window_index"]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["some_text_col"] is None


def test_build_feature_vector_none_value_stays_none(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders(snapshot={"nullable_col": None}):
        cols = ["nullable_col", "window_year", "window_month", "window_index"]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["nullable_col"] is None


def test_build_feature_vector_float_passthrough(tmp_path: Path):
    from canary.scoring.ml import _build_feature_vector

    with _patch_all_loaders(github={"github_stars": 42.5}):
        cols = ["github_stars", "window_year", "window_month", "window_index"]
        vec = _build_feature_vector("test-plugin", tmp_path, cols)

    assert vec["github_stars"] == 42.5


# ---------------------------------------------------------------------------
# score_plugin_ml
# ---------------------------------------------------------------------------


def _make_mock_scorer(
    feature_columns: list[str] | None = None,
    proba: float = 0.3,
) -> MLScorer:
    cols = feature_columns or ["feat_a", "feat_b"]
    mock_pipeline = MagicMock()
    mock_pipeline.predict_proba.return_value = np.array([[1 - proba, proba]])
    return MLScorer(pipeline=mock_pipeline, feature_columns=cols, model_dir="/tmp/model")


def _score_with_mocks(
    plugin_id: str = "my-plugin",
    safe_id: str | None = "my-plugin",
    proba: float = 0.3,
    feature_cols: list[str] | None = None,
) -> MLScoreResult:
    """Helper to call score_plugin_ml with all internals mocked."""
    scorer = _make_mock_scorer(feature_cols or ["feat_a", "feat_b"], proba=proba)
    vec = {c: 1.0 for c in scorer.feature_columns}
    with (
        patch("canary.plugin_aliases.canonicalize_plugin_id", return_value=plugin_id),
        patch("canary.scoring.baseline._safe_plugin_id", return_value=safe_id),
        patch("canary.scoring.ml._build_feature_vector", return_value=vec),
        patch("canary.scoring.ml._extract_drivers", return_value=[]),
    ):
        return score_plugin_ml(plugin_id, scorer=scorer)


def test_score_plugin_ml_returns_ml_score_result():
    result = _score_with_mocks()
    assert isinstance(result, MLScoreResult)


def test_score_plugin_ml_plugin_field():
    result = _score_with_mocks(plugin_id="my-plugin", safe_id="my-plugin")
    assert result.plugin == "my-plugin"


def test_score_plugin_ml_probability_in_range():
    result = _score_with_mocks(proba=0.3)
    assert 0.0 <= result.probability <= 1.0


def test_score_plugin_ml_canary_score_equals_probability():
    result = _score_with_mocks(proba=0.15)
    assert result.canary_score == result.probability


def test_score_plugin_ml_risk_category_low():
    result = _score_with_mocks(proba=0.03)
    assert result.risk_category == "Low"


def test_score_plugin_ml_risk_category_medium():
    result = _score_with_mocks(proba=0.10)
    assert result.risk_category == "Medium"


def test_score_plugin_ml_risk_category_high():
    result = _score_with_mocks(proba=0.30)
    assert result.risk_category == "High"


def test_score_plugin_ml_drivers_is_list():
    result = _score_with_mocks()
    assert isinstance(result.drivers, list)


def test_score_plugin_ml_feature_vector_is_dict():
    result = _score_with_mocks()
    assert isinstance(result.feature_vector, dict)


def test_score_plugin_ml_model_dir():
    result = _score_with_mocks()
    assert result.model_dir == "/tmp/model"


def test_score_plugin_ml_scored_at_is_iso_string():
    result = _score_with_mocks()
    assert isinstance(result.scored_at, str)
    assert "T" in result.scored_at


def test_score_plugin_ml_to_dict_roundtrip():
    result = _score_with_mocks()
    d = result.to_dict()
    assert d["plugin"] == result.plugin
    assert d["probability"] == result.probability
    assert d["risk_category"] == result.risk_category


def test_score_plugin_ml_invalid_plugin_id_raises():
    scorer = _make_mock_scorer()
    with (
        patch("canary.plugin_aliases.canonicalize_plugin_id", return_value="bad"),
        patch("canary.scoring.baseline._safe_plugin_id", return_value=None),
    ):
        with pytest.raises(ValueError, match="Invalid plugin id"):
            score_plugin_ml("bad", scorer=scorer)


def test_score_plugin_ml_probability_rounded():
    scorer = _make_mock_scorer(proba=0.123456789)
    vec = {"feat_a": 1.0, "feat_b": 1.0}
    with (
        patch("canary.plugin_aliases.canonicalize_plugin_id", return_value="p"),
        patch("canary.scoring.baseline._safe_plugin_id", return_value="p"),
        patch("canary.scoring.ml._build_feature_vector", return_value=vec),
        patch("canary.scoring.ml._extract_drivers", return_value=[]),
    ):
        result = score_plugin_ml("p", scorer=scorer)
    # probability should be rounded to 4 decimal places
    assert result.probability == round(result.probability, 4)


def test_score_plugin_ml_uses_top_drivers_param():
    """top_drivers parameter is forwarded to _extract_drivers."""
    scorer = _make_mock_scorer()
    vec = {"feat_a": 1.0, "feat_b": 1.0}
    with (
        patch("canary.plugin_aliases.canonicalize_plugin_id", return_value="p"),
        patch("canary.scoring.baseline._safe_plugin_id", return_value="p"),
        patch("canary.scoring.ml._build_feature_vector", return_value=vec),
        patch("canary.scoring.ml._extract_drivers", return_value=[]) as mock_extract,
    ):
        score_plugin_ml("p", scorer=scorer, top_drivers=5)
    _, kwargs = mock_extract.call_args
    assert kwargs.get("top_n") == 5 or mock_extract.call_args[0][3] == 5
