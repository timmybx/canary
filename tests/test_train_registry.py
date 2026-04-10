"""Tests for canary.train.registry."""

from __future__ import annotations

import pytest

from canary.train.registry import AVAILABLE_MODELS, MODEL_REGISTRY, get_model

# ---------------------------------------------------------------------------
# MODEL_REGISTRY shape
# ---------------------------------------------------------------------------


def test_model_registry_contains_core_models():
    assert "logistic" in MODEL_REGISTRY
    assert "random_forest" in MODEL_REGISTRY


def test_model_registry_contains_optional_models():
    # xgboost and lightgbm may be None if not installed, but should be present as keys
    assert "xgboost" in MODEL_REGISTRY
    assert "lightgbm" in MODEL_REGISTRY


def test_available_models_is_subset_of_registry():
    for name in AVAILABLE_MODELS:
        assert name in MODEL_REGISTRY
        assert MODEL_REGISTRY[name] is not None


def test_core_models_always_available():
    # logistic and random_forest should always be available (sklearn is a hard dep)
    assert "logistic" in AVAILABLE_MODELS
    assert "random_forest" in AVAILABLE_MODELS


# ---------------------------------------------------------------------------
# get_model
# ---------------------------------------------------------------------------


def test_get_model_logistic():
    model = get_model("logistic")
    assert model is not None


def test_get_model_random_forest():
    model = get_model("random_forest")
    assert model is not None


def test_get_model_unknown_raises():
    with pytest.raises(ValueError, match="Unknown model"):
        get_model("totally_nonexistent_model")


def test_get_model_error_includes_available_models():
    with pytest.raises(ValueError) as exc_info:
        get_model("totally_nonexistent_model")
    error_msg = str(exc_info.value)
    for available in AVAILABLE_MODELS:
        assert available in error_msg


def test_get_model_none_model_raises():
    """If a model key exists but the value is None (optional dep not installed),
    get_model should raise ValueError with a helpful message."""
    # Temporarily override a model to None for testing
    import canary.train.registry as reg

    original = reg.MODEL_REGISTRY.get("xgboost")
    if original is not None:
        # xgboost is installed; skip this test path
        pytest.skip("xgboost is installed; cannot test None model path")

    with pytest.raises(ValueError, match="not installed"):
        get_model("xgboost")
