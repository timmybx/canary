"""
ML-backed scoring for CANARY.

Loads a trained sklearn pipeline (saved by canary/train/baseline.py) and
uses it to produce a probabilistic CANARY score for a single plugin using
its current collected data.

The score is returned as a float in [0, 1] alongside a ranked list of the
features that most influenced it, drawn from the feature_columns.json
contract saved alongside the model.

Usage
-----
    from canary.scoring.ml import load_ml_scorer, score_plugin_ml

    scorer = load_ml_scorer("data/processed/models/baseline_6m")
    result = score_plugin_ml("cucumber-reports", scorer=scorer)
    print(result.probability)   # e.g. 0.62
    print(result.drivers)       # top features pushing the score up/down
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FeatureDriver:
    """A single feature that influenced the ML score."""

    name: str
    value: float | None
    direction: str  # "increases_risk" | "decreases_risk" | "neutral"
    rank: int


@dataclass
class MLScoreResult:
    """Result of ML-based scoring for a single plugin."""

    plugin: str
    probability: float  # raw model output in [0, 1]
    canary_score: float  # same value, alias for UI consistency
    risk_category: str  # "Low" | "Medium" | "High"
    drivers: list[FeatureDriver]
    feature_vector: dict[str, float | None]
    model_dir: str
    model_name: str  # e.g. "xgboost", "logistic", "lightgbm"
    scored_at: str  # ISO timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "probability": self.probability,
            "canary_score": self.canary_score,
            "risk_category": self.risk_category,
            "model_name": self.model_name,
            "drivers": [
                {
                    "name": d.name,
                    "value": d.value,
                    "direction": d.direction,
                    "rank": d.rank,
                }
                for d in self.drivers
            ],
            "feature_vector": self.feature_vector,
            "model_dir": self.model_dir,
            "scored_at": self.scored_at,
        }


@dataclass
class MLScorer:
    """A loaded model + feature contract, ready to score plugins."""

    pipeline: Any  # fitted sklearn Pipeline
    feature_columns: list[str]  # exact ordered column list the pipeline expects
    model_dir: str
    model_name: str  # e.g. "xgboost", "logistic", "lightgbm" — from metrics.json


# ---------------------------------------------------------------------------
# CANARY risk thresholds (mirrors Table 1-1 in the praxis)
# ---------------------------------------------------------------------------

_LOW_THRESHOLD = 0.05
_HIGH_THRESHOLD = 0.20


def _risk_category(probability: float) -> str:
    if probability < _LOW_THRESHOLD:
        return "Low"
    if probability < _HIGH_THRESHOLD:
        return "Medium"
    return "High"


# ---------------------------------------------------------------------------
# Column name mapping: bundle output -> model training names
#
# features_bundle.py uses slightly different names for a handful of columns
# compared to what monthly_features.py produced during training.  This map
# translates bundle names so the feature vector matches the model contract.
# ---------------------------------------------------------------------------

_BUNDLE_TO_MODEL: dict[str, str] = {
    "swh_present": "swh_present_any",
    "swh_has_snapshot": "swh_has_snapshot_to_date",
    "swh_visit_count": "swh_visit_count_to_date",
    "swh_archive_age_days": "swh_archive_age_days_to_date",
    # advisory bundle names -> monthly training names
    "advisories_present": "advisories_present_any",
    "advisory_count": "advisory_count_to_date",
    "advisory_cve_count": "advisory_cve_count_to_date",
    "advisory_max_cvss": "advisory_max_cvss_to_date",
    "advisory_mean_cvss": "advisory_mean_cvss_to_date",
    "advisory_days_since_first": "advisory_days_since_first_to_date",
    "advisory_days_since_latest": "advisory_days_since_latest_to_date",
    "advisory_span_days": "advisory_span_days_to_date",
    "advisory_count_last_365d": "advisories_last_365d",
    "advisory_cvss_ge_7_count": "advisory_cvss_ge_7_count_to_date",
}


# ---------------------------------------------------------------------------
# window_* features
#
# During training, window_index / window_month / window_year encoded which
# calendar month a row came from.  At inference time we use today's date.
# window_index is the number of months since Jan 2020 (a stable epoch).
# ---------------------------------------------------------------------------

_WINDOW_EPOCH = date(2020, 1, 1)


# Features excluded from driver display — temporal window artifacts that
# reflect training-period position rather than plugin-level risk signals.
# They may still contribute to the model's probability estimate, but showing
# them to analysts is misleading and not actionable.
_DRIVER_EXCLUDE: frozenset[str] = frozenset({"window_index", "window_month", "window_year"})


def _window_features(today: date | None = None) -> dict[str, float]:
    d = today or datetime.now(tz=UTC).date()
    months_since_epoch = (d.year - _WINDOW_EPOCH.year) * 12 + (d.month - _WINDOW_EPOCH.month)
    return {
        "window_year": float(d.year),
        "window_month": float(d.month),
        "window_index": float(months_since_epoch),
    }


# ---------------------------------------------------------------------------
# Load a scorer from a model directory
# ---------------------------------------------------------------------------


def load_ml_scorer(model_dir: str | Path) -> MLScorer:
    """
    Load a trained pipeline and its feature contract from *model_dir*.

    Expects:
      model_dir/model.joblib          — fitted sklearn Pipeline
      model_dir/feature_columns.json  — ordered list of feature names

    Raises FileNotFoundError if either file is missing (model not yet trained).
    """
    import joblib  # pyright: ignore[reportMissingImports]  # lazy import

    model_dir = Path(model_dir)
    model_path = model_dir / "model.joblib"
    cols_path = model_dir / "feature_columns.json"

    if not model_path.exists():
        raise FileNotFoundError(
            f"No trained model found at {model_path}. Run 'canary train baseline' first."
        )
    if not cols_path.exists():
        raise FileNotFoundError(
            f"No feature column list found at {cols_path}. "
            "Re-run 'canary train baseline' to regenerate it."
        )

    pipeline = joblib.load(model_path)
    feature_columns: list[str] = json.loads(cols_path.read_text(encoding="utf-8"))

    # Read model_name from metrics.json if available — used for UI badge display
    model_name = "unknown"
    metrics_path = model_dir / "metrics.json"
    if metrics_path.exists():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            model_name = str(metrics.get("model_name") or "unknown")
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Could not read model metadata from metrics.json.", exc_info=exc)

    return MLScorer(
        pipeline=pipeline,
        feature_columns=feature_columns,
        model_dir=str(model_dir),
        model_name=model_name,
    )


# ---------------------------------------------------------------------------
# Build a feature vector for a single plugin from its collected data
# ---------------------------------------------------------------------------


def _build_feature_vector(
    plugin_id: str,
    data_raw_dir: Path,
    feature_columns: list[str],
) -> dict[str, float | None]:
    """
    Construct a feature vector for *plugin_id* using the same individual
    loaders that features_bundle.py uses, then map the column names to
    match what the model was trained on.

    Any column the model expects that we cannot populate is set to None;
    the pipeline's imputer will handle it exactly as it did during training.
    """
    from canary.build.features_bundle import (
        _load_advisory_features,
        _load_gharchive_features,
        _load_github_features,
        _load_healthscore_features,
        _load_snapshot_features,
        _load_software_heritage_features,
    )

    # --- Collect raw features from each source ---
    raw: dict[str, Any] = {}
    raw.update(_load_snapshot_features(plugin_id, data_raw_dir))
    raw.update(_load_advisory_features(plugin_id, data_raw_dir))
    raw.update(_load_healthscore_features(plugin_id, data_raw_dir))
    raw.update(_load_software_heritage_features(plugin_id, data_raw_dir, backend="athena"))
    raw.update(_load_github_features(plugin_id, data_raw_dir))
    raw.update(_load_gharchive_features(plugin_id, data_raw_dir))

    # --- Apply bundle->model column name mapping ---
    mapped: dict[str, Any] = {}
    for k, v in raw.items():
        mapped[_BUNDLE_TO_MODEL.get(k, k)] = v

    # --- Add window features (today's date) ---
    mapped.update(_window_features())

    # --- Build final vector aligned to model's feature_columns ---
    # Coerce everything to float or None; non-numeric values become None.
    vector: dict[str, float | None] = {}
    for col in feature_columns:
        val = mapped.get(col)
        if val is None:
            vector[col] = None
        elif isinstance(val, bool):
            vector[col] = float(int(val))
        else:
            try:
                vector[col] = float(val)
            except (TypeError, ValueError):
                vector[col] = None

    return vector


# ---------------------------------------------------------------------------
# Feature importance → human-readable drivers
# ---------------------------------------------------------------------------


def _unwrap_pipeline(pipeline: Any) -> tuple[Any, Any]:
    """Return (imputer_step, classifier_step) from a fitted sklearn Pipeline."""
    if hasattr(pipeline, "named_steps"):
        imputer = pipeline.named_steps.get("impute")
        model = pipeline.named_steps.get("model")
        if model is not None:
            return imputer, model
        # Fallback: second-to-last and last steps
        steps = list(pipeline.named_steps.values())
        return (steps[-2] if len(steps) >= 2 else None), steps[-1]
    return None, pipeline


def _is_tree_model(clf: Any) -> bool:
    """True for XGBoost, LightGBM, RandomForest and similar tree ensembles."""
    name = type(clf).__name__
    return any(k in name for k in ("XGB", "LGBM", "LGB", "Forest", "GBM", "Gradient", "Tree"))


def _is_linear_model(clf: Any) -> bool:
    """True for LogisticRegression and similar linear classifiers."""
    return hasattr(clf, "coef_")


def _make_drivers(
    feature_columns: list[str],
    feature_vector: Mapping[str, float | None],
    contribs: Any,
    top_n: int,
) -> list[FeatureDriver]:
    """Build a ranked FeatureDriver list from a contribution array.

    Window features (window_index, window_month, window_year) are excluded
    from the driver list — they are training-period artifacts that are not
    actionable signals for an analyst reviewing a specific plugin.
    """
    pairs = sorted(
        (
            (col, float(sv))
            for col, sv in zip(feature_columns, contribs, strict=False)
            if col not in _DRIVER_EXCLUDE
        ),
        key=lambda x: abs(x[1]),
        reverse=True,
    )[:top_n]
    drivers = []
    for rank, (name, sv_f) in enumerate(pairs, start=1):
        direction = "increases_risk" if sv_f > 0 else "decreases_risk" if sv_f < 0 else "neutral"
        drivers.append(
            FeatureDriver(
                name=name,
                value=feature_vector.get(name),
                direction=direction,
                rank=rank,
            )
        )
    return drivers


def _extract_drivers(
    pipeline: Any,
    feature_columns: list[str],
    feature_vector: Mapping[str, float | None],
    top_n: int = 10,
) -> list[FeatureDriver]:
    """
    Return the top-N features that most influenced this prediction,
    with direction (increases/decreases risk).

    Strategy by model type:
      Tree models   → SHAP TreeExplainer (accurate per-prediction explanation)
      Linear models → SHAP LinearExplainer, fallback to coef * imputed_value
      Unknown       → feature_importances_ if available, else empty list

    The fallback uses *imputed* feature values (as seen by the model) rather
    than raw None values, so coef * imputed_value reflects the model's actual
    per-feature contribution rather than zeroing out missing inputs.
    """
    import numpy as np  # pyright: ignore[reportMissingImports]
    import pandas as pd  # pyright: ignore[reportMissingModuleSource]

    raw_values = [feature_vector.get(col) for col in feature_columns]
    imputer_step, clf = _unwrap_pipeline(pipeline)

    # Impute values the same way the pipeline does so contributions are accurate
    try:
        X_raw = pd.DataFrame([raw_values], columns=feature_columns)
        X_imputed: Any = imputer_step.transform(X_raw) if imputer_step is not None else X_raw.values
    except Exception as exc:
        LOGGER.debug("Imputation failed in driver extraction; using zero-fill.", exc_info=exc)
        X_imputed = np.array([[v if v is not None else 0.0 for v in raw_values]])

    # ── SHAP path ─────────────────────────────────────────────────────────────
    try:
        import shap  # pyright: ignore[reportMissingImports]

        if _is_tree_model(clf):
            explainer = shap.TreeExplainer(clf)
            shap_out = explainer.shap_values(X_imputed)
            # Binary tree classifiers return [neg_class_array, pos_class_array]
            contrib = (shap_out[1] if isinstance(shap_out, list) else shap_out)[0]

        elif _is_linear_model(clf):
            # Use a zero background — appropriate for mean-imputed features
            background = np.zeros((1, len(feature_columns)))
            explainer = shap.LinearExplainer(clf, background, feature_perturbation="interventional")
            shap_out = explainer.shap_values(X_imputed)
            contrib = shap_out[0]

        else:
            raise ValueError(f"No SHAP explainer for model type {type(clf).__name__!r}")

        return _make_drivers(feature_columns, feature_vector, contrib, top_n)

    except Exception as exc:
        LOGGER.debug("SHAP driver extraction failed; using fallback.", exc_info=exc)

    # ── Fallback: coef * imputed_value (linear) or feature_importances (tree) ─
    imp_values: Any = X_imputed[0]
    scores: list[tuple[str, float]] = []

    if _is_linear_model(clf):
        # coef * imputed_value gives the actual per-feature log-odds contribution
        coefs = clf.coef_[0]
        for col, coef, imp_val in zip(feature_columns, coefs, imp_values, strict=False):
            contribution = float(coef) * float(imp_val if imp_val is not None else 0.0)
            if abs(contribution) > 1e-10:  # skip zero-contribution features
                scores.append((col, contribution))

    elif hasattr(clf, "feature_importances_"):
        for col, imp in zip(feature_columns, clf.feature_importances_, strict=False):
            if float(imp) > 1e-10:
                scores.append((col, float(imp)))

    scores.sort(key=lambda x: abs(x[1]), reverse=True)
    if not scores:
        return []
    top_scores = scores[:top_n]
    return _make_drivers(
        [col for col, _ in top_scores],
        feature_vector,
        [s for _, s in top_scores],
        top_n,
    )


# ---------------------------------------------------------------------------
# Main public entry point
# ---------------------------------------------------------------------------


def score_plugin_ml(
    plugin_id: str,
    *,
    scorer: MLScorer,
    data_raw_dir: str | Path = "data/raw",
    top_drivers: int = 10,
) -> MLScoreResult:
    """
    Score *plugin_id* using the trained ML model in *scorer*.

    Parameters
    ----------
    plugin_id:
        The canonical Jenkins plugin short name (e.g. "cucumber-reports").
    scorer:
        A loaded MLScorer from load_ml_scorer().
    data_raw_dir:
        Root of the collected raw data (default: data/raw).
    top_drivers:
        How many influential features to include in the result.

    Returns
    -------
    MLScoreResult with probability, risk_category, and drivers.
    """
    import pandas as pd  # pyright: ignore[reportMissingModuleSource]

    from canary.plugin_aliases import canonicalize_plugin_id
    from canary.scoring.baseline import _safe_plugin_id

    data_raw_dir = Path(data_raw_dir)

    # Canonicalize and validate the plugin id
    canonical = canonicalize_plugin_id(plugin_id.lower().strip(), data_dir=data_raw_dir)
    safe_id = _safe_plugin_id(canonical)
    if safe_id is None:
        raise ValueError(f"Invalid plugin id: {plugin_id!r}")

    # Build feature vector
    feature_vector = _build_feature_vector(safe_id, data_raw_dir, scorer.feature_columns)

    # Align to a single-row DataFrame in the exact column order the pipeline expects
    X = pd.DataFrame(
        [[feature_vector.get(col) for col in scorer.feature_columns]],
        columns=scorer.feature_columns,
    )

    # Predict
    probability = float(scorer.pipeline.predict_proba(X)[0, 1])

    # Drivers
    drivers = _extract_drivers(
        scorer.pipeline,
        scorer.feature_columns,
        feature_vector,
        top_n=top_drivers,
    )

    return MLScoreResult(
        plugin=safe_id,
        probability=round(probability, 4),
        canary_score=round(probability, 4),
        risk_category=_risk_category(probability),
        drivers=drivers,
        feature_vector=feature_vector,
        model_dir=scorer.model_dir,
        model_name=scorer.model_name,
        scored_at=datetime.now(tz=UTC).isoformat(),
    )
