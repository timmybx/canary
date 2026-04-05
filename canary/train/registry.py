"""
Model registry for CANARY training experiments.

Each entry is a named sklearn-compatible estimator (or Pipeline).
Pass the name via --model on the CLI:

    canary train baseline --model xgboost ...

Tree-based models (random_forest, xgboost, lightgbm) do NOT include a
StandardScaler step because they are scale-invariant.  The preprocessing
pipeline in train_model() handles imputation for all models.

xgboost and lightgbm are optional dependencies.  If the package is not
installed the registry entry is set to None and the CLI will report a
clear error rather than an ImportError.
"""

from __future__ import annotations

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Logistic regression  (scale-sensitive — scaler included in pipeline)
# ---------------------------------------------------------------------------

_logistic = Pipeline(
    steps=[
        ("scaler", StandardScaler()),
        (
            "clf",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
                solver="lbfgs",
            ),
        ),
    ]
)

# ---------------------------------------------------------------------------
# Random Forest  (scale-invariant)
# ---------------------------------------------------------------------------

_random_forest = RandomForestClassifier(
    n_estimators=500,
    class_weight="balanced",
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1,
)

# ---------------------------------------------------------------------------
# XGBoost  (optional — scale-invariant)
# scale_pos_weight ≈ neg/pos ratio; 18 is appropriate for ~4–6% base rate.
# Tune per-run with --scale-pos-weight if your base rate differs.
# ---------------------------------------------------------------------------

_xgboost = None
try:
    from xgboost import XGBClassifier  # pyright: ignore[reportMissingImports]

    _xgboost = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=18,
        eval_metric="aucpr",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
except ImportError:
    pass

# ---------------------------------------------------------------------------
# LightGBM  (optional — scale-invariant)
# ---------------------------------------------------------------------------

_lightgbm = None
try:
    from lightgbm import LGBMClassifier  # pyright: ignore[reportMissingImports]

    _lightgbm = LGBMClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.05,
        class_weight="balanced",
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
    )
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

MODEL_REGISTRY: dict[str, object] = {
    "logistic": _logistic,
    "random_forest": _random_forest,
    "xgboost": _xgboost,
    "lightgbm": _lightgbm,
}

AVAILABLE_MODELS: list[str] = [
    name for name, estimator in MODEL_REGISTRY.items() if estimator is not None
]


def get_model(name: str) -> object:
    """Return the estimator for *name*, raising ValueError if unknown or not installed."""
    if name not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model '{name}'. Available: {AVAILABLE_MODELS}")
    estimator = MODEL_REGISTRY[name]
    if estimator is None:
        raise ValueError(
            f"Model '{name}' is not installed.  "
            f"Install the optional dependency and rebuild.  "
            f"Currently available: {AVAILABLE_MODELS}"
        )
    return estimator
