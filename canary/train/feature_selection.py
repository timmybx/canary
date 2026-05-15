"""
Principled feature selection for CANARY using SHAP global importance ranking.

This module answers H3 directly:
  "A compact top-10-feature model retains at least 90% of full-model
   precision-recall area on future data."

Workflow
--------
1.  Load a previously trained model (model.joblib + feature_columns.json).
2.  Compute SHAP values across the test set to produce a global feature
    ranking (mean |SHAP| per feature, descending).
3.  Iteratively retrain the *same model family* on progressively smaller
    feature subsets: top-5, top-10, top-15, top-20, top-30, top-50, full.
4.  Record average precision at each subset size.
5.  Write feature_selection.json to the model directory.

The output is a JSON file that the webapp can render as a curve and that
Chapter 4 can cite as a direct empirical test of H3.

Temporal window features (window_index, window_month, window_year) are
excluded from the ranking because they reflect training-period position
rather than generalizable plugin-level risk signals.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, cast

import joblib  # pyright: ignore[reportMissingImports]
import numpy as np  # pyright: ignore[reportMissingImports]

from canary.train.baseline import (
    _load_jsonl,
    _month_to_sortable,
    _parse_month_value,
    _rows_to_matrix,
    _select_feature_columns,
    _split_rows,
    train_model,
)

LOGGER = logging.getLogger(__name__)

# Features excluded from the ranking — they encode calendar position rather
# than plugin-level risk characteristics and do not generalise across plugins.
_WINDOW_FEATURES: frozenset[str] = frozenset({"window_index", "window_month", "window_year"})

# Subset sizes to evaluate.  Always includes the full feature set as the
# baseline reference point.
DEFAULT_SUBSET_SIZES: tuple[int, ...] = (5, 10, 15, 20, 30, 50)


# ---------------------------------------------------------------------------
# SHAP global importance
# ---------------------------------------------------------------------------


def compute_shap_global_importance(
    pipeline: Any,
    X_test: Any,
    feature_cols: list[str],
) -> list[dict[str, Any]]:
    """
    Return features ranked by mean absolute SHAP value (descending).

    Window features are excluded from the returned ranking.
    Falls back to built-in feature_importances_ / coef_ if SHAP is not
    available or fails — so the study can still run without SHAP installed,
    albeit with a less accurate ranking.

    Parameters
    ----------
    pipeline:
        Fitted sklearn Pipeline (imputer + model).
    X_test:
        pandas DataFrame of test features (pre-imputation).
    feature_cols:
        Ordered list of feature names matching X_test columns.

    Returns
    -------
    List of dicts ordered by importance descending:
        [{"feature": str, "mean_abs_shap": float, "rank": int}, ...]
    """

    imputer_step = pipeline.named_steps.get("impute")
    model_step = pipeline.named_steps.get("model")
    if model_step is None:
        steps = list(pipeline.named_steps.values())
        model_step = steps[-1]

    # Impute so the explainer sees what the model actually saw
    if imputer_step is not None:
        X_imp = imputer_step.transform(X_test)
    else:
        X_imp = X_test.values

    # --- SHAP path -----------------------------------------------------------
    try:
        import shap  # pyright: ignore[reportMissingImports]

        clf = model_step
        # Unwrap inner pipeline (e.g. logistic has scaler inside)
        if hasattr(clf, "named_steps"):
            inner_steps = list(clf.named_steps.values())
            # Apply any scaler steps
            for step in inner_steps[:-1]:
                if hasattr(step, "transform"):
                    X_imp = step.transform(X_imp)
            clf = inner_steps[-1]

        model_type = type(clf).__name__
        is_tree = any(k in model_type for k in ("XGB", "LGBM", "LGB", "Forest", "GBM"))
        is_linear = hasattr(clf, "coef_")

        if is_tree:
            explainer = shap.TreeExplainer(clf)
            shap_out = explainer.shap_values(X_imp)
            vals = shap_out[1] if isinstance(shap_out, list) else shap_out
        elif is_linear:
            background = np.zeros((1, X_imp.shape[1]))
            explainer = shap.LinearExplainer(clf, background, feature_perturbation="interventional")
            shap_out = explainer.shap_values(X_imp)
            vals = shap_out
        else:
            raise ValueError(f"No SHAP explainer for {model_type}")

        if vals is None:
            raise ValueError("SHAP explainer returned no values.")
        vals_array = np.asarray(cast(Any, vals), dtype=float)
        mean_abs = np.abs(vals_array).mean(axis=0)
        LOGGER.info("SHAP global importance computed over %d test rows.", len(X_imp))

    except Exception as exc:  # noqa: BLE001
        LOGGER.warning(
            "SHAP unavailable or failed (%s); falling back to built-in importance.",
            exc,
        )
        # --- Fallback --------------------------------------------------------
        clf = model_step
        if hasattr(clf, "named_steps"):
            clf = list(clf.named_steps.values())[-1]

        if hasattr(clf, "feature_importances_"):
            mean_abs = np.array(clf.feature_importances_)
        elif hasattr(clf, "coef_"):
            mean_abs = np.abs(clf.coef_[0])
        else:
            # Last resort: uniform importance
            mean_abs = np.ones(len(feature_cols))

    # Build ranked list, excluding window features
    pairs = [
        (col, float(score))
        for col, score in zip(feature_cols, mean_abs, strict=False)
        if col not in _WINDOW_FEATURES
    ]
    pairs.sort(key=lambda x: x[1], reverse=True)

    return [
        {"feature": col, "mean_abs_shap": score, "rank": rank}
        for rank, (col, score) in enumerate(pairs, start=1)
    ]


# ---------------------------------------------------------------------------
# Feature selection study
# ---------------------------------------------------------------------------


def run_feature_selection(
    *,
    model_dir: str | Path,
    in_path: str | Path = "data/processed/features/plugins.monthly.labeled.jsonl",
    target_col: str = "label_advisory_within_6m",
    test_start_month: str = "2025-10",
    split_strategy: str = "time",
    subset_sizes: tuple[int, ...] = DEFAULT_SUBSET_SIZES,
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
) -> dict[str, Any]:
    """
    Run the principled feature selection study for a trained CANARY model.

    Loads the trained model from *model_dir*, computes SHAP global feature
    importance, then retrains on progressively smaller top-N feature subsets
    and records average precision at each size.  Results are written to
    *model_dir*/feature_selection.json.

    Parameters
    ----------
    model_dir:
        Directory containing model.joblib, feature_columns.json, metrics.json.
    in_path:
        Path to the labeled monthly JSONL dataset.
    target_col:
        Target label column (must match the original training run).
    test_start_month:
        Same test cutoff used in the original training run.
    split_strategy:
        Same split strategy used in the original training run.
    subset_sizes:
        Tuple of top-N sizes to evaluate (e.g. (5, 10, 15, 20, 30, 50)).
        The full feature set is always added automatically.
    group_col, test_fraction, random_seed:
        Match to the original training run.

    Returns
    -------
    The feature_selection results dict (also written to disk).
    """
    from sklearn.base import clone  # pyright: ignore[reportMissingModuleSource]

    model_dir = Path(model_dir)

    # --- Load the existing trained pipeline ----------------------------------
    model_path = model_dir / "model.joblib"
    cols_path = model_dir / "feature_columns.json"
    metrics_path = model_dir / "metrics.json"

    if not model_path.exists():
        raise FileNotFoundError(
            f"No trained model found at {model_path}.  Run 'canary train baseline' first."
        )

    pipeline = joblib.load(model_path)
    full_feature_cols: list[str] = json.loads(cols_path.read_text(encoding="utf-8"))

    # Read model name and original metrics for reference
    model_name = "unknown"
    full_ap: float | None = None
    if metrics_path.exists():
        orig_metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        model_name = str(orig_metrics.get("model_name") or "unknown")
        full_ap = orig_metrics.get("average_precision")

    LOGGER.info(
        "Loaded model '%s' with %d features from %s",
        model_name,
        len(full_feature_cols),
        model_dir,
    )

    # --- Load dataset and produce train/test split ---------------------------
    rows = _load_jsonl(in_path)
    usable_rows = sorted(
        [r for r in rows if r.get(target_col) is not None],
        key=lambda r: (
            _month_to_sortable(_parse_month_value(r)),
            str(r.get("plugin_id", "")),
        ),
    )

    train_rows, test_rows, _ = _split_rows(
        usable_rows,
        split_strategy=split_strategy,
        test_start_month=test_start_month,
        group_col=group_col,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )

    X_test_full = _rows_to_matrix(test_rows, full_feature_cols)

    # --- Compute SHAP global importance ranking --------------------------------
    LOGGER.info("Computing SHAP global importance ranking …")
    ranked_features = compute_shap_global_importance(pipeline, X_test_full, full_feature_cols)
    ranked_col_names = [item["feature"] for item in ranked_features]

    LOGGER.info("Top 10 features by importance:")
    for item in ranked_features[:10]:
        LOGGER.info("  %3d. %-55s %.6f", item["rank"], item["feature"], item["mean_abs_shap"])

    # --- Extract the estimator to clone for retraining -----------------------
    # We need the raw estimator (not the fitted pipeline) to retrain from scratch
    from sklearn.base import BaseEstimator  # pyright: ignore[reportMissingModuleSource]

    from canary.train.registry import get_model  # noqa: PLC0415

    try:
        estimator = cast(BaseEstimator, clone(cast(BaseEstimator, get_model(model_name))))
    except Exception:  # noqa: BLE001
        # If model_name isn't in the registry (e.g. from an older run),
        # extract and clone the fitted model step directly
        model_step = pipeline.named_steps.get("model")
        if model_step is None:
            model_step = list(pipeline.named_steps.values())[-1]
        estimator = cast(BaseEstimator, clone(cast(BaseEstimator, model_step)))
        LOGGER.warning("Could not look up '%s' in registry; cloned fitted estimator.", model_name)

    # --- Evaluate each subset size -------------------------------------------
    # Include the full feature count as the reference baseline
    all_sizes = sorted(set(list(subset_sizes) + [len(ranked_col_names)]))
    # Cap sizes at the actual number of ranked features
    all_sizes = [s for s in all_sizes if s <= len(ranked_col_names)]

    subset_results: list[dict[str, Any]] = []

    for size in all_sizes:
        subset_cols = ranked_col_names[:size]
        is_full = size == len(ranked_col_names)
        label = "full" if is_full else f"top_{size}"

        LOGGER.info(
            "Training %s model on %d features (subset: %s) …",
            model_name,
            size,
            label,
        )

        try:
            subset_metrics = train_model(
                estimator=clone(estimator),
                model_name=model_name,
                in_path=in_path,
                target_col=target_col,
                out_dir=model_dir / f"feature_selection_{label}",
                test_start_month=test_start_month,
                extra_exclude=None,
                # Restrict to only the top-N columns by passing them explicitly
                # We achieve this by setting include_prefixes=None and letting
                # the column list be pre-filtered via a custom exclude set
                split_strategy=split_strategy,
                group_col=group_col,
                test_fraction=test_fraction,
                random_seed=random_seed,
            )
            # Note: train_model uses _select_feature_columns which may pick up
            # extra columns.  We need to force the exact subset.  Use the
            # exclude mechanism: exclude everything NOT in subset_cols.
            # Re-run with forced column set via extra_exclude:
            all_available_cols = set(_select_feature_columns(usable_rows, target_col=target_col))
            cols_to_exclude = all_available_cols - set(subset_cols)
            subset_metrics = train_model(
                estimator=clone(estimator),
                model_name=model_name,
                in_path=in_path,
                target_col=target_col,
                out_dir=model_dir / f"feature_selection_{label}",
                test_start_month=test_start_month,
                extra_exclude=cols_to_exclude,
                split_strategy=split_strategy,
                group_col=group_col,
                test_fraction=test_fraction,
                random_seed=random_seed,
            )

            ap = subset_metrics.get("average_precision")
            roc = subset_metrics.get("roc_auc")
            actual_features = subset_metrics.get("feature_count", size)

            # Compute retention relative to the full model AP
            retention: float | None = None
            ref_ap = full_ap if not is_full else ap
            if ref_ap and ap is not None and ref_ap > 0:
                retention = round(ap / ref_ap, 4) if not is_full else 1.0

            result = {
                "subset_label": label,
                "requested_size": size,
                "actual_feature_count": actual_features,
                "average_precision": round(ap, 4) if ap is not None else None,
                "roc_auc": round(roc, 4) if roc is not None else None,
                "ap_retention_vs_full": retention,
                "meets_h3_threshold": (ap is not None and ap >= (full_ap or 0) * 0.90)
                if not is_full
                else None,
                "features_used": subset_cols,
            }
            subset_results.append(result)

            status = ""
            if not is_full and ap is not None and full_ap is not None:
                pct = 100 * ap / full_ap if full_ap > 0 else 0
                h3_flag = "✓ H3" if ap >= full_ap * 0.90 else "  —"
                status = f"  AP={ap:.4f}  ({pct:.1f}% of full)  {h3_flag}"
            else:
                status = f"  AP={ap:.4f}  (full model baseline)"
            LOGGER.info("  %s: %d features%s", label, actual_features, status)

        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Subset '%s' failed: %s", label, exc)
            subset_results.append(
                {
                    "subset_label": label,
                    "requested_size": size,
                    "actual_feature_count": None,
                    "average_precision": None,
                    "roc_auc": None,
                    "ap_retention_vs_full": None,
                    "meets_h3_threshold": None,
                    "features_used": subset_cols,
                    "error": str(exc),
                }
            )

    # --- Find the smallest subset that meets H3 (>=90% of full AP) -----------
    h3_result: dict[str, Any] | None = None
    for res in subset_results:
        if res.get("meets_h3_threshold") is True:
            h3_result = res
            break  # results are ordered by size ascending — take the smallest

    # --- Build and write output -----------------------------------------------
    output: dict[str, Any] = {
        "model_dir": str(model_dir),
        "model_name": model_name,
        "full_model_feature_count": len(full_feature_cols),
        "full_model_average_precision": full_ap,
        "target_col": target_col,
        "split_strategy": split_strategy,
        "test_start_month": test_start_month,
        "h3_threshold": 0.90,
        "h3_satisfied": h3_result is not None,
        "h3_smallest_qualifying_subset": (
            {
                "size": h3_result["actual_feature_count"],
                "average_precision": h3_result["average_precision"],
                "ap_retention": h3_result["ap_retention_vs_full"],
                "label": h3_result["subset_label"],
            }
            if h3_result
            else None
        ),
        "feature_ranking": ranked_features,
        "subset_results": subset_results,
    }

    out_path = model_dir / "feature_selection.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    LOGGER.info("Feature selection results written to %s", out_path)

    return output
