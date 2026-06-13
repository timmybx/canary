from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import joblib  # pyright: ignore[reportMissingImports]
import numpy as np  # pyright: ignore[reportMissingImports]
import pandas as pd  # pyright: ignore[reportMissingModuleSource]
from sklearn.compose import ColumnTransformer  # pyright: ignore[reportMissingModuleSource]
from sklearn.impute import SimpleImputer  # pyright: ignore[reportMissingModuleSource]
from sklearn.metrics import (  # pyright: ignore[reportMissingModuleSource]
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline  # pyright: ignore[reportMissingModuleSource]

DEFAULT_EXCLUDE_COLUMNS = {
    # Identifiers / bookkeeping
    "plugin_id",
    "month",
    "month_id",
    "period",
    "yyyymm",
    # Future-label columns
    "months_until_next_advisory",
    "future_advisory_count",
    # Other labels
    "label_advisory_within_1m",
    "label_advisory_within_3m",
    "label_advisory_within_6m",
    "label_advisory_within_12m",
    # Strong target leakage / same-month direct signals
    "had_advisory_this_month",
    "has_advisory_this_month",
    "advisory_this_month",
    "advisory_count_this_month",
}


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def _load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no} of {path}") from exc
    return rows


def _parse_month_value(row: dict[str, Any]) -> str:
    for key in ("month", "month_id", "period", "yyyymm"):
        if key in row:
            value = row[key]
            if key == "yyyymm":
                s = str(value)
                if len(s) == 6:
                    return f"{s[:4]}-{s[4:]}"
            return str(value)
    raise KeyError("Missing month field (month/month_id/period/yyyymm).")


def _month_to_sortable(month_str: str) -> tuple[int, int]:
    year_s, month_s = month_str.split("-", 1)
    return int(year_s), int(month_s)


def _is_numeric_like(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    return False


def _coerce_numeric(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _select_feature_columns(
    rows: list[dict[str, Any]],
    *,
    target_col: str,
    extra_exclude: set[str] | None = None,
    include_prefixes: tuple[str, ...] | None = None,
) -> list[str]:
    exclude = set(DEFAULT_EXCLUDE_COLUMNS)
    exclude.add(target_col)
    if extra_exclude:
        exclude.update(extra_exclude)

    candidate_cols = sorted({k for row in rows for k in row.keys()} - exclude)

    if include_prefixes:
        candidate_cols = [
            col
            for col in candidate_cols
            if any(col.startswith(prefix) for prefix in include_prefixes)
        ]

    selected: list[str] = []
    for col in candidate_cols:
        values = [row.get(col) for row in rows]
        if not all(_is_numeric_like(v) for v in values):
            continue

        observed = [_coerce_numeric(v) for v in values]
        if all(v is None for v in observed):
            continue

        selected.append(col)

    return selected


def _rows_to_matrix(rows: list[dict[str, Any]], feature_cols: list[str]) -> pd.DataFrame:
    data = []
    for row in rows:
        data.append({col: _coerce_numeric(row.get(col)) for col in feature_cols})
    return pd.DataFrame(data, columns=feature_cols)  # pyright: ignore[reportArgumentType]


def _write_predictions_csv(
    *,
    path: str | Path,
    rows: list[dict[str, Any]],
    y_true: np.ndarray,
    y_prob: np.ndarray,
) -> None:
    import csv

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["plugin_id", "month", "y_true", "y_prob"]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row, truth, prob in zip(rows, y_true, y_prob, strict=False):
            writer.writerow(
                {
                    "plugin_id": row.get("plugin_id"),
                    "month": _parse_month_value(row),
                    "y_true": int(truth),
                    "y_prob": float(prob),
                }
            )


# ---------------------------------------------------------------------------
# Feature importance helpers
# ---------------------------------------------------------------------------


def _extract_feature_importance(
    model: Any,
    feature_cols: list[str],
    model_name: str,
    X_sample: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Return (top_positive, top_negative) feature importance dicts.

    For logistic regression: uses signed coefficients directly.

    For tree-based models (XGBoost, LightGBM, Random Forest): uses SHAP
    TreeExplainer to compute mean signed SHAP values over X_sample.
    - mean_shap > 0  → feature raises predicted advisory risk  (top_positive)
    - mean_shap < 0  → feature lowers predicted advisory risk  (top_negative)
    - mean_abs_shap  → unsigned magnitude used for ranking / bar width

    Falls back to unsigned feature_importances_ if SHAP is unavailable or
    X_sample is not provided (Random Forest is excluded from SHAP due to OOM).
    """
    # Unwrap a Pipeline to get to the actual classifier
    clf = model
    if hasattr(model, "named_steps"):
        last_step_name = list(model.named_steps.keys())[-1]
        clf = model.named_steps[last_step_name]

    top_positive: list[dict[str, Any]] = []
    top_negative: list[dict[str, Any]] = []

    # ── Logistic regression — signed coefficients ────────────────────────────
    if hasattr(clf, "coef_"):
        coef_pairs = sorted(
            zip(feature_cols, clf.coef_[0], strict=False),
            key=lambda x: abs(float(x[1])),
            reverse=True,
        )
        top_positive = [{"feature": f, "coefficient": float(c)} for f, c in coef_pairs if c > 0][
            :20
        ]
        top_negative = [{"feature": f, "coefficient": float(c)} for f, c in coef_pairs if c < 0][
            :20
        ]
        return top_positive, top_negative

    # ── Tree-based models ─────────────────────────────────────────────────────
    model_type = type(clf).__name__
    is_xgb_lgb = any(k in model_type for k in ("XGB", "LGBM", "LGB"))

    # Random Forest SHAP is prohibitively slow — fall through to feature_importances_
    if is_xgb_lgb and X_sample is not None:
        try:
            import shap  # pyright: ignore[reportMissingImports]

            print(f"Computing signed SHAP values for {model_type} …")
            explainer = shap.TreeExplainer(clf)
            shap_out = explainer.shap_values(X_sample)
            vals_array = np.asarray(
                shap_out[1] if isinstance(shap_out, list) else shap_out,
                dtype=float,
            )

            mean_shap = vals_array.mean(axis=0)  # signed — direction
            mean_abs_shap = np.abs(vals_array).mean(axis=0)  # magnitude — ranking

            pairs = list(
                zip(feature_cols, mean_shap.tolist(), mean_abs_shap.tolist(), strict=False)
            )

            # Sort by magnitude descending for each direction
            pos_pairs = sorted(
                [(f, ms, ma) for f, ms, ma in pairs if ms > 0],
                key=lambda x: x[2],
                reverse=True,
            )
            neg_pairs = sorted(
                [(f, ms, ma) for f, ms, ma in pairs if ms < 0],
                key=lambda x: x[2],
                reverse=True,
            )

            top_positive = [
                {"feature": f, "mean_shap": round(ms, 6), "mean_abs_shap": round(ma, 6)}
                for f, ms, ma in pos_pairs
            ][:20]
            top_negative = [
                {"feature": f, "mean_shap": round(ms, 6), "mean_abs_shap": round(ma, 6)}
                for f, ms, ma in neg_pairs
            ][:20]

            print(
                f"SHAP direction split: {len(top_positive)} risk-raising, "
                f"{len(top_negative)} risk-reducing features."
            )
            return top_positive, top_negative

        except Exception as exc:  # noqa: BLE001
            print(f"SHAP failed for {model_type} ({exc}); falling back to feature_importances_.")

    # ── Fallback: unsigned feature_importances_ ───────────────────────────────
    if hasattr(clf, "feature_importances_"):
        importance_pairs = sorted(
            zip(feature_cols, clf.feature_importances_, strict=False),
            key=lambda x: float(x[1]),
            reverse=True,
        )
        top_positive = [
            {"feature": f, "importance": float(imp)} for f, imp in importance_pairs if imp > 0
        ][:20]

    return top_positive, top_negative


def _stable_plugin_bucket(plugin_id: Any, *, seed: int) -> float:
    text = str(plugin_id or "")
    digest = hashlib.sha256(f"{seed}:{text}".encode()).hexdigest()
    return int(digest[:16], 16) / float(16**16)


def _split_rows(
    rows: list[dict[str, Any]],
    *,
    split_strategy: str,
    test_start_month: str,
    group_col: str,
    test_fraction: float,
    random_seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    if split_strategy == "time":
        train_rows = [
            row
            for row in rows
            if _month_to_sortable(_parse_month_value(row)) < _month_to_sortable(test_start_month)
        ]
        test_rows = [
            row
            for row in rows
            if _month_to_sortable(_parse_month_value(row)) >= _month_to_sortable(test_start_month)
        ]
        return train_rows, test_rows, set()

    groups = sorted({str(row.get(group_col) or "") for row in rows if row.get(group_col)})
    test_groups = {
        group for group in groups if _stable_plugin_bucket(group, seed=random_seed) < test_fraction
    }

    if split_strategy == "group":
        return (
            [r for r in rows if str(r.get(group_col) or "") not in test_groups],
            [r for r in rows if str(r.get(group_col) or "") in test_groups],
            test_groups,
        )

    if split_strategy == "group_time":
        return (
            [
                r
                for r in rows
                if str(r.get(group_col) or "") not in test_groups
                and _month_to_sortable(_parse_month_value(r)) < _month_to_sortable(test_start_month)
            ],
            [
                r
                for r in rows
                if str(r.get(group_col) or "") in test_groups
                and _month_to_sortable(_parse_month_value(r))
                >= _month_to_sortable(test_start_month)
            ],
            test_groups,
        )

    raise ValueError(f"Unknown split_strategy: {split_strategy}")


# ---------------------------------------------------------------------------
# Core training function — model-agnostic
# ---------------------------------------------------------------------------


def train_model(
    *,
    estimator: Any,
    model_name: str,
    in_path: str | Path = "data/processed/features/plugins.monthly.labeled.jsonl",
    target_col: str = "label_advisory_within_6m",
    out_dir: str | Path = "data/processed/models/baseline_6m",
    test_start_month: str = "2025-10",
    extra_exclude: set[str] | None = None,
    include_prefixes: tuple[str, ...] | None = None,
    split_strategy: str = "time",
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
) -> dict[str, Any]:
    """
    Train *estimator* on monthly plugin rows using a time-based split.

    The estimator must be sklearn-compatible (fit / predict_proba).
    Imputation of missing values is always applied before the estimator.
    For logistic regression the estimator should include a scaler step
    (as in the registry).  Tree-based models receive raw imputed features.

    Returns a metrics dict and writes metrics.json, test_predictions.csv,
    and pr_curve.json to *out_dir*.
    """
    rows = _load_jsonl(in_path)

    usable_rows = [row for row in rows if row.get(target_col) is not None]
    if not usable_rows:
        raise ValueError(f"No rows with non-null target: {target_col}")

    usable_rows = sorted(
        usable_rows,
        key=lambda r: (
            _month_to_sortable(_parse_month_value(r)),
            str(r.get("plugin_id", "")),
        ),
    )

    feature_cols = _select_feature_columns(
        usable_rows,
        target_col=target_col,
        extra_exclude=extra_exclude,
        include_prefixes=include_prefixes,
    )
    if not feature_cols:
        raise ValueError("No usable numeric feature columns found.")

    train_rows, test_rows, test_groups = _split_rows(
        usable_rows,
        split_strategy=split_strategy,
        test_start_month=test_start_month,
        group_col=group_col,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )

    if not train_rows:
        raise ValueError("No training rows found. Adjust test_start_month.")
    if not test_rows:
        raise ValueError("No test rows found. Adjust test_start_month.")

    X_train = _rows_to_matrix(train_rows, feature_cols)
    X_test = _rows_to_matrix(test_rows, feature_cols)

    y_train = np.array([int(row[target_col]) for row in train_rows], dtype=int)
    y_test = np.array([int(row[target_col]) for row in test_rows], dtype=int)

    # Imputation wraps the estimator so it never sees NaNs
    imputer = ColumnTransformer(
        transformers=[("impute", SimpleImputer(strategy="median"), feature_cols)],
        remainder="drop",
    )
    full_pipeline = Pipeline(steps=[("impute", imputer), ("model", estimator)])
    full_pipeline.fit(X_train, y_train)

    y_prob = full_pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    metrics: dict[str, Any] = {
        "model_name": model_name,
        "input_path": str(in_path),
        "target_col": target_col,
        "test_start_month": test_start_month,
        "include_prefixes": list(include_prefixes) if include_prefixes else [],
        "train_row_count": int(len(train_rows)),
        "test_row_count": int(len(test_rows)),
        "train_start_month": (
            min(_parse_month_value(r) for r in train_rows) if train_rows else None
        ),
        "train_positive_count": int(y_train.sum()),
        "test_positive_count": int(y_test.sum()),
        "train_unique_plugin_count": int(
            len({str(row.get("plugin_id") or "") for row in train_rows})
        ),
        "test_unique_plugin_count": int(
            len({str(row.get("plugin_id") or "") for row in test_rows})
        ),
        "feature_count": int(len(feature_cols)),
        "feature_columns": feature_cols,
        "roc_auc": None,
        "average_precision": None,
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(
            y_test,
            y_pred,
            output_dict=True,
            zero_division=cast(Any, 0),
        ),
        "split_strategy": split_strategy,
        "group_col": group_col,
        "test_fraction": float(test_fraction),
        "random_seed": int(random_seed),
        "test_group_count": int(len(test_groups)),
        "train_group_count": int(
            len({str(row.get(group_col) or "") for row in train_rows if row.get(group_col)})
        ),
    }

    if len(np.unique(y_test)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_test, y_prob))
        metrics["average_precision"] = float(average_precision_score(y_test, y_prob))

    top_positive, top_negative = _extract_feature_importance(
        full_pipeline.named_steps["model"],
        feature_cols,
        model_name,
        X_sample=X_test,
    )
    metrics["top_positive_features"] = top_positive
    metrics["top_negative_features"] = top_negative

    ranked = sorted(
        zip(test_rows, y_test.tolist(), y_prob.tolist(), strict=False),
        key=lambda x: x[2],
        reverse=True,
    )
    topk_summary: dict[str, Any] = {}
    for k in (10, 25, 50, 100):
        if len(ranked) >= k:
            top_k = ranked[:k]
            topk_summary[f"precision_at_{k}"] = float(sum(int(item[1]) for item in top_k) / k)
    metrics["ranking_metrics"] = topk_summary

    # --- Operational scenario analysis ----------------------------------------
    # Computes precision, recall, and lift at a range of k values so the webapp
    # can present results in plain operational terms (e.g. "if your team reviews
    # 50 plugins per cycle, CANARY identifies 46 of 77 future advisory plugins
    # with 92% precision — a 49x improvement over random selection").
    n_test = len(ranked)
    n_pos = int(y_test.sum())
    base_rate_v = n_pos / n_test if n_test > 0 else 0.0
    cum_tp = 0
    pk_rows: list[dict[str, Any]] = []
    k_values = [5, 10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200]

    for i, (_, truth, _) in enumerate(ranked, start=1):
        cum_tp += int(truth)
        if i in k_values:
            prec = cum_tp / i
            rec = cum_tp / n_pos if n_pos > 0 else 0.0
            lift = prec / base_rate_v if base_rate_v > 0 else 0.0
            pk_rows.append(
                {
                    "k": i,
                    "true_positives": cum_tp,
                    "false_positives": i - cum_tp,
                    "precision": round(prec, 4),
                    "recall": round(rec, 4),
                    "lift": round(lift, 2),
                }
            )

    # Recall-target analysis: how many plugins to review to reach X% recall
    recall_targets: list[dict[str, Any]] = []
    for target in (0.25, 0.50, 0.75, 0.90):
        target_tp = int(np.ceil(target * n_pos))
        k_needed = n_test  # fallback
        cum = 0
        for i, (_, truth, _) in enumerate(ranked, start=1):
            cum += int(truth)
            if cum >= target_tp:
                k_needed = i
                break
        prec_at = cum / k_needed if k_needed > 0 else 0.0
        recall_targets.append(
            {
                "target_recall": target,
                "plugins_to_review": k_needed,
                "pct_of_ecosystem": round(k_needed / n_test * 100, 1) if n_test > 0 else None,
                "true_positives": min(cum, n_pos),
                "precision": round(prec_at, 4),
            }
        )

    # Named operational scenarios
    scenarios = [
        ("Weekly triage \u2014 very tight capacity", 10),
        ("Monthly review \u2014 small team", 25),
        ("Quarterly review \u2014 moderate capacity", 50),
        ("Semi-annual audit \u2014 larger team", 100),
    ]
    scenario_rows: list[dict[str, Any]] = []
    for label, k in scenarios:
        if len(ranked) >= k:
            tp_k = sum(int(item[1]) for item in ranked[:k])
            prec_k = tp_k / k
            rec_k = tp_k / n_pos if n_pos > 0 else 0.0
            lift_k = prec_k / base_rate_v if base_rate_v > 0 else 0.0
            scenario_rows.append(
                {
                    "label": label,
                    "k": k,
                    "true_positives": tp_k,
                    "precision": round(prec_k, 4),
                    "recall": round(rec_k, 4),
                    "lift": round(lift_k, 2),
                }
            )

    operational: dict[str, Any] = {
        "n_test": n_test,
        "n_positive": n_pos,
        "base_rate": round(base_rate_v, 6),
        "model_name": model_name,
        "split_strategy": split_strategy,
        "test_start_month": test_start_month,
        "precision_at_k": pk_rows,
        "recall_targets": recall_targets,
        "scenarios": scenario_rows,
    }
    metrics["operational_scenarios"] = {
        "n_test": n_test,
        "n_positive": n_pos,
        "base_rate": round(base_rate_v, 6),
        "scenarios": scenario_rows,
    }

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    (out_path / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8"
    )
    _write_predictions_csv(
        path=out_path / "test_predictions.csv",
        rows=test_rows,
        y_true=y_test,
        y_prob=y_prob,
    )

    precision_arr, recall_arr, thresholds_arr = precision_recall_curve(y_test, y_prob)
    (out_path / "pr_curve.json").write_text(
        json.dumps(
            {
                "precision": precision_arr.tolist(),
                "recall": recall_arr.tolist(),
                "thresholds": thresholds_arr.tolist(),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    # --- Save the fitted pipeline so it can be loaded for inference ---
    # The pipeline includes the imputer + model, and is sklearn-compatible.
    # feature_columns.json records the exact column order the pipeline expects,
    # which is required to construct a matching feature vector at inference time.
    joblib.dump(full_pipeline, out_path / "model.joblib")
    (out_path / "feature_columns.json").write_text(
        json.dumps(feature_cols, indent=2), encoding="utf-8"
    )

    # --- Operational precision@k analysis ------------------------------------
    (out_path / "precision_at_k.json").write_text(
        json.dumps(operational, indent=2, sort_keys=True), encoding="utf-8"
    )

    return metrics


# ---------------------------------------------------------------------------
# Backwards-compatible wrapper
# ---------------------------------------------------------------------------


def train_baseline(
    *,
    in_path: str | Path = "data/processed/features/plugins.monthly.labeled.jsonl",
    target_col: str = "label_advisory_within_6m",
    out_dir: str | Path = "data/processed/models/baseline_6m",
    test_start_month: str = "2025-10",
    extra_exclude: set[str] | None = None,
    include_prefixes: tuple[str, ...] | None = None,
    model_name: str = "logistic",
    split_strategy: str = "time",
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
) -> dict[str, Any]:
    """
    Train a model by name using the CANARY model registry.

    Defaults to logistic regression for backwards compatibility.
    """
    from canary.train.registry import get_model

    estimator = get_model(model_name)
    return train_model(
        estimator=estimator,
        model_name=model_name,
        in_path=in_path,
        target_col=target_col,
        out_dir=out_dir,
        test_start_month=test_start_month,
        extra_exclude=extra_exclude,
        include_prefixes=include_prefixes,
        split_strategy=split_strategy,
        group_col=group_col,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
