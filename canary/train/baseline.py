from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

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
    return pd.DataFrame(data, columns=feature_cols)


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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Return (top_positive, top_negative) feature importance dicts.

    For logistic regression: uses signed coefficients.
    For tree-based models: uses feature_importances_ (unsigned),
    reported under top_positive only.
    """
    # Unwrap a Pipeline to get to the actual classifier
    clf = model
    if hasattr(model, "named_steps"):
        last_step_name = list(model.named_steps.keys())[-1]
        clf = model.named_steps[last_step_name]

    top_positive: list[dict[str, Any]] = []
    top_negative: list[dict[str, Any]] = []

    # Logistic regression — signed coefficients
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

    # Tree-based — unsigned feature importances
    elif hasattr(clf, "feature_importances_"):
        importance_pairs = sorted(
            zip(feature_cols, clf.feature_importances_, strict=False),
            key=lambda x: float(x[1]),
            reverse=True,
        )
        top_positive = [
            {"feature": f, "importance": float(imp)} for f, imp in importance_pairs if imp > 0
        ][:20]

    return top_positive, top_negative


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

    train_rows = [
        row
        for row in usable_rows
        if _month_to_sortable(_parse_month_value(row)) < _month_to_sortable(test_start_month)
    ]
    test_rows = [
        row
        for row in usable_rows
        if _month_to_sortable(_parse_month_value(row)) >= _month_to_sortable(test_start_month)
    ]

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
        "train_positive_count": int(y_train.sum()),
        "test_positive_count": int(y_test.sum()),
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
    }

    if len(np.unique(y_test)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_test, y_prob))
        metrics["average_precision"] = float(average_precision_score(y_test, y_prob))

    top_positive, top_negative = _extract_feature_importance(
        full_pipeline.named_steps["model"],
        feature_cols,
        model_name,
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
    )
