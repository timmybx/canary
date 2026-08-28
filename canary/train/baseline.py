from __future__ import annotations

import hashlib
import json
import re
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

from canary.build.monthly_labels import _row_has_advisory_this_month

# Temporal window features encode the calendar position of an observation,
# not plugin behavior. They are excluded from training by default: rolling
# six-month label windows overlap the train/test boundary, so the labels of
# the final training months share advisory events with the test window, and
# calendar position lets tree models specialize to exactly those months
# (label-maturity optimism; ~+0.21 pooled AP on the advisory+SWH headline
# configuration with no change to within-month P@10, praxis Section 4.4.3).
# Pass include_window_features=True (CLI: --include-window-features) to
# reproduce the historical window-bearing configurations.
WINDOW_FEATURE_COLUMNS = {"window_index", "window_month", "window_year"}

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


def _validate_month(month_str: str, *, name: str) -> tuple[int, int]:
    """Parse a ``YYYY-MM`` string, raising a clear ValueError if malformed."""
    try:
        year, month = _month_to_sortable(str(month_str))
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be YYYY-MM, got {month_str!r}") from exc
    if not (1 <= month <= 12) or year < 1900:
        raise ValueError(f"{name} must be YYYY-MM, got {month_str!r}")
    return year, month


def _add_months(key: tuple[int, int], n: int) -> tuple[int, int]:
    """Return the (year, month) tuple *n* calendar months after *key*."""
    year, month = key
    total = year * 12 + (month - 1) + n
    return total // 12, total % 12 + 1


_HORIZON_PATTERN = re.compile(r"within_(\d+)m$")


def horizon_months_from_target(target_col: str) -> int | None:
    """
    Infer the label horizon (in months) from a target column name such as
    ``label_advisory_within_6m``. Returns None if the name carries no horizon.
    """
    match = _HORIZON_PATTERN.search(target_col)
    return int(match.group(1)) if match else None


def deployment_as_of_month(test_start_month: str) -> str:
    """
    The deployment-realistic label as-of month for a test window starting at
    *test_start_month*: the month after it. Observation month T is scored on
    the first day of T+1, when advisories published through T are known and
    T's own label window (T+1 .. T+H) has not yet begun.
    """
    year, month = _add_months(_validate_month(test_start_month, name="test_start_month"), 1)
    return f"{year:04d}-{month:02d}"


# ---------------------------------------------------------------------------
# Label embargo ("as-of" relabeling)
# ---------------------------------------------------------------------------
#
# The stored label for plugin P in observation month M is 1 if an advisory for
# P was published in any of months M+1 .. M+H. Building that label uses the
# full advisory feed, so the last H-1 training months "know" about advisories
# published inside the test window. A model trained on those labels can learn
# entity-level label overlap (the same plugin is positive in adjacent training
# and test months) and report performance no deployment could reproduce.
#
# relabel_as_of() rebuilds each training row's label using only advisories
# published strictly before the as-of month — exactly the label a model
# trained on that date could have used. Windows that had already fully
# matured before the as-of month reproduce their stored label bit-for-bit;
# only rows whose windows overlap the unseen future can change (1 -> 0).
# See tools/README.md ("embargo_backtest.py") for the motivating results.


def relabel_as_of(
    all_rows: list[dict[str, Any]],
    train_rows: list[dict[str, Any]],
    *,
    target_col: str,
    as_of_month: str,
    horizon_months: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Return copies of *train_rows* with *target_col* rebuilt as knowable at
    *as_of_month*, plus relabeling statistics.

    Label = 1 if any of the observation's next *horizon_months* calendar months
    both (a) contains an advisory and (b) is strictly before *as_of_month*;
    else 0. A window that has not finished maturing counts as "not positive
    so far", as it would in deployment.

    *all_rows* must contain every row of the dataset (including rows whose
    stored label is null) so each plugin's advisory months are complete. The
    horizon defaults to the number encoded in *target_col*
    (``..._within_6m`` -> 6) and must be given explicitly otherwise.

    Raises ValueError if any fully matured window disagrees with its stored
    label — that means the dataset's label semantics differ from the
    positional next-H-months definition this function mirrors.
    """
    as_of_key = _validate_month(as_of_month, name="as_of_month")
    if horizon_months is None:
        horizon_months = horizon_months_from_target(target_col)
    if horizon_months is None or horizon_months < 1:
        raise ValueError(
            f"Cannot infer label horizon from target_col {target_col!r}; "
            "pass horizon_months explicitly."
        )

    advisory_months: dict[str, set[tuple[int, int]]] = {}
    for row in all_rows:
        if _row_has_advisory_this_month(row):
            pid = str(row.get("plugin_id") or "")
            advisory_months.setdefault(pid, set()).add(_month_to_sortable(_parse_month_value(row)))

    stats = {
        "train_rows": len(train_rows),
        "positives_stored": 0,
        "positives_as_of": 0,
        "flipped_1_to_0": 0,
        "matured_mismatch": 0,
    }
    relabeled: list[dict[str, Any]] = []
    for row in train_rows:
        pid = str(row.get("plugin_id") or "")
        month_key = _month_to_sortable(_parse_month_value(row))
        window = [_add_months(month_key, i) for i in range(1, horizon_months + 1)]
        knowable = [m for m in window if m < as_of_key]
        plugin_advisories = advisory_months.get(pid, set())
        label = int(any(m in plugin_advisories for m in knowable))

        stored = row.get(target_col)
        stored_int = int(stored) if stored is not None else None
        if stored_int == 1:
            stats["positives_stored"] += 1
        if label == 1:
            stats["positives_as_of"] += 1
        if stored_int == 1 and label == 0:
            stats["flipped_1_to_0"] += 1
        if len(knowable) == horizon_months and stored_int is not None and stored_int != label:
            stats["matured_mismatch"] += 1

        new_row = dict(row)
        new_row[target_col] = label
        relabeled.append(new_row)

    if stats["matured_mismatch"]:
        raise ValueError(
            f"{stats['matured_mismatch']} fully matured training windows disagree with "
            f"their stored {target_col!r} labels under as-of relabeling. The dataset's "
            f"labels do not follow the positional next-{horizon_months}-months definition "
            "(check --target-col / the monthly grid is dense)."
        )
    return relabeled, stats


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
    include_window_features: bool = False,
) -> list[str]:
    exclude = set(DEFAULT_EXCLUDE_COLUMNS)
    exclude.add(target_col)
    if not include_window_features:
        exclude.update(WINDOW_FEATURE_COLUMNS)
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
    return pd.DataFrame(  # pyright: ignore[reportArgumentType]
        data,
        columns=feature_cols,
        dtype=float,
    )


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
    test_end_month: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    if test_end_month is not None:
        end_key = _validate_month(test_end_month, name="test_end_month")
        if end_key < _month_to_sortable(test_start_month):
            raise ValueError(
                f"test_end_month {test_end_month!r} precedes test_start_month {test_start_month!r}."
            )
        # Rows after the test window are dropped entirely: they can never be
        # training rows (those precede test_start_month) and they are not in
        # the evaluated window. This is what makes a rolling-origin backtest
        # score each fold on a fixed-width window rather than "everything
        # after the cutoff".
        rows = [row for row in rows if _month_to_sortable(_parse_month_value(row)) <= end_key]

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
    include_window_features: bool = False,
    split_strategy: str = "time",
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
    test_end_month: str | None = None,
    label_as_of_month: str | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Train *estimator* on monthly plugin rows using a time-based split.

    Temporal window features (``WINDOW_FEATURE_COLUMNS``) are excluded from
    the feature matrix unless *include_window_features* is True.

    *test_end_month* (inclusive, ``YYYY-MM``) bounds the evaluated window;
    rows after it are dropped. Leave None to test on every month at or after
    *test_start_month* (historical behavior).

    *label_as_of_month* (``YYYY-MM``) applies the label embargo: training
    labels are rebuilt using only advisories published strictly before that
    month (see :func:`relabel_as_of`). For deployment-realistic evaluation
    pass the test start month. Leave None to train on the stored labels
    (historical behavior). Test labels are never modified.

    *rows* lets a caller that trains many models on one dataset (rolling
    backtests, feature selection) pass pre-loaded rows instead of re-reading
    *in_path*; the rows are not mutated.

    The estimator must be sklearn-compatible (fit / predict_proba).
    Imputation of missing values is always applied before the estimator.
    For logistic regression the estimator should include a scaler step
    (as in the registry).  Tree-based models receive raw imputed features.

    Returns a metrics dict and writes metrics.json, test_predictions.csv,
    and pr_curve.json to *out_dir*.
    """
    test_start_key = _validate_month(test_start_month, name="test_start_month")
    if label_as_of_month is not None:
        as_of_key = _validate_month(label_as_of_month, name="label_as_of_month")
        # Observation month T is scored on the first day of T+1 (its features
        # are complete at month end), and its label window starts at T+1. So
        # advisories published through month T are legitimately known on the
        # prediction date and never enter any test label; the latest honest
        # as-of month is therefore test_start_month + 1 (advisories strictly
        # before it). Anything later lets training labels see advisories that
        # fall inside a test label window.
        if split_strategy in ("time", "group_time") and as_of_key > _add_months(test_start_key, 1):
            raise ValueError(
                f"label_as_of_month {label_as_of_month!r} is more than one month after "
                f"test_start_month {test_start_month!r}: training labels would use "
                "advisories published inside the test label window. Use "
                f"{deployment_as_of_month(test_start_month)} (deployment-realistic) or earlier."
            )

    if rows is None:
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
        include_window_features=include_window_features,
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
        test_end_month=test_end_month,
    )

    if not train_rows:
        raise ValueError("No training rows found. Adjust test_start_month.")
    if not test_rows:
        raise ValueError("No test rows found. Adjust test_start_month / test_end_month.")

    # Label embargo: rebuild training labels as they were knowable on the
    # as-of date. Applied after the split so test labels stay untouched, and
    # computed from *rows* (not usable_rows) so every plugin's advisory months
    # are complete even where the stored label is null.
    label_as_of_stats: dict[str, int] | None = None
    if label_as_of_month is not None:
        train_rows, label_as_of_stats = relabel_as_of(
            rows,
            train_rows,
            target_col=target_col,
            as_of_month=label_as_of_month,
        )

    # Advisory-family features derive from the Jenkins security advisory feed,
    # which is complete by construction: a missing value means the plugin has
    # no advisory history, not that the data went unobserved. Zero-filling
    # encodes that ("no severity / count / recency to date"). The previous
    # global median imputation placed no-history plugins in the middle of the
    # observed severity range, entangling them with genuine mid-severity
    # history (praxis Section 4.4.6). All other families keep median
    # imputation, where missingness reflects incomplete public coverage.
    # NOTE: feature_cols is reordered so that the saved feature_columns.json
    # matches the ColumnTransformer's output order (advisory block first).
    advisory_cols = [c for c in feature_cols if c.startswith(("advisory_", "advisories_"))]
    other_cols = [c for c in feature_cols if not c.startswith(("advisory_", "advisories_"))]
    feature_cols = advisory_cols + other_cols

    X_train = _rows_to_matrix(train_rows, feature_cols)
    X_test = _rows_to_matrix(test_rows, feature_cols)

    y_train = np.array([int(row[target_col]) for row in train_rows], dtype=int)
    y_test = np.array([int(row[target_col]) for row in test_rows], dtype=int)

    # Imputation wraps the estimator so it never sees NaNs
    impute_transformers = []
    if advisory_cols:
        impute_transformers.append(
            (
                "impute_advisory_zero",
                SimpleImputer(strategy="constant", fill_value=0.0),
                advisory_cols,
            )
        )
    if other_cols:
        impute_transformers.append(("impute_median", SimpleImputer(strategy="median"), other_cols))
    imputer = ColumnTransformer(transformers=impute_transformers, remainder="drop")
    full_pipeline = Pipeline(steps=[("impute", imputer), ("model", estimator)])
    full_pipeline.fit(X_train, y_train)

    y_prob = full_pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    metrics: dict[str, Any] = {
        "model_name": model_name,
        "input_path": str(in_path),
        "target_col": target_col,
        "test_start_month": test_start_month,
        "test_end_month": test_end_month,
        "label_as_of_month": label_as_of_month,
        "label_horizon_months": horizon_months_from_target(target_col),
        "label_as_of_stats": label_as_of_stats,
        "include_prefixes": list(include_prefixes) if include_prefixes else [],
        "include_window_features": include_window_features,
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
    include_window_features: bool = False,
    model_name: str = "logistic",
    split_strategy: str = "time",
    group_col: str = "plugin_id",
    test_fraction: float = 0.2,
    random_seed: int = 42,
    test_end_month: str | None = None,
    label_as_of_month: str | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Train a model by name using the CANARY model registry.

    Defaults to logistic regression for backwards compatibility.
    See :func:`train_model` for *test_end_month*, *label_as_of_month*, *rows*.
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
        include_window_features=include_window_features,
        split_strategy=split_strategy,
        group_col=group_col,
        test_fraction=test_fraction,
        random_seed=random_seed,
        test_end_month=test_end_month,
        label_as_of_month=label_as_of_month,
        rows=rows,
    )
