"""
crossval/pypi/04_dedup_precision.py
====================================
Package-level deduplicated precision-at-k robustness check.

The main evaluation in 03_train.py ranks *package-month* observations, so a
single high-risk package can occupy several of the top-k positions (one row
per test month). This script re-computes precision-at-k after deduplicating
the ranking to one row per package (each package's highest-scored test row),
so that P@k reads as "of the k distinct packages ranked riskiest, what
fraction received an advisory in the 6-month window following the selected
observation month."

Training configuration (features, split, imputation, class weighting,
hyperparameters, random seed) is identical to 03_train.py.

Usage
-----
    python crossval/pypi/04_dedup_precision.py

Input
-----
    data/pypi/processed/monthly_labeled.jsonl

Output
------
    data/pypi/processed/results/dedup_precision.json
    Console: row-level vs package-deduplicated P@k per model
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

_XGBClassifier: Any = None
try:
    from xgboost import (  # pyright: ignore[reportMissingImports]
        XGBClassifier as _ImportedXGBClassifier,
    )

    _XGBClassifier = _ImportedXGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[WARN] xgboost not installed — skipping XGBoost model")

_LGBMClassifier: Any = None
try:
    from lightgbm import (  # pyright: ignore[reportMissingImports]
        LGBMClassifier as _ImportedLGBMClassifier,
    )

    _LGBMClassifier = _ImportedLGBMClassifier
    HAS_LGB = True
except ImportError:
    HAS_LGB = False
    print("[WARN] lightgbm not installed — skipping LightGBM model")

IN_PATH = Path("data/pypi/processed/monthly_labeled.jsonl")
OUT_PATH = Path("data/pypi/processed/results/dedup_precision.json")
TEST_START = "2025-05"
TARGET_COL = "label_advisory_within_6m"
FEATURE_COLS = [
    "advisory_count_to_date",
    "advisory_cve_count_to_date",
    "advisory_max_cvss_to_date",
]
RANDOM_SEED = 42
K_VALUES = (10, 25, 50)
type FloatArray = NDArray[np.float64]
type IntArray = NDArray[np.int_]


def _load_data(path: Path) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return pd.DataFrame(rows)


def _precision_at_k(y_true: IntArray, y_prob: FloatArray, k: int) -> float:
    if k <= 0 or len(y_true) == 0:
        return 0.0
    idx = np.argsort(y_prob)[::-1][:k]
    return float(y_true[idx].sum() / k)


def _distinct_packages_in_top_k(packages: pd.Series, y_prob: FloatArray, k: int) -> int:
    idx = np.argsort(y_prob)[::-1][:k]
    return int(packages.iloc[idx].nunique())


def _dedup_precision_at_k(
    packages: pd.Series, y_true: IntArray, y_prob: FloatArray, k: int
) -> float:
    """P@k over distinct packages: keep each package's highest-scored row."""
    frame = pd.DataFrame({"package": packages.to_numpy(), "prob": y_prob, "label": y_true})
    best = (
        frame.sort_values("prob", ascending=False)
        .drop_duplicates(subset="package", keep="first")
        .head(k)
    )
    if len(best) == 0:
        return 0.0
    return float(best["label"].sum() / k)


def main() -> None:
    if not IN_PATH.exists():
        raise FileNotFoundError(f"Input not found: {IN_PATH}\nRun 02_build_monthly.py first.")

    print(f"Loading {IN_PATH} ...")
    df = _load_data(IN_PATH)

    train_df = df[df["month"] < TEST_START].copy()
    test_df = df[df["month"] >= TEST_START].copy()
    test_package_col = cast(pd.Series, test_df["package_id"])
    print(f"  Train: {len(train_df):,} rows | Test: {len(test_df):,} rows")
    print(f"  Distinct packages in test set: {test_package_col.nunique():,}")

    X_train = np.asarray(train_df.loc[:, FEATURE_COLS], dtype=np.float64)
    y_train = np.asarray(train_df.loc[:, TARGET_COL], dtype=np.int_)
    X_test = np.asarray(test_df.loc[:, FEATURE_COLS], dtype=np.float64)
    y_test = np.asarray(test_df.loc[:, TARGET_COL], dtype=np.int_)
    test_packages = test_package_col.reset_index(drop=True)

    imputer = SimpleImputer(strategy="median")
    X_train = np.asarray(imputer.fit_transform(X_train), dtype=np.float64)
    X_test = np.asarray(imputer.transform(X_test), dtype=np.float64)

    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    pos_weight = n_neg / n_pos if n_pos > 0 else 1.0

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models: list[tuple[str, Any, bool]] = [
        (
            "logistic",
            LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED),
            True,  # use scaled features
        ),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced",
                random_state=RANDOM_SEED,
                n_jobs=-1,
            ),
            False,
        ),
    ]
    if HAS_XGB and _XGBClassifier is not None:
        models.append(
            (
                "xgboost",
                _XGBClassifier(
                    n_estimators=300,
                    learning_rate=0.05,
                    max_depth=4,
                    scale_pos_weight=pos_weight,
                    random_state=RANDOM_SEED,
                    eval_metric="aucpr",
                    verbosity=0,
                ),
                False,
            )
        )
    if HAS_LGB and _LGBMClassifier is not None:
        models.append(
            (
                "lightgbm",
                _LGBMClassifier(
                    n_estimators=300,
                    learning_rate=0.05,
                    num_leaves=31,
                    class_weight="balanced",
                    random_state=RANDOM_SEED,
                    verbose=-1,
                ),
                False,
            )
        )

    results: list[dict[str, Any]] = []
    header = f"{'Model':<16} {'k':>4} {'row P@k':>9} {'distinct':>9} {'dedup P@k':>10}"
    print("\n" + "=" * 56)
    print("Row-level vs package-deduplicated precision-at-k")
    print("=" * 56)
    print(header)
    print("-" * 56)

    for name, model, use_scaled in models:
        Xtr = X_train_scaled if use_scaled else X_train
        Xte = X_test_scaled if use_scaled else X_test
        model.fit(Xtr, y_train)
        y_prob = np.asarray(model.predict_proba(Xte)[:, 1], dtype=np.float64)

        entry: dict[str, Any] = {"model": name}
        for k in K_VALUES:
            row_p = _precision_at_k(y_test, y_prob, k)
            distinct = _distinct_packages_in_top_k(test_packages, y_prob, k)
            dedup_p = _dedup_precision_at_k(test_packages, y_test, y_prob, k)
            entry[f"row_p_at_{k}"] = round(row_p, 4)
            entry[f"distinct_packages_in_top_{k}"] = distinct
            entry[f"dedup_p_at_{k}"] = round(dedup_p, 4)
            print(f"{name:<16} {k:>4} {row_p:>9.3f} {distinct:>9d} {dedup_p:>10.3f}")
        results.append(entry)
        print("-" * 56)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved: {OUT_PATH}")


if __name__ == "__main__":
    main()
