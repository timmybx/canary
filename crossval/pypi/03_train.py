"""
crossval/pypi/03_train.py
==========================
Train advisory-only models on the PyPI monthly labeled dataset and compare
results against the equivalent Jenkins advisory-only ablation runs.

This script is intentionally a direct parallel to the Jenkins advisory-only
experiment so results are comparable:
  - Same four model families: XGBoost, LightGBM, Random Forest, Logistic
  - Same time-split strategy (train < 2025-05, test >= 2025-05)
  - Same features: advisory_count_to_date, advisory_cve_count_to_date,
    advisory_max_cvss_to_date
  - Same evaluation metrics: AP, ROC-AUC, precision-at-k

Usage
-----
    python crossval/pypi/03_train.py

Input
-----
    data/pypi/processed/monthly_labeled.jsonl

Output
------
    data/pypi/processed/results/<model>_metrics.json
    Console: side-by-side comparison table vs Jenkins advisory-only
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier  # pyright: ignore[reportMissingImports]

    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[WARN] xgboost not installed — skipping XGBoost model")

try:
    from lightgbm import LGBMClassifier  # pyright: ignore[reportMissingImports]

    HAS_LGB = True
except ImportError:
    HAS_LGB = False
    print("[WARN] lightgbm not installed — skipping LightGBM model")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IN_PATH = Path("data/pypi/processed/monthly_labeled.jsonl")
OUT_DIR = Path("data/pypi/processed/results")
TEST_START = "2025-05"
TARGET_COL = "label_advisory_within_6m"
FEATURE_COLS = [
    "advisory_count_to_date",
    "advisory_cve_count_to_date",
    "advisory_max_cvss_to_date",
]
RANDOM_SEED = 42

# Jenkins advisory-only results for comparison (from ablation runs)
JENKINS_ADVISORY_ONLY = {
    "xgboost": {"ap": 0.0896, "auc": 0.6717, "p_at_10": 0.30, "p_at_25": 0.24},
    "lightgbm": {"ap": 0.0882, "auc": 0.6647, "p_at_10": 0.30, "p_at_25": 0.24},
    "random_forest": {"ap": 0.0617, "auc": 0.6830, "p_at_10": 0.20, "p_at_25": 0.16},
    "logistic": {"ap": 0.0253, "auc": 0.5034, "p_at_10": 0.00, "p_at_25": 0.00},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_data(path: Path) -> pd.DataFrame:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return pd.DataFrame(rows)


FeatureMatrix = NDArray[np.float64]
TargetArray = NDArray[np.int_]
ProbabilityArray = NDArray[np.float64]


def _as_float(value: Any) -> float:
    return float(np.asarray(value).item())


def _precision_at_k(y_true: TargetArray, y_prob: ProbabilityArray, k: int) -> float:
    if k <= 0 or len(y_true) == 0:
        return 0.0
    idx = np.argsort(y_prob)[::-1][:k]
    return float(y_true[idx].sum() / k)


def _train_evaluate(
    name: str,
    model: Any,
    X_train: FeatureMatrix,
    y_train: TargetArray,
    X_test: FeatureMatrix,
    y_test: TargetArray,
    pos_weight: float,
) -> dict[str, Any]:
    """Fit model and return metrics dict."""
    # Class weight via sample_weight for models that don't accept class_weight
    sample_weight = np.where(y_train == 1, pos_weight, 1.0)

    fit_kwargs: dict[str, Any] = {}
    model_name = type(model).__name__
    if model_name in ("XGBClassifier", "LGBMClassifier"):
        # These accept sample_weight in fit
        fit_kwargs["sample_weight"] = sample_weight

    model.fit(X_train, y_train, **fit_kwargs)
    y_prob = np.asarray(model.predict_proba(X_test)[:, 1], dtype=np.float64)

    ap = _as_float(average_precision_score(y_test, y_prob))
    auc = _as_float(roc_auc_score(y_test, y_prob))
    p10 = _precision_at_k(y_test, y_prob, 10)
    p25 = _precision_at_k(y_test, y_prob, 25)
    p50 = _precision_at_k(y_test, y_prob, 50)

    n_pos = int(y_test.sum())
    n_tot = len(y_test)
    base_rate = n_pos / n_tot if n_tot else 0.0

    return {
        "model": name,
        "average_precision": round(ap, 4),
        "roc_auc": round(auc, 4),
        "precision_at_10": round(p10, 4),
        "precision_at_25": round(p25, 4),
        "precision_at_50": round(p50, 4),
        "n_positive_test": n_pos,
        "n_total_test": n_tot,
        "base_rate": round(base_rate, 6),
        "test_start": TEST_START,
        "features": FEATURE_COLS,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if not IN_PATH.exists():
        raise FileNotFoundError(f"Input not found: {IN_PATH}\nRun 02_build_monthly.py first.")

    print(f"Loading {IN_PATH} ...")
    df = _load_data(IN_PATH)
    print(f"  {len(df):,} rows, {df[TARGET_COL].sum():,} positives")

    # Time split
    train_df = df[df["month"] < TEST_START].copy()
    test_df = df[df["month"] >= TEST_START].copy()
    print(f"  Train: {len(train_df):,} rows | Test: {len(test_df):,} rows")

    X_train = np.asarray(train_df.loc[:, FEATURE_COLS], dtype=np.float64)
    y_train = np.asarray(train_df.loc[:, TARGET_COL], dtype=np.int_)
    X_test = np.asarray(test_df.loc[:, FEATURE_COLS], dtype=np.float64)
    y_test = np.asarray(test_df.loc[:, TARGET_COL], dtype=np.int_)

    # Impute missing values (NaN → median of training set)
    imputer = SimpleImputer(strategy="median")
    X_train = np.asarray(imputer.fit_transform(X_train), dtype=np.float64)
    X_test = np.asarray(imputer.transform(X_test), dtype=np.float64)

    # Class imbalance weight
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    pos_weight = n_neg / n_pos if n_pos > 0 else 1.0
    print(f"  Train positives: {n_pos:,}  negatives: {n_neg:,}  pos_weight: {pos_weight:.1f}")

    # Scale features (for logistic regression)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    all_results: list[dict[str, Any]] = []

    # --- Logistic Regression ---
    print("\nTraining Logistic Regression ...")
    lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED)
    lr.fit(X_train_scaled, y_train)
    y_prob = np.asarray(lr.predict_proba(X_test_scaled)[:, 1], dtype=np.float64)
    ap = _as_float(average_precision_score(y_test, y_prob))
    auc = _as_float(roc_auc_score(y_test, y_prob))
    lr_metrics = {
        "model": "logistic",
        "average_precision": round(ap, 4),
        "roc_auc": round(auc, 4),
        "precision_at_10": round(_precision_at_k(y_test, y_prob, 10), 4),
        "precision_at_25": round(_precision_at_k(y_test, y_prob, 25), 4),
        "precision_at_50": round(_precision_at_k(y_test, y_prob, 50), 4),
        "n_positive_test": int(y_test.sum()),
        "n_total_test": len(y_test),
        "base_rate": round(int(y_test.sum()) / len(y_test), 6),
        "test_start": TEST_START,
        "features": FEATURE_COLS,
    }
    all_results.append(lr_metrics)
    (OUT_DIR / "logistic_metrics.json").write_text(
        json.dumps(lr_metrics, indent=2), encoding="utf-8"
    )
    print(f"  AP={ap:.4f}  AUC={auc:.4f}")

    # --- Random Forest ---
    print("Training Random Forest ...")
    rf = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1
    )
    rf_metrics = _train_evaluate("random_forest", rf, X_train, y_train, X_test, y_test, pos_weight)
    all_results.append(rf_metrics)
    (OUT_DIR / "rf_metrics.json").write_text(json.dumps(rf_metrics, indent=2), encoding="utf-8")
    print(f"  AP={rf_metrics['average_precision']:.4f}  AUC={rf_metrics['roc_auc']:.4f}")

    # --- XGBoost ---
    if HAS_XGB:
        print("Training XGBoost ...")
        xgb = XGBClassifier(
            n_estimators=300,
            learning_rate=0.05,
            max_depth=4,
            scale_pos_weight=pos_weight,
            random_state=RANDOM_SEED,
            eval_metric="aucpr",
            verbosity=0,
        )
        xgb.fit(X_train, y_train)
        y_prob = np.asarray(xgb.predict_proba(X_test)[:, 1], dtype=np.float64)
        ap = _as_float(average_precision_score(y_test, y_prob))
        auc = _as_float(roc_auc_score(y_test, y_prob))
        xgb_metrics: dict[str, Any] = {
            "model": "xgboost",
            "average_precision": round(ap, 4),
            "roc_auc": round(auc, 4),
            "precision_at_10": round(_precision_at_k(y_test, y_prob, 10), 4),
            "precision_at_25": round(_precision_at_k(y_test, y_prob, 25), 4),
            "precision_at_50": round(_precision_at_k(y_test, y_prob, 50), 4),
            "n_positive_test": int(y_test.sum()),
            "n_total_test": len(y_test),
            "base_rate": round(int(y_test.sum()) / len(y_test), 6),
            "test_start": TEST_START,
            "features": FEATURE_COLS,
        }
        all_results.append(xgb_metrics)
        (OUT_DIR / "xgb_metrics.json").write_text(
            json.dumps(xgb_metrics, indent=2), encoding="utf-8"
        )
        print(f"  AP={ap:.4f}  AUC={auc:.4f}")

    # --- LightGBM ---
    if HAS_LGB:
        print("Training LightGBM ...")
        lgb = LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=31,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            verbose=-1,
        )
        lgb_metrics = _train_evaluate("lightgbm", lgb, X_train, y_train, X_test, y_test, pos_weight)
        all_results.append(lgb_metrics)
        (OUT_DIR / "lgb_metrics.json").write_text(
            json.dumps(lgb_metrics, indent=2), encoding="utf-8"
        )
        print(f"  AP={lgb_metrics['average_precision']:.4f}  AUC={lgb_metrics['roc_auc']:.4f}")

    # Save combined results
    (OUT_DIR / "all_results.json").write_text(json.dumps(all_results, indent=2), encoding="utf-8")

    # ---------------------------------------------------------------------------
    # Comparison table
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("PyPI vs Jenkins  —  Advisory-Only Models  —  Time Split")
    print("=" * 72)
    print(f"{'Model':<16} {'Ecosystem':<10} {'AP':>7} {'AUC':>7} {'P@10':>7} {'P@25':>7}")
    print("-" * 72)

    model_order = ["xgboost", "lightgbm", "random_forest", "logistic"]
    pypi_lookup = {r["model"]: r for r in all_results}

    for m in model_order:
        j = JENKINS_ADVISORY_ONLY.get(m)
        p = pypi_lookup.get(m)
        if j:
            print(
                f"{m:<16} {'Jenkins':<10}"
                f" {j['ap']:>7.4f} {j['auc']:>7.4f}"
                f" {j['p_at_10']:>7.3f} {j['p_at_25']:>7.3f}"
            )
        if p:
            print(
                f"{m:<16} {'PyPI':<10}"
                f" {p['average_precision']:>7.4f} {p['roc_auc']:>7.4f}"
                f" {p['precision_at_10']:>7.3f} {p['precision_at_25']:>7.3f}"
            )
        if j or p:
            print()

    print("=" * 72)
    if all_results:
        base = all_results[0].get("base_rate", 0)
        n_pos = all_results[0].get("n_positive_test", 0)
        n_tot = all_results[0].get("n_total_test", 0)
        print(f"PyPI test set: {n_pos} positives / {n_tot} total  (base rate {base:.4f})")
        print("Jenkins test set: 77 positives / 4106 total  (base rate 0.0188)")
    print(f"\nPer-model metrics saved to: {OUT_DIR}/")


if __name__ == "__main__":
    main()
