"""
tools/shap_single_model.py
===========================
Signed SHAP feature importance for ONE specified model, with direction
computed from feature values rather than from the mean signed SHAP.

Why this tool exists
--------------------
Aggregating SHAP across model configurations (tools/shap_consistency.py) mixes
incomparable magnitudes (5-feature vs 40-feature models), non-SHAP fallbacks
(Random Forest MDI, logistic coefficients), and algorithm-dependent direction
labels. This tool instead reports from a single well specified configuration,
the same way the praxis reports precision (Table 4-4).

Why direction-by-correlation
----------------------------
The per-model `mean_shap` sign answers "which way is the AVERAGE plugin
pushed?" For zero-inflated features like advisory_max_cvss_to_date (most
plugins have no advisory history), the majority's small downward pushes can
outweigh the minority's large upward pushes, flipping the sign per algorithm.
This tool instead reports the sign of the Pearson correlation between the
imputed feature value and its per-row SHAP value: "do HIGH values of this
feature push predicted risk up or down?" That is the question the praxis
prose actually asks, and it is how SHAP beeswarm plots assign color.

Usage
-----
    # inside the container (defaults to the headline Advisory+SWH model)
    python tools/shap_single_model.py \
        --json data/processed/results/shap_single_model.json

    # another model
    python tools/shap_single_model.py \
        --model-dir data/processed/models/xgb_6m_full_cleaned_time

Output
------
    Console: ranked table with magnitude, direction, and direction confidence.
    JSON: consumed by tools/make_figures.py (figure: shap_single).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

MODEL_DIR = "data/processed/models/xgb_6m_advisory_swh_time"
IN_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
TARGET_COL = "label_advisory_within_6m"
WINDOW_FEATURES = frozenset({"window_index", "window_month", "window_year"})
AMBIGUOUS_CORR = 0.2  # |r| below this -> direction flagged as weak

FAMILY_PREFIXES = {
    "advisory_": "Advisory History",
    "swh_": "Software Heritage",
    "gharchive_": "GitHub Archive",
}


def _family(feature: str) -> str:
    for prefix, name in FAMILY_PREFIXES.items():
        if feature.startswith(prefix):
            return name
    return "Other"


def _test_start_month(model_dir: Path, fallback: str) -> str:
    fs = model_dir / "feature_selection.json"
    if fs.exists():
        j = json.loads(fs.read_text(encoding="utf-8"))
        if j.get("test_start_month"):
            return str(j["test_start_month"])
    return fallback


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Signed SHAP importance for one model, direction by value correlation."
    )
    parser.add_argument("--model-dir", default=MODEL_DIR)
    parser.add_argument("--in-path", default=IN_PATH)
    parser.add_argument("--target-col", default=TARGET_COL)
    parser.add_argument("--test-start", default="2025-05", help="fallback if not in artifacts")
    parser.add_argument("--top", type=int, default=20, help="rows to print/store")
    parser.add_argument("--json", default=None, help="optional JSON output path")
    args = parser.parse_args()

    import joblib  # pyright: ignore[reportMissingImports]  # noqa: PLC0415
    import numpy as np  # pyright: ignore[reportMissingImports]  # noqa: PLC0415
    import shap  # pyright: ignore[reportMissingImports]  # noqa: PLC0415

    from canary.train.baseline import (  # noqa: PLC0415
        _load_jsonl,
        _month_to_sortable,
        _parse_month_value,
        _rows_to_matrix,
        _split_rows,
    )

    model_dir = Path(args.model_dir)
    pipeline = joblib.load(model_dir / "model.joblib")
    feature_cols: list[str] = json.loads(
        (model_dir / "feature_columns.json").read_text(encoding="utf-8")
    )
    test_start = _test_start_month(model_dir, args.test_start)

    # --- rebuild the test matrix exactly as training/feature_selection did ---
    rows = _load_jsonl(args.in_path)
    usable = sorted(
        [r for r in rows if r.get(args.target_col) is not None],
        key=lambda r: (_month_to_sortable(_parse_month_value(r)), str(r.get("plugin_id", ""))),
    )
    _, test_rows, _ = _split_rows(
        usable,
        split_strategy="time",
        test_start_month=test_start,
        group_col="plugin_id",
        test_fraction=0.2,
        random_seed=42,
    )
    X_test = _rows_to_matrix(test_rows, feature_cols)
    print(f"Model: {model_dir.name} | test rows: {len(X_test)} | test start: {test_start}")

    # --- impute / unwrap exactly like feature_selection.compute_shap_* -------
    imputer = pipeline.named_steps.get("impute")
    model_step = pipeline.named_steps.get("model")
    if model_step is None:
        model_step = list(pipeline.named_steps.values())[-1]
    X_imp = imputer.transform(X_test) if imputer is not None else X_test.values
    clf = model_step
    if hasattr(clf, "named_steps"):
        inner = list(clf.named_steps.values())
        for step in inner[:-1]:
            if hasattr(step, "transform"):
                X_imp = step.transform(X_imp)
        clf = inner[-1]
    model_type = type(clf).__name__
    if not any(k in model_type for k in ("XGB", "LGBM", "LGB", "GBM")):
        raise SystemExit(
            f"{model_type} is not a boosted tree model; this tool is for XGBoost/LightGBM "
            "configurations where exact TreeExplainer SHAP is tractable."
        )

    # --- version-drift self-check: reproduce the saved test predictions ------
    # The model was pickled under whatever library versions were current at
    # training time. If unpickling under newer versions changed its behavior,
    # predictions will not match the test_predictions.csv written at training
    # time, and SHAP values computed now would describe a different model.
    pred_path = model_dir / "test_predictions.csv"
    max_diff = None
    if pred_path.exists():
        import csv as _csv  # noqa: PLC0415

        saved: dict[tuple[str, str], float] = {}
        with pred_path.open(encoding="utf-8", newline="") as f:
            for r in _csv.DictReader(f):
                saved[(r["plugin_id"], str(r.get("month", "")))] = float(r["y_prob"])
        probs_now = pipeline.predict_proba(X_test)[:, 1]
        diffs = []
        for row, p_now in zip(test_rows, probs_now, strict=True):
            key = (str(row.get("plugin_id", "")), str(row.get("month", "")))
            if key in saved:
                diffs.append(abs(saved[key] - float(p_now)))
        if diffs:
            max_diff = max(diffs)
            print(
                f"Version-drift check: reproduced {len(diffs)} saved predictions, "
                f"max |diff| = {max_diff:.2e}"
            )
            if max_diff > 1e-6:
                print(
                    "WARNING: predictions differ from training-time artifacts. "
                    "The unpickled model does not behave identically under current "
                    "library versions; SHAP values below describe the CURRENT "
                    "behavior, not the model as originally evaluated. Consider "
                    "retraining in the current environment before citing these numbers."
                )
        else:
            print("Version-drift check: no overlapping rows found to compare (skipped)")

    print(f"Computing SHAP values ({model_type}) ...")
    explainer = shap.TreeExplainer(clf)
    shap_out = explainer.shap_values(X_imp)
    vals = np.asarray(shap_out[1] if isinstance(shap_out, list) else shap_out)
    X_arr = np.asarray(X_imp, dtype=float)

    entries: list[dict[str, Any]] = []
    for i, col in enumerate(feature_cols):
        if col in WINDOW_FEATURES:
            continue
        s = vals[:, i]
        x = X_arr[:, i]
        mean_abs = float(np.mean(np.abs(s)))
        if np.std(x) > 0 and np.std(s) > 0:
            corr = float(np.corrcoef(x, s)[0, 1])
        else:
            corr = 0.0
        # Binned dependence profile: mean SHAP within value bins.
        # Reveals nonlinear shapes that a linear correlation can hide.
        # Bin scheme adapts to the distribution:
        #   - few distinct values (binaries, small counts): one bin per value
        #   - zero-inflated (majority at the minimum): min bin + terciles above
        #   - otherwise: quintiles
        profile = []
        uniq = np.unique(x)
        masks: list[tuple[float, float, Any]] = []
        if len(uniq) <= 6:
            masks = [(float(v), float(v), x == v) for v in uniq]
        else:
            xmin = float(uniq[0])
            at_min = x == xmin
            if at_min.mean() > 0.5:
                rest = x[~at_min]
                qs = np.unique(np.quantile(rest, [0.0, 1 / 3, 2 / 3, 1.0]))
                masks = [(xmin, xmin, at_min)]
                for b in range(len(qs) - 1):
                    hi_inc = b == len(qs) - 2
                    m = (~at_min) & (x >= qs[b]) & ((x <= qs[b + 1]) if hi_inc else (x < qs[b + 1]))
                    masks.append((float(qs[b]), float(qs[b + 1]), m))
            else:
                qs = np.unique(np.quantile(x, [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]))
                if len(qs) >= 3:
                    bins = np.clip(np.searchsorted(qs, x, side="right") - 1, 0, len(qs) - 2)
                    masks = [
                        (float(qs[b]), float(qs[b + 1]), bins == b) for b in range(len(qs) - 1)
                    ]
        for lo, hi, mask in masks:
            if mask.sum() >= 5:
                profile.append(
                    {
                        "value_lo": lo,
                        "value_hi": hi,
                        "n": int(mask.sum()),
                        "mean_shap": round(float(np.mean(s[mask])), 4),
                    }
                )
        monotone = None
        if len(profile) >= 3:
            deltas = [
                profile[i + 1]["mean_shap"] - profile[i]["mean_shap"]
                for i in range(len(profile) - 1)
            ]
            if all(d >= -1e-9 for d in deltas):
                monotone = "increasing"
            elif all(d <= 1e-9 for d in deltas):
                monotone = "decreasing"
            else:
                monotone = "non-monotone"
        # For features with substantial missingness, also profile ONLY the rows
        # where the value was genuinely observed (pre-imputation non-null).
        # Median imputation can merge the missing majority into the same value
        # range as real observations, hiding the observed-value relationship.
        observed_profile = []
        na_mask = X_test[col].isna().to_numpy()
        if na_mask.mean() > 0.10:
            xo, so = x[~na_mask], s[~na_mask]
            if len(xo) >= 25:
                qs_o = np.unique(np.quantile(xo, [0.0, 0.25, 0.5, 0.75, 1.0]))
                if len(qs_o) >= 3:
                    bins_o = np.clip(np.searchsorted(qs_o, xo, side="right") - 1, 0, len(qs_o) - 2)
                    for b in range(len(qs_o) - 1):
                        m = bins_o == b
                        if m.sum() >= 5:
                            observed_profile.append(
                                {
                                    "value_lo": float(qs_o[b]),
                                    "value_hi": float(qs_o[b + 1]),
                                    "n": int(m.sum()),
                                    "mean_shap": round(float(np.mean(so[m])), 4),
                                }
                            )
        entries.append(
            {
                "feature": col,
                "family": _family(col),
                "mean_abs_shap": round(mean_abs, 4),
                "value_shap_corr": round(corr, 3),
                "direction": "increasing" if corr > 0 else "decreasing",
                "direction_weak": abs(corr) < AMBIGUOUS_CORR,
                "missing_fraction": round(float(na_mask.mean()), 3),
                "bin_profile": profile,
                "bin_profile_observed_only": observed_profile,
                "bin_shape": monotone,
            }
        )
    entries.sort(key=lambda e: -e["mean_abs_shap"])
    for rank, e in enumerate(entries, start=1):
        e["rank"] = rank

    header = (
        f"  {'#':>3} {'feature':<44} {'family':<18} {'|SHAP|':>7} "
        f"{'dir':>11} {'r(value,shap)':>13}  bin shape"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for e in entries[: args.top]:
        weak = " (weak)" if e["direction_weak"] else ""
        shape = e.get("bin_shape") or "-"
        print(
            f"  {e['rank']:>3} {e['feature'][:44]:<44} {e['family']:<18} "
            f"{e['mean_abs_shap']:>7.3f} {e['direction']:>11} "
            f"{e['value_shap_corr']:>13.3f}{weak}  {shape}"
        )

    detail = [
        e
        for e in entries
        if e["feature"].startswith("advisory_") and e.get("bin_profile_observed_only")
    ]
    if detail:
        print("\n  Observed-only profiles (rows with genuine values, imputed rows excluded):")
        for e in detail:
            print(f"    {e['feature']} (missing fraction {e['missing_fraction']:.0%}):")
            for b in e["bin_profile_observed_only"]:
                print(
                    f"       value {b['value_lo']:g}..{b['value_hi']:g}  "
                    f"n={b['n']:>5}  mean SHAP {b['mean_shap']:+.3f}"
                )

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "_provenance": (
                        "Signed SHAP for a single model configuration; direction from the "
                        "Pearson correlation between imputed feature value and per-row SHAP "
                        "value. Generated by tools/shap_single_model.py."
                    ),
                    "model": model_dir.name,
                    "version_drift_max_pred_diff": max_diff,
                    "model_type": model_type,
                    "n_test_rows": int(len(X_test)),
                    "test_start_month": test_start,
                    "window_features_excluded": sorted(WINDOW_FEATURES),
                    "ambiguous_corr_threshold": AMBIGUOUS_CORR,
                    "features": entries[: max(args.top, 30)],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
