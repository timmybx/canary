"""
Apply a frozen, recorded fold model to the newest month of the panel.

This is inference, not training. The rolling-backtest protocol froze the
champion configuration and recorded its fold models; deploying one of those
models on months the protocol never evaluated is what a security team
would do with CANARY, and it touches nothing the protocol governs: no model
is fitted, no label is read, and the recorded results are not changed.

The output is a small JSON file the web console reads for the Score tab:
each plugin's probability, rank and percentile for the forecast month, with
the per-plugin feature contributions for linear models (coefficient times
imputed value, the same fallback the scorer uses).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from canary.train.baseline import _rows_to_matrix

DEFAULT_MODEL_DIR = "data/processed/results/rolling_backtest/oot_champion/fold_2025-11"
DEFAULT_OUT_PATH = "data/processed/results/latest_forecast.json"
TOP_DRIVERS = 6


def _iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no} of {path}") from exc


def _row_month(row: dict[str, Any]) -> str:
    for key in ("month", "month_id", "period"):
        if key in row:
            return str(row[key])
    return ""


def panel_months(in_path: Path) -> list[str]:
    """Every observation month present in the panel, sorted."""
    months: set[str] = set()
    for row in _iter_jsonl(in_path):
        m = _row_month(row)
        if m:
            months.add(m)
    return sorted(months)


def rows_for_month(in_path: Path, month: str) -> list[dict[str, Any]]:
    return [row for row in _iter_jsonl(in_path) if _row_month(row) == month]


def run_in_path(model_dir: Path) -> str | None:
    """The panel a fold model was trained from, as its run recorded it."""
    payload_path = model_dir.parent / "rolling_backtest.json"
    if not payload_path.is_file():
        return None
    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    value = payload.get("in_path") if isinstance(payload, dict) else None
    return str(value) if value else None


def _unwrap(pipeline: Any) -> tuple[Any, Any]:
    steps = dict(getattr(pipeline, "named_steps", {}) or {})
    return steps.get("impute"), steps.get("model", pipeline)


def _linear_contributions(
    pipeline: Any, X: Any, feature_columns: list[str]
) -> list[list[tuple[str, float]]] | None:
    """Per-row (feature, coefficient × imputed value) for linear models, else None."""
    imputer, clf = _unwrap(pipeline)
    coefs = getattr(clf, "coef_", None)
    if coefs is None:
        return None
    coefs = coefs[0]
    X_imp = imputer.transform(X) if imputer is not None else X.values
    out: list[list[tuple[str, float]]] = []
    for i in range(X_imp.shape[0]):
        contribs = [
            (col, float(coef) * float(X_imp[i, j]))
            for j, (col, coef) in enumerate(zip(feature_columns, coefs, strict=False))
        ]
        contribs.sort(key=lambda c: -abs(c[1]))
        out.append(contribs[:TOP_DRIVERS])
    return out


def forecast_month(model_dir: Path, in_path: Path, month: str | None = None) -> dict[str, Any]:
    """
    Score every plugin row of ``month`` (default: the newest month in the
    panel) with the pipeline in ``model_dir`` and rank the results.
    """
    import joblib  # pyright: ignore[reportMissingImports]

    pipeline = joblib.load(model_dir / "model.joblib")
    feature_columns: list[str] = json.loads(
        (model_dir / "feature_columns.json").read_text(encoding="utf-8")
    )
    months = panel_months(in_path)
    if not months:
        raise ValueError(f"{in_path} has no rows with a month")
    target = month or months[-1]
    if target not in months:
        raise ValueError(f"month {target} is not in {in_path} (have {months[0]}..{months[-1]})")
    rows = rows_for_month(in_path, target)
    X = _rows_to_matrix(rows, feature_columns)
    probs = pipeline.predict_proba(X)[:, 1]
    contribs = _linear_contributions(pipeline, X, feature_columns)

    order = sorted(
        range(len(rows)), key=lambda i: (-float(probs[i]), str(rows[i].get("plugin_id")))
    )
    n = len(rows)
    scores: dict[str, Any] = {}
    for rank, i in enumerate(order, start=1):
        pid = str(rows[i].get("plugin_id") or "")
        entry: dict[str, Any] = {
            "prob": float(probs[i]),
            "rank": rank,
            "n": n,
            "percentile": 100.0 * (n - rank) / (n - 1) if n > 1 else 100.0,
        }
        if contribs is not None:
            entry["drivers"] = [
                {
                    "feature": col,
                    "contribution": round(val, 4),
                    "value": rows[i].get(col),
                }
                for col, val in contribs[i]
            ]
        scores[pid] = entry

    metrics_path = model_dir / "metrics.json"
    metrics: dict[str, Any] = {}
    if metrics_path.is_file():
        try:
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            metrics = {}
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model_dir": str(model_dir),
        "run_name": model_dir.parent.name,
        "fold": model_dir.name.removeprefix("fold_"),
        "model_name": str(metrics.get("model_name") or ""),
        "include_prefixes": list(metrics.get("include_prefixes") or []),
        "train_start_month": metrics.get("train_start_month"),
        "train_end_month": metrics.get("test_start_month"),
        "label_as_of_month": metrics.get("label_as_of_month"),
        "in_path": str(in_path),
        "month": target,
        "panel_months": [months[0], months[-1]],
        "n_plugins": n,
        "feature_columns": feature_columns,
        "scores": scores,
    }


def write_forecast(payload: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
