"""
Data preparation for the charts on the Honest-evaluation tab.

Everything here is numeric / structural: it reads rolling-backtest result
files and returns plain dicts and lists that ``canary.web.charts`` turns into
SVG. No HTML is produced in this module.

Three views are prepared:

* ``timeline_series`` — for every pre-registered configuration, the per-fold
  ROC-AUC of its development run followed by its out-of-time run, so the
  chart can show the sixteen folds as one curve with the protocol boundary
  drawn where the development era ends.
* ``load_curves`` — cumulative-gain and ROC curves computed from the
  ``fold_*/test_predictions.csv`` files of a run directory. Results are
  cached on the files' modification times so the web console never re-parses
  a run that has not changed.
* ``leakage_pairs`` — stored-label vs embargoed pairs of the same
  configuration on the same folds (rolling ``<run>`` / ``<run>_leaky``
  siblings, plus named time-split ``<stem>`` / ``<stem>_embargo`` model
  directories), which is the before-and-after picture of the label leak.
* ``ranked_index`` — every fold prediction of a configuration's runs ranked
  within its month, for a plugin's track record across forecast dates
  (``plugin_track``) and the top-N of a fold (``fold_top_n``).
* ``family_ladder`` — the best embargoed development result per feature set
  in one ecosystem, for the Jenkins-vs-PyPI "which signals survive" chart.
"""

from __future__ import annotations

import csv
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

LEAKY_RUN_SUFFIX = "_leaky"
EMBARGO_MODEL_SUFFIX = "_embargo"
# Fractions of the ranked list at which the gain curve is evaluated.
GAIN_FRACTIONS: tuple[float, ...] = (
    0.01,
    0.02,
    0.03,
    0.05,
    0.075,
    0.10,
    0.15,
    0.20,
    0.25,
    0.30,
    0.40,
    0.50,
    0.60,
    0.70,
    0.80,
    0.90,
    1.00,
)
ROC_CURVE_MAX_POINTS = 200


# ---------------------------------------------------------------------------
# Timeline: development folds followed by out-of-time folds, per configuration
# ---------------------------------------------------------------------------


def _config_key(run: dict[str, Any]) -> tuple[tuple[str, ...], str]:
    return (
        tuple(str(p) for p in run.get("include_prefixes") or ()),
        str(run.get("model_name") or ""),
    )


def _is_primary(run: dict[str, Any], kind: str) -> bool:
    return (
        bool(run.get("embargo"))
        and not run.get("sensitivity")
        and str(run.get("window_kind") or "development") == kind
    )


def _fold_points(run: dict[str, Any], window: str) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for fold in run.get("folds") or []:
        if not isinstance(fold, dict) or fold.get("roc_auc") is None:
            continue
        points.append(
            {
                "month": str(fold.get("test_start_month") or ""),
                "roc_auc": float(fold["roc_auc"]),
                "positives": int(fold.get("test_positive_count") or 0),
                "window": window,
            }
        )
    points.sort(key=lambda p: p["month"])
    return points


def timeline_series(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Build one series per pre-registered configuration: the development run's
    folds followed by the out-of-time run's folds for the same feature
    prefixes and model.

    ``runs`` is the list produced by ``canary.webapp._load_rolling_backtests``
    (each payload carries ``window_kind`` and ``sensitivity``). Only primary
    embargoed runs take part; mixed-window curves and sensitivity runs are
    skipped because they duplicate the development + out-of-time pair. When no
    configuration has an out-of-time run, the best development configuration
    is returned alone so the chart still has something to show.
    """
    dev_by_config: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for run in runs:
        if _is_primary(run, "development"):
            dev_by_config.setdefault(_config_key(run), run)
    oot_by_config: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for run in runs:
        if _is_primary(run, "out_of_time"):
            oot_by_config.setdefault(_config_key(run), run)

    def _pooled_roc(run: dict[str, Any] | None) -> float:
        pooled = (run or {}).get("pooled") or {}
        value = pooled.get("roc_auc")
        if value is None:
            return -1.0
        try:
            return float(value)
        except (TypeError, ValueError):
            return -1.0

    keys = [k for k in oot_by_config if k in dev_by_config]
    if not keys and dev_by_config:
        keys = [max(dev_by_config, key=lambda k: _pooled_roc(dev_by_config[k]))]
    keys.sort(key=lambda k: -_pooled_roc(oot_by_config.get(k) or dev_by_config.get(k)))

    series: list[dict[str, Any]] = []
    for key in keys:
        dev = dev_by_config[key]
        oot = oot_by_config.get(key)
        points = _fold_points(dev, "development")
        if oot is not None:
            points += _fold_points(oot, "out_of_time")
        series.append(
            {
                "include_prefixes": list(key[0]),
                "model_name": key[1],
                "run_names": [str(dev.get("run_name") or "")]
                + ([str(oot.get("run_name") or "")] if oot else []),
                "dev_pooled_roc_auc": _pooled_roc(dev),
                "oot_pooled_roc_auc": _pooled_roc(oot) if oot else None,
                "points": points,
            }
        )
    return series


# ---------------------------------------------------------------------------
# Gain and ROC curves from fold-level predictions
# ---------------------------------------------------------------------------


def _read_predictions(path: Path) -> list[tuple[int, float]]:
    rows: list[tuple[int, float]] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        for rec in csv.DictReader(fh):
            try:
                rows.append((int(float(rec["y_true"])), float(rec["y_prob"])))
            except (KeyError, TypeError, ValueError):
                continue
    return rows


def _ranked(rows: list[tuple[int, float]]) -> list[tuple[int, float]]:
    # Highest score first; ties keep file order (a stable, deterministic choice).
    return sorted(rows, key=lambda r: -r[1])


def gain_curve(rows: list[tuple[int, float]]) -> dict[str, Any] | None:
    """
    Cumulative gain: after reviewing the top ``f`` of the ranked list, what
    share of all positives has been seen. Returns None when there are no
    positives (the curve is undefined).
    """
    n_pos = sum(y for y, _ in rows)
    if not rows or n_pos == 0:
        return None
    ranked = _ranked(rows)
    n = len(ranked)
    cumulative: list[int] = []
    seen = 0
    for y, _ in ranked:
        seen += y
        cumulative.append(seen)
    captured: list[float] = []
    for frac in GAIN_FRACTIONS:
        k = max(1, min(n, round(frac * n)))
        captured.append(cumulative[k - 1] / n_pos)
    return {"fractions": list(GAIN_FRACTIONS), "captured": captured}


def roc_curve(rows: list[tuple[int, float]]) -> dict[str, Any] | None:
    """
    ROC curve (false-positive rate, true-positive rate) with scores tied at
    the same value advanced together, plus the trapezoidal area. Down-sampled
    to at most ``ROC_CURVE_MAX_POINTS`` points for rendering. None when either
    class is absent.
    """
    n_pos = sum(y for y, _ in rows)
    n_neg = len(rows) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    ranked = _ranked(rows)
    fpr = [0.0]
    tpr = [0.0]
    tp = fp = 0
    i = 0
    while i < len(ranked):
        score = ranked[i][1]
        while i < len(ranked) and ranked[i][1] == score:
            if ranked[i][0]:
                tp += 1
            else:
                fp += 1
            i += 1
        fpr.append(fp / n_neg)
        tpr.append(tp / n_pos)
    auc = 0.0
    for j in range(1, len(fpr)):
        auc += (fpr[j] - fpr[j - 1]) * (tpr[j] + tpr[j - 1]) / 2
    if len(fpr) > ROC_CURVE_MAX_POINTS:
        step = (len(fpr) - 1) / (ROC_CURVE_MAX_POINTS - 1)
        idx = sorted({round(k * step) for k in range(ROC_CURVE_MAX_POINTS)} | {len(fpr) - 1})
        fpr = [fpr[k] for k in idx]
        tpr = [tpr[k] for k in idx]
    return {"fpr": fpr, "tpr": tpr, "auc": auc}


def _fold_dirs(run_dir: Path) -> list[Path]:
    return sorted(p for p in run_dir.glob("fold_*") if (p / "test_predictions.csv").is_file())


def _signature(run_dir: Path) -> tuple[tuple[str, int, int], ...]:
    sig: list[tuple[str, int, int]] = []
    for fold_dir in _fold_dirs(run_dir):
        st = (fold_dir / "test_predictions.csv").stat()
        sig.append((fold_dir.name, st.st_mtime_ns, st.st_size))
    return tuple(sig)


@lru_cache(maxsize=32)
def _curves_cached(run_dir: str, signature: tuple[tuple[str, int, int], ...]) -> dict[str, Any]:
    del signature  # part of the cache key only
    root = Path(run_dir)
    folds: list[dict[str, Any]] = []
    pooled_rows: list[tuple[int, float]] = []
    for fold_dir in _fold_dirs(root):
        rows = _read_predictions(fold_dir / "test_predictions.csv")
        if not rows:
            continue
        pooled_rows.extend(rows)
        n_pos = sum(y for y, _ in rows)
        roc = roc_curve(rows)
        folds.append(
            {
                "month": fold_dir.name.removeprefix("fold_"),
                "n_rows": len(rows),
                "n_positive": n_pos,
                "roc_auc": roc["auc"] if roc else None,
                "roc": roc,
                "gain": gain_curve(rows),
            }
        )
    n_pos = sum(y for y, _ in pooled_rows)
    pooled_roc = roc_curve(pooled_rows)
    return {
        "run_name": root.name,
        "n_rows": len(pooled_rows),
        "n_positive": n_pos,
        "base_rate": (n_pos / len(pooled_rows)) if pooled_rows else 0.0,
        "pooled": {
            "gain": gain_curve(pooled_rows),
            "roc_auc": pooled_roc["auc"] if pooled_roc else None,
        },
        "folds": folds,
    }


def load_curves(run_dir: Path) -> dict[str, Any] | None:
    """
    Gain and ROC curves for every fold of a rolling-backtest run directory,
    plus the pooled gain curve over all folds' test predictions. Returns None
    when the directory has no fold predictions.
    """
    if not run_dir.is_dir():
        return None
    signature = _signature(run_dir)
    if not signature:
        return None
    return _curves_cached(str(run_dir.resolve()), signature)


# ---------------------------------------------------------------------------
# Stored-label vs embargoed pairs (the before-and-after of the leak)
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _pooled_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    pooled = payload.get("pooled") or {}
    return {
        "roc_auc": pooled.get("roc_auc"),
        "average_precision": pooled.get("average_precision"),
        "ap_lift": pooled.get("ap_lift_over_base_rate"),
        "n_positive": pooled.get("n_positive"),
    }


def _split_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    n_pos = payload.get("test_positive_count")
    n_rows = payload.get("test_row_count")
    ap = payload.get("average_precision")
    lift = None
    if ap is not None and n_pos and n_rows:
        try:
            lift = float(ap) / (float(n_pos) / float(n_rows))
        except (TypeError, ValueError, ZeroDivisionError):
            lift = None
    return {
        "roc_auc": payload.get("roc_auc"),
        "average_precision": ap,
        "ap_lift": lift,
        "n_positive": n_pos,
    }


def rolling_leakage_pairs(root: Path, ecosystem: str) -> list[dict[str, Any]]:
    """
    Every ``<run>_leaky`` directory under ``root`` that has an embargoed
    ``<run>`` sibling, as one before/after record. Runs are matched by name,
    which is how ``tools/rolling_backtest.py --no-embargo`` counterparts are
    conventionally saved.
    """
    pairs: list[dict[str, Any]] = []
    if not root.is_dir():
        return pairs
    for leaky_dir in sorted(root.glob(f"*{LEAKY_RUN_SUFFIX}")):
        honest_dir = root / leaky_dir.name.removesuffix(LEAKY_RUN_SUFFIX)
        leaky = _read_json(leaky_dir / "rolling_backtest.json")
        honest = _read_json(honest_dir / "rolling_backtest.json")
        if not leaky or not honest or not honest.get("embargo") or leaky.get("embargo"):
            continue
        pairs.append(
            {
                "ecosystem": ecosystem,
                "layer": "rolling",
                "run_name": honest_dir.name,
                "include_prefixes": list(honest.get("include_prefixes") or []),
                "in_path": str(honest.get("in_path") or ""),
                "model_name": str(honest.get("model_name") or ""),
                "folds": len(honest.get("folds") or []),
                "stored": _pooled_metrics(leaky),
                "embargoed": _pooled_metrics(honest),
            }
        )
    return pairs


def time_split_leakage_pairs(
    models_root: Path, stems: dict[str, str], ecosystem: str
) -> list[dict[str, Any]]:
    """
    Named single-split model directories paired with their ``<stem>_embargo``
    retrain (the ablation driver's ``--embargo`` convention). ``stems`` maps
    each directory stem to its display label; only listed stems are used, so
    a 64-configuration suite does not turn into 64 bars.
    """
    pairs: list[dict[str, Any]] = []
    for stem, label in stems.items():
        stored = _read_json(models_root / stem / "metrics.json")
        embargoed = _read_json(models_root / f"{stem}{EMBARGO_MODEL_SUFFIX}" / "metrics.json")
        if not stored or not embargoed or not embargoed.get("label_as_of_month"):
            continue
        pairs.append(
            {
                "ecosystem": ecosystem,
                "layer": "time split",
                "run_name": stem,
                "label": label,
                "include_prefixes": list(embargoed.get("include_prefixes") or []),
                "model_name": str(embargoed.get("model_name") or ""),
                "folds": 1,
                "stored": _split_metrics(stored),
                "embargoed": _split_metrics(embargoed),
            }
        )
    return pairs


# ---------------------------------------------------------------------------
# Per-plugin track record and per-fold top-N across a run's fold predictions
# ---------------------------------------------------------------------------


def _read_prediction_records(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        for rec in csv.DictReader(fh):
            try:
                rows.append(
                    {
                        "plugin_id": str(rec["plugin_id"]),
                        "month": str(rec["month"]),
                        "y_true": int(float(rec["y_true"])),
                        "y_prob": float(rec["y_prob"]),
                    }
                )
            except (KeyError, TypeError, ValueError):
                continue
    return rows


def _run_signature(run_dirs: tuple[Path, ...]) -> tuple[tuple[str, int, int], ...]:
    sig: list[tuple[str, int, int]] = []
    for run_dir in run_dirs:
        for fold_dir in _fold_dirs(run_dir):
            st = (fold_dir / "test_predictions.csv").stat()
            sig.append((str(fold_dir), st.st_mtime_ns, st.st_size))
    return tuple(sig)


@lru_cache(maxsize=8)
def _ranked_index_cached(
    run_dirs: tuple[str, ...], signature: tuple[tuple[str, int, int], ...]
) -> dict[str, Any]:
    """
    Every fold prediction of the given runs, ranked within its month.

    Returns ``{"by_plugin": {plugin_id: [row, ...]}, "by_fold": {fold: [row, ...]}}``
    where each row carries ``month, fold, run_name, y_prob, y_true, rank, n,
    percentile``. ``rank`` is 1 for the highest score in that month;
    ``percentile`` is the share of that month's other plugins scored below.
    """
    del signature  # part of the cache key only
    by_plugin: dict[str, list[dict[str, Any]]] = {}
    by_fold: dict[str, list[dict[str, Any]]] = {}
    for run_dir in (Path(d) for d in run_dirs):
        for fold_dir in _fold_dirs(run_dir):
            fold = fold_dir.name.removeprefix("fold_")
            records = _read_prediction_records(fold_dir / "test_predictions.csv")
            months: dict[str, list[dict[str, Any]]] = {}
            for rec in records:
                months.setdefault(rec["month"], []).append(rec)
            for month_rows in months.values():
                month_rows.sort(key=lambda r: -r["y_prob"])
                n = len(month_rows)
                for rank, rec in enumerate(month_rows, start=1):
                    row = {
                        **rec,
                        "fold": fold,
                        "run_name": run_dir.name,
                        "rank": rank,
                        "n": n,
                        "percentile": 100.0 * (n - rank) / (n - 1) if n > 1 else 100.0,
                    }
                    by_plugin.setdefault(rec["plugin_id"], []).append(row)
                    by_fold.setdefault(fold, []).append(row)
    for rows in by_plugin.values():
        rows.sort(key=lambda r: r["month"])
    return {"by_plugin": by_plugin, "by_fold": by_fold}


def ranked_index(run_dirs: list[Path]) -> dict[str, Any] | None:
    """Cached month-ranked index over the fold predictions of ``run_dirs``
    (development run first, then out-of-time). None when nothing is on disk."""
    existing = tuple(d for d in run_dirs if d.is_dir())
    if not existing:
        return None
    signature = _run_signature(existing)
    if not signature:
        return None
    return _ranked_index_cached(tuple(str(d.resolve()) for d in existing), signature)


def plugin_track(index: dict[str, Any], plugin_id: str) -> list[dict[str, Any]]:
    """Month-ordered ranked rows for one plugin (empty when never scored)."""
    return list(index.get("by_plugin", {}).get(plugin_id, []))


def fold_top_n(index: dict[str, Any], fold: str, n_top: int = 25) -> list[dict[str, Any]]:
    """
    The top ``n_top`` plugins of a fold by their best month score, one row per
    plugin (a two-month fold scores each plugin twice; the higher score and
    its month are kept). ``y_true`` is 1 when either month's label was
    positive. Rows carry ``rank`` re-numbered 1..n_top within the fold.
    """
    best: dict[str, dict[str, Any]] = {}
    for row in index.get("by_fold", {}).get(fold, []):
        pid = row["plugin_id"]
        current = best.get(pid)
        if current is None or row["y_prob"] > current["y_prob"]:
            best[pid] = dict(row, y_true=max(row["y_true"], (current or row)["y_true"]))
        elif row["y_true"] and not current["y_true"]:
            current["y_true"] = 1
    ordered = sorted(best.values(), key=lambda r: (-r["y_prob"], r["plugin_id"]))[:n_top]
    for i, row in enumerate(ordered, start=1):
        row["rank"] = i
    return ordered


# ---------------------------------------------------------------------------
# Family ladder per ecosystem: which signal families survive the embargo
# ---------------------------------------------------------------------------


def _family_key(run: dict[str, Any]) -> tuple[str, ...]:
    prefixes = tuple(str(p).rstrip("_") for p in run.get("include_prefixes") or ())
    if prefixes:
        return prefixes
    # A run with no prefix filter was trained on a pre-filtered family
    # dataset (plugins.monthly.labeled.<family>_only.jsonl).
    stem = str(run.get("in_path") or "").replace("\\", "/").rsplit("/", 1)[-1]
    stem = stem.removesuffix(".jsonl").removeprefix("plugins.monthly.labeled").strip(".")
    return (stem.removesuffix("_only") or str(run.get("run_name") or ""),)


def family_ladder(runs: list[dict[str, Any]], ecosystem: str) -> list[dict[str, Any]]:
    """
    The single-family embargoed development results of an ecosystem, best
    model per family, sorted best first, plus the best multi-family
    configuration (flagged ``champion``) when one beats every single family.
    Each entry carries the run's ``include_prefixes``, ``in_path`` and
    ``model_name`` so the label helper can name it, its ``family`` key,
    ``roc_auc`` (pooled) and ``n_positive``.
    """
    best: dict[tuple[str, ...], dict[str, Any]] = {}
    for run in runs:
        if not _is_primary(run, "development"):
            continue
        pooled = run.get("pooled") or {}
        roc = pooled.get("roc_auc")
        if roc is None:
            continue
        key = _family_key(run)
        entry = {
            "ecosystem": ecosystem,
            "run_name": str(run.get("run_name") or ""),
            "include_prefixes": list(run.get("include_prefixes") or []),
            "in_path": str(run.get("in_path") or ""),
            "model_name": str(run.get("model_name") or ""),
            "family": key,
            "champion": False,
            "roc_auc": float(roc),
            "n_positive": pooled.get("n_positive"),
        }
        if key not in best or entry["roc_auc"] > best[key]["roc_auc"]:
            best[key] = entry
    singles = sorted(
        (e for e in best.values() if len(e["family"]) == 1), key=lambda e: -e["roc_auc"]
    )
    multis = [e for e in best.values() if len(e["family"]) > 1]
    if multis:
        top = max(multis, key=lambda e: e["roc_auc"])
        if not singles or top["roc_auc"] > singles[0]["roc_auc"]:
            top["champion"] = True
            singles.insert(0, top)
    return singles


# ---------------------------------------------------------------------------
# Feature drivers aggregated across a run's folds
# ---------------------------------------------------------------------------


def _drivers_signature(run_dir: Path) -> tuple[tuple[str, int, int], ...]:
    sig: list[tuple[str, int, int]] = []
    for fold_dir in sorted(run_dir.glob("fold_*")):
        path = fold_dir / "metrics.json"
        if path.is_file():
            st = path.stat()
            sig.append((fold_dir.name, st.st_mtime_ns, st.st_size))
    return tuple(sig)


@lru_cache(maxsize=16)
def _fold_drivers_cached(
    run_dir: str, signature: tuple[tuple[str, int, int], ...]
) -> dict[str, Any]:
    del signature  # part of the cache key only
    root = Path(run_dir)
    per_feature: dict[str, dict[str, Any]] = {}
    kind = ""
    n_folds = 0
    for fold_dir in sorted(root.glob("fold_*")):
        metrics = _read_json(fold_dir / "metrics.json")
        if not metrics:
            continue
        n_folds += 1
        entries = list(metrics.get("top_positive_features") or []) + list(
            metrics.get("top_negative_features") or []
        )
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("feature"):
                continue
            name = str(entry["feature"])
            if "coefficient" in entry:
                kind = kind or "coefficient"
                signed = float(entry["coefficient"])
                magnitude = abs(signed)
            elif "mean_abs_shap" in entry:
                kind = kind or "shap"
                magnitude = float(entry["mean_abs_shap"])
                signed = float(entry.get("mean_shap", 0.0) or 0.0)
            else:
                continue
            slot = per_feature.setdefault(name, {"feature": name, "signed": [], "magnitude": []})
            slot["signed"].append(signed)
            slot["magnitude"].append(magnitude)
    drivers: list[dict[str, Any]] = []
    for slot in per_feature.values():
        n = len(slot["magnitude"])
        drivers.append(
            {
                "feature": slot["feature"],
                "n_present": n,
                "mean_signed": sum(slot["signed"]) / n,
                "mean_magnitude": sum(slot["magnitude"]) / n,
                "n_positive": sum(1 for v in slot["signed"] if v > 0),
                "n_negative": sum(1 for v in slot["signed"] if v < 0),
            }
        )
    drivers.sort(key=lambda d: -d["mean_magnitude"])
    return {"kind": kind, "n_folds": n_folds, "drivers": drivers}


def fold_drivers(run_dir: Path) -> dict[str, Any] | None:
    """
    Feature drivers of a rolling run aggregated over its folds, from each
    fold's ``metrics.json`` (``top_positive_features`` /
    ``top_negative_features``). ``kind`` is ``"coefficient"`` for linear
    models (signed, direction meaningful) or ``"shap"`` for tree models
    (mean |SHAP| as magnitude; the signed mean is kept but is an average
    over a zero-heavy panel and should not be read as direction). Each
    driver carries the number of folds it appeared in and how many of those
    had a positive or negative sign. None when no fold metrics exist.
    """
    if not run_dir.is_dir():
        return None
    signature = _drivers_signature(run_dir)
    if not signature:
        return None
    payload = _fold_drivers_cached(str(run_dir.resolve()), signature)
    return payload if payload["drivers"] else None
