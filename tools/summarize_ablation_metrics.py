from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected JSON object in {path}")
    return payload


def _fmt_float(value: Any, digits: int = 4) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _fmt_int(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return str(value)


def _extract_row(model_dir: Path, payload: dict[str, Any]) -> dict[str, str]:
    return {
        "run": model_dir.name,
        "features": _fmt_int(payload.get("n_features") or payload.get("features")),
        "train_rows": _fmt_int(payload.get("train_rows")),
        "test_rows": _fmt_int(payload.get("test_rows")),
        "train_pos": _fmt_int(payload.get("train_positives") or payload.get("train_pos")),
        "test_pos": _fmt_int(payload.get("test_positives") or payload.get("test_pos")),
        "roc_auc": _fmt_float(payload.get("roc_auc")),
        "avg_prec": _fmt_float(payload.get("average_precision") or payload.get("avg_precision")),
        "p_at_10": _fmt_float(payload.get("precision_at_10")),
        "p_at_25": _fmt_float(payload.get("precision_at_25")),
        "p_at_100": _fmt_float(payload.get("precision_at_100")),
    }


def _print_table(rows: list[dict[str, str]]) -> None:
    columns = [
        ("run", "Run"),
        ("features", "Feat"),
        ("train_rows", "Train"),
        ("test_rows", "Test"),
        ("train_pos", "Train+"),
        ("test_pos", "Test+"),
        ("roc_auc", "ROC-AUC"),
        ("avg_prec", "AvgPrec"),
        ("p_at_10", "P@10"),
        ("p_at_25", "P@25"),
        ("p_at_100", "P@100"),
    ]

    widths: dict[str, int] = {}
    for key, label in columns:
        widths[key] = len(label)
        for row in rows:
            widths[key] = max(widths[key], len(row.get(key, "")))

    header = "  ".join(label.ljust(widths[key]) for key, label in columns)
    rule = "  ".join("-" * widths[key] for key, _ in columns)
    print(header)
    print(rule)

    for row in rows:
        print("  ".join(row.get(key, "").ljust(widths[key]) for key, _ in columns))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize baseline ablation metrics from model output folders."
    )
    parser.add_argument(
        "--models-dir",
        default="data/processed/models",
        help="Directory containing model subfolders with metrics.json files",
    )
    parser.add_argument(
        "--contains",
        default="baseline_6m",
        help="Only include model folder names containing this text",
    )
    parser.add_argument(
        "--sort-by",
        default="avg_prec",
        choices=["run", "roc_auc", "avg_prec", "p_at_10", "p_at_25", "p_at_100"],
        help="Metric to sort by",
    )
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    if not models_dir.exists():
        raise SystemExit(f"Models directory not found: {models_dir}")

    rows: list[dict[str, str]] = []

    for model_dir in sorted(models_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        if args.contains and args.contains not in model_dir.name:
            continue

        metrics_path = model_dir / "metrics.json"
        if not metrics_path.exists():
            continue

        payload = _read_json(metrics_path)
        rows.append(_extract_row(model_dir, payload))

    if not rows:
        raise SystemExit("No matching metrics.json files found.")

    if args.sort_by != "run":
        rows.sort(
            key=lambda r: (
                float(r[args.sort_by]) if r[args.sort_by] not in {"-", ""} else float("-inf")
            ),
            reverse=True,
        )
    else:
        rows.sort(key=lambda r: r["run"])

    _print_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
