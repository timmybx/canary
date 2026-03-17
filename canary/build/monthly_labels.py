from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def _parse_month_key(value: str) -> tuple[int, int]:
    """
    Parse a month string like '2025-01' into a sortable (year, month) tuple.
    """
    year_s, month_s = value.split("-", 1)
    return int(year_s), int(month_s)


def _get_month_value(row: dict[str, Any]) -> str:
    """
    Return the month field from a row.

    Adjust this if your monthly feature rows use a different key name.
    """
    for key in ("month", "month_id", "period", "yyyymm"):
        if key in row:
            value = row[key]
            if key == "yyyymm":
                # Convert 202501 -> 2025-01 if needed
                s = str(value)
                if len(s) == 6:
                    return f"{s[:4]}-{s[4:]}"
            return str(value)

    raise KeyError("Row is missing a recognized month field (month/month_id/period/yyyymm).")


def _row_has_advisory_this_month(row: dict[str, Any]) -> bool:
    """
    Return whether the row indicates an advisory in the current month.

    Adjust this mapping if your feature rows use a different key name.
    """
    candidate_keys = (
        "had_advisory_this_month",
        "has_advisory_this_month",
        "advisory_this_month",
    )

    for key in candidate_keys:
        if key in row:
            return bool(row[key])

    # Fallback: infer from advisory_count_this_month if present.
    if "advisory_count_this_month" in row:
        try:
            return int(row["advisory_count_this_month"]) > 0
        except (TypeError, ValueError):
            return False

    raise KeyError(
        "Row is missing advisory indicator "
        "("
        "had_advisory_this_month / has_advisory_this_month / "
        "advisory_this_month / advisory_count_this_month"
        ")."
    )


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


def _write_jsonl(path: str | Path, rows: list[dict[str, Any]]) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    import csv

    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames: list[str] = sorted({key for row in rows for key in row.keys()})

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _build_labels_for_plugin_rows(
    rows: list[dict[str, Any]],
    *,
    horizons: tuple[int, ...],
) -> list[dict[str, Any]]:
    """
    Given rows for a single plugin, sorted by month, attach future-looking labels.

    A label for horizon H is:
      - 1 if any advisory occurs in months i+1 through i+H
      - 0 if the full future window exists and none occur
      - None if the full future window does not exist (right-censored)
    """
    rows_sorted = sorted(rows, key=lambda r: _parse_month_key(_get_month_value(r)))

    output: list[dict[str, Any]] = []

    for i, row in enumerate(rows_sorted):
        new_row = dict(row)

        for horizon in horizons:
            future_rows = rows_sorted[i + 1 : i + 1 + horizon]
            label_key = f"label_advisory_within_{horizon}m"

            if len(future_rows) < horizon:
                new_row[label_key] = None
            else:
                new_row[label_key] = int(any(_row_has_advisory_this_month(r) for r in future_rows))

        # Optional extras that may be handy later
        future_all = rows_sorted[i + 1 :]

        months_until_next_advisory: int | None = None
        for offset, future_row in enumerate(future_all, start=1):
            if _row_has_advisory_this_month(future_row):
                months_until_next_advisory = offset
                break

        new_row["months_until_next_advisory"] = months_until_next_advisory
        new_row["future_advisory_count"] = sum(
            1 for future_row in future_all if _row_has_advisory_this_month(future_row)
        )

        output.append(new_row)

    return output


def build_monthly_labels(
    *,
    in_path: str | Path = "data/processed/features/plugins.monthly.features.jsonl",
    out_path: str | Path = "data/processed/features/plugins.monthly.labeled.jsonl",
    out_csv_path: str | Path | None = "data/processed/features/plugins.monthly.labeled.csv",
    summary_path: str
    | Path
    | None = "data/processed/features/plugins.monthly.labeled.summary.json",
    horizons: tuple[int, ...] = (1, 3, 6, 12),
) -> list[dict[str, Any]]:
    """
    Build future advisory labels for each plugin-month row.

    Returns the labeled rows.
    """
    rows = _load_jsonl(in_path)

    rows_by_plugin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        plugin_id = str(row["plugin_id"])
        rows_by_plugin[plugin_id].append(row)

    labeled_rows: list[dict[str, Any]] = []
    for plugin_id in sorted(rows_by_plugin):
        labeled_rows.extend(
            _build_labels_for_plugin_rows(
                rows_by_plugin[plugin_id],
                horizons=horizons,
            )
        )

    # Sort final output for determinism
    labeled_rows = sorted(
        labeled_rows,
        key=lambda r: (str(r["plugin_id"]), _parse_month_key(_get_month_value(r))),
    )

    _write_jsonl(out_path, labeled_rows)

    if out_csv_path:
        _write_csv(out_csv_path, labeled_rows)

    if summary_path:
        summary = {
            "input_path": str(in_path),
            "output_path": str(out_path),
            "row_count": len(labeled_rows),
            "plugin_count": len(rows_by_plugin),
            "horizons": list(horizons),
            "label_non_null_counts": {
                f"label_advisory_within_{h}m": sum(
                    1 for row in labeled_rows if row.get(f"label_advisory_within_{h}m") is not None
                )
                for h in horizons
            },
            "label_positive_counts": {
                f"label_advisory_within_{h}m": sum(
                    1 for row in labeled_rows if row.get(f"label_advisory_within_{h}m") == 1
                )
                for h in horizons
            },
        }
        Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
        Path(summary_path).write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )

    return labeled_rows
