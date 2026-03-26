from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path

KEEP_ALWAYS = {
    "plugin_id",
    "month",
    "window_start",
    "window_end",
    "window_year",
    "window_month",
    "window_index",
}


def _wanted_keys(
    row: dict[str, object],
    *,
    prefixes: list[str],
    keep_time_fields: bool,
) -> list[str]:
    keep = set(KEEP_ALWAYS)
    if not keep_time_fields:
        keep -= {"window_year", "window_month", "window_index"}

    for key in row:
        if key in keep:
            continue
        if key.startswith("label_"):
            keep.add(key)
            continue
        if any(key.startswith(prefix) for prefix in prefixes):
            keep.add(key)

    return sorted(keep)


def _iter_jsonl(path: Path) -> Iterable[dict[str, object]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                yield payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Filter monthly labeled CANARY rows to selected feature families."
    )
    parser.add_argument(
        "--in-path",
        required=True,
        help="Input JSONL path (for example plugins.monthly.labeled.jsonl)",
    )
    parser.add_argument(
        "--out-path",
        required=True,
        help="Output JSONL path",
    )
    parser.add_argument(
        "--families",
        required=True,
        help="Comma-separated family prefixes to keep, e.g. advisory_,gharchive_,swh_",
    )
    parser.add_argument(
        "--drop-time-fields",
        action="store_true",
        help="Drop window_year/window_month/window_index from output",
    )
    args = parser.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)
    prefixes = [p.strip() for p in args.families.split(",") if p.strip()]
    keep_time_fields = not args.drop_time_fields

    rows = list(_iter_jsonl(in_path))
    if not rows:
        raise SystemExit(f"No rows found in {in_path}")

    keys = _wanted_keys(rows[0], prefixes=prefixes, keep_time_fields=keep_time_fields)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for row in rows:
            slim = {k: row.get(k) for k in keys}
            f.write(json.dumps(slim, ensure_ascii=False) + "\n")

    print(f"Wrote {len(rows)} rows to {out_path}")
    print(f"Kept {len(keys)} columns")
    print("Families:", ", ".join(prefixes))
    print(
        "Dropped time fields:" if args.drop_time_fields else "Kept time fields:",
        not args.drop_time_fields,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
