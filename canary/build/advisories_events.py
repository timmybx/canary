from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from canary.collectors.jenkins_advisories import merge_advisory_records


def build_advisories_events(
    *,
    data_raw_dir: str | Path = "data/raw",
    out_path: str | Path = "data/processed/events/advisories.jsonl",
) -> list[dict[str, Any]]:
    """Build a deduplicated advisories "events" dataset.

    Reads:
      - {data_raw_dir}/advisories/*.jsonl (output of `canary collect advisories --real`)

    Writes:
      - out_path (JSONL), one record per (plugin_id, advisory_id)

    Returns the list of written records.
    """

    data_raw_dir = Path(data_raw_dir)
    out_path = Path(out_path)
    advisories_dir = data_raw_dir / "advisories"

    if not advisories_dir.exists():
        raise FileNotFoundError(f"Advisories directory not found: {advisories_dir}")

    records: list[dict[str, Any]] = []

    for p in sorted(advisories_dir.glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines rather than killing the build.
                continue

            # Only keep the records we understand today.
            if rec.get("source") != "jenkins" or rec.get("type") != "advisory":
                continue
            records.append(rec)

    merged = merge_advisory_records(records)

    # Sort deterministically for stable diffs.
    merged.sort(key=lambda r: (str(r.get("published_date", "")), str(r.get("plugin_id", ""))))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for r in merged:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    return merged
