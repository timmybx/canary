from __future__ import annotations

import json
from pathlib import Path

from canary.build.advisories_events import build_advisories_events
from canary.collectors.jenkins_advisories import collect_advisories_sample


def test_build_advisories_events_writes_deduped_jsonl(tmp_path: Path) -> None:
    data_raw = tmp_path / "data" / "raw"
    advisories_dir = data_raw / "advisories"
    advisories_dir.mkdir(parents=True)

    # Write sample advisories as if they were collected per-plugin.
    sample = collect_advisories_sample()
    in_path = advisories_dir / "sample.advisories.jsonl"
    with in_path.open("w", encoding="utf-8") as f:
        for rec in sample:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    out_path = tmp_path / "data" / "processed" / "events" / "advisories.jsonl"
    records = build_advisories_events(data_raw_dir=data_raw, out_path=out_path)

    assert out_path.exists()
    out_lines = out_path.read_text(encoding="utf-8").splitlines()
    assert len(out_lines) == len(records)
    assert len(records) > 0

    # Basic schema sanity.
    r0 = json.loads(out_lines[0])
    assert r0["source"] == "jenkins"
    assert r0["type"] == "advisory"
    assert "plugin_id" in r0
    assert "advisory_id" in r0
    assert "published_date" in r0
    assert "url" in r0
