"""Shared helpers for the CANARY CLI command groups."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from canary.plugin_aliases import canonicalize_plugin_id


def _nonempty(path: Path) -> bool:
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def _iter_registry_plugin_ids(registry_path: Path) -> Iterable[str]:
    with registry_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            pid = (rec.get("plugin_id") or "").strip()
            if pid:
                yield canonicalize_plugin_id(pid, registry_path=registry_path)


def bulk_collect_loop(
    *,
    registry_path: Path,
    max_plugins: int | None,
    sleep_s: float,
    overwrite: bool,
    out_path_for: Callable[[str], Path],
    collect_one: Callable[[str, Path], None],
    precondition: Callable[[str], bool] | None = None,
) -> dict[str, int]:
    """
    Shared bulk-collection loop used by ``collect plugin`` and ``collect advisories``.

    Iterates the registry, honors --max-plugins / --sleep / --overwrite, skips
    items whose output already exists, counts a failed *precondition* separately
    (e.g. advisories require a snapshot first), and isolates per-plugin errors
    so one bad plugin never aborts a bulk run.

    Returns counts: processed, written, skipped, precondition_failed, errors.
    """
    counts = {"processed": 0, "written": 0, "skipped": 0, "precondition_failed": 0, "errors": 0}
    for plugin_id in _iter_registry_plugin_ids(registry_path):
        if max_plugins is not None and counts["processed"] >= max_plugins:
            break
        counts["processed"] += 1

        if precondition is not None and not precondition(plugin_id):
            counts["precondition_failed"] += 1
            continue

        out_path = out_path_for(plugin_id)
        if (not overwrite) and _nonempty(out_path):
            counts["skipped"] += 1
            continue

        try:
            collect_one(plugin_id, out_path)
            counts["written"] += 1
        except Exception as e:  # noqa: BLE001
            counts["errors"] += 1
            print(f"[ERROR] {plugin_id}: {e}")

        if sleep_s > 0:
            time.sleep(sleep_s)
    return counts
