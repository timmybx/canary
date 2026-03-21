from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_ALIAS_PATH = Path("data/raw/registry/plugin_aliases.json")


ALIAS_PAYLOAD_KEYS = (
    "aliases",
    "alias_ids",
    "historical_plugin_ids",
    "historical_ids",
    "previous_names",
    "previousNames",
    "former_names",
    "formerNames",
    "legacy_names",
    "legacyNames",
)


def _normalize_plugin_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text


def _iter_alias_values(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        norm = _normalize_plugin_id(value)
        if norm:
            out.append(norm)
        return out
    if isinstance(value, list):
        for item in value:
            norm = _normalize_plugin_id(item)
            if norm:
                out.append(norm)
    return out


def _merge_aliases(alias_map: dict[str, str], canonical: str, aliases: list[str]) -> None:
    for alias in aliases:
        if alias == canonical:
            continue
        alias_map.setdefault(alias, canonical)


def _load_json_if_exists(path: Path) -> Any:
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def alias_file_candidates(*, data_dir: str | Path = "data/raw") -> list[Path]:
    data_dir = Path(data_dir)
    return [
        data_dir / "registry" / "plugin_aliases.json",
        Path("data/raw/registry/plugin_aliases.json"),
    ]


def load_plugin_alias_map(
    *,
    registry_path: str | Path | None = None,
    data_dir: str | Path = "data/raw",
) -> dict[str, str]:
    alias_map: dict[str, str] = {}

    registry = Path(registry_path) if registry_path is not None else None
    if registry is not None and registry.exists() and registry.is_file():
        try:
            with registry.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(record, dict):
                        continue
                    canonical = _normalize_plugin_id(record.get("plugin_id"))
                    if not canonical:
                        continue
                    for key in ALIAS_PAYLOAD_KEYS:
                        _merge_aliases(alias_map, canonical, _iter_alias_values(record.get(key)))
        except OSError:
            pass

    for path in alias_file_candidates(data_dir=data_dir):
        payload = _load_json_if_exists(path)
        if payload is None:
            continue
        if isinstance(payload, dict):
            for alias, canonical in payload.items():
                alias_norm = _normalize_plugin_id(alias)
                canonical_norm = _normalize_plugin_id(canonical)
                if alias_norm and canonical_norm and alias_norm != canonical_norm:
                    alias_map[alias_norm] = canonical_norm

    plugins_dir = Path(data_dir) / "plugins"
    if plugins_dir.exists() and plugins_dir.is_dir():
        for snap_path in sorted(plugins_dir.glob("*.snapshot.json")):
            payload = _load_json_if_exists(snap_path)
            if not isinstance(payload, dict):
                continue
            canonical = _normalize_plugin_id(payload.get("plugin_id"))
            if not canonical:
                canonical = _normalize_plugin_id(snap_path.name.split(".snapshot.json", 1)[0])
            if not canonical:
                continue
            for key in ALIAS_PAYLOAD_KEYS:
                _merge_aliases(alias_map, canonical, _iter_alias_values(payload.get(key)))
            plugin_api = payload.get("plugin_api")
            if isinstance(plugin_api, dict):
                for key in ALIAS_PAYLOAD_KEYS:
                    _merge_aliases(alias_map, canonical, _iter_alias_values(plugin_api.get(key)))

    return alias_map


@lru_cache(maxsize=32)
def _load_plugin_alias_map_cached(
    registry_path_str: str | None, data_dir_str: str
) -> dict[str, str]:
    registry_path = Path(registry_path_str) if registry_path_str else None
    return load_plugin_alias_map(registry_path=registry_path, data_dir=Path(data_dir_str))


def canonicalize_plugin_id(
    plugin_id: str,
    *,
    registry_path: str | Path | None = None,
    data_dir: str | Path = "data/raw",
) -> str:
    norm = _normalize_plugin_id(plugin_id)
    if norm is None:
        return plugin_id
    alias_map = _load_plugin_alias_map_cached(
        str(Path(registry_path)) if registry_path is not None else None,
        str(Path(data_dir)),
    )
    seen: set[str] = set()
    current = norm
    while current not in seen:
        seen.add(current)
        nxt = alias_map.get(current)
        if not nxt or nxt == current:
            break
        current = nxt
    return current


def alias_candidates(
    plugin_id: str,
    *,
    registry_path: str | Path | None = None,
    data_dir: str | Path = "data/raw",
) -> list[str]:
    canonical = canonicalize_plugin_id(plugin_id, registry_path=registry_path, data_dir=data_dir)
    alias_map = _load_plugin_alias_map_cached(
        str(Path(registry_path)) if registry_path is not None else None,
        str(Path(data_dir)),
    )
    out = [canonical]
    for alias, target in sorted(alias_map.items()):
        if target == canonical and alias not in out:
            out.append(alias)
    return out
