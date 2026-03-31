from __future__ import annotations

from typing import Any

from canary.collectors.software_heritage import collect_software_heritage_real
from canary.collectors.software_heritage_athena import (
    collect_software_heritage_athena_real,
)

DEFAULT_API_OUT_DIR = "data/raw/software_heritage_api"
DEFAULT_ATHENA_OUT_DIR = "data/raw/software_heritage_athena"


def default_out_dir_for_backend(backend: str) -> str:
    if backend == "athena":
        return DEFAULT_ATHENA_OUT_DIR
    if backend == "api":
        return DEFAULT_API_OUT_DIR
    raise ValueError(f"Unsupported software heritage backend: {backend}")


def collect_software_heritage(
    *,
    plugin_id: str,
    data_dir: str = "data/raw",
    out_dir: str | None = None,
    backend: str = "athena",
    timeout_s: float = 20.0,
    overwrite: bool = False,
    database: str | None = None,
    output_location: str | None = None,
    max_visits: int = 1,
    directory_batch_size: int = 20,
    max_directories: int = 100,
    verbose: bool = True,
) -> dict[str, Any]:
    if out_dir is None:
        out_dir = default_out_dir_for_backend(backend)

    if backend == "api":
        return collect_software_heritage_real(
            plugin_id=plugin_id,
            data_dir=data_dir,
            out_dir=out_dir,
            timeout_s=timeout_s,
            overwrite=overwrite,
        )

    if backend == "athena":
        return collect_software_heritage_athena_real(
            plugin_id=plugin_id,
            data_dir=data_dir,
            out_dir=out_dir,
            overwrite=overwrite,
            database=database or "swh_jenkins",
            output_location=output_location,
            max_visits=max_visits,
            directory_batch_size=directory_batch_size,
            max_directories=max_directories,
            verbose=verbose,
        )

    raise ValueError(f"Unsupported software heritage backend: {backend}")
