"""
CANARY command-line interface.

The CLI is organized by command group — :mod:`canary.cli.collect`,
:mod:`canary.cli.build`, :mod:`canary.cli.train`, :mod:`canary.cli.score` —
with shared helpers in :mod:`canary.cli._common`.  This package init
re-exports the command handlers and helpers so ``canary.cli`` remains the
stable import surface, and ``canary.cli:main`` remains the console-script
entry point declared in pyproject.toml.
"""

from __future__ import annotations

import argparse

from canary.cli import build, collect, score, train
from canary.cli._common import (
    _iter_registry_plugin_ids,  # noqa: F401
    _nonempty,  # noqa: F401
    bulk_collect_loop,  # noqa: F401
)
from canary.cli.build import (
    _cmd_build_advisories_events,  # noqa: F401
    _cmd_build_feature_bundle,  # noqa: F401
    _cmd_build_monthly_feature_bundle,  # noqa: F401
    _cmd_build_monthly_labels,  # noqa: F401
)
from canary.cli.collect import (
    _cmd_collect_advisories,  # noqa: F401
    _cmd_collect_enrich,  # noqa: F401
    _cmd_collect_gharchive,  # noqa: F401
    _cmd_collect_github,  # noqa: F401
    _cmd_collect_healthscore,  # noqa: F401
    _cmd_collect_plugin,  # noqa: F401
    _cmd_collect_registry,  # noqa: F401
    _cmd_collect_software_heritage,  # noqa: F401
)
from canary.cli.score import (
    _cmd_score,  # noqa: F401
    _cmd_score_ml,  # noqa: F401
)
from canary.cli.train import (
    _cmd_train_baseline,  # noqa: F401
    _cmd_train_feature_select,  # noqa: F401
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="canary",
        description="CANARY: Component Analytics & Near-term Advisory Risk Yardstick",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    collect.register(sub)
    train.register(sub)
    build.register(sub)
    score.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
