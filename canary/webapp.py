from __future__ import annotations

# ruff: noqa: E501
import argparse
import html
import io
import json
import logging
import mimetypes
import os
import re
import shlex
import urllib.parse
from contextlib import redirect_stdout
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol, cast
from wsgiref.simple_server import make_server

from canary.cli import (
    _cmd_build_monthly_feature_bundle,
    _cmd_build_monthly_labels,
    _cmd_collect_advisories,
    _cmd_collect_enrich,
    _cmd_collect_github,
    _cmd_collect_healthscore,
    _cmd_collect_plugin,
    _cmd_collect_registry,
    _cmd_train_baseline,
)
from canary.plugin_aliases import canonicalize_plugin_id
from canary.scoring.baseline import ScoreResult, score_plugin_baseline
from canary.scoring.ml import MLScorer, MLScoreResult, load_ml_scorer, score_plugin_ml

DEFAULT_DATA_DIR = "data/raw"
DEFAULT_REGISTRY_PATH = "data/raw/registry/plugins.jsonl"
DEFAULT_MONTHLY_FEATURES_PATH = "data/processed/features/plugins.monthly.features.jsonl"
DEFAULT_MONTHLY_FEATURES_CSV = "data/processed/features/plugins.monthly.features.csv"
DEFAULT_MONTHLY_FEATURES_SUMMARY = "data/processed/features/plugins.monthly.features.summary.json"
DEFAULT_LABELED_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
DEFAULT_LABELED_CSV = "data/processed/features/plugins.monthly.labeled.csv"
DEFAULT_LABELED_SUMMARY = "data/processed/features/plugins.monthly.labeled.summary.json"
DEFAULT_MODEL_DIR = "data/processed/models/baseline_6m"
MODEL_OUTPUTS_ROOT = Path("data/processed/models").resolve()
MODEL_OUTPUTS_ROOT_PARTS = Path("data/processed/models").parts
MODEL_OUTPUT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

DEFAULTS: dict[str, Any] = {
    "active_tab": "score",
    "plugin": "",
    "data_dir": DEFAULT_DATA_DIR,
    "real": True,
    "overwrite": False,
    "out_dir": "data/raw/plugins",
    "registry_path": DEFAULT_REGISTRY_PATH,
    "max_plugins": "",
    "sleep": "0",
    "repo_url": "",
    "timeout_s": "30",
    "page_size": "2500",
    "raw_out": "",
    "out_name": "plugins.jsonl",
    "github_out_dir": "data/raw/github",
    "github_timeout_s": "20",
    "github_max_pages": "5",
    "github_commits_days": "365",
    "only": "",
    "healthscore_timeout_s": "30",
    "command": "collect-registry",
    "monthly_start": "2025-01",
    "monthly_end": "2025-12",
    "monthly_out": DEFAULT_MONTHLY_FEATURES_PATH,
    "monthly_out_csv": DEFAULT_MONTHLY_FEATURES_CSV,
    "monthly_summary_out": DEFAULT_MONTHLY_FEATURES_SUMMARY,
    "labeled_in_path": DEFAULT_MONTHLY_FEATURES_PATH,
    "labeled_out_path": DEFAULT_LABELED_PATH,
    "labeled_out_csv_path": DEFAULT_LABELED_CSV,
    "labeled_summary_path": DEFAULT_LABELED_SUMMARY,
    "horizons": "1,3,6,12",
    "target_col": "label_advisory_within_6m",
    "model_in_path": DEFAULT_LABELED_PATH,
    "model_out_dir": DEFAULT_MODEL_DIR,
    "score_model_dir": DEFAULT_MODEL_DIR,
    "test_start_month": "2025-10",
    "exclude_cols": "",
    "include_prefixes": "",
    "ml_action": "train",
}

STATIC_DIR = Path(__file__).with_name("static")
logger = logging.getLogger(__name__)


class _WaitressServe(Protocol):
    def __call__(
        self,
        app: Any,
        *,
        host: str,
        port: int,
        threads: int,
        connection_limit: int,
    ) -> None: ...


def _load_waitress_serve() -> _WaitressServe | None:
    try:
        from waitress import serve  # pyright: ignore[reportMissingModuleSource]
    except ImportError:  # pragma: no cover
        return None
    return cast(_WaitressServe, serve)


waitress_serve = _load_waitress_serve()

CSS = """
:root {
  --bg: #09111d;
  --bg2: #0d1727;
  --panel: rgba(17, 26, 43, .92);
  --panel2: #172338;
  --panel3: #0f192b;
  --text: #e8eefb;
  --muted: #a8b3c8;
  --line: #24324b;
  --accent: #6fb1ff;
  --accent2: #9fd0ff;
  --good: #8df0bc;
  --warn: #ffd87a;
  --error-bg: #3a1820;
  --error-line: #7f3142;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, Segoe UI, Roboto, sans-serif;
  background: linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%);
  color: var(--text);
}
.hero {
  padding: 2.2rem 1.25rem 1.75rem;
  border-bottom: 1px solid rgba(255,255,255,.06);
  background:
    radial-gradient(circle at top left, rgba(111,177,255,.22), transparent 32%),
    radial-gradient(circle at top right, rgba(159,208,255,.12), transparent 24%);
}
.hero__inner, .page-shell { max-width: 1240px; margin: 0 auto; }
.hero__brand { display:flex; align-items:center; gap:1rem; }
.hero__logo-wrap {
  width: 88px; height: 88px; display:grid; place-items:center;
  border-radius: 24px; background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.02));
  border: 1px solid rgba(255,255,255,.08); box-shadow: 0 16px 40px rgba(0,0,0,.24);
}
.hero__logo { width:72px; height:72px; object-fit:contain; }
.hero__copy { color:var(--muted); max-width:68rem; font-size:1.02rem; margin-top:.75rem; }
.page-shell { padding: 1.25rem 1.25rem 3rem; }
.tabs {
  display:flex; gap:.75rem; flex-wrap:wrap; margin-bottom:1rem;
}
.tab-link {
  text-decoration:none; color:var(--text); padding:.85rem 1rem; border-radius:16px;
  background: rgba(255,255,255,.04); border:1px solid var(--line); min-width: 180px;
}
.tab-link strong { display:block; }
.tab-link span { display:block; color:var(--muted); font-size:.9rem; margin-top:.2rem; }
.tab-link.is-active {
  background: linear-gradient(180deg, rgba(111,177,255,.18), rgba(111,177,255,.08));
  border-color: rgba(111,177,255,.45);
  box-shadow: 0 12px 30px rgba(0,0,0,.2);
}
.tab-panel { display:none; }
.tab-panel.is-active { display:block; }
.grid { display:grid; grid-template-columns:1fr; gap:1rem; }
.grid--score { display:grid; grid-template-columns:1fr; gap:1rem; }
.grid--two { display:grid; grid-template-columns:1fr; gap:1rem; }
@media (min-width: 1040px) {
  .grid--score { grid-template-columns: 1.08fr .92fr; }
  .grid--two { grid-template-columns: 1fr 1fr; }
}
.card {
  background: var(--panel); border:1px solid var(--line); border-radius:20px; padding:1.2rem;
  box-shadow: 0 16px 40px rgba(0,0,0,.22);
}
.card__header, .score-banner, .metrics-row, .two-up, .button-row, .helper-row {
  display:flex; gap:1rem; flex-wrap:wrap;
}
.card__header, .score-banner { justify-content:space-between; align-items:flex-start; }
.eyebrow { text-transform:uppercase; letter-spacing:.08em; font-size:.75rem; color:var(--accent2); margin:0 0 .35rem; }
h1,h2,h3,h4 { margin:0 0 .45rem; }
p { margin:.35rem 0 0; }
.pill {
  padding:.35rem .7rem; background:rgba(111,177,255,.16); border:1px solid rgba(111,177,255,.3);
  border-radius:999px; color:var(--accent2); font-size:.85rem;
}
.pill--muted { background:rgba(255,255,255,.05); border-color:rgba(255,255,255,.08); color:var(--muted); }
.pill--warn  { background:rgba(230,160,30,.15);  border-color:rgba(230,160,30,.35);  color:#e6a01e; }
.pill--danger{ background:rgba(220,80,60,.15);   border-color:rgba(220,80,60,.35);   color:#e05c5c; }
.form-grid {
  display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:.9rem; margin-top:1rem;
}
.form-grid--dense { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
label { display:grid; gap:.4rem; font-weight:600; color:var(--muted); }
input, select, button, textarea {
  border-radius: 12px; border:1px solid var(--line); background:var(--panel2); color:var(--text);
  padding:.8rem .9rem; font:inherit;
}
textarea { min-height: 120px; resize: vertical; }
button {
  background: linear-gradient(180deg, var(--accent), #4d95e6); color:#071423; font-weight:700; cursor:pointer; align-self:end;
}
button:hover { filter: brightness(1.05); }
button.secondary {
  background: rgba(255,255,255,.06); color: var(--text); border-color: var(--line);
}
button[disabled] { cursor:not-allowed; opacity:.65; }
input[readonly] { color:var(--muted); background:rgba(255,255,255,.04); cursor:not-allowed; }
.checkbox-row {
  display:flex; align-items:center; gap:.65rem; padding:.8rem .9rem; border:1px solid var(--line);
  border-radius:12px; background:var(--panel2); color:var(--text);
}
.checkbox-row input { width:18px; height:18px; margin:0; }
.notice {
  margin-top: 1rem; padding:.9rem 1rem; border-radius:14px; border:1px solid var(--error-line); background:var(--error-bg);
}
.field-note { display:block; font-size:.82rem; color:var(--muted); font-weight:500; }
.result-stack { display:grid; gap:1rem; margin-top:1rem; }
.score-number { font-size:2.6rem; font-weight:800; }
.score-number span { font-size:1rem; color:var(--muted); margin-left:.2rem; }
.metric, .panel, .action-card {
  background: var(--panel3); border:1px solid var(--line); border-radius:16px; padding:1rem;
}
.metrics-row { margin-top:.2rem; }
.metric { min-width: 145px; flex: 1 1 145px; }
.metric--details {
  min-width: 145px; flex: 1 1 145px;
}
.metric--details summary {
  list-style: none; cursor: pointer;
}
.metric--details summary::-webkit-details-marker { display: none; }
.metric--details[open] {
  border-color: rgba(111,177,255,.45);
  box-shadow: inset 0 0 0 1px rgba(111,177,255,.12);
}
.metric--details:hover { filter: brightness(1.05); }
.metric__label { display:block; color:var(--muted); font-size:.9rem; }
.metric__value { display:block; margin-top:.35rem; font-size:1.4rem; font-weight:700; }
.metric__value--good { color: var(--good); }
.metric__value--warn { color: var(--warn); }
.metric__hint { display:block; margin-top:.45rem; color:var(--accent2); font-size:.82rem; font-weight:600; }
.bullet-list { margin:0; padding-left:1.2rem; }
.feature-list {
  margin: 0; padding-left: 1.2rem;
}
.feature-list li { break-inside: avoid; margin-bottom: .35rem; }
.feature-list-wrap {
  margin-top: .9rem; padding-top: .85rem; border-top: 1px solid rgba(255,255,255,.08);
}
.muted { color:var(--muted); }
.code-block, pre {
  white-space: pre-wrap; word-break: break-word; margin:0; padding:1rem; border-radius:14px;
  background:#0b1322; border:1px solid rgba(255,255,255,.06); color:#dbe5fb; overflow-x:auto;
}
code { background:rgba(255,255,255,.05); padding:.15rem .35rem; border-radius:6px; }
.kicker { color: var(--muted); margin-top:.15rem; }
.action-grid { display:grid; grid-template-columns:1fr; gap:1rem; margin-top:1rem; }
@media (min-width: 980px) { .action-grid { grid-template-columns: 1fr 1fr; } }
.action-card h3 { margin-bottom:.2rem; }
.action-card p { color: var(--muted); margin-bottom:.9rem; }
.tab-summary { margin-bottom: 1rem; }
.small { font-size: .9rem; }
.hidden { display:none; }
.matrix-wrap { margin-top: .2rem; }
.matrix-axis { color: var(--muted); font-size: .85rem; margin-bottom: .55rem; }
.matrix-grid { width: 100%; border-collapse: separate; border-spacing: .5rem; table-layout: fixed; }
.matrix-grid th { color: var(--muted); font-weight: 600; font-size: .9rem; text-align: center; }
.matrix-grid th.corner { text-align: left; }
.matrix-grid td { background: #0b1322; border: 1px solid rgba(255,255,255,.08); border-radius: 14px; padding: .9rem .7rem; text-align: center; vertical-align: middle; }
.matrix-grid td.matrix-cell--tn, .matrix-grid td.matrix-cell--tp { background: rgba(141,240,188,.08); border-color: rgba(141,240,188,.24); }
.matrix-grid td.matrix-cell--fp, .matrix-grid td.matrix-cell--fn { background: rgba(255,216,122,.08); border-color: rgba(255,216,122,.24); }
.matrix-count { display: block; font-size: 1.5rem; font-weight: 800; color: var(--text); }
.matrix-label { display: block; margin-top: .25rem; color: var(--muted); font-size: .85rem; }
.matrix-label.tip { border-bottom: none; text-decoration: underline dotted var(--muted); text-underline-offset: 2px; }
.matrix-side { min-width: 5.5rem; text-align: left; }

/* ── Tooltip ─────────────────────────────────────────────────── */
.tip { position:relative; display:inline-block; cursor:help; border-bottom:1px dashed var(--muted); }
.tip::after {
  content: attr(data-tip);
  position: absolute; bottom: calc(100% + 6px); left: 50%; transform: translateX(-50%);
  background: #111c30; color: var(--text); border: 1px solid var(--line);
  border-radius: 10px; padding: .55rem .75rem; font-size: .82rem; font-weight: 400;
  white-space: normal; width: 240px; z-index: 99; pointer-events: none;
  opacity: 0; transition: opacity .15s; line-height: 1.5;
  box-shadow: 0 8px 24px rgba(0,0,0,.35);
}
.tip:hover::after { opacity: 1; }

/* ── Model badge ─────────────────────────────────────────────── */
.model-badge {
  display:inline-flex; align-items:center; gap:.45rem;
  padding:.3rem .8rem; border-radius:999px; font-size:.82rem; font-weight:700;
  background:rgba(111,177,255,.13); border:1px solid rgba(111,177,255,.3); color:var(--accent2);
}
.model-badge--xgb { background:rgba(159,208,255,.1); border-color:rgba(159,208,255,.28); color:#b8e4ff; }
.model-badge--lgb { background:rgba(141,240,188,.1); border-color:rgba(141,240,188,.28); color:var(--good); }

/* ── Base rate bar ───────────────────────────────────────────── */
.baserate-row { display:flex; align-items:center; gap:.75rem; margin-top:.5rem; flex-wrap:wrap; }
.baserate-label { font-size:.85rem; color:var(--muted); white-space:nowrap; }
.baserate-track { flex:1; min-width:120px; height:8px; background:rgba(255,255,255,.08); border-radius:99px; overflow:hidden; }
.baserate-fill { height:100%; border-radius:99px; background: linear-gradient(90deg, var(--accent), #4d95e6); }
.baserate-val { font-size:.85rem; font-weight:700; color:var(--accent2); white-space:nowrap; }

/* ── Ranking metrics row ─────────────────────────────────────── */
.ranking-row { display:flex; gap:.6rem; flex-wrap:wrap; margin-top:.2rem; }
.rank-cell {
  flex:1; min-width:110px; background:var(--panel3); border:1px solid var(--line);
  border-radius:14px; padding:.75rem .9rem; text-align:center;
}
.rank-cell__k { font-size:.8rem; color:var(--muted); font-weight:600; }
.rank-cell__val { font-size:1.3rem; font-weight:800; margin-top:.2rem; }
.rank-cell__lift { font-size:.78rem; color:var(--muted); margin-top:.15rem; }
.rank-cell__val--good { color:var(--good); }
.rank-cell__val--warn { color:var(--warn); }
.rank-cell__val--muted { color:var(--muted); }

/* ── Class report panel ──────────────────────────────────────── */
.cls-table { width:100%; border-collapse:separate; border-spacing:.35rem; margin-top:.5rem; font-size:.88rem; }
.cls-table th { color:var(--muted); font-weight:600; text-align:right; padding:.3rem .5rem; }
.cls-table th:first-child { text-align:left; }
.cls-table td { background:#0b1322; border:1px solid rgba(255,255,255,.06); border-radius:8px; padding:.4rem .6rem; text-align:right; }
.cls-table td:first-child { text-align:left; font-weight:600; color:var(--accent2); }
"""


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _bool_from_form(value: Any) -> bool:
    return str(value).lower() in {"1", "true", "on", "yes"}


def _optional_str(value: str) -> str | None:
    value = value.strip()
    return value or None


def _merge_defaults(form: dict[str, str] | None = None) -> dict[str, Any]:
    values = DEFAULTS.copy()
    if form:
        for key, default in DEFAULTS.items():
            if isinstance(default, bool):
                values[key] = _bool_from_form(form.get(key))
            else:
                values[key] = (form.get(key) or default).strip()
    return values


def _capture_command(func: Any, args: argparse.Namespace) -> dict[str, Any]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = int(func(args))
    return {"exit_code": exit_code, "output": buffer.getvalue().strip()}


def _namespace_for_data_action(command_name: str, form: dict[str, str]) -> argparse.Namespace:
    if command_name == "collect-registry":
        return argparse.Namespace(
            out_dir="data/raw/registry",
            out_name=(form.get("out_name") or "plugins.jsonl").strip(),
            raw_out=_optional_str(form.get("raw_out") or ""),
            page_size=int((form.get("page_size") or "2500").strip()),
            max_plugins=_optional_str(form.get("max_plugins") or ""),
            timeout_s=float((form.get("timeout_s") or "30").strip()),
            real=_bool_from_form(form.get("real")),
        )
    if command_name == "collect-plugin":
        return argparse.Namespace(
            id=_optional_str(form.get("plugin") or ""),
            out_dir="data/raw/plugins",
            repo_url=_optional_str(form.get("repo_url") or ""),
            real=_bool_from_form(form.get("real")),
            registry_path=(form.get("registry_path") or DEFAULT_REGISTRY_PATH).strip(),
            max_plugins=_optional_str(form.get("max_plugins") or ""),
            sleep=float((form.get("sleep") or "0").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-advisories":
        return argparse.Namespace(
            plugin=_optional_str(form.get("plugin") or ""),
            data_dir=DEFAULT_DATA_DIR,
            out_dir="data/raw/advisories",
            real=_bool_from_form(form.get("real")),
            registry_path=(form.get("registry_path") or DEFAULT_REGISTRY_PATH).strip(),
            max_plugins=_optional_str(form.get("max_plugins") or ""),
            sleep=float((form.get("sleep") or "0").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-github":
        plugin = (form.get("plugin") or "").strip()
        if not plugin:
            raise ValueError("GitHub collection requires a plugin ID.")
        return argparse.Namespace(
            plugin=plugin,
            data_dir=DEFAULT_DATA_DIR,
            out_dir="data/raw/github",
            timeout_s=float((form.get("github_timeout_s") or "20").strip()),
            max_pages=int((form.get("github_max_pages") or "5").strip()),
            commits_days=int((form.get("github_commits_days") or "365").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-healthscore":
        return argparse.Namespace(
            data_dir=DEFAULT_DATA_DIR,
            timeout_s=float((form.get("healthscore_timeout_s") or "30").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-enrich":
        return argparse.Namespace(
            registry=(form.get("registry_path") or DEFAULT_REGISTRY_PATH).strip(),
            data_dir=DEFAULT_DATA_DIR,
            only=_optional_str(form.get("only") or ""),
            max_plugins=_optional_str(form.get("max_plugins") or ""),
            sleep=float((form.get("sleep") or "0").strip()),
            real=_bool_from_form(form.get("real")),
            github_timeout_s=float((form.get("github_timeout_s") or "20").strip()),
            github_max_pages=int((form.get("github_max_pages") or "5").strip()),
            github_commits_days=int((form.get("github_commits_days") or "365").strip()),
            healthscore_timeout_s=float((form.get("healthscore_timeout_s") or "30").strip()),
        )
    if command_name == "build-monthly-features":
        return argparse.Namespace(
            data_raw_dir=DEFAULT_DATA_DIR,
            registry=(form.get("registry_path") or DEFAULT_REGISTRY_PATH).strip(),
            start=(form.get("monthly_start") or "2025-01").strip(),
            end=(form.get("monthly_end") or "2025-12").strip(),
            out=(form.get("monthly_out") or DEFAULT_MONTHLY_FEATURES_PATH).strip(),
            out_csv=(form.get("monthly_out_csv") or DEFAULT_MONTHLY_FEATURES_CSV).strip(),
            summary_out=(
                form.get("monthly_summary_out") or DEFAULT_MONTHLY_FEATURES_SUMMARY
            ).strip(),
        )
    if command_name == "build-monthly-labels":
        return argparse.Namespace(
            in_path=(form.get("labeled_in_path") or DEFAULT_MONTHLY_FEATURES_PATH).strip(),
            out_path=(form.get("labeled_out_path") or DEFAULT_LABELED_PATH).strip(),
            out_csv_path=(form.get("labeled_out_csv_path") or DEFAULT_LABELED_CSV).strip(),
            summary_path=(form.get("labeled_summary_path") or DEFAULT_LABELED_SUMMARY).strip(),
            horizons=(form.get("horizons") or "1,3,6,12").strip(),
        )
    raise ValueError(f"Unsupported data action: {command_name}")


def _namespace_for_train(form: dict[str, str]) -> argparse.Namespace:
    model_out_dir = _normalize_model_output_dir(form.get("model_out_dir") or DEFAULT_MODEL_DIR)
    return argparse.Namespace(
        in_path=(form.get("model_in_path") or DEFAULT_LABELED_PATH).strip(),
        target_col=(form.get("target_col") or "label_advisory_within_6m").strip(),
        out_dir=model_out_dir,
        test_start_month=(form.get("test_start_month") or "2025-10").strip(),
        exclude_cols=(form.get("exclude_cols") or "").strip(),
        include_prefixes=(form.get("include_prefixes") or "").strip(),
    )


def _argv_preview_data(command_name: str, args: argparse.Namespace) -> list[str]:
    if command_name == "collect-registry":
        parts = [
            "--out-dir",
            args.out_dir,
            "--out-name",
            args.out_name,
            "--page-size",
            str(args.page_size),
        ]
        if args.raw_out:
            parts += ["--raw-out", args.raw_out]
        if args.max_plugins is not None:
            parts += ["--max-plugins", str(args.max_plugins)]
        parts += ["--timeout-s", str(args.timeout_s)]
        if args.real:
            parts.append("--real")
        return parts
    if command_name == "collect-plugin":
        parts = [
            "--out-dir",
            args.out_dir,
            "--registry-path",
            args.registry_path,
            "--sleep",
            str(args.sleep),
        ]
        if args.id:
            parts += ["--id", args.id]
        if args.repo_url:
            parts += ["--repo-url", args.repo_url]
        if args.max_plugins is not None:
            parts += ["--max-plugins", str(args.max_plugins)]
        if args.real:
            parts.append("--real")
        if args.overwrite:
            parts.append("--overwrite")
        return parts
    if command_name == "collect-advisories":
        parts = [
            "--data-dir",
            args.data_dir,
            "--out-dir",
            args.out_dir,
            "--registry-path",
            args.registry_path,
            "--sleep",
            str(args.sleep),
        ]
        if args.plugin:
            parts += ["--plugin", args.plugin]
        if args.max_plugins is not None:
            parts += ["--max-plugins", str(args.max_plugins)]
        if args.real:
            parts.append("--real")
        if args.overwrite:
            parts.append("--overwrite")
        return parts
    if command_name == "collect-github":
        parts = [
            "--plugin",
            args.plugin,
            "--data-dir",
            args.data_dir,
            "--out-dir",
            args.out_dir,
            "--timeout-s",
            str(args.timeout_s),
            "--max-pages",
            str(args.max_pages),
            "--commits-days",
            str(args.commits_days),
        ]
        if args.overwrite:
            parts.append("--overwrite")
        return parts
    if command_name == "collect-healthscore":
        parts = ["--data-dir", args.data_dir, "--timeout-s", str(args.timeout_s)]
        if args.overwrite:
            parts.append("--overwrite")
        return parts
    if command_name == "collect-enrich":
        parts = [
            "--registry",
            args.registry,
            "--data-dir",
            args.data_dir,
            "--sleep",
            str(args.sleep),
            "--github-timeout-s",
            str(args.github_timeout_s),
            "--github-max-pages",
            str(args.github_max_pages),
            "--github-commits-days",
            str(args.github_commits_days),
            "--healthscore-timeout-s",
            str(args.healthscore_timeout_s),
        ]
        if args.only:
            parts += ["--only", args.only]
        if args.max_plugins is not None:
            parts += ["--max-plugins", str(args.max_plugins)]
        if args.real:
            parts.append("--real")
        return parts
    if command_name == "build-monthly-features":
        return [
            "--data-raw-dir",
            args.data_raw_dir,
            "--registry",
            args.registry,
            "--start",
            args.start,
            "--end",
            args.end,
            "--out",
            args.out,
            "--out-csv",
            args.out_csv,
            "--summary-out",
            args.summary_out,
        ]
    if command_name == "build-monthly-labels":
        return [
            "--in-path",
            args.in_path,
            "--out-path",
            args.out_path,
            "--out-csv-path",
            args.out_csv_path,
            "--summary-path",
            args.summary_path,
            "--horizons",
            args.horizons,
        ]
    return []


def _argv_preview_train(args: argparse.Namespace) -> list[str]:
    parts = [
        "--in-path",
        args.in_path,
        "--target-col",
        args.target_col,
        "--out-dir",
        args.out_dir,
        "--test-start-month",
        args.test_start_month,
    ]
    if args.exclude_cols:
        parts += ["--exclude-cols", args.exclude_cols]
    if args.include_prefixes:
        parts += ["--include-prefixes", args.include_prefixes]
    return parts


def _run_data_action(command_name: str, form: dict[str, str]) -> dict[str, Any]:
    handlers: dict[str, tuple[Any, list[str]]] = {
        "collect-registry": (_cmd_collect_registry, ["canary", "collect", "registry"]),
        "collect-plugin": (_cmd_collect_plugin, ["canary", "collect", "plugin"]),
        "collect-advisories": (_cmd_collect_advisories, ["canary", "collect", "advisories"]),
        "collect-github": (_cmd_collect_github, ["canary", "collect", "github"]),
        "collect-healthscore": (_cmd_collect_healthscore, ["canary", "collect", "healthscore"]),
        "collect-enrich": (_cmd_collect_enrich, ["canary", "collect", "enrich"]),
        "build-monthly-features": (
            _cmd_build_monthly_feature_bundle,
            ["canary", "build", "monthly-features"],
        ),
        "build-monthly-labels": (_cmd_build_monthly_labels, ["canary", "build", "monthly-labels"]),
    }
    handler, argv = handlers[command_name]
    args = _namespace_for_data_action(command_name, form)
    result = _capture_command(handler, args)
    return {
        "command": " ".join(
            shlex.quote(part) for part in argv + _argv_preview_data(command_name, args)
        ),
        "exit_code": result["exit_code"],
        "output": result["output"],
        "action": command_name,
    }


def _run_train_action(form: dict[str, str]) -> dict[str, Any]:
    args = _namespace_for_train(form)
    result = _capture_command(_cmd_train_baseline, args)
    metrics_path = _model_metrics_path(args.out_dir)
    metrics = _load_model_metrics(args.out_dir)
    return {
        "command": " ".join(
            shlex.quote(part)
            for part in ["canary", "train", "baseline"] + _argv_preview_train(args)
        ),
        "exit_code": result["exit_code"],
        "output": result["output"],
        "metrics": metrics,
        "metrics_path": str(metrics_path),
        "action": "train",
    }


def _run_load_metrics_action(form: dict[str, str]) -> dict[str, Any]:
    out_dir = _normalize_model_output_dir(form.get("model_out_dir") or DEFAULT_MODEL_DIR)
    metrics_path = _model_metrics_path(out_dir)
    metrics = _load_model_metrics(out_dir)
    if not metrics:
        raise ValueError(f"No metrics.json was found under {metrics_path}.")
    return {
        "command": f"load metrics from {metrics_path}",
        "exit_code": 0,
        "output": f"Loaded metrics from {metrics_path}",
        "metrics": metrics,
        "metrics_path": str(metrics_path),
        "action": "load",
    }


@lru_cache(maxsize=256)
def _detect_available_files_cached(plugin_id: str) -> list[str]:
    base = Path(DEFAULT_DATA_DIR)
    plugin_id = canonicalize_plugin_id(plugin_id, data_dir=base)
    candidates = [
        base / "plugins" / f"{plugin_id}.snapshot.json",
        base / "advisories" / f"{plugin_id}.advisories.real.jsonl",
        base / "advisories" / f"{plugin_id}.advisories.sample.jsonl",
        base / "github" / f"{plugin_id}.github_index.json",
        base / "healthscore" / "plugins" / f"{plugin_id}.healthscore.json",
    ]
    return [str(path) for path in candidates if path.exists()]


def _detect_available_files(plugin_id: str) -> list[str]:
    return _detect_available_files_cached(plugin_id)


@lru_cache(maxsize=32)
def _load_registry_plugin_choices_cached(registry_path: str, mtime_ns: int) -> tuple[str, ...]:
    path = Path(registry_path)
    plugin_ids: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            plugin_id = str(record.get("plugin_id") or "").strip()
            if plugin_id:
                plugin_ids.append(plugin_id)
    return tuple(sorted(set(plugin_ids)))


def _load_plugin_choices(registry_path: str) -> list[str]:
    path = Path(registry_path)
    if not path.exists() or not path.is_file():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    return list(_load_registry_plugin_choices_cached(str(path.resolve()), stat.st_mtime_ns))


def _plugin_known(plugin_id: str, registry_path: str) -> bool:
    plugin_id = plugin_id.strip()
    if not plugin_id:
        return False
    choices = _load_plugin_choices(registry_path)
    return not choices or plugin_id in choices


def _plugin_picker(
    name: str, label: str, value: Any, plugin_options: list[str], *, note_mode: str = "strict"
) -> str:
    datalist_id = f"{name}-list"
    options_html = "".join(
        f'<option value="{_escape(plugin)}"></option>' for plugin in plugin_options
    )
    attrs = [
        'type="text"',
        f'name="{_escape(name)}"',
        f'value="{_escape(value)}"',
        'placeholder="cucumber-reports"',
        f'list="{_escape(datalist_id)}"',
        'autocomplete="off"',
        'spellcheck="false"',
        'data-plugin-input="true"',
    ]
    if plugin_options and note_mode == "strict":
        note = '<span class="field-note">Autocomplete is populated from the current registry file. Unknown plugin IDs are blocked.</span>'
    elif plugin_options:
        note = '<span class="field-note">Autocomplete is populated from the current registry file.</span>'
    else:
        note = '<span class="field-note">No registry plugin list was found yet, so free text is still allowed.</span>'
    return (
        f"<label>{_escape(label)}"
        f"<input {' '.join(attrs)}>"
        f'<datalist id="{_escape(datalist_id)}">{options_html}</datalist>'
        f"{note}</label>"
    )


def _input_text(
    name: str,
    label: str,
    value: Any,
    placeholder: str = "",
    *,
    readonly: bool = False,
    input_type: str = "text",
) -> str:
    attrs = [
        f'type="{_escape(input_type)}"',
        f'name="{_escape(name)}"',
        f'value="{_escape(value)}"',
        f'placeholder="{_escape(placeholder)}"',
    ]
    if readonly:
        attrs.append("readonly")
    note = '<span class="field-note">Shown for reference only.</span>' if readonly else ""
    return f"<label>{_escape(label)}<input {' '.join(attrs)}>{note}</label>"


def _checkbox(name: str, label: str, checked: bool) -> str:
    return (
        '<label class="checkbox-row">'
        f'<input type="checkbox" name="{_escape(name)}" {"checked" if checked else ""}>'
        f"{_escape(label)}</label>"
    )


def _select(name: str, label: str, current: str, options: list[tuple[str, str]]) -> str:
    rendered = []
    for value, display in options:
        selected = " selected" if current == value else ""
        rendered.append(f'<option value="{_escape(value)}"{selected}>{_escape(display)}</option>')
    return f'<label>{_escape(label)}<select name="{_escape(name)}">{"".join(rendered)}</select></label>'


@lru_cache(maxsize=128)
def _load_model_metrics_cached(
    model_dir_parts: tuple[str, ...], mtime_ns: int
) -> dict[str, Any] | None:
    target = MODEL_OUTPUTS_ROOT.joinpath(*model_dir_parts, "metrics.json")
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_model_metrics(model_out_dir: str | Path) -> dict[str, Any] | None:
    try:
        model_dir_parts = _model_output_dir_parts(model_out_dir)
    except ValueError:
        return None
    target = MODEL_OUTPUTS_ROOT.joinpath(*model_dir_parts, "metrics.json")
    if not target.exists() or not target.is_file():
        return None
    try:
        stat = target.stat()
    except OSError:
        return None
    return _load_model_metrics_cached(model_dir_parts, stat.st_mtime_ns)


def _model_output_dir_parts(path: str | Path) -> tuple[str, ...]:
    raw_value = str(path).strip()
    if not raw_value:
        raise ValueError("Please choose a model output directory.")
    normalized = raw_value.replace("\\", "/")
    if normalized.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"Model output directories must stay under {MODEL_OUTPUTS_ROOT}.")
    parts = tuple(part for part in normalized.split("/") if part)
    if len(parts) <= len(MODEL_OUTPUTS_ROOT_PARTS):
        raise ValueError(f"Model output directories must stay under {MODEL_OUTPUTS_ROOT}.")
    if parts[: len(MODEL_OUTPUTS_ROOT_PARTS)] != MODEL_OUTPUTS_ROOT_PARTS:
        raise ValueError(f"Model output directories must stay under {MODEL_OUTPUTS_ROOT}.")
    suffix = parts[len(MODEL_OUTPUTS_ROOT_PARTS) :]
    if any(part in {".", ".."} or not MODEL_OUTPUT_SEGMENT_RE.fullmatch(part) for part in suffix):
        raise ValueError(f"Model output directories must stay under {MODEL_OUTPUTS_ROOT}.")
    return suffix


def _normalize_model_output_dir(path: str | Path) -> str:
    return str(Path(*MODEL_OUTPUTS_ROOT_PARTS, *_model_output_dir_parts(path)))


def _model_metrics_path(path: str | Path) -> Path:
    return MODEL_OUTPUTS_ROOT.joinpath(*_model_output_dir_parts(path), "metrics.json")


@lru_cache(maxsize=32)
def _discover_model_output_dirs_cached(
    base_dir_str: str, signature: tuple[tuple[str, int], ...]
) -> list[str]:
    found: list[str] = []
    for child_name, _mtime_ns in signature:
        found.append(str(Path(*MODEL_OUTPUTS_ROOT_PARTS, child_name)))
    return found


def _discover_model_output_dirs(base_dir: str | Path = "data/processed/models") -> list[str]:
    base = Path(base_dir)
    if not base.exists() or not base.is_dir():
        return []
    signature: list[tuple[str, int]] = []
    try:
        children = sorted(
            (child for child in base.iterdir() if child.is_dir()), key=lambda p: p.name
        )
    except OSError:
        return []
    for child in children:
        metrics_path = child / "metrics.json"
        if not metrics_path.exists() or not metrics_path.is_file():
            continue
        try:
            signature.append((child.name, metrics_path.stat().st_mtime_ns))
        except OSError:
            continue
    return _discover_model_output_dirs_cached(str(base.resolve()), tuple(signature))


def _model_dir_picker(name: str, label: str, value: Any, model_dir_options: list[str]) -> str:
    datalist_id = f"{name}-list"
    options_html = "".join(
        f'<option value="{_escape(path)}"></option>' for path in model_dir_options
    )
    note = (
        '<span class="field-note">Choose an existing model run directory with a <code>metrics.json</code>, or enter a new output directory for training.</span>'
        if model_dir_options
        else '<span class="field-note">No existing model runs were discovered yet. Enter a directory to save a new run.</span>'
    )
    return (
        f"<label>{_escape(label)}"
        f'<input type="text" name="{_escape(name)}" value="{_escape(value)}" placeholder="data/processed/models/baseline_6m" list="{_escape(datalist_id)}" autocomplete="off" spellcheck="false">'
        f'<datalist id="{_escape(datalist_id)}">{options_html}</datalist>'
        f"{note}</label>"
    )


def _validation_script(plugin_options: list[str], active_tab: str) -> str:
    if not plugin_options:
        plugin_payload = "[]"
    else:
        plugin_payload = json.dumps(plugin_options, ensure_ascii=False)
    return f"""
<script>
(() => {{
  const allowed = new Set({plugin_payload});
  for (const form of document.querySelectorAll('form')) {{
    const pluginInput = form.querySelector('[data-plugin-input="true"]');
    const strict = form.dataset.pluginStrict === 'true';
    const button = form.querySelector('button[type="submit"]');
    if (pluginInput && strict && allowed.size > 0) {{
      const sync = () => {{
        const value = pluginInput.value.trim();
        const valid = value.length > 0 && allowed.has(value);
        pluginInput.setCustomValidity(valid ? '' : 'Choose a plugin ID from the registry list.');
        if (button) button.disabled = !valid;
      }};
      pluginInput.addEventListener('input', sync);
      pluginInput.addEventListener('change', sync);
      sync();
    }}
  }}

}})();
</script>
"""


def _score_payload(result: ScoreResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["pretty_json"] = json.dumps(payload, indent=2, ensure_ascii=False)
    payload["pretty_features"] = json.dumps(payload["features"], indent=2, ensure_ascii=False)
    payload["data_files"] = _detect_available_files(result.plugin)
    return payload


def _get_ml_scorer(model_dir: str) -> MLScorer | None:
    """Load the ML scorer from *model_dir*, returning None if not yet trained."""
    try:
        return load_ml_scorer(model_dir)
    except FileNotFoundError:
        return None


def _ml_score_payload(result: MLScoreResult) -> dict:
    """Serialize an MLScoreResult for template rendering."""
    payload = result.to_dict()
    payload["probability_pct"] = f"{result.probability * 100:.1f}%"
    payload["pretty_json"] = json.dumps(
        {k: v for k, v in payload.items() if k != "feature_vector"},
        indent=2,
        ensure_ascii=False,
    )
    return payload


def _render_command_result(result: dict[str, Any] | None, title: str) -> str:
    if not result:
        return ""
    return (
        '<div class="result-stack">'
        f'<div class="panel"><h4>{_escape(title)} preview</h4><pre>{_escape(result["command"])}</pre></div>'
        '<div class="metrics-row">'
        f'<div class="metric"><span class="metric__label">Exit code</span><span class="metric__value">{_escape(result["exit_code"])}</span></div>'
        "</div>"
        f'<div class="panel"><h4>Console output</h4><pre>{_escape(result["output"] or "No stdout captured.")}</pre></div>'
        "</div>"
    )


def _render_ml_score_panel(ml: dict[str, Any]) -> str:
    """Render the ML score panel that sits below the heuristic score card."""
    risk_colors = {"Low": "pill--muted", "Medium": "pill--warn", "High": "pill--danger"}
    risk_pill_cls = risk_colors.get(ml.get("risk_category", ""), "pill--muted")

    drivers_html = ""
    for d in ml.get("drivers") or []:
        direction = d.get("direction", "neutral")
        icon = (
            "▲"
            if direction == "increases_risk"
            else ("▼" if direction == "decreases_risk" else "—")
        )
        color = (
            "color:#e05c5c"
            if direction == "increases_risk"
            else ("color:#5ce0a0" if direction == "decreases_risk" else "")
        )
        val = d.get("value")
        val_str = f"{val:.3g}" if val is not None else "n/a"
        drivers_html += (
            f'<li style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,.05)">'
            f'<span><span style="{color};font-weight:700;margin-right:.4rem">{_escape(icon)}</span><code>{_escape(d["name"])}</code></span>'
            f'<span class="muted" style="font-size:.85rem">{_escape(val_str)}</span>'
            f"</li>"
        )

    return (
        '<div class="result-stack">'
        '<div class="score-banner">'
        f'<div><p class="eyebrow">ML Score (experimental)</p><h3>{_escape(ml["plugin"])}</h3></div>'
        f'<div style="display:flex;align-items:center;gap:.75rem">'
        f'<div class="score-number">{_escape(ml["probability_pct"])}<span> advisory risk</span></div>'
        f'<span class="pill {risk_pill_cls}">{_escape(ml.get("risk_category", "?"))}</span>'
        "</div></div>"
        '<div class="metrics-row">'
        f'<div class="metric"><span class="metric__label">Probability</span><span class="metric__value">{_escape(str(ml["probability"]))}</span></div>'
        f'<div class="metric"><span class="metric__label">Risk category</span><span class="metric__value">{_escape(ml.get("risk_category", "?"))}</span></div>'
        f'<div class="metric"><span class="metric__label">Top drivers</span><span class="metric__value">{len(ml.get("drivers") or [])}</span></div>'
        "</div>"
        f'<div class="panel"><h4>Top contributing features</h4><ul style="list-style:none;padding:0;margin:0">{drivers_html}</ul></div>'
        f'<div class="panel"><h4>ML result (JSON)</h4><pre>{_escape(ml["pretty_json"])}</pre></div>'
        "</div>"
    )


def _render_score_section(
    values: dict[str, Any],
    plugin_options: list[str],
    score_result: dict[str, Any] | None,
    score_error: str | None,
    model_dir_options: list[str] | None = None,
) -> str:
    # Build model dropdown options — only include dirs that have a model.joblib
    from pathlib import Path as _Path

    ml_model_options: list[tuple[str, str]] = [("", "— none / heuristic only —")]
    for d in model_dir_options or []:
        if (_Path(d) / "model.joblib").exists():
            ml_model_options.append((d, _Path(d).name))

    parts = [
        '<div class="grid--score">',
        '<section class="card">',
        '<div class="card__header"><div><p class="eyebrow">Plugin scoring</p><h2>Score a plugin</h2><p class="kicker">Review the CANARY score, rationale, and supporting evidence.</p></div><span class="pill">Core workflow</span></div>',
        '<form method="post" action="/score" class="form-grid" data-plugin-strict="true">',
        '<input type="hidden" name="active_tab" value="score">',
        _plugin_picker("plugin", "Plugin ID", values["plugin"], plugin_options),
        _input_text("data_dir", "Data directory", values["data_dir"], readonly=True),
        _checkbox("real", "Prefer real advisory data", bool(values["real"])),
        _select("score_model_dir", "ML model", values.get("score_model_dir", ""), ml_model_options),
        '<button type="submit">Score plugin</button></form>',
    ]
    if score_error:
        parts.append(f'<div class="notice">{_escape(score_error)}</div>')
    parts.append("</section>")

    summary = '<p class="muted">Choose a plugin and run a score to see the rationale, features, and local supporting files.</p>'
    if score_result:
        reasons = "".join(f"<li>{_escape(reason)}</li>" for reason in score_result["reasons"])
        files_html = (
            '<ul class="bullet-list">'
            + "".join(
                f"<li><code>{_escape(path)}</code></li>" for path in score_result["data_files"]
            )
            + "</ul>"
            if score_result["data_files"]
            else '<p class="muted">No matching local files were found under <code>data/raw</code> for this plugin.</p>'
        )
        summary = (
            '<div class="result-stack">'
            f'<div class="score-banner"><div><p class="eyebrow">Heuristic score</p><h3>{_escape(score_result["plugin"])}</h3></div><div class="score-number">{_escape(score_result["score"])}<span>/100</span></div></div>'
            '<div class="metrics-row">'
            f'<div class="metric"><span class="metric__label">Reasons</span><span class="metric__value">{len(score_result["reasons"])}</span></div>'
            f'<div class="metric"><span class="metric__label">Feature keys</span><span class="metric__value">{len(score_result["features"])}</span></div>'
            f'<div class="metric"><span class="metric__label">Local files found</span><span class="metric__value">{len(score_result["data_files"])}</span></div>'
            "</div>"
            f'<div class="panel"><h4>Why this score</h4><ul class="bullet-list">{reasons}</ul></div>'
            '<div class="grid--two">'
            f'<div class="panel"><h4>Feature details</h4><pre>{_escape(score_result["pretty_features"])}</pre></div>'
            f'<div class="panel"><h4>JSON payload</h4><pre>{_escape(score_result["pretty_json"])}</pre></div>'
            "</div>"
            f'<div class="panel"><h4>Detected local data files</h4>{files_html}</div>'
            "</div>"
        )

    parts.append(
        f'<section class="card"><div class="card__header"><div><p class="eyebrow">Readable output</p><h2>Score details</h2></div><span class="pill pill--muted">Reasons + evidence</span></div>{summary}</section>'
    )

    # ML score panel — shown only when a trained model is available
    ml = (score_result or {}).get("ml")
    if ml:
        parts.append(
            '<section class="card"><div class="card__header"><div>'
            '<p class="eyebrow">Machine learning</p><h2>ML advisory risk score</h2>'
            '<p class="kicker">Probability of a Jenkins security advisory within the next 180 days, based on the trained CANARY model.</p>'
            '</div><span class="pill pill--muted">Experimental</span></div>'
            + _render_ml_score_panel(ml)
            + "</section>"
        )
    elif score_result is not None:
        parts.append(
            '<section class="card"><div class="card__header"><div>'
            '<p class="eyebrow">Machine learning</p><h2>ML advisory risk score</h2></div>'
            '<span class="pill pill--muted">Not available</span></div>'
            '<p class="muted" style="padding:1rem">No trained model found. Run <strong>canary train baseline</strong> to enable ML scoring.</p>'
            "</section>"
        )

    parts.append("</div>")
    return "".join(parts)


def _action_card(title: str, subtitle: str, form_html: str) -> str:
    return f'<section class="action-card"><h3>{_escape(title)}</h3><p>{_escape(subtitle)}</p>{form_html}</section>'


def _render_data_tab(
    values: dict[str, Any],
    plugin_options: list[str],
    data_result: dict[str, Any] | None,
    data_error: str | None,
) -> str:
    result_html = _render_command_result(data_result, "Action")
    parts = [
        '<div class="tab-summary card"><div class="card__header"><div><p class="eyebrow">Data pipeline</p><h2>Run a collection step</h2><p class="kicker">Run collection and preparation steps with a streamlined set of inputs while keeping standard output paths fixed.</p></div><span class="pill pill--muted">Pipeline actions</span></div></div>',
        '<div class="action-grid">',
    ]

    parts.append(
        _action_card(
            "Registry",
            "Refresh the Jenkins plugin universe snapshot.",
            '<form method="post" action="/run" class="form-grid form-grid--dense">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-registry">'
            f"{_input_text('page_size', 'Page size', values['page_size'])}"
            f"{_input_text('max_plugins', 'Max plugins', values['max_plugins'], 'optional')}"
            f"{_input_text('timeout_s', 'Timeout seconds', values['timeout_s'])}"
            f"{_checkbox('real', 'Use live registry data', bool(values['real']))}"
            '<button type="submit">Collect registry</button></form>',
        )
    )

    parts.append(
        _action_card(
            "Plugin snapshot",
            "Collect one plugin snapshot or bulk snapshots from the registry.",
            '<form method="post" action="/run" class="form-grid form-grid--dense" data-plugin-strict="false">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-plugin">'
            f"{_plugin_picker('plugin', 'Plugin ID (optional for single-plugin mode)', values['plugin'], plugin_options, note_mode='soft')}"
            f"{_input_text('repo_url', 'Repo URL override', values['repo_url'], 'https://github.com/jenkinsci/...')}"
            f"{_input_text('max_plugins', 'Max plugins', values['max_plugins'], 'optional')}"
            f"{_input_text('sleep', 'Sleep seconds', values['sleep'])}"
            f"{_checkbox('real', 'Use live snapshot data', bool(values['real']))}"
            f"{_checkbox('overwrite', 'Overwrite existing files', bool(values['overwrite']))}"
            '<button type="submit">Collect snapshot(s)</button></form>',
        )
    )

    parts.append(
        _action_card(
            "Advisories",
            "Collect advisories for one plugin or in bulk.",
            '<form method="post" action="/run" class="form-grid form-grid--dense" data-plugin-strict="false">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-advisories">'
            f"{_plugin_picker('plugin', 'Plugin ID (optional)', values['plugin'], plugin_options, note_mode='soft')}"
            f"{_input_text('max_plugins', 'Max plugins', values['max_plugins'], 'optional')}"
            f"{_input_text('sleep', 'Sleep seconds', values['sleep'])}"
            f"{_checkbox('real', 'Use live advisories', bool(values['real']))}"
            f"{_checkbox('overwrite', 'Overwrite existing files', bool(values['overwrite']))}"
            '<button type="submit">Collect advisories</button></form>',
        )
    )

    parts.append(
        _action_card(
            "GitHub",
            "Collect GitHub activity and repository metadata for a plugin.",
            '<form method="post" action="/run" class="form-grid form-grid--dense" data-plugin-strict="true">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-github">'
            f"{_plugin_picker('plugin', 'Plugin ID', values['plugin'], plugin_options)}"
            f"{_input_text('github_timeout_s', 'Timeout seconds', values['github_timeout_s'])}"
            f"{_input_text('github_max_pages', 'Max pages', values['github_max_pages'])}"
            f"{_input_text('github_commits_days', 'Commits lookback days', values['github_commits_days'])}"
            f"{_checkbox('overwrite', 'Overwrite existing files', bool(values['overwrite']))}"
            '<button type="submit">Collect GitHub data</button></form>',
        )
    )

    parts.append(
        _action_card(
            "Health score + enrich",
            "Refresh health score data or run the enrich batch flow.",
            '<div class="result-stack">'
            '<form method="post" action="/run" class="form-grid form-grid--dense">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-healthscore">'
            f"{_input_text('healthscore_timeout_s', 'Timeout seconds', values['healthscore_timeout_s'])}"
            f"{_checkbox('overwrite', 'Overwrite existing files', bool(values['overwrite']))}"
            '<button type="submit">Collect health scores</button></form>'
            '<form method="post" action="/run" class="form-grid form-grid--dense">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="collect-enrich">'
            f"{_select('only', 'Stage', values['only'], [('', 'Run all stages'), ('snapshot', 'snapshot'), ('advisories', 'advisories'), ('github', 'github'), ('healthscore', 'healthscore')])}"
            f"{_input_text('max_plugins', 'Max plugins', values['max_plugins'], 'optional')}"
            f"{_input_text('sleep', 'Sleep seconds', values['sleep'])}"
            f"{_checkbox('real', 'Use live data', bool(values['real']))}"
            '<button type="submit">Run enrich</button></form>'
            "</div>",
        )
    )

    parts.append(
        _action_card(
            "Monthly dataset build",
            "Prepare the dense monthly features and labeled rows that feed the ML baseline.",
            '<div class="result-stack">'
            '<form method="post" action="/run" class="form-grid form-grid--dense">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="build-monthly-features">'
            f"{_input_text('monthly_start', 'Start month', values['monthly_start'], input_type='month')}"
            f"{_input_text('monthly_end', 'End month', values['monthly_end'], input_type='month')}"
            f"{_input_text('monthly_out', 'JSONL output', values['monthly_out'], readonly=True)}"
            '<button type="submit">Build monthly features</button></form>'
            '<form method="post" action="/run" class="form-grid form-grid--dense">'
            '<input type="hidden" name="active_tab" value="data">'
            '<input type="hidden" name="command" value="build-monthly-labels">'
            f"{_input_text('labeled_in_path', 'Input features', values['labeled_in_path'], readonly=True)}"
            f"{_input_text('horizons', 'Horizons (months)', values['horizons'])}"
            f"{_input_text('labeled_out_path', 'Labeled output', values['labeled_out_path'], readonly=True)}"
            '<button type="submit">Build monthly labels</button></form>'
            "</div>",
        )
    )

    parts.append("</div>")
    if data_error:
        parts.append(f'<div class="notice">{_escape(data_error)}</div>')
    if result_html:
        parts.append(
            f'<section class="card"><div class="card__header"><div><p class="eyebrow">Latest action</p><h2>Console result</h2></div><span class="pill pill--muted">Exact CLI preview</span></div>{result_html}</section>'
        )
    return "".join(parts)


def _metric_value(value: Any, *, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _render_feature_columns_panel(feature_columns: Any) -> str:
    if not isinstance(feature_columns, list):
        return ""
    items = [item for item in feature_columns if isinstance(item, str) and item.strip()]
    if not items:
        return ""

    def _feature_li(feat: str) -> str:
        tip = _FEATURE_TIPS.get(feat, "")
        if tip:
            return (
                f'<li><span class="tip" data-tip="{_escape(tip)}">'
                f"<code>{_escape(feat)}</code>"
                f"</span></li>"
            )
        return f"<li><code>{_escape(feat)}</code></li>"

    list_html = "".join(_feature_li(item) for item in items)
    return (
        '<div class="feature-list-wrap">'
        "<h4>All feature columns</h4>"
        f'<ul class="feature-list">{list_html}</ul>'
        "</div>"
    )


_METRIC_TIPS: dict[str, str] = {
    "ROC AUC": (
        "Area Under the ROC Curve. Measures how well the model ranks positive cases above negative ones. "
        "0.5 = no better than random; 1.0 = perfect separation. "
        "When the positive class is rare, the Precision-Recall curve (Average Precision) is generally more informative."
    ),
    "Average Precision": (
        "Area under the Precision-Recall curve, summarising model quality across all classification thresholds. "
        "Preferred over ROC AUC when positive examples are a small fraction of the dataset, "
        "because it focuses on the model's ability to identify true positives without being inflated by the large number of true negatives."
    ),
    "Precision@K": (
        "Of the top K components ranked by predicted risk score, what fraction were actually labeled positive "
        "(i.e., received an advisory within the prediction horizon)? "
        "Directly measures triage utility: if a security team can only review K components per cycle, "
        "Precision@K tells them how often that review effort will be well-placed."
    ),
    "Base rate": (
        "The fraction of observations in the test set that are labeled positive (i.e., an advisory occurred "
        "within the prediction horizon). This is the baseline: a model that randomly flags components "
        "would achieve this precision by chance. Precision@K values should be interpreted relative to the base rate."
    ),
    "Recall (positive)": (
        "Of all components that actually received an advisory during the test window, "
        "what fraction did the model flag as high-risk? "
        "High recall means fewer missed advisories; lower recall means more vulnerable components go undetected."
    ),
    "Precision (positive)": (
        "Of all components the model predicted as high-risk, what fraction actually received an advisory? "
        "High precision means fewer false alarms; lower precision means more wasted review effort."
    ),
    "F1 (positive)": (
        "The harmonic mean of precision and recall for the positive class. "
        "Balances the trade-off between catching true advisories and avoiding false alarms. "
        "Can be misleading when classes are heavily imbalanced — "
        "a model that rarely predicts positive may have misleadingly high precision."
    ),
    "Support": (
        "The number of actual observations in this class within the test set. "
        "For the positive class this is the count of plugin-month records that received an advisory; "
        "for the negative class it is the count that did not. "
        "Support is fixed by the data — it does not depend on model predictions."
    ),
    "Positive coefficient": (
        "This feature's weight in the logistic regression model. "
        "A positive coefficient means the model associates higher values of this feature "
        "with a higher predicted probability of advisory occurrence. "
        "Magnitude indicates relative influence within the model."
    ),
    "Negative coefficient": (
        "This feature's weight in the logistic regression model. "
        "A negative coefficient means the model associates higher values of this feature "
        "with a lower predicted probability of advisory occurrence. "
        "Direction and magnitude should be interpreted alongside other features — "
        "correlated features can shift each other's coefficients."
    ),
    "XGBoost importance": (
        "Gain-based feature importance from the XGBoost model. "
        "Measures the average improvement in the loss function brought by splits on this feature, "
        "weighted by the number of observations affected. "
        "Higher importance means the feature contributed more to the model's splitting decisions. "
        "Unlike logistic coefficients, this does not indicate direction (higher or lower risk)."
    ),
    "Train rows": (
        "Total number of plugin-month records used to train the model. "
        "Each row represents one plugin observed in one calendar month. "
        "Rows from months before the test start date are used for training."
    ),
    "Test rows": (
        "Total number of plugin-month records in the held-out test set. "
        "These are records from months at or after the test start date "
        "and were not seen by the model during training. "
        "All evaluation metrics are computed on this set."
    ),
    "True negative": (
        "The model predicted 'not vulnerable' and the component was indeed not associated "
        "with an advisory during the prediction horizon. A correct negative prediction."
    ),
    "False positive": (
        "The model predicted 'vulnerable' but no advisory was published for this component "
        "during the prediction horizon. Also called a false alarm — "
        "a security team acting on this would review a component that turned out to be fine."
    ),
    "False negative": (
        "The model predicted 'not vulnerable' but an advisory was actually published "
        "during the prediction horizon. A missed detection — "
        "the riskiest type of error for a proactive risk-scoring use case."
    ),
    "True positive": (
        "The model predicted 'vulnerable' and an advisory was indeed published "
        "for this component during the prediction horizon. A correct positive prediction — "
        "the model successfully flagged a component that warranted attention."
    ),
}

_MODEL_LABELS: dict[str, tuple[str, str]] = {
    "logistic": ("Logistic Regression", ""),
    "xgboost": ("XGBoost", "model-badge--xgb"),
    "lightgbm": ("LightGBM", "model-badge--lgb"),
}

# Feature descriptions: what the feature measures and why it was collected,
# based on the literature motivating its inclusion. No results-based judgements.
_FEATURE_TIPS: dict[str, str] = {
    # ── Advisory history ────────────────────────────────────────────────────
    "advisories_last_365d": (
        "Count of Jenkins security advisories published for this plugin in the 365 days prior to the observation date. "
        "Included because recent advisory history is a direct measure of past security exposure, "
        "which the vulnerability recidivism literature (e.g. Ozment & Schechter, 2006) links to future risk."
    ),
    "advisories_present_any": (
        "Binary indicator: has this plugin ever appeared in a Jenkins security advisory before the observation date? "
        "Included to capture whether a plugin has any prior security disclosure history at all, "
        "independent of frequency."
    ),
    "advisory_count_to_date": (
        "Cumulative count of Jenkins security advisories for this plugin up to the observation date. "
        "Included because prior advisory frequency is a standard predictor in vulnerability recidivism research "
        "(Ozment & Schechter, 2006; Frei et al., 2010)."
    ),
    "advisory_cve_count_to_date": (
        "Count of CVE identifiers associated with this plugin's advisories up to the observation date. "
        "Included to distinguish advisories that resulted in formal CVE assignments, "
        "which may indicate more severe or externally verified vulnerabilities."
    ),
    "advisory_cvss_ge_7_count_to_date": (
        "Count of advisories with a CVSS base score of 7.0 or higher up to the observation date. "
        "Included to capture exposure to high-severity vulnerabilities, "
        "following CVSS severity thresholds used in NVD classification."
    ),
    "advisory_days_since_first_to_date": (
        "Days between the plugin's first ever Jenkins security advisory and the observation date. "
        "Included as a proxy for how long a plugin has been in the advisory-publication ecosystem; "
        "longer exposure windows provide more historical signal."
    ),
    "advisory_days_since_latest_to_date": (
        "Days since the most recent Jenkins security advisory for this plugin, as of the observation date. "
        "Included to capture recency of security activity; "
        "recent advisories may indicate ongoing maintenance attention to security issues."
    ),
    "advisory_max_cvss_to_date": (
        "Highest CVSS base score observed across all advisories for this plugin up to the observation date. "
        "Included because maximum severity may reflect the attack surface or code complexity "
        "that could predispose a plugin to future vulnerabilities."
    ),
    "advisory_mean_cvss_to_date": (
        "Mean CVSS base score across all advisories for this plugin up to the observation date. "
        "Included to characterise the typical severity of past vulnerabilities, "
        "complementing the maximum severity measure."
    ),
    "advisory_span_days_to_date": (
        "Number of days between the first and most recent advisory for this plugin, up to the observation date. "
        "Included to measure how long a plugin has had an ongoing security disclosure history; "
        "a longer span may indicate sustained vulnerability introduction over time."
    ),
    # ── GH Archive: activity volume ─────────────────────────────────────────
    "gharchive_events_total": (
        "Total GitHub event count for this repository in the current observation month, derived from GH Archive. "
        "Included as a broad measure of project activity level, motivated by MSR research "
        "linking activity signals to software health (Gousios et al., 2014)."
    ),
    "gharchive_events_total_trailing_3m": (
        "Total GitHub events in the three months prior to the observation month. "
        "Included to capture short-term activity trends that may not be visible in single-month counts."
    ),
    "gharchive_events_total_trailing_6m": (
        "Total GitHub events in the six months prior to the observation month. "
        "Included alongside the 3-month window to distinguish sustained activity from recent bursts."
    ),
    "gharchive_human_events": (
        "GitHub events attributed to human (non-bot) actors in the current observation month. "
        "Included to separate genuine developer activity from automated processes, "
        "following Jordan & Chen (2025) on developer telemetry."
    ),
    "gharchive_human_events_trailing_3m": (
        "Human-attributed GitHub events in the three months prior to the observation month."
    ),
    "gharchive_human_events_trailing_6m": (
        "Human-attributed GitHub events in the six months prior to the observation month."
    ),
    "gharchive_bot_events": (
        "GitHub events attributed to bots in the current observation month. "
        "Included to measure automation activity such as dependency updates and CI, "
        "which Alfadel et al. (2023) link to reduced vulnerability exposure windows."
    ),
    "gharchive_bot_events_trailing_3m": (
        "Bot-attributed GitHub events in the three months prior to the observation month."
    ),
    "gharchive_bot_events_trailing_6m": (
        "Bot-attributed GitHub events in the six months prior to the observation month."
    ),
    "gharchive_bot_event_ratio_3m": (
        "Fraction of recent events attributed to bots over the trailing 3 months. "
        "Included to characterise how much of a project's activity is automated vs. human-driven."
    ),
    # ── GH Archive: staleness / recency ─────────────────────────────────────
    "gharchive_days_active": (
        "Number of distinct days with any GitHub activity in the current observation month. "
        "Included as a regularity signal — evenly distributed activity may indicate consistent maintenance."
    ),
    "gharchive_days_active_trailing_3m": ("Distinct active days over the trailing 3-month window."),
    "gharchive_days_active_trailing_6m": ("Distinct active days over the trailing 6-month window."),
    "gharchive_active_month_ratio_3m": (
        "Fraction of the past 3 months in which any GitHub activity was observed. "
        "Included as a maintenance regularity proxy — gaps may indicate reduced oversight."
    ),
    "gharchive_active_month_ratio_6m": (
        "Fraction of the past 6 months in which any GitHub activity was observed. "
        "Included alongside the 3-month window to capture longer-term maintenance patterns."
    ),
    "gharchive_activity_burstiness_6m": (
        "Ratio of peak-month activity to average monthly activity over the past 6 months. "
        "Included to detect sprint-then-stall development patterns, "
        "which may indicate irregular maintenance (Prana et al., 2021)."
    ),
    "gharchive_months_since_any_activity": (
        "Months elapsed since any GitHub event was observed for this repository. "
        "Included as a staleness indicator; prolonged inactivity may signal project abandonment "
        "(Panter & Eisty, 2026; Xu et al., 2025)."
    ),
    "gharchive_months_since_push": (
        "Months since the last push event. "
        "Included because push frequency is a core maintenance signal; "
        "infrequent pushes are cited as a risk indicator in Prana et al. (2021)."
    ),
    "gharchive_months_since_release": (
        "Months since the last GitHub release event. "
        "Included because release cadence is linked to patch delivery timeliness, "
        "a key factor in vulnerability remediation research (Alexopoulos et al., 2022)."
    ),
    "gharchive_months_since_release_tag": (
        "Months since the last tag-create event associated with a release. "
        "Included as a complementary release recency signal using tag-based versioning."
    ),
    "gharchive_months_since_issue": (
        "Months since the last issue-related event. "
        "Included to capture responsiveness to user-reported problems."
    ),
    "gharchive_months_since_pr": (
        "Months since the last pull request event. "
        "Included as a proxy for how recently the project has undergone code review activity."
    ),
    "gharchive_source_window_count": (
        "Number of calendar months for which GH Archive data is available for this repository. "
        "Included to account for data coverage — repositories with sparse archival may appear inactive."
    ),
    "gharchive_sample_percent": (
        "Estimated fraction of GH Archive data available for this repository and window. "
        "Included as a data quality indicator; low values may indicate incomplete event coverage."
    ),
    "gharchive_present": (
        "Binary indicator: was any GH Archive data found for this repository? "
        "Included to distinguish repositories with no archival coverage from those with measured zero activity."
    ),
    # ── GH Archive: contributors / actors ───────────────────────────────────
    "gharchive_unique_actors": (
        "Distinct GitHub actor identities (human and bot) observed in the current observation month. "
        "Included as a contributor breadth measure; "
        "contributor diversity is linked to both software quality and defect introduction (Meneely et al., 2014)."
    ),
    "gharchive_unique_actors_trailing_3m": (
        "Distinct GitHub actors over the trailing 3-month window."
    ),
    "gharchive_unique_actors_trailing_6m": (
        "Distinct GitHub actors over the trailing 6-month window."
    ),
    "gharchive_unique_human_actors": (
        "Distinct human (non-bot) GitHub actors in the current observation month. "
        "Included to measure genuine developer participation separate from automation."
    ),
    "gharchive_unique_human_actors_trailing_3m": (
        "Distinct human GitHub actors over the trailing 3-month window."
    ),
    "gharchive_unique_human_actors_trailing_6m": (
        "Distinct human GitHub actors over the trailing 6-month window. "
        "Included because sustained contributor diversity over a longer window "
        "may reflect a project's ongoing community engagement."
    ),
    "gharchive_actors_per_active_day_3m": (
        "Average number of distinct actors per active day over the trailing 3 months. "
        "Included as a density measure — high values may indicate concentrated burst activity."
    ),
    "gharchive_actors_per_active_day_6m": (
        "Average number of distinct actors per active day over the trailing 6 months."
    ),
    "gharchive_owner_push_fraction": (
        "Fraction of push events attributed to the most active single human pusher. "
        "Included as a key-person risk (bus factor) indicator; "
        "high concentration is linked to project fragility (Yamashita et al., 2015)."
    ),
    "gharchive_events_per_active_month_6m": (
        "Average events per active month over the trailing 6-month window. "
        "Included to normalise total activity by the number of active months, "
        "distinguishing sustained activity from single-month bursts."
    ),
    # ── GH Archive: pull requests ────────────────────────────────────────────
    "gharchive_pull_request_events": (
        "Pull request events in the current observation month. "
        "Included as a measure of code review workflow activity; "
        "PR-based development is associated with higher code review discipline (Thompson, 2017)."
    ),
    "gharchive_pull_request_events_trailing_3m": (
        "Pull request events over the trailing 3-month window."
    ),
    "gharchive_pull_request_events_trailing_6m": (
        "Pull request events over the trailing 6-month window."
    ),
    "gharchive_pull_request_events_trailing_3m_delta_prev_3m": (
        "Change in PR event volume between the most recent 3-month window and the prior 3-month window. "
        "Included to detect trends in review activity — rising or falling PR rates may signal process changes."
    ),
    "gharchive_pull_request_closed_events": (
        "Pull requests closed in the current observation month. "
        "Included as a throughput indicator for the code review and integration process."
    ),
    "gharchive_pull_request_closed_events_trailing_3m": (
        "Pull requests closed over the trailing 3-month window."
    ),
    "gharchive_pull_request_closed_events_trailing_6m": (
        "Pull requests closed over the trailing 6-month window."
    ),
    "gharchive_pull_request_merged_events": (
        "Pull requests merged in the current observation month. "
        "Included to measure accepted code integration, distinct from closed-without-merge."
    ),
    "gharchive_pull_request_merged_events_trailing_3m": (
        "Pull requests merged over the trailing 3-month window."
    ),
    "gharchive_pull_request_merged_events_trailing_6m": (
        "Pull requests merged over the trailing 6-month window."
    ),
    "gharchive_pull_request_review_events": (
        "PR review events in the current observation month. "
        "Included as a direct measure of code review activity; "
        "review intensity is linked to defect and vulnerability outcomes (Meneely et al., 2014)."
    ),
    "gharchive_pull_request_review_events_trailing_3m": (
        "PR review events over the trailing 3-month window."
    ),
    "gharchive_pull_request_review_events_trailing_6m": (
        "PR review events over the trailing 6-month window."
    ),
    "gharchive_pr_close_rate_3m": (
        "Fraction of opened pull requests that were closed over the trailing 3 months. "
        "Included as a triage efficiency indicator."
    ),
    "gharchive_pr_close_rate_6m": (
        "Fraction of opened pull requests that were closed over the trailing 6 months."
    ),
    "gharchive_merge_rate_3m": (
        "Fraction of closed pull requests that were merged over the trailing 3 months. "
        "Included to distinguish accepted code changes from rejected or abandoned PRs."
    ),
    "gharchive_merge_rate_6m": (
        "Fraction of closed pull requests that were merged over the trailing 6 months."
    ),
    "gharchive_pr_review_intensity_3m": (
        "Average review events per pull request over the trailing 3 months. "
        "Included as a proxy for depth of code scrutiny per change."
    ),
    "gharchive_pr_review_intensity_6m": (
        "Average review events per pull request over the trailing 6 months."
    ),
    "gharchive_prs_per_push_3m": (
        "Ratio of PR events to push events over the trailing 3 months. "
        "Included to characterise how much of the project's code flow is review-gated vs. direct."
    ),
    "gharchive_prs_per_push_6m": ("Ratio of PR events to push events over the trailing 6 months."),
    "gharchive_pr_merge_time_p50_hours": (
        "Median time in hours from PR open to merge. "
        "Included because review latency is linked to code integration quality (Zhang et al., 2021)."
    ),
    "gharchive_pr_merge_time_p90_hours": (
        "90th-percentile time from PR open to merge. "
        "Included to capture the slow tail of the review process — long delays may indicate bottlenecks."
    ),
    # ── GH Archive: pushes ───────────────────────────────────────────────────
    "gharchive_push_events": (
        "Push events in the current observation month. "
        "Included as a measure of code change volume; "
        "code churn is one of the earliest proposed vulnerability predictors (Shin et al., 2011)."
    ),
    "gharchive_push_events_trailing_3m": ("Push events over the trailing 3-month window."),
    "gharchive_push_events_trailing_6m": ("Push events over the trailing 6-month window."),
    "gharchive_push_events_trailing_3m_delta_prev_3m": (
        "Change in push event volume between the most recent 3-month window and the prior 3-month window. "
        "Included to detect acceleration or deceleration in code change activity."
    ),
    # ── GH Archive: issues ───────────────────────────────────────────────────
    "gharchive_issues_events": (
        "Issue-related events in the current observation month. "
        "Included as a measure of community engagement and bug/feature intake."
    ),
    "gharchive_issues_events_trailing_3m": ("Issue events over the trailing 3-month window."),
    "gharchive_issues_events_trailing_6m": ("Issue events over the trailing 6-month window."),
    "gharchive_issues_closed_events": (
        "Issues closed in the current observation month. "
        "Included as a responsiveness indicator — how quickly reported problems are addressed."
    ),
    "gharchive_issues_closed_events_trailing_3m": (
        "Issues closed over the trailing 3-month window."
    ),
    "gharchive_issues_closed_events_trailing_6m": (
        "Issues closed over the trailing 6-month window."
    ),
    "gharchive_issue_close_rate_3m": (
        "Fraction of issues closed relative to opened over the trailing 3 months. "
        "Included as a maintainer responsiveness measure."
    ),
    "gharchive_issue_close_rate_6m": (
        "Fraction of issues closed relative to opened over the trailing 6 months."
    ),
    "gharchive_issue_close_time_p50_hours": (
        "Median time from issue open to close. "
        "Included because issue resolution latency reflects maintainer responsiveness."
    ),
    "gharchive_issue_close_time_p90_hours": (
        "90th-percentile issue resolution time. "
        "Included to capture slow-tail responsiveness — some issues may remain open very long."
    ),
    # ── GH Archive: releases / tags ─────────────────────────────────────────
    "gharchive_release_events": (
        "GitHub release publication events in the current observation month. "
        "Included because release cadence is linked to patch delivery (Alexopoulos et al., 2022)."
    ),
    "gharchive_release_events_trailing_3m": ("Release events over the trailing 3-month window."),
    "gharchive_release_events_trailing_6m": ("Release events over the trailing 6-month window."),
    "gharchive_release_events_trailing_3m_delta_prev_3m": (
        "Change in release event volume between the most recent and prior 3-month windows."
    ),
    "gharchive_releases_per_active_month_6m": (
        "Average release events per active month over the trailing 6 months. "
        "Included to normalise release frequency by actual activity, not calendar time."
    ),
    "gharchive_tag_create_events": (
        "Tag-create events in the current observation month. "
        "Included as a complementary versioning signal to formal GitHub releases."
    ),
    "gharchive_tag_create_events_trailing_3m": (
        "Tag-create events over the trailing 3-month window."
    ),
    "gharchive_tag_create_events_trailing_6m": (
        "Tag-create events over the trailing 6-month window."
    ),
    # ── GH Archive: branches ─────────────────────────────────────────────────
    "gharchive_branch_create_events": (
        "Branch creation events in the current observation month. "
        "Included as an indicator of parallel development activity."
    ),
    "gharchive_branch_create_events_trailing_3m": (
        "Branch creation events over the trailing 3-month window."
    ),
    "gharchive_branch_create_events_trailing_6m": (
        "Branch creation events over the trailing 6-month window."
    ),
    # ── GH Archive: forks / stars ────────────────────────────────────────────
    "gharchive_fork_events": (
        "Fork events in the current observation month. "
        "Included as a proxy for downstream adoption; "
        "widely-forked projects may have larger exposure surfaces."
    ),
    "gharchive_fork_events_trailing_3m": ("Fork events over the trailing 3-month window."),
    "gharchive_fork_events_trailing_6m": ("Fork events over the trailing 6-month window."),
    "gharchive_forks_trailing_6m": ("Cumulative fork count over the trailing 6-month window."),
    "gharchive_watch_events": (
        "Watch/star events in the current observation month. "
        "Included as a community interest proxy; Siavvas et al. (2018) examined popularity as a risk signal."
    ),
    "gharchive_watch_events_trailing_3m": ("Watch/star events over the trailing 3-month window."),
    "gharchive_watch_events_trailing_6m": ("Watch/star events over the trailing 6-month window."),
    "gharchive_watch_events_trailing_3m_delta_prev_3m": (
        "Change in watch/star events between the most recent and prior 3-month windows."
    ),
    "gharchive_stars_trailing_6m": (
        "Cumulative star count over the trailing 6-month window. "
        "Included as a popularity measure complementing watch events."
    ),
    # ── GH Archive: security / dependency keywords ───────────────────────────
    "gharchive_security_keyword_events": (
        "PR and issue events containing security-related keywords in the current observation month. "
        "Included because security-related textual cues in development artifacts "
        "can precede formal vulnerability disclosure (Goldman & Kadkoda, 2023)."
    ),
    "gharchive_security_keyword_events_trailing_3m": (
        "Security-keyword events over the trailing 3-month window."
    ),
    "gharchive_security_keyword_events_trailing_6m": (
        "Security-keyword events over the trailing 6-month window."
    ),
    "gharchive_security_keyword_events_trailing_3m_delta_prev_3m": (
        "Change in security-keyword event volume between the most recent and prior 3-month windows."
    ),
    "gharchive_security_keyword_rate_3m": (
        "Security-keyword events as a fraction of total PR and issue events over the trailing 3 months. "
        "Included to normalise security discussion by overall activity level."
    ),
    "gharchive_months_since_security_keyword": (
        "Months elapsed since the last security-keyword PR or issue event. "
        "Included to capture recency of visible security-related discussion."
    ),
    "gharchive_hotfix_keyword_events": (
        "PR and issue events containing hotfix-related keywords in the current observation month. "
        "Included to detect emergency patch activity, which may signal unplanned security responses."
    ),
    "gharchive_hotfix_keyword_events_trailing_3m": (
        "Hotfix-keyword events over the trailing 3-month window."
    ),
    "gharchive_hotfix_keyword_events_trailing_6m": (
        "Hotfix-keyword events over the trailing 6-month window."
    ),
    "gharchive_dependency_bump_events": (
        "PR and issue events related to dependency version updates in the current observation month. "
        "Included because proactive dependency management is linked to reduced vulnerability exposure "
        "(Alfadel et al., 2023; Prana et al., 2021)."
    ),
    "gharchive_dependency_bump_events_trailing_3m": (
        "Dependency update events over the trailing 3-month window."
    ),
    "gharchive_dependency_bump_events_trailing_6m": (
        "Dependency update events over the trailing 6-month window."
    ),
    # ── Software Heritage: repository structure / governance ─────────────────
    "swh_origin_found": (
        "Whether a Software Heritage origin record was found for this repository. "
        "Included to distinguish repositories with archival coverage from those without, "
        "since missing records may indicate an unrecognised or very new repository."
    ),
    "swh_has_snapshot_to_date": (
        "Whether at least one Software Heritage snapshot exists for this repository "
        "as of the observation date. "
        "Included to confirm that archival coverage is present for the historical window being studied."
    ),
    "swh_present_any": (
        "Whether any Software Heritage data was retrieved for this repository. "
        "Included as a data availability flag; absence may indicate the repository was not crawled."
    ),
    "swh_visit_count_to_date": (
        "Number of Software Heritage archival visits recorded for this repository up to the observation date. "
        "Included as a proxy for how frequently the archive has crawled this project."
    ),
    "swh_visits_last_365d": (
        "Number of Software Heritage visits in the 365 days prior to the observation date. "
        "Included to capture recent archival activity."
    ),
    "swh_visits_this_month": (
        "Software Heritage visits recorded in the observation month. "
        "Included as a recency indicator of archival coverage."
    ),
    "swh_archive_age_days_to_date": (
        "Days since the first Software Heritage visit, up to the observation date. "
        "Included as a proxy for how long this repository has been publicly visible and archived."
    ),
    "swh_top_level_entry_count": (
        "Number of entries (files and directories) at the root of the archived repository. "
        "Included as a rough proxy for project structure complexity."
    ),
    "swh_has_readme": (
        "Whether a README file is present in the archived repository root. "
        "Included because basic documentation presence is an indicator of project maturity "
        "and contributor onboarding (Ayala et al., 2025)."
    ),
    "swh_has_security_md": (
        "Whether a SECURITY.md file is present, indicating a formal security disclosure policy. "
        "Included because security contact visibility is a recommended OSS security practice "
        "(OpenSSF Scorecard; Zahan et al., 2023)."
    ),
    "swh_has_contributing_md": (
        "Whether a CONTRIBUTING.md file is present, documenting contribution guidelines. "
        "Included as an indicator of governance maturity and contributor onboarding process."
    ),
    "swh_has_changelog": (
        "Whether a changelog file is present. "
        "Included because explicit change tracking is associated with release discipline "
        "and transparency in software projects."
    ),
    "swh_has_dot_github": (
        "Whether a .github/ directory is present, typically containing issue templates, "
        "PR templates, or workflow configurations. "
        "Included as an indicator of GitHub-native project governance tooling adoption."
    ),
    "swh_has_github_actions": (
        "Whether GitHub Actions workflow configuration is present. "
        "Included because CI/CD adoption is a security best practice measured by frameworks "
        "such as OpenSSF Scorecard (Zahan et al., 2023)."
    ),
    "swh_has_dependabot": (
        "Whether Dependabot configuration is present, enabling automated dependency update PRs. "
        "Included because automated dependency management is linked to shorter vulnerability "
        "exposure windows (Alfadel et al., 2023)."
    ),
    "swh_has_jenkinsfile": (
        "Whether a Jenkinsfile is present, indicating CI pipeline configuration via Jenkins. "
        "Included because build pipeline definition is a proxy for build reproducibility and automation maturity."
    ),
    "swh_has_travis_yml": (
        "Whether a Travis CI configuration file is present. "
        "Included as an indicator of CI adoption; predates GitHub Actions and common in older OSS projects."
    ),
    "swh_has_pom_xml": (
        "Whether a Maven pom.xml build file is present. "
        "Included because Maven is the standard build system for Jenkins plugins; "
        "presence indicates adherence to ecosystem conventions."
    ),
    "swh_has_build_gradle": (
        "Whether a Gradle build file is present. "
        "Included as an alternative build tooling indicator; "
        "some Jenkins plugins use Gradle instead of or alongside Maven."
    ),
    "swh_has_mvn_wrapper": (
        "Whether a Maven wrapper (mvnw) is present. "
        "Included as a proxy for build reproducibility — "
        "the wrapper pins the Maven version used to build the project."
    ),
    "swh_has_dockerfile": (
        "Whether a Dockerfile is present. "
        "Included as a proxy for containerisation and reproducible environment practices."
    ),
    "swh_has_tests_directory": (
        "Whether a test directory is present in the archived repository. "
        "Included because the presence of automated tests is associated with software quality "
        "and defect detection (Bassi & Singh, 2025)."
    ),
    "swh_has_sonar_config": (
        "Whether a SonarQube/SonarCloud configuration file is present. "
        "Included as a proxy for static analysis tooling adoption, "
        "which is associated with proactive quality and security checking."
    ),
    "swh_has_snyk_config": (
        "Whether a Snyk configuration file is present, indicating dependency vulnerability scanning. "
        "Included because dependency scanning tools are part of recommended supply-chain security practices."
    ),
    # ── Software Heritage: commit-level signals ───────────────────────────────
    "swh_commit_count": (
        "Total number of commits visible in the archived repository snapshot. "
        "Included as a proxy for project maturity and accumulated change history."
    ),
    "swh_days_since_last_commit": (
        "Days between the most recent commit in the archived snapshot and the archive visit date. "
        "Included because commit staleness is a primary maintenance health signal "
        "(Panter & Eisty, 2026)."
    ),
    "swh_author_committer_lag_p50_hours": (
        "Median time in hours between the commit author date and the committer date across all commits. "
        "Included as a proxy for the review or integration lag in the development pipeline; "
        "a gap may indicate that commits pass through a separate integration step (Zhang et al., 2021)."
    ),
    "swh_author_committer_lag_p90_hours": (
        "90th-percentile author-to-committer lag across commits. "
        "Included to capture the slow tail of the integration pipeline."
    ),
    "swh_author_committer_mismatch_rate": (
        "Fraction of commits where the author and committer identities differ. "
        "Included as a heuristic indicator of a review or merge workflow where "
        "someone other than the original author integrates the change."
    ),
    "swh_timezone_diversity": (
        "Number of distinct UTC offset values observed across commit authors. "
        "Included as a proxy for geographic distribution of contributors; "
        "distributed teams may have different coordination dynamics (Claes et al., 2018)."
    ),
    "swh_weekend_commit_fraction": (
        "Fraction of commits authored on weekends. "
        "Included because work timing patterns may reflect volunteer vs. institutional development dynamics; "
        "Claes et al. (2018) and Eyolfson et al. (2011) examine timing as a process signal."
    ),
    "swh_late_night_commit_fraction": (
        "Fraction of commits authored during late-night hours. "
        "Included as an exploratory process signal; "
        "Eyolfson et al. (2011) found timing patterns correlated with commit bugginess in some contexts."
    ),
    "swh_merge_commit_fraction": (
        "Fraction of commits that are merge commits. "
        "Included as a proxy for PR-based or branch-based integration workflows."
    ),
    "swh_conventional_commit_fraction": (
        "Fraction of commit messages following the Conventional Commits specification. "
        "Included as a commit discipline indicator; "
        "structured commit messages are associated with changelog quality and release tooling adoption."
    ),
    "swh_issue_reference_rate": (
        "Fraction of commit messages containing an issue number reference (e.g., #123). "
        "Included as a traceability signal — linking commits to issues indicates structured change management "
        "(Li & Ahmed, 2023)."
    ),
    "swh_empty_message_rate": (
        "Fraction of commits with empty or near-empty commit messages. "
        "Included because low commit message quality is associated with reduced traceability "
        "and weaker peer review practices (Li & Ahmed, 2023)."
    ),
    "swh_security_fix_commit_count": (
        "Count of commits whose messages contain security-fix-related keywords (e.g., 'CVE', 'security fix', 'patch'). "
        "Included because security-fix language in commit history may indicate prior vulnerability remediation activity "
        "(Goldman & Kadkoda, 2023; Sabetta & Bezzi, 2018)."
    ),
    # ── Window / temporal ────────────────────────────────────────────────────
    "window_index": (
        "Sequential integer index of the observation month across the full dataset timeline. "
        "Included to allow the model to account for temporal trends across the observation period."
    ),
    "window_month": (
        "Calendar month number (1–12) of the observation window. "
        "Included to capture potential seasonal patterns in advisory publication or repository activity."
    ),
    "window_year": (
        "Calendar year of the observation window. "
        "Included to allow the model to account for year-over-year trends in the Jenkins ecosystem."
    ),
}


def _tip(label: str, tip_key: str | None = None) -> str:
    """Wrap a label in a tooltip span if a tip exists for it."""
    tip = _METRIC_TIPS.get(tip_key or label, "")
    if not tip:
        return _escape(label)
    return f'<span class="tip" data-tip="{_escape(tip)}">{_escape(label)}</span>'


def _render_model_badge(model_name: str | None) -> str:
    if not model_name:
        return ""
    label, extra_class = _MODEL_LABELS.get(model_name.lower(), (model_name.upper(), ""))
    return f'<span class="model-badge {extra_class}">{_escape(label)}</span>'


def _render_base_rate_bar(test_positive: int | None, test_total: int | None) -> str:
    if not test_positive or not test_total:
        return ""
    rate = test_positive / test_total
    pct = rate * 100
    fill_pct = min(pct * 8, 100)  # scale up so ~2% is visible
    return (
        '<div class="baserate-row">'
        f'<span class="baserate-label">{_tip("Base rate", "Base rate")} (test set)</span>'
        '<div class="baserate-track">'
        f'<div class="baserate-fill" style="width:{fill_pct:.1f}%"></div>'
        "</div>"
        f'<span class="baserate-val">{pct:.2f}% ({test_positive:,} of {test_total:,})</span>'
        "</div>"
    )


def _render_ranking_row(ranking: dict[str, Any], base_rate: float) -> str:
    ks = [10, 25, 50, 100]
    cells = []
    for k in ks:
        val = _float_or_none(ranking.get(f"precision_at_{k}"))
        if val is None:
            continue
        lift = (val / base_rate) if base_rate > 0 else 0
        if val >= 0.5:
            cls = "rank-cell__val--good"
        elif val > base_rate * 2:
            cls = "rank-cell__val--warn"
        else:
            cls = "rank-cell__val--muted"
        lift_str = f"{lift:.1f}× base rate" if lift >= 1 else "≤ base rate"
        cells.append(
            f'<div class="rank-cell">'
            f'<div class="rank-cell__k">{_tip("Precision@K", "Precision@K")} @ {k}</div>'
            f'<div class="rank-cell__val {cls}">{val:.0%}</div>'
            f'<div class="rank-cell__lift">{lift_str}</div>'
            "</div>"
        )
    if not cells:
        return ""
    return (
        "<div>"
        '<h4 style="margin-bottom:.5rem">Ranking precision (top-K)</h4>'
        f'<div class="ranking-row">{"".join(cells)}</div>'
        '<p style="font-size:.82rem;color:var(--muted);margin-top:.5rem">'
        "Of the top K plugins ranked by predicted risk, what fraction received an advisory in the test window?"
        "</p>"
        "</div>"
    )


def _render_class_report(report: dict[str, Any] | None, is_xgb: bool) -> str:
    if not report:
        return ""
    pos_raw = report.get("1")
    neg_raw = report.get("0")
    pos: dict[str, Any] = cast("dict[str, Any]", pos_raw) if isinstance(pos_raw, dict) else {}
    neg: dict[str, Any] = cast("dict[str, Any]", neg_raw) if isinstance(neg_raw, dict) else {}

    def fmt(v: Any) -> str:
        value = _float_or_none(v)
        if value is None:
            return "—"
        return f"{value:.3f}"

    def fmt_support(v: Any) -> str:
        value = _int_or_none(v)
        if value is None:
            return "—"
        return f"{value:,}"

    rows = [
        (
            "Not vulnerable (0)",
            neg.get("precision"),
            neg.get("recall"),
            neg.get("f1-score"),
            neg.get("support"),
        ),
        (
            "Vulnerable (1)",
            pos.get("precision"),
            pos.get("recall"),
            pos.get("f1-score"),
            pos.get("support"),
        ),
    ]
    tbody = "".join(
        f"<tr>"
        f"<td>{_escape(str(label))}</td>"
        f"<td>{fmt(p)}</td>"
        f"<td>{fmt(r)}</td>"
        f"<td>{fmt(f1)}</td>"
        f"<td>{fmt_support(sup)}</td>"
        "</tr>"
        for label, p, r, f1, sup in rows
    )
    note = (
        '<p style="font-size:.82rem;color:var(--muted);margin-top:.5rem">'
        "Focus on the <strong>Vulnerable (1)</strong> row — the negative class metrics look good because the model mostly predicts 'not vulnerable' by default."
        "</p>"
    )
    return (
        f'<div class="panel"><h4>Per-class classification report</h4>'
        f'<table class="cls-table">'
        f"<thead><tr>"
        f"<th>Class</th>"
        f"<th>{_tip('Precision', 'Precision (positive)')}</th>"
        f"<th>{_tip('Recall', 'Recall (positive)')}</th>"
        f"<th>{_tip('F1', 'F1 (positive)')}</th>"
        f"<th>{_tip('Support', 'Support')}</th>"
        f"</tr></thead>"
        f"<tbody>{tbody}</tbody>"
        f"</table>"
        f"{note}"
        f"</div>"
    )


def _render_feature_item(item: dict[str, Any], is_xgb: bool) -> str:
    feat = str(item.get("feature") or "")
    feat_tip = _FEATURE_TIPS.get(feat, "")
    feat_display = (
        f'<span class="tip" data-tip="{_escape(feat_tip)}"><code>{_escape(feat)}</code></span>'
        if feat_tip
        else f"<code>{_escape(feat)}</code>"
    )
    if is_xgb:
        val = _float_or_none(item.get("importance"))
        val_str = f"{val:.4f}" if val is not None else "—"
        tip_key = "XGBoost importance"
    else:
        val = _float_or_none(item.get("coefficient"))
        val_str = f"{val:+.3f}" if val is not None else "—"
        tip_key = "Positive coefficient" if val is None or val >= 0 else "Negative coefficient"
    return (
        f"<li>{feat_display} "
        f'<span class="tip" data-tip="{_escape(_METRIC_TIPS.get(tip_key, ""))}">'
        f"({val_str})"
        f"</span></li>"
    )


def _render_ml_metrics(metrics: dict[str, Any] | None) -> str:
    if not metrics:
        return '<p class="muted">Train a baseline or load metrics from an existing model run to surface results here.</p>'

    raw_ranking = metrics.get("ranking_metrics")
    ranking = raw_ranking if isinstance(raw_ranking, dict) else {}
    raw_positive = metrics.get("top_positive_features")
    positive = (
        [item for item in raw_positive if isinstance(item, dict)]
        if isinstance(raw_positive, list)
        else []
    )
    raw_negative = metrics.get("top_negative_features")
    negative = (
        [item for item in raw_negative if isinstance(item, dict)]
        if isinstance(raw_negative, list)
        else []
    )
    model_name = str(metrics.get("model_name") or "")
    is_xgb = model_name.lower() in {"xgboost", "lightgbm"}
    test_positive = _int_or_none(metrics.get("test_positive_count"))
    test_total = _int_or_none(metrics.get("test_row_count"))
    train_positive = _int_or_none(metrics.get("train_positive_count"))
    train_total = _int_or_none(metrics.get("train_row_count"))
    base_rate = (test_positive / test_total) if test_positive and test_total else 0.0

    feature_panel = _render_feature_columns_panel(metrics.get("feature_columns"))
    features_metric = (
        '<details class="metric metric--details">'
        "<summary>"
        '<span class="metric__label">Features</span>'
        f'<span class="metric__value">{_metric_value(metrics.get("feature_count"), digits=0)}</span>'
        '<span class="metric__hint">Click to show all</span>'
        "</summary>"
        f"{feature_panel}"
        "</details>"
        if feature_panel
        else f'<div class="metric"><span class="metric__label">Features</span><span class="metric__value">{_metric_value(metrics.get("feature_count"), digits=0)}</span></div>'
    )

    # Positive / negative feature lists with per-feature tooltips
    pos_label = "Top features (by importance)" if is_xgb else "Top positive features"
    positive_items = (
        "".join(_render_feature_item(item, is_xgb) for item in positive[:10])
        or "<li>No features found.</li>"
    )
    negative_items = (
        "".join(_render_feature_item(item, is_xgb) for item in negative[:10])
        or "<li>No negative coefficients found.</li>"
    )

    # Train/test class balance note
    train_pct = (
        f"{train_positive / train_total * 100:.2f}%" if train_positive and train_total else "—"
    )
    test_pct = f"{base_rate * 100:.2f}%" if test_positive and test_total else "—"
    balance_note = (
        f'<p class="small muted" style="margin-top:.35rem">'
        f"Train positives: {train_positive:,} / {train_total:,} ({train_pct}) &nbsp;·&nbsp; "
        f"Test positives: {test_positive:,} / {test_total:,} ({test_pct})"
        f"</p>"
        if train_positive and train_total and test_positive and test_total
        else ""
    )

    target_label = (
        (metrics.get("target_col") or "")
        .replace("label_advisory_within_", "")
        .replace("m", " month")
    )
    test_month = metrics.get("test_start_month") or ""

    header_meta = (
        '<div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-bottom:.9rem">'
        f"{_render_model_badge(model_name)}"
        + (
            f'<span class="small muted">Target: advisory within <strong>{_escape(target_label)}</strong></span>'
            if target_label
            else ""
        )
        + (
            f'<span class="small muted">Test from: <strong>{_escape(test_month)}</strong></span>'
            if test_month
            else ""
        )
        + "</div>"
    )

    return (
        '<div class="result-stack">'
        f"{header_meta}"
        # Core metric tiles
        '<div class="metrics-row">'
        f'<div class="metric"><span class="metric__label">{_tip("ROC AUC")}</span><span class="metric__value metric__value--good">{_metric_value(metrics.get("roc_auc"))}</span></div>'
        f'<div class="metric"><span class="metric__label">{_tip("Average Precision")}</span><span class="metric__value metric__value--good">{_metric_value(metrics.get("average_precision"))}</span></div>'
        f'<div class="metric"><span class="metric__label">{_tip("Train rows", "Train rows")}</span><span class="metric__value">{_metric_value(metrics.get("train_row_count"), digits=0)}</span></div>'
        f'<div class="metric"><span class="metric__label">{_tip("Test rows", "Test rows")}</span><span class="metric__value">{_metric_value(metrics.get("test_row_count"), digits=0)}</span></div>'
        f"{features_metric}"
        "</div>"
        f"{balance_note}"
        f"{_render_base_rate_bar(test_positive, test_total)}"
        # Ranking precision
        f'<div class="panel">{_render_ranking_row(ranking, base_rate)}</div>'
        # Feature importance columns — always two columns
        '<div class="grid--two">'
        f'<div class="panel"><h4>{_escape(pos_label)}</h4><ul class="bullet-list">{positive_items}</ul></div>'
        + (
            f'<div class="panel"><h4>Top negative features</h4>'
            f'<p class="small muted" style="margin-bottom:.5rem">Features whose higher values the model associates with <em>lower</em> predicted risk. '
            f"For logistic regression, the direction reflects the signed coefficient. "
            f"Correlated features can shift each other's signs — interpret alongside the positive list.</p>"
            f'<ul class="bullet-list">{negative_items}</ul></div>'
            if not is_xgb
            else f'<div class="panel"><h4>Feature importance</h4>'
            f'<p class="small muted" style="margin-bottom:.5rem">Gain-based importance does not indicate direction. '
            f"Higher values mean more contribution to model splits, not whether the feature raises or lowers predicted risk.</p>"
            f'<ul class="bullet-list">{positive_items}</ul></div>'
        )
        + "</div>"
        # Classification report
        + _render_class_report(metrics.get("classification_report"), is_xgb)
        # Confusion matrix
        + f'<div class="panel"><h4>Confusion matrix</h4>{_render_confusion_matrix(metrics.get("confusion_matrix"))}</div>'
        "</div>"
    )


def _render_confusion_matrix(confusion: Any) -> str:
    if not isinstance(confusion, list) or len(confusion) != 2:
        return f"<pre>{_escape(json.dumps(confusion, indent=2))}</pre>"
    rows: list[list[int]] = []
    for row in confusion:
        if not isinstance(row, list) or len(row) != 2:
            return f"<pre>{_escape(json.dumps(confusion, indent=2))}</pre>"
        try:
            rows.append([int(row[0]), int(row[1])])
        except (TypeError, ValueError):
            return f"<pre>{_escape(json.dumps(confusion, indent=2))}</pre>"

    tn, fp = rows[0]
    fn, tp = rows[1]
    return (
        '<div class="matrix-wrap">'
        '<div class="matrix-axis">Rows = actual class, columns = predicted class.</div>'
        '<table class="matrix-grid" aria-label="Confusion matrix">'
        "<thead>"
        '<tr><th class="corner">Actual vs Predicted</th><th>Negative</th><th>Positive</th></tr>'
        "</thead>"
        "<tbody>"
        f'<tr><th class="matrix-side">Negative</th><td class="matrix-cell--tn"><span class="matrix-count">{tn}</span><span class="matrix-label tip" data-tip="{_escape(_METRIC_TIPS["True negative"])}">True negative</span></td><td class="matrix-cell--fp"><span class="matrix-count">{fp}</span><span class="matrix-label tip" data-tip="{_escape(_METRIC_TIPS["False positive"])}">False positive</span></td></tr>'
        f'<tr><th class="matrix-side">Positive</th><td class="matrix-cell--fn"><span class="matrix-count">{fn}</span><span class="matrix-label tip" data-tip="{_escape(_METRIC_TIPS["False negative"])}">False negative</span></td><td class="matrix-cell--tp"><span class="matrix-count">{tp}</span><span class="matrix-label tip" data-tip="{_escape(_METRIC_TIPS["True positive"])}">True positive</span></td></tr>'
        "</tbody>"
        "</table>"
        "</div>"
    )


def _render_ml_tab(
    values: dict[str, Any],
    ml_result: dict[str, Any] | None,
    ml_error: str | None,
    latest_metrics: dict[str, Any] | None,
    model_dir_options: list[str],
) -> str:
    metrics = None
    if ml_result and ml_result.get("metrics"):
        metrics = ml_result["metrics"]
    elif latest_metrics:
        metrics = latest_metrics

    parts = [
        '<div class="grid--two">',
        '<section class="card">',
        '<div class="card__header"><div><p class="eyebrow">ML / evaluation</p><h2>Run the baseline model</h2><p class="kicker">Configure baseline training with a compact form and review the results in readable metric cards.</p></div><span class="pill">Training metrics</span></div>',
        '<form method="post" action="/train" class="form-grid">',
        '<input type="hidden" name="active_tab" value="ml">',
        _input_text("model_in_path", "Labeled dataset", values["model_in_path"], readonly=True),
        _select(
            "target_col",
            "Target label",
            values["target_col"],
            [
                ("label_advisory_within_1m", "Advisory within 1 month"),
                ("label_advisory_within_3m", "Advisory within 3 months"),
                ("label_advisory_within_6m", "Advisory within 6 months"),
                ("label_advisory_within_12m", "Advisory within 12 months"),
            ],
        ),
        _input_text(
            "test_start_month", "Test start month", values["test_start_month"], input_type="month"
        ),
        _model_dir_picker(
            "model_out_dir", "Model output directory", values["model_out_dir"], model_dir_options
        ),
        _input_text(
            "include_prefixes",
            "Feature prefixes (optional)",
            values["include_prefixes"],
            "gharchive_,window_",
        ),
        _input_text(
            "exclude_cols", "Extra excluded columns", values["exclude_cols"], "comma,separated"
        ),
        '<div class="button-row">'
        '<button type="submit" name="ml_action" value="train">Train baseline</button>'
        '<button type="submit" name="ml_action" value="load" class="secondary">Load metrics</button>'
        "</div></form>",
    ]
    if ml_error:
        parts.append(f'<div class="notice">{_escape(ml_error)}</div>')
    if ml_result:
        parts.append(_render_command_result(ml_result, "Training command"))
    parts.append("</section>")

    status_text = '<p class="muted">No metrics loaded yet.</p>'
    if metrics:
        source = (
            ml_result.get("metrics_path")
            if ml_result and ml_result.get("metrics_path")
            else str(Path(values["model_out_dir"]) / "metrics.json")
        )
        status_text = f'<p class="small muted">Metrics source: <code>{_escape(source)}</code></p>'
    parts.append(
        f'<section class="card"><div class="card__header"><div><p class="eyebrow">Model performance</p><h2>Readable metrics</h2></div><span class="pill pill--muted">Metrics view</span></div>{status_text}{_render_ml_metrics(metrics)}</section>'
    )
    parts.append("</div>")
    return "".join(parts)


def render_page(
    values: dict[str, Any],
    *,
    plugin_options: list[str] | None = None,
    score_result: dict[str, Any] | None = None,
    score_error: str | None = None,
    data_result: dict[str, Any] | None = None,
    data_error: str | None = None,
    ml_result: dict[str, Any] | None = None,
    ml_error: str | None = None,
    latest_metrics: dict[str, Any] | None = None,
    model_dir_options: list[str] | None = None,
) -> str:
    values = {**DEFAULTS, **values}
    plugin_options = plugin_options or []
    model_dir_options = model_dir_options or []
    active_tab = values.get("active_tab") or "score"
    tabs = [
        ("score", "Scoring", "Plugin score and rationale"),
        ("data", "Data collection", "Run collection and monthly prep"),
        ("ml", "Machine learning", "Train baseline and review metrics"),
    ]
    tab_links = "".join(
        f'<a href="/?tab={_escape(tab_key)}" class="tab-link {"is-active" if tab_key == active_tab else ""}" data-tab-link="{_escape(tab_key)}"><strong>{_escape(title)}</strong><span>{_escape(subtitle)}</span></a>'
        for tab_key, title, subtitle in tabs
    )
    active_panel_html = ""
    if active_tab == "score":
        active_panel_html = _render_score_section(
            values, plugin_options, score_result, score_error, model_dir_options
        )
    elif active_tab == "data":
        active_panel_html = _render_data_tab(values, plugin_options, data_result, data_error)
    else:
        active_panel_html = _render_ml_tab(
            values, ml_result, ml_error, latest_metrics, model_dir_options
        )
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CANARY Web Console</title>
    <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="/static/favicon.png">
    <style>{CSS}</style>
  </head>
  <body>
    <header class="hero">
      <div class="hero__inner">
        <div class="hero__brand">
          <div class="hero__logo-wrap">
            <img class="hero__logo" src="/static/canary-logo.png" alt="CANARY logo">
          </div>
          <div>
            <p class="eyebrow">Web interface</p>
            <h1>CANARY Web Console</h1>
          </div>
        </div>
        <p class="hero__copy">
          A lightweight zero-dependency web UI for scoring Jenkins plugins, running collection jobs,
          and showing baseline ML results.
        </p>
      </div>
    </header>
    <main class="page-shell">
      <nav class="tabs">{tab_links}</nav>
      <section class="tab-panel is-active" data-tab-panel="{_escape(active_tab)}">
        {active_panel_html}
      </section>
    </main>
    {_validation_script(plugin_options, active_tab)}
  </body>
</html>"""


def _serve_static_asset(asset_name: str, start_response: Any) -> list[bytes]:
    asset_path = (STATIC_DIR / asset_name).resolve()
    if STATIC_DIR.resolve() not in asset_path.parents and asset_path != STATIC_DIR.resolve():
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]
    if not asset_path.exists() or not asset_path.is_file():
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]
    content_type = mimetypes.guess_type(asset_path.name)[0] or "application/octet-stream"
    start_response(
        "200 OK", [("Content-Type", content_type), ("Cache-Control", "public, max-age=3600")]
    )
    return [asset_path.read_bytes()]


def parse_form(environ: dict[str, Any]) -> dict[str, str]:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0") or "0")
    except ValueError:
        size = 0
    body = environ["wsgi.input"].read(size).decode("utf-8") if size else ""
    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _prepare_request_state(
    values: dict[str, Any],
) -> tuple[list[str], dict[str, Any] | None, list[str]]:
    active_tab = values.get("active_tab") or "score"
    plugin_options = (
        _load_plugin_choices(values["registry_path"]) if active_tab in {"score", "data"} else []
    )
    latest_metrics = None
    model_dir_options: list[str] = []
    if active_tab == "ml":
        model_dir_options = _discover_model_output_dirs()
        try:
            values["model_out_dir"] = _normalize_model_output_dir(
                values.get("model_out_dir") or DEFAULT_MODEL_DIR
            )
        except ValueError:
            values["model_out_dir"] = DEFAULT_MODEL_DIR
        latest_metrics = _load_model_metrics(values["model_out_dir"])
    return plugin_options, latest_metrics, model_dir_options


def _public_validation_error(path: str) -> str:
    if path == "/score":
        return "The scoring request could not be completed. Check the form values and try again."
    if path == "/run":
        return "The data collection request could not be completed. Check the form values and try again."
    return (
        "The machine learning request could not be completed. Check the form values and try again."
    )


def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")

    if path == "/health":
        start_response("200 OK", [("Content-Type", "application/json; charset=utf-8")])
        return [b'{"status": "ok"}']

    if path.startswith("/static/"):
        asset_name = path.removeprefix("/static/")
        return _serve_static_asset(asset_name, start_response)

    query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    values = _merge_defaults({"active_tab": query.get("tab", [DEFAULTS["active_tab"]])[-1]})
    plugin_options, latest_metrics, model_dir_options = _prepare_request_state(values)
    score_result = None
    score_error = None
    data_result = None
    data_error = None
    ml_result = None
    ml_error = None

    if method == "POST" and path in {"/score", "/run", "/train"}:
        form = parse_form(environ)
        values = _merge_defaults(form)
        plugin_options, latest_metrics, model_dir_options = _prepare_request_state(values)
        try:
            if path == "/score":
                plugin = (form.get("plugin") or "").strip()
                if not plugin:
                    raise ValueError("Please enter a plugin ID to score.")
                if not _plugin_known(plugin, values["registry_path"]):
                    raise ValueError("Please choose a plugin ID from the current registry list.")
                score_result = _score_payload(
                    score_plugin_baseline(plugin, real=_bool_from_form(form.get("real")))
                )
                # Also run the ML scorer if a trained model is available
                _score_model_dir = (
                    values.get("score_model_dir") or values.get("model_dir") or DEFAULT_MODEL_DIR
                )
                _ml_scorer = _get_ml_scorer(_score_model_dir) if _score_model_dir else None
                if _ml_scorer is not None:
                    try:
                        ml_score_result = _ml_score_payload(
                            score_plugin_ml(
                                plugin,
                                scorer=_ml_scorer,
                                data_raw_dir=values.get("data_dir") or DEFAULT_DATA_DIR,
                            )
                        )
                        score_result["ml"] = ml_score_result
                    except Exception as _ml_exc:
                        logger.warning("ML scoring failed for %s: %s", plugin, _ml_exc)
                        score_result["ml"] = None
                else:
                    score_result["ml"] = None
                values["active_tab"] = "score"
            elif path == "/run":
                command = values["command"]
                data_result = _run_data_action(command, form)
                values["active_tab"] = "data"
            else:
                ml_action = (form.get("ml_action") or "train").strip().lower()
                if ml_action == "load":
                    ml_result = _run_load_metrics_action(form)
                else:
                    ml_result = _run_train_action(form)
                    model_dir_options = _discover_model_output_dirs()
                latest_metrics = ml_result.get("metrics") or latest_metrics
                values["active_tab"] = "ml"
        except ValueError as exc:
            logger.warning("Rejected webapp request for %s: %s", path, exc)
            if path == "/score":
                score_error = _public_validation_error(path)
                values["active_tab"] = "score"
            elif path == "/run":
                data_error = _public_validation_error(path)
                values["active_tab"] = "data"
            else:
                ml_error = _public_validation_error(path)
                values["active_tab"] = "ml"
        except Exception:  # pragma: no cover
            logger.exception("Unhandled webapp error while processing %s", path)
            public_error = (
                "Something went wrong while processing your request. Check the server logs."
            )
            if path == "/score":
                score_error = public_error
                values["active_tab"] = "score"
            elif path == "/run":
                data_error = public_error
                values["active_tab"] = "data"
            else:
                ml_error = public_error
                values["active_tab"] = "ml"

    html_body = render_page(
        values,
        plugin_options=plugin_options,
        score_result=score_result,
        score_error=score_error,
        data_result=data_result,
        data_error=data_error,
        ml_result=ml_result,
        ml_error=ml_error,
        latest_metrics=latest_metrics,
        model_dir_options=model_dir_options,
    )
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [html_body.encode("utf-8")]


def main() -> None:
    host = os.getenv("CANARY_WEB_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("CANARY_WEB_PORT", "8000"))
    except ValueError:
        port = 8000
    try:
        threads = int(os.getenv("CANARY_WEB_THREADS", "8"))
    except ValueError:
        threads = 8
    try:
        connection_limit = int(os.getenv("CANARY_WEB_CONNECTION_LIMIT", "200"))
    except ValueError:
        connection_limit = 200

    print(f"CANARY web console running on http://{host}:{port}")
    if waitress_serve is not None:
        print(f"Using waitress with threads={threads} and connection_limit={connection_limit}")
        waitress_serve(
            app, host=host, port=port, threads=threads, connection_limit=connection_limit
        )
        return

    print("Waitress is not installed; falling back to wsgiref.simple_server")
    with make_server(host, port, app) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
