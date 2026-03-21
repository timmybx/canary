from __future__ import annotations

# ruff: noqa: E501
import argparse
import html
import io
import json
import logging
import mimetypes
import os
import shlex
import urllib.parse
from contextlib import redirect_stdout
from functools import lru_cache
from pathlib import Path
from typing import Any
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

DEFAULT_DATA_DIR = "data/raw"
DEFAULT_REGISTRY_PATH = "data/raw/registry/plugins.jsonl"
DEFAULT_MONTHLY_FEATURES_PATH = "data/processed/features/plugins.monthly.features.jsonl"
DEFAULT_MONTHLY_FEATURES_CSV = "data/processed/features/plugins.monthly.features.csv"
DEFAULT_MONTHLY_FEATURES_SUMMARY = "data/processed/features/plugins.monthly.features.summary.json"
DEFAULT_LABELED_PATH = "data/processed/features/plugins.monthly.labeled.jsonl"
DEFAULT_LABELED_CSV = "data/processed/features/plugins.monthly.labeled.csv"
DEFAULT_LABELED_SUMMARY = "data/processed/features/plugins.monthly.labeled.summary.json"
DEFAULT_MODEL_DIR = "data/processed/models/baseline_6m"

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
    "test_start_month": "2025-10",
    "exclude_cols": "",
    "include_prefixes": "",
}

STATIC_DIR = Path(__file__).with_name("static")
logger = logging.getLogger(__name__)

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
.metric__label { display:block; color:var(--muted); font-size:.9rem; }
.metric__value { display:block; margin-top:.35rem; font-size:1.4rem; font-weight:700; }
.metric__value--good { color: var(--good); }
.metric__value--warn { color: var(--warn); }
.bullet-list { margin:0; padding-left:1.2rem; }
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
    return argparse.Namespace(
        in_path=(form.get("model_in_path") or DEFAULT_LABELED_PATH).strip(),
        target_col=(form.get("target_col") or "label_advisory_within_6m").strip(),
        out_dir=(form.get("model_out_dir") or DEFAULT_MODEL_DIR).strip(),
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
    metrics_path = Path(args.out_dir) / "metrics.json"
    metrics = _load_json_file(metrics_path)
    return {
        "command": " ".join(
            shlex.quote(part)
            for part in ["canary", "train", "baseline"] + _argv_preview_train(args)
        ),
        "exit_code": result["exit_code"],
        "output": result["output"],
        "metrics": metrics,
        "metrics_path": str(metrics_path),
    }


def _detect_available_files(plugin_id: str) -> list[str]:
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


@lru_cache(maxsize=32)
def _load_plugin_choices_cached(registry_path: str, mtime_ns: int) -> list[str]:
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
                plugin_ids.append(
                    canonicalize_plugin_id(
                        plugin_id,
                        registry_path=path,
                        data_dir=path.parent.parent,
                    )
                )
    return sorted(set(plugin_ids))


def _load_plugin_choices(registry_path: str) -> list[str]:
    path = Path(registry_path)
    if not path.exists() or not path.is_file():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    return _load_plugin_choices_cached(str(path.resolve()), stat.st_mtime_ns)


def _plugin_known(plugin_id: str, registry_path: str) -> bool:
    plugin_id = canonicalize_plugin_id(
        plugin_id.strip(),
        registry_path=registry_path,
        data_dir=Path(registry_path).parent.parent,
    )
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


def _load_json_file(path: str | Path) -> dict[str, Any] | None:
    target = Path(path)
    if not target.exists() or not target.is_file():
        return None
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


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

  const links = Array.from(document.querySelectorAll('[data-tab-link]'));
  const panels = Array.from(document.querySelectorAll('[data-tab-panel]'));
  const hiddenInputs = Array.from(document.querySelectorAll('input[name="active_tab"]'));

  const activate = (tab) => {{
    links.forEach((link) => link.classList.toggle('is-active', link.dataset.tabLink === tab));
    panels.forEach((panel) => panel.classList.toggle('is-active', panel.dataset.tabPanel === tab));
    hiddenInputs.forEach((input) => input.value = tab);
    const nextUrl = new URL(window.location.href);
    nextUrl.searchParams.set('tab', tab);
    window.history.replaceState(null, '', nextUrl.toString());
  }};

  links.forEach((link) => {{
    link.addEventListener('click', (event) => {{
      event.preventDefault();
      activate(link.dataset.tabLink);
    }});
  }});

  activate({_escape(json.dumps(active_tab))});
}})();
</script>
"""


def _score_payload(result: ScoreResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["pretty_json"] = json.dumps(payload, indent=2, ensure_ascii=False)
    payload["pretty_features"] = json.dumps(payload["features"], indent=2, ensure_ascii=False)
    payload["data_files"] = _detect_available_files(result.plugin)
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


def _render_score_section(
    values: dict[str, Any],
    plugin_options: list[str],
    score_result: dict[str, Any] | None,
    score_error: str | None,
) -> str:
    parts = [
        '<div class="grid--score">',
        '<section class="card">',
        '<div class="card__header"><div><p class="eyebrow">Plugin scoring</p><h2>Score a plugin</h2><p class="kicker">Review the CANARY score, rationale, and supporting evidence.</p></div><span class="pill">Core workflow</span></div>',
        '<form method="post" action="/score" class="form-grid" data-plugin-strict="true">',
        '<input type="hidden" name="active_tab" value="score">',
        _plugin_picker("plugin", "Plugin ID", values["plugin"], plugin_options),
        _input_text("data_dir", "Data directory", values["data_dir"], readonly=True),
        _checkbox("real", "Prefer real advisory data", bool(values["real"])),
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
            f'<div class="score-banner"><div><p class="eyebrow">Score result</p><h3>{_escape(score_result["plugin"])}</h3></div><div class="score-number">{_escape(score_result["score"])}<span>/100</span></div></div>'
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


def _render_ml_metrics(metrics: dict[str, Any] | None) -> str:
    if not metrics:
        return '<p class="muted">Run baseline training to surface metrics here. If a previous metrics.json exists in the default model directory, it will also show up automatically.</p>'
    ranking = metrics.get("ranking_metrics") or {}
    positive = metrics.get("top_positive_features") or []
    negative = metrics.get("top_negative_features") or []
    positive_items = (
        "".join(
            f"<li><code>{_escape(item.get('feature'))}</code> ({_metric_value(item.get('coefficient'), digits=3)})</li>"
            for item in positive[:8]
        )
        or "<li>No positive coefficients found.</li>"
    )
    negative_items = (
        "".join(
            f"<li><code>{_escape(item.get('feature'))}</code> ({_metric_value(item.get('coefficient'), digits=3)})</li>"
            for item in negative[:8]
        )
        or "<li>No negative coefficients found.</li>"
    )
    return (
        '<div class="result-stack">'
        '<div class="metrics-row">'
        f'<div class="metric"><span class="metric__label">ROC AUC</span><span class="metric__value metric__value--good">{_metric_value(metrics.get("roc_auc"))}</span></div>'
        f'<div class="metric"><span class="metric__label">Average Precision</span><span class="metric__value metric__value--good">{_metric_value(metrics.get("average_precision"))}</span></div>'
        f'<div class="metric"><span class="metric__label">Train rows</span><span class="metric__value">{_metric_value(metrics.get("train_row_count"), digits=0)}</span></div>'
        f'<div class="metric"><span class="metric__label">Test rows</span><span class="metric__value">{_metric_value(metrics.get("test_row_count"), digits=0)}</span></div>'
        f'<div class="metric"><span class="metric__label">Features</span><span class="metric__value">{_metric_value(metrics.get("feature_count"), digits=0)}</span></div>'
        f'<div class="metric"><span class="metric__label">Precision@10</span><span class="metric__value metric__value--warn">{_metric_value(ranking.get("precision_at_10"))}</span></div>'
        "</div>"
        '<div class="grid--two">'
        f'<div class="panel"><h4>Top positive features</h4><ul class="bullet-list">{positive_items}</ul></div>'
        f'<div class="panel"><h4>Top negative features</h4><ul class="bullet-list">{negative_items}</ul></div>'
        "</div>"
        f'<div class="panel"><h4>Confusion matrix</h4><pre>{_escape(json.dumps(metrics.get("confusion_matrix"), indent=2))}</pre></div>'
        "</div>"
    )


def _render_ml_tab(
    values: dict[str, Any],
    ml_result: dict[str, Any] | None,
    ml_error: str | None,
    latest_metrics: dict[str, Any] | None,
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
        _input_text(
            "model_out_dir", "Model output directory", values["model_out_dir"], readonly=True
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
        '<button type="submit">Train baseline</button></form>',
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
            if ml_result
            else str(Path(DEFAULT_MODEL_DIR) / "metrics.json")
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
) -> str:
    values = {**DEFAULTS, **values}
    plugin_options = plugin_options or []
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
          and showing baseline ML results in a cleaner way than raw CLI output.
        </p>
      </div>
    </header>
    <main class="page-shell">
      <nav class="tabs">{tab_links}</nav>
      <section class="tab-panel {"is-active" if active_tab == "score" else ""}" data-tab-panel="score">
        {_render_score_section(values, plugin_options, score_result, score_error)}
      </section>
      <section class="tab-panel {"is-active" if active_tab == "data" else ""}" data-tab-panel="data">
        {_render_data_tab(values, plugin_options, data_result, data_error)}
      </section>
      <section class="tab-panel {"is-active" if active_tab == "ml" else ""}" data-tab-panel="ml">
        {_render_ml_tab(values, ml_result, ml_error, latest_metrics)}
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
    plugin_options = _load_plugin_choices(values["registry_path"])
    latest_metrics = _load_json_file(Path(values["model_out_dir"]) / "metrics.json")
    score_result = None
    score_error = None
    data_result = None
    data_error = None
    ml_result = None
    ml_error = None

    if method == "POST" and path in {"/score", "/run", "/train"}:
        form = parse_form(environ)
        values = _merge_defaults(form)
        plugin_options = _load_plugin_choices(values["registry_path"])
        latest_metrics = _load_json_file(Path(values["model_out_dir"]) / "metrics.json")
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
                values["active_tab"] = "score"
            elif path == "/run":
                command = values["command"]
                data_result = _run_data_action(command, form)
                values["active_tab"] = "data"
            else:
                ml_result = _run_train_action(form)
                latest_metrics = ml_result.get("metrics") or latest_metrics
                values["active_tab"] = "ml"
        except ValueError as exc:
            if path == "/score":
                score_error = str(exc)
                values["active_tab"] = "score"
            elif path == "/run":
                data_error = str(exc)
                values["active_tab"] = "data"
            else:
                ml_error = str(exc)
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
    )
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [html_body.encode("utf-8")]


def main() -> None:
    host = os.getenv("CANARY_WEB_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("CANARY_WEB_PORT", "8000"))
    except ValueError:
        port = 8000

    with make_server(host, port, app) as httpd:
        print(f"CANARY web console running on http://{host}:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
