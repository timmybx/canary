from __future__ import annotations

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
    _cmd_collect_advisories,
    _cmd_collect_enrich,
    _cmd_collect_github,
    _cmd_collect_healthscore,
    _cmd_collect_plugin,
    _cmd_collect_registry,
)
from canary.scoring.baseline import ScoreResult, score_plugin_baseline

DEFAULT_DATA_DIR = "data/raw"
DEFAULT_REGISTRY_PATH = "data/raw/registry/plugins.jsonl"
DEFAULTS: dict[str, Any] = {
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
}

STATIC_DIR = Path(__file__).with_name("static")
logger = logging.getLogger(__name__)

CSS = """
:root {
  --bg: #0b1220;
  --panel: #111a2b;
  --panel2: #172338;
  --text: #e8eefb;
  --muted: #a8b3c8;
  --line: #24324b;
  --accent: #6fb1ff;
  --accent2: #9fd0ff;
  --error-bg: #3a1820;
  --error-line: #7f3142;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, Segoe UI, Roboto, sans-serif;
  background: linear-gradient(180deg, #08111f 0%, #0c1423 100%);
  color: var(--text);
}
.hero {
  padding: 2.4rem 1.25rem 2rem;
  border-bottom: 1px solid rgba(255, 255, 255, .06);
  background:
    radial-gradient(circle at top left, rgba(111, 177, 255, .22), transparent 30%),
    radial-gradient(circle at top right, rgba(159, 208, 255, .12), transparent 24%);
}
.hero__inner,.page-shell { max-width:1200px; margin:0 auto; }
.hero__brand { display:flex; align-items:center; gap:1rem; }
.hero__logo-wrap {
  width: 88px;
  height: 88px;
  display: grid;
  place-items: center;
  border-radius: 24px;
  background: linear-gradient(180deg, rgba(255, 255, 255, .05), rgba(255, 255, 255, .02));
  border: 1px solid rgba(255, 255, 255, .08);
  box-shadow: 0 16px 40px rgba(0, 0, 0, .24);
}
.hero__logo {
  width: 72px;
  height: 72px;
  object-fit: contain;
  filter: drop-shadow(0 0 18px rgba(255, 223, 82, .18));
}
.hero__copy { color:var(--muted); max-width:60rem; font-size:1.05rem; margin-top:.75rem; }
.page-shell { padding:1.5rem 1.25rem 3rem; }
.grid { display:grid; grid-template-columns:1fr; gap:1.25rem; }
@media (min-width:1050px){ .grid { grid-template-columns:1.05fr 1fr; }}
.card {
  background: rgba(17, 26, 43, .92);
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 1.25rem;
  box-shadow: 0 16px 40px rgba(0, 0, 0, .24);
}
.card__header,.score-banner,.metrics-row,.checkbox-cluster,.two-up { display:flex; gap:1rem; }
.card__header,.score-banner { justify-content:space-between; align-items:flex-start; }
.metrics-row,.checkbox-cluster,.two-up { flex-wrap:wrap; }
.two-up > .panel { flex:1 1 320px; }
.eyebrow {
  text-transform: uppercase;
  letter-spacing: .08em;
  font-size: .75rem;
  color: var(--accent2);
  margin: 0 0 .35rem;
}
h1,h2,h3,h4 { margin:0 0 .45rem; }
.pill {
  padding: .35rem .7rem;
  background: rgba(111, 177, 255, .16);
  border: 1px solid rgba(111, 177, 255, .3);
  border-radius: 999px;
  color: var(--accent2);
  font-size: .85rem;
}
.pill--muted {
  background: rgba(255, 255, 255, .05);
  border-color: rgba(255, 255, 255, .08);
  color: var(--muted);
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: .9rem;
  margin-top: 1rem;
}
label { display:grid; gap:.4rem; font-weight:600; color:var(--muted); }
input,select,button {
  border-radius: 12px;
  border: 1px solid var(--line);
  background: var(--panel2);
  color: var(--text);
  padding: .8rem .9rem;
  font: inherit;
}
button {
  background: linear-gradient(180deg, var(--accent), #4d95e6);
  color: #071423;
  font-weight: 700;
  cursor: pointer;
  align-self: end;
}
button:hover { filter:brightness(1.05); }
.checkbox-row {
  display: flex;
  align-items: center;
  gap: .65rem;
  padding: .8rem .9rem;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--panel2);
  color: var(--text);
}
.checkbox-row input { width:18px; height:18px; margin:0; }
.notice {
  margin-top: 1rem;
  padding: .9rem 1rem;
  border-radius: 14px;
  border: 1px solid var(--error-line);
  background: var(--error-bg);
}
.field-note {
  display:block;
  font-size:.82rem;
  color:var(--muted);
  font-weight:500;
}
input[readonly] {
  color: var(--muted);
  background: rgba(255,255,255,.04);
  cursor: not-allowed;
}
button[disabled] {
  cursor: not-allowed;
  opacity: .65;
  filter: grayscale(.15);
}
.result-stack { display:grid; gap:1rem; margin-top:1rem; }
.score-number { font-size:2.5rem; font-weight:800; }
.score-number span { font-size:1.05rem; color:var(--muted); margin-left:.2rem; }
.metric,.panel {
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 1rem;
}
.metric { min-width:140px; }
.metric__label { display:block; color:var(--muted); font-size:.9rem; }
.metric__value { display:block; margin-top:.35rem; font-size:1.4rem; font-weight:700; }
.bullet-list { margin:0; padding-left:1.2rem; }
pre {
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
  padding: 1rem;
  border-radius: 14px;
  background: #0b1322;
  border: 1px solid rgba(255, 255, 255, .06);
  color: #dbe5fb;
  overflow-x: auto;
}
.muted { color:var(--muted); }
code { background:rgba(255,255,255,.05); padding:.15rem .35rem; border-radius:6px; }
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


def _namespace_for_command(command_name: str, form: dict[str, str]) -> argparse.Namespace:
    if command_name == "collect-registry":
        return argparse.Namespace(
            out_dir=(form.get("out_dir") or "data/raw/registry").strip(),
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
            out_dir=(form.get("out_dir") or "data/raw/plugins").strip(),
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
            data_dir=(form.get("data_dir") or DEFAULT_DATA_DIR).strip(),
            out_dir=(form.get("out_dir") or "data/raw/advisories").strip(),
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
            data_dir=(form.get("data_dir") or DEFAULT_DATA_DIR).strip(),
            out_dir=(form.get("github_out_dir") or "data/raw/github").strip(),
            timeout_s=float((form.get("github_timeout_s") or "20").strip()),
            max_pages=int((form.get("github_max_pages") or "5").strip()),
            commits_days=int((form.get("github_commits_days") or "365").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-healthscore":
        return argparse.Namespace(
            data_dir=(form.get("data_dir") or DEFAULT_DATA_DIR).strip(),
            timeout_s=float((form.get("healthscore_timeout_s") or "30").strip()),
            overwrite=_bool_from_form(form.get("overwrite")),
        )
    if command_name == "collect-enrich":
        return argparse.Namespace(
            registry=(form.get("registry_path") or DEFAULT_REGISTRY_PATH).strip(),
            data_dir=(form.get("data_dir") or DEFAULT_DATA_DIR).strip(),
            only=_optional_str(form.get("only") or ""),
            max_plugins=_optional_str(form.get("max_plugins") or ""),
            sleep=float((form.get("sleep") or "0").strip()),
            real=_bool_from_form(form.get("real")),
            github_timeout_s=float((form.get("github_timeout_s") or "20").strip()),
            github_max_pages=int((form.get("github_max_pages") or "5").strip()),
            github_commits_days=int((form.get("github_commits_days") or "365").strip()),
            healthscore_timeout_s=float((form.get("healthscore_timeout_s") or "30").strip()),
        )
    raise ValueError(f"Unsupported command selection: {command_name}")


def _argv_preview(command_name: str, args: argparse.Namespace) -> list[str]:
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
        if args.timeout_s is not None:
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
    return []


def _run_command(command_name: str, form: dict[str, str]) -> dict[str, Any]:
    handlers: dict[str, tuple[Any, list[str]]] = {
        "collect-registry": (_cmd_collect_registry, ["canary", "collect", "registry"]),
        "collect-plugin": (_cmd_collect_plugin, ["canary", "collect", "plugin"]),
        "collect-advisories": (_cmd_collect_advisories, ["canary", "collect", "advisories"]),
        "collect-github": (_cmd_collect_github, ["canary", "collect", "github"]),
        "collect-healthscore": (_cmd_collect_healthscore, ["canary", "collect", "healthscore"]),
        "collect-enrich": (_cmd_collect_enrich, ["canary", "collect", "enrich"]),
    }
    handler, argv = handlers[command_name]
    args = _namespace_for_command(command_name, form)
    result = _capture_command(handler, args)
    return {
        "command": " ".join(shlex.quote(part) for part in argv + _argv_preview(command_name, args)),
        "exit_code": result["exit_code"],
        "output": result["output"],
    }


def _detect_available_files(plugin_id: str) -> list[str]:
    base = Path(DEFAULT_DATA_DIR)
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
                plugin_ids.append(plugin_id)
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
    plugin_id = plugin_id.strip()
    if not plugin_id:
        return False
    choices = _load_plugin_choices(registry_path)
    return not choices or plugin_id in choices


def _plugin_picker(name: str, label: str, value: Any, plugin_options: list[str]) -> str:
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
    if plugin_options:
        note = (
            '<span class="field-note">Autocomplete is populated from the current registry file. '
            "Unknown plugin IDs are blocked.</span>"
        )
    else:
        note = (
            '<span class="field-note">No registry plugin list was found yet, '
            "so free text is still allowed.</span>"
        )
    return (
        f"<label>{_escape(label)}"
        f"<input {' '.join(attrs)}>"
        f'<datalist id="{_escape(datalist_id)}">{options_html}</datalist>'
        f"{note}</label>"
    )


def _input_text(
    name: str, label: str, value: Any, placeholder: str = "", *, readonly: bool = False
) -> str:
    attrs = [
        'type="text"',
        f'name="{_escape(name)}"',
        f'value="{_escape(value)}"',
        f'placeholder="{_escape(placeholder)}"',
    ]
    if readonly:
        attrs.append("readonly")
    note = '<span class="field-note">Shown for reference only.</span>' if readonly else ""
    return f"<label>{_escape(label)}<input {' '.join(attrs)}>{note}</label>"


def _validation_script(plugin_options: list[str]) -> str:
    if not plugin_options:
        return ""
    payload = json.dumps(plugin_options, ensure_ascii=False)
    return f"""
<script>
(() => {{
  const allowed = new Set({payload});
  for (const form of document.querySelectorAll('form')) {{
    const pluginInput = form.querySelector('[data-plugin-input="true"]');
    if (!pluginInput) continue;
    const button = form.querySelector('button[type="submit"]');
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
}})();
</script>
"""


def _score_payload(result: ScoreResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["pretty_json"] = json.dumps(payload, indent=2, ensure_ascii=False)
    payload["pretty_features"] = json.dumps(payload["features"], indent=2, ensure_ascii=False)
    payload["data_files"] = _detect_available_files(result.plugin)
    return payload


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
    return (
        f'<label>{_escape(label)}<select name="{_escape(name)}">'
        f"{''.join(rendered)}</select></label>"
    )


def _render_score_section(
    values: dict[str, Any],
    plugin_options: list[str],
    score_result: dict[str, Any] | None,
    score_error: str | None,
) -> str:
    parts = [
        '<section class="card card--score">',
        '<div class="card__header"><div><p class="eyebrow">Fast demo path</p>'
        "<h2>Score a plugin</h2></div>"
        '<span class="pill">Recommended first</span></div>',
        '<form method="post" action="/score" class="form-grid">',
        _plugin_picker("plugin", "Plugin ID", values["plugin"], plugin_options),
        _input_text("data_dir", "Data directory", values["data_dir"], readonly=True),
        _checkbox("real", "Prefer real advisory data", bool(values["real"])),
        '<button type="submit">Score plugin</button></form>',
    ]
    if score_error:
        parts.append(f'<div class="notice notice--error">{_escape(score_error)}</div>')
    if score_result:
        reasons = "".join(f"<li>{_escape(reason)}</li>" for reason in score_result["reasons"])
        files_html = (
            "".join(f"<li><code>{_escape(path)}</code></li>" for path in score_result["data_files"])
            if score_result["data_files"]
            else (
                '<p class="muted">No matching local files were found under '
                "<code>data/raw</code> for this plugin.</p>"
            )
        )
        parts.extend(
            [
                f'<div class="result-stack" id="score-{_escape(score_result["plugin"])}">',
                '<div class="score-banner"><div><p class="eyebrow">Score result</p>'
                f"<h3>{_escape(score_result['plugin'])}</h3></div>"
                f'<div class="score-number">{_escape(score_result["score"])}'
                "<span>/100</span></div></div>",
                '<div class="metrics-row">'
                f'<div class="metric"><span class="metric__label">Reasons</span>'
                f'<span class="metric__value">{len(score_result["reasons"])}</span></div>'
                f'<div class="metric"><span class="metric__label">Feature keys</span>'
                f'<span class="metric__value">{len(score_result["features"])}</span></div>'
                f'<div class="metric"><span class="metric__label">Local files found</span>'
                f'<span class="metric__value">{len(score_result["data_files"])}</span></div>'
                "</div>",
                f'<div class="panel"><h4>Why this score</h4>'
                f'<ul class="bullet-list">{reasons}</ul></div>',
                '<div class="two-up">'
                f'<div class="panel"><h4>Feature details</h4>'
                f"<pre>{_escape(score_result['pretty_features'])}</pre></div>"
                f'<div class="panel"><h4>JSON payload</h4>'
                f"<pre>{_escape(score_result['pretty_json'])}</pre></div></div>",
                f'<div class="panel"><h4>Detected local data files</h4>{files_html}</div>',
                "</div>",
            ]
        )
    parts.append("</section>")
    return "".join(parts)


def _render_command_section(
    values: dict[str, Any],
    plugin_options: list[str],
    command_result: dict[str, Any] | None,
    command_error: str | None,
) -> str:
    options = [
        ("collect-registry", "Collect registry"),
        ("collect-plugin", "Collect plugin snapshot(s)"),
        ("collect-advisories", "Collect advisories"),
        ("collect-github", "Collect GitHub data"),
        ("collect-healthscore", "Collect health scores"),
        ("collect-enrich", "Run enrich pipeline"),
    ]
    stage_options = [
        ("", "Run all stages"),
        ("snapshot", "snapshot"),
        ("advisories", "advisories"),
        ("github", "github"),
        ("healthscore", "healthscore"),
    ]
    parts = [
        '<section class="card">',
        '<div class="card__header"><div><p class="eyebrow">CLI without remembering flags</p>'
        "<h2>Run a collection step</h2></div>"
        '<span class="pill pill--muted">Same backend logic</span></div>',
        '<form method="post" action="/run" class="form-grid">',
        _select("command", "Action", values["command"], options),
        _plugin_picker("plugin", "Plugin ID", values["plugin"], plugin_options),
        _input_text("data_dir", "Data directory", values["data_dir"], readonly=True),
        _input_text("registry_path", "Registry path", values["registry_path"], readonly=True),
        _input_text("out_dir", "Output directory", values["out_dir"], readonly=True),
        _input_text(
            "github_out_dir", "GitHub output directory", values["github_out_dir"], readonly=True
        ),
        _input_text(
            "repo_url", "Repo URL override", values["repo_url"], "https://github.com/jenkinsci/..."
        ),
        _input_text("max_plugins", "Max plugins", values["max_plugins"], "25"),
        _input_text("sleep", "Sleep seconds", values["sleep"]),
        _input_text("timeout_s", "Timeout seconds", values["timeout_s"]),
        _input_text("page_size", "Page size", values["page_size"]),
        _input_text("out_name", "Registry output filename", values["out_name"], readonly=True),
        _input_text("raw_out", "Raw registry filename", values["raw_out"], readonly=True),
        _input_text("github_timeout_s", "GitHub timeout seconds", values["github_timeout_s"]),
        _input_text("github_max_pages", "GitHub max pages", values["github_max_pages"]),
        _input_text(
            "github_commits_days", "GitHub commits lookback days", values["github_commits_days"]
        ),
        _select("only", "Enrich stage only", values["only"], stage_options),
        _input_text(
            "healthscore_timeout_s", "Healthscore timeout seconds", values["healthscore_timeout_s"]
        ),
        '<div class="checkbox-cluster">',
        _checkbox("real", "Use real/live data", bool(values["real"])),
        _checkbox("overwrite", "Overwrite existing files", bool(values["overwrite"])),
        "</div>",
        '<button type="submit">Run action</button></form>',
    ]
    if command_error:
        parts.append(f'<div class="notice notice--error">{_escape(command_error)}</div>')
    if command_result:
        parts.extend(
            [
                '<div class="result-stack">',
                f'<div class="panel"><h4>Command preview</h4>'
                f"<pre>{_escape(command_result['command'])}</pre></div>",
                '<div class="metrics-row">'
                f'<div class="metric"><span class="metric__label">Exit code</span>'
                f'<span class="metric__value">{_escape(command_result["exit_code"])}</span></div>'
                "</div>",
                f'<div class="panel"><h4>Console output</h4>'
                f"<pre>{_escape(command_result['output'] or 'No stdout captured.')}</pre></div>",
                "</div>",
            ]
        )
    parts.append("</section>")
    return "".join(parts)


def render_page(
    values: dict[str, Any],
    *,
    plugin_options: list[str] | None = None,
    score_result: dict[str, Any] | None = None,
    score_error: str | None = None,
    command_result: dict[str, Any] | None = None,
    command_error: str | None = None,
) -> str:
    plugin_options = plugin_options or []
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
            <p class="eyebrow">Local demo frontend</p>
            <h1>CANARY Web Console</h1>
          </div>
        </div>
        <p class="hero__copy">
          A lightweight zero-dependency web UI for scoring Jenkins plugins and running the same
          collection flows you already use from the CLI.
        </p>
      </div>
    </header>
    <main class="page-shell">
      <div class="grid">
        {_render_score_section(values, plugin_options, score_result, score_error)}
        {_render_command_section(values, plugin_options, command_result, command_error)}
      </div>
    </main>
    {_validation_script(plugin_options)}
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

    values = _merge_defaults()
    plugin_options = _load_plugin_choices(values["registry_path"])
    score_result = None
    score_error = None
    command_result = None
    command_error = None

    if method == "POST" and path in {"/score", "/run"}:
        form = parse_form(environ)
        values = _merge_defaults(form)
        plugin_options = _load_plugin_choices(values["registry_path"])
        try:
            if path == "/score":
                plugin = (form.get("plugin") or "").strip()
                if not plugin:
                    raise ValueError("Please enter a plugin ID to score.")
                if not _plugin_known(plugin, values["registry_path"]):
                    raise ValueError("Please choose a plugin ID from the current registry list.")
                score_result = _score_payload(
                    score_plugin_baseline(
                        plugin,
                        real=_bool_from_form(form.get("real")),
                    )
                )
            else:
                command_result = _run_command(values["command"], form)
        except Exception:  # pragma: no cover - UI safety net
            logger.exception("Unhandled webapp error while processing %s", path)
            public_error = (
                "Something went wrong while processing your request. Check the server logs."
            )
            if path == "/score":
                score_error = public_error
            else:
                command_error = public_error

    html_body = render_page(
        values,
        plugin_options=plugin_options,
        score_result=score_result,
        score_error=score_error,
        command_result=command_result,
        command_error=command_error,
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
