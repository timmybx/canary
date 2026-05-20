from __future__ import annotations

# ruff: noqa: E501
import collections
import html
import json
import logging
import mimetypes
import os
import re
import threading
import time as _time
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol, cast
from wsgiref.simple_server import make_server

from canary.scoring.baseline import ScoreResult, score_plugin_baseline
from canary.scoring.ml import MLScorer, MLScoreResult, load_ml_scorer, score_plugin_ml

DEFAULT_REGISTRY_PATH = "data/raw/registry/plugins.jsonl"
DEFAULT_MODEL_DIR = "data/processed/models/baseline_6m"
MODEL_OUTPUTS_ROOT = Path("data/processed/models").resolve()
ADVISORY_DATA_ROOT = Path("data/raw/advisories").resolve()
MODEL_OUTPUTS_ROOT_PARTS = Path("data/processed/models").parts
VALID_TABS = frozenset({"score", "ml", "about", "casestudy"})
MODEL_OUTPUT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

DEFAULTS: dict[str, Any] = {
    "active_tab": "score",
    "plugin": "",
    "real": True,
    "overwrite": False,
    "registry_path": DEFAULT_REGISTRY_PATH,
    "model_out_dir": DEFAULT_MODEL_DIR,
    "score_model_dir": DEFAULT_MODEL_DIR,
}

STATIC_DIR = Path(__file__).with_name("static")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-page AI explanation — rate limiter constants
# ---------------------------------------------------------------------------
_EXPLAIN_RATE_LIMIT_LOCK = threading.Lock()
_EXPLAIN_RATE_LIMIT: dict[str, list[float]] = collections.defaultdict(list)
_EXPLAIN_RATE_WINDOW = 3600  # 1 hour window
_EXPLAIN_RATE_MAX = 3  # max requests per IP per window


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
.score-output { display:grid; gap:1rem; align-content:start; }
details > summary { cursor:pointer; font-weight:600; color:var(--muted); font-size:.9rem; padding:.3rem 0; }
details[open] > summary { color:var(--text); }
details pre { margin-top:.6rem; }
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


def _score_payload(result: ScoreResult, score_model_dir: str = "") -> dict[str, Any]:
    payload = result.to_dict()
    payload["pretty_json"] = json.dumps(payload, indent=2, ensure_ascii=False)
    payload["pretty_features"] = json.dumps(payload["features"], indent=2, ensure_ascii=False)
    payload["score_model_dir"] = score_model_dir  # preserved for explain round-trip
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
    # Filter out drivers where the feature value is None — these were imputed
    # to the training mean by the pipeline, so showing "n/a" gives the analyst
    # nothing actionable. Fill from the next-ranked drivers that have real values.
    all_drivers = ml.get("drivers") or []
    drivers = [d for d in all_drivers if d.get("value") is not None]
    # If fewer than 8 visible drivers remain, pad with null-value ones marked as such
    if len(drivers) < 5 and len(all_drivers) > len(drivers):
        null_drivers = [d for d in all_drivers if d.get("value") is None]
        drivers = drivers + null_drivers[: max(0, 5 - len(drivers))]

    for d in drivers:
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
        feat_nm = d.get("name", "")
        val_str = _fmt_driver_value(val, feat_nm)
        feat_tip = _FEATURE_TIPS.get(feat_nm, "")
        name_html = (
            f'<span class="tip" data-tip="{_escape(feat_tip)}"><code>{_escape(feat_nm)}</code></span>'
            if feat_tip
            else f"<code>{_escape(feat_nm)}</code>"
        )
        drivers_html += (
            f'<li style="display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,.05)">'
            f'<span><span style="{color};font-weight:700;margin-right:.4rem">{_escape(icon)}</span>{name_html}</span>'
            f'<span class="muted" style="font-size:.85rem">{_escape(val_str)}</span>'
            f"</li>"
        )

    model_badge_html = _render_model_badge(ml.get("model_name") or "")

    return (
        '<div class="result-stack">'
        '<div class="score-banner">'
        f'<div><p class="eyebrow">ML Score (experimental)</p><h3>{_escape(ml["plugin"])}</h3></div>'
        f'<div style="display:flex;align-items:center;gap:.75rem">'
        f"{model_badge_html}"
        f'<div class="score-number">{_escape(ml["probability_pct"])}<span> advisory risk</span></div>'
        f'<span class="pill {risk_pill_cls}">{_escape(ml.get("risk_category", "?"))}</span>'
        "</div></div>"
        '<div class="metrics-row">'
        f'<div class="metric"><span class="metric__label">Probability</span><span class="metric__value">{_escape(str(ml["probability"]))}</span></div>'
        f'<div class="metric"><span class="metric__label">Risk category</span><span class="metric__value">{_escape(ml.get("risk_category", "?"))}</span></div>'
        f'<div class="metric"><span class="metric__label">Top drivers</span><span class="metric__value">{len(ml.get("drivers") or [])}</span></div>'
        "</div>"
        f'<div class="panel"><h4>Top contributing features</h4>'
        f'<p style="font-size:.78rem;color:var(--muted);margin:.2rem 0 .6rem">'
        f'<span style="color:#e05c5c;font-weight:700">▲</span> increases risk &nbsp;&nbsp;'
        f'<span style="color:#5ce0a0;font-weight:700">▼</span> decreases risk &nbsp;&nbsp;'
        f"Hover a feature name for details.</p>"
        f'<ul style="list-style:none;padding:0;margin:0">{drivers_html}</ul></div>'
        f'<div class="panel"><h4>ML result (JSON)</h4><pre>{_escape(ml["pretty_json"])}</pre></div>'
        "</div>"
    )


def _fmt_driver_value(val: float | int | str | None, feature_name: str = "") -> str:
    """
    Format a driver feature value for human display.

    Rules:
    - None / missing  → "n/a"
    - Days features   → "X days" or "X.X years" for large values
    - Fraction/rate   → 2 decimal places as percentage where appropriate
    - Count features  → integer with comma separator
    - Small floats    → 3 significant figures, no scientific notation
    - Large floats    → comma-separated integer
    """
    if val is None:
        return "n/a"
    try:
        v = float(val)
    except (TypeError, ValueError):
        return str(val)

    name = feature_name.lower()

    # Days features — convert large values to years
    if "days" in name or "age_days" in name:
        days = int(round(v))
        if abs(days) >= 730:
            years = days / 365.25
            return f"{years:.1f} yrs"
        return f"{days:,} days"

    # Fraction / rate features (0-1 range) — show as decimal, not %
    # (These are model feature values, not probabilities shown to users)
    if any(k in name for k in ("fraction", "ratio", "rate")):
        return f"{v:.3f}"

    # Count features — integer with commas
    if any(k in name for k in ("count", "events", "visits", "days_active")):
        return f"{int(round(v)):,}"

    # Month staleness features — "X months"
    if "months_since" in name:
        months = int(round(v))
        if months >= 24:
            years = months / 12
            return f"{years:.1f} yrs"
        return f"{months} mo"

    # Small values (< 1000) — 3 sig figs, no sci notation
    if abs(v) < 1000:
        # Avoid showing e.g. "4.00" for integers
        if v == int(v):
            return f"{int(v):,}"
        return f"{v:.3g}"

    # Large values — comma-separated integer
    return f"{int(round(v)):,}"


def _build_explain_prompt(
    plugin: str,
    score_result: dict[str, Any],
    ml: dict[str, Any] | None,
) -> str:
    """Assemble a structured LLM prompt from the score data."""
    lines: list[str] = [
        "You are a cybersecurity analyst assistant. A tool called CANARY has just "
        "assessed the near-term advisory risk for a Jenkins plugin. Please explain "
        "the results below in plain English for a software security analyst who is "
        "not familiar with machine learning. Focus on:",
        "  1. What the overall risk level means practically",
        "  2. The two or three most important reasons driving the score",
        "  3. What concrete actions the analyst should consider",
        "  4. Any caveats or limitations worth mentioning",
        "",
        "Keep the explanation concise — three to five short paragraphs.",
        "",
        "=" * 60,
        f"CANARY ASSESSMENT — Plugin: {plugin}",
        "=" * 60,
        "",
    ]

    score = score_result.get("score", "?")
    reasons = score_result.get("reasons", [])
    lines.append(f"HEURISTIC SCORE: {score} / 100")
    lines.append("")
    lines.append("Scoring rationale:")
    for r in reasons:
        lines.append(f"  * {r}")
    lines.append("")

    components = score_result.get("features", {}).get("score_components")
    if components:
        lines.append("Score breakdown by component:")
        for k, v in components.items():
            lines.append(f"  * {k.replace('_', ' ').title()}: {v} pts")
        lines.append("")

    if ml:
        prob = ml.get("probability", "?")
        risk_cat = ml.get("risk_category", "?")
        model_nm = ml.get("model_name", "")
        model_dr = (ml.get("model_dir") or "").split("/")[-1]
        try:
            prob_pct = f"{float(prob) * 100:.1f}%"
        except (TypeError, ValueError):
            prob_pct = str(prob)
        lines.append(
            f"ML ADVISORY RISK SCORE: {prob} ({prob_pct} probability of "
            "a security advisory within 180 days)"
        )
        lines.append(f"Risk category: {risk_cat}")
        if model_nm:
            lines.append(f"Model: {model_nm} ({model_dr})")
        lines.append("")
        drivers = ml.get("drivers") or []
        if drivers:
            lines.append("Top contributing features (from ML model):")
            for d in drivers[:8]:
                name = d.get("name", "")
                val = d.get("value")
                dirn = d.get("direction", "")
                arrow = (
                    "increases risk"
                    if dirn == "increases_risk"
                    else "decreases risk"
                    if dirn == "decreases_risk"
                    else "neutral"
                )
                val_s = _fmt_driver_value(val, name)
                lines.append(f"  * {name} = {val_s}  [{arrow}]")
            lines.append("")

    lines += ["=" * 60, "Please provide your plain-English explanation now."]
    return "\n".join(lines)


def _check_explain_rate_limit(ip: str) -> bool:
    """Return True if this IP is within the allowed request rate."""
    now = _time.monotonic()
    with _EXPLAIN_RATE_LIMIT_LOCK:
        timestamps = _EXPLAIN_RATE_LIMIT[ip]
        cutoff = now - _EXPLAIN_RATE_WINDOW
        # Prune old timestamps
        _EXPLAIN_RATE_LIMIT[ip] = [t for t in timestamps if t > cutoff]
        if len(_EXPLAIN_RATE_LIMIT[ip]) >= _EXPLAIN_RATE_MAX:
            return False
        _EXPLAIN_RATE_LIMIT[ip].append(now)
        return True


def _call_anthropic_explain(prompt: str) -> str:
    """
    Call the Anthropic API and return the explanation text.
    Uses a tight token cap to bound cost.
    Raises RuntimeError with the full API error body on failure.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set.")

    payload = json.dumps(
        {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 800,
            "system": (
                "You are a concise cybersecurity analyst assistant. "
                "Explain CANARY risk scores in plain English. "
                "Keep responses to 3-5 short paragraphs. Be direct and actionable. "
                "Do not use markdown headers or bullet lists — write in flowing prose only."
            ),
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()

    api_url = "https://api.anthropic.com/v1/messages"
    parsed = urllib.parse.urlparse(api_url)
    if parsed.scheme != "https" or parsed.netloc != "api.anthropic.com":
        raise ValueError("Refusing to call non-allowlisted Anthropic API URL.")

    req = urllib.request.Request(
        api_url,
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"Anthropic API error {exc.code}: {body}") from exc

    blocks = data.get("content") or []
    return "\n\n".join(b["text"] for b in blocks if b.get("type") == "text").strip()


def _render_explain_card(
    plugin: str,
    score_result: dict[str, Any],
    ai_result: str | None = None,
    ai_error: str | None = None,
    rate_limited: bool = False,
) -> str:
    """
    Render the Explain with AI card.
    Shows copy-prompt buttons plus an optional in-page AI response panel.
    """
    import urllib.parse as _up

    ml = score_result.get("ml")
    prompt = _build_explain_prompt(plugin, score_result, ml)

    claude_url = "https://claude.ai/new?q=" + _up.quote(prompt, safe="")
    chatgpt_url = "https://chatgpt.com/?q=" + _up.quote(prompt, safe="")

    btn_copy = (
        '<button type="button"'
        ' onclick="(function(b){navigator.clipboard.writeText('
        "document.getElementById('ep').value)"
        ".then(function(){var o=b.textContent;b.textContent='Copied!';"
        "setTimeout(function(){b.textContent=o;},2000);})"
        ".catch(function(){document.getElementById('ep').select();"
        "document.execCommand('copy');});})(this)\""
        ' style="background:var(--accent);border:none;color:#fff;'
        "padding:.45rem .9rem;border-radius:8px;cursor:pointer;"
        'font-weight:600;font-size:.85rem">Copy prompt</button>'
    )
    btn_claude = (
        f'<a href="{claude_url}" target="_blank" rel="noopener noreferrer"'
        ' style="display:inline-flex;align-items:center;'
        "background:rgba(204,153,51,.15);border:1px solid rgba(204,153,51,.3);"
        "color:#cc9933;padding:.45rem .9rem;border-radius:8px;"
        'text-decoration:none;font-weight:600;font-size:.85rem">Open in Claude</a>'
    )
    btn_chatgpt = (
        f'<a href="{chatgpt_url}" target="_blank" rel="noopener noreferrer"'
        ' style="display:inline-flex;align-items:center;'
        "background:rgba(16,163,127,.12);border:1px solid rgba(16,163,127,.3);"
        "color:#10a37f;padding:.45rem .9rem;border-radius:8px;"
        'text-decoration:none;font-weight:600;font-size:.85rem">Open in ChatGPT</a>'
    )

    # In-page "Explain now" button — uses GET so corporate firewalls don't block it
    _explain_model_dir = _escape(score_result.get("score_model_dir") or "")
    _explain_plugin = _escape(plugin)
    btn_inpage = (
        '<form method="get" action="/" style="display:inline">'
        '<input type="hidden" name="tab" value="score">'
        f'<input type="hidden" name="plugin" value="{_explain_plugin}">'
        f'<input type="hidden" name="score_model_dir" value="{_explain_model_dir}">'
        '<input type="hidden" name="explain" value="1">'
        '<button type="submit"'
        ' style="background:rgba(120,80,220,.2);border:1px solid rgba(120,80,220,.4);'
        "color:#a78bfa;padding:.45rem .9rem;border-radius:8px;cursor:pointer;"
        'font-weight:600;font-size:.85rem">Explain now (AI)</button>'
        "</form>"
    )

    textarea = (
        '<details style="margin-top:.6rem">'
        '<summary style="cursor:pointer;font-size:.82rem;color:var(--muted);'
        'padding:.25rem 0">Show / edit raw prompt</summary>'
        '<textarea id="ep" readonly'
        ' style="width:100%;min-height:160px;margin-top:.4rem;'
        "background:var(--panel2);border:1px solid var(--line);"
        "border-radius:8px;padding:.6rem;font-family:var(--mono);"
        "font-size:.75rem;line-height:1.5;color:var(--text);"
        'resize:vertical;box-sizing:border-box">'
        f"{_escape(prompt)}</textarea>"
        "</details>"
    )

    # In-page AI result panel
    ai_panel = ""
    if rate_limited:
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.7rem .9rem;'
            "background:rgba(220,80,60,.1);border:1px solid rgba(220,80,60,.3);"
            'border-radius:8px;font-size:.88rem;color:#e05c5c">'
            "Rate limit reached — you can request up to "
            f"{_EXPLAIN_RATE_MAX} AI explanations per hour. "
            "Use the Copy or Open buttons to continue in your own AI session."
            "</div>"
        )
    elif ai_error:
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.7rem .9rem;'
            "background:rgba(220,80,60,.1);border:1px solid rgba(220,80,60,.3);"
            'border-radius:8px;font-size:.88rem;color:#e05c5c">'
            f"AI explanation error: {_escape(ai_error)}"
            "</div>"
        )
    elif ai_result:
        # Render the AI response — convert newlines to <p> tags
        def _md_to_html(text: str) -> str:
            """Convert basic markdown to HTML for AI response display."""
            import re as _re

            # Escape HTML first
            t = _escape(text)
            # ## Heading → bold header
            t = _re.sub(r"^##\s+(.+)$", r"<strong>\1</strong>", t, flags=_re.MULTILINE)
            # **bold** → <strong>
            t = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
            # *italic* → <em>
            t = _re.sub(r"\*(.+?)\*", r"<em>\1</em>", t)
            # Numbered list items
            t = _re.sub(r"^\d+\.\s+", r"&nbsp;&nbsp;• ", t, flags=_re.MULTILINE)
            return t

        paras = "".join(
            f"<p style='margin:.5rem 0'>{_md_to_html(p.strip())}</p>"
            for p in ai_result.split("\n\n")
            if p.strip()
        )
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.8rem 1rem;'
            "background:rgba(120,80,220,.08);border:1px solid rgba(120,80,220,.25);"
            'border-radius:10px">'
            '<p style="font-size:.78rem;color:#a78bfa;font-weight:600;margin:0 0 .5rem">'
            "AI explanation (Claude)</p>"
            f"{paras}"
            "</div>"
        )

    tip = (
        '<p style="font-size:.76rem;color:var(--muted);margin-top:.5rem">'
        '"Explain now" uses the server API key (max 3/hr). '
        '"Open in" buttons use your own account with no limits.'
        "</p>"
    )

    # ── "Bring your own AI" collapsible section ──────────────────────────────
    byoai_section = (
        '<details style="margin-top:.9rem;border-top:1px solid var(--line);padding-top:.8rem">'
        '<summary style="cursor:pointer;font-size:.88rem;font-weight:600;color:var(--muted);'
        'padding:.2rem 0">Bring your own AI</summary>'
        '<p style="font-size:.82rem;color:var(--muted);margin:.5rem 0 .7rem">Copy the prompt '
        "below and paste it into Claude, ChatGPT, or any other AI assistant. "
        "You control what gets shared.</p>"
        '<div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.6rem">'
        + btn_copy
        + btn_claude
        + btn_chatgpt
        + "</div>"
        + textarea
        + "</details>"
    )

    return (
        '<section class="card" style="align-self:start">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">AI explanation</p>'
        "<h2>Explain this score</h2>"
        "</div></div>"
        # Primary action — in-page explanation
        '<div style="margin:.6rem 0">'
        + btn_inpage
        + "</div>"
        + ai_panel
        + byoai_section
        + tip
        + "</section>"
    )


def _render_score_section(
    values: dict[str, Any],
    plugin_options: list[str],
    score_result: dict[str, Any] | None,
    score_error: str | None,
    model_dir_options: list[str] | None = None,
    ai_result: str | None = None,
    ai_error: str | None = None,
    rate_limited: bool = False,
) -> str:
    # Build model dropdown with human-readable labels grouped by algorithm.
    # Uses the same parser as the ML tab picker so names are consistent.
    from pathlib import Path as _Path

    ml_model_options: list[tuple[str, str]] = [("", "— none / heuristic only —")]

    # Group parsed models by algorithm for a logical ordering
    grouped: dict[str, list[tuple[str, str]]] = {a: [] for a in _ALGO_ORDER}
    ungrouped: list[tuple[str, str]] = []

    for d in model_dir_options or []:
        parsed = _parse_model_dir(d)
        if parsed is not None:
            algo, feat, split = parsed
            feat_label = _FEATURE_LABELS.get(feat, feat)
            split_label = _SPLIT_LABELS.get(split, split)
            label = f"{feat_label}  ({split_label})"
            grouped.setdefault(algo, []).append((d, label))
        else:
            # Fallback for dirs that don't match the naming convention
            ungrouped.append((d, _Path(d).name))

    for algo in _ALGO_ORDER:
        entries = sorted(grouped.get(algo, []), key=lambda x: x[1])
        if entries:
            algo_label = _ALGO_LABELS.get(algo, algo)
            for val, label in entries:
                ml_model_options.append((val, f"{algo_label} — {label}"))

    for val, label in ungrouped:
        ml_model_options.append((val, label))

    # ── Left column: form card ────────────────────────────────────────────────
    form_card = "".join(
        [
            '<section class="card" style="align-self:start">',
            '<div class="card__header"><div>'
            '<p class="eyebrow">Plugin scoring</p>'
            "<h2>Score a plugin</h2>"
            '<p class="kicker">Review the CANARY score, rationale, and supporting evidence.</p>'
            '</div><span class="pill">Core workflow</span></div>',
            '<form method="get" action="/" style="display:grid;gap:.9rem" data-plugin-strict="true">',
            '<input type="hidden" name="tab" value="score">',
            _plugin_picker("plugin", "Plugin ID", values["plugin"], plugin_options),
            _select(
                "score_model_dir", "ML model", values.get("score_model_dir", ""), ml_model_options
            ),
            '<button type="submit">Score plugin</button></form>',
            f'<div class="notice">{_escape(score_error)}</div>' if score_error else "",
            "</section>",
            # Explain card always shown in left column after scoring
            _render_explain_card(
                score_result["plugin"],
                score_result,
                ai_result=ai_result,
                ai_error=ai_error,
                rate_limited=rate_limited,
            )
            if score_result
            else "",
        ]
    )

    # ── Right column: output cards stacked vertically ─────────────────────────
    output_parts: list[str] = []

    if score_result:
        # Heuristic score card — compact, with collapsible raw sections
        reasons_html = "".join(f"<li>{_escape(r)}</li>" for r in score_result["reasons"])
        output_parts.append(
            '<section class="card">'
            '<div class="card__header"><div>'
            '<p class="eyebrow">Heuristic score</p>'
            f"<h2>{_escape(score_result['plugin'])}</h2>"
            '<p class="kicker">Rule-based score — independent of the ML model selection above.</p>'
            "</div>"
            f'<div class="score-number">{_escape(score_result["score"])}<span>/100</span></div>'
            "</div>"
            '<div class="metrics-row" style="margin-top:.8rem">'
            f'<div class="metric"><span class="metric__label">Reasons</span><span class="metric__value">{len(score_result["reasons"])}</span></div>'
            f'<div class="metric"><span class="metric__label">Features</span><span class="metric__value">{len(score_result["features"])}</span></div>'
            "</div>"
            f'<div class="panel" style="margin-top:.8rem"><h4>Why this score</h4><ul class="bullet-list">{reasons_html}</ul></div>'
            '<div style="margin-top:.8rem;display:grid;gap:.6rem">'
            f"<details><summary>Feature details ({len(score_result['features'])} keys)</summary><pre>{_escape(score_result['pretty_features'])}</pre></details>"
            f"<details><summary>JSON payload</summary><pre>{_escape(score_result['pretty_json'])}</pre></details>"
            "</div>"
            "</section>"
        )

        # ML score card
        ml = score_result.get("ml")
        if ml:
            output_parts.append(
                '<section class="card">'
                '<div class="card__header"><div>'
                '<p class="eyebrow">Machine learning</p>'
                "<h2>ML advisory risk score</h2>"
                '<p class="kicker">Probability of a Jenkins security advisory within the next 180 days.</p>'
                '</div><span class="pill pill--muted">Experimental</span></div>'
                + _render_ml_score_panel(ml)
                + "</section>"
            )
        else:
            output_parts.append(
                '<section class="card">'
                '<div class="card__header"><div>'
                '<p class="eyebrow">Machine learning</p>'
                "<h2>ML advisory risk score</h2>"
                '</div><span class="pill pill--muted">Not available</span></div>'
                '<p class="muted" style="padding:.6rem 0">Select a trained ML model above, or run '
                "<strong>canary train baseline</strong> to create one.</p>"
                "</section>"
            )
    else:
        output_parts.append(
            '<section class="card">'
            '<p class="muted" style="padding:.4rem 0">Choose a plugin and click '
            "<strong>Score plugin</strong> to see results here.</p>"
            "</section>"
        )

    right_col = '<div class="score-output">' + "".join(output_parts) + "</div>"

    left_col = '<div class="score-output">' + form_card + "</div>"

    return '<div class="grid--score">' + left_col + right_col + "</div>"


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


def _load_precision_at_k(model_out_dir: str | Path) -> dict[str, Any] | None:
    """Load precision_at_k.json from a model directory if it exists."""
    try:
        parts = _model_output_dir_parts(model_out_dir)
    except ValueError:
        return None
    # Try direct path first (works on Render where paths resolve consistently)
    stem = Path(str(model_out_dir)).name
    for target in [
        MODEL_OUTPUTS_ROOT / stem / "precision_at_k.json",
        MODEL_OUTPUTS_ROOT.joinpath(*parts, "precision_at_k.json"),
    ]:
        if target.exists():
            try:
                return json.loads(target.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                return None
    return None


def _render_operational_panel(pk: dict[str, Any]) -> str:
    """
    Render the operational scenario analysis panel.

    Shows results in plain English: "if your team reviews X plugins per cycle,
    CANARY identifies Y of Z future advisory plugins with P% precision."
    This directly answers the question a security manager would actually ask.
    """
    n_pos = pk.get("n_positive", 0)
    n_test = pk.get("n_test", 0)
    base_rate = pk.get("base_rate", 0.0)
    scenarios = pk.get("scenarios") or []
    targets = pk.get("recall_targets") or []
    split = pk.get("split_strategy", "time")

    if not scenarios:
        return ""

    # Context note about evaluation strategy
    split_label = "time split" if split == "time" else "group-time split"
    context = (
        f'<p style="font-size:.84rem;color:var(--muted);margin:.4rem 0 .9rem">'
        f"Based on {n_test:,} test observations, {n_pos} future advisory plugins, "
        f"base rate {base_rate * 100:.2f}% &mdash; evaluated under <strong>{split_label}</strong>. "
        f"Time-split results represent continuous monitoring of a known plugin inventory."
        f"</p>"
    )

    # Scenario table
    rows_html = ""
    for s in scenarios:
        k = s.get("k", 0)
        tp = s.get("true_positives", 0)
        prec = s.get("precision", 0.0)
        rec = s.get("recall", 0.0)
        lift = s.get("lift", 0.0)
        label = _escape(s.get("label", ""))
        if prec >= 0.90:
            prec_color = "color:#5ce0a0;font-weight:700"
        elif prec >= 0.60:
            prec_color = "color:#e6a01e;font-weight:700"
        else:
            prec_color = "color:var(--text)"
        rows_html += (
            f"<tr>"
            f"<td style='padding:.5rem .75rem;font-size:.88rem'>{label}</td>"
            f"<td style='padding:.5rem .75rem;text-align:right;font-size:.88rem'>{k}</td>"
            f"<td style='padding:.5rem .75rem;text-align:right;font-size:.88rem'>"
            f"{tp} of {n_pos}</td>"
            f"<td style='padding:.5rem .75rem;text-align:right;{prec_color}'>"
            f"{prec:.0%}</td>"
            f"<td style='padding:.5rem .75rem;text-align:right;font-size:.88rem'>"
            f"{rec:.0%}</td>"
            f"<td style='padding:.5rem .75rem;text-align:right;font-size:.88rem;"
            f"color:var(--muted)'>{lift:.1f}x</td>"
            f"</tr>"
        )

    table_html = (
        '<table style="width:100%;border-collapse:collapse">'
        "<thead><tr>"
        + "".join(
            f"<th style='text-align:{align};padding:.4rem .75rem;"
            f"font-size:.8rem;color:var(--muted);font-weight:600'>{h}</th>"
            for h, align in [
                ("Scenario", "left"),
                ("Review", "right"),
                ("Catch", "right"),
                ("Precision", "right"),
                ("Recall", "right"),
                ("vs. random", "right"),
            ]
        )
        + "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
    )

    # Recall target callouts
    callout_parts = []
    for t in targets:
        rec_pct = int(t.get("target_recall", 0) * 100)
        k_need = t.get("plugins_to_review", 0)
        pct_eco = t.get("pct_of_ecosystem")
        tp_t = t.get("true_positives", 0)
        prec_t = t.get("precision", 0.0)
        eco_str = f" ({pct_eco:.1f}% of ecosystem)" if pct_eco is not None else ""
        callout_parts.append(
            f'<div style="padding:.5rem .75rem;background:var(--panel2);'
            f'border-radius:8px;font-size:.84rem">'
            f"<strong>{rec_pct}% recall</strong><br>"
            f'<span style="color:var(--muted)">Review top {k_need}{eco_str} → '
            f"catch {tp_t}/{n_pos} ({prec_t:.0%} precision)</span>"
            f"</div>"
        )
    callouts_html = (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));'
        f'gap:.5rem;margin-top:.75rem">{"".join(callout_parts)}</div>'
        if callout_parts
        else ""
    )

    # Key headline finding (best scenario)
    best = scenarios[2] if len(scenarios) > 2 else (scenarios[-1] if scenarios else None)
    headline = ""
    if best:
        headline = (
            '<div style="margin-bottom:.75rem;padding:.7rem .9rem;'
            "background:rgba(82,196,26,.08);border:1px solid rgba(82,196,26,.25);"
            'border-radius:10px;font-size:.9rem">'
            f"<strong>Key finding:</strong> reviewing the top "
            f"<strong>{best['k']}</strong> highest-scored plugins "
            f"({best['k'] / n_test * 100:.1f}% of the ecosystem) identifies "
            f"<strong>{best['true_positives']} of {n_pos}</strong> future advisory "
            f"plugins with <strong>{best['precision']:.0%} precision</strong> "
            f"&mdash; a <strong>{best['lift']:.0f}x</strong> improvement over random selection."
            "</div>"
        )

    return (
        "<div>"
        "<h4>Operational scenario analysis</h4>"
        + context
        + headline
        + table_html
        + callouts_html
        + '<p style="font-size:.78rem;color:var(--muted);margin-top:.6rem">'
        "Precision = fraction of flagged plugins that had a future advisory. "
        "Recall = fraction of all future advisory plugins that were flagged. "
        "vs. random = improvement over baseline rate of selecting plugins at random."
        "</p>"
        "</div>"
    )


def _render_ml_metrics(metrics: dict[str, Any] | None, model_out_dir: str = "") -> str:
    if not metrics:
        return '<p class="muted">Train a baseline or load metrics from an existing model run to surface results here.</p>'
    pk_data = _load_precision_at_k(model_out_dir) if model_out_dir else None

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
        + (
            f'<span class="small muted">Trained from: <strong>{_escape(metrics.get("train_start_month") or "")}</strong></span>'
            if metrics.get("train_start_month")
            else (
                f'<span class="small muted">Train rows: <strong>{_metric_value(metrics.get("train_row_count"), digits=0)}</strong></span>'
                if metrics.get("train_row_count")
                else ""
            )
        )
        + "</div>"
    )

    operational_panel_html = (
        f'<div class="panel">{_render_operational_panel(pk_data)}</div>' if pk_data else ""
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
        f"{operational_panel_html}"
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


# ---------------------------------------------------------------------------
# Feature selection loader and renderer
# ---------------------------------------------------------------------------


def _load_feature_selection(model_out_dir: str | Path) -> dict[str, Any] | None:
    """Load feature_selection.json from a model directory if it exists."""
    if not model_out_dir:
        return None
    try:
        # Build the path directly from MODEL_OUTPUTS_ROOT + the final directory
        # name rather than going through _model_output_dir_parts, which uses
        # an absolute-path prefix check that can fail when the working directory
        # differs between environments (e.g. local dev vs Render deployment).
        stem = Path(str(model_out_dir)).name  # just "lgb_6m_full_cleaned_time"
        target = MODEL_OUTPUTS_ROOT / stem / "feature_selection.json"
        if not target.exists():
            return None
        return json.loads(target.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _render_feature_selection_panel(fs: dict[str, Any]) -> str:
    """Render the feature selection results as a card body."""
    full_n = fs.get("full_model_feature_count", "?")
    full_ap = fs.get("full_model_average_precision")
    h3_ok = fs.get("h3_satisfied", False)
    h3_info = fs.get("h3_smallest_qualifying_subset")
    results = fs.get("subset_results", [])
    ranking = fs.get("feature_ranking", [])

    if h3_ok and h3_info:
        verdict_cls = "pill pill--warn"
        verdict = (
            f"H3 SATISFIED &#x2014; {h3_info['size']}-feature model retains "
            f"{h3_info['ap_retention'] * 100:.1f}% of full AP "
            f"({h3_info['average_precision']:.4f})"
        )
    else:
        verdict_cls = "pill pill--muted"
        verdict = "H3 not satisfied at evaluated subset sizes"

    rows_html = ""
    for res in results:
        label = _escape(res.get("subset_label", "?"))
        n = res.get("actual_feature_count", "?")
        ap = res.get("average_precision")
        ret = res.get("ap_retention_vs_full")
        h3_flag = res.get("meets_h3_threshold")
        ap_str = f"{ap:.4f}" if ap is not None else "n/a"
        ret_str = f"{ret * 100:.1f}%" if ret is not None else "—"
        h3_cell = (
            '<span style="color:#5ce0a0;font-weight:700">&#x2713;</span>'
            if h3_flag is True
            else ('<span style="color:var(--muted)">&#x2014;</span>' if h3_flag is False else "")
        )
        is_full = "full" in str(res.get("subset_label", ""))
        row_style = 'style="background:rgba(255,255,255,.04)"' if is_full else ""
        rows_html += (
            f"<tr {row_style}>"
            f"<td><code>{label}</code></td>"
            f"<td style='text-align:right'>{n}</td>"
            f"<td style='text-align:right'>{ap_str}</td>"
            f"<td style='text-align:right'>{ret_str}</td>"
            f"<td style='text-align:center'>{h3_cell}</td>"
            f"</tr>"
        )

    table_html = (
        '<table style="width:100%;border-collapse:collapse;font-size:.9rem;margin-top:.6rem">'
        "<thead><tr>"
        "<th style='text-align:left;padding:.3rem .5rem;color:var(--muted)'>Subset</th>"
        "<th style='text-align:right;padding:.3rem .5rem;color:var(--muted)'>Features</th>"
        "<th style='text-align:right;padding:.3rem .5rem;color:var(--muted)'>Avg Precision</th>"
        "<th style='text-align:right;padding:.3rem .5rem;color:var(--muted)'>% of Full</th>"
        "<th style='text-align:center;padding:.3rem .5rem;color:var(--muted)'>H3 &#x2265;90%</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
    )

    all_features_html = ""
    if ranking:
        max_score = ranking[0].get("mean_abs_shap", 1.0) or 1.0
        for item in ranking:
            rank = item.get("rank", "")
            feat = str(item.get("feature", ""))
            score = item.get("mean_abs_shap", 0.0)
            bar_w = max(4, int(score / max_score * 180))
            feat_tip = _FEATURE_TIPS.get(feat, "")
            name_html = (
                f'<span class="tip" data-tip="{_escape(feat_tip)}">'
                f'<code style="flex:1;font-size:.82rem">{_escape(feat)}</code></span>'
                if feat_tip
                else f'<code style="flex:1;font-size:.82rem">{_escape(feat)}</code>'
            )
            # Items beyond 10 are hidden by default; JS toggles visibility
            # Use a single consistent style — JS overrides display only
            is_hidden = bool(rank and int(rank) > 10)
            li_style = (
                "display:none;align-items:center;gap:.5rem;padding:.25rem 0;"
                "border-bottom:1px solid rgba(255,255,255,.04)"
                if is_hidden
                else "display:flex;align-items:center;gap:.5rem;padding:.25rem 0;"
                "border-bottom:1px solid rgba(255,255,255,.04)"
            )
            all_features_html += (
                f'<li data-rank="{rank}" style="{li_style}">'
                f'<span style="color:var(--muted);width:1.6rem;text-align:right;font-size:.8rem">{rank}</span>'
                f"{name_html}"
                f'<span style="width:{bar_w}px;height:6px;background:#3266ad;'
                f'border-radius:3px;flex-shrink:0"></span>'
                f'<span style="color:var(--muted);font-size:.8rem;width:4.5rem;'
                f'text-align:right">{score:.5f}</span>'
                f"</li>"
            )

    # Show-more button controls — only rendered when there are more than 10 features
    n_features = len(ranking) if ranking else 0
    show_controls = ""
    if n_features > 10:
        steps = [s for s in [10, 15, 20, 30, 50, n_features] if s <= n_features]
        # deduplicate while preserving order
        seen: set[int] = set()
        steps = [s for s in steps if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]
        btn_style = (
            "background:none;border:1px solid var(--line);color:var(--muted);"
            "padding:.25rem .7rem;border-radius:6px;cursor:pointer;font-size:.8rem;"
            "margin:.1rem"
        )
        btns = "".join(
            f'<button type="button" style="{btn_style}" '
            f'onclick="fsShowTop(this,{s})">'
            f"{'All' if s == n_features else f'Top {s}'}"
            f"</button>"
            for s in steps
        )
        show_controls = (
            f'<div style="margin-top:.5rem;display:flex;align-items:center;'
            f'flex-wrap:wrap;gap:.2rem">'
            f'<span style="font-size:.78rem;color:var(--muted);margin-right:.3rem">Show:</span>'
            f"{btns}"
            f"</div>"
            f"<script>"
            f"function fsShowTop(btn,n){{"
            f'var ul=btn.closest(".panel").querySelector("ul");'
            f'ul.querySelectorAll("li[data-rank]").forEach(function(li){{'
            f'var r=parseInt(li.getAttribute("data-rank"));'
            f'li.style.display=r<=n?"flex":"none";}});'
            f'btn.closest("div").querySelectorAll("button")'
            f'.forEach(function(b){{b.style.fontWeight=b===btn?"700":"normal";}});'
            f'var h=btn.closest(".panel").querySelector("#fs-feat-title");'
            f'if(h){{h.firstChild.textContent=(n>={n_features}?"All "+{n_features}:"Top "+n)+" features by importance";}}'
            f"}}"
            f"</script>"
        )

    features_panel = (
        (
            f'<div class="panel" style="margin-top:.6rem">'
            f'<h4 id="fs-feat-title">Top {min(10, n_features)} features by importance'
            f'<span style="font-weight:normal;color:var(--muted);font-size:.82rem"> — hover a name for details</span></h4>'
            f'<ul style="list-style:none;padding:0;margin:0">{all_features_html}</ul>'
            f"{show_controls}"
            f"</div>"
        )
        if all_features_html
        else ""
    )

    return (
        f'<span class="{verdict_cls}" style="margin-bottom:.6rem;display:inline-block">'
        f"{verdict}</span>"
        f'<div class="metrics-row" style="margin:.6rem 0">'
        f'<div class="metric"><span class="metric__label">Full model features</span>'
        f'<span class="metric__value">{full_n}</span></div>'
        f'<div class="metric"><span class="metric__label">Full model AP</span>'
        f'<span class="metric__value">{f"{full_ap:.4f}" if full_ap is not None else "n/a"}</span></div>'
        f'<div class="metric"><span class="metric__label">H3 satisfied</span>'
        f'<span class="metric__value">{"Yes" if h3_ok else "No"}</span></div>'
        f"</div>"
        f'<div class="panel" style="margin-top:.6rem">'
        f"<h4>AP retention by feature subset</h4>{table_html}</div>" + features_panel
    )


# ---------------------------------------------------------------------------
# Structured model picker
# ---------------------------------------------------------------------------

_ALGO_LABELS: dict[str, str] = {
    "logistic": "Logistic Regression",
    "xgb": "XGBoost",
    "lgb": "LightGBM",
    "rf": "Random Forest",
}
_FEATURE_LABELS: dict[str, str] = {
    "advisory_only": "Advisory history only",
    "gharchive_only": "GHArchive only",
    "swh_only": "Software Heritage only",
    "advisory_gharchive": "Advisory + GHArchive",
    "advisory_swh": "Advisory + SWH",
    "gharchive_swh": "GHArchive + SWH",
    "full_no_time": "Full (no window features)",
    "full_cleaned": "Full (all features)",
}
_SPLIT_LABELS: dict[str, str] = {
    "time": "Time split",
    "gt": "Group-time split",
}
_ALGO_ORDER = ["logistic", "xgb", "lgb", "rf"]
_FEATURE_ORDER = [
    "advisory_only",
    "gharchive_only",
    "swh_only",
    "advisory_gharchive",
    "advisory_swh",
    "gharchive_swh",
    "full_no_time",
    "full_cleaned",
]
_SPLIT_ORDER = ["time", "gt"]


def _parse_model_dir(name: str) -> tuple[str, str, str] | None:
    """Parse a directory name into (algo, feature_set, split) or None."""
    stem = Path(name).name
    for algo in _ALGO_LABELS:
        prefix = f"{algo}_6m_"
        if not stem.startswith(prefix):
            continue
        rest = stem[len(prefix) :]
        for feat in _FEATURE_LABELS:
            if rest == feat:
                return (algo, feat, "time")
            if rest == f"{feat}_time":
                return (algo, feat, "time")
            if rest == f"{feat}_gt":
                return (algo, feat, "gt")
    return None


def _build_model_index(model_dir_options: list[str]) -> dict[tuple[str, str, str], str]:
    """Map (algo, feature_set, split) → directory path."""
    index: dict[tuple[str, str, str], str] = {}
    for d in model_dir_options:
        parsed = _parse_model_dir(d)
        if parsed is not None:
            index[parsed] = d
    return index


def _render_model_picker(values: dict[str, Any], model_dir_options: list[str]) -> str:
    """Three cascading dropdowns that resolve to a model directory."""
    index = _build_model_index(model_dir_options)
    current = values.get("model_out_dir") or ""
    parsed_current = _parse_model_dir(current)
    cur_algo = parsed_current[0] if parsed_current else ""
    cur_feature = parsed_current[1] if parsed_current else ""
    cur_split = parsed_current[2] if parsed_current else ""

    def _opt(val: str, label: str, selected: str) -> str:
        sel = " selected" if val == selected else ""
        return f'<option value="{_escape(val)}"{sel}>{_escape(label)}</option>'

    algo_opts = '<option value="">— choose —</option>' + "".join(
        _opt(a, _ALGO_LABELS[a], cur_algo) for a in _ALGO_ORDER
    )
    feat_opts = '<option value="">— choose —</option>' + "".join(
        _opt(f, _FEATURE_LABELS[f], cur_feature) for f in _FEATURE_ORDER
    )
    split_opts = '<option value="">— choose —</option>' + "".join(
        _opt(s, _SPLIT_LABELS[s], cur_split) for s in _SPLIT_ORDER
    )

    js_map = json.dumps(
        {f"{a}|{f}|{s}": d for (a, f, s), d in index.items()},
        ensure_ascii=False,
    )
    resolved_label = Path(current).name if current else ""
    resolved_html = (
        f'<code style="color:var(--accent)">{_escape(resolved_label)}</code>'
        if current
        else '<span style="color:var(--muted)">— select all three dimensions —</span>'
    )

    return (
        '<div class="form-grid" style="margin-top:.8rem">'
        f'<label>Algorithm<select id="pick-algo" onchange="updatePicker()">{algo_opts}</select></label>'
        f'<label>Feature set<select id="pick-feat" onchange="updatePicker()">{feat_opts}</select></label>'
        f'<label>Evaluation<select id="pick-split" onchange="updatePicker()">{split_opts}</select></label>'
        "</div>"
        '<div style="margin:.75rem 0;padding:.6rem .8rem;background:var(--panel2);'
        'border:1px solid var(--line);border-radius:10px;font-size:.9rem">'
        f'<span style="color:var(--muted)">Resolved model: </span>'
        f'<span id="pick-resolved">{resolved_html}</span></div>'
        f'<input type="hidden" id="pick-model-dir" name="model_out_dir" value="{_escape(current)}">'
        f"<script>const _PICKER_MAP={js_map};"
        "function updatePicker(){{"
        'const a=document.getElementById("pick-algo").value;'
        'const f=document.getElementById("pick-feat").value;'
        'const s=document.getElementById("pick-split").value;'
        'const key=a+"|"+f+"|"+s;'
        'const dir=_PICKER_MAP[key]||"";'
        'document.getElementById("pick-model-dir").value=dir;'
        'const lbl=dir?dir.split("/").pop():"";'
        'document.getElementById("pick-resolved").innerHTML=dir'
        '?`<code style="color:var(--accent)">${lbl}</code>`'
        ':`<span style="color:var(--muted)">— combination not yet available —</span>`;}}'
        "</script>"
    )


def _build_ml_explain_prompt(
    metrics: dict[str, Any],
    pk_data: dict[str, Any] | None,
    fs_data: dict[str, Any] | None,
    model_out_dir: str,
) -> str:
    """Build a focused LLM prompt from ML metrics for the ML tab explain feature."""
    parsed = _parse_model_dir(model_out_dir)
    algo = _ALGO_LABELS.get(parsed[0], parsed[0]) if parsed else "Unknown"
    feat_set = _FEATURE_LABELS.get(parsed[1], parsed[1]) if parsed else "Unknown"
    split = _SPLIT_LABELS.get(parsed[2], parsed[2]) if parsed else "Unknown"

    roc = metrics.get("roc_auc")
    ap = metrics.get("average_precision")
    n_test = metrics.get("test_row_count", 0)
    n_pos = metrics.get("test_positive_count", 0)
    base = n_pos / n_test if n_test > 0 else 0.0
    feat_cnt = metrics.get("feature_count", 0)
    model_nm = metrics.get("model_name", algo)

    ranking = metrics.get("ranking_metrics") or {}
    p10 = ranking.get("precision_at_10")
    p25 = ranking.get("precision_at_25")
    p50 = ranking.get("precision_at_50")
    p100 = ranking.get("precision_at_100")

    top_pos = metrics.get("top_positive_features") or []

    lines: list[str] = [
        "You are a cybersecurity analyst assistant. The following are machine learning "
        "evaluation results for CANARY, a tool that predicts near-term Jenkins plugin "
        "advisory risk. Please explain what these results mean for a security manager "
        "deciding whether to deploy this model in their Jenkins environment. Focus on:",
        "  1. Whether the model is reliable enough to act on",
        "  2. What the precision-at-K results mean for team sizing and workload",
        "  3. What the top features reveal about what drives advisory risk",
        "  4. Any important caveats about the evaluation design",
        "",
        "Keep the explanation to 3-5 short paragraphs. Write in plain prose — "
        "no markdown headers or bullet lists.",
        "",
        "=" * 60,
        f"MODEL: {model_nm} | Feature set: {feat_set} | Evaluation: {split}",
        f"Features used: {feat_cnt}",
        "=" * 60,
        "",
        "CORE METRICS:",
        f"  ROC-AUC:           {roc:.4f}" if roc else "  ROC-AUC:           n/a",
        f"  Average Precision: {ap:.4f}" if ap else "  Average Precision: n/a",
        f"  Test set:          {n_test:,} observations, {n_pos} advisory plugins",
        f"  Base rate:         {base * 100:.2f}% (random selection benchmark)",
        "",
    ]

    if p10 is not None or p25 is not None:
        lines.append("PRECISION AT K (top-K plugins reviewed per cycle):")
        for k, v in [("10", p10), ("25", p25), ("50", p50), ("100", p100)]:
            if v is not None:
                lift = v / base if base > 0 else 0
                lines.append(f"  Top {k:>3}: {v:.0%} precision  ({lift:.1f}x vs random)")
        lines.append("")

    if top_pos:
        lines.append("TOP RISK-INCREASING FEATURES (SHAP importance):")
        for item in top_pos[:5]:
            name = item.get("feature") or item.get("name", "")
            score = item.get("mean_abs_shap") or item.get("importance", 0.0)
            lines.append(f"  {name}: {score:.5f}")
        lines.append("")

    if pk_data:
        scenarios = pk_data.get("scenarios") or []
        best = next((s for s in scenarios if s.get("k") == 50), None)
        if best:
            lines.append(
                f"OPERATIONAL FINDING: reviewing the top {best['k']} plugins "
                f"({best['k'] / n_test * 100:.1f}% of ecosystem) catches "
                f"{best['true_positives']} of {n_pos} future advisory plugins "
                f"with {best['precision']:.0%} precision — "
                f"a {best['lift']:.0f}x improvement over random."
            )
            lines.append("")

    if fs_data:
        h3_ok = fs_data.get("h3_satisfied", False)
        h3_info = fs_data.get("h3_smallest_qualifying_subset")
        full_ap = fs_data.get("full_model_average_precision")
        if h3_ok and h3_info:
            lines.append(
                f"FEATURE SELECTION (H3): a {h3_info['size']}-feature subset retains "
                f"{h3_info['ap_retention'] * 100:.1f}% of full-model AP "
                f"({h3_info['average_precision']:.4f} vs {full_ap:.4f}) — "
                "H3 is satisfied."
            )
        else:
            lines.append(
                "FEATURE SELECTION (H3): no evaluated subset reached 90% of full-model AP — "
                "H3 is not satisfied at tested subset sizes."
            )
        lines.append("")

    lines += ["=" * 60, "Please provide your plain-English explanation now."]
    return "\n".join(lines)


def _render_ml_explain_card(
    values: dict[str, Any],
    metrics: dict[str, Any] | None,
    pk_data: dict[str, Any] | None,
    fs_data: dict[str, Any] | None,
    ai_result: str | None = None,
    ai_error: str | None = None,
    rate_limited: bool = False,
) -> str:
    """Render the AI explanation card for the ML tab."""
    import urllib.parse as _up

    model_out_dir = values.get("model_out_dir") or ""
    if not metrics or not model_out_dir:
        return ""

    prompt = _build_ml_explain_prompt(metrics, pk_data, fs_data, model_out_dir)
    claude_url = "https://claude.ai/new?q=" + _up.quote(prompt, safe="")
    chatgpt_url = "https://chatgpt.com/?q=" + _up.quote(prompt, safe="")

    _mdir_esc = _escape(model_out_dir)
    btn_inpage = (
        '<form method="get" action="/" style="display:inline">'
        '<input type="hidden" name="tab" value="ml">'
        f'<input type="hidden" name="model_out_dir" value="{_mdir_esc}">'
        '<input type="hidden" name="ml_explain" value="1">'
        '<button type="submit"'
        ' style="background:rgba(120,80,220,.2);border:1px solid rgba(120,80,220,.4);'
        "color:#a78bfa;padding:.45rem .9rem;border-radius:8px;cursor:pointer;"
        'font-weight:600;font-size:.85rem">Explain now (AI)</button>'
        "</form>"
    )
    btn_copy = (
        '<button type="button"'
        ' onclick="(function(b){navigator.clipboard.writeText('
        "document.getElementById('mlep').value)"
        ".then(function(){var o=b.textContent;b.textContent='Copied!';"
        "setTimeout(function(){b.textContent=o;},2000);})"
        ".catch(function(){document.getElementById('mlep').select();"
        "document.execCommand('copy');});})(this)\""
        ' style="background:var(--accent);border:none;color:#fff;'
        "padding:.45rem .9rem;border-radius:8px;cursor:pointer;"
        'font-weight:600;font-size:.85rem">Copy prompt</button>'
    )
    btn_claude = (
        f'<a href="{claude_url}" target="_blank" rel="noopener noreferrer"'
        ' style="display:inline-flex;align-items:center;'
        "background:rgba(204,153,51,.15);border:1px solid rgba(204,153,51,.3);"
        "color:#cc9933;padding:.45rem .9rem;border-radius:8px;"
        'text-decoration:none;font-weight:600;font-size:.85rem">Open in Claude</a>'
    )
    btn_chatgpt = (
        f'<a href="{chatgpt_url}" target="_blank" rel="noopener noreferrer"'
        ' style="display:inline-flex;align-items:center;'
        "background:rgba(16,163,127,.12);border:1px solid rgba(16,163,127,.3);"
        "color:#10a37f;padding:.45rem .9rem;border-radius:8px;"
        'text-decoration:none;font-weight:600;font-size:.85rem">Open in ChatGPT</a>'
    )

    # AI result panel
    ai_panel = ""
    if rate_limited:
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.7rem .9rem;'
            "background:rgba(220,80,60,.1);border:1px solid rgba(220,80,60,.3);"
            'border-radius:8px;font-size:.88rem;color:#e05c5c">'
            f"Rate limit reached — max {_EXPLAIN_RATE_MAX} AI explanations per hour. "
            "Use Copy or Open buttons to continue in your own AI session."
            "</div>"
        )
    elif ai_error:
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.7rem .9rem;'
            "background:rgba(220,80,60,.1);border:1px solid rgba(220,80,60,.3);"
            'border-radius:8px;font-size:.88rem;color:#e05c5c">'
            f"AI explanation error: {_escape(ai_error)}"
            "</div>"
        )
    elif ai_result:

        def _md_simple(text: str) -> str:
            import re as _re

            t = _escape(text)
            t = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
            return t

        paras = "".join(
            f"<p style='margin:.5rem 0'>{_md_simple(p.strip())}</p>"
            for p in ai_result.split("\n\n")
            if p.strip()
        )
        ai_panel = (
            '<div style="margin-top:.8rem;padding:.8rem 1rem;'
            "background:rgba(120,80,220,.08);border:1px solid rgba(120,80,220,.25);"
            'border-radius:10px">'
            '<p style="font-size:.78rem;color:#a78bfa;font-weight:600;margin:0 0 .5rem">'
            "AI explanation (Claude)</p>"
            f"{paras}"
            "</div>"
        )

    byoai = (
        '<details style="margin-top:.9rem;border-top:1px solid var(--line);padding-top:.8rem">'
        '<summary style="cursor:pointer;font-size:.88rem;font-weight:600;color:var(--muted);'
        'padding:.2rem 0">Bring your own AI</summary>'
        '<p style="font-size:.82rem;color:var(--muted);margin:.5rem 0 .7rem">'
        "Copy the prompt and paste into any AI assistant.</p>"
        '<div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.6rem">'
        + btn_copy
        + btn_claude
        + btn_chatgpt
        + "</div>"
        '<textarea id="mlep" readonly'
        ' style="width:100%;min-height:140px;background:var(--panel2);'
        "border:1px solid var(--line);border-radius:8px;padding:.6rem;"
        "font-family:var(--mono);font-size:.75rem;line-height:1.5;"
        'color:var(--text);resize:vertical;box-sizing:border-box">'
        f"{_escape(prompt)}</textarea>"
        "</details>"
    )
    tip = (
        '<p style="font-size:.76rem;color:var(--muted);margin-top:.5rem">'
        '"Explain now" uses the server API key (max 3/hr). '
        '"Open in" buttons use your own account with no limits.'
        "</p>"
    )

    return (
        '<section class="card" style="align-self:start">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">AI explanation</p>'
        "<h2>Explain these results</h2>"
        '<p class="kicker">Get a plain-English summary of what these ML results '
        "mean operationally.</p>"
        '</div><span class="pill pill--muted">Bring your own AI</span></div>'
        '<div style="display:flex;gap:.6rem;flex-wrap:wrap;margin:.7rem 0">'
        + btn_inpage
        + "</div>"
        + ai_panel
        + byoai
        + tip
        + "</section>"
    )


def _render_ml_tab(
    values: dict[str, Any],
    latest_metrics: dict[str, Any] | None,
    model_dir_options: list[str],
    ml_ai_result: str | None = None,
    ml_ai_error: str | None = None,
    ml_rate_limited: bool = False,
) -> str:
    """Read-only ML results tab — model selector + metrics display + feature selection."""
    metrics = latest_metrics

    # ── Left column: structured model picker (GET form) ──────────────────────
    selector_card = "".join(
        [
            '<section class="card" style="align-self:start">',
            '<div class="card__header"><div>',
            '<p class="eyebrow">ML / evaluation</p>',
            "<h2>Select a model</h2>",
            '<p class="kicker">Choose algorithm, feature set, and evaluation strategy '
            "to view pre-computed metrics, feature importance, and feature selection results.</p>",
            '</div><span class="pill pill--muted">Results viewer</span></div>',
            '<form method="get" action="/">',
            '<input type="hidden" name="tab" value="ml">',
            _render_model_picker(values, model_dir_options),
            '<div style="margin-top:.9rem">',
            '<button type="submit">Load metrics</button>',
            "</div>",
            "</form>",
            "</section>",
        ]
    )

    # AI explain card — only shown when a model is selected
    pk_data_for_explain = (
        _load_precision_at_k(values.get("model_out_dir") or "")
        if values.get("model_out_dir")
        else None
    )
    fs_data_for_explain = (
        _load_feature_selection(values.get("model_out_dir") or "")
        if values.get("model_out_dir")
        else None
    )
    ml_explain_card = _render_ml_explain_card(
        values,
        latest_metrics,
        pk_data_for_explain,
        fs_data_for_explain,
        ai_result=ml_ai_result,
        ai_error=ml_ai_error,
        rate_limited=ml_rate_limited,
    )
    left_col = '<div class="score-output">' + selector_card + ml_explain_card + "</div>"

    # ── Right column: metrics + feature selection ─────────────────────────────
    output_parts: list[str] = []

    status_text = '<p class="muted">Select a model directory on the left to view results.</p>'
    if metrics:
        source = str(Path(values["model_out_dir"]) / "metrics.json")
        status_text = f'<p class="small muted">Metrics source: <code>{_escape(source)}</code></p>'

    output_parts.append(
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Model performance</p>'
        "<h2>Readable metrics</h2>"
        '</div><span class="pill pill--muted">Metrics view</span></div>'
        + status_text
        + _render_ml_metrics(metrics, model_out_dir=values.get("model_out_dir") or "")
        + "</section>"
    )

    # Feature selection panel — shown when feature_selection.json exists
    model_dir_for_fs = values.get("model_out_dir") or ""
    fs_data = _load_feature_selection(model_dir_for_fs) if model_dir_for_fs else None
    if fs_data:
        output_parts.append(
            '<section class="card">'
            '<div class="card__header"><div>'
            '<p class="eyebrow">Feature selection</p>'
            "<h2>Principled feature selection (H3)</h2>"
            '<p class="kicker">SHAP-ranked feature subsets — smallest set retaining '
            "&#x2265;90% of full-model average precision.</p>"
            '</div><span class="pill pill--muted">Empirical H3 test</span></div>'
            + _render_feature_selection_panel(fs_data)
            + "</section>"
        )
    elif model_dir_for_fs:
        # Determine if this is a single-family model where selection isn't meaningful
        parsed = _parse_model_dir(model_dir_for_fs)
        single_family = parsed is not None and parsed[1] in {
            "advisory_only",
            "gharchive_only",
            "swh_only",
        }
        if single_family:
            fs_msg = (
                "Feature selection is not applicable for single-family feature sets — "
                "the model is already restricted to one signal family and there is "
                "nothing to select down from. Choose a multi-family or full-feature "
                "model to view feature selection results."
            )
        else:
            fs_msg = (
                "Feature selection has not yet been run for this model. "
                "Run <strong>canary train feature-select --model-dir "
                + _escape(model_dir_for_fs)
                + "</strong> to generate the H3 report."
            )
        output_parts.append(
            '<section class="card">'
            '<div class="card__header"><div>'
            '<p class="eyebrow">Feature selection</p>'
            "<h2>Principled feature selection (H3)</h2>"
            '</div><span class="pill pill--muted">'
            + ("Not applicable" if single_family else "Not yet run")
            + "</span></div>"
            f'<p class="muted" style="padding:.6rem 0">{fs_msg}</p>'
            "</section>"
        )

    right_col = '<div class="score-output">' + "".join(output_parts) + "</div>"

    return '<div class="grid--score">' + left_col + right_col + "</div>"


def _load_plugin_advisories(plugin_id: str) -> list[dict[str, Any]]:
    """Load advisory records for a plugin from the local advisory JSONL file."""
    stem = plugin_id.replace("/", "_").replace(" ", "_")
    target = ADVISORY_DATA_ROOT / f"{stem}.advisories.real.jsonl"
    if not target.exists():
        return []
    try:
        records = [
            json.loads(line)
            for line in target.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return sorted(records, key=lambda r: r.get("published_date") or "")
    except Exception:  # noqa: BLE001
        return []


def _advisories_in_window(
    plugin_id: str,
    after_date: str,
    before_date: str,
) -> list[dict[str, Any]]:
    """Return advisory records for plugin_id that fall within (after_date, before_date]."""
    records = _load_plugin_advisories(plugin_id)
    return [r for r in records if after_date < (r.get("published_date") or "") <= before_date]


def _render_case_study_tab(
    values: dict[str, Any],
    model_dir_options: list[str],
) -> str:
    """
    Dynamic case study tab — shows top-ranked test predictions alongside
    confirmed advisory outcomes drawn from the local advisory dataset.

    The model picker mirrors the ML tab.  When a model is selected the tab:
      - reads test_predictions.csv ranked by predicted probability
      - joins against local advisory JSONL files to find confirmed advisories
        within the 6-month prediction window
      - renders a ranked table split into Confirmed and Unconfirmed sections
    """
    import csv
    from datetime import datetime, timedelta

    model_out_dir = values.get("model_out_dir") or ""

    # ── Left column: model picker ─────────────────────────────────────────────
    selector_card = "".join(
        [
            '<section class="card" style="align-self:start">',
            '<div class="card__header"><div>',
            '<p class="eyebrow">Case study</p>',
            "<h2>Validated predictions</h2>",
            '<p class="kicker">Choose a model to see how its top-ranked predictions ',
            "compared against advisories subsequently published by Jenkins. "
            "Confirmed rows show plugins CANARY flagged that received a real advisory "
            "within the 6-month prediction window. Unconfirmed rows are CANARY's "
            "current forward-looking recommendations.</p>",
            '</div><span class="pill pill--muted">Live validation</span></div>',
            '<form method="get" action="/">',
            '<input type="hidden" name="tab" value="casestudy">',
            _render_model_picker(values, model_dir_options),
            '<div style="margin-top:.9rem">',
            '<button type="submit">Load predictions</button>',
            "</div>",
            "</form>",
            "</section>",
        ]
    )

    # ── Right column: no model selected yet ───────────────────────────────────
    if not model_out_dir:
        right_col = (
            '<section class="card">'
            '<div class="card__header"><div>'
            '<p class="eyebrow">Prediction outcomes</p>'
            "<h2>Select a model to view results</h2>"
            "</div></div>"
            '<p class="muted" style="padding:.6rem 0">Choose an algorithm, '
            "feature set, and evaluation strategy on the left, then click "
            "<strong>Load predictions</strong>.</p>"
            "</section>"
        )
        return (
            '<div class="grid--score">'
            + '<div class="score-output">'
            + selector_card
            + "</div>"
            + '<div class="score-output">'
            + right_col
            + "</div>"
            + "</div>"
        )

    # Load test predictions CSV
    stem = Path(model_out_dir).name
    pred_path = MODEL_OUTPUTS_ROOT / stem / "test_predictions.csv"
    metrics = _load_model_metrics(model_out_dir)

    if not pred_path.exists():
        right_html = (
            '<section class="card">'
            + '<div class="card__header"><div>'
            + '<p class="eyebrow">Prediction outcomes</p>'
            + "<h2>No predictions file found</h2>"
            + "</div></div>"
            + '<p class="muted" style="padding:.6rem 0">Could not find '
            + f"<code>test_predictions.csv</code> under <code>{_escape(stem)}</code>. "
            "Re-run training to generate predictions.</p>" + "</section>"
        )
        return (
            '<div class="grid--score">'
            + '<div class="score-output">'
            + selector_card
            + "</div>"
            + '<div class="score-output">'
            + right_html
            + "</div>"
            + "</div>"
        )

    # Parse and sort predictions
    rows: list[dict[str, Any]] = []
    try:
        reader = csv.DictReader(pred_path.read_text(encoding="utf-8").splitlines())
        for row in reader:
            rows.append(
                {
                    "plugin_id": row.get("plugin_id", ""),
                    "month": row.get("month", ""),
                    "y_true": int(row.get("y_true", 0)),
                    "y_prob": float(row.get("y_prob", 0.0)),
                }
            )
        rows.sort(key=lambda r: r["y_prob"], reverse=True)
    except Exception:  # noqa: BLE001
        rows = []

    # Observation date and prediction window
    obs_date = (metrics or {}).get("test_start_month") or (
        min(r["month"] for r in rows) if rows else ""
    )
    window_end = ""
    if obs_date:
        try:
            obs_dt = datetime.strptime(obs_date, "%Y-%m")
            em = obs_dt.month + 6
            ey = obs_dt.year + (em - 1) // 12
            em = ((em - 1) % 12) + 1
            end_dt = (datetime(ey, em, 1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            window_end = end_dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    # Deduplicate by plugin_id — keep highest-scored row
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        if row["plugin_id"] not in seen:
            seen.add(row["plugin_id"])
            deduped.append(row)

    top_rows = deduped[:25]
    n_pos = (metrics or {}).get("test_positive_count", 0)
    n_test = (metrics or {}).get("test_row_count", 1)
    base_rate = n_pos / n_test if n_test > 0 else 0.0

    # Enrich with advisory data
    enriched: list[dict[str, Any]] = []
    for rank, row in enumerate(top_rows, start=1):
        pid = row["plugin_id"]
        advisories = (
            _advisories_in_window(pid, obs_date, window_end) if obs_date and window_end else []
        )
        confirmed = bool(advisories) or row["y_true"] == 1
        adv_date = adv_sev = adv_url = ""
        adv_cvss: float | None = None
        sec_ids: list[str] = []
        if advisories:
            best = max(
                advisories,
                key=lambda a: (a.get("severity_summary") or {}).get("max_cvss_base_score") or 0,
            )
            adv_date = best.get("published_date", "")
            sev_sum = best.get("severity_summary") or {}
            adv_sev = (sev_sum.get("max_severity_label") or "").title()
            adv_cvss = sev_sum.get("max_cvss_base_score")
            adv_url = best.get("url", "")
            sec_ids = best.get("security_warning_ids") or []
        days_to_adv: int | None = None
        if adv_date and obs_date:
            try:
                days_to_adv = (
                    datetime.strptime(adv_date, "%Y-%m-%d") - datetime.strptime(obs_date, "%Y-%m")
                ).days
            except ValueError:
                pass
        enriched.append(
            {
                "rank": rank,
                "plugin_id": pid,
                "y_prob": row["y_prob"],
                "confirmed": confirmed,
                "adv_date": adv_date,
                "adv_sev": adv_sev,
                "adv_cvss": adv_cvss,
                "adv_url": adv_url,
                "sec_ids": sec_ids,
                "days_to_adv": days_to_adv,
            }
        )

    confirmed_rows = [r for r in enriched if r["confirmed"]]
    unconfirmed_rows = [r for r in enriched if not r["confirmed"]]

    def _sev_color(sev: str) -> str:
        s = sev.lower()
        return (
            "#e05c5c"
            if s in ("high", "critical")
            else ("#e6a01e" if s == "medium" else "var(--muted)")
        )

    def _row_html(r: dict[str, Any], show_outcome: bool) -> str:
        plugin_url = f"/?tab=score&plugin={_escape(r['plugin_id'])}"
        plugin_cell = (
            f'<a href="{plugin_url}" style="color:var(--accent);text-decoration:none">'
            + f"<code>{_escape(r['plugin_id'])}</code></a>"
        )
        prob_cell = f"<strong>{r['y_prob']:.1%}</strong>"
        if show_outcome and r["confirmed"]:
            days_str = f"{r['days_to_adv']} days" if r["days_to_adv"] is not None else "—"
            sev_cell = (
                f'<span style="color:{_sev_color(r["adv_sev"])};font-weight:600">'
                + _escape(r["adv_sev"])
                + (f" ({r['adv_cvss']:.1f})" if r["adv_cvss"] is not None else "")
                + "</span>"
            )
            adv_cell = (
                (
                    f'<a href="{_escape(r["adv_url"])}" target="_blank" rel="noopener noreferrer" '
                    + f'style="color:var(--accent);font-size:.82rem">{_escape(r["sec_ids"][0])}</a>'
                    + (
                        f' <span style="color:var(--muted);font-size:.78rem">+{len(r["sec_ids"]) - 1} more</span>'
                        if len(r["sec_ids"]) > 1
                        else ""
                    )
                )
                if r["adv_url"] and r["sec_ids"]
                else '<span style="color:var(--muted)">—</span>'
            )
            outcome = (
                "<td style='padding:.45rem .6rem;text-align:center'>"
                '<span style="color:#5ce0a0;font-weight:700">&#x2713;</span></td>'
                + f"<td style='padding:.45rem .6rem'>{sev_cell}</td>"
                + f"<td style='padding:.45rem .6rem;font-size:.82rem'>{_escape(adv_date)}</td>"
                + f"<td style='padding:.45rem .6rem;font-size:.82rem;color:var(--muted)'>{days_str}</td>"
                + f"<td style='padding:.45rem .6rem;font-size:.82rem'>{adv_cell}</td>"
            )
        else:
            outcome = (
                "<td style='padding:.45rem .6rem;text-align:center'>"
                '<span style="color:var(--muted)">?</span></td>'
                + "<td colspan='4' style='padding:.45rem .6rem;color:var(--muted);"
                "font-size:.82rem;font-style:italic'>No confirmed advisory in window</td>"
            )
        return (
            "<tr>"
            + f"<td style='padding:.45rem .6rem;text-align:right;color:var(--muted);font-size:.82rem'>{r['rank']}</td>"
            + f"<td style='padding:.45rem .6rem'>{plugin_cell}</td>"
            + f"<td style='padding:.45rem .6rem;text-align:right'>{prob_cell}</td>"
            + outcome
            + "</tr>"
        )

    thead = (
        "<thead><tr>"
        + "".join(
            f"<th style='text-align:{a};padding:.4rem .6rem;color:var(--muted);font-size:.8rem;font-weight:600'>{h}</th>"
            for h, a in [
                ("#", "right"),
                ("Plugin", "left"),
                ("CANARY score", "right"),
                ("Confirmed", "center"),
                ("Severity", "left"),
                ("Advisory date", "left"),
                ("Lead time", "left"),
                ("Advisory", "left"),
            ]
        )
        + "</tr></thead>"
    )

    n_confirmed = len(confirmed_rows)
    n_total = len(enriched)
    prec = n_confirmed / n_total if n_total > 0 else 0.0
    lift = prec / base_rate if base_rate > 0 else 0.0

    headline = (
        '<div style="margin-bottom:.8rem;padding:.7rem .9rem;'
        + "background:rgba(82,196,26,.08);border:1px solid rgba(82,196,26,.25);"
        + 'border-radius:10px;font-size:.9rem">'
        + f"<strong>Observation date:</strong> {_escape(obs_date)} &nbsp;|&nbsp; "
        + f"<strong>Prediction window:</strong> {_escape(obs_date)} &#8594; {_escape(window_end)} &nbsp;|&nbsp; "
        + f"<strong>Top-{n_total} precision:</strong> {n_confirmed}/{n_total} ({prec:.0%}) &nbsp;|&nbsp; "
        + f"<strong>Lift vs random:</strong> {lift:.1f}&#215;"
        + "</div>"
    )

    confirmed_html = (
        (
            '<div class="panel" style="margin-top:.6rem">'
            + f'<h4>Confirmed predictions <span style="color:#5ce0a0">({n_confirmed} of {n_total})</span></h4>'
            + '<p style="font-size:.82rem;color:var(--muted);margin:.2rem 0 .5rem">Plugins CANARY ranked '
            + f"in its top {n_total} that received a Jenkins security advisory within the 180-day window. "
            "Plugin names link to their CANARY score page.</p>"
            + '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
            + thead
            + "<tbody>"
            + "".join(_row_html(r, show_outcome=True) for r in confirmed_rows)
            + "</tbody></table></div></div>"
        )
        if confirmed_rows
        else ""
    )

    unconfirmed_html = (
        (
            '<div class="panel" style="margin-top:.6rem">'
            + f'<h4>Unconfirmed predictions <span style="color:var(--muted)">({len(unconfirmed_rows)})</span></h4>'
            + '<p style="font-size:.82rem;color:var(--muted);margin:.2rem 0 .5rem">'
            + "High-scored plugins with no confirmed advisory in the window. "
            "In a live deployment these are CANARY's current forward-looking recommendations &#8212; "
            "some may receive advisories after the window closes.</p>"
            + '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
            + thead
            + "<tbody>"
            + "".join(_row_html(r, show_outcome=False) for r in unconfirmed_rows)
            + "</tbody></table></div></div>"
        )
        if unconfirmed_rows
        else ""
    )

    right_html = (
        '<section class="card">'
        + '<div class="card__header"><div>'
        + '<p class="eyebrow">Prediction outcomes</p>'
        + f"<h2>Top-{n_total} predictions vs. confirmed advisories</h2>"
        + f'<p class="kicker">Model: <strong>{_escape(stem)}</strong></p>'
        + "</div>"
        + '<span class="pill pill--muted">Empirical validation</span></div>'
        + headline
        + confirmed_html
        + unconfirmed_html
        + '<p style="font-size:.78rem;color:var(--muted);margin-top:.8rem">'
        + "Advisory data sourced from local Jenkins advisory dataset. "
        "Lead time = days from observation date to advisory publication. "
        "Retrain on newer data and reload to see updated predictions.</p>" + "</section>"
    )

    return (
        '<div class="grid--score">'
        + '<div class="score-output">'
        + selector_card
        + "</div>"
        + '<div class="score-output">'
        + right_html
        + "</div>"
        + "</div>"
    )


def _render_about_tab() -> str:
    """Render the About / Help tab — lightweight context for new visitors."""
    github_url = "https://github.com/timmybx/canary"

    risk_rows = "".join(
        f"<tr><td style='padding:.5rem .75rem'><span class='pill {cls}'>{label}</span></td>"
        f"<td style='padding:.5rem .75rem;color:var(--muted);font-size:.9rem'>{threshold}</td>"
        f"<td style='padding:.5rem .75rem;font-size:.9rem'>{action}</td></tr>"
        for label, cls, threshold, action in [
            (
                "Low",
                "pill--muted",
                "Score &lt; 0.05",
                "Normal patch hygiene — no special action needed.",
            ),
            (
                "Medium",
                "pill--warn",
                "0.05 – 0.20",
                "Monitor advisories; include in scheduled patch cycles.",
            ),
            (
                "High",
                "pill--danger",
                "Score &ge; 0.20",
                "Prioritize review; consider alternatives for new pipelines.",
            ),
        ]
    )

    signal_rows = "".join(
        f"<tr><td style='padding:.4rem .75rem;font-size:.88rem'><code>{sig}</code></td>"
        f"<td style='padding:.4rem .75rem;font-size:.88rem;color:var(--muted)'>{desc}</td></tr>"
        for sig, desc in [
            (
                "Days since last commit",
                "How long ago the repository was last updated — stale repos carry higher risk.",
            ),
            (
                "Archive age",
                "How long the plugin has been publicly archived — older projects tend to be better-hardened.",
            ),
            (
                "Release recency",
                "Time since the last published release — infrequent releases correlate with elevated risk.",
            ),
            (
                "Security-fix commit count",
                "Commits whose messages reference security fixes — a positive maintenance signal.",
            ),
            (
                "Advisory history",
                "Number and recency of previously published Jenkins security advisories.",
            ),
            (
                "Governance artifacts",
                "Presence of SECURITY.md, Dependabot config, changelog, and CI workflows.",
            ),
            ("Dependency risk", "Whether the plugin's dependencies have known advisories."),
        ]
    )

    return (
        '<div style="max-width:860px;margin:0 auto;display:grid;gap:1.2rem">'
        # ── What is CANARY ────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">About this tool</p>'
        "<h2>What is CANARY?</h2>"
        "</div></div>"
        '<p style="margin-top:.6rem;line-height:1.7">CANARY (<em>Component Analytics &amp; '
        "Near-term Advisory Risk Yardstick</em>) predicts near-term security advisory risk for "
        "Jenkins plugins using publicly observable project signals. Rather than waiting for a "
        "vulnerability to be disclosed, CANARY estimates the likelihood that a plugin will "
        "appear in a Jenkins security advisory within the next 180 days — giving security "
        "teams a proactive prioritization signal.</p>"
        '<p style="margin-top:.6rem;line-height:1.7">This is a research prototype developed '
        "as part of a Doctor of Engineering praxis at "
        "<strong>The George Washington University</strong>. It is intended as a "
        "decision-support tool, not a replacement for security review.</p>"
        "</section>"
        # ── Quick start ───────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Getting started</p>'
        "<h2>Score a plugin in 30 seconds</h2>"
        "</div></div>"
        '<ol style="margin:.6rem 0 0;padding-left:1.4rem;line-height:2;font-size:.95rem">'
        "<li>Click the <strong>Scoring</strong> tab.</li>"
        "<li>Type a Jenkins plugin name in the <strong>Plugin ID</strong> field "
        "(autocomplete is populated from the live registry).</li>"
        "<li>Optionally select an <strong>ML model</strong> from the dropdown "
        "to add a probabilistic score alongside the heuristic one.</li>"
        "<li>Click <strong>Score plugin</strong>.</li>"
        "<li>Review the heuristic score, ML advisory probability, and SHAP-based "
        "feature drivers. Use <strong>Explain now (AI)</strong> for a plain-English summary.</li>"
        "</ol>"
        "</section>"
        # ── Score meanings ────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Interpreting results</p>'
        "<h2>What the scores mean</h2>"
        "</div></div>"
        '<p style="margin-top:.4rem;font-size:.9rem;color:var(--muted)">'
        "The <strong>heuristic score</strong> (0–100) is a rule-based signal using advisory "
        "history, maintenance staleness, governance artifacts, and dependency risk. "
        "The <strong>ML score</strong> (0.0–1.0) is the model's estimated probability of "
        "a Jenkins security advisory within 180 days.</p>"
        '<table style="width:100%;border-collapse:collapse;margin-top:.8rem">'
        "<thead><tr>"
        "<th style='text-align:left;padding:.5rem .75rem;color:var(--muted);font-size:.85rem'>Risk level</th>"
        "<th style='text-align:left;padding:.5rem .75rem;color:var(--muted);font-size:.85rem'>ML score</th>"
        "<th style='text-align:left;padding:.5rem .75rem;color:var(--muted);font-size:.85rem'>Suggested action</th>"
        "</tr></thead>"
        f"<tbody>{risk_rows}</tbody>"
        "</table>"
        "</section>"
        # ── Signals ───────────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">How it works</p>'
        "<h2>Key signals used</h2>"
        "</div></div>"
        '<p style="margin-top:.4rem;font-size:.9rem;color:var(--muted)">'
        "CANARY uses only publicly observable data — no private telemetry or credentials "
        "are required. The most predictive signals come from Software Heritage archival "
        "data and GitHub Archive event history.</p>"
        '<table style="width:100%;border-collapse:collapse;margin-top:.8rem">'
        "<thead><tr>"
        "<th style='text-align:left;padding:.4rem .75rem;color:var(--muted);font-size:.85rem'>Signal</th>"
        "<th style='text-align:left;padding:.4rem .75rem;color:var(--muted);font-size:.85rem'>What it captures</th>"
        "</tr></thead>"
        f"<tbody>{signal_rows}</tbody>"
        "</table>"
        "</section>"
        # ── ML models ─────────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Machine learning tab</p>'
        "<h2>Exploring model results</h2>"
        "</div></div>"
        '<p style="margin-top:.6rem;line-height:1.7;font-size:.95rem">'
        "The <strong>Machine learning</strong> tab lets you explore pre-computed results "
        "across 29 model configurations. Use the three dropdowns to select an algorithm "
        "(XGBoost, LightGBM, Random Forest, Logistic Regression), a feature set "
        "(from advisory-history-only up to all 154 features), and an evaluation strategy "
        "(time split or group-time split). "
        "Where available, a <strong>feature selection panel</strong> shows which features "
        "are most important and whether a compact subset can match full-model performance.</p>"
        '<p style="margin-top:.6rem;line-height:1.7;font-size:.95rem">'
        "<strong>Time split</strong> evaluates models where the same plugins appear in "
        "both training and testing — a continuous monitoring scenario. "
        "<strong>Group-time split</strong> withholds entire plugins from training, testing "
        "whether the model generalises to previously unseen plugins. The group-time design "
        "is the more conservative and realistic evaluation of the two.</p>"
        "</section>"
        # ── Limitations ───────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Limitations</p>'
        "<h2>What CANARY is not</h2>"
        "</div></div>"
        '<ul style="margin:.6rem 0 0;padding-left:1.4rem;line-height:2;font-size:.95rem">'
        "<li>CANARY is scoped to the <strong>Jenkins plugin ecosystem</strong> only — "
        "it does not score npm, PyPI, Maven, or other package registries.</li>"
        "<li>Scores reflect <strong>near-term advisory likelihood</strong>, not exploitability "
        "or severity in your specific environment.</li>"
        "<li>A low score does not mean a plugin is safe — it means CANARY sees no strong "
        "signal of an imminent advisory based on publicly observable data.</li>"
        "<li>Data is updated periodically, not in real time. "
        "Always consult the official "
        '<a href="https://www.jenkins.io/security/advisories/" target="_blank" '
        'rel="noopener noreferrer" style="color:var(--accent)">Jenkins security advisories</a> '
        "for the authoritative source.</li>"
        "</ul>"
        "</section>"
        # ── Learn more ────────────────────────────────────────────────────────
        '<section class="card">'
        '<div class="card__header"><div>'
        '<p class="eyebrow">Learn more</p>'
        "<h2>Going deeper</h2>"
        "</div></div>"
        '<p style="margin-top:.6rem;line-height:1.7;font-size:.95rem">'
        "The full source code, data pipeline, and research documentation are available "
        "on GitHub. The praxis document provides a detailed description of the methodology, "
        "ablation results, and future research directions.</p>"
        '<div style="display:flex;gap:.75rem;flex-wrap:wrap;margin-top:.8rem">'
        f'<a href="{github_url}" target="_blank" rel="noopener noreferrer" '
        'style="display:inline-flex;align-items:center;gap:.5rem;'
        "background:rgba(111,177,255,.12);border:1px solid rgba(111,177,255,.3);"
        "color:var(--accent);padding:.55rem 1.1rem;border-radius:10px;"
        'text-decoration:none;font-weight:600;font-size:.92rem">'
        "&#128279; View on GitHub"
        "</a>"
        '<a href="https://www.jenkins.io/security/advisories/" target="_blank" '
        'rel="noopener noreferrer" '
        'style="display:inline-flex;align-items:center;gap:.5rem;'
        "background:rgba(255,255,255,.05);border:1px solid var(--line);"
        "color:var(--muted);padding:.55rem 1.1rem;border-radius:10px;"
        'text-decoration:none;font-weight:600;font-size:.92rem">'
        "Jenkins Security Advisories"
        "</a>"
        "</div>"
        "</section>"
        "</div>"
    )


def render_page(
    values: dict[str, Any],
    *,
    plugin_options: list[str] | None = None,
    score_result: dict[str, Any] | None = None,
    score_error: str | None = None,
    latest_metrics: dict[str, Any] | None = None,
    model_dir_options: list[str] | None = None,
    ai_result: str | None = None,
    ai_error: str | None = None,
    rate_limited: bool = False,
    ml_ai_result: str | None = None,
    ml_ai_error: str | None = None,
    ml_rate_limited: bool = False,
) -> str:
    values = {**DEFAULTS, **values}
    plugin_options = plugin_options or []
    model_dir_options = model_dir_options or []
    active_tab = values.get("active_tab") or "score"
    if active_tab not in VALID_TABS:
        active_tab = "score"
    tabs = [
        ("score", "Scoring", "Plugin score and rationale"),
        ("ml", "Machine learning", "Model results and metrics"),
        ("about", "About", "What is CANARY and how to use it"),
        ("casestudy", "Case study", "Validated predictions vs. confirmed advisories"),
    ]
    tab_links = "".join(
        f'<a href="/?tab={_escape(tab_key)}" class="tab-link {"is-active" if tab_key == active_tab else ""}" data-tab-link="{_escape(tab_key)}"><strong>{_escape(title)}</strong><span>{_escape(subtitle)}</span></a>'
        for tab_key, title, subtitle in tabs
    )
    active_panel_html = ""
    if active_tab == "score":
        active_panel_html = _render_score_section(
            values,
            plugin_options,
            score_result,
            score_error,
            model_dir_options,
            ai_result=ai_result,
            ai_error=ai_error,
            rate_limited=rate_limited,
        )
    elif active_tab == "about":
        active_panel_html = _render_about_tab()
    elif active_tab == "casestudy":
        active_panel_html = _render_case_study_tab(values, model_dir_options or [])
    else:
        active_panel_html = _render_ml_tab(
            values,
            latest_metrics,
            model_dir_options,
            ml_ai_result=ml_ai_result,
            ml_ai_error=ml_ai_error,
            ml_rate_limited=ml_rate_limited,
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
          A lightweight web UI for scoring Jenkins plugins and exploring ML-based advisory risk.
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
    if active_tab not in VALID_TABS:
        active_tab = "score"
        values["active_tab"] = active_tab
    plugin_options = _load_plugin_choices(values["registry_path"]) if active_tab == "score" else []
    latest_metrics = None
    # Always discover model dirs — needed by both the ML tab and the Score tab dropdown
    model_dir_options: list[str] = _discover_model_output_dirs()
    if active_tab == "ml" and values.get("model_out_dir"):
        try:
            values["model_out_dir"] = _normalize_model_output_dir(
                values.get("model_out_dir") or DEFAULT_MODEL_DIR
            )
            latest_metrics = _load_model_metrics(values["model_out_dir"])
        except ValueError:
            values["model_out_dir"] = DEFAULT_MODEL_DIR
    return plugin_options, latest_metrics, model_dir_options


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
    values = _merge_defaults(
        {
            "active_tab": query.get("tab", [DEFAULTS["active_tab"]])[-1],
            "model_out_dir": query.get("model_out_dir", [""])[-1],
            "plugin": query.get("plugin", [""])[-1],
            "score_model_dir": query.get("score_model_dir", [""])[-1],
        }
    )
    _get_explain = query.get("explain", [""])[-1] == "1"
    _get_ml_explain = query.get("ml_explain", [""])[-1] == "1"
    plugin_options, latest_metrics, model_dir_options = _prepare_request_state(values)
    score_result = None
    score_error = None
    ai_result: str | None = None
    ai_error: str | None = None
    rate_limited: bool = False
    ml_ai_result: str | None = None
    ml_ai_error: str | None = None
    ml_rate_limited: bool = False

    # /run and /train are disabled in the public deployment
    if path in {"/run", "/train"}:
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]

    # /score, /explain, /ml_explain redirects — corporate firewalls block POST;
    # redirect to GET equivalents so everything works as normal page navigation.
    if path == "/ml_explain":
        qs = urllib.parse.urlencode(
            {
                "tab": "ml",
                "model_out_dir": values.get("model_out_dir") or "",
                "ml_explain": "1",
            }
        )
        start_response("302 Found", [("Location", f"/?{qs}"), ("Content-Type", "text/plain")])
        return [b""]

    if path == "/explain":
        qs = urllib.parse.urlencode(
            {
                "tab": "score",
                "plugin": values.get("plugin") or "",
                "score_model_dir": values.get("score_model_dir") or "",
                "explain": "1",
            }
        )
        start_response("302 Found", [("Location", f"/?{qs}"), ("Content-Type", "text/plain")])
        return [b""]

    if path == "/score":
        qs = urllib.parse.urlencode(
            {
                "tab": "score",
                "plugin": values.get("plugin") or "",
                "score_model_dir": values.get("score_model_dir") or "",
            }
        )
        start_response("302 Found", [("Location", f"/?{qs}"), ("Content-Type", "text/plain")])
        return [b""]

    # GET ml_explain — runs when ml_explain=1 is in query string (ML tab)
    if method == "GET" and _get_ml_explain and values.get("model_out_dir"):
        _ml_explain_dir = values["model_out_dir"]
        _ml_metrics = _load_model_metrics(_ml_explain_dir)
        _ml_pk = _load_precision_at_k(_ml_explain_dir)
        _ml_fs = _load_feature_selection(_ml_explain_dir)
        if _ml_metrics:
            client_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[
                0
            ].strip() or environ.get("REMOTE_ADDR", "unknown")
            if not _check_explain_rate_limit(client_ip):
                ml_rate_limited = True  # noqa: F841
            else:
                try:
                    _ml_prompt = _build_ml_explain_prompt(
                        _ml_metrics, _ml_pk, _ml_fs, _ml_explain_dir
                    )
                    ml_ai_result = _call_anthropic_explain(_ml_prompt)  # noqa: F841
                except Exception as exc:  # noqa: BLE001
                    logger.warning("ML explain call failed: %s", exc)
                    ml_ai_error = (
                        f"AI explanation unavailable ({exc}) — use Copy or Open buttons below."  # noqa: F841
                    )
        values["active_tab"] = "ml"

    # GET explain — runs when explain=1 is in query string
    # Same logic as the old POST /explain but triggered by GET so firewalls don't block it
    if method == "GET" and _get_explain and values.get("plugin"):
        plugin = values["plugin"].strip()
        try:
            _score_model_dir = values.get("score_model_dir") or ""
            score_result = _score_payload(
                score_plugin_baseline(plugin, real=True),
                score_model_dir=_score_model_dir,
            )
            _ml_scorer = _get_ml_scorer(_score_model_dir) if _score_model_dir else None
            if _ml_scorer is not None:
                try:
                    ml_score_result = _ml_score_payload(score_plugin_ml(plugin, scorer=_ml_scorer))
                    score_result["ml"] = ml_score_result
                except Exception as _ml_exc:  # noqa: BLE001
                    logger.warning("ML scoring failed for %s: %s", plugin, _ml_exc)
                    score_result["ml"] = None
            else:
                score_result["ml"] = None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Score failed during GET explain for %s: %s", plugin, exc)
            score_error = str(exc)
        # Call Anthropic API with rate limiting
        if score_result is not None:
            client_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[
                0
            ].strip() or environ.get("REMOTE_ADDR", "unknown")
            if not _check_explain_rate_limit(client_ip):
                rate_limited = True  # noqa: F841
            else:
                try:
                    prompt = _build_explain_prompt(plugin, score_result, score_result.get("ml"))
                    ai_result = _call_anthropic_explain(prompt)  # noqa: F841
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Anthropic explain call failed: %s", exc)
                    ai_error = (
                        f"AI explanation unavailable ({exc}) — use Copy or Open buttons below."  # noqa: F841
                    )
        if _score_model_dir:
            values["score_model_dir"] = _score_model_dir

    # GET scoring — runs when tab=score and a plugin is provided in the query string
    if (
        method == "GET"
        and values.get("active_tab") == "score"
        and values.get("plugin")
        and not _get_explain
    ):
        plugin = values["plugin"].strip()
        try:
            if not _plugin_known(plugin, values["registry_path"]):
                raise ValueError("Please choose a plugin ID from the current registry list.")
            _score_model_dir = (
                values.get("score_model_dir") or values.get("model_dir") or DEFAULT_MODEL_DIR
            )
            score_result = _score_payload(
                score_plugin_baseline(plugin, real=True),
                score_model_dir=_score_model_dir,
            )
            _ml_scorer = _get_ml_scorer(_score_model_dir) if _score_model_dir else None
            if _ml_scorer is not None:
                try:
                    ml_score_result = _ml_score_payload(score_plugin_ml(plugin, scorer=_ml_scorer))
                    score_result["ml"] = ml_score_result
                except Exception as _ml_exc:  # noqa: BLE001
                    logger.warning("ML scoring failed for %s: %s", plugin, _ml_exc)
                    score_result["ml"] = None
            else:
                score_result["ml"] = None
        except ValueError as exc:
            logger.warning("Rejected GET score request for %s: %s", plugin, exc)
            score_error = (
                "The scoring request could not be completed. Check the plugin ID and try again."
            )
        except Exception:  # pragma: no cover
            logger.exception("Unhandled error during GET scoring for %s", plugin)
            score_error = "Something went wrong while processing your request."

    if method == "POST" and path == "/explain":
        form = parse_form(environ)
        values = _merge_defaults(form)
        plugin_options, latest_metrics, model_dir_options = _prepare_request_state(values)
        # Re-score the plugin to get fresh score_result for the explain card
        plugin = (form.get("plugin") or values.get("plugin") or "").strip()
        if plugin:
            try:
                _score_model_dir = values.get("score_model_dir") or values.get("model_dir") or ""
                score_result = _score_payload(
                    score_plugin_baseline(plugin, real=True),
                    score_model_dir=_score_model_dir,
                )
                _ml_scorer = _get_ml_scorer(_score_model_dir) if _score_model_dir else None
                if _ml_scorer is not None:
                    try:
                        ml_score_result = _ml_score_payload(
                            score_plugin_ml(plugin, scorer=_ml_scorer)
                        )
                        score_result["ml"] = ml_score_result
                    except Exception as _ml_exc:  # noqa: BLE001
                        logger.warning("ML scoring failed for %s: %s", plugin, _ml_exc)
                        score_result["ml"] = None
                else:
                    score_result["ml"] = None
            except Exception as exc:  # noqa: BLE001
                score_error = str(exc)
        # Now call the Anthropic API with rate limiting
        if score_result is not None:
            client_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[
                0
            ].strip() or environ.get("REMOTE_ADDR", "unknown")
            if not _check_explain_rate_limit(client_ip):
                rate_limited = True  # noqa: F841
            else:
                try:
                    prompt = _build_explain_prompt(
                        plugin,
                        score_result,
                        score_result.get("ml"),
                    )
                    ai_result = _call_anthropic_explain(prompt)  # noqa: F841
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Anthropic explain call failed: %s", exc)
                    ai_error = (
                        f"AI explanation unavailable ({exc}) — use Copy or Open buttons below."  # noqa: F841
                    )
        values["active_tab"] = "score"
        # Restore score_model_dir in values so the ML dropdown stays selected
        if _score_model_dir:
            values["score_model_dir"] = _score_model_dir

    if method == "POST" and path == "/score":
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
                _score_model_dir = (
                    values.get("score_model_dir") or values.get("model_dir") or DEFAULT_MODEL_DIR
                )
                score_result = _score_payload(
                    score_plugin_baseline(plugin, real=True),
                    score_model_dir=_score_model_dir,
                )
                # Also run the ML scorer if a trained model is available
                _ml_scorer = _get_ml_scorer(_score_model_dir) if _score_model_dir else None
                if _ml_scorer is not None:
                    try:
                        ml_score_result = _ml_score_payload(
                            score_plugin_ml(
                                plugin,
                                scorer=_ml_scorer,
                            )
                        )
                        score_result["ml"] = ml_score_result
                    except Exception as _ml_exc:
                        logger.warning("ML scoring failed for %s: %s", plugin, _ml_exc)
                        score_result["ml"] = None
                else:
                    score_result["ml"] = None
                values["active_tab"] = "score"
        except ValueError as exc:
            logger.warning("Rejected webapp request for %s: %s", path, exc)
            if path == "/score":
                score_error = "The scoring request could not be completed. Check the form values and try again."
                values["active_tab"] = "score"

        except Exception:  # pragma: no cover
            logger.exception("Unhandled webapp error while processing %s", path)
            public_error = (
                "Something went wrong while processing your request. Check the server logs."
            )
            if path == "/score":
                score_error = public_error
                values["active_tab"] = "score"

    html_body = render_page(
        values,
        plugin_options=plugin_options,
        score_result=score_result,
        score_error=score_error,
        latest_metrics=latest_metrics,
        model_dir_options=model_dir_options,
        ai_result=ai_result,
        ai_error=ai_error,
        rate_limited=rate_limited,
        ml_ai_result=ml_ai_result,
        ml_ai_error=ml_ai_error,
        ml_rate_limited=ml_rate_limited,
    )
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [html_body.encode("utf-8")]


def main() -> None:
    host = os.getenv("CANARY_WEB_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("PORT", os.getenv("CANARY_WEB_PORT", "8000")))
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
