from __future__ import annotations

# ruff: noqa: E501
import json
import logging
import mimetypes
import os
import re
import time as _time
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol, cast
from wsgiref.simple_server import make_server

from canary.scoring.baseline import score_plugin_baseline
from canary.scoring.ml import MLScorer, load_ml_scorer, score_plugin_ml
from canary.web.services import (
    _EXPLAIN_RATE_LIMIT,  # noqa: F401
    _EXPLAIN_RATE_LIMIT_LOCK,  # noqa: F401
    _EXPLAIN_RATE_MAX,  # noqa: F401
    _EXPLAIN_RATE_WINDOW,  # noqa: F401
    _fetch_live_commit_date,  # noqa: F401
    _inject_live_commit_signal,  # noqa: F401
    _load_plugin_choices,  # noqa: F401
    _load_registry_plugin_choices_cached,  # noqa: F401
)
from canary.web.ui import (
    _ALGO_LABELS,  # noqa: F401
    _ALGO_ORDER,  # noqa: F401
    _FEATURE_LABELS,  # noqa: F401
    _FEATURE_ORDER,  # noqa: F401
    _FEATURE_TIPS,  # noqa: F401
    _METRIC_TIPS,  # noqa: F401
    _MODEL_LABELS,  # noqa: F401
    _SPLIT_LABELS,  # noqa: F401
    _SPLIT_ORDER,  # noqa: F401
    CSS,  # noqa: F401
    _build_cs_explain_prompt,  # noqa: F401
    _build_explain_prompt,  # noqa: F401
    _build_ml_explain_prompt,  # noqa: F401
    _build_model_index,  # noqa: F401
    _checkbox,  # noqa: F401
    _escape,  # noqa: F401
    _float_or_none,  # noqa: F401
    _fmt_driver_value,  # noqa: F401
    _input_text,  # noqa: F401
    _int_or_none,  # noqa: F401
    _metric_value,  # noqa: F401
    _ml_score_payload,  # noqa: F401
    _parse_model_dir,  # noqa: F401
    _plugin_picker,  # noqa: F401
    _render_about_tab,  # noqa: F401
    _render_base_rate_bar,  # noqa: F401
    _render_case_study_tab,  # noqa: F401
    _render_class_report,  # noqa: F401
    _render_command_result,  # noqa: F401
    _render_confusion_matrix,  # noqa: F401
    _render_cs_explain_card,  # noqa: F401
    _render_explain_card,  # noqa: F401
    _render_feature_columns_panel,  # noqa: F401
    _render_feature_item,  # noqa: F401
    _render_feature_selection_panel,  # noqa: F401
    _render_ml_explain_card,  # noqa: F401
    _render_ml_metrics,  # noqa: F401
    _render_ml_score_panel,  # noqa: F401
    _render_ml_tab,  # noqa: F401
    _render_model_badge,  # noqa: F401
    _render_model_picker,  # noqa: F401
    _render_operational_panel,  # noqa: F401
    _render_ranking_row,  # noqa: F401
    _render_score_section,  # noqa: F401
    _score_payload,  # noqa: F401
    _select,  # noqa: F401
    _tip,  # noqa: F401
    _validation_script,  # noqa: F401
)

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


def _plugin_known(plugin_id: str, registry_path: str) -> bool:
    plugin_id = plugin_id.strip()
    if not plugin_id:
        return False
    choices = _load_plugin_choices(registry_path)
    return not choices or plugin_id in choices


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


def _get_ml_scorer(model_dir: str) -> MLScorer | None:
    """Load the ML scorer from *model_dir*, returning None if not yet trained."""
    try:
        return load_ml_scorer(model_dir)
    except FileNotFoundError:
        return None


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


# Feature descriptions: what the feature measures and why it was collected,
# based on the literature motivating its inclusion. No results-based judgements.
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


# ---------------------------------------------------------------------------
# Structured model picker
# ---------------------------------------------------------------------------


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


def _load_cs_prediction_rows(
    model_out_dir: str,
    metrics: dict[str, Any] | None,
    n_top: int = 25,
) -> tuple[str, str, list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Load and enrich top-N case study predictions for a model directory.

    Returns (obs_date, window_end, confirmed_rows, unconfirmed_rows).
    Each row dict includes: rank, plugin_id, score, adv_sev, adv_cvss,
    adv_date, adv_url, days_to_adv, confirmed.
    """
    import csv as _csv
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    stem = Path(model_out_dir).name
    pred_path = MODEL_OUTPUTS_ROOT / stem / "test_predictions.csv"
    if not pred_path.exists():
        return "", "", [], []

    rows: list[dict[str, Any]] = []
    try:
        reader = _csv.DictReader(pred_path.read_text(encoding="utf-8").splitlines())
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
        return "", "", [], []

    obs_date = (metrics or {}).get("test_start_month") or (
        min(r["month"] for r in rows) if rows else ""
    )
    window_end = ""
    if obs_date:
        try:
            obs_dt = _dt.strptime(obs_date, "%Y-%m")
            em = obs_dt.month + 6
            ey = obs_dt.year + (em - 1) // 12
            em = ((em - 1) % 12) + 1
            end_dt = (_dt(ey, em, 1) + _td(days=32)).replace(day=1) - _td(days=1)
            window_end = end_dt.strftime("%Y-%m-%d")
        except ValueError:
            pass

    # Deduplicate by plugin_id
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        if row["plugin_id"] not in seen:
            seen.add(row["plugin_id"])
            deduped.append(row)

    enriched: list[dict[str, Any]] = []
    for rank, row in enumerate(deduped[:n_top], start=1):
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
                    _dt.strptime(adv_date, "%Y-%m-%d") - _dt.strptime(obs_date, "%Y-%m")
                ).days
            except ValueError:
                pass
        enriched.append(
            {
                "rank": rank,
                "plugin_id": pid,
                "score": row["y_prob"],
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
    return obs_date, window_end, confirmed_rows, unconfirmed_rows


def _load_case_study_view(values: dict[str, Any]) -> dict[str, Any] | None:
    """
    Assemble everything the case-study tab renders: model metrics, the
    enriched top-N prediction rows, and ecosystem context numbers.

    Returns None when no model is selected. This is the seam between data
    loading (here, in webapp) and presentation (_render_case_study_tab in ui).
    """
    model_out_dir = values.get("model_out_dir") or ""
    if not model_out_dir:
        return None
    stem = Path(model_out_dir).name
    pred_exists = (MODEL_OUTPUTS_ROOT / stem / "test_predictions.csv").exists()
    metrics = _load_model_metrics(model_out_dir)
    obs_date = window_end = ""
    confirmed: list[dict[str, Any]] = []
    unconfirmed: list[dict[str, Any]] = []
    if pred_exists:
        obs_date, window_end, confirmed, unconfirmed = _load_cs_prediction_rows(
            model_out_dir, metrics
        )
    n_pos = (metrics or {}).get("test_positive_count", 0)
    n_test = (metrics or {}).get("test_row_count", 1)
    return {
        "stem": stem,
        "pred_exists": pred_exists,
        "metrics": metrics,
        "obs_date": obs_date,
        "window_end": window_end,
        "confirmed_rows": confirmed,
        "unconfirmed_rows": unconfirmed,
        "base_rate": n_pos / n_test if n_test > 0 else 0.0,
        "n_pos": n_pos,
        "n_test_plugins": (metrics or {}).get("test_unique_plugin_count"),
    }


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
    cs_ai_result: str | None = None,
    cs_ai_error: str | None = None,
    cs_rate_limited: bool = False,
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
        active_panel_html = _render_case_study_tab(
            values,
            model_dir_options or [],
            cs_view=_load_case_study_view(values),
            cs_ai_result=cs_ai_result,
            cs_ai_error=cs_ai_error,
            cs_rate_limited=cs_rate_limited,
        )
    else:
        _ml_dir = values.get("model_out_dir") or ""
        active_panel_html = _render_ml_tab(
            values,
            latest_metrics,
            model_dir_options,
            pk_data=_load_precision_at_k(_ml_dir) if _ml_dir else None,
            fs_data=_load_feature_selection(_ml_dir) if _ml_dir else None,
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
    _get_cs_explain = query.get("cs_explain", [""])[-1] == "1"
    plugin_options, latest_metrics, model_dir_options = _prepare_request_state(values)
    score_result = None
    score_error = None
    ai_result: str | None = None
    ai_error: str | None = None
    rate_limited: bool = False
    ml_ai_result: str | None = None
    ml_ai_error: str | None = None
    ml_rate_limited: bool = False
    cs_ai_result: str | None = None
    cs_ai_error: str | None = None
    cs_rate_limited: bool = False

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
                ml_rate_limited = True
            else:
                try:
                    _ml_prompt = _build_ml_explain_prompt(
                        _ml_metrics, _ml_pk, _ml_fs, _ml_explain_dir
                    )
                    ml_ai_result = _call_anthropic_explain(_ml_prompt)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("ML explain call failed: %s", exc)
                    ml_ai_error = "AI explanation unavailable — use Copy or Open buttons below."
        values["active_tab"] = "ml"

    # GET cs_explain — runs when cs_explain=1 is in query string (case study tab)
    if method == "GET" and _get_cs_explain and values.get("model_out_dir"):
        _cs_explain_dir = values["model_out_dir"]
        _cs_metrics = _load_model_metrics(_cs_explain_dir)
        if _cs_metrics:
            client_ip = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[
                0
            ].strip() or environ.get("REMOTE_ADDR", "unknown")
            if not _check_explain_rate_limit(client_ip):
                cs_rate_limited = True
            else:
                try:
                    _cs_obs, _cs_wend, _cs_confirmed, _cs_unconfirmed = _load_cs_prediction_rows(
                        _cs_explain_dir, _cs_metrics
                    )
                    _cs_train = _cs_metrics.get("train_start_month") or ""
                    _cs_stem = Path(_cs_explain_dir).name
                    _cs_n_total = len(_cs_confirmed) + len(_cs_unconfirmed)
                    _cs_n_confirmed = len(_cs_confirmed)
                    _cs_n_pos = _cs_metrics.get("test_positive_count", 0)
                    _cs_n_test = _cs_metrics.get("test_unique_plugin_count") or _cs_metrics.get(
                        "test_row_count", 1
                    )
                    _cs_base = _cs_n_pos / _cs_n_test if _cs_n_test > 0 else 0.0
                    _cs_lift = (
                        (_cs_n_confirmed / _cs_n_total) / _cs_base
                        if _cs_n_total > 0 and _cs_base > 0
                        else 0.0
                    )
                    _cs_prompt = _build_cs_explain_prompt(
                        metrics=_cs_metrics,
                        confirmed_rows=_cs_confirmed,
                        unconfirmed_rows=_cs_unconfirmed,
                        obs_date=_cs_obs,
                        window_end=_cs_wend,
                        n_total=_cs_n_total,
                        n_confirmed=_cs_n_confirmed,
                        lift=_cs_lift,
                        base_rate=_cs_base,
                        train_start=_cs_train,
                        stem=_cs_stem,
                    )
                    cs_ai_result = _call_anthropic_explain(_cs_prompt)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("CS explain call failed: %s", exc)
                    cs_ai_error = "AI explanation unavailable — use Copy or Open buttons below."
        values["active_tab"] = "casestudy"

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
            score_result = _inject_live_commit_signal(score_result, plugin)
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
            score_error = "Unable to score the requested plugin right now."
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
                    ai_error = "AI explanation unavailable — use Copy or Open buttons below."  # noqa: F841
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
            score_result = _inject_live_commit_signal(score_result, plugin)
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
        cs_ai_result=cs_ai_result,
        cs_ai_error=cs_ai_error,
        cs_rate_limited=cs_rate_limited,
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
