"""
Server-rendered SVG charts for the web console.

The console has no JavaScript charting dependency on purpose: every figure is
an inline ``<svg>`` built here from plain Python data, so pages render with no
network access (a conference projector is the target), scale cleanly, and can
be saved straight from the browser as vector figures. Colors reference the
page's CSS variables so the charts follow the console theme.

All text that comes from data passes through ``_esc``. Hover detail uses SVG
``<title>`` elements, which browsers show as native tooltips.
"""

from __future__ import annotations

import html
import math
from collections.abc import Sequence
from typing import Any

SERIES_COLORS: tuple[str, ...] = (
    "var(--accent)",
    "var(--good)",
    "var(--warn)",
    "#ff9fb2",
    "#c9a7ff",
    "#7fe3e8",
)
STORED_COLOR = "var(--warn)"
EMBARGOED_COLOR = "var(--accent)"
_TEXT = "var(--text)"
_MUTED = "var(--muted)"
_LINE = "var(--line)"
_FONT = "font-family:Inter,Segoe UI,Roboto,sans-serif"


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _fmt(value: Any, digits: int = 3) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "—"


def _pct(value: float) -> str:
    return f"{round(value * 100):d}%"


def _svg_open(width: int, height: int, aria_label: str) -> str:
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" width="100%" '
        f'role="img" aria-label="{_esc(aria_label)}" style="{_FONT};max-width:{width}px;'
        'height:auto;display:block">'
    )


def _text(
    x: float, y: float, label: str, *, size: int = 12, fill: str = _MUTED, **attrs: str
) -> str:
    extra = "".join(f' {k.replace("_", "-")}="{_esc(v)}"' for k, v in attrs.items())
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}"{extra}>'
        f"{_esc(label)}</text>"
    )


def _line(x1: float, y1: float, x2: float, y2: float, stroke: str, **attrs: str) -> str:
    extra = "".join(f' {k.replace("_", "-")}="{_esc(v)}"' for k, v in attrs.items())
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{stroke}"{extra}/>'
    )


def _polyline(points: Sequence[tuple[float, float]], stroke: str, width: float) -> str:
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return (
        f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{width}" '
        'stroke-linejoin="round" stroke-linecap="round"/>'
    )


def _nice_bounds(lo: float, hi: float, step: float) -> tuple[float, float]:
    return math.floor(lo / step) * step, math.ceil(hi / step) * step


# ---------------------------------------------------------------------------
# Timeline: ROC-AUC per fold across the development sweep and the holdout
# ---------------------------------------------------------------------------


def svg_timeline(
    series: list[dict[str, Any]],
    *,
    criterion: float,
    boundary_month: str,
    width: int = 960,
    height: int = 360,
) -> str:
    """
    Line chart of per-fold ROC-AUC. Each series is ``{"label", "points"}``
    with points ``{"month", "roc_auc", "positives", "window"}``. Folds whose
    month is after ``boundary_month`` are drawn in a shaded holdout region;
    the chance line (0.5) and the pre-registered criterion are drawn across.
    """
    months = sorted({p["month"] for s in series for p in s.get("points") or []})
    if not months:
        return ""
    left, right, top, bottom = 54, 24, 30, 92
    plot_w = width - left - right
    plot_h = height - top - bottom
    values = [float(p["roc_auc"]) for s in series for p in s["points"]]
    lo, hi = _nice_bounds(min(values + [0.5, criterion]) - 0.02, max(values) + 0.02, 0.05)
    lo = max(0.0, lo)
    hi = min(1.0, hi)

    def x_of(month: str) -> float:
        return left + (months.index(month) + 0.5) * plot_w / len(months)

    def y_of(v: float) -> float:
        return top + (hi - v) / (hi - lo) * plot_h

    out = [_svg_open(width, height, "ROC-AUC per fold, development sweep and out-of-time holdout")]
    # Holdout shading and boundary line.
    holdout = [m for m in months if m > boundary_month]
    if holdout and len(holdout) < len(months):
        first_hold = x_of(holdout[0])
        last_dev = x_of(months[months.index(holdout[0]) - 1])
        bx = (first_hold + last_dev) / 2
        out.append(
            f'<rect x="{bx:.1f}" y="{top}" width="{left + plot_w - bx:.1f}" height="{plot_h}" '
            'fill="rgba(141,240,188,.07)"/>'
        )
        out.append(_line(bx, top, bx, top + plot_h, "var(--good)", stroke_dasharray="4 4"))
        out.append(_text(bx + 6, top + 14, "pre-registered holdout", size=11, fill="var(--good)"))
        out.append(_text(bx - 6, top + 14, "development sweep", size=11, text_anchor="end"))
    # Gridlines and y axis.
    v = lo
    while v <= hi + 1e-9:
        y = y_of(v)
        out.append(_line(left, y, left + plot_w, y, _LINE, stroke_width="1"))
        out.append(_text(left - 8, y + 4, f"{v:.2f}", size=11, text_anchor="end"))
        v = round(v + 0.05, 10)
    # Chance and criterion.
    if lo <= 0.5 <= hi:
        y = y_of(0.5)
        out.append(_line(left, y, left + plot_w, y, _MUTED, stroke_dasharray="6 4"))
        out.append(_text(left + plot_w - 4, y - 5, "chance 0.50", size=11, text_anchor="end"))
    if lo <= criterion <= hi:
        y = y_of(criterion)
        out.append(_line(left, y, left + plot_w, y, "var(--accent2)", stroke_dasharray="6 4"))
        out.append(
            _text(
                left + 4,
                y - 5,
                f"pre-registered criterion {criterion:.2f}",
                size=11,
                fill="var(--accent2)",
            )
        )
    # X labels.
    for m in months:
        out.append(_text(x_of(m), top + plot_h + 18, m, size=10, text_anchor="middle"))
    # Series.
    for i, s in enumerate(series):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        pts = [(x_of(p["month"]), y_of(float(p["roc_auc"]))) for p in s["points"]]
        if len(pts) > 1:
            out.append(_polyline(pts, color, 2.5 if i == 0 else 1.8))
        for p, (x, y) in zip(s["points"], pts, strict=True):
            r = 4.5 if p.get("window") == "out_of_time" else 3.5
            out.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" stroke="var(--bg)" '
                f'stroke-width="1.5"><title>{_esc(s.get("label", ""))}\n{_esc(p["month"])} · '
                f"ROC-AUC {_fmt(p['roc_auc'])} · {_esc(p.get('positives', 0))} advisory outcomes"
                "</title></circle>"
            )
    # Legend.
    ly = top + plot_h + 44
    lx = left
    for i, s in enumerate(series):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        out.append(f'<rect x="{lx}" y="{ly - 9}" width="14" height="14" rx="3" fill="{color}"/>')
        out.append(_text(lx + 20, ly + 2, str(s.get("label", "")), size=12, fill=_TEXT))
        lx += 20 + 7 * len(str(s.get("label", ""))) + 28
        if lx > width - 200:
            lx = left
            ly += 20
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Cumulative gain: share of advisories caught vs share of plugins reviewed
# ---------------------------------------------------------------------------


def svg_gain(
    series: list[dict[str, Any]],
    *,
    fold_curves: list[dict[str, Any]] | None = None,
    callouts: Sequence[float] = (0.10, 0.20, 0.30),
    width: int = 560,
    height: int = 400,
) -> str:
    """
    Gain curves. Each series is ``{"label", "fractions", "captured"}``.
    ``fold_curves`` (same shape, drawn thin and unlabelled) show fold-to-fold
    spread behind the first series. Callouts annotate the first series at
    the given review fractions.
    """
    series = [s for s in series if s.get("fractions") and s.get("captured")]
    if not series:
        return ""
    left, right, top, bottom = 50, 20, 20, 58 + 22 * len(series)
    plot_w = width - left - right
    plot_h = height - top - bottom

    def x_of(f: float) -> float:
        return left + f * plot_w

    def y_of(c: float) -> float:
        return top + (1 - c) * plot_h

    out = [_svg_open(width, height, "Cumulative gain: advisories caught vs plugins reviewed")]
    for k in range(0, 11, 2):
        f = k / 10
        out.append(_line(x_of(f), top, x_of(f), top + plot_h, _LINE, stroke_width="1"))
        out.append(_line(left, y_of(f), left + plot_w, y_of(f), _LINE, stroke_width="1"))
        out.append(_text(x_of(f), top + plot_h + 16, _pct(f), size=11, text_anchor="middle"))
        out.append(_text(left - 8, y_of(f) + 4, _pct(f), size=11, text_anchor="end"))
    out.append(_line(x_of(0), y_of(0), x_of(1), y_of(1), _MUTED, stroke_dasharray="6 4"))
    out.append(_text(x_of(0.62), y_of(0.56), "random order", size=11))
    for fc in fold_curves or []:
        pts = [(x_of(0.0), y_of(0.0))] + [
            (x_of(f), y_of(c)) for f, c in zip(fc["fractions"], fc["captured"], strict=True)
        ]
        out.append(_polyline(pts, "rgba(111,177,255,.35)", 1.2))
    for i, s in enumerate(series):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        pairs = list(zip(s["fractions"], s["captured"], strict=True))
        pts = [(x_of(0.0), y_of(0.0))] + [(x_of(f), y_of(c)) for f, c in pairs]
        out.append(_polyline(pts, color, 2.8 if i == 0 else 1.8))
        for f, c in pairs:
            out.append(
                f'<circle cx="{x_of(f):.1f}" cy="{y_of(c):.1f}" r="3" fill="{color}">'
                f"<title>{_esc(s.get('label', ''))}\nreview top {_pct(f)} of plugins → "
                f"{_pct(c)} of advisories</title></circle>"
            )
    first = series[0]
    lookup = dict(zip(first["fractions"], first["captured"], strict=True))
    for f in callouts:
        if f not in lookup:
            continue
        c = lookup[f]
        x, y = x_of(f), y_of(c)
        out.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5.5" fill="none" stroke="{_TEXT}" '
            'stroke-width="1.5"/>'
        )
        label = f"top {_pct(f)} → {_pct(c)} caught"
        out.append(
            f'<rect x="{x + 7:.1f}" y="{y + 6:.1f}" width="{6.3 * len(label) + 6:.1f}" height="16" '
            'rx="3" fill="var(--panel3)" opacity=".92"/>'
        )
        out.append(_text(x + 10, y + 18, label, size=11, fill=_TEXT))
    out.append(
        _text(
            left + plot_w / 2,
            top + plot_h + 34,
            "share of plugins reviewed",
            size=11,
            text_anchor="middle",
        )
    )
    ly = top + plot_h + 58
    for i, s in enumerate(series):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        out.append(f'<rect x="{left}" y="{ly - 9}" width="14" height="14" rx="3" fill="{color}"/>')
        out.append(_text(left + 20, ly + 2, str(s.get("label", "")), size=12, fill=_TEXT))
        ly += 22
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------
# ROC curves per fold
# ---------------------------------------------------------------------------


def svg_roc(folds: list[dict[str, Any]], *, width: int = 400, height: int = 400) -> str:
    """ROC curves. Each fold is ``{"label", "fpr", "tpr", "auc"}``."""
    folds = [f for f in folds if f.get("fpr") and f.get("tpr")]
    if not folds:
        return ""
    left, right, top, bottom = 44, 16, 16, 52 + 20 * len(folds)
    plot_w = width - left - right
    plot_h = height - top - bottom

    def x_of(f: float) -> float:
        return left + f * plot_w

    def y_of(t: float) -> float:
        return top + (1 - t) * plot_h

    out = [_svg_open(width, height, "ROC curves per out-of-time fold")]
    for k in range(0, 11, 2):
        f = k / 10
        out.append(_line(x_of(f), top, x_of(f), top + plot_h, _LINE, stroke_width="1"))
        out.append(_line(left, y_of(f), left + plot_w, y_of(f), _LINE, stroke_width="1"))
        out.append(_text(x_of(f), top + plot_h + 14, f"{f:.1f}", size=10, text_anchor="middle"))
        out.append(_text(left - 6, y_of(f) + 3, f"{f:.1f}", size=10, text_anchor="end"))
    out.append(_line(x_of(0), y_of(0), x_of(1), y_of(1), _MUTED, stroke_dasharray="6 4"))
    for i, fold in enumerate(folds):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        pts = [(x_of(a), y_of(b)) for a, b in zip(fold["fpr"], fold["tpr"], strict=True)]
        out.append(_polyline(pts, color, 2.0))
    out.append(
        _text(
            left + plot_w / 2,
            top + plot_h + 30,
            "false-positive rate",
            size=10,
            text_anchor="middle",
        )
    )
    ly = top + plot_h + 52
    for i, fold in enumerate(folds):
        color = SERIES_COLORS[i % len(SERIES_COLORS)]
        out.append(f'<rect x="{left}" y="{ly - 8}" width="12" height="12" rx="3" fill="{color}"/>')
        out.append(
            _text(
                left + 18,
                ly + 2,
                f"{fold.get('label', '')} · AUC {_fmt(fold.get('auc'))}",
                size=11,
                fill=_TEXT,
            )
        )
        ly += 20
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Paired bars: stored labels vs embargoed, per configuration
# ---------------------------------------------------------------------------


def svg_paired_bars(
    items: list[dict[str, Any]],
    *,
    metric_label: str,
    chance: float | None = None,
    digits: int = 3,
    width: int = 960,
) -> str:
    """
    Horizontal grouped bars. Each item is ``{"label", "stored", "embargoed"}``
    with numeric values (None skips the bar). ``chance`` draws a dashed
    reference line (0.5 for ROC-AUC).
    """
    items = [it for it in items if it.get("stored") is not None or it.get("embargoed") is not None]
    if not items:
        return ""
    longest = max(len(str(it.get("label", ""))) for it in items)
    left, right, top = min(460, max(220, 7 * longest + 24)), 70, 26
    row_h, bar_h = 50, 16
    height = top + row_h * len(items) + 34
    plot_w = width - left - right
    values = [
        float(v) for it in items for v in (it.get("stored"), it.get("embargoed")) if v is not None
    ]
    x_max = max(values + ([chance] if chance is not None else [])) * 1.12
    x_max = 1.0 if x_max > 0.9 else x_max

    def x_of(v: float) -> float:
        return left + v / x_max * plot_w

    out = [_svg_open(width, height, f"{metric_label}: stored labels vs embargoed")]
    # Legend.
    out.append(f'<rect x="{left}" y="6" width="14" height="14" rx="3" fill="{STORED_COLOR}"/>')
    out.append(_text(left + 20, 18, "stored labels (leaky)", size=12, fill=_TEXT))
    out.append(
        f'<rect x="{left + 190}" y="6" width="14" height="14" rx="3" fill="{EMBARGOED_COLOR}"/>'
    )
    out.append(_text(left + 210, 18, "embargoed (honest)", size=12, fill=_TEXT))
    if chance is not None and chance <= x_max:
        x = x_of(chance)
        out.append(_line(x, top, x, top + row_h * len(items), _MUTED, stroke_dasharray="6 4"))
        out.append(_text(x, height - 10, f"chance {chance:.2f}", size=11, text_anchor="middle"))
    for i, it in enumerate(items):
        y0 = top + i * row_h
        out.append(
            _text(
                left - 12,
                y0 + row_h / 2 + 4,
                str(it.get("label", "")),
                size=12,
                fill=_TEXT,
                text_anchor="end",
            )
        )
        if it.get("sublabel"):
            out.append(
                _text(
                    left - 12, y0 + row_h / 2 + 18, str(it["sublabel"]), size=10, text_anchor="end"
                )
            )
        for j, (key, color) in enumerate(
            (("stored", STORED_COLOR), ("embargoed", EMBARGOED_COLOR))
        ):
            v = it.get(key)
            if v is None:
                continue
            y = y0 + 6 + j * (bar_h + 3)
            w = max(0.0, x_of(float(v)) - left)
            out.append(
                f'<rect x="{left}" y="{y:.1f}" width="{w:.1f}" height="{bar_h}" rx="3" '
                f'fill="{color}">'
                f"<title>{_esc(it.get('label', ''))}\n{_esc(key)}: {metric_label} {_fmt(v, digits)}"
                "</title></rect>"
            )
            out.append(_text(left + w + 6, y + bar_h - 4, _fmt(v, digits), size=11, fill=_TEXT))
    out.append("</svg>")
    return "".join(out)
