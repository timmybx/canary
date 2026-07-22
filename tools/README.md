# CANARY analysis tools

Standalone analysis scripts that operate on the pipeline's saved outputs
(`data/processed/`). Each is a plain-stdlib CLI designed to run inside the
project container so results are reproducible under pinned dependencies:

```bash
docker compose run --rm canary python tools/<script>.py
```

| Tool | Question it answers |
|---|---|
| `dedup_precision.py` | What is precision-at-k over *distinct components* rather than component-month rows? |
| `h1_odds_ratio.py` | Does hypothesis H1's marginal claim (stale/small → ≥50% higher advisory odds) hold? |
| `heuristic_baseline.py` | Does the ML model beat the trivial rule "flag anything with a prior advisory"? |

---

## dedup_precision.py — component-level precision-at-k

Recomputes P@k after deduplicating a model's ranked test predictions to each
component's highest-scored row. This is the primary operational metric used in
the praxis (Methodology 3.10) and the web console. Works on any
`test_predictions.csv` (auto-detects `plugin_id`/`package_id`).

```bash
docker compose run --rm canary python tools/dedup_precision.py \
    data/processed/models/xgb_6m_advisory_swh_time --k 10 25 50 100
```

Jenkins and PyPI results are documented in `crossval/pypi/README.md` and in
the praxis (Tables 4-4 and 4-6).

---

## h1_odds_ratio.py — direct marginal test of H1

H1 states that infrequent releases or small contributor teams raise six-month
advisory odds by at least fifty percent (OR ≥ 1.5). This tool computes the
odds ratios directly from `plugins.monthly.labeled.jsonl` using 2x2
contingency tables with Woolf 95% confidence intervals (Haldane-Anscombe
correction on zero cells). The 1.3 GB dataset is streamed at constant memory.

```bash
docker compose run --rm canary python tools/h1_odds_ratio.py \
    --json data/processed/results/h1_odds.json
```

### Results (container run, July 2026)

| Window | Factor | OR | 95% CI | Exposed rate | Unexposed rate | H1 met? |
|---|---|---|---|---|---|---|
| train | releases ≥ 12 months since release tag | 0.350 | [0.322, 0.381] | 2.00% | 5.52% | no |
| train | team ≤ 2 human actors (trailing 6m) | 0.307 | [0.291, 0.325] | 1.80% | 5.63% | no |
| train | either (H1 disjunction) | 0.395 | [0.368, 0.424] | 2.48% | 6.05% | no |
| train | commits ≥ 365 days since last commit | 0.410 | [0.384, 0.439] | 2.20% | 5.19% | no |
| test | releases ≥ 12 months since release tag | 0.896 | [0.530, 1.515] | 0.46% | 0.52% | no |
| test | team ≤ 2 human actors (trailing 6m) | 0.903 | [0.560, 1.457] | 0.45% | 0.50% | no |
| test | either (H1 disjunction) | 0.667 | [0.393, 1.131] | 0.42% | 0.62% | no |
| test | commits ≥ 365 days since last commit | 1.326 | [0.818, 2.152] | 0.53% | 0.40% | no |

Cells are plugin-month observations; rates are P(advisory within 6 months).
Missing factor values are excluded per factor, never treated as unexposed.
JSON artifact: `data/processed/results/h1_odds.json`.

### Interpretation

The marginal association is significantly **reversed**: plugin-months with
stale releases or tiny teams received advisories at roughly a third the rate
of actively maintained ones (train-window ORs 0.31-0.41 with tight CIs).
This does not mean neglected plugins are safer. The label measures *published*
advisories, and publication requires attention: active plugins attract
scrutiny, scrutiny produces labels, and quiet plugins accumulate unexamined
risk that never becomes one. Conditional on the full feature set, SHAP
attribution still ranks maintenance staleness as risk-increasing — a
marginal-vs-conditional reversal (Simpson's paradox) driven by surveillance
bias in advisory-labeled data. Test-window estimates are underpowered (few
positives) and partially right-censored; the train window is authoritative.
H1 is therefore **not supported as stated**; see praxis Section 4.6.

---

## heuristic_baseline.py — trivial rule vs the ML ranking

Because advisory history is CANARY's dominant signal family, a fair question
is whether the model beats the obvious rule: "flag any plugin that has ever
had an advisory." This tool compares, on a single fully-labeled observation
month (default 2025-05):

1. the flag rule as a set (size, precision, coverage, lift),
2. CANARY's top-N at the same review budget N as the rule flagged,
3. the heuristic *ranked* by advisory count vs CANARY at k = 10/25/50/100
   (with tie-group sizes reported — count-based rankings are mostly ties).

```bash
docker compose run --rm canary python tools/heuristic_baseline.py \
    --json data/processed/results/heuristic_baseline.json
```

### Results (container run, July 2026; model `xgb_6m_full_cleaned_time`)

Snapshot 2025-05: 2,053 plugins, 37 positive (component base rate 1.80%).
(37 is the distinct advisory plugins for this single observation month's
6-month window; the full May-November test window contains 39.)

| Approach | Review size | Precision | Coverage | Lift |
|---|---|---|---|---|
| Flag rule (≥ 1 prior advisory) | 629 (30.6% of ecosystem) | 0.018 | 30% | **1.0x** |
| CANARY at the same budget | 629 | 0.059 | 100% | **3.3x** |

Ranked comparison at fixed review sizes:

| k | Heuristic P@k | Heuristic coverage | CANARY P@k | CANARY coverage |
|---|---|---|---|---|
| 10 | 0.000 | 0% | 1.000 | 27% |
| 25 | 0.000 | 0% | 0.920 | 62% |
| 50 | 0.000 | 0% | 0.620 | 84% |
| 100 | 0.060 | 16% | 0.350 | 95% |

Heuristic ranking tie groups (plugins per advisory count, top values):
24:1, 10:1, 9:1, 8:1, 6:2 — within a tie group ordering is arbitrary.
JSON artifact: `data/processed/results/heuristic_baseline.json`.

### Interpretation

The trivial rule is operationally worthless: it flags 30.6% of the entire
ecosystem for a lift of exactly **1.0x** — prior-advisory status alone is
literally no better than random review selection, because a third of the
ecosystem has advisory history and almost all of it is currently fine. At
the same 629-plugin budget the model achieves 3.3x lift and 100% coverage
(every one of the 37 upcoming advisory plugins appears in its top 629).
Ranked by advisory count, the heuristic finds **zero** true positives in the
top 10, 25, and 50 — the plugins with the most historical advisories are not
the ones about to receive new ones — while the model scores 1.000/0.920/0.620
at the same cutoffs. A count ranking is also dominated by ties and cannot be
cut to a review budget in a principled way; the model produces a total order.
Advisory history is a strong *feature*; it is a weak *policy*. The
multivariate model is what converts the signal into a useful ranking.
