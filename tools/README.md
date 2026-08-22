# CANARY analysis tools

Standalone analysis scripts that operate on the pipeline's saved outputs
(`data/processed/`). Each is designed to run inside the project container so
results are reproducible under pinned dependencies:

```bash
docker compose run --rm canary python tools/<script>.py
```

| Tool | Question it answers |
|---|---|
| `run_monthly_ablation_experiments.sh` | (driver) Trains the full 64-configuration ablation suite. |
| `summarize_ablation_metrics.py` | Summarizes metrics across the trained suite. |
| `dedup_precision.py` | What is precision-at-k over *distinct components* rather than component-month rows? |
| `h1_odds_ratio.py` | Does hypothesis H1's marginal claim (stale/small → ≥50% higher advisory odds) hold? |
| `simpson_stratified.py` | Does the H1 reversal survive stratification by an attention proxy? |
| `heuristic_baseline.py` | Does the ML model beat the trivial rule "flag anything with a prior advisory"? |
| `brier_score.py` | Do the predicted probabilities carry information beyond the base rate (Brier / skill score)? |
| `shap_single_model.py` | **Source of record for feature interpretation**: signed SHAP for one specified model, direction from feature values, binned dependence profiles. |
| `shap_consistency.py` | Robustness check only: is a feature's importance stable across model configurations? |
| `compare_model_metrics.py` | How much did a pipeline change move the metrics? (before/after retrain diff) |
| `embargo_backtest.py` | Does the time-split headline survive when training labels are restricted to those matured before the prediction date? |
| `make_figures.py` | Renders praxis/defense figures from the saved artifacts above. |

---

## July 2026: advisory imputation correction

Advisory-family features (`advisory_*`, `advisories_*`) derive from the
Jenkins security advisory feed, which is **complete by construction** — a
missing value means the plugin has no advisory history, not that data went
unobserved. These features are now **zero-filled** instead of median-imputed
(`canary/train/baseline.py`; same fix mirrored in `crossval/pypi/03_train.py`
and `04_dedup_precision.py`). The previous global median imputation placed
no-history plugins in the middle of the observed severity range, entangling
them with genuine mid-severity history.

Consequences for the results in this README:

- **Dataset-level analyses are unaffected** (`h1_odds_ratio.py`,
  `simpson_stratified.py`): they read the labeled JSONL directly and never
  touch a model. Their result tables below remain current.
- **Model-derived results predate the correction** (`heuristic_baseline.py`
  results table, all SHAP outputs) and regenerate after the suite retrain.
  Use `compare_model_metrics.py` against the pre-correction snapshot to
  quantify the change.

---

## run_monthly_ablation_experiments.sh — training driver

Trains the full experiment matrix (4 model families x 2 split strategies x 8
feature families) plus the feature selection runs behind the H3 analysis.
Sections can be run individually; `--skip-filter` reuses existing per-family
feature files (they are dataset-level and unaffected by pipeline changes);
`--dry-run` prints commands. Full suite is roughly 5.5 hours.
`summarize_ablation_metrics.py` tabulates the resulting metrics.

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

*Dataset-level; unaffected by model retraining.*

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
risk that never becomes one. This is a form of **surveillance bias** — the
outcome can only be recorded where someone is looking, so maintenance
conditions that correlate with attention inherit a protective-looking
marginal association. Test-window estimates are underpowered (few positives)
and partially right-censored; the train window is authoritative. H1 is
therefore **not supported as stated**; see praxis Section 4.6, and
`simpson_stratified.py` below for a direct test of the mechanism.

---

## simpson_stratified.py — attention-stratified test of the H1 reversal

*Dataset-level; unaffected by model retraining.*

If the reversal is surveillance bias, stratifying by an attention proxy
should weaken it. This tool splits plugin-months into three strata of
`gharchive_unique_actors` (none / at-or-below median nonzero / above median)
and compares stale vs fresh advisory rates per stratum and pooled.

```bash
docker compose run --rm canary python tools/simpson_stratified.py \
    --json data/processed/results/simpson_stratified.json
```

### Results (container run, July 2026; releases factor, train window)

| Stratum | n | Fresh rate | Stale rate | Stale/fresh ratio |
|---|---|---|---|---|
| No observed activity | 44,549 | 4.30% | 1.57% | 0.37 |
| Lower activity | 25,300 | 5.12% | 3.21% | 0.63 |
| Higher activity | 19,742 | 7.05% | 5.13% | 0.73 |
| **All pooled** | 89,591 | 5.52% | 2.00% | **0.36** |

### Interpretation

The sign does **not** flip within strata, so this is not a textbook Simpson's
paradox demonstration: staleness remains marginally protective in every
stratum. What the stratification shows instead is a **monotone attenuation**
exactly where the surveillance mechanism predicts it: the stale/fresh ratio
climbs from 0.37 among unwatched plugins toward 0.73 in the most active
stratum. A single activity proxy captures attention only coarsely (the top
stratum still spans a wide attention range), which is consistent with the
residual protective association within strata. Mechanism supported; textbook
label withheld.

---

## heuristic_baseline.py — trivial rule vs the ML ranking

Because advisory history is a natural candidate policy, a fair question is
whether the model beats the obvious rule: "flag any plugin that has ever had
an advisory." This tool compares, on a single fully-labeled observation month
(default 2025-05):

1. the flag rule as a set (size, precision, coverage, lift),
2. CANARY's top-N at the same review budget N as the rule flagged,
3. the heuristic *ranked* by advisory count vs CANARY at k = 10/25/50/100
   (with tie-group sizes reported — count-based rankings are mostly ties).

```bash
docker compose run --rm canary python tools/heuristic_baseline.py \
    --json data/processed/results/heuristic_baseline.json
```

### Results (July 2026, `xgb_6m_full_cleaned_time` — PRE-CORRECTION; regenerate after retrain)

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

### Interpretation

The trivial rule is operationally worthless: it flags 30.6% of the ecosystem
for a lift of exactly **1.0x** — prior-advisory status alone is no better
than random review selection. At the same 629-plugin budget the model
achieves 3.3x lift and 100% coverage. Ranked by advisory count, the heuristic
finds **zero** true positives in the top 10, 25, and 50. Advisory history is
a *feature*; it is a weak *policy*. The multivariate model is what converts
signals into a useful ranking. The rule itself is model-independent, so only
the CANARY columns change with the retrain.

---

## brier_score.py — preliminary probability calibration check

Computes the Brier score (mean squared error between predicted probability
and binary outcome) from a model's saved `test_predictions.csv`, alongside a
base-rate reference (always predict the test-set base rate) and the Brier
skill score, BSS = 1 − BS/BS_ref. At CANARY's ~1.9% base rate a raw Brier
score is deceptively small, so only the skill score is meaningful: positive
skill means the probabilities carry information beyond the base rate.

```bash
docker compose run --rm canary python tools/brier_score.py \
    --json data/processed/results/brier_scores.json
```

### Results (container run, August 2026, post zero-fill retrain)

| Model | n | Base rate | Brier | Base-rate ref | Skill |
|---|---|---|---|---|---|
| `xgb_6m_advisory_swh_time` (headline) | 4,106 | 0.0188 | 0.0141 | 0.0184 | **+0.236** |
| `xgb_6m_full_cleaned_time` (deployed) | 4,106 | 0.0188 | 0.0135 | 0.0184 | **+0.268** |

This is the preliminary check reported in praxis Section 4.7. It is
necessary but not sufficient for interpreting scores as probabilities;
formal calibration (reliability analysis, ECE, threshold justification)
remains future work.

---

## shap_single_model.py — feature interpretation (source of record)

Computes exact TreeExplainer SHAP for **one specified model configuration**
over the full test set, and reports for each feature:

- **magnitude**: mean |SHAP| (importance ranking),
- **direction**: the Pearson correlation between imputed feature values and
  per-row SHAP contributions — answering "do HIGH values raise or lower
  predicted risk?", the question praxis prose actually asks. (The per-model
  `mean_shap` sign answers a different question — "which way is the *average*
  plugin pushed?" — and is unstable for zero-inflated features.) Correlations
  with |r| < 0.2 are flagged weak.
- **binned dependence profiles**: mean SHAP within value bins, with adaptive
  binning (quintiles; one bin per value for low-cardinality features; a
  minimum-value bin plus terciles for zero-inflated features). A `bin_shape`
  verdict (increasing / decreasing / non-monotone) is derived per feature.
- **observed-only profiles** for features with >10% missingness: bins over
  only the rows where the value was genuinely observed, excluding imputed
  rows. This is what isolated the advisory severity signal from the
  pre-correction median imputation.
- **version-drift self-check**: reproduces the model's saved
  `test_predictions.csv` before computing SHAP and reports the max
  difference, so unpickling under newer library versions can never silently
  change what is being explained. (July 2026 runs: max |diff| = 0.0 on both
  reported models.)

Temporal window features are excluded (praxis Section 4.4.1).

```bash
# interpretation model (deployed full configuration)
docker compose run --rm canary python tools/shap_single_model.py \
    --model-dir data/processed/models/xgb_6m_full_cleaned_time \
    --json data/processed/results/shap_full_model.json

# Advisory+SWH headline configuration (robustness comparison)
docker compose run --rm canary python tools/shap_single_model.py \
    --json data/processed/results/shap_single_model.json
```

Results live in the JSON artifacts and regenerate after the imputation
correction retrain; see praxis Sections 4.4.5-4.4.9 for the reported
interpretation.

---

## shap_consistency.py — cross-model stability check (NOT a source of record)

Aggregates the `top_positive_features` / `top_negative_features` lists from
each model's `metrics.json` across a set of configurations. Useful as a
*stability check* (does a feature appear among top contributors in many
configurations?) and it is the tool that caught the temporal window features
topping the raw rankings. It is **not** used for reported importance numbers
because the aggregation:

- mixes signed SHAP (XGBoost/LightGBM) with unsigned fallbacks (Random
  Forest MDI, logistic coefficients),
- averages magnitudes that are not comparable across feature-set sizes
  (a 5-feature model concentrates SHAP mass that a 40-feature model spreads),
- counts appearances in a way that favors small models,
- inherits the mean-sign direction instability described above.

```bash
docker compose run --rm canary python tools/shap_consistency.py \
    --json data/processed/results/shap_consistency.json
```

---

## compare_model_metrics.py — before/after retrain diff

Quantifies how much a pipeline change moved the metrics, so a retrain's
effect is measured rather than eyeballed.

```bash
# BEFORE retraining: snapshot the small artifacts
tar czf models_backup_$(date +%Y%m%d).tgz \
    data/processed/models/*/metrics.json \
    data/processed/models/*/feature_selection.json \
    data/processed/models/*/precision_at_k.json

# AFTER retraining:
# extract INSIDE the repo tree (host /tmp is not mounted into the container)
mkdir -p data/tmp_before && tar xzf models_backup_*.tgz -C data/tmp_before
docker compose run --rm canary python tools/compare_model_metrics.py \
    --before data/tmp_before/data/processed/models \
    --after data/processed/models \
    --json data/processed/results/imputation_fix_deltas.json
```

Reports AP/ROC-AUC per model with deltas, the largest movers, and the max
absolute change across the suite.

---

## embargo_backtest.py — label-embargo backtest of the time-split protocol

Six-month labels look forward, so the labels of the final training months
(2024-12 through 2025-04) are determined by advisory events that also fall in
the test outcome window. A model standing at the test prediction date could
not have used those labels — they had not yet matured. This tool measures how
much of the reported time-split performance depends on that overlap.

No relabeling is required: labels derive from advisory publication dates, so
for any observation month whose window closed before the embargo date, the
truncated feed and the full feed produce identical labels. The embargo
therefore reduces to a training-month cutoff over the existing labeled
dataset. The tool retrains the official configuration (feature columns taken
verbatim from `xgb_6m_advisory_swh_no_window_time/feature_columns.json`,
same registry estimator, same imputation) at each cutoff and evaluates on
the identical 4,106 test rows, sanity-checking them against the saved
official predictions. Nothing under `data/processed/models/` is touched;
outputs go to `data/processed/results/embargo_backtest/`, with per-run
`test_predictions.csv` files compatible with `dedup_precision.py`.

A deployment-realistic variant (`--as-of YYYY-MM`) keeps every training
observation and instead rebuilds each label as it was knowable at that
date: 1 if an advisory fell in the observation's window and was published
in a month strictly before the as-of date, 0 otherwise (a censored
"no advisory yet" counts as 0, as it would in deployment). This is the
most generous honest protocol — everything a system retraining on
prediction day could legally have known. `--as-of 2025-06` = labels as
known June 1, 2025.

```bash
docker compose run --rm canary python tools/embargo_backtest.py --as-of 2025-06

# earlier-era control (repeat the protocol around a 2024 test window)
docker compose run --rm canary python tools/embargo_backtest.py \
    --test-start 2024-05 --test-end 2024-06 --cutoffs 2023-11 2023-05
```

### Results (container run, August 2026)

Test rows: observation months 2025-05/06 (4,106 rows, 77 positives, base
rate 1.88%). `cutoff_2024-11` removes only the training rows whose label
windows overlap the test outcome window; `cutoff_2024-05` additionally
requires every training label to have matured by 2024-11-30.

| Run | Train through | Rows | AP | ROC-AUC | P@25 (rows) | P@25 (dedup) | P@50 (dedup) |
|---|---|---|---|---|---|---|---|
| full (= official) | 2025-04 | 180,664 | 0.5831 | 0.9302 | 92% | 76% | 46% |
| cutoff_2024-11 | 2024-11 | 170,399 | 0.0193 | 0.4776 | 4% | 4% | 2% |
| cutoff_2024-05 | 2024-05 | 158,081 | 0.0220 | 0.4920 | 8% | 4% | 2% |
| asof_2025-06 | 2025-04 | 180,664 | 0.0193 | 0.4816 | 8% | 4% | 2% |

### Interpretation

Removing the overlapping training rows — 6% of the data — collapses the
time-split configuration to base-rate performance (AP ≈ 0.02 against a
1.88% base rate; ROC ≈ 0.5). The embargoed result converges with the
group-time split for the same feature family (`xgb_6m_advisory_swh_gt`,
AP 0.0233): two independent controls, one severing plugin identity and one
severing label maturity, arrive at the same number.

The as-of run makes the attribution exact. It kept all 180,664 training
rows and 5,187 of the 5,292 stored positives — withholding only the 105
positive labels that depended on advisories published during the test
outcome window — and collapsed identically (AP 0.0193). The entire gap
between AP 0.583 and base-rate performance therefore rests on 105 label
bits about the test outcome window, 0.06% of the training data. Partial
label maturity carries essentially no forward signal for this window, and
the most generous honest protocol fails the same way as the strictest one.

The mechanism is visible in the test positives. Of the 41 distinct plugins
with a positive test label, 29 had no advisory history before 2025; they
were hit by batch advisory publications (2025-07-09 covers 20 of them,
2025-10-29 another 12). The overlapping training rows of those same plugins
carry positive labels, and the SWH features are close to a per-plugin
fingerprint, so the full model can learn *which specific plugins* are in an
ongoing advisory wave from supervision that postdates the prediction date.
The embargoed models fall back to genuine forward signal — they rank
long-history plugins such as `workflow-cps` and `script-security` highest —
but the 2025 batches swept first-time plugins, so that signal does not
transfer to this test window.

Read with the ablation-suite results: the time-split headline (AP 0.5831)
measures within-window entity continuity, not prospective forecasting skill.
The deployment-honest estimate for this task is the embargoed/group-time
level. The window-feature exclusion documented in
`canary/train/baseline.py` removed the calendar-position channel of the same
optimism (~+0.21 AP); this backtest measures the entity-level channel that
remains.

### Era control (container run, August 2026)

The earlier-era control repeats the protocol around a 2024 test window
(observation months 2024-05/06: 4,106 rows, 23 positives, base rate 0.56%)
with the analogous cutoffs:

| Run | Train through | Rows | AP | AP ÷ base rate | ROC-AUC | P@25 (dedup) |
|---|---|---|---|---|---|---|
| cutoff_2023-11 | 2023-11 | 145,763 | 0.0122 | 2.2× | 0.5427 | 0% |
| cutoff_2023-05 | 2023-05 | 133,445 | 0.0090 | 1.6× | 0.6048 | 0% |

The collapse reproduces in an independent era: embargoed performance sits at
1–2× base rate in both 2024 and 2025 (the lower absolute AP in 2024 reflects
its lower base rate, not worse behavior), versus ~31× base rate under the
standard protocol. The structural reading stands — this is how the task
behaves, not a quirk of the 2025 batch composition. With only 23 positives
the 2024 estimates are noisy; the defensible statement is "at or near base
rate in every honest configuration, in both eras tested."

---

## make_figures.py — praxis and defense figures

Renders figures from the saved artifacts above (no retraining, no new
experiments). Requires matplotlib (dev dependency).

| Figure | Source artifact |
|---|---|
| `h1_forest.png` | `results/h1_odds.json` |
| `simpson.png` | `results/simpson_stratified.json` |
| `precision_coverage.png` | `<model>/test_predictions.csv` (component-level) |
| `h3_retention.png` | `<model>/feature_selection.json` |
| `calibration.png` | `<model>/test_predictions.csv` |
| `shap_single.png` | `results/shap_single_model.json` (diverging importance) |
| `shap_profiles.png` | `results/shap_single_model.json` (dependence small-multiples) |
| `shap_consistency.png` | `results/shap_consistency.json` (stability check) |
| `shap_importance.png` | `<model>/feature_selection.json` (superseded by shap_single) |

```bash
# everything
docker compose run --rm canary python tools/make_figures.py

# praxis interpretation figures from the full model
docker compose run --rm canary python tools/make_figures.py \
    --only shap_single shap_profiles \
    --shap-single-json data/processed/results/shap_full_model.json \
    --out-dir data/processed/figures/praxis
```
