# Panel Extension & Out-of-Time Validation Protocol

**Status:** Pre-registered — written and committed BEFORE any post-June-2025
data was collected. **Signed:** 2026-08-30. **Advisor sign-off:** pending
(Sep 6, 2026 meeting).

This document pre-specifies how the CANARY monthly panel will be extended
with newly available data and how the extended months will be used. Its
purpose is to make the extension an out-of-time (OOT) validation rather than
another development iteration: every modeling decision below was made using
data ending 2025-06, so observation months after that boundary constitute a
temporal holdout that no feature, encoding, threshold, or protocol choice
was ever informed by. Committing the rules before the data exists is what
gives the eventual numbers their evidential weight; deviations are permitted
only as described in §6 and must be documented in this file's changelog
section.

---

## 1. Development-era state (what the holdout is a holdout FROM)

- Panel: dense monthly grid, 2,053 plugins, 2018-01 → 2025-06 (197,088
  rows); label = `label_advisory_within_6m` (advisory within 6 months after
  the observation month); base rate 1.88%.
- Raw-source cutoffs at development time: Software Heritage graph export
  through ~2025-11 (previous "latest" export); GH Archive events through the
  panel end; advisories/registry as collected 2026-04.
- Evaluation protocol: rolling-origin (expanding-window) backtest with the
  label embargo at every fold (as-of = test start + 1 month), fold test
  starts 2023-05 → 2025-05 step 2, 2-month test windows → 13 folds, 53,378
  pooled test rows / 760 positives, 4,106 test rows per fold.
- Feature families (all as-of, cap-plus-flag no-missing encoding):
  original source features plus the enrichment families `advhist_`,
  `ghclock_`, `ghtext_`, `contagion_`, `ghdyn_`, `swhdelta_`, `installs_`.
- Development-era honest champion (subject to the declared sweep below):
  `ghclock_`-only logistic, pooled ROC-AUC 0.627 / AP lift ≈ 1.9×.

## 2. Frozen as of the sign date

The following may not change in response to anything observed in
post-2025-06 months:

1. **Label definition and horizon** (6-month forward advisory window) and
   the maturation rule (only fully matured observation months are
   evaluated).
2. **Embargo convention:** training labels rebuilt as-of test start + 1
   month, at every fold, via the core `--embargo` path.
3. **Fold design:** expanding window, step 2, 2-month test windows,
   metrics pooled over concatenated fold predictions.
4. **Encoding conventions:** cap-plus-flag "never" encoding, family caps
   and windows exactly as in `canary/build/enrich_monthly.py` at the
   commit containing this document (advhist 120mo, ghclock/ghtext/swhdelta
   3650d, contagion 24-month maintainer window, installs 1-month
   publication lag, growth clamp [-1, +10]).
5. **The ghtext_ security vocabulary** (`SECURITY_TEXT_RE`), the
   contagion_ committer definition, the ghdyn_ windows, and the
   swhdelta_ governance-flag list — verbatim.
6. **Model families and hyperparameters:** the registry defaults for
   `logistic`, `xgboost`, `lightgbm` as of this commit. No tuning on
   extension months.
7. **Champion selection rule:** the final reported configuration is the
   best pooled embargoed ROC-AUC from the DECLARED development-era sweep —
   the 14-run grid (`tools/run_second_wave_backtests.sh`) plus the three
   installs_ runs (`installs_xgb`, `ghclock_installs_xgb`,
   `ghclock_installs_logistic`) — evaluated on the 13 development folds
   only. The champion is recorded in §7 of this file BEFORE any extension
   fold is run. Extension months play no role in selecting it.

## 3. Panel extension specification

| Source | Action | Window |
|--------|--------|--------|
| Software Heritage | Extract from the `s3://softwareheritage/graph/2026-06-04/orc` export against the existing Athena pipeline; visits after the previous export's coverage | ~2025-11 → 2026-06 |
| GH Archive | Incremental BigQuery collection with the existing `canary collect gharchive` pipeline | 2025-07 → 2026-06 (fill any gap after the current panel end) |
| Jenkins advisories | Refresh with the existing collector | through collection date |
| Registry + install stats | Refresh registry; `canary collect installstats` (full history arrives in one fetch per plugin) | through collection date |

Then rebuild: `build features` → `build monthly-features --end 2026-06` →
`build monthly-labels` → `tools/enrich_monthly_features.py` (all families).

Integrity gates (from the development-era incidents): the enriched output
must carry its `.summary.json` completion marker; the extended row count is
recorded here when known and becomes the new `EXPECTED_ROWS` guard; any
fold whose test-row count deviates from the dense-grid expectation
invalidates the run. SWH schema drift between exports is checked on a
single plugin BEFORE the full extraction (see §6 for how schema fixes are
classified).

With advisories known through ~2026-06 and a 6-month label window, fully
matured observation months extend through **2025-12**.

## 4. Out-of-time evaluation specification

Primary OOT measurement — the frozen champion configuration, evaluated on
folds whose test months lie entirely after the development boundary:

```bash
python tools/rolling_backtest.py \
  --in-path data/processed/features/plugins.monthly.labeled.enriched.jsonl \
  --model <champion model> --start 2025-07 --end 2025-11 --step 2 --test-months 2 \
  --include-prefixes <champion prefixes> \
  --out-dir data/processed/results/rolling_backtest/oot_champion
```

Three folds: test windows 2025-07/08, 2025-09/10, 2025-11/12, each trained
on the expanding window through the month before the test start, embargoed
as always. The runner-up configuration and the `ghclock_`-only logistic
baseline are run identically (`oot_runnerup`, `oot_ghclock_logistic`) for
context — declared here, so the OOT sweep is exactly three configurations.
If the runner-up IS the `ghclock_`-only logistic baseline, the third slot
goes to the best tree-model configuration from the development sweep
(`oot_tree_reference`), so that the OOT evaluation always includes one
stability reference alongside the pooled-metric leaders.

Also reported: the full 16-fold curve (`--start 2023-05 --end 2025-11`) for
the combined pooled number and the fold-by-fold trajectory across the
boundary.

**Primary metric:** pooled ROC-AUC (with AP and lift at the operating
tiers) over the three OOT folds. **Reference points:** the H2 criterion
(ROC ≥ 0.55) and the development-era pooled value. **The result is
reported whatever it is** — a drop on OOT months is a finding about
temporal stability, not a reason to iterate; iteration on these months
would convert the holdout into development data, and there is no second
holdout.

## 5. What the extension months may and may not be used for

Allowed: evaluating the frozen configurations (§4); descriptive statistics
for reporting (base rate, advisory counts, coverage); the praxis's
temporal-stability discussion; the SCORED talk; retraining the FINAL
deployed/showcased model on all matured data AFTER the OOT numbers are
recorded (standard practice, disclosed as such).

Not allowed: feature engineering, vocabulary edits, window/cap changes,
hyperparameter changes, model-family choices, or champion re-selection
informed by extension-month results; re-running the OOT evaluation after
any such change ("just to see") — the first recorded OOT run of each
declared configuration is the result.

## 6. Deviation policy

Data-integrity fixes (schema drift in the new SWH export, parsing errors,
truncation, id-mapping breaks) are permitted at any time: they correct what
the data IS, not what the model does with it. Each such fix is re-validated
on the development folds first (numbers there must be unchanged or the
change is a modeling change by definition) and logged in the changelog
below. Anything that alters development-fold numbers is a modeling change
and is out of scope until after the praxis freeze.

## 7. Recorded at freeze (before any extension fold runs)

**Recorded 2026-09-01.** The declared development sweep (19 configurations,
13 embargoed rolling folds, 53,378 pooled test rows / 760 positives, 4,106
test rows per fold in every run) is complete. Under the §2.7 rule (best
pooled embargoed ROC-AUC):

- **Champion:** `ghclock_,ghdyn_` logistic — pooled ROC 0.6381, AP 0.0308,
  lift 2.16×, mean P@25 6.5%; fold floor 0.479 (10/13 folds ≥ 0.55).
- **Runner-up:** `ghclock_,installs_` xgboost — pooled ROC 0.6319, AP
  0.0253, lift 1.78×; fold floor 0.578 (13/13 folds ≥ 0.55).
- **Baseline:** `ghclock_`-only logistic — pooled ROC 0.6275, AP 0.0273,
  lift 1.92×; fold floor 0.465 (10/13).
- Context, not an OOT slot: `ghclock_,ghdyn_,installs_` xgboost — pooled
  ROC 0.6311, lift 1.89×, and the sweep's best fold floor (0.591) and
  fold-mean (0.654); reported in the sweep table as the stability leader.

Negative results retained in full (all below chance alone: advhist_ 0.435,
ghtext_ 0.491, swhdelta_ 0.474; contagion_ ≈ chance at 0.551 and dilutive
in every combination; the five-family pool at 0.551 under xgboost).

- Freeze commit hash of this repository: _to be filled by the commit that
  includes this §7 record (the working tree's v0.1.16 commit)._
- Extended panel row count (new `EXPECTED_ROWS`): _pending collection._

## 8. Schedule and external constraints

- ~Sep 5: SWH 2026-06-04 schema smoke-test (one plugin) — go/no-go on cost
  and drift. Development-era sweep (14 + 3 runs) completes on current panel.
- Sep 6: advisor meeting (this protocol is the sign-off item). SCORED SIP
  final talk abstract due (external; carries no extension numbers).
- Mid-Sep: incremental collection + panel rebuild + integrity gates.
- Late Sep: §7 recorded, then the three OOT runs, then the praxis
  temporal-stability section.
- Oct 6: SCORED talk (Prague) — OOT results presentable as "evaluated on
  months unavailable when the submitted abstract was written."
- ~Oct: praxis integrity-review freeze.

## Changelog

- 2026-08-30 — protocol created and committed (pre-collection).
- 2026-08-31 — §4 clarified (pre-collection, no extension data exists yet):
  when the runner-up coincides with the declared baseline, the third OOT
  slot is the best tree-model configuration. Prompted by the 14-run grid
  result, where ghclock_ghdyn_logistic leads and ghclock_only_logistic is
  runner-up; the three installs_ runs remain to complete the declared sweep
  before §7 is recorded.
- 2026-09-01 — second-stage development sweep declared (pre-collection, OOT
  holdout untouched): the 17-config sweep is complete (installs_ results:
  installs_xgb 0.568; ghclock_installs_xgb 0.632, 13/13 folds ≥ 0.55;
  ghclock_installs_logistic 0.620). Because ghdyn_ and installs_ are the
  only two additive families and were never combined, two further
  configurations are added — `ghclock_,ghdyn_,installs_` under xgboost and
  logistic — making the declared development sweep 19 configurations. The
  §2.7 champion rule applies unchanged over all 19; the sweep size is
  reported as 19 wherever the champion is cited.
- 2026-09-01 (later) — sweep complete; §7 recorded; MODELING FREEZE in
  effect. Both pre-stated triple-combo predictions held (xgb triple ≈ tree
  ceiling ~0.63 with the sweep's best stability; logistic triple inherits
  the 2025 install-drift collapse). From here, only the §3 collection, the
  §4 OOT runs, and §6 data-integrity fixes.
