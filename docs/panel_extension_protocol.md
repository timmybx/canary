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

**Recorded 2026-08-31.** The declared development sweep (19 configurations,
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

- Freeze commit: tag `v0.1.16`, hash
  `eebc53f17b1c69c9efb3e30b1a9b213db16e5749` (contains this §7 record and
  the complete frozen feature/tooling state; this hash line was added in
  the immediately following commit, since a commit cannot contain its own
  hash).
- Extended panel row count (new `EXPECTED_ROWS`): **209,406** (102 months,
  2018-01 → 2026-06, × 2,053 plugins; recorded 2026-09-02 after the
  rebuild's integrity gates passed — see changelog).

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
- 2026-08-31 — second-stage development sweep declared (pre-collection, OOT
  holdout untouched): the 17-config sweep is complete (installs_ results:
  installs_xgb 0.568; ghclock_installs_xgb 0.632, 13/13 folds ≥ 0.55;
  ghclock_installs_logistic 0.620). Because ghdyn_ and installs_ are the
  only two additive families and were never combined, two further
  configurations are added — `ghclock_,ghdyn_,installs_` under xgboost and
  logistic — making the declared development sweep 19 configurations. The
  §2.7 champion rule applies unchanged over all 19; the sweep size is
  reported as 19 wherever the champion is cited.
- 2026-08-31 (later) — sweep complete; §7 recorded; MODELING FREEZE in
  effect. Both pre-stated triple-combo predictions held (xgb triple ≈ tree
  ceiling ~0.63 with the sweep's best stability; logistic triple inherits
  the 2025 install-drift collapse). From here, only the §3 collection, the
  §4 OOT runs, and §6 data-integrity fixes.
- 2026-08-31 (later; pre-collection, no extension data exists yet) — §3
  sequencing amendment, recorded before any collection: the §4 OOT runs
  will execute on a panel whose Software Heritage inputs remain FROZEN at
  their development-era values (the existing Athena visit files; swh_* and
  swhdelta_ columns recomputed from them with unchanged semantics).
  Rationale: none of the three declared OOT configurations includes any
  SWH-derived feature prefix, so new SWH data cannot alter the OOT numbers;
  extraction from the 2026-06-04 export proceeds on a parallel track and
  feeds the praxis discussion and future work, not the OOT evaluation.
  Additionally made explicit: the extended grid keeps the development-era
  plugin universe (the frozen registry, 2,053 plugins), preserving the
  4,106-rows-per-fold integrity gate; plugins registered after the
  development era are out of cohort and disclosed as such. Advisor
  sign-off on this amendment is a Sep 6 agenda item alongside the protocol
  itself.
- 2026-08-31 — date correction (no content changed): the §7 record and two
  changelog entries above were previously dated 2026-09-01; they were written
  late on 2026-08-31 US Mountain time and picked up the UTC date. Corrected to
  match the freeze commit timestamp (`eebc53f`, 2026-08-31 10:20 −0600).
- 2026-09-01 — §3 collection status and two post-freeze data events (recorded
  BEFORE any OOT fold runs; no extension fold has been evaluated).
  Collection: plugin snapshots and advisories refreshed (advisories through
  2026-08-05; the five 2026 Jenkins plugin batches, 53 plugin-advisory
  records, batch sizes matching jenkins.io exactly); GH Archive extended
  2025-10 → 2026-06 at 100% sampling with the dev-era repo mapping
  (0 of 340 sampled plugins changed repositories); install stats collected
  2026-08-31. Plugin universe held at the frozen registry (2,053; one plugin,
  keepSlaveOffline, removed from the update center since 2026-04 — its
  dev-era snapshot retained). SWH extraction remains on the parallel track
  per the 2026-08-31 amendment.
  Event 1 — GH Archive per-repository capture collapses in 2026. Global
  archive intake is unchanged (BigQuery `githubarchive.day.__TABLES__`:
  3.3–3.8M rows/day in 2025-06 vs 3.0–3.9M/day in 2026-06), but captured
  events for cohort repositories fall from ~7.5k/month (2025-08) to ~1.3k
  (2026-06) with PR-opened events vanishing on core plugins (git-plugin:
  9 PRs created on GitHub in 2026-06, 0 captured). Consequence: observation
  months from ~2026-02 onward are collected but NOT evaluable and are
  excluded from all reporting beyond coverage statistics; the declared OOT
  window (through 2025-12) predates the collapse but not the decay.
  Calibration against GitHub's own PR-created counts (jenkinsci/git-plugin,
  captured `PullRequestEvent` opened / PRs created on GitHub): 2024-Q4
  39/42 = 93%; 2025-Q3 23/38 = 61%; 2025-Q4 16/37 = 43%; 2026-06 0/9 = 0%.
  Development-era months were therefore near-completely captured while the
  OOT months run at roughly 43-61% capture: any OOT decline is confounded
  with archive coverage loss and is reported with these ratios beside it.
  The decay's onset (~mid-2025) also coincides with the historically weakest
  development fold (test 2025-05/06); noted as a hypothesis for the praxis
  temporal-stability discussion, not as a finding.
  Event 2 — Dec-2025 JIRA→GitHub issue migration by `jenkins-infra-bot`:
  17,642 issues opened across 155 cohort plugins on 2025-12-01 (plus ~95k
  label events; smaller waves in 2025-11 and 2026-01). The account carries
  no `[bot]` suffix and was absent from the frozen bot list, so `ghdyn_*`
  would count it as a human contributor for those rows in the third OOT
  fold. Correction (§6 data-integrity): `jenkins-infra-bot` added to
  `_BOT_LOGINS`. Proof it cannot alter development-fold numbers: the account
  has zero events in every 2018-01..2025-10 month of the normalized event
  store (exhaustive grep), so all dev-era feature values are bit-identical;
  re-validated by the gate-2b dev-fold regression run before any OOT run.
  Not corrected (disclosed): the `ghclock_days_since_issue_opened` clock is
  not actor-filtered and resets for the 155 migrated plugins; a fold-3
  sensitivity excluding those plugins will be reported as a secondary,
  descriptive number alongside the primary result.
- 2026-09-01 (later) — SWH 2026-06-04 schema smoke-test: PASSED (run early;
  §8 had it ~Sep 5). `s3://softwareheritage/graph/2026-06-04/orc` registered
  as `swh_graph_2026_06_04`; `origin_visit_status` schema identical to the
  2025-10-08 export. git-plugin shows 29 full visits with snapshots covering
  2025-10-29 → 2026-05-30 at roughly WEEKLY cadence (dev-era data averaged
  ~9 visits/plugin/YEAR) — the denser archival cadence weakens the
  measurement-cadence explanation for the swhdelta_ refutation prospectively
  and is noted for future work. Incremental extraction is GO: visit window
  2025-10-01 → 2026-06-01, destination `swh_jenkins_2026` (frozen
  `swh_jenkins` untouched), new local out-dir
  `data/raw/software_heritage_athena_2026/`. Merged data feeds the
  post-OOT/archival record only, per the SWH-decoupling amendment.
- 2026-09-02 — §3 panel rebuild complete and integrity gates PASSED (still
  before any OOT fold runs). Rebuilt on the frozen registry with
  `monthly-features --start 2018-01 --end 2026-06` → `monthly-labels` →
  enrichment (all seven families): 209,406 rows = 102 × 2,053 exactly,
  `.summary.json` completion marker present (`row_count` 209406), 65
  enrichment columns; `EXPECTED_ROWS` in §7 set to 209,406. Labels: the
  6-month target is non-null on 197,088 rows (the trailing six unmatured
  months are unlabeled, as designed) with 5,496 positives vs 5,369 in the
  development-era file — the difference is newly matured 2025-H2 windows,
  not relabeling of any development-era row. Gate 2b (development-fold
  regression, `ghclock_`-only logistic, 13 embargoed folds 2023-05 →
  2025-05) was run twice — once on the interim 96-month panel (run dir
  `ghclock_only_logistic_rebuilt`) and once on the final 102-month panel
  (`ghclock_only_logistic_rebuilt_102m`) — and both reproduce the frozen
  `ghclock_only_logistic` run bit-for-bit: every fold identical in ROC-AUC,
  AP, P@25, base rate, 4,106 test rows, positive counts, training rows and
  as-of statistics; pooled ROC-AUC 0.6274790771018923 in all three. This
  also certifies the `jenkins-infra-bot` §6 correction as a development-era
  no-op, as predicted. Software Heritage 2026-06-04 pull-down continues on
  the decoupled parallel track (~420 of 2,053 plugins at this entry; the
  only failures are plugins whose snapshot carries no repository URL, as in
  the development-era extraction).
