# PyPI Cross-Validation

This directory contains a self-contained cross-validation study of the CANARY
advisory-history signal in the PyPI ecosystem.  It was produced in response to
advisor feedback requesting validation of the approach in a second package
ecosystem beyond Jenkins.

## Purpose

The main CANARY model is trained and evaluated on the Jenkins plugin registry.
A natural question is whether the predictive signal generalises: does advisory
history predict near-term vulnerability risk in other ecosystems, or is the
finding specific to Jenkins?

These scripts reproduce the advisory-only ablation experiment (the weakest
feature subset from the Jenkins study) on PyPI, using an equivalent
methodology and evaluation design, and compare results side-by-side.

## Methodology

### Package universe

The universe is the top 8,000 PyPI packages by monthly downloads, filtered to
those with a resolvable GitHub URL.  This yields approximately 7,053 packages.

Scoping to packages with a GitHub URL is a **data-availability** criterion,
not a risk criterion — it does not select packages because they are or are not
vulnerable, so it does not distort the label distribution.  Packages lacking a
GitHub URL (~12%) are excluded because the full CANARY feature set (SWH
staleness, GHArchive commit activity) requires a source repository; keeping
them would be inconsistent with the broader data collection pipeline.

This design is deliberately analogous to Jenkins, where all 2,053 plugins are
included regardless of advisory history.  The resulting PyPI base rate
(~1.7%) is nearly identical to the Jenkins base rate (~1.9%), making the
two tasks directly comparable.

> **Why not filter to packages with prior advisories?**
> An earlier iteration scoped the universe to the ~12,900 PyPI packages that
> appear in at least one OSV advisory.  This inflated the base rate to ~7%
> and made the task structurally easier (selection bias on the outcome
> variable).  The current approach corrects for this.

### Features

Three advisory features are used, all computed strictly before the observation
month to prevent temporal leakage:

| Feature | Description |
|---|---|
| `advisory_count_to_date` | Cumulative advisories published before this month |
| `advisory_cve_count_to_date` | Cumulative distinct CVEs before this month |
| `advisory_max_cvss_to_date` | Highest CVSS v3 base score seen to date |

Advisory data is sourced from the OSV bulk PyPI export
(`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`).

### Label

`label_advisory_within_6m` — 1 if any advisory is published in the six months
following the observation month, 0 otherwise.  This matches the Jenkins
prediction horizon.

### Evaluation

Two layers, matching the Jenkins study:

1. **Single chronological split on stored labels** (`03_train.py`): train on
   observations before 2025-05, test on 2025-05 through 2025-10. This is the
   original design and it inherits the label-side leakage documented for the
   Jenkins time split: the last five training months carry labels that
   already encode advisories published inside the test window, and the same
   package appears on both sides of the cut. Its numbers are diagnostic
   (Layer 1 in the praxis's terms).
2. **Embargoed rolling-origin backtest** (`05_rolling_embargo.sh`): the same
   13 folds as the Jenkins development sweep (test starts 2023-05 -> 2025-05,
   step 2, 2-month windows), training labels rebuilt as-of test start + 1
   month at every fold. This is the layer the Jenkins results are reported
   on, and it is the layer on which the two ecosystems are compared.

## Results

### Embargoed rolling-origin backtest (primary)

Container run of 2026-09-16 (PyPI) beside the Jenkins advisory-only runs of
2026-08-28 from `data/processed/results/rolling_backtest/`, identical fold
design and embargo. PyPI pools 183,378 test rows / 2,143 positives (base
rate 1.17%); Jenkins pools 53,378 / 760 (1.42%).

| Configuration | Ecosystem | Training labels | Pooled ROC-AUC | Pooled AP | AP lift | Fold ROC range | Mean P@25 |
|---|---|---|---|---|---|---|---|
| advisory-only XGBoost | PyPI | embargoed | 0.720 | 0.187 | 16.0x | 0.647 - 0.780 | 0.57 |
| advisory-only logistic | PyPI | embargoed | 0.778 | 0.222 | 19.0x | 0.763 - 0.822 | 0.53 |
| advisory-only XGBoost | PyPI | stored (leaky) | 0.773 | 0.288 | 24.6x | 0.750 - 0.832 | 0.71 |
| advisory-only XGBoost | Jenkins | embargoed | 0.553 | 0.025 | 1.7x | 0.515 - 0.623 | 0.08 |
| advisory-only XGBoost | Jenkins | stored (leaky) | 0.602 | 0.037 | 2.6x | 0.521 - 0.684 | 0.11 |

Two things happen at once. The leakage mechanism replicates: on identical
folds, stored labels inflate the PyPI advisory-only result (AP 0.288 -> 0.187
when training labels are rebuilt honestly, P@25 0.71 -> 0.57, ROC-AUC
0.773 -> 0.720), in the same direction and of a similar relative size as in
Jenkins. The verdict does not replicate. Under the embargo, Jenkins advisory
recurrence sits at the H2 criterion (0.553) and its richer `advhist_` form is
below chance (0.435); PyPI advisory recurrence is the strongest honest number
in the project, 0.72 - 0.78 pooled with every fold above 0.64, and about one in
two of each fold's top-25 packages goes on to receive an advisory within six
months against a 1.2% base rate. Same feature family, same honest protocol,
strong forward signal in one ecosystem and none in the other. The plausible
reason is how each ecosystem produces advisories: PyPI advisories accrue
continuously to a small set of heavily used, heavily scrutinised packages, so
past advisories predict future ones; Jenkins advisories arrive in coordinated
batches from security-team audits, and an audited plugin tends to go quiet.

Reading notes. Logistic beats XGBoost on PyPI under the embargo (0.778 vs
0.720); with three features and a heavily skewed count the linear model is
the safer one. In the logistic folds the cumulative CVE count carries the
positive weight and the cumulative advisory count takes a negative,
collinear coefficient; the XGBoost logs' "risk-reducing" SHAP direction
lines are an averaging artifact over the zero-history majority and are not a
finding. A leaky logistic run was not made; the like-for-like leaky/honest
pair is the XGBoost one. No group-time split was run for PyPI, so this is a
monitoring-setting result (same package in train and test), which is the
deployment setting but not the cold-start one. `matured_mismatch` is 0 in
every fold (stored labels reproduce exactly for fully matured windows).

### Single chronological split, stored labels (Layer 1, `03_train.py`)

Results from the July 31, 2026 container run (top-8000 universe, pinned
`requirements.txt` environment), after the advisory zero-fill imputation
correction (see `tools/README.md`). These are stored-label numbers on a
single test window and are subject to the label overlap described above;
the Jenkins column here is the single-window advisory-only ablation, not the
embargoed rolling result. Keep them as the diagnostic layer; do not cite
them as the cross-ecosystem finding.

| Model | Ecosystem | AP | AUC | Row-level P@10 | Row-level P@25 |
|---|---|---|---|---|---|
| XGBoost | Jenkins | 0.0907 | 0.6744 | 0.300 | 0.240 |
| XGBoost | PyPI | 0.2704 | 0.7743 | 1.000 | 0.840 |
| LightGBM | Jenkins | 0.0915 | 0.6717 | 0.300 | 0.240 |
| LightGBM | PyPI | 0.2622 | 0.7643 | 0.700 | 0.840 |
| Random Forest | Jenkins | 0.0649 | 0.6648 | 0.200 | 0.160 |
| Random Forest | PyPI | 0.2173 | 0.6994 | 0.900 | 0.840 |
| Logistic | Jenkins | 0.0247 | 0.4978 | 0.000 | 0.000 |
| Logistic | PyPI | 0.2244 | 0.7749 | 0.100 | 0.120 |

PyPI test set: 709 positives / 42,318 total (base rate 1.68%)
Jenkins test set: 77 positives / 4,106 total (base rate 1.88%)

> **Version-sensitivity note:** top-k metrics for the low-capacity models
> are sensitive to library version and score tie-breaking (an earlier
> dependency refresh alone moved RF AP 0.1597 → 0.2213); the
> gradient-boosted results are stable. Relative to the pre-correction July
> run, the imputation correction moved AP only modestly in both ecosystems
> (e.g., PyPI XGBoost 0.2688 → 0.2704; Jenkins row-level P@k unchanged).
> Cite only container-run numbers.

On this layer both ecosystems score above base rate and PyPI scores higher.
The embargoed comparison above shows how much of each is leakage: most of
the Jenkins number, about a third of the PyPI precision.

### Package-level deduplicated precision (04_dedup_precision.py, Layer 1)

Because observations are package-months, one high-risk package can occupy
several top-k rows. Deduplicating to each package's highest-scored test row
(the operationally meaningful triage view) yields:

| Model | Distinct pkgs in row top-10 | Dedup P@10 | Distinct in top-25 | Dedup P@25 |
|---|---|---|---|---|
| XGBoost | 3 | 0.700 | 6 | 0.680 |
| LightGBM | 2 | 0.700 | 5 | 0.640 |
| Random Forest | 5 | 0.800 | 8 | 0.680 |
| Logistic | 3 | 0.600 | 6 | 0.560 |

The row-level XGBoost P@10 of 1.000 collapses to only three distinct packages;
under deduplication P@10 is 0.700 (~42x the 1.68% base rate). The
deduplicated values are the ones to treat as primary when describing triage
precision, and they are what the praxis reports (Table 4-4, "component level
P@k") — the row-level columns in the table above are not comparable to it.

## Scripts

Run in order from the repository root.

**Preferred: run inside the project container.** The container is built from
the pinned `requirements.txt`, so results are produced under a known,
reproducible set of library versions (top-k metrics are sensitive to library
version and seed, so the host interpreter's environment should not be trusted
for citable numbers):

```
docker compose build canary
docker compose run --rm canary python crossval/pypi/03_train.py
docker compose run --rm canary python crossval/pypi/04_dedup_precision.py
```

Outputs are written to the repository `data/` directory on the host via the
compose volume mount. When re-running after a dependency update, re-run
`03_train.py` and `04_dedup_precision.py` together so the headline metrics and
the deduplicated robustness check come from the same environment.

### `00_collect_universe.py` — Build the package universe (~20 minutes)

Downloads the top-8000 PyPI packages by monthly downloads from
[hugovk.github.io/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/)
and fetches each package's PyPI JSON metadata to extract its GitHub URL.

```
python crossval/pypi/00_collect_universe.py [--top N] [--delay SECS]
```

Progress is saved every 100 packages so the script can be interrupted and
resumed safely.  Output: `data/pypi/raw/package_universe.jsonl`.

### `01_collect_osv.py` — Download PyPI advisories (~1 minute)

Downloads the OSV bulk PyPI advisory export (~25 MB zip, ~20,000 records) and
writes a flat JSONL file with one row per (package, advisory).

```
python crossval/pypi/01_collect_osv.py
```

Output: `data/pypi/raw/advisories.jsonl`.

### `02_build_monthly.py` — Build the labeled dataset (~1 minute)

Joins the package universe against advisory history and generates monthly
observations for every package from 2018-01 to 2025-10, with advisory
features and a 6-month forward label.

```
python crossval/pypi/02_build_monthly.py
```

Output: `data/pypi/processed/monthly_labeled.jsonl` (~663,000 rows).

### `03_train.py` — Train models and print comparison (~2 minutes)

Trains XGBoost, LightGBM, Random Forest, and Logistic Regression on the
monthly labeled dataset using a time split, then prints a side-by-side
comparison against the Jenkins advisory-only ablation results.

```
python crossval/pypi/03_train.py
```

Output: `data/pypi/processed/results/` (per-model JSON metrics files).

### `05_rolling_embargo.sh` — Embargoed rolling-origin check (the honest layer)

`03_train.py` is a single chronological split on stored labels: the same
design as the original Jenkins time split, and it inherits the same
label-side leakage (the last five training months carry labels that already
encode advisories published inside the test window, and the same package
appears on both sides of the cut). Its numbers are Layer 1 numbers in the
praxis's terms. This script re-runs the advisory-only configuration under the
protocol the Jenkins results are actually reported on: 13 embargoed
rolling-origin folds (test starts 2023-05 -> 2025-05, step 2, 2-month test
windows, training labels rebuilt as-of test start + 1 month at every fold),
via the core `tools/rolling_backtest.py`. Three runs: embargoed xgboost,
embargoed logistic, and the same folds on stored labels (`--no-embargo`) for
the leaky-vs-honest side-by-side.

It needs `monthly_labeled.jsonl` rebuilt by the current `02_build_monthly.py`,
which adds two bookkeeping columns (`plugin_id`, an alias of `package_id`
that the core embargo and group-split code keys on, and
`advisory_count_this_month`, which lets the relabeler rebuild each training
label from advisories published before the as-of month). Both are in the
core path's default exclusion list and never enter a model; the feature set
is still exactly the three `advisory_*_to_date` columns.

```
docker compose run --rm canary python crossval/pypi/02_build_monthly.py
docker compose run --rm canary bash crossval/pypi/05_rolling_embargo.sh
```

Outputs: `data/pypi/processed/results/rolling_backtest/<run>/rolling_backtest.json`
plus a per-fold directory each, and a `<run>.log` beside them. The pooled
ROC-AUC over the 13 folds is the number to compare with the Jenkins
advisory-only pooled result under the same protocol; `matured_mismatch` in
each fold's `label_as_of_stats` must be 0 (stored labels reproduce exactly
for fully matured windows), or the relabeling did not line up.

### `04_dedup_precision.py` — Package-level deduplicated P@k (~3 minutes)

Recomputes precision-at-k after deduplicating the test ranking to one row per
package (each package's highest-scored test observation). Because the main
evaluation ranks package-months, a single high-risk package can occupy several
top-k positions; the deduplicated metric reads as "of the k distinct packages
ranked riskiest, what fraction received an advisory in the following six
months," which is the operationally meaningful triage measure. Also reports
the number of distinct packages appearing in each row-level top k. Training
configuration is identical to `03_train.py`.

```
python crossval/pypi/04_dedup_precision.py
```

Output: `data/pypi/processed/results/dedup_precision.json`.

## Dependencies

No additional dependencies are required beyond those already declared in the
project's `pyproject.toml`.  The scripts use `xgboost`, `lightgbm`,
`scikit-learn`, `numpy`, and `pandas`, all of which are installed as part of
the standard CANARY development environment (`pip install -e ".[dev]"`).

The scripts use only the Python standard library for data collection
(`urllib`, `zipfile`, `json`) and require no API keys or credentials.

## Relation to the main CANARY pipeline

The collection and single-split scripts (`00` - `04`) are self-contained and
do not depend on `canary` package internals. The embargoed rolling-origin
check (`05_rolling_embargo.sh`) is the exception by design: it runs the
core `tools/rolling_backtest.py` so that the PyPI numbers come from the
same embargo, fold and scoring code as the Jenkins results.

Data is written under `data/pypi/` to keep it separate from the Jenkins data
under `data/raw/` and `data/processed/`.  If a full multi-ecosystem CANARY
were built in the future, the natural structure would be `data/jenkins/` and
`data/pypi/` with shared pipeline code underneath.

## Limitations

- **Advisory-only features**: These scripts reproduce the advisory-only
  ablation, not the full 154-feature CANARY model.  Adding SWH staleness and
  GHArchive commit-activity features to PyPI would require significant
  additional data infrastructure (SWH Athena queries against the full archive,
  or per-repository API lookups) since PyPI packages lack the common
  `github.com/jenkinsci/` namespace that made Jenkins subsetting tractable.

- **Popularity bias**: The universe is the top-8,000 packages by downloads.
  Findings apply to widely-used PyPI packages and may not generalise to the
  long tail of less-downloaded packages.

- **Time coverage**: OSV advisory data for PyPI is available from roughly
  2018 onward; earlier history is sparse.

- **No cold-start evaluation**: the embargoed check is a monitoring-setting
  result (the same package appears in training and test months). A
  group-time split for PyPI has not been run, so nothing here says how the
  advisory-recurrence signal behaves for a package with no history.
