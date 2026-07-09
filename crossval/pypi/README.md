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

Time split: train on observations before 2025-05, test on 2025-05 onward.
This matches the Jenkins time-split evaluation design.

## Results

Results from the July 2026 container run (top-8000 universe, pinned
`requirements.txt` environment):

| Model | Ecosystem | AP | AUC | P@10 | P@25 |
|---|---|---|---|---|---|
| XGBoost | Jenkins | 0.0896 | 0.6717 | 0.300 | 0.240 |
| XGBoost | PyPI | 0.2688 | 0.7707 | 1.000 | 0.880 |
| LightGBM | Jenkins | 0.0882 | 0.6647 | 0.300 | 0.240 |
| LightGBM | PyPI | 0.2605 | 0.7644 | 0.700 | 0.840 |
| Random Forest | Jenkins | 0.0617 | 0.6830 | 0.200 | 0.160 |
| Random Forest | PyPI | 0.2213 | 0.7046 | 0.600 | 0.800 |
| Logistic | Jenkins | 0.0253 | 0.5034 | 0.000 | 0.000 |
| Logistic | PyPI | 0.2288 | 0.7762 | 0.700 | 0.400 |

PyPI test set: 709 positives / 42,318 total (base rate 1.68%)
Jenkins test set: 77 positives / 4,106 total (base rate 1.88%)

> **Version-sensitivity note:** relative to the initial June 2026 run,
> XGBoost and LightGBM metrics reproduced exactly under refreshed library
> pins, while Random Forest and Logistic Regression shifted noticeably
> (e.g., RF AP 0.1597 → 0.2213). Top-k metrics for the low-capacity models
> are sensitive to library version and score tie-breaking; the
> gradient-boosted results are stable. Cite only container-run numbers.

The directional finding replicates: advisory history predicts near-term
vulnerability risk above base rate in both ecosystems.  PyPI shows stronger
advisory-only signal than Jenkins, likely because PyPI packages receive more
formal CVE disclosures (wider deployment footprint, more external security
scrutiny) and CVSS scores are more consistently populated in the OSV data.

### Package-level deduplicated precision (04_dedup_precision.py)

Because observations are package-months, one high-risk package can occupy
several top-k rows. Deduplicating to each package's highest-scored test row
(the operationally meaningful triage view) yields:

| Model | Distinct pkgs in row top-10 | Dedup P@10 | Distinct in top-25 | Dedup P@25 |
|---|---|---|---|---|
| XGBoost | 2 | 0.700 | 5 | 0.640 |
| LightGBM | 2 | 0.900 | 6 | 0.680 |
| Random Forest | 5 | 0.900 | 9 | 0.720 |
| Logistic | 4 | 0.500 | 7 | 0.480 |

The row-level XGBoost P@10 of 1.000 collapses to only two distinct packages;
under deduplication P@10 is 0.700 (~42x the 1.68% base rate). The
deduplicated values are the ones to treat as primary when describing triage
precision.

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

These scripts are intentionally self-contained and do not depend on any
`canary` package internals.  They are a standalone reproduction study, not
an extension of the production pipeline.

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
