# Trained model artifacts

`data/processed/models/` holds one directory per trained configuration from the
single-split layers (Layer 1 chronological time split, Layer 2 group time split,
and their `_embargo` twins). The rolling-origin runs of the honest layer
(Layers 3 and 4) keep the same per-model artifacts one level down, under
`data/processed/results/rolling_backtest/<run>/fold_<YYYY-MM>/`.

Everything here is generated. The published copies are on Zenodo (see
"Published Dataset & Model Artifacts" in the top-level README).

## Run directory naming

```
<model>_<horizon>_<feature family>_<split>[_no_window][_embargo]
```

| Part | Values |
|---|---|
| `model` | `logistic`, `rf`, `xgb`, `lgb` |
| `horizon` | `6m` (every reported result; 1/3/12-month labels exist in the panel but were not modeled) |
| `feature family` | `advisory_only`, `gharchive_only`, `swh_only`, `advisory_gharchive`, `advisory_swh`, `gharchive_swh`, `full_no_time`, `full_cleaned` |
| `split` | `time` (chronological, test 2025-05/06) or `gt` (group time split: plugin identity severed between train and test) |
| `_no_window` | calendar-position columns (`window_index`, `window_month`, `window_year`) excluded; the reporting configurations |
| `_embargo` | training labels rebuilt as of the forecast date (`--embargo`), the Layer 1/2 configurations retrained under the honest protocol |

Directories named `*_INVALID_*` or `*_PARTIAL_*` are quarantined runs (truncated
input or interrupted training) kept for the audit trail; nothing reads them.

## Files in a run directory

| File | Contents |
|---|---|
| `metrics.json` | AP, ROC-AUC, classification report and confusion matrix at 0.5, ranking metrics and operational scenarios, train/test row and positive counts, feature list, label embargo statistics (embargoed runs), top positive/negative features |
| `feature_columns.json` | ordered feature contract; the imputer and estimator consume columns in this order |
| `model.joblib` | the fitted sklearn `Pipeline` (imputer + estimator) |
| `test_predictions.csv` | every test row with its predicted score, ranked |
| `pr_curve.json` | precision-recall curve points |
| `precision_at_k.json` | row-level precision@k; `tools/dedup_precision.py` recomputes it per distinct plugin |
| `feature_selection.json` | H3 analysis: SHAP ranking of the full model and AP retention of the top-k refits (single-split layers only) |

## Model registry (hyperparameters)

Every configuration in every layer uses the estimators in
`canary/train/registry.py`, unchanged. They were fixed before the pre-registered
out-of-time holdout and were never tuned against any test window; the honest
layer result is the same to the second decimal across three model families on
the same features, so it is a property of the data rather than of these values.

| Registry name | Estimator | Settings |
|---|---|---|
| `logistic` | `StandardScaler` + `LogisticRegression` | `solver=lbfgs`, `max_iter=2000`, `class_weight=balanced` |
| `random_forest` | `RandomForestClassifier` | `n_estimators=500`, `min_samples_leaf=5`, `class_weight=balanced` |
| `xgboost` | `XGBClassifier` | `n_estimators=500`, `max_depth=6`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `scale_pos_weight=18`, `eval_metric=aucpr` |
| `lightgbm` | `LGBMClassifier` | `n_estimators=500`, `max_depth=6`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `class_weight=balanced` |

All four use `random_state=42`. Class imbalance is handled by class weighting
(balanced weights; XGBoost uses a fixed positive-class weight of 18, set for the
4–6% base rate of the early single-split experiments and left unchanged). Tree
models are scale invariant and have no scaler step.

## Preprocessing applied in `train_model()`

- **Excluded columns** (`DEFAULT_EXCLUDE_COLUMNS`): identifiers, the four label
  columns, the future-looking helper columns (`months_until_next_advisory`,
  `future_advisory_count`) and every same-month advisory indicator
  (`had_advisory_this_month`, `advisory_count_this_month`, ...). Calendar-position
  columns are excluded unless `--include-window-features` is passed.
- **Imputation**, by feature family, fitted on the training rows only:
  `advisory_*` / `advisories_*` columns are filled with zero (the advisory feed is
  complete by construction, so a missing value means no history); every other
  column is median imputed. The second-generation enrichment families
  (`ghclock_`, `ghdyn_`, `installs_`, `advhist_`, `ghtext_`, `contagion_`,
  `swhdelta_`) emit no missing values (cap-and-flag encoding), so the imputer
  never touches them.
- **Label embargo** (`--embargo` / `--label-as-of-month`): training labels are
  rebuilt as of the month after the test start, so a row is positive only if its
  advisory was published before the forecast date. Test labels are never modified.
  `metrics.json` records `label_as_of_month` and the number of labels flipped.

## Which runs the praxis reports

| Layer | Run | Where |
|---|---|---|
| 1, stored labels (diagnostic) | `xgb_6m_advisory_swh_no_window_time` (AP 0.583 / ROC 0.930) | this directory |
| 1, embargoed twin | `xgb_6m_advisory_swh_no_window_time_embargo` (AP 0.019 / ROC ≈ 0.5) | this directory |
| 3, development sweep | `ghclock_ghdyn_logistic` (champion, pooled ROC 0.638), `ghclock_installs_xgb` (0.632), `ghclock_only_logistic` (0.627), plus the other declared configurations | `results/rolling_backtest/` |
| 4, pre-registered holdout | `oot_champion` (0.670), `oot_runnerup` (0.628), `oot_ghclock_logistic` (0.638) | `results/rolling_backtest/` |
| Deployed forecast | `oot_champion/fold_2025-11` applied to the newest panel month by `tools/latest_forecast.py` | `results/latest_forecast.json` |

`docs/panel_extension_protocol.md` is the provenance record for Layers 3 and 4;
`tools/README.md` documents the analysis scripts that read these artifacts.
