# GH Archive Historical Event Collection

This folder contains historical GitHub event data collected from the
[GH Archive](https://www.gharchive.org/) public dataset via Google BigQuery,
used as time-series features for vulnerability prediction in Jenkins plugins.

---

## Overview

GH Archive records every public GitHub event in real time and makes the full
history available as a public BigQuery dataset (`githubarchive.day.*`). This
pipeline queries that dataset for the GitHub repositories corresponding to
Jenkins plugins, collecting event-level data that is then aggregated into
monthly feature vectors.

Because the data is sourced from GH Archive rather than the GitHub API, all
signals are genuinely historical — you can query any past date range and the
numbers reflect what was actually happening at that time. This avoids the
data leakage problem that affects pipelines that use current GitHub API
statistics as features for predicting historical vulnerabilities.

---

## Prerequisites

- **Google Cloud project** with BigQuery enabled and billing configured
- **Python 3.12+** with project dependencies installed (`pip install -r requirements.txt`)
- The `google-cloud-bigquery` package (`pip install google-cloud-bigquery`)
- Application Default Credentials configured:
  ```bash
  gcloud auth application-default login
  ```
- The following environment variable set (optional — uses default project if absent):
  ```
  GOOGLE_CLOUD_PROJECT=your-gcp-project-id
  ```
- Plugin snapshots already collected for the plugins you want to cover, so
  the collector can resolve plugin IDs to GitHub repository names:
  ```bash
  canary collect registry --real
  canary collect enrich --real   # collects plugin snapshots with SCM URLs
  ```

---

## Step 1 — Collect GH Archive event history

The collector queries the BigQuery `githubarchive.day.*` tables for all Jenkins
plugin repositories over a specified date range, writing normalized monthly JSONL
files to `data/raw/gharchive/normalized-events/`.

```bash
canary collect gharchive \
  --start 20190101 \
  --end 20191231 \
  --bucket-days 30 \
  --sample-percent 5.0 \
  --max-bytes-billed 2000000000
```

### Key parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--start` | required | Start date in YYYYMMDD format |
| `--end` | required | End date in YYYYMMDD format |
| `--bucket-days` | 30 | Number of days per BigQuery query window. Smaller windows cost less per query but require more queries. |
| `--sample-percent` | 5.0 | Percentage of GH Archive rows to sample per window. Use 100.0 for complete data; lower values reduce cost for exploration. |
| `--max-bytes-billed` | 2,000,000,000 | Hard cap on BigQuery bytes per query window (safety guard against runaway costs). |
| `--allow-jenkinsci-fallback` | False | If a plugin snapshot does not have an explicit SCM URL, fall back to the `jenkinsci/<plugin_id>-plugin` naming convention. |
| `--overwrite` | False | Overwrite existing monthly JSONL files. Without this flag, new rows are appended, which causes duplicates on reruns. |

### Cost guidance

GH Archive queries are billed at standard BigQuery rates (~$5/TB). Typical costs
for the full Jenkins plugin corpus over one year:

| Sample % | Approx. scan per 30-day window | Approx. annual cost |
|----------|-------------------------------|---------------------|
| 5% | ~1–3 GB | ~$0.10–$0.30 |
| 100% | ~20–60 GB | ~$2–$6 |

For ML feature development, 5% sampling is generally sufficient to capture event
trends while keeping costs minimal. For production or publication-quality datasets,
use 100% sampling.

### Dry run (estimate cost before running)

```bash
canary collect gharchive \
  --start 20190101 \
  --end 20191231 \
  --bucket-days 30 \
  --sample-percent 5.0 \
  --dry-run
```

---

## Step 2 — Build monthly feature bundles

Once raw events are collected, the monthly feature builder aggregates them into
per-plugin, per-month feature vectors suitable for ML model training:

```bash
canary build monthly-features \
  --start 2019-01 \
  --end 2019-12
```

Output lands in `data/processed/features/plugins.monthly.features.jsonl` and
a companion CSV.

---

## Output file layout

```
data/raw/gharchive/
  normalized-events/
    2019-01.gharchive.events.jsonl   # one record per event per plugin per month
    2019-02.gharchive.events.jsonl
    ...
  gharchive_index.json               # collection metadata and run summary
```

Each normalized event record contains the raw event fields needed for downstream
aggregation. The monthly feature builder reads these files and produces the
aggregated feature vectors described below.

---

## Features collected

All features are computed per plugin per calendar month and carry the prefix
`gharchive_`. The feature pipeline automatically computes trailing window
aggregates (3-month and 6-month) and derived ratio features from the raw counts.

---

### Raw monthly counts

These are direct counts of GitHub events observed in the calendar month.
Because GH Archive data is sampled (see `--sample-percent`), these counts should
be treated as proportional indicators rather than exact totals. The
`gharchive_sample_percent` field records what sampling rate was used so counts
can be scaled if needed.

| Field | Predictive rationale |
|-------|----------------------|
| `gharchive_present` | Whether any GH Archive data exists for this plugin-month. Used to distinguish true zeros from missing data. |
| `gharchive_sample_percent` | The sampling rate used during collection. Required to correctly interpret all count fields. |
| `gharchive_events_total` | Total events of all types. A general activity level signal — completely inactive plugins are far more likely to have unpatched vulnerabilities (Panter & Eisty, 2026). |
| `gharchive_push_events` | Number of push events (direct commits to any branch). High push frequency suggests active development; low values over multiple months indicate a stale codebase associated with elevated vulnerability risk (Alexopoulos et al., 2022). |
| `gharchive_pull_request_events` | Number of PR-related events (opened, closed, reopened). PR activity indicates a collaborative review workflow. Thompson (2017) found in a large-scale study that code review coverage is directly associated with reduced security issues in open-source projects. |
| `gharchive_pull_request_closed_events` | PRs that were closed (merged or rejected). Together with opened PRs, this gives a view of PR throughput. |
| `gharchive_pull_request_merged_events` | PRs that were merged. The ratio of merged to opened PRs reflects how much proposed work actually gets accepted. |
| `gharchive_pull_request_review_events` | Review events (approvals, change requests, comments). A direct signal of code review activity — Thompson (2017) found that review intensity, not just the presence of review, is what correlates with security outcomes. |
| `gharchive_issues_events` | Issues opened, closed, or otherwise touched. Active issue tracking suggests maintainers are engaged with user-reported problems, including potential security reports. |
| `gharchive_issues_closed_events` | Issues that were closed. Relative to opened issues, this indicates how quickly problems are being resolved. |
| `gharchive_release_events` | GitHub release publications. Regular releases indicate a disciplined release process. Infrequent releases may mean security fixes sit in code longer before reaching users (Alexopoulos et al., 2022). |
| `gharchive_unique_actors` | Number of distinct GitHub users who interacted with the repo this month (all event types). A broader contributor base reduces single-person dependency risk. |
| `gharchive_days_active` | Number of distinct calendar days with at least one event. Spread-out activity suggests professional maintenance; clustering suggests hobbyist or part-time maintenance (Claes et al., 2018). |
| `gharchive_watch_events` | GitHub star events received this month. A historical proxy for community interest and visibility, capturing star velocity without relying on a current-day API call. |
| `gharchive_fork_events` | Fork events this month. Forks indicate downstream users and potential contributors. |
| `gharchive_branch_create_events` | New branches created. Indicates active parallel development or feature branching. |
| `gharchive_tag_create_events` | New tags created. Tags typically mark releases; consistent tagging indicates a disciplined release process with clear version boundaries. |
| `gharchive_bot_events` | Events attributable to known bot accounts (Dependabot, Renovate, GitHub Actions, etc.). Bot-driven activity indicates automated tooling is in place. Alfadel et al. (2023) found that automated dependency management tools significantly increase the rate of security patch uptake. |
| `gharchive_human_events` | Events from human (non-bot) actors. A repo where only bots are active may be effectively abandoned by human maintainers. |
| `gharchive_unique_human_actors` | Distinct human (non-bot) actors this month. A purer bus-factor signal than `unique_actors` since it excludes automation noise. Xu et al. (2025) identified contributor diversity as a key predictor of OSS project health. |
| `gharchive_owner_push_fraction` | Fraction of push events from the single most active human pusher. High values indicate one person controls the codebase. The XZ Utils supply chain attack (Przymus & Durieux, 2025) highlighted bus-factor concentration as a critical security risk vector in OSS. |
| `gharchive_security_keyword_events` | PR or issue events whose title/body contains security-related keywords (CVE, vulnerability, exploit, RCE, XSS, injection, etc.). Goldman & Landsman (2024) demonstrated that scanning GitHub activity for security trigger words can surface vulnerability exposure before official CVE assignment — making this a direct leading indicator. |
| `gharchive_hotfix_keyword_events` | Events mentioning hotfix, urgent fix, emergency release, etc. Hotfixes are often triggered by critical bugs or security disclosures. |
| `gharchive_dependency_bump_events` | PRs or issues related to dependency updates (Dependabot PRs, "bump" commits, Renovate). Alfadel et al. (2023) found that projects using automated dependency tooling update dependencies 1.6× more frequently, directly reducing their vulnerability exposure window. |
| `gharchive_pr_merge_time_p50_hours` | Median hours from PR creation to merge. Zhang et al. (2022) found in a large-scale study that the same-user factor (whether contributor and integrator are the same person) is one of the strongest predictors of merge latency — short times can indicate either efficiency or lack of review. |
| `gharchive_pr_merge_time_p90_hours` | 90th percentile of PR merge time. The tail captures the slowest PRs; a high p90 may indicate security-sensitive PRs are getting stuck in review. |
| `gharchive_issue_close_time_p50_hours` | Median hours from issue creation to close. Fast issue resolution suggests an engaged maintainer team; slow times may indicate security reports go unacknowledged. |
| `gharchive_issue_close_time_p90_hours` | 90th percentile of issue close time. The tail captures severely delayed responses, which is particularly concerning if those issues contain vulnerability reports. |

---

### Trailing window aggregates

For every raw count field above, the pipeline automatically computes 3-month and
6-month trailing sums. These smooth out month-to-month noise and capture
medium-term trends. The naming pattern is `<field>_trailing_3m` and
`<field>_trailing_6m`.

For example: `gharchive_push_events_trailing_3m` is the sum of push events in the
current month and the two preceding months.

---

### Staleness signals

These capture how long it has been since each activity type was last observed.
`None` means the activity has never been observed in the available history.

| Field | Predictive rationale |
|-------|----------------------|
| `gharchive_months_since_push` | Months since the last push event. One of the strongest staleness signals — Panter & Eisty (2026) found that packages averaging over 2,000 days since their last commit were systematically misclassified as low-risk by version-based metrics alone. |
| `gharchive_months_since_pr` | Months since the last pull request. Absence of PR activity may mean the project has moved to direct pushes (reducing code review) or has been abandoned. |
| `gharchive_months_since_issue` | Months since the last issue event. Long gaps suggest maintainers are not monitoring or responding to bug reports. |
| `gharchive_months_since_release` | Months since the last GitHub release. Even if code is being committed, a project that never cuts releases may not be delivering security fixes to users (Alexopoulos et al., 2022). |
| `gharchive_months_since_any_activity` | Months since any GitHub event of any type. The broadest staleness signal. |
| `gharchive_months_since_release_tag` | Months since the last Git tag was created. Complements `months_since_release` — some projects tag without creating GitHub releases. |
| `gharchive_months_since_security_keyword` | Months since a PR or issue mentioned a security keyword. Long gaps may mean security issues are not being discussed openly. Goldman & Landsman (2024) showed that the presence of security keywords in project activity is a meaningful leading indicator ahead of formal CVE assignment. |

---

### Delta signals

These capture month-over-month changes in activity, useful for detecting sudden
increases or drops in project health.

| Field | Predictive rationale |
|-------|----------------------|
| `gharchive_push_events_trailing_3m_delta_prev_3m` | Change in push volume between the current 3-month window and the previous 3-month window. Xu et al. (2025) found that deviation from historical activity baseline is an early marker of project decline. |
| `gharchive_pull_request_events_trailing_3m_delta_prev_3m` | Change in PR volume. A sudden drop may signal contributor loss or project abandonment. |
| `gharchive_release_events_trailing_3m_delta_prev_3m` | Change in release frequency. Useful for detecting when a regularly-releasing project suddenly stops shipping. |
| `gharchive_security_keyword_events_trailing_3m_delta_prev_3m` | Change in security-keyword event volume. A spike may precede a public vulnerability disclosure. Goldman & Landsman (2024) found that security-relevant activity in GitHub often precedes formal CVE assignment by days or weeks. |
| `gharchive_watch_events_trailing_3m_delta_prev_3m` | Change in star velocity. A sudden spike can indicate the project gained attention, which may increase both scrutiny and adversarial interest. |

---

### Derived ratio features

These normalize raw counts to produce scale-invariant features that are
comparable across plugins with very different activity levels.

| Field | Predictive rationale |
|-------|----------------------|
| `gharchive_prs_per_push_3m` | PRs per push event over 3 months. High values indicate most code changes go through PR review. Thompson (2017) found code review coverage to be directly associated with security outcomes. |
| `gharchive_prs_per_push_6m` | Same as above over a 6-month window for trend stability. |
| `gharchive_merge_rate_3m` | Fraction of opened PRs that were merged over 3 months. Very low merge rates may indicate maintainer disengagement; very high rates may indicate rubber-stamp reviews. |
| `gharchive_merge_rate_6m` | Same over 6 months. |
| `gharchive_pr_close_rate_3m` | Fraction of opened PRs that were closed (merged or rejected) over 3 months. Low close rates indicate a growing backlog of unreviewed contributions. |
| `gharchive_pr_close_rate_6m` | Same over 6 months. |
| `gharchive_pr_review_intensity_3m` | Review events per PR over 3 months. Higher values mean more thorough scrutiny of incoming code. Thompson (2017) found that a diversity of experienced reviewers, not just review quantity, predicts security outcomes. |
| `gharchive_pr_review_intensity_6m` | Same over 6 months. |
| `gharchive_issue_close_rate_3m` | Fraction of opened issues closed over 3 months. Low values suggest maintainers are not keeping up with bug reports. |
| `gharchive_issue_close_rate_6m` | Same over 6 months. |
| `gharchive_actors_per_active_day_3m` | Average distinct actors per active day over 3 months. Measures contributor density on active days. |
| `gharchive_actors_per_active_day_6m` | Same over 6 months. |
| `gharchive_active_month_ratio_3m` | Fraction of the last 3 months with at least one event. A value of 1.0 means the project was active every month. |
| `gharchive_active_month_ratio_6m` | Same over 6 months. |
| `gharchive_releases_per_active_month_6m` | Releases per active month over 6 months. Captures release cadence normalized by actual activity level. |
| `gharchive_events_per_active_month_6m` | Events per active month over 6 months. Measures activity intensity in months when the project is actually being worked on. |
| `gharchive_activity_burstiness_6m` | Ratio of the peak month's activity to the 6-month average. Xu et al. (2025) found that disruption or breakdown of regular, periodic activity patterns is an early marker of project decline. High burstiness indicates erratic, sprint-then-stall development; low burstiness indicates steady professional maintenance. |
| `gharchive_bot_event_ratio_3m` | Fraction of all events over 3 months from bot accounts. A high ratio with low human activity may indicate the project is effectively on autopilot — dependency bumps happening automatically with no human review. |
| `gharchive_security_keyword_rate_3m` | Security keyword events as a fraction of total PR+issue events over 3 months. Normalizes for project size — a small project with proportionally many security-keyword events is more concerning than a large project with the same raw count. Motivated by Goldman & Landsman (2024). |
| `gharchive_stars_trailing_6m` | Total star events received over 6 months. An approximation of historical star velocity, usable as a community interest proxy without relying on a current-day GitHub API call. |
| `gharchive_forks_trailing_6m` | Total fork events over 6 months. Approximates historical fork velocity. |

---

## Data limitations

**Sampling:** Unless `--sample-percent 100` is used, all event counts are sampled
and do not represent exact totals. This is generally acceptable for ML features
since the relative ordering of plugins is preserved, but raw counts should not be
reported as ground truth statistics.

**Repository URL matching:** The collector resolves plugin IDs to GitHub repository
names using plugin snapshot SCM URLs. Plugins without snapshot data or with
non-GitHub SCM URLs will be excluded. The `--allow-jenkinsci-fallback` flag
partially addresses this by guessing the `jenkinsci/<plugin_id>-plugin` pattern,
but some plugins with non-standard repository names will still be missed.

**GH Archive gaps:** GH Archive has occasional gaps in coverage where events were
not recorded. These appear as months with zero events for otherwise active projects.
The `gharchive_present` field distinguishes true zeros from missing data at the
monthly level, but intra-month gaps are not detectable.

**Event type coverage:** GH Archive records public events only. Private repository
events, events from GitHub Enterprise instances, and events that occurred before a
repository was made public are not captured.

**`text_blob` analysis:** Security keyword detection is based on lowercased PR title,
PR body, issue title, and issue body text. Keywords in code comments, commit
messages, or review thread replies are not captured. False positives can occur when
keywords appear in non-security contexts (e.g., "injection molding", "exploit this
feature").

**Bot detection:** The bot actor list (`dependabot`, `renovate-bot`, `github-actions[bot]`,
etc.) is a curated set and may not capture all automation accounts. Custom or
organization-specific bots will be counted as human actors.

**Time-to-merge/close:** PR merge time and issue close time are computed only for
events where both the creation and close timestamps are available in the same
GH Archive window. PRs opened in one query window and closed in another will have
their lag silently dropped. This is more likely to affect long-running PRs (high-lag
values are underrepresented), so the p50 is generally more reliable than the p90.

---

## Cost summary

| Operation | Approx. cost |
|-----------|-------------|
| Full year collection, 5% sample | ~$0.20–$0.50 |
| Full year collection, 100% sample | ~$4–$10 |
| Monthly feature build (CPU only, no BigQuery) | $0.00 |
| Re-running monthly feature build after adding features | $0.00 |

The BigQuery cost is incurred only during raw event collection. All feature
aggregation, ratio computation, and rolling window calculation happens locally
in Python at no cloud cost.

---

## References

Alfadel, M., Costa, D. E., & Shihab, E. (2023). Empirical analysis of security
vulnerabilities in Python packages. *Empirical Software Engineering*, *28*(3), 59.
https://doi.org/10.1007/s10664-022-10278-4

Alexopoulos, P., Iannone, E., Malburg, J., & Zaidman, A. (2022). How long do
vulnerabilities live in the code? A large-scale empirical measurement study on
FOSS vulnerability lifetimes. *Proceedings of the 31st USENIX Security Symposium*,
4187–4204. https://www.usenix.org/system/files/sec22-alexopoulos.pdf

Claes, M., Mäntylä, M. V., Kuutila, M., & Adams, B. (2018). Do programmers work at night or
during the weekend? *Proceedings of the 40th International Conference on Software
Engineering (ICSE 2018)*, 705–716. https://doi.org/10.1145/3180155.3180193

Thompson, C. (2017). *Large-scale analysis of modern code review practices and
software security in open source software* (Technical Report No. UCB/EECS-2017-217). University of
California, Berkeley.
https://www2.eecs.berkeley.edu/Pubs/TechRpts/2017/EECS-2017-217.pdf

Goldman, I., & Landsman, I. (2024). *50 shades of vulnerabilities: Uncovering
flaws in open-source vulnerability disclosures*. Aqua Nautilus Research.
https://www.aquasec.com/blog/50-shades-of-vulnerabilities-uncovering-flaws-in-open-source-vulnerability-disclosures/

Przymus, P., & Durieux, T. (2025). *Wolves in the repository: A software engineering
analysis of the XZ Utils supply chain attack*. Presented at MSR 2025. arXiv preprint arXiv:2504.17473.
https://arxiv.org/pdf/2504.17473

Panter, S. K., & Eisty, N. U. (2026). *MALTA: Maintenance-aware technical lag
estimation to address software abandonment*. arXiv preprint arXiv:2603.10265.
https://arxiv.org/abs/2603.10265

Xu, Y., He, R., Ye, H., Zhou, M., & Wang, H. (2025). *Predicting abandonment of
open source software projects with an integrated feature framework*. arXiv preprint
arXiv:2507.21678. https://arxiv.org/abs/2507.21678

Zhang, X., Yu, Y., Rastogi, A., Zanetti, A., & Hassan, A. E. (2022). Pull request
latency explained: An empirical overview. *Empirical Software Engineering*, *27*(6),
131. https://doi.org/10.1007/s10664-022-10172-1
