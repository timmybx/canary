# Software Heritage Athena Data Collection

This folder contains historical repository signals collected from the
[Software Heritage](https://www.softwareheritage.org/) public dataset via AWS Athena,
used as features for vulnerability prediction in Jenkins plugins.

---

## Overview

The Software Heritage (SWH) Graph Dataset is a public archive of source code from
virtually every public Git repository on GitHub, GitLab, and other forges, snapshot
as of **2021-03-23**. Rather than querying the full multi-TB dataset on every
collection run, this pipeline performs a **one-time extraction** of just the Jenkins
plugin subset into a compact set of Athena tables in your own S3 bucket. All
subsequent collector runs query only those small tables, completing in seconds at
negligible cost.

---

## Prerequisites

Before running any of the steps below you will need:

- **AWS account** with Athena and S3 access
- **Google Cloud project** with BigQuery enabled (for the GH Archive steps — separate pipeline)
- **Python 3.11+** with the project dependencies installed (`pip install -r requirements.txt`)
- The following environment variables set (in a `.env` file or your shell):

```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...          # only if using temporary/STS credentials
AWS_REGION=us-east-1
ATHENA_S3_STAGING_DIR=s3://YOUR-BUCKET/athena-results/
ATHENA_DATABASE=swh_jenkins    # the extracted subset database
```

---

## Step 1 — Register the full SWH dataset as Athena tables

The Software Heritage dataset lives at `s3://softwareheritage/graph/2021-03-23/`
and is publicly readable without credentials. You need to register it in your AWS
Glue catalog so Athena can query it.

```bash
python tools/create_swh_athena_tables.py \
  --database-name swh_graph_2021_03_23 \
  --location-prefix s3://softwareheritage/graph/2021-03-23 \
  --output-location s3://YOUR-BUCKET/athena-results/
```

This creates external Athena table definitions pointing at the public SWH S3 bucket.
No data is copied; queries read directly from the public bucket. This step takes
about 2 minutes.

> **Note:** The full dataset tables (`directory_entry`, `snapshot_branch`, `revision`,
> etc.) each scan tens to hundreds of GB per query. Do not run ad-hoc queries against
> them without understanding the cost implications (~$5/TB at standard Athena pricing).
> The extraction steps below are the only time you should query the full tables.

---

## Step 2 — Extract the Jenkins plugin subset

This is the core one-time ETL. It reads the Jenkins plugin registry, constructs
GitHub URLs for all ~2,053 plugins (trying both `jenkinsci/<id>` and
`jenkinsci/<id>-plugin` variants), and extracts only the rows that correspond to
those plugins from the four heavy SWH tables. The results land in a new
`swh_jenkins` database in your own S3 bucket.

```bash
python tools/extract_jenkins_swh_subset.py \
  --database swh_graph_2021_03_23 \
  --plugins-jsonl data/raw/registry/plugins.jsonl \
  --dest-bucket s3://YOUR-BUCKET \
  --output-location s3://YOUR-BUCKET/athena-results/
```

The script runs four sequential Athena CTAS jobs:

| Step | Table created | Source scan | Est. time | Est. cost |
|------|--------------|-------------|-----------|-----------|
| 1 | `jenkins_plugin_urls` | — (VALUES clause) | ~5 s | $0.00 |
| 2 | `jenkins_visits` | ~36 GB | ~30 s | $0.18 |
| 3 | `jenkins_snapshot_branch` | ~52 GB | ~30 s | $0.26 |
| 4 | `jenkins_directory_entry` | ~6.5 TB | 1–3 hours | ~$32 |

> **The directory_entry step** is the expensive one. The script will prompt for
> confirmation before running it. It only needs to be run once. All future
> collector queries scan kilobytes from the extracted tables.

The date window for `jenkins_visits` is **2019-01-01 to 2019-12-31**, chosen because
2019 has the best SWH archival coverage for Jenkins plugins (~878 plugins with at
least one snapshot, vs ~140 for 2020 which had crawling gaps).

### Sanity checks after extraction

Run these in the Athena console with `swh_jenkins` selected as the database:

```sql
SELECT COUNT(*) FROM jenkins_visits;                    -- expect ~2464
SELECT COUNT(DISTINCT origin) FROM jenkins_visits;      -- expect ~878
SELECT COUNT(*) FROM jenkins_snapshot_branch;           -- expect ~7392
SELECT COUNT(*) FROM jenkins_directory_entry;           -- expect ~26437
```

---

## Step 3 — Extract the revision metadata table

This step extracts commit-level metadata (dates, timezone offsets, commit messages)
for all revisions reachable from the Jenkins snapshots. Run this SQL directly in
the Athena console:

```sql
CREATE TABLE swh_jenkins.jenkins_revision_meta
WITH (
    format            = 'ORC',
    write_compression = 'ZSTD',
    external_location = 's3://YOUR-BUCKET/swh_jenkins/revision_meta/'
)
AS
SELECT
    r.id                          AS revision_id,
    r.directory                   AS directory_id,
    r.date                        AS author_date,
    r.committer_date,
    r.date_offset                 AS author_tz_offset_minutes,
    r.committer_offset            AS committer_tz_offset_minutes,
    from_utf8(r.message, '?')     AS commit_message
FROM swh_graph_2021_03_23.revision r
INNER JOIN swh_jenkins.jenkins_snapshot_branch jsb
    ON r.id = jsb.target
WHERE r.directory IS NOT NULL;
```

Expected scan: ~50–100 GB. Expected output: ~7,000 rows, a few MB.

> **Note:** The `author` and `committer` identity fields in the SWH ORC export are
> stored as opaque binary blobs (a custom git-object encoding), not as readable JSON.
> Author name and email are therefore not recoverable from this dataset without a
> custom binary decoder. The revision signals below are derived purely from dates,
> timezone offsets, and commit messages.

Sanity check:

```sql
SELECT COUNT(*) FROM swh_jenkins.jenkins_revision_meta;   -- expect ~7000
SELECT author_date, commit_message
FROM swh_jenkins.jenkins_revision_meta
LIMIT 5;
```

---

## Step 4 — Run the collector

With the four extraction tables in place, run the per-plugin collector:

```bash
# Single plugin (for testing)
python canary/collectors/software_heritage_athena.py \
  --repo-url https://github.com/jenkinsci/credentials-plugin

# All plugins via the canary CLI
canary collect software-heritage-athena --real
```

Output lands in `data/raw/software_heritage_athena/` as two files per plugin:

- `<plugin_id>.swh_athena_visits.jsonl` — one record per archived visit
- `<plugin_id>.swh_athena_index.json` — collection metadata

Each query against the extracted tables scans roughly **700 KB** and completes in
**~10 seconds**, compared to ~522 GB and ~97 seconds against the full SWH dataset.

---

## Extracted Athena tables reference

All tables live in the `swh_jenkins` Glue database.

| Table | Rows | Description |
|-------|------|-------------|
| `jenkins_plugin_urls` | ~3,949 | Canonical GitHub URLs for all Jenkins plugins (both `<id>` and `<id>-plugin` variants) |
| `jenkins_visits` | ~2,464 | One visit per plugin per calendar month, 2019, most recent visit per month |
| `jenkins_snapshot_branch` | ~7,392 | `snapshot_id → revision_id` mappings for all Jenkins snapshots |
| `jenkins_directory_entry` | ~26,437 | Root directory entry names for all Jenkins snapshot directories |
| `jenkins_revision_meta` | ~7,000 | Commit dates, timezone offsets, and messages for all Jenkins revisions |

---

## Features collected

Each output record contains the following fields. All signals reflect the state of
the repository at the time of the SWH archival visit (2019), making them valid
historical features for a vulnerability prediction model without data leakage.

### Record metadata

| Field | Type | Description |
|-------|------|-------------|
| `source` | str | Always `"software_heritage_athena"` |
| `collected_at` | str | ISO 8601 timestamp when the collector ran |
| `repo_url` | str | Canonical GitHub URL of the plugin repository |
| `visit` | int | SWH visit sequence number |
| `visit_date` | str | ISO 8601 date/time of the SWH archival visit |
| `snapshot_id` | str | SWH snapshot SHA1 identifier |

### CI and governance flags

Derived from the root directory listing of the repository at visit time. These are
boolean presence/absence signals — cheap to collect (one Athena query) and directly
interpretable.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `has_readme` | bool | A README signals basic project hygiene. Projects without one tend to be less actively maintained. |
| `has_dot_github` | bool | A `.github/` directory indicates use of GitHub-specific tooling (issue templates, PR templates, Actions). Its presence correlates with community maturity. |
| `has_jenkinsfile` | bool | A Jenkinsfile means the project uses its own CI pipeline, suggesting the maintainer actively runs builds. Projects that don't build their own code are less likely to catch regressions. |
| `has_travis_yml` | bool | Travis CI was the dominant CI platform for open-source Java projects in 2019. Presence indicates automated testing was in place. |
| `has_security_md` | bool | An explicit `SECURITY.md` describes how to report vulnerabilities and is associated with faster patch cycles. Ayala et al. (2025) found that having a security contact point was the most commonly mentioned aspect of a security policy among OSS maintainers who had experienced security incidents. |
| `has_changelog` | bool | A changelog (`CHANGELOG.md`, `CHANGES.md`, etc.) indicates disciplined release tracking. Projects that document changes tend to have more deliberate release processes. |
| `has_contributing_md` | bool | A `CONTRIBUTING.md` lowers the barrier for external contributors, which diversifies the contributor base and reduces bus-factor risk. Xu et al. (2025) identified disruption to contributor diversity as an early marker of project abandonment and elevated security risk. |
| `has_dockerfile` | bool | A Dockerfile indicates the project has thought about reproducible build environments, generally correlated with DevOps maturity. |
| `has_pom_xml` | bool | Standard Maven build file for Jenkins plugins. Its absence may indicate an unusual or non-standard build setup. |
| `has_build_gradle` | bool | Gradle build file. Some plugins use Gradle instead of or alongside Maven. |
| `has_mvn_wrapper` | bool | The `.mvn/` Maven wrapper directory ensures builds use a pinned Maven version, improving reproducibility and reducing supply-chain risk. |
| `has_tests_directory` | bool | Presence of a `src/`, `tests/`, `test/`, or `spec/` directory suggests an automated test suite exists. Projects with tests tend to catch regressions and security issues earlier. |
| `has_github_actions` | bool | A `workflows/` directory inside `.github/` indicates GitHub Actions CI (less common in 2019 but present in some early adopters). |
| `has_dependabot` | bool | A `dependabot.yml` file enables automated dependency update PRs. Alfadel et al. (2023) found in a study of 9.9 million pull requests that maintainers update dependencies 1.6× more frequently when using automated dependency tools, directly reducing the vulnerability exposure window. |
| `has_sonar_config` | bool | SonarQube/SonarCloud configuration (`sonar-project.properties`) indicates static analysis is part of the build process, which can catch security-relevant code patterns. |
| `has_snyk_config` | bool | A `.snyk` policy file indicates the project uses Snyk for dependency vulnerability scanning. |
| `top_level_entry_count` | int | Number of entries in the repository root directory. A rough proxy for project complexity — very large or very small counts may indicate unusual project structure. |

### Revision signals

Derived from commit metadata in `jenkins_revision_meta`. All signals are computed
from commits reachable from the snapshot's branch tips.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `commit_count` | int | Total number of commits visible from the snapshot. A proxy for project maturity and accumulated technical debt. Very low counts may indicate immaturity; very high counts may indicate complexity. |
| `days_since_last_commit` | float \| None | Days between the most recent commit's author date and the SWH visit date. Panter & Eisty (2026) found that packages classified as high-risk by maintenance-aware metrics averaged over 2,000 days since their last commit, and that 62% of packages considered low-risk by version lag alone were reclassified as high-risk when commit staleness was incorporated. One of the strongest known predictors of unpatched vulnerabilities. |
| `author_committer_lag_p50_hours` | float \| None | Median time between when a commit was authored and when it was committed (merged). A larger lag suggests an async review workflow — someone other than the author is merging changes — which is a proxy for code review culture. Cánovas Izquierdo & Mens (2022) identified PR latency as a key indicator of maintainer responsiveness and team health. |
| `author_committer_lag_p90_hours` | float \| None | 90th percentile of author-to-commit lag. The tail of this distribution captures how long the slowest code reviews take, which may indicate a bottleneck in the review process. |
| `timezone_diversity` | int | Number of distinct timezone offsets (in minutes) among commit authors. Higher diversity suggests a geographically distributed contributor base, which generally correlates with healthier open-source community dynamics. Exploratory signal; not directly validated in the vulnerability prediction literature. |
| `weekend_commit_fraction` | float \| None | Fraction of commits authored on a Saturday or Sunday. Claes et al. (2018) analyzed commit timestamps across 86 open-source projects and found that two-thirds of developers follow a standard work schedule and rarely commit on weekends, establishing weekend commits as a marker of volunteer or hobbyist maintenance. Projects with high weekend fractions may respond more slowly to vulnerability disclosures. |
| `security_fix_commit_count` | int | Number of commits whose message contains security-related keywords (CVE, vulnerability, exploit, RCE, XSS, injection, etc.). Goldman et al. (2024) demonstrated that proactively scanning commits and issues for security trigger words can surface vulnerability exposure before official disclosure. A direct historical signal of past security issues. |
| `merge_commit_fraction` | float \| None | Fraction of commits that are merge commits (message starts with "Merge"). A high merge fraction indicates a PR-based workflow rather than direct pushes to main. Thompson (2017) found in a large-scale analysis that code review coverage is directly associated with security outcomes in open-source projects. |
| `conventional_commit_fraction` | float \| None | Fraction of commits following the Conventional Commits specification (`feat:`, `fix:`, `chore:`, etc.). Tian et al. (2023) found that commit message quality has a measurable impact on software defect proneness, providing empirical backing for this discipline signal. |
| `issue_reference_rate` | float \| None | Fraction of commit messages containing a GitHub issue reference (`#NNN`). Tian et al. (2023) specifically identified issue report and pull request links in commit messages as a key dimension of commit message quality associated with lower defect proneness. |
| `empty_message_rate` | float \| None | Fraction of commits with no meaningful commit message. Tian et al. (2023) demonstrated that commit message quality impacts defect proneness; empty messages represent the lowest-quality extreme of this spectrum. |
| `author_committer_mismatch_rate` | float \| None | Fraction of commits where the author timezone offset differs from the committer timezone offset. Used as an imperfect proxy for code review — if someone in a different timezone committed your code, a review step likely occurred. This is an exploratory heuristic not directly validated in the literature; timezone offsets can change without reflecting a real review. |
| `late_night_commit_fraction` | float \| None | Fraction of commits authored between midnight and 4 AM local time (timezone-adjusted using `author_tz_offset_minutes`). Eyolfson et al. (2011) found that commits made between midnight and 4 AM have significantly higher bug rates than commits made during normal working hours, while Claes et al. (2018) established that most professional developers rarely commit during these hours. High values may indicate rushed or fatigued development practices. Complements `weekend_commit_fraction` as a second dimension of the professional vs. hobbyist maintenance signal. |

---

## Data limitations

**Coverage:** Only 878 of the 2,053 Jenkins plugins in the registry have SWH
archival data in 2019. The remaining ~1,175 were either not yet created, not
archived by SWH during that period, or used a different repository URL format.

**Author identity:** The SWH ORC export stores author/committer identity as binary
git-object blobs. Contributor names and email addresses are not recoverable from
the Athena dataset without a custom binary decoder. Signals that would require
author identity (distinct contributor count, email domain diversity, bus factor)
are therefore not available from this pipeline.

**Snapshot depth:** The collector queries only the root directory of each snapshot,
not subdirectory contents. Signals like test file counts, dependency file contents,
or source file counts would require querying deeper into the directory tree.

**Point-in-time:** All signals reflect the repository state at the time of the SWH
visit in 2019. They are valid for use as features predicting vulnerabilities
disclosed after the visit date, but should not be used with vulnerability labels
from before the visit date.

**Sampling:** SWH archives are not exhaustive. The archive may have missed some
commits, branches, or repositories depending on when SWH crawled them. The
`visit_date` field indicates when SWH captured the snapshot.

---

## Cost summary

| Step | One-time or recurring | Approx. cost |
|------|-----------------------|--------------|
| Step 1 — register tables | One-time | $0.00 |
| Step 2 — extract subset | One-time | ~$32 |
| Step 3 — extract revision meta | One-time | ~$0.50 |
| Step 4 — run collector (all 878 plugins) | Recurring | ~$0.01 per full run |

After the one-time extraction, the full collector run against all 878 plugins
costs approximately one cent in Athena scan fees.

---

## References

Alfadel, M., Costa, D. E., & Shihab, E. (2023). Empirical analysis of security
vulnerabilities in Python packages. *Empirical Software Engineering*, *28*(3), 59.
https://doi.org/10.1007/s10664-022-10278-4

Ayala, A., Nolen, S., & Sarma, A. (2025). *A mixed-methods study of open-source
software maintainers on vulnerability management and platform security features*.
Proceedings of the 34th USENIX Security Symposium.
https://www.usenix.org/system/files/usenixsecurity25-ayala.pdf

Cánovas Izquierdo, J. L., & Mens, T. (2022). Pull request latency explained:
an empirical overview. *Empirical Software Engineering*, *27*(6), 131.
https://doi.org/10.1007/s10664-022-10172-1

Claes, M., Mäntylä, M. V., Kuutila, M., & Adams, B. (2018). Do programmers work at night or
during the weekend? *Proceedings of the 40th International Conference on Software
Engineering (ICSE 2018)*, 705–716. https://doi.org/10.1145/3180155.3180193

Thompson, C. (2017). *Large-scale analysis of modern code review practices and
software security in open source software* (Technical Report No. UCB/EECS-2017-217).
University of California, Berkeley.
https://www2.eecs.berkeley.edu/Pubs/TechRpts/2017/EECS-2017-217.pdf

Eyolfson, J., Tan, L., & Lam, P. (2011). Do time of day and developer experience
affect commit bugginess? *Proceedings of the 8th Working Conference on Mining
Software Repositories (MSR 2011)*, 153–162.
https://doi.org/10.1145/1985441.1985464

Goldman, I., & Landsman, I. (2024). *50 shades of vulnerabilities: Uncovering
flaws in open-source vulnerability disclosures*. Aqua Nautilus Research.
https://www.aquasec.com/blog/50-shades-of-vulnerabilities-uncovering-flaws-in-open-source-vulnerability-disclosures/

Panter, S. K., & Eisty, N. U. (2026). *MALTA: Maintenance-aware technical lag
estimation to address software abandonment*. arXiv preprint arXiv:2603.10265.
https://arxiv.org/abs/2603.10265

Tian, Y., Zhang, Y., Stol, K.-J., Jiang, L., & Liu, H. (2023). Commit message
matters: Investigating impact and evolution of commit message quality.
*Proceedings of the 45th International Conference on Software Engineering
(ICSE 2023)*, 806–817. https://doi.org/10.1109/ICSE48619.2023.00076

Xu, Y., He, R., Ye, H., Zhou, M., & Wang, H. (2025). *Predicting abandonment of
open source software projects with an integrated feature framework*. arXiv preprint
arXiv:2507.21678. https://arxiv.org/abs/2507.21678
