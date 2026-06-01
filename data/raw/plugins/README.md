# Jenkins Plugin Snapshot and Ecosystem Features

This folder contains per-plugin snapshot data collected from the Jenkins plugin
registry and API, used as plugin-level ecosystem features in the CANARY framework.

---

## Overview

The Jenkins plugin registry and snapshot API provide metadata about each plugin's
current state — its version history, dependency relationships, installation counts,
maintainer information, and declared security warnings. These signals characterize
the plugin's position within the Jenkins ecosystem rather than its repository
activity, making them complementary to the GitHub Archive and Software Heritage
signals.

Unlike the GH Archive and Software Heritage features, snapshot features reflect
the **current state** of the plugin at collection time rather than a historical
point-in-time state. They are included in the static feature bundle for
current-state scoring. For historical modeling experiments, only the subset of
snapshot features that can be meaningfully anchored to an observation date
(such as `days_since_release`) are included in the monthly feature bundle.

---

## File layout

```
data/raw/plugins/
  <plugin_id>.snapshot.json           # per-plugin Jenkins API snapshot
data/raw/healthscore/plugins/
  <plugin_id>.healthscore.json        # per-plugin Jenkins Plugin Health Score
```

Produced by:

```bash
canary collect registry --real
canary collect enrich --real
canary collect healthscore
```

---

## Features

### Plugin snapshot features

These features are derived from the Jenkins plugin registry and snapshot API.
They capture plugin-level ecosystem metadata at collection time.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `snapshot_present` | bool | Whether a valid snapshot record was found for this plugin. Used to distinguish missing data from plugins that genuinely have no snapshot. |
| `snapshot_current_version` | str \| None | The current published version string. Used for version-based comparisons and to detect whether a plugin is actively releasing. |
| `snapshot_previous_version` | str \| None | The previous version string. Supports detection of version cadence and release frequency. |
| `snapshot_required_core` | str \| None | The minimum Jenkins core version required by this plugin. Plugins requiring very old or very new core versions may indicate maintenance status — very old requirements suggest an unmaintained plugin; very new requirements may indicate active development. |
| `snapshot_dependencies_count` | int | Number of declared plugin dependencies. Higher dependency counts increase the transitive attack surface — a plugin with many dependencies is exposed to vulnerabilities in any of those dependencies. Zerouali et al. (2022) found that dependency network position substantially affects vulnerability risk in OSS ecosystems. |
| `snapshot_maintainers_count` | int | Number of declared maintainers. Very low counts (especially one) raise bus-factor concerns. Walden et al. (2014) found that social metrics including contributor counts are informative predictors of vulnerability risk. A single maintainer is both a key-person dependency and a signal that security reviews may be limited. |
| `snapshot_installations_latest` | int \| None | Estimated current installation count. Higher adoption means more downstream exposure when a vulnerability is discovered — though it also tends to attract more security scrutiny. Siavvas et al. (2018) found that popularity alone is not a reliable predictor of vulnerability risk, but installation count provides useful ecosystem context. |
| `snapshot_labels_count` | int | Number of category labels assigned to the plugin. Labels classify plugins by function (e.g., "scm", "pipeline", "security"). A higher label count may indicate a more broadly scoped plugin with a larger attack surface. |
| `snapshot_categories_count` | int | Number of distinct categories the plugin belongs to. Similar to `snapshot_labels_count` but at the category level. |
| `snapshot_security_warning_count` | int | Total number of security warnings declared for this plugin in the registry, including both active and resolved warnings. A non-zero count is a direct signal of known security history within the Jenkins ecosystem. |
| `snapshot_active_security_warning_count` | int | Number of currently active (unresolved) security warnings. An active warning means a known vulnerability has been disclosed but the plugin has not yet released a fix. This is a strong and direct risk signal. |
| `snapshot_first_release` | str \| None | Date of the plugin's first known release. Used as a proxy for project age — older plugins have more history to analyze but may also carry accumulated technical debt. |
| `snapshot_latest_release_timestamp` | float \| None | Unix timestamp of the most recent release. Used to compute release recency, which is one of the most reliable maintenance freshness signals. Panter & Eisty (2026) found that release staleness is among the strongest predictors of unpatched vulnerabilities. |

### Derived snapshot features

These are computed from the raw snapshot fields during feature construction.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `days_since_release` | float \| None | Days since the most recent plugin release, computed from `snapshot_latest_release_timestamp` at the observation date. One of the most interpretable maintenance freshness signals in CANARY — a plugin that has not released in two years is far more likely to contain unpatched vulnerabilities than one that released last month. Alexopoulos et al. (2022) found that maintenance inactivity is one of the most reliable indicators of elevated OSS vulnerability risk. |
| `release_count` | int | Total number of releases in the plugin's version history. A proxy for project maturity and release discipline. |

### Jenkins Plugin Health Score features

The Jenkins Plugin Health Score is an external, structured indicator of plugin
maintenance posture computed by the Jenkins infrastructure team. It provides a
normalized score reflecting whether a plugin meets a set of best-practice criteria
such as having active maintainers, passing CI builds, using current tooling, and
having no unresolved security warnings.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `healthscore_present` | bool | Whether a health score record was found for this plugin. Some plugins, particularly very new or recently deprecated ones, may not have a health score. |
| `healthscore_value` | float \| None | The Jenkins Plugin Health Score, ranging from 0 to 100. Higher values indicate better maintenance posture. This score aggregates multiple best-practice signals into a single interpretable indicator that is directly actionable for security practitioners. It is treated as an external posture signal rather than a raw feature — it summarizes conditions that CANARY also measures individually through its own feature pipeline, but provides a standardized external reference point. |

---

## Data limitations

**Point-in-time validity:** Snapshot features reflect the plugin state at the
time of collection, not at a historical observation date. For the static scoring
bundle this is appropriate; for historical modeling, only features that can be
anchored to a specific date (like `days_since_release` computed from a dated
timestamp) should be used.

**Installation count reliability:** Installation counts in the Jenkins registry
are estimates based on update center telemetry and may undercount plugins used
in air-gapped or offline Jenkins instances. The signal is useful as a relative
ordering but should not be treated as exact.

**Health score availability:** Not all plugins have a health score. New plugins
and deprecated plugins are most likely to be missing this signal. Missing values
are preserved as `None` rather than imputed.

**Maintainer count accuracy:** Declared maintainer counts reflect who is listed
in the plugin metadata, not who is actively reviewing code. A plugin with three
listed maintainers may effectively be maintained by one person if the others are
inactive.

---

## References

Alexopoulos, N., Brack, M., Wagner, J. P., Grube, T., & Mühlhäuser, M. (2022).
How long do vulnerabilities live in the code? A large-scale empirical measurement
study on FOSS vulnerability lifetimes. *Proceedings of the 31st USENIX Security
Symposium*, 4187–4204. https://www.usenix.org/system/files/sec22summer_alexopoulos.pdf

Panter, S. K., & Eisty, N. U. (2026). *MALTA: Maintenance-aware technical lag
estimation to address software abandonment*. arXiv preprint arXiv:2603.10265.
https://arxiv.org/abs/2603.10265

Siavvas, M., Jankovic, M., Kehagias, D., & Tzovaras, D. (2018). Is popularity an
indicator of software security? *2018 IEEE International Conference on Intelligent
Systems (IS)*. https://doi.org/10.1109/IS.2018.8710484

Walden, J., Stuckman, J., & Scandariato, R. (2014). Predicting vulnerable components:
Software metrics vs. text mining. *2014 IEEE International Symposium on Software
Reliability Engineering (ISSRE)*, 22–33.
https://doi.org/10.1109/ISSRE.2014.32

Zerouali, A., Mens, T., Decan, A., & Roover, C. (2022). On the impact of security
vulnerabilities in the npm and RubyGems dependency networks. *Empirical Software
Engineering*, *27*(6), 132.
https://doi.org/10.1007/s10664-022-10154-1
