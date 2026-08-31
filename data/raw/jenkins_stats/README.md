# Jenkins Install Statistics Collection

## Overview

Monthly plugin installation statistics from the Jenkins project's public
statistics site, [stats.jenkins.io](https://stats.jenkins.io/). Each plugin
has a static JSON at
`https://stats.jenkins.io/plugin-installation-trend/<plugin-id>.stats.json`
containing monthly installation counts and install-share percentages derived
from anonymous usage pings, with history back to December 2008.

Unlike the plugin Health Score (`data/raw/healthscore/` — a current-only
snapshot that cannot enter a historical model), this source is TRUE monthly
history: every panel month has an as-of value that was actually published
near that time and is never restated afterwards. That makes it the one
Jenkins-ecosystem source that can join the monthly panel without any
leakage machinery. It is also the study's only **demand-side** signal —
every other source measures the supply side (maintainer activity,
advisories, repository state); this measures who is running the plugin.

Measurement caveat: counts come from instances that report anonymous usage
data, so they are a lower bound on the true installed base and are best
used as scale/trend/rank signals rather than absolute magnitudes. The
`installationsPercentage` field normalizes by the reporting population.

Ecosystem portability: the *source* is Jenkins-specific, but the *feature
family* transfers — PyPI (BigQuery public download data), npm (downloads
API), and crates.io all publish the analogous adoption series; semantics
shift from "installed base" to "downloads" and belong in the limitations
discussion.

## Collection

```bash
docker compose run --rm canary canary collect installstats
```

One small GET per registry plugin (~2,000 requests against a static file
host), throttled by `--sleep` (default 0.2s). The run is resumable —
existing files are skipped unless `--overwrite` (use `--overwrite` for a
monthly refresh) — and `--max-plugins N` supports smoke tests. Plugins the
stats site does not know (404) are recorded under `missing` in
`_collection_summary.json`, not treated as errors.

## Output file layout

```
data/raw/jenkins_stats/
  <plugin-id>.stats.json        raw installation-trend payload, verbatim
  _collection_summary.json      written/skipped/missing/errors for the run
```

Payload shape (keys are epoch milliseconds, UTC, first of the month):

```json
{
  "name": "git",
  "installations":           {"1228089600000": 46, "...": 196667},
  "installationsPercentage": {"1228089600000": 3.57, "...": 96.05}
}
```

## Features collected

### Install-base scale, trend, and rank (`installs_` — enrichment layer)

Added to the labeled monthly dataset by `tools/enrich_monthly_features.py`
(family `installs`). **Publication-lag aware:** month M's figures publish
shortly after M ends, so at scoring time (the first of T+1) month T's value
is typically not yet available — features for observation month T therefore
use the series only through T−1. No missing values are emitted: plugins
absent from the stats site get zeros plus `installs_has_data = false`.

| Field | Predictive rationale |
|-------|----------------------|
| `installs_count` | Reported installations at the most recent available stats month. The demand-side exposure measure: install base draws both attackers and security researchers (the H1 attention channel). Butler et al. (2025) found a moderate positive correlation between package popularity and security scrutiny in software ecosystems; Zimmermann et al. (2019) showed that in npm, a small number of highly popular packages were disproportionate targets for malicious maintainer account takeovers. |
| `installs_log10_count` | log10(installations + 1) — the same scale on compressed dynamic range for linear models. |
| `installs_pct` | Share of reporting Jenkins instances with the plugin installed — the count normalized by the reporting population. Scale-invariant complement to `installs_count`; both measure the popularity-driven exposure surface documented by Butler et al. (2025). |
| `installs_rank_pct` | Percentile of the plugin's count among all plugins with stats that month (0–1). Growth-invariant popularity: ranks stay comparable across years as the ecosystem itself grows and shrinks. Provides ecosystem-relative standing complementary to absolute count; Zimmermann et al. (2019) found that relative ecosystem position is relevant to attacker targeting strategies. |
| `installs_growth_3m` | Relative change vs. three months earlier (clamped to [−1, +10]; 0 when unknown). Short-horizon adoption momentum. |
| `installs_growth_12m` | Relative change vs. twelve months earlier (same clamp). A shrinking install base is an abandonment-adjacent signal the activity clocks cannot see. Avelino et al. (2019) found that sustained decline in external usage is a leading indicator of open-source project abandonment; Panter & Eisty (2026) demonstrated that maintenance-aware abandonment metrics substantially improve on version-lag-alone measures of vulnerability risk. |
| `installs_peak_ratio` | Current count / historical peak (0–1]. Low values on a still-large base mark the legacy-decay archetype: widely deployed, fading attention. This decay pattern aligns with the abandonment trajectory described by Avelino et al. (2019) and the "stale but large installed base" risk profile highlighted by Panter & Eisty (2026). |
| `installs_rank_delta_12m` | Change in percentile rank vs. twelve months earlier — the ecosystem moving toward or away from the plugin, independent of raw scale. |
| `installs_months_of_data` | Monthly observations available as of scoring time. |
| `installs_has_data` | Whether stats.jenkins.io has any history for the plugin as of scoring time; companion flag for the zero-filled values. |

## References

Avelino, G., Constantinou, E., Mens, T., & Serebrenik, A. (2019). On the abandonment and
survival of open source projects: An empirical investigation. *Proceedings of the 13th
ACM/IEEE International Symposium on Empirical Software Engineering and Measurement
(ESEM 2019)*, 1–11. https://doi.org/10.1109/ESEM.2019.8870181

Butler, A., O'Keeffe, D., & Dash, S. K. (2025). Links between package popularity,
criticality, and security in software ecosystems. *Proceedings of the 32nd IEEE
International Conference on Software Analysis, Evolution and Reengineering
(SANER 2025 — Companion)*. https://doi.org/10.1109/saner-c66551.2025.00020

Panter, S. K., & Eisty, N. U. (2026). *MALTA: Maintenance-aware technical lag
estimation to address software abandonment*. arXiv preprint arXiv:2603.10265.
https://arxiv.org/abs/2603.10265

Zimmermann, M., Staicu, C.-A., Tenny, C., & Pradel, M. (2019). Small world with high
risks: A study of security threats in the npm ecosystem. *Proceedings of the 28th
USENIX Security Symposium*, 995–1010.
https://www.usenix.org/system/files/sec19-zimmermann.pdf
