# Jenkins Advisory History Features

This folder contains Jenkins security advisory records collected per plugin,
used as both the ground-truth label source and a set of predictive features
for vulnerability risk modeling in the CANARY framework.

---

## Overview

Jenkins publishes security advisories at [jenkins.io/security/advisories](https://www.jenkins.io/security/advisories/)
whenever security issues are identified in Jenkins core or its plugins. These
advisories are the authoritative, ecosystem-native disclosure mechanism for the
Jenkins plugin ecosystem, making them a reliable and reproducible labeling source
for the CANARY prediction task.

Advisory data serves two distinct roles in CANARY:

- **Label source:** Whether a plugin appears in a Jenkins-published advisory within
  the 180-day window following the observation date determines its ground-truth label
  (`had_advisory_this_month` / `advisory_count_this_month`).
- **Predictive features:** Prior advisory history — how many advisories a plugin has
  received, how severe they were, and how recently they occurred — is among the
  strongest predictive signals for near-term advisory risk. The intuition is
  straightforward: plugins that have been vulnerable before tend to carry underlying
  technical debt or maintenance weaknesses that persist over time.

**Critical temporal note:** Features with the `_to_date` suffix are computed using
only advisory records published on or before the observation date. These are the
features used for predictive modeling. Features without `_to_date` (e.g.,
`advisory_count`, `advisory_max_cvss`) reflect the full advisory history at
collection time and are used for current-state scoring and reporting, not for
historical modeling experiments where they would introduce data leakage.

---

## File layout

```
data/raw/advisories/
  <plugin_id>.advisories.real.jsonl    # per-plugin advisory records (real mode)
  <plugin_id>.advisories.sample.jsonl  # per-plugin advisory records (sample mode)
data/processed/events/
  advisories.jsonl                     # deduplicated, normalized advisory event stream
```

Produced by:

```bash
canary collect advisories --real
canary build advisories-events
```

---

## Features

All advisory features carry the prefix `advisory_` and are computed from the
normalized advisory event stream. Features are divided into two groups:
time-bounded features suitable for historical modeling (suffix `_to_date`) and
full-history features suitable for current-state scoring.

### Prior advisory history features (`_to_date` — safe for ML modeling)

These features are computed using only advisory records published strictly before
the observation date, making them safe inputs for a forward-looking prediction model
without introducing data leakage.

| Field | Type | Predictive rationale |
|-------|------|----------------------|
| `advisory_count_to_date` | int | Number of Jenkins security advisories published for this plugin up to and including the observation date. One of the strongest and most consistent predictors of near-term advisory risk across all model configurations. Walden et al. (2014) found that prior vulnerability exposure is among the most informative predictors of future vulnerabilities, and Yang-Smith & Abdellatif (2025) confirmed this finding specifically for Maven CVEs. Plugins with a history of advisories tend to carry persistent underlying weaknesses. |
| `advisory_max_cvss_to_date` | float \| None | Highest CVSS base score observed across all prior advisories. The single strongest individual feature in SHAP analysis across the advisory+SWH model family (avg \|SHAP\| = 1.048). A prior High or Critical severity advisory is a substantially stronger risk signal than a prior Low severity one, reflecting that the severity of past vulnerabilities correlates with the severity of underlying code quality issues. |
| `advisory_mean_cvss_to_date` | float \| None | Mean CVSS base score across all prior advisories. Complements `advisory_max_cvss_to_date` by capturing the average severity profile rather than just the worst case. A plugin with consistently Medium advisories has a different risk profile than one with a mix of Low and Critical. |
| `advisory_days_since_latest_to_date` | float \| None | Days since the most recent prior advisory, relative to the observation date. Recent advisories may indicate ongoing security debt; older advisories may indicate a one-time issue that has since been resolved. Used in combination with `advisory_count_to_date` to distinguish plugins with a growing advisory history from those with a historical one. |
| `advisory_days_since_first_to_date` | float \| None | Days since the earliest known advisory for this plugin, relative to the observation date. A proxy for how long the plugin has had a known security history. Plugins with a long advisory history may have persistent structural issues; plugins with a very recent first advisory may be experiencing a newly identified class of vulnerability. |
| `advisory_span_days_to_date` | float \| None | Days between the first and most recent prior advisory. A longer span indicates recurring vulnerabilities over time rather than a single incident, which is a stronger signal of ongoing security risk than a cluster of advisories in a short period. |
| `advisory_cve_count_to_date` | int | Number of distinct CVE identifiers associated with prior advisories. Some Jenkins advisories cover multiple CVEs; this field captures the total CVE exposure count rather than just the advisory count. Higher values indicate broader or more diverse vulnerability exposure. |

### Full-history features (current-state scoring only — not for ML modeling)

These features use the complete advisory history at collection time and should
not be used as inputs to a historical prediction model. They are included in the
static feature bundle for current-state scoring and reporting.

| Field | Type | Description |
|-------|------|-------------|
| `advisory_count` | int | Total advisory count across all time (not bounded to observation date). |
| `advisory_max_cvss` | float \| None | Highest CVSS score ever observed for this plugin. |
| `advisory_mean_cvss` | float \| None | Mean CVSS score across all advisories. |
| `advisory_days_since_latest` | float \| None | Days since the most recent advisory at collection time. |
| `advisory_days_since_first` | float \| None | Days since the earliest known advisory at collection time. |
| `advisory_span_days` | float \| None | Span in days between first and most recent advisory. |
| `advisory_cve_count` | int | Total distinct CVE count across all advisories. |
| `advisory_latest_published_date` | str \| None | ISO 8601 date of the most recent advisory. |
| `advisory_first_published_date` | str \| None | ISO 8601 date of the earliest advisory. |
| `advisory_active_warning_count` | int | Count of currently active security warnings declared in the plugin snapshot. Distinct from historical advisories — these are warnings actively flagged in the Jenkins plugin registry. |

### Monthly modeling label fields

These fields are generated by `build monthly-labels` and define the prediction
targets used for supervised learning. They are not predictive input features —
they are the outcome variables the model is trained to predict.

| Field | Type | Description |
|-------|------|-------------|
| `had_advisory_this_month` | bool | Whether this plugin appeared in at least one Jenkins-published advisory in the label month. The primary binary classification target for CANARY. |
| `advisory_count_this_month` | int | Number of advisories published for this plugin in the label month. Supports multi-class or count-regression formulations, though CANARY currently treats this as binary. |
| `rows_with_advisory_this_month` | int | Number of plugin-month observation rows in the dataset that had at least one advisory in the label month. Dataset-level diagnostic field used to verify class balance during training. |

---

## Advisory record format

Each raw advisory record in `data/raw/advisories/` contains the following fields:

```json
{
  "source": "jenkins",
  "type": "advisory",
  "advisory_id": "2025-03-15",
  "plugin_id": "credentials-binding",
  "url": "https://www.jenkins.io/security/advisory/2025-03-15/",
  "published_date": "2025-03-15",
  "security_warning_ids": ["SECURITY-3499"],
  "vulnerabilities": [
    {
      "security_warning_id": "SECURITY-3499",
      "severity_label": "medium",
      "cvss": {
        "version": "3.1",
        "base_score": 4.3,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
      }
    }
  ],
  "severity_summary": {
    "max_cvss_base_score": 4.3,
    "max_severity_label": "medium"
  }
}
```

CVSS scores are mapped to qualitative severity labels using FIRST guidance
(FIRST, 2024): None (0.0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9),
Critical (9.0–10.0).

---

## Data limitations

**Advisory completeness:** Jenkins advisories cover issues that are formally
reported and processed through the Jenkins security team. Vulnerabilities that
are fixed silently in a commit without a formal advisory — a known phenomenon
in OSS security — will not appear in this dataset. The label therefore captures
disclosed risk rather than total risk.

**Label lag:** Advisory publication dates reflect when Jenkins formally published
the advisory, which may lag behind when the vulnerability was discovered, fixed,
or first exploited. Some advisories cover issues that were resolved months before
publication.

**CVSS availability:** Not all Jenkins advisories include CVSS scores. Features
dependent on CVSS (`advisory_max_cvss_to_date`, `advisory_mean_cvss_to_date`) will
be `None` for plugins whose advisories predate CVSS adoption in Jenkins advisories
or where scores were not assigned. Missing values are preserved explicitly rather
than imputed as zero.

**Multi-plugin advisories:** A single Jenkins advisory often covers many plugins
simultaneously — for example, a batch advisory addressing a common vulnerability
class across dozens of plugins. In such cases all covered plugins receive the same
advisory date and severity. The CANARY case study results show several plugins
sharing the same advisory ID and lead time for this reason.

---

## References

FIRST. (2024). *Common Vulnerability Scoring System (CVSS) v4.0 Specification*.
Forum of Incident Response and Security Teams.
https://www.first.org/cvss/

Walden, J., Stuckman, J., & Scandariato, R. (2014). Predicting vulnerable components:
Software metrics vs. text mining. *2014 IEEE International Symposium on Software
Reliability Engineering (ISSRE)*, 22–33.
https://doi.org/10.1109/ISSRE.2014.32

Yang-Smith, C., & Abdellatif, A. (2025). Tracing vulnerabilities in Maven: A study
of CVE lifecycles and dependency networks. *2025 IEEE/ACM 22nd International
Conference on Mining Software Repositories (MSR)*, 349–353.
https://doi.org/10.1109/MSR66628.2025.00064
