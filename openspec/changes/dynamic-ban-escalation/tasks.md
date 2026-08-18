## 1. README Ban Escalation Section

- [x] 1.1 Add "Ban Escalation" subsection under the existing "CrowdSec" section in README.md
- [x] 1.2 Write introductory paragraph explaining that CrowdSec Profiles can override ran's default ban duration with dynamic escalation
- [x] 1.3 Add combined YAML example showing both profiles in correct order (permanent threshold first, then exponential escalation)
- [x] 1.4 Add escalation duration table showing hit count → duration mapping for the default formula
- [x] 1.5 Document profile ordering requirement (permanent before escalation, top-to-bottom evaluation)
- [x] 1.6 Add verification command (`cscli decisions list -o json`) with brief explanation

## 2. Fallback and Prerequisites Documentation

- [x] 2.1 Add note explaining that `RAN_CROWDSEC_BAN_DURATION` serves as fallback when no Profile is configured
- [x] 2.2 Add CrowdSec >= 1.4 version prerequisite note for `duration_expr`
- [x] 2.3 Add decision retention note referencing `db_config.flush.max_age`
