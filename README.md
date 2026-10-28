# Authentication Log Analysis with Splunk Enterprise

This project investigates authentication activity using Splunk Enterprise and a synthetic dataset of 1,200 Windows authentication events. The analysis focuses on failed login attempts, targeted accounts, authentication outcomes, and suspicious patterns associated with password spraying. It includes seven documented SPL queries, a threshold-based detection rule, investigation evidence, and a PDF report (case SOC-2026-001).

> **Python follow-up:** the same dataset is analysed with Python in [authentication-log-analysis-python](https://github.com/okanalpturk0/authentication-log-analysis-python), which reproduces these findings with regex filtering and time-window detection rules.

## Dataset

| Property | Value |
|---|---|
| Events | 1,200 |
| Period | 2026-10-19 to 2026-10-24 |
| Splunk index / dataset | `main` / `small_company_auth_lab_v2` |
| Source type | `windows_security` (Event ID 4624 successful logon, 4625 failed logon) |
| Accounts / departments | 30 users across 7 departments |
| Fields | `timestamp`, `username`, `source_ip`, `event_type`, `status`, `hostname`, `event_id`, `message`, `department`, `auth_method`, `mfa_result`, `source_type`, `dataset` |

## Investigation Results

- **Total authentication events:** 1,200
- **Successful authentications:** 1,072
- **Failed authentications:** 128

### Suspicious Authentication Activity

| Finding | Source IP | Account(s) | Failed attempts |
|---|---|---|---|
| Potential password spraying | `203.0.113.77` | 16 different accounts | 16 |
| Repeated login failures | `198.51.100.24` | Charlie | 18 |
| Repeated login failures | `192.0.2.44` | Dana | 14 |
| Repeated login failures | `192.0.2.88` | Bob | 8 |

All 16 failed attempts from `203.0.113.77` targeted 16 different accounts, with no successful logon from that IP. The activity is consistent with potential password spraying because multiple accounts were targeted from a single source. The account-level failures (Charlie, Dana, Bob) are separate observations and should not be attributed to `203.0.113.77`. These findings warrant further investigation but do not independently confirm malicious intent or a successful account compromise.

## Investigation Queries

The queries are documented in `authentication-queries.spl`. Each one includes its purpose, the reasoning behind the logic, what the results show, and an interpretation limitation.

| Query | Purpose |
|---|---|
| 01 | Authentication event overview with the fields needed for investigation |
| 02 | Failed logins by source IP and username, with first and last attempt |
| 03 | Failed logins per source IP with distinct targeted accounts (password spraying indicator) |
| 04 | Chronological events from the suspicious source IP `203.0.113.77` |
| 05 | Failed vs. successful logins for the accounts targeted from `203.0.113.77` |
| 06 | Successful logins within one hour of an immediately preceding failure for the same account |
| 07 | Authentication summary for `203.0.113.77` (total, failed, successful, targeted accounts) |

## Detection Rule

`detection-rule.spl` contains a threshold-based rule for potential password spraying (MITRE T1110.003):

| Setting | Value |
|---|---|
| Logic | Distinct usernames with failed logins per source IP and 10-minute window |
| Threshold | 10 or more distinct accounts |
| Severity | Medium |

The 16 accounts targeted from `203.0.113.77` within about two minutes exceed this threshold. The rule is documented for testing and tuning; no scheduled alert was configured or deployed, and a match indicates suspicious activity, not confirmed compromise.

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Covers attempts to gain access by guessing or systematically trying credentials. |
| Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Relevant to the observed pattern of failed login attempts against multiple accounts from a single source IP. |

These mappings provide a framework for classifying the investigated authentication patterns using the MITRE ATT&CK knowledge base. The observed activity is consistent with potential password spraying, but the available findings do not establish a confirmed attack or account compromise.

## Repository Contents

The `Splunk-Authentication-Investigation` folder contains:

| File | Description |
|---|---|
| `small_company_authentication_events.csv` | Synthetic dataset (1,200 events) |
| `authentication-queries.spl` | Seven documented investigation queries |
| `detection-rule.spl` | Password spraying detection rule |
| `report.pdf` | SOC investigation report with figures, findings, risk assessment, and recommended actions |
| Screenshots | Splunk search results used as investigation evidence |

## Related Project: Python Follow-up

[authentication-log-analysis-python](https://github.com/okanalpturk0/authentication-log-analysis-python) continues this investigation the way an analyst would script a repeatable triage step after the SIEM search. It reads the same CSV and reproduces the results above, then extends them:

| Splunk | Python equivalent |
|---|---|
| Query 01 (event overview) | Dataset summary in the generated report |
| Query 02 (failed logins by IP and username) | `brute_force` rule |
| Query 03 and `detection-rule.spl` (distinct accounts per IP) | `password_spraying` rule with a sliding time window |
| Queries 04 and 07 (events and summary for one IP) | Follow-up check: any successful logon from the same IP afterwards |
| Queries 05 and 06 (failure followed by success) | `success_after_failures` rule |

What the Python version adds:

- **A rule that covers all accounts.** Query 06 is scoped to the accounts targeted from `203.0.113.77`, so it does not cover Charlie, whose failures came from `198.51.100.24`. The Python rule runs across every account and flags a successful logon by Charlie 14 seconds after the 18 failed attempts, with no MFA required, which makes Charlie the strongest lead for follow-up.
- **Sliding time windows** instead of fixed 10-minute buckets, so a burst cannot be split across a bucket boundary.
- **Off-hours context:** the password spraying and Bob's failed attempts occurred outside business hours.
- **Automated tests** that check the results against the Splunk numbers, plus an incident report and a findings CSV.

The Python rules use lower thresholds (5 accounts in 10 minutes) than the Splunk rule (10 accounts), chosen for this dataset. Both thresholds would need tuning against normal behavior in a real environment.

## Tools & Technologies

- **Splunk Enterprise** — SIEM-based log analysis and investigation.
- **SPL (Search Processing Language)** — searching, filtering, and analyzing authentication events.
- **Authentication Log Analysis** — reviewing successful and failed login activity.
- **Threat Detection** — investigating repeated failures and suspicious account-targeting patterns.
- **MITRE ATT&CK** — mapping relevant behavior to recognized adversary techniques.
- **Security Investigation & Reporting** — documenting findings and supporting evidence.

## Disclaimer

This project uses synthetic authentication data for educational purposes and cybersecurity portfolio demonstration. The IP addresses belong to documentation ranges and do not represent verified malicious infrastructure.

The findings describe patterns identified within the analyzed dataset and should not be interpreted as evidence of a real-world security incident or confirmed account compromise.
