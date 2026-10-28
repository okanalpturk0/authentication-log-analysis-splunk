# Authentication Log Analysis with Splunk Enterprise

This project investigates authentication activity using Splunk Enterprise and a synthetic dataset of 1,200 authentication events. The analysis focuses on failed login attempts, targeted accounts, authentication outcomes, and suspicious patterns associated with password spraying.

## Investigation Results

- **Total authentication events:** 1,200
- **Successful authentications:** 1,072
- **Failed authentications:** 128

### Suspicious Authentication Activity

The investigation identified the following patterns:

- **Potential password spraying:** Source IP `203.0.113.77` generated 16 failed login attempts targeting 16 different accounts.
- **Repeated login failures:** Charlie had 18 failed attempts from `198.51.100.24`.
- **Repeated login failures:** Dana had 14 failed attempts from `192.0.2.44`.
- **Repeated login failures:** Bob had 8 failed attempts from `192.0.2.88`.

The activity associated with `203.0.113.77` is consistent with potential password spraying because multiple accounts were targeted from a single source. These findings warrant further investigation but do not independently confirm malicious intent or a successful account compromise.

## Detection & Analysis

Splunk Enterprise was used to investigate authentication events through Search Processing Language (SPL) queries.

The analysis focuses on:

- Comparing successful and failed authentication attempts.
- Identifying accounts with repeated login failures.
- Correlating source IP addresses with targeted accounts.
- Investigating authentication patterns consistent with password spraying.
- Documenting findings and supporting evidence.

The detection logic highlights suspicious authentication behavior for further investigation. It represents an analytical detection approach and does not imply that a production alerting system was deployed.

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) | Covers attempts to gain access by guessing or systematically trying credentials. |
| Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Relevant to the observed pattern of failed login attempts against multiple accounts from a single source IP. |

These mappings provide a framework for classifying the investigated authentication patterns using the MITRE ATT&CK knowledge base. The observed activity is consistent with potential password spraying, but the available findings do not establish a confirmed attack or account compromise.

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
