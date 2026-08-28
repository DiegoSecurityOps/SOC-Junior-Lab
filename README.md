# SOC Junior Lab

Hands-on SOC Analyst lab focused on Splunk, Windows Security Events, incident triage and detection engineering.

## About this lab

This repository documents practical SOC Analyst Tier 1 investigations performed in a controlled lab environment.

The goal is to develop hands-on skills in:

- Alert triage
- SPL investigation
- Windows Security Event analysis
- Authentication monitoring
- PowerShell analysis
- Process chain investigation
- Detection tuning
- Incident classification
- Technical documentation

## Tools & Technologies

- Splunk Enterprise
- Windows Security Logs
- PowerShell
- Wireshark
- Python
- Git & GitHub

## Completed Investigations

### Case 01 — Multiple Failed Logins Followed by Success
Investigation of repeated Windows authentication failures followed by a successful interactive logon.

### Case 02 — Suspicious PowerShell Execution
Analysis of PowerShell process creation, command-line arguments and suspicious execution indicators.

### Case 03 — Local Account Creation
Investigation of a newly created local account, account changes and subsequent successful logon activity.

### Case 04 — Suspicious Process Chain
Reconstruction and analysis of a process chain:

`explorer.exe → cmd.exe → powershell.exe`

## Investigation Methodology

Each case follows a structured SOC workflow:

1. Alert / event identification
2. Initial triage
3. SPL investigation
4. Evidence collection
5. Timeline reconstruction
6. Context validation
7. Classification
8. Recommended action
9. Analyst conclusion

## Security & Privacy

All evidence included in this repository is sanitized before publication.

Sensitive information such as usernames, hostnames, credentials, tokens, private IP addresses and environment-specific identifiers is removed or replaced with lab-safe placeholders.

Examples:

- `SOC-WS01`
- `lab_user`
- `<USER_SID>`
- `<LOGON_ID>`
- `<REDACTED_SECRET>`

## Current Focus

- Splunk SPL
- Windows Security monitoring
- Incident triage
- Detection engineering fundamentals
- Microsoft Sentinel
- Endpoint Detection & Response
- Threat Intelligence
- CompTIA Security+

## Disclaimer

All activity documented in this repository was performed in a controlled lab environment for educational and defensive security purposes.
