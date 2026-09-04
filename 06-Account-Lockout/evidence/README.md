# Evidence — Case 06

This folder contains sanitized evidence related to:

**Case 06 — Account Lockout Investigation**

## Evidence Guidelines

Only sanitized laboratory evidence should be stored in this folder.

Before uploading screenshots, logs, or exported data:

- Remove personal usernames
- Remove real hostnames
- Remove private IP addresses when unnecessary
- Remove SIDs, Logon IDs, and Record Numbers when not required
- Remove credentials, passwords, tokens, and secrets
- Remove personal file paths
- Review the entire screenshot before publication

## Approved Lab Placeholders

- Host: `SOC-WS01`
- Account: `SOC_LAB`
- SID: `<USER_SID>`
- Logon ID: `<LOGON_ID>`
- Secret values: `<REDACTED_SECRET>`

## Evidence for This Case

Relevant evidence may include:

- Event ID `4625` — failed logon attempts
- Event ID `4740` — account lockout
- Event ID `4624` — successful logon check
- Ten failed authentication attempts within the configured lockout window
- Logon Type `2`
- Source IP `127.0.0.1`
- SubStatus `0xC000006A`
- Splunk timeline showing the failed logons followed by the account lockout

## Sanitized Investigation Summary

```text
Host: SOC-WS01
Account: SOC_LAB
Source IP: 127.0.0.1
Logon Type: 2
SubStatus: 0xC000006A

10 x Event ID 4625
        ↓
Event ID 4740 — Account Lockout
        ↓
No Event ID 4624 observed afterward
within the reviewed investigation window.
```

## Privacy Notice

All evidence published in this repository must come from a controlled laboratory environment and must be reviewed and sanitized before publication.
