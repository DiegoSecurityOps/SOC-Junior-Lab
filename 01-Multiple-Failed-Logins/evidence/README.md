# Evidence — Case 01

This folder contains sanitized evidence related to the investigation:

**Case 01 — Multiple Failed Logins Followed by Success**

## Evidence Guidelines

Only sanitized laboratory evidence should be stored in this folder.

Before uploading screenshots, logs, or exported data:

- Remove personal usernames
- Remove real hostnames
- Remove private IP addresses when they are not required
- Remove SIDs, Logon IDs, Record Numbers, and environment-specific identifiers when unnecessary
- Remove credentials, passwords, tokens, secrets, and sensitive values
- Remove personal file paths
- Review the entire screenshot before publication

## Approved Lab Placeholders

- Host: `SOC-WS01`
- User: `lab_user`
- SID: `<USER_SID>`
- Logon ID: `<LOGON_ID>`
- Secret values: `<REDACTED_SECRET>`

## Evidence for This Case

Relevant evidence may include:

- Event ID 4625 — Failed logon attempts
- Event ID 4624 — Successful logon
- Multiple authentication failures within a 5-minute window
- Successful interactive logon after repeated failures
- Splunk search results showing account, source IP, host, and timeline

## Privacy Notice

All evidence published in this repository must come from a controlled laboratory environment and must be reviewed and sanitized before publication.
