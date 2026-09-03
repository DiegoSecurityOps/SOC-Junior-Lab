# Evidence — Case 05

This folder contains sanitized evidence related to:

**Case 05 — User Added to Local Administrators Group**

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
- Actor: `lab_analyst`
- Account: `SOC_LAB`
- SID: `<USER_SID>`
- Logon ID: `<LOGON_ID>`
- Secret values: `<REDACTED_SECRET>`

## Evidence for This Case

Relevant evidence may include:

- Event ID 4732 showing a member added to a local security-enabled group
- Event ID 4798 used to correlate the SID with the account
- Local Administrators group membership change
- Actor responsible for the modification
- Affected account
- Host and timeline
- Splunk correlation results

## Privacy Notice

All evidence published in this repository must come from a controlled laboratory environment and must be reviewed and sanitized before publication.
