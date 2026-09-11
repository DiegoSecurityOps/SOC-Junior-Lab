# Case 08 Evidence

The primary timeline screenshot for this case is still pending.

## Required Evidence

A real Splunk screenshot should be generated using:

[timeline.spl](../spl/timeline.spl)

The screenshot should show the chronological activity related to `SOC_CASE08`, including the relevant Windows Security Event IDs:

- 4720 — Account created
- 4738 — Account modified
- 4722 — Account enabled
- 4798 — Local group membership enumerated
- 4726 — Account deleted

## Sanitization Requirements

Before publishing, sanitize the screenshot as follows:

- Analyst account → `lab_analyst`
- Hostname → `SOC-WS01`
- SID → `<SID_REDACTED>`
- Logon ID → `<LOGON_ID_REDACTED>`
- Remove unrelated personal or browser information

Timestamps and Event IDs should remain unchanged.

No evidence should be fabricated or modified beyond sanitization.

## Suggested Filename

`case08-timeline.png`

An additional screenshot of the main Event ID 4726 detection may also be included as:

`case08-detection.png`
