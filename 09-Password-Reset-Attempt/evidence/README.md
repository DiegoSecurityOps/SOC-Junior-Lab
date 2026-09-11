# Case 09 Evidence

## Publication Status

**Pending.** No screenshots or raw event exports are included. The case findings were supplied from the original laboratory investigation; this folder does not independently substantiate them.

## Required Evidence

Capture real Splunk results after following the time zone and alias setup in the [case README](../README.md).

| Suggested filename | Query | Capture requirements |
| --- | --- | --- |
| case09-detection.png | [detection.spl](../spl/detection.spl) | Both 4724 events, time, actor, target, and host |
| case09-timeline.png | [timeline.spl](../spl/timeline.spl) | Chronological related activity with Event IDs and host |
| case09-reset-interval.png | [reset-interval.spl](../spl/reset-interval.spl) | Consecutive reset times, target, host, and calculated interval |

Include the search window and display time zone where practical. Inspect the original 4724 event details to verify the actor/target extraction and audit outcome. Preserve an original private copy of the evidence.

The reported findings are two attempts at 2026-09-10 22:56:02 and 22:56:21, an interval of 19.243 seconds, and the sequence 4720 → 4724 → 4738 → 4722 → 4798 → 4724 → 4738. These are verification targets, not instructions to alter results. If a replay differs, record and investigate the difference.

## Sanitization Requirements

Before publishing:

- Replace the analyst account with `lab_analyst`.
- Replace the target account with `SOC_CASE09`.
- Replace the hostname with `SOC-WS01`.
- Replace SIDs with `<SID_REDACTED>` and logon IDs with `<LOGON_ID_REDACTED>`.
- Redact real domain names, IP addresses, machine paths, and other identifying values where present.
- Remove credentials, tokens, browser profile details, unrelated tabs, and unrelated events.
- Inspect both the query text and results, expanded raw events, tooltips, filenames, and image metadata.

Use opaque, flattened redactions or clearly marked alias replacements. Keep original timestamps, event order, Event IDs, counts, audit outcomes, and measured intervals unchanged. Label published images as sanitized.

Do not create synthetic screenshots, recreate missing result rows, or invent fractional timestamps. Add links to images only after the real sanitized files exist.
