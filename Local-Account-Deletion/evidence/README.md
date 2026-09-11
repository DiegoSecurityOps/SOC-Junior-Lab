# Case 08 evidence — pending

`case08-timeline.png` has not been added. The available attachments do not contain a suitable Splunk timeline for this case. No screenshot or event result has been fabricated.

## Required screenshot

Run [timeline.spl](../spl/timeline.spl) against the original Case 08 data and save a real, sanitized screenshot as `case08-timeline.png` in this directory.

- Set the search interval to include the original laboratory activity on 2026-09-09, using the timezone configured in Splunk. Replace the query's relative time bounds; the last 24 hours will not retrieve older events.
- Show the search, time interval, and chronological results for `SOC_CASE08`, including Event IDs 4720, 4738, 4722, 4798, and 4726 where present.
- Keep timestamps and event IDs unchanged. Do not add missing events or alter results to match an expected sequence.
- Replace the personal analyst account with `lab_analyst` and the workstation name with `SOC-WS01` throughout the image, including search text and surrounding interface.
- Replace any SID with `<SID_REDACTED>` and any Logon ID with `<LOGON_ID_REDACTED>`. Remove unrelated personal details, addresses, and browser information.
- Apply permanent, opaque redactions and inspect the exported PNG before uploading. Label identifier replacements as sanitization, not original values.

An additional real screenshot of [detection.spl](../spl/detection.spl) may document the deletion actor and target. Query output is not automatically sanitized.
