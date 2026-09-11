# Case 09 — Analyst Notes

## Query Provenance

The SPL files were prepared for this documentation update from the user-supplied laboratory findings and the repository's Spanish Windows event extraction conventions. They are replay queries, not claimed verbatim copies of the original searches. They have not been run against the laboratory Splunk instance during this update.

## Original Case Findings

- Event ID: `4724`
- Actor: `lab_analyst`
- Target: `SOC_CASE09`
- Host: `SOC-WS01`
- Displayed reset attempt times: `2026-09-10 22:56:02` and `2026-09-10 22:56:21`
- Reported interval: `19.243 seconds`
- Related sequence: `4720 → 4724 → 4738 → 4722 → 4798 → 4724 → 4738`
- Classification: `True Positive / Benign Activity`
- Severity: `Low`

The benign determination comes from the authorized laboratory context. Exact fractional timestamps, the original display time zone, timestamps and actors for other timeline events, and audit outcomes were not supplied. Do not infer them.

## Search Design

- `detection.spl` extracts actor and target separately, then filters the target. It leaves the actor unrestricted so other actors can be seen.
- `timeline.spl` matches the account name in raw text across five event types on the same host. This deliberately avoids imposing the 4724 target-section layout on other event types. Verify each match's account role and SID manually.
- `reset-interval.spl` uses the same reset scope as detection, sorts all results chronologically with `sort 0`, and calculates consecutive intervals by host and target. It includes previous and current actors to expose actor changes.

The interval calculation uses numeric `_time` before `strftime` formatting. The output rounds the difference to three decimals. The reported 19.243 seconds cannot be recovered from the two second-resolution display values alone. Do not insert fabricated millisecond components to force that result.

Additional events produce additional interval rows. Review duplicate ingestion before interpreting repeated attempts; do not automatically deduplicate events merely because their displayed times match.

## Localization and Replay Limitations

The `rex` expressions depend on `Sujeto`, `Cuenta de destino`, and `Nombre de cuenta` in Spanish rendered `_raw` text. They are sensitive to section wording and layout, and assume account names contain no whitespace. English or XML data needs adapted extraction, such as verified native subject/target fields.

For replay:

1. Privately substitute the real indexed values for sanitized host/account aliases.
2. Verify the original Splunk display time zone and set the historical window accordingly. The saved one-day window is a replay choice, not a claimed original search range.
3. Inspect an original 4724 event and verify both extractions. If results are unexpectedly empty, temporarily remove the target filter and inspect missing fields and the source format.
4. Run detection, timeline, and interval searches. Validate account identity and event ordering against original records; equal timestamps may require a source record identifier to resolve order.
5. Check the audit outcome before describing a reset as successful. Event 4738 proximity alone is insufficient.
6. Capture real evidence, sanitize it, and document any discrepancy from the reported findings.

These are scoped investigation searches, not a deployed production alert. A production rule would need its own schedule, time window, thresholds, and authorization context.

## Evidence and Disposition

No screenshots or raw exports were added. Follow [evidence requirements](../evidence/README.md) before publication.

Maintain **True Positive / Benign Activity — Low** for the reported controlled exercise. Technical detection of a reset attempt is valid even when the activity is benign. Do not claim production containment, confirmed compromise, successful authentication, or a completed evidence review.
