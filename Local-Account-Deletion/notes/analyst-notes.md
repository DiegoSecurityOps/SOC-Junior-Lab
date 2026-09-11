# Case 08 — Analyst Notes

## Query Provenance

The SPL files in the `spl/` directory reproduce the searches used during the original Case 08 investigation.

- `detection.spl` — identifies Event ID 4726 and extracts the actor and target accounts.
- `timeline.spl` — reconstructs the account activity related to `SOC_CASE08`.
- `lifetime.spl` — calculates the elapsed time between the first and last relevant events.

## Important Notes

The searches use Spanish Windows Security event labels, including:

- `Sujeto`
- `Cuenta de destino`
- `Nombre de cuenta`

If the event format changes or English/XML rendering is used, the `rex` expressions may need to be adjusted.

The lifetime calculation represents the observed event span in Splunk and should only be interpreted as the account lifecycle when:

- Event ID 4720 is the first relevant event
- Event ID 4726 is the last relevant event
- all events belong to the same account and host

## Original Case Findings

The controlled laboratory activity showed:

- Account: `SOC_CASE08`
- Observed lifecycle: approximately `39.654 seconds`
- Classification: `True Positive / Benign Activity`
- Severity: `Low`

These results were obtained during the original investigation.

## Publication Status

The SPL files do not contain personal identifiers.

Any screenshots published in GitHub must use sanitized values:

- `lab_analyst`
- `SOC-WS01`
- `<SID_REDACTED>`
- `<LOGON_ID_REDACTED>`

The real Splunk timeline screenshot is still pending.
