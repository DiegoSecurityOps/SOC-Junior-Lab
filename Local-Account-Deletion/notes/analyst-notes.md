# Case 08 — analyst notes

## Query provenance

The three files in [spl](../spl) reproduce the SPL defined in the original Case 08 discussion. The existing case README is preserved unchanged.

- [detection.spl](../spl/detection.spl): Event ID 4726, with actor and target extraction from Spanish Windows Security event text. It intentionally searches all deletion events in the interval; identify `SOC_CASE08` in the results.
- [timeline.spl](../spl/timeline.spl): events containing `SOC_CASE08`, restricted to 4720/4722/4738/4798/4726, ordered by time.
- [lifetime.spl](../spl/lifetime.spl): elapsed seconds between `min(_time)` and `max(_time)` for those matching events.

## Reproduction and limitations

Replace `earliest=-24h latest=now` with bounds covering the original 2026-09-09 exercise when investigating historical data. Confirm the Splunk timezone before comparing displayed timestamps.

The extraction patterns depend on Spanish rendered event labels (`Sujeto`, `Cuenta de destino`, and `Nombre de cuenta`). Check the actual event format if fields are empty; English or XML events require different extraction.

The lifetime search measures the observed event span, not necessarily the full account lifetime. Verify that the first event is creation (4720) and the last is deletion (4726), and that all events belong to one account instance on one host. The original query does not group by host or SID; repeated account names or multiple hosts can combine unrelated activity. `sort _time` also uses Splunk's default result limit, so check completeness for larger datasets.

The original discussion reported 39.654 seconds and classified the controlled exercise as True Positive / Benign Activity, Low severity. Those findings have not been independently revalidated against Splunk in this update. No synthetic result rows are included.

## Publication status

The SPL files contain no personal account name, actual workstation identifier, SID, or Logon ID. They do not sanitize live query results. Public evidence must use `lab_analyst`, `SOC-WS01`, `<SID_REDACTED>`, and `<LOGON_ID_REDACTED>` as appropriate.

The real timeline screenshot remains pending; see [evidence requirements](../evidence/README.md). The existing README ends at the initial search and is retained as requested; these supporting files supply the complete queries without replacing it.
