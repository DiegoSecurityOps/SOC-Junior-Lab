# Case 09 — Password Reset Attempt

## Overview

This investigation reviews Windows account password reset attempts detected through **Windows Security Event ID 4724**. It identifies the actor, target account, host, timing, and surrounding account activity to distinguish authorized administration from suspicious behavior.

The reported laboratory findings show two reset attempts involving `SOC_CASE09` on `SOC-WS01`, attributed to `lab_analyst`. The activity was part of a controlled lab exercise.

**Classification:** True Positive / Benign Activity
**Severity:** Low
**Evidence status:** Pending sanitized screenshots; the findings below are reported laboratory observations, not a new execution of the searches.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Data Source: Windows Security Events
- Index: `windows_soc`
- Host: `SOC-WS01`
- Test Account: `SOC_CASE09`
- Analyst Account: `lab_analyst`

> All account and host identifiers shown here are sanitized for public documentation.

---

## Detection Objective

Detect Event ID **4724**, which records an attempt to reset an account password. Investigate who initiated the attempt, which account was affected, and whether the surrounding activity matches authorized administration.

A reset attempt may be legitimate, but unexpected resets can indicate account manipulation or misuse of administrative credentials. Event ID 4724 alone does not establish malicious intent or a successful password reset; the audit outcome and surrounding evidence must be reviewed.

---

## Search Setup

The queries use an explicit historical window: September 10, 2026, from 00:00:00 inclusive to September 11, 2026, at 00:00:00 exclusive. This covers the reported reset times without depending on when the searches are rerun.

Splunk interprets these absolute times in the search user's configured time zone. The original display time zone was not supplied; verify it before replaying the searches. Expand the window if related activity falls outside it.

The public host and account values are sanitized aliases. For a private replay, replace them with the corresponding values in the actual lab data. Do not publish those originals.

## Initial Search and Field Extraction

[detection.spl](spl/detection.spl) isolates reset attempts for the target account and extracts the actor and target from separate Spanish event sections:

```spl
index=windows_soc host="SOC-WS01" EventCode=4724 earliest="09/10/2026:00:00:00" latest="09/11/2026:00:00:00"
| rex field=_raw "Sujeto:[\s\S]*?Nombre de cuenta:\s+(?<actor_account>\S+)"
| rex field=_raw "Cuenta de destino:[\s\S]*?Nombre de cuenta:\s+(?<target_account>\S+)"
| search target_account="SOC_CASE09"
| sort 0 _time
| table _time EventCode actor_account target_account host
```

The actor is deliberately not used as a search filter, so attempts by other actors remain visible.

### Reported Laboratory Findings

| Displayed time | Event ID | Actor | Target | Host |
| --- | --- | --- | --- | --- |
| 2026-09-10 22:56:02 | 4724 | lab_analyst | SOC_CASE09 | SOC-WS01 |
| 2026-09-10 22:56:21 | 4724 | lab_analyst | SOC_CASE09 | SOC-WS01 |

The reported interval was **19.243 seconds**. The displayed timestamps above have second-level precision and cannot independently reproduce the fractional interval. The original fractional timestamps were not supplied and are not reconstructed here.

---

## Related Account Timeline

[timeline.spl](spl/timeline.spl) searches the same host and time window for mentions of the account across the relevant event types, sorted chronologically.

The reported sequence was:

| Order | Event ID | Meaning |
| --- | --- | --- |
| 1 | 4720 | A user account was created |
| 2 | 4724 | An attempt was made to reset an account password |
| 3 | 4738 | A user account was changed |
| 4 | 4722 | A user account was enabled |
| 5 | 4798 | A user's local group membership was enumerated |
| 6 | 4724 | An attempt was made to reset an account password |
| 7 | 4738 | A user account was changed |

Exact timestamps for the other events were not supplied. This table preserves the reported order without assigning invented times or actors.

The timeline matches the account name in raw event text. It is a contextual search, not proof that the account occupies the target field in every event. Inspect each event's account role and, where available, SID before treating it as confirmed correlation. Event 4798 indicates enumeration, not a change to group membership.

## Reset Interval

[reset-interval.spl](spl/reset-interval.spl) computes the interval between consecutive 4724 events for the same host and target account. It sorts numeric `_time` values, uses `streamstats` to retain the preceding reset time, and subtracts before formatting the timestamps.

- Reported interval between the two attempts: **19.243 seconds**.
- The calculation measures spacing between reset attempts, not account lifetime or reset completion time.
- If additional attempts exist in the window, the query returns each consecutive pair rather than assuming there are exactly two.
- Millisecond precision requires the original indexed timestamps to retain that precision.

---

## Analysis and Classification

The detection correctly identified password reset attempts, making this a **True Positive**. The supplied context identifies them as controlled laboratory activity, supporting **Benign Activity** and **Low** severity.

The surrounding creation, modification, enablement, and enumeration events provide context for the exercise. Their proximity does not by itself prove authorization, reset success, privilege escalation, or account compromise. No audit outcome or subsequent authentication result is asserted here.

## Recommended Action

- For this lab, document the authorized exercise and retain the classification **True Positive / Benign Activity — Low**.
- Capture and sanitize the pending evidence using [the evidence instructions](evidence/README.md).
- In a production investigation, validate the actor's authorization and the expected change with the account owner or administrator.
- Review the audit outcome, account identifiers, and relevant authentication activity before concluding that a reset succeeded or that the account was used.
- Escalate unexpected or unauthorized activity according to the incident response process.

## Limitations

The extraction depends on Spanish rendered Windows labels: `Sujeto`, `Cuenta de destino`, and `Nombre de cuenta`. English events, XML events, alternative translations, or changed layouts require different extraction logic.

The expressions take the first matching account name after each section label. Verify them against the original event layout. Missing or changed target labels can exclude events from the filtered results; an empty result does not prove that no resets occurred. See [analyst notes](notes/analyst-notes.md) for replay and validation details.

These searches were prepared from the supplied findings and have not been executed against Splunk during this documentation update. Screenshots and raw event exports are pending.

## Lessons Learned

- Separate the initiating actor from the affected account when field labels repeat.
- Correlate reset attempts with surrounding account management activity.
- Calculate intervals from numeric event times before formatting them.
- Distinguish detection validity from maliciousness and from audit success.
- Preserve the boundary between reported findings and independently verified evidence.

## Analyst Conclusion

Two reported Event ID 4724 attempts involved `lab_analyst` and `SOC_CASE09` on `SOC-WS01` at **2026-09-10 22:56:02** and **22:56:21**, with a reported interval of **19.243 seconds**. The provided lab context supports **True Positive / Benign Activity**, with **Low** severity. Evidence publication remains pending.

## Case Files

- [Detection query](spl/detection.spl)
- [Related timeline query](spl/timeline.spl)
- [Reset interval query](spl/reset-interval.spl)
- [Evidence requirements](evidence/README.md)
- [Analyst notes](notes/analyst-notes.md)

## References

- [Microsoft: Event 4724](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724)
- [Microsoft: Audit User Account Management](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management)
- [Splunk: streamstats](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.1/search-commands/streamstats)
