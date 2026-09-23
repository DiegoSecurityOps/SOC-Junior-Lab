# Case 10 — User Account Disabled

## Overview

This investigation focuses on the disabling of a local Windows account detected through **Windows Security Event ID 4725**.

The objective was to identify:

- who performed the action,
- which account was disabled,
- when the activity occurred,
- which host was involved,
- what activity occurred before the account was disabled,
- and whether the event was legitimate or suspicious.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Data Source: Windows Security Events
- Index: `windows_soc`
- Host: `SOC-WS01`
- Test Account: `SOC_CASE10`
- Analyst Account: `lab_analyst`

> All identifiers have been sanitized for public documentation.

---

## Detection Objective

Detect and investigate **Event ID 4725**, which indicates that a user account was disabled.

Account disabling may be legitimate administrative activity, but in a production environment it may also be associated with:

- unauthorized account manipulation,
- administrative misuse,
- compromised privileged credentials,
- identity lifecycle changes,
- or attempts to disrupt access.

The event should therefore be investigated in context.

---

## Initial Search

```spl
index=windows_soc EventCode=4725 earliest=-24h latest=now
```

The initial search did not immediately return the expected event.

A broader search for the laboratory account was then performed to reconstruct the surrounding activity and confirm that Event ID 4725 had been ingested.

---

## Account Activity Search

```spl
index=windows_soc "SOC_CASE10" earliest=-30m latest=now
| table _time EventCode host
| sort _time
```

This search confirmed the presence of Event ID `4725` and provided the surrounding account lifecycle events.

---

## Field Extraction

The Windows Security event contains repeated account field labels.

The actor and target accounts were therefore extracted from their respective sections using `rex`.

```spl
index=windows_soc EventCode=4725 earliest=-30m latest=now
| rex "Sujeto:[\s\S]*?Nombre de cuenta:\s+(?<actor_account>\S+)"
| rex "Cuenta de destino:[\s\S]*?Nombre de cuenta:\s+(?<target_account>\S+)"
| table _time EventCode actor_account target_account host
| sort _time
```

### Sanitized Result

| Time | EventCode | Actor Account | Target Account | Host |
|---|---:|---|---|---|
| 2026-09-23 16:11:09 | 4725 | `lab_analyst` | `SOC_CASE10` | `SOC-WS01` |

---

## Event Interpretation

The Event ID 4725 showed that:

- `lab_analyst` performed the account disabling action.
- `SOC_CASE10` was the affected account.
- The activity occurred on `SOC-WS01`.
- Event ID `4725` confirmed that the account was disabled.

The key distinction during the investigation was:

- **Actor account** = account performing the action.
- **Target account** = account affected by the action.

---

## Timeline Reconstruction

The surrounding events were reviewed to understand the account lifecycle.

Relevant sequence:

```text
4720 → Account created
4724 → Password/configuration activity
4738 → Account modified
4722 → Account enabled
4798 → Local group membership enumerated
4738 → Account modified
4725 → Account disabled
```

Several Event ID `4688` process creation events were also observed around the administrative actions.

---

## Timeline Search

```spl
index=windows_soc "SOC_CASE10" earliest=-30m latest=now
| table _time EventCode host
| sort _time
```

### Relevant Timeline

| Time | EventCode | Description |
|---|---:|---|
| 2026-09-23 16:11:01.834 | 4720 | Account created |
| 2026-09-23 16:11:01.867 | 4724 | Password/configuration activity |
| 2026-09-23 16:11:01.867 | 4738 | Account modified |
| 2026-09-23 16:11:01.867 | 4722 | Account enabled |
| 2026-09-23 16:11:09.362 | 4798 | Local group membership enumerated |
| 2026-09-23 16:11:09.364 | 4738 | Account modified |
| 2026-09-23 16:11:09.364 | 4725 | Account disabled |

---

## Account Lifetime Calculation

The time between account creation and account disabling was calculated using `stats`.

```spl
index=windows_soc "SOC_CASE10" earliest=-30m latest=now
(EventCode=4720 OR EventCode=4725)
| stats min(_time) as first_seen max(_time) as last_seen
| eval duration_seconds=last_seen-first_seen
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen duration_seconds
```

### Result

| First Seen | Last Seen | Duration |
|---|---|---:|
| 2026-09-23 16:11:01 | 2026-09-23 16:11:09 | 7.530 seconds |

---

## Analysis

The account `SOC_CASE10` was created, configured, modified, enabled, enumerated, and subsequently disabled within approximately **7.53 seconds**.

In a production environment, such a short account lifecycle may require further investigation because it could represent:

- legitimate administrative activity,
- temporary account creation,
- operational error,
- testing activity,
- or suspicious identity manipulation.

In this case, the activity was intentionally generated as part of a controlled SOC laboratory exercise.

No evidence of malicious activity was identified.

---

## Classification

- Detection: **True Positive**
- Activity: **Benign Activity**
- Severity: **Low**

---

## Analyst Conclusion

A local account disabling event was identified through Windows Security Event ID 4725.

The account `SOC_CASE10` was created, configured, modified, enabled, enumerated, and subsequently disabled within approximately **7.53 seconds**.

The activity was intentionally generated as part of a controlled SOC laboratory exercise. No evidence of malicious behavior was identified.

The activity was classified as:

**True Positive / Benign Activity**

Severity:

**Low**

---

## Key Takeaways

- Event ID `4725` indicates that a user account was disabled.
- Account disabling should not automatically be considered malicious.
- Broader account searches can help identify events that may not immediately appear in a narrowly filtered search.
- `rex` can distinguish actor and target accounts from repeated Windows Security event fields.
- Timeline reconstruction provides important context around identity lifecycle events.
- `stats min(_time)` and `max(_time)` can be used to calculate the observed account lifecycle.
- Very short-lived accounts may require additional investigation in production environments.

---

## Skills Practiced

- Splunk SPL
- Windows Security Event Analysis
- Event ID 4725 Investigation
- Field Extraction with `rex`
- Timeline Reconstruction
- Account Lifecycle Analysis
- Alert Triage
- Evidence Correlation
- Incident Classification
- SOC Documentation
