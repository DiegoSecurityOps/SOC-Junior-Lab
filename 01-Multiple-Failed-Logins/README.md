# Case 01 — Multiple Failed Logins Followed by Success

## Scenario

Multiple failed Windows logon attempts were observed for the same account, followed by a successful interactive logon.

The objective was to determine whether the activity represented brute force behavior, legitimate user activity, or another authentication anomaly.

## Objective

Investigate repeated failed authentication attempts and correlate them with a subsequent successful logon.

## Data Source

- Splunk Enterprise
- Windows Security Event Log
- Event ID 4625 — Failed logon
- Event ID 4624 — Successful logon

## Investigation

The investigation focused on:

- Account involved
- Source IP
- Host
- Logon type
- Failure frequency
- Timeline
- Successful authentication after repeated failures

## SPL — Failed Logons

```spl
index=windows_soc EventCode=4625
| rex "Cuenta con error de inicio de sesión:[\s\S]*?Nombre de cuenta:\s+(?<account>\S+)"
| rex "Dirección de red de origen:\s+(?<src_ip>\S+)"
| table _time host account src_ip
| sort _time
```

## SPL — Multiple Failures in 5 Minutes

```spl
index=windows_soc EventCode=4625
| rex "Cuenta con error de inicio de sesión:[\s\S]*?Nombre de cuenta:\s+(?<account>\S+)"
| rex "Dirección de red de origen:\s+(?<src_ip>\S+)"
| bin _time span=5m
| stats count by _time account src_ip
| where count>=5
```

## Evidence

Sanitized laboratory evidence:

```text
Host: SOC-WS01
Account: lab_user
Source IP: 127.0.0.1

Multiple Event ID 4625 authentication failures
followed by Event ID 4624 successful logon.

Logon Type: 2
```

## Analysis

The repeated failed logons originated from localhost and targeted the same local account.

A successful interactive logon was later observed.

No evidence of remote authentication activity was identified.

The activity was generated intentionally as part of a controlled SOC laboratory exercise.

## Classification

**True Positive / Benign Activity**

## Severity

**Low**

## Recommended Action

- Validate whether the authentication attempts were authorized
- Review source IP and account activity
- Check for additional suspicious authentication events
- Document the investigation
- Close the alert when benign activity is confirmed

## Lessons Learned

- Event ID 4625 represents failed Windows logon attempts
- Event ID 4624 represents successful Windows logons
- Multiple failed logons should be investigated using account, IP, and time context
- A detection can be technically correct while the underlying activity remains benign
- `stats`, `bin`, and `where` are useful for detecting repeated behavior over time

## Analyst Conclusion

Multiple failed authentication attempts were observed for `lab_user`, followed by a successful interactive logon.

The source was localhost (`127.0.0.1`) and no evidence of remote authentication activity was identified.

The activity was confirmed as an authorized laboratory test.

**Classification:** True Positive / Benign Activity  
**Severity:** Low  
**Action:** Documented and closed
