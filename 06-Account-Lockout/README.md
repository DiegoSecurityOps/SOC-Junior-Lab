# Case 06 — Account Lockout Investigation

## Scenario

A local user account was locked out after multiple failed authentication attempts on a Windows host.

The objective was to determine which account was affected, what caused the failures, whether the activity originated locally or remotely, and whether a successful logon occurred afterward.

## Objective

Investigate a Windows account lockout by correlating failed logon events with the account lockout event and validating the authentication context.

## Data Source

- Splunk Enterprise
- Windows Security Event Log
- Event ID `4625` — Failed logon
- Event ID `4740` — User account locked out
- Event ID `4624` — Successful logon

## Investigation

The investigation focused on:

- Locked account
- Number of failed authentication attempts
- Logon type
- Source IP
- Failure reason
- Account lockout event
- Successful logons after the lockout
- Correlation with the configured Windows lockout policy

## SPL — Failed Logon Analysis

```spl
index=windows_soc "SOC_LAB" EventCode=4625 earliest=-180m latest=now host="SOC-WS01"
| rex "Cuenta con error de inicio de sesión:[\s\S]*?Nombre de cuenta:\s+(?<account>\S+)"
| rex "Tipo de inicio de sesión:\s+(?<LogonType>\d+)"
| rex "Dirección de red de origen:\s+(?<src_ip>\S+)"
| rex "Subestado:\s+(?<SubStatus>\S+)"
| stats count by account src_ip LogonType SubStatus
```

## SPL — Authentication Timeline

```spl
index=windows_soc "SOC_LAB" earliest=-180m latest=now
(EventCode=4625 OR EventCode=4740)
| table _time EventCode host
| sort _time
```

## SPL — Successful Logon Check

```spl
index=windows_soc "SOC_LAB" EventCode=4624 earliest=-180m latest=now
```

## Evidence

Sanitized laboratory evidence:

```text
Host: SOC-WS01
Account: SOC_LAB
Source IP: 127.0.0.1
Logon Type: 2
SubStatus: 0xC000006A

10 failed Event ID 4625 logons
followed by Event ID 4740 account lockout.

No Event ID 4624 successful logon was observed afterward
within the reviewed investigation window.
```

## Analysis

The investigation identified ten failed authentication attempts for `SOC_LAB`.

All failures originated from `127.0.0.1` and used Logon Type `2`, indicating an interactive local logon.

The failure SubStatus was `0xC000006A`, consistent with an incorrect password.

The ten failed authentication attempts occurred within the configured Windows account lockout window and were followed by Event ID `4740`, confirming that the account was locked out.

A subsequent search for Event ID `4624` identified no successful authentication for `SOC_LAB` within the reviewed time range.

The activity was generated intentionally as part of a controlled SOC laboratory exercise.

## Classification

**True Positive / Benign Activity**

## Severity

**Low**

## Recommended Action

- Validate whether the failed authentication attempts were authorized
- Review the affected account and source system
- Confirm whether the attempts originated locally or remotely
- Review the configured account lockout policy
- Search for successful logons before and after the lockout
- Check whether additional accounts show similar failed authentication patterns
- Document the investigation
- Close the alert when authorized activity is confirmed

## Lessons Learned

- Event ID `4740` records when a Windows account is locked out
- Event ID `4625` provides the authentication failures leading up to the lockout
- Logon Type `2` represents an interactive local logon
- Source IP `127.0.0.1` indicates activity originating from the local host
- SubStatus `0xC000006A` indicates an incorrect password
- Correlating multiple events provides stronger context than analyzing a single event
- Account lockouts should be investigated to distinguish user error, stale credentials, misconfiguration, and potential credential attacks

## Analyst Conclusion

A local account lockout was identified for `SOC_LAB` on `SOC-WS01`.

Ten failed interactive logon attempts (Event ID `4625`) were observed from `127.0.0.1`, all using Logon Type `2` and SubStatus `0xC000006A`, indicating incorrect passwords.

The failed authentication attempts occurred within the configured account lockout window and were followed by Event ID `4740`.

No successful Event ID `4624` logon was observed for `SOC_LAB` afterward within the reviewed investigation window.

The activity was generated as part of an authorized laboratory exercise.

**Classification:** True Positive / Benign Activity  
**Severity:** Low  
**Action:** Documented and closed
