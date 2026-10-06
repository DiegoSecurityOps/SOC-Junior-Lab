# Case 11 — Windows Endpoint Hardening Review

## Scenario

As a cybersecurity student, I reviewed a Windows endpoint used for SOC practice. The aim was to understand its security posture and document hardening opportunities, using the command outputs and analysis recorded in the lab conversation. The sanitized endpoint is `SOC-WS01`; the analyst account is `lab_analyst`.

This is a configuration review, not a complete forensic examination or a compliance assessment. No new endpoint checks or remediation were performed when preparing this report.

## Objectives

- Establish host and network context.
- Correlate connections and listening ports with processes and services.
- Review firewall, Defender, local accounts, privileges, UAC and audit policy.
- Separate observed settings from recommendations and unresolved questions.

## Methodology

1. Review the host baseline with `systeminfo` and network configuration with `Get-NetIPConfiguration`.
2. Inspect neighbors and connections, then correlate port → PID → process → service.
3. Compare listeners with firewall rules and the active network profile.
4. Review Defender and local account/group membership.
5. Review UAC, session groups/privileges, audit policy and password/account lockout policy.
6. Summarize evidence, limitations and recommended follow-up.

The baseline and neighbor checks are documented as workflow steps; a complete sanitized raw export is not included. Hardware, network inventory and patch compliance are not inferred.

## Findings

| Area | Recorded observation | Interpretation |
| --- | --- | --- |
| Firewall | Domain, Private and Public enabled; default actions displayed `NotConfigured` | Positive enabled status; this output alone does not establish effective default actions |
| Network profile | Initially Public; later output confirmed Private | A recorded profile change; Private is a trust classification, not proof of improved security |
| Delivery Optimization | Enabled TCP/UDP inbound Allow rules with Profile `Any`; DoSvc Running, Auto, NetworkService | Review whether inbound access is needed across all profiles |
| Splunk | TCP 8000/8089 on `0.0.0.0`, PID 5808 → splunkd; TCP 5432 on `0.0.0.0`, PID 18092 → postgres in Splunk's bin directory | Expected lab components with broad listening scope; review access requirements |
| Firewall filters | Exact-port checks returned Delivery Optimization rules; Splunk program filter returned no results | Does not prove that Splunk is blocked or remotely reachable; broader rules and effective policy were not established |
| Windows services | PID 1556 → RpcEptMapper/RpcSs; PID 11880 → DoSvc. SSDPSRV and webthreatdefsvc ran from System32 svchost as LocalService, Manual | Settings were consistent with expected Windows service context; names and paths alone are not authenticity checks |
| Defender | Antivirus, real-time, behavior monitoring and Tamper Protection enabled; signatures not out of date; QuickScanAge 0 | Positive protection settings at the time of review |
| Additional Defender context | SmartAppControlState Off; FullScanAge 4294967295 with empty full-scan times | Full-scan history was not established; do not turn the sentinel value into a precise scan age |
| Local accounts | SOC_CASE09 and SOC_LAB enabled; SOC_CASE10 disabled; built-in Administrator and Guest disabled | Review the lifecycle of remaining test accounts |
| Administrators | Built-in Administrator, lab_analyst and SOC_LAB listed | SOC_LAB retained administrative membership; disabled status and group membership are separate facts |
| CodexSandboxOnline | Enabled, prior logon recorded, no PasswordExpires value; member of Users and CodexSandboxUsers, absent from Administrators | No administrative membership observed; creator, purpose and ongoing need remain to be verified |
| UAC/session | EnableLUA 1, ConsentPromptBehaviorAdmin 5, PromptOnSecureDesktop 1; Administrators and high integrity in session groups | UAC enabled; reviewed console was elevated |
| Session privileges | SeDebugPrivilege, SeChangeNotifyPrivilege, SeImpersonatePrivilege and SeCreateGlobalPrivilege recorded as enabled | Context of an elevated session; privilege availability alone does not demonstrate abuse |
| Audit policy | Logon success/failure and process creation success enabled; several subcategories disabled, including Privilege Use | Partial visibility, requiring a policy appropriate to the lab's detection goals |
| Password policy | Minimum length 0, no history; minimum age 0 days, maximum age 42 days | Local policy does not enforce a minimum length or password reuse history; actual password strength was not measured |
| Lockout | Threshold 10, duration 10 minutes, observation window 10 minutes | Lockout configured; effectiveness was not tested here |

### Connection and process correlation

An Edge process was associated with a connection to sanitized destination `192.0.2.20:8009`. The recorded analysis linked Edge PID 16612 to parent Edge PID 11504, whose creation event showed Edge parent PID 9988. A different historical event used PID 9988 for splunk-netmon.exe; it was not evidence that Splunk launched Edge. PID reuse made timestamp and process context essential. The search for the originating creation of the relevant Edge PID 9988 returned no results, leaving the ancestry incomplete. Port number alone did not establish the destination's purpose.

## Privilege Auditing Validation

In the follow-up practice, I checked `Uso de privilegio confidencial` with auditpol. Its initial state was `Sin auditoría`. I enabled success auditing with `auditpol /set /subcategory:"Uso de privilegio confidencial" /success:enable`, then checked it again. The subsequent state was confirmed as `Aciertos`. These actions were performed during the recorded practice; no endpoint commands were rerun for this update.

| Field | Recorded value, sanitized where needed |
| --- | --- |
| EventCode / index | 4674 / windows_soc |
| Account | lab_analyst |
| Host / account domain | SOC-WS01 |
| SID | <SID_REDACTED> |
| Process | C:\Windows\System32\lsass.exe |
| PID | 0x4e8 (1256 decimal) |
| Privilege | SeSecurityPrivilege |
| Object server | LSA |

`Get-Process -Id 1256 | Select-Object Name,Id,Path` returned `lsass`, ID `1256`, and an empty Path. The full path came from the 4674 event. Other sensitive identifiers and account-specific timestamps are omitted.

I used `rex` to extract the account, process ID, process name and privilege into a readable table. I then searched for EventCode 4674 and 4688 in a 30-minute window, extracted their process IDs and filtered for `0x4e8`. Only 4674 appeared; no matching 4688 was found. The recorded searches are in [related-searches.spl](spl/related-searches.spl).

The active-process check linked PID 1256 to lsass, but did not establish its historical creation time. The interpretation was that lsass.exe probably started much earlier, outside the window. This is a probable explanation, not a verified startup timestamp. The absence of 4688 does not invalidate the investigation or prove an auditing failure. Host, time and process context matter because PIDs can be reused.

**Classification: TP / Benign.** The privileged activity was real, and the LSA/LSASS context was treated as expected in this lab. This classification applies to the reviewed activity; a process name/path alone does not prove authenticity or that the whole endpoint is safe.

My lesson: **if the endpoint does not audit an activity, the SIEM cannot see it through that audit telemetry.** The practice connected audit policy, recorded activity, Splunk ingestion and investigation. An unsuccessful historical correlation can leave a gap in the available evidence.

## Recommendations — not applied

- Review Delivery Optimization requirements and restrict inbound profiles/scope where appropriate.
- Review whether Splunk needs remote access; consider loopback binding or scoped firewall access after checking lab dependencies.
- Review enabled laboratory accounts; remove administrative membership from SOC_LAB if no longer required, and disable obsolete test accounts through a planned change.
- Identify the ownership and purpose of sandbox accounts before changing them.
- Define a stronger local password length/history policy suited to the environment. Review expiration and lockout settings together rather than assuming expiration makes passwords strong.
- Expand auditing according to detection objectives, especially relevant privilege-use and account activity, while considering log volume. Verify resulting events and ingestion afterward.
- Review full-scan history and the need for additional execution controls. Preserve the active Defender and UAC protections.

## Conclusion

No evident indicators of compromise were identified during the review. This limited observation does not establish that the endpoint is free of compromise. The main opportunities were Delivery Optimization inbound access in `Any`, enabled lab accounts, SOC_LAB administrative privileges, no enforced minimum password length/history, and partial auditing.

I practiced moving from an unfamiliar connection or service to evidence and context before recommending a change. The follow-up audit → activity → Splunk exercise validated sensitive privilege-use telemetry. Other hardening recommendations remain follow-up work.

## Supporting files

- [Investigation commands](commands/investigation-commands.md)
- [Sanitized evidence summary](evidence/README.md)
- [Related SPL searches](spl/related-searches.spl)
- [Analyst notes](notes/analyst-notes.md)
