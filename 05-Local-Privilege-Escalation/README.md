# Case 05 — User Added to Local Administrators Group

## Scenario

A local account was added to the built-in local Administrators group on a Windows host.

The objective was to determine which account was affected, who performed the change, whether the action represented privilege escalation, and whether the activity was authorized.

## Objective

Investigate a local group membership change associated with elevated privileges.

## Data Source

- Splunk Enterprise
- Windows Security Event Log
- Event ID 4732 — A member was added to a security-enabled local group
- Event ID 4798 — A user's local group membership was enumerated

## Investigation

The investigation focused on:

- Actor performing the change
- Member SID
- Account associated with the SID
- Destination group
- Host
- Correlation between Event ID 4732 and Event ID 4798
- Security impact of the group membership change

## SPL — Local Administrators Group Membership Change

```spl
index=windows_soc EventCode=4732 earliest=-24h latest=now
| rex "Sujeto:[\s\S]*?Nombre de cuenta:\s+(?<actor>\S+)"
| rex "Miembro:[\s\S]*?Id\. de seguridad:\s+(?<member_sid>\S+)"
| rex "Grupo:[\s\S]*?Nombre de grupo:\s+(?<group_name>[^\r\n]+)"
| table _time host actor member_sid group_name
| sort _time
```

## SPL — SID Correlation

```spl
index=windows_soc earliest=-24h latest=now
(EventCode=4732 OR EventCode=4798)
"<USER_SID>"
| rex "Sujeto:[\s\S]*?Nombre de cuenta:\s+(?<actor>\S+)"
| rex "Miembro:[\s\S]*?Id\. de seguridad:\s+(?<member_sid>\S+)"
| rex "Usuario:[\s\S]*?Id\. de seguridad:\s+(?<user_sid>\S+)"
| rex "Usuario:[\s\S]*?Nombre de cuenta:\s+(?<resolved_account>\S+)"
| rex "Grupo:[\s\S]*?Nombre de grupo:\s+(?<group_name>[^\r\n]+)"
| eval account_sid=coalesce(member_sid,user_sid)
| stats values(actor) as actor values(resolved_account) as account values(group_name) as group by account_sid host
```

## Evidence

Sanitized laboratory evidence:

```text
Host: SOC-WS01
Actor: lab_analyst
Account: SOC_LAB
Group: Administrators
Member SID: <USER_SID>

Event ID 4732 showed that the account was added to the local Administrators group.

Event ID 4798 was used to correlate the SID with the SOC_LAB account.
```

## Analysis

The investigation confirmed that the `SOC_LAB` account was added to the local `Administrators` group.

The Event ID 4732 record identified the actor responsible for the group membership change and the SID of the member that was added.

Event ID 4798 was used to resolve the SID and confirm that it belonged to the `SOC_LAB` account.

Because membership in the local Administrators group grants elevated privileges on the affected host, the activity represents a local privilege escalation.

The activity was performed intentionally as part of a controlled SOC laboratory exercise.

## Classification

**True Positive / Benign Activity**

## Severity

**Medium**

## Recommended Action

- Validate whether the group membership change was authorized
- Confirm the account associated with the member SID
- Review the actor responsible for the change
- Investigate subsequent logons or privileged activity
- Review additional account-management events
- Document the investigation
- Close the alert when authorized activity is confirmed

## Lessons Learned

- Event ID 4732 records when a member is added to a local security-enabled group
- Local Administrators group membership can represent privilege escalation
- A SID may require correlation with additional Windows events to resolve the associated account
- Event ID 4798 can provide useful context for local group membership
- Detection accuracy and malicious intent must be evaluated separately
- Privilege-related changes should receive greater analytical attention than routine account activity

## Analyst Conclusion

A local privilege escalation event was identified on `SOC-WS01`.

Windows Security Event ID 4732 showed that a member was added to the local `Administrators` group by `lab_analyst`.

Correlation with Event ID 4798 confirmed that the member SID belonged to the `SOC_LAB` account.

The activity was generated as part of an authorized laboratory exercise.

**Classification:** True Positive / Benign Activity  
**Severity:** Medium  
**Action:** Documented and closed
