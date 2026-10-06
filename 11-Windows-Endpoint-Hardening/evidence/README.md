# Evidence — sanitized textual summary

Source: command output and analysis recorded in the Case 11 lab conversation. These are selected transcriptions/summaries, not new executions or a complete raw evidence archive. Screenshots and raw logs are omitted because they contain environment details and have not been prepared for public release.

## E01 — Listeners correlated with processes/services

| Local address | TCP port | PID | Correlated component |
| --- | --- | --- | --- |
| 0.0.0.0 / :: | 135 | 1556 | svchost; RpcEptMapper/RpcSs |
| 192.0.2.10 / 192.0.2.11 | 139 | 4 | System |
| :: | 445 | 4 | System |
| 0.0.0.0 | 5432 | 18092 | postgres, C:\Program Files\Splunk\bin\postgres.exe |
| :: | 7680 | 11880 | svchost; DoSvc |
| 0.0.0.0 | 8000 / 8089 | 5808 | splunkd, C:\Program Files\Splunk\bin\splunkd.exe |

Addresses 192.0.2.10 and 192.0.2.11 are replacements, not the original network. PIDs are retained as transient correlation values; they must not be reused as current process identifiers. Wildcard and loopback addresses describe binding scope and are not personal network identifiers.

## E02 — Firewall/profile

```text
Domain Enabled=True
Private Enabled=True
Public Enabled=True
DefaultInboundAction / DefaultOutboundAction = NotConfigured
Delivery Optimization TCP inbound: Enabled=True Profile=Any Direction=Inbound Action=Allow
Delivery Optimization UDP inbound: Enabled=True Profile=Any Direction=Inbound Action=Allow
NetworkCategory: Public initially; Private in later verification
```

No remotely conducted reachability test for the Splunk listeners is established by these outputs. The Delivery Optimization Config registry path returned PathNotFound; the Policies query produced no output with errors suppressed, so absence of an applied policy was not conclusively established.

## E03 — Defender

```text
AntivirusEnabled=True
RealTimeProtectionEnabled=True
BehaviorMonitorEnabled=True
IsTamperProtected=True
DefenderSignaturesOutOfDate=False
QuickScanAge=0
FullScanAge=4294967295
FullScanStartTime / FullScanEndTime: empty
SmartAppControlState=Off
```

## E04 — Accounts and session

```text
SOC-WS01\lab_analyst: local Administrators member
SOC-WS01\SOC_LAB: Enabled=True; local Administrators member; prior logon and password expiration recorded
SOC-WS01\CodexSandboxOnline: Enabled=True; prior logon; PasswordExpires empty
CodexSandboxOnline groups: Users; CodexSandboxUsers
SOC_CASE09: enabled; SOC_CASE10: disabled
Built-in Administrator and Guest: disabled
UAC: EnableLUA=1; ConsentPromptBehaviorAdmin=5; PromptOnSecureDesktop=1
Session: Administrators membership; high integrity
SID: <SID_REDACTED>
```

Account-specific timestamps are omitted. An empty expiration field is reported as observed, without inferring how the account was provisioned.

## E05 — Audit policy

Recorded coverage included logon success/failure, logoff success, account lockout success, special logon success, process creation success, audit policy change success, and user account/security group management success. Privilege Use subcategories were recorded without auditing. File/registry access and other subcategories also lacked auditing. This is a selected summary, not the full policy export.

## E06 — net accounts

| Setting | Recorded value |
| --- | --- |
| Minimum password age | 0 days |
| Maximum password age | 42 days |
| Minimum password length | 0 |
| Password history | None |
| Lockout threshold | 10 |
| Lockout duration | 10 minutes |
| Lockout observation window | 10 minutes |
| Computer role | Workstation |

## Publication sanitization

Host and personal account names are replaced with SOC-WS01 and lab_analyst. Real private addresses use 192.0.2.x replacements; IPv6 identifiers are omitted. MAC values are omitted or represented as `<MAC_REDACTED>`. SIDs and sensitive identifiers are omitted or redacted. No router, ISP, credentials, Product ID, network names or household inventory is included. No synthetic screenshot or fabricated raw output is presented as evidence.

## E07 — Follow-up privilege auditing

Selected sanitized summary from the subsequent practice: initial `Uso de privilegio confidencial = Sin auditoría`; success auditing enabled; subsequent state `Aciertos`. Splunk index `windows_soc`, EventCode `4674`, account `lab_analyst`, host/domain `SOC-WS01`, SID `<SID_REDACTED>`, process `C:\Windows\System32\lsass.exe`, PID `0x4e8` (1256 decimal), privilege `SeSecurityPrivilege`, object server `LSA`. PowerShell confirmed active `lsass` / 1256 with Path empty. The rex table was confirmed; the 30-minute correlation search returned 4674 without a matching 4688. Classification: **TP / Benign**.

Earlier lsass startup is a probable explanation, not a verified timestamp. Account-specific times and other sensitive identifiers are omitted. This is a summary of recorded evidence, not a fabricated raw export or a new execution.
