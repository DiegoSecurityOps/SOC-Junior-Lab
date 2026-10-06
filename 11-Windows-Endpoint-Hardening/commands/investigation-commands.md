# Investigation commands

Commands documented in the lab workflow. Examples below use sanitized destinations and recorded snapshot PIDs. They are reference material, not a script to run wholesale. Queries can expose usernames, IPs, SIDs, command-line secrets or product identifiers; publish only selected sanitized output.

## Host, network and connections

```powershell
systeminfo
Get-NetIPConfiguration
Get-NetNeighbor
arp -a
Get-NetTCPConnection
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort
Get-NetUDPEndpoint |
    Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort
```

`systeminfo` supplies baseline context. IP configuration describes interfaces and addressing; neighbor/ARP queries describe local address mappings. TCP and UDP queries identify connections or endpoints and their owning PIDs. They do not identify malicious activity on their own.

```powershell
Get-Process -Id 5808,18092,1556,4,11880 | Select-Object Id,ProcessName,Path
Get-Process -Id 11504 | Select-Object Name,Id,Path,StartTime
Get-CimInstance Win32_Process -Filter "ProcessId = 11504" |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
```

These correlate PIDs with process paths, start time, parent and command line. PIDs are from the historical snapshot. A terminated process may produce no current result.

`ping`, `nslookup` and `Test-NetConnection` were also documented as availability, resolution and port-check tools. Sanitized reference examples (not preserved exact invocations/results):

```powershell
ping 192.0.2.20
nslookup example.invalid
Test-NetConnection -ComputerName 192.0.2.20 -Port 8009
```

## Services

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-CimInstance Win32_Service -Filter "Name='webthreatdefsvc'" |
    Select-Object Name,DisplayName,State,StartMode,StartName,PathName
Get-CimInstance Win32_Service -Filter "Name='SSDPSRV'" |
    Select-Object Name,DisplayName,State,StartMode,StartName,PathName
Get-CimInstance Win32_Service |
    Where-Object {$_.ProcessId -in 1556,11880} |
    Select-Object Name,DisplayName,State,StartMode,ProcessId,PathName
Get-Service DoSvc
Get-CimInstance Win32_Service -Filter "Name='DoSvc'" |
    Select-Object Name,State,StartMode,StartName,PathName
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -ErrorAction SilentlyContinue
```

Service queries establish execution identity, location, startup and state. The first registry path was not found. The second returned no visible output with errors suppressed; that cannot establish the complete effective configuration.

## Firewall and profile

```powershell
Get-NetFirewallProfile |
    Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
    Select-Object DisplayName,Profile,Direction,Action
$ports = Get-NetFirewallPortFilter |
    Where-Object {$_.LocalPort -in @("8000","8089","5432","7680")}
foreach ($p in $ports) {
    Get-NetFirewallRule -AssociatedNetFirewallPortFilter $p |
        Select-Object DisplayName,Enabled,Profile,Direction,Action
}
Get-NetFirewallApplicationFilter |
    Where-Object {$_.Program -like "*Splunk*"} | Select-Object Program,InstanceID
Get-NetFirewallRule -DisplayName "*Optimización de distribución*" |
    Where-Object {$_.Enabled -eq "True"} |
    Select-Object DisplayName,Profile,Direction,Action
Get-NetConnectionProfile
```

These inspect enabled profiles and selected rules. Exact LocalPort matching can miss rules with Any, ranges or other conditions; a lack of matches is not proof of blocking. Display names depend on the Windows language.

Recorded configuration change, followed by profile/firewall verification:

```powershell
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
Get-NetConnectionProfile
Get-NetFirewallProfile | Select-Object Name,Enabled
```

The `Set-` command changes trust classification. It is historical documentation, not an instruction to change an arbitrary network to Private.

## Defender, accounts, UAC and policies

```powershell
Get-MpComputerStatus
Get-LocalUser
Get-LocalGroupMember -Group "Administradores"
Get-LocalUser -Name "SOC_LAB" |
    Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,UserMayChangePassword
Get-LocalUser -Name "CodexSandboxOnline" |
    Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordExpires,UserMayChangePassword
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
        Where-Object {$_.Name -like "*CodexSandboxOnline*"} |
        Select-Object @{Name="Group";Expression={$group}},Name,ObjectClass
}
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop
whoami /groups
whoami /priv
auditpol /get /category:*
net accounts
```

Defender reports protection state. Account/group queries report enabled users and membership (group names are localized). UAC queries report elevation settings. `whoami /groups` shows session groups/integrity; `/priv` shows token privileges and enabled status. `auditpol` reports configured audit coverage. `net accounts` reports local password and lockout policy.

## Terms used in the case

`Listen`: waiting TCP listener. `Established`: active TCP connection. `PID` / `OwningProcess`: transient process identifier. `Inbound` / `Outbound`: traffic direction. `Allow`: rule action. `Any`: all firewall profiles in the observed Profile field. `0.0.0.0` / `::`: all IPv4 / IPv6 interfaces. `127.0.0.1` / `::1`: loopback.

Observed correlations: TCP 8000/8089 → splunkd; 5432 → Splunk's postgres; 7680 → DoSvc; 135 → RPC services; 139/445 → System. Port 8009 was the Edge connection destination; its number does not establish service identity. Other listeners were present but were not fully attributed, so this case does not classify them by number alone.
