#requires -Version 2.0
<#
.SYNOPSIS
    Windows event logging gap analysis for incident response - read-only, no dependencies.

.DESCRIPTION
    Runs locally on a (potentially compromised) Windows server and answers:
      1. Which time frame does every event log cover, and how fast is it overwritten?
      2. Which detection use cases (MITRE ATT&CK) does the current logging configuration support?
      3. Was logging weakened or tampered with (log clearing, audit policy changes, disabled loggers ...)?
      4. Which channels / event IDs actually reach the SIEM (Splunk Universal Forwarder inputs.conf)?
      5. Who holds local admin / RDP rights, and which accounts logged on interactively (when, from where)?
    The checks are selected from the detected Windows version (Windows Server 2008 / Vista and later,
    Windows PowerShell 2.0 and later). Nothing on the system is changed.

    Output folder LogGapAnalysis_<HOST>_<yyyyMMdd_HHmmss>:
      report.html          self-contained HTML report (score, timeline, findings, coverage matrix)
      results.json         all results, machine readable
      *.csv                findings, use cases, logs, audit policy, Splunk inputs
      raw\                 data as collected (auditpol backup, GPO audit.csv, Splunk btool, registry values)
      collection.log       every step executed
      manifest_sha256.txt  SHA-256 of every output file

.PARAMETER OutputPath
    Folder that receives the result folder. Default: the current working directory.
    On a compromised host prefer external media or a network share.

.PARAMETER SuspectedStart
    Suspected start of the incident ("2026-09-01" or "2026-09-01 14:00", local time). Every log is checked
    for whether it still reaches back to this time; it is drawn on the timeline.

.PARAMETER DeepScan
    Reads the key logs completely: event record ID gaps (deleted events), periods without events, event
    volume per hour and anti-logging commands in process / PowerShell events. Takes minutes on large logs.

.PARAMETER DeepScanMaxEvents
    Maximum number of events read per log during -DeepScan (default 2,000,000).

.PARAMETER GapMinutes
    -DeepScan: a period longer than this without any Security / Sysmon event is reported (default 60).

.PARAMETER SkipSplunkBtool
    Do not run "splunk.exe btool"; parse the Splunk .conf files directly.

.PARAMETER ExpandDomainGroups
    Also expand domain groups that are members of local privileged groups (Administrators, Remote Desktop Users ...).
    Needs a reachable domain controller; off by default because an isolated host would wait for timeouts.
    On a domain controller the groups are always expanded.

.PARAMETER LogonMaxEvents
    Maximum number of interactive logon events (4624) read from the Security log (default 50,000, newest first).

.NOTES
    Author : secamin  (SIEM Detection Content) - https://github.com/secamin
    Co-author and contributor: HXM14 - https://github.com/HXM14
    Tool ID: secamin/log-gap-analysis (Windows)

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-LogGapAnalysis.ps1

.EXAMPLE
    .\Invoke-LogGapAnalysis.ps1 -OutputPath E:\IR -SuspectedStart 2026-09-01 -DeepScan
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$SuspectedStart,
    [switch]$DeepScan,
    [int]$DeepScanMaxEvents = 2000000,
    [int]$GapMinutes = 60,
    [switch]$SkipSplunkBtool,
    [switch]$ExpandDomainGroups,
    [int]$LogonMaxEvents = 50000,
    [switch]$ComplianceMap,
    [string]$ComplianceMapPath = ''
)

$ErrorActionPreference = 'Continue'
$ScriptVersion = '1.1.0'
$ScriptAuthor = 'secamin'
$ScriptCoAuthor = 'HXM14'
$ScriptRepo = 'https://github.com/secamin'
$ScriptCoAuthorRepo = 'https://github.com/HXM14'
$ScriptToolId = 'secamin/log-gap-analysis'
$ScriptPath = $MyInvocation.MyCommand.Path

# 32-bit PowerShell on 64-bit Windows sees redirected registry / System32 views - re-launch as 64-bit
if ($env:PROCESSOR_ARCHITEW6432 -and $ScriptPath) {
    $ps64 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $ps64) {
        Write-Host 'Re-launching in 64-bit PowerShell ...' -ForegroundColor Yellow
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath)
        foreach ($k in $PSBoundParameters.Keys) {
            $v = $PSBoundParameters[$k]
            if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $relaunch += "-$k" } }
            else { $relaunch += "-$k"; $relaunch += [string]$v }
        }
        & $ps64 @relaunch
        exit $LASTEXITCODE
    }
}

$Inv = [Globalization.CultureInfo]::InvariantCulture
$script:RunStart = Get-Date
try { Add-Type -AssemblyName System.Core -ErrorAction Stop } catch { }
$script:HasReader = $false
try { $script:LogPathType = [System.Diagnostics.Eventing.Reader.PathType]::LogName; $script:HasReader = $true } catch { }

$script:Suspect = $null
if ($SuspectedStart) {
    $parsed = [datetime]::MinValue
    $formats = [string[]]@('yyyy-MM-dd', 'yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm', 'yyyy-MM-ddTHH:mm:ss')
    if ([datetime]::TryParseExact($SuspectedStart.Trim(), $formats, $Inv, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)) {
        $script:Suspect = $parsed
    } else {
        Write-Host "Cannot parse -SuspectedStart '$SuspectedStart' (use yyyy-MM-dd or 'yyyy-MM-dd HH:mm')" -ForegroundColor Red
        exit 2
    }
}

# =====================================================================================================
#  Reference data
# =====================================================================================================
# Category | Subcategory | last byte of the subcategory GUID {0CCE92xx-69AE-11D9-BED3-505054503030}
$AuditSubcategories = @(
    'System|Security State Change|10', 'System|Security System Extension|11', 'System|System Integrity|12',
    'System|IPsec Driver|13', 'System|Other System Events|14',
    'Logon/Logoff|Logon|15', 'Logon/Logoff|Logoff|16', 'Logon/Logoff|Account Lockout|17',
    'Logon/Logoff|IPsec Main Mode|18', 'Logon/Logoff|IPsec Quick Mode|19', 'Logon/Logoff|IPsec Extended Mode|1A',
    'Logon/Logoff|Special Logon|1B', 'Logon/Logoff|Other Logon/Logoff Events|1C', 'Logon/Logoff|Network Policy Server|43',
    'Logon/Logoff|User / Device Claims|47', 'Logon/Logoff|Group Membership|49',
    'Object Access|File System|1D', 'Object Access|Registry|1E', 'Object Access|Kernel Object|1F', 'Object Access|SAM|20',
    'Object Access|Certification Services|21', 'Object Access|Application Generated|22', 'Object Access|Handle Manipulation|23',
    'Object Access|File Share|24', 'Object Access|Filtering Platform Packet Drop|25', 'Object Access|Filtering Platform Connection|26',
    'Object Access|Other Object Access Events|27', 'Object Access|Detailed File Share|44', 'Object Access|Removable Storage|45',
    'Object Access|Central Policy Staging|46',
    'Privilege Use|Sensitive Privilege Use|28', 'Privilege Use|Non Sensitive Privilege Use|29', 'Privilege Use|Other Privilege Use Events|2A',
    'Detailed Tracking|Process Creation|2B', 'Detailed Tracking|Process Termination|2C', 'Detailed Tracking|DPAPI Activity|2D',
    'Detailed Tracking|RPC Events|2E', 'Detailed Tracking|Plug and Play Events|48', 'Detailed Tracking|Token Right Adjusted Events|4A',
    'Policy Change|Audit Policy Change|2F', 'Policy Change|Authentication Policy Change|30', 'Policy Change|Authorization Policy Change|31',
    'Policy Change|MPSSVC Rule-Level Policy Change|32', 'Policy Change|Filtering Platform Policy Change|33', 'Policy Change|Other Policy Change Events|34',
    'Account Management|User Account Management|35', 'Account Management|Computer Account Management|36',
    'Account Management|Security Group Management|37', 'Account Management|Distribution Group Management|38',
    'Account Management|Application Group Management|39', 'Account Management|Other Account Management Events|3A',
    'DS Access|Directory Service Access|3B', 'DS Access|Directory Service Changes|3C', 'DS Access|Directory Service Replication|3D',
    'DS Access|Detailed Directory Service Replication|3E',
    'Account Logon|Credential Validation|3F', 'Account Logon|Kerberos Service Ticket Operations|40',
    'Account Logon|Other Account Logon Events|41', 'Account Logon|Kerberos Authentication Service|42'
)
$script:SubByName = @{}; $script:SubByGuid = @{}; $script:SubOrder = New-Object System.Collections.ArrayList
foreach ($s in $AuditSubcategories) {
    $p = $s.Split('|')
    $o = @{ Category = $p[0]; Name = $p[1]; Guid = ('{0CCE92' + $p[2] + '-69AE-11D9-BED3-505054503030}') }
    $script:SubByName[$o.Name] = $o; $script:SubByGuid[$o.Guid] = $o; [void]$script:SubOrder.Add($o)
}

# Role based audit baseline - Need: 1 = Success, 2 = Failure, 3 = Success and Failure (merged with -bor per role)
# Sources: Microsoft "Audit Policy Recommendations", CIS Benchmarks (DC / member server L1), ASD event logging guidance
$Baseline = @(
    @{ Sub = 'Credential Validation'; Need = 3; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'NTLM authentication (4776): password spraying, pass-the-hash' },
    @{ Sub = 'Kerberos Authentication Service'; Need = 3; Roles = 'DC'; Ref = 'MS, CIS'; Why = 'TGT requests (4768/4771): AS-REP roasting, spraying' },
    @{ Sub = 'Kerberos Service Ticket Operations'; Need = 3; Roles = 'DC'; Ref = 'MS, CIS'; Why = 'Service tickets (4769): Kerberoasting' },
    @{ Sub = 'Computer Account Management'; Need = 1; Roles = 'DC'; Ref = 'MS, CIS'; Why = 'Computer accounts (4741/4742): RBCD, noPac' },
    @{ Sub = 'Distribution Group Management'; Need = 1; Roles = 'DC'; Ref = 'CIS'; Why = 'Distribution group changes' },
    @{ Sub = 'Other Account Management Events'; Need = 1; Roles = 'ALL'; Ref = 'CIS'; Why = 'Password hash access (4782)' },
    @{ Sub = 'Security Group Management'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Group membership changes (4728/4732/4756)' },
    @{ Sub = 'User Account Management'; Need = 3; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Account creation / password reset (4720/4724/4738)' },
    @{ Sub = 'Plug and Play Events'; Need = 1; Roles = 'ALL'; Ref = 'CIS'; Why = 'External device connections (6416)' },
    @{ Sub = 'Process Creation'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS, ASD'; Why = 'Process execution (4688)' },
    @{ Sub = 'Directory Service Access'; Need = 3; Roles = 'DC'; Ref = 'MS, CIS'; Why = 'AD object access (4662): DCSync' },
    @{ Sub = 'Directory Service Changes'; Need = 1; Roles = 'DC'; Ref = 'MS, CIS'; Why = 'AD object / GPO modifications (5136/5137/5141)' },
    @{ Sub = 'Account Lockout'; Need = 2; Roles = 'ALL'; Ref = 'CIS'; Why = 'Logon failures caused by lockout (4625)' },
    @{ Sub = 'Group Membership'; Need = 1; Roles = 'ALL'; Ref = 'CIS'; Why = 'Group membership of logged-on users (4627)' },
    @{ Sub = 'Logoff'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Session end (4634/4647)' },
    @{ Sub = 'Logon'; Need = 3; Roles = 'ALL'; Ref = 'MS, CIS, ASD'; Why = 'Logons and failed logons (4624/4625)' },
    @{ Sub = 'Other Logon/Logoff Events'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'RDP reconnect / disconnect (4778/4779)' },
    @{ Sub = 'Special Logon'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Privileged logons (4672)' },
    @{ Sub = 'Detailed File Share'; Need = 2; Roles = 'ALL'; Ref = 'CIS'; Why = 'Denied share access (5145)' },
    @{ Sub = 'Detailed File Share'; Need = 1; Roles = 'FS'; Ref = 'ASD'; Why = 'File access over SMB on file servers (5145)' },
    @{ Sub = 'File Share'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'Share access (5140): admin shares, lateral movement' },
    @{ Sub = 'File System'; Need = 3; Roles = 'FS'; Ref = 'MS'; Why = 'Access to audited folders (4663) - requires SACLs' },
    @{ Sub = 'Other Object Access Events'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'Scheduled task creation / change (4698/4702)' },
    @{ Sub = 'Removable Storage'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'Removable media access (4663)' },
    @{ Sub = 'Certification Services'; Need = 3; Roles = 'CA'; Ref = 'MS'; Why = 'Certificate requests / issuance (4886/4887)' },
    @{ Sub = 'Audit Policy Change'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Audit policy changes (4719)' },
    @{ Sub = 'Authentication Policy Change'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Trust / Kerberos policy changes (4706/4713)' },
    @{ Sub = 'Authorization Policy Change'; Need = 1; Roles = 'ALL'; Ref = 'CIS'; Why = 'User right assignment (4704/4705)' },
    @{ Sub = 'MPSSVC Rule-Level Policy Change'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'Firewall rule changes (4946-4950)' },
    @{ Sub = 'Other Policy Change Events'; Need = 2; Roles = 'ALL'; Ref = 'CIS'; Why = 'Failed policy changes' },
    @{ Sub = 'Sensitive Privilege Use'; Need = 3; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Sensitive privileges (4673/4674)' },
    @{ Sub = 'IPsec Driver'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'IPsec driver integrity' },
    @{ Sub = 'Other System Events'; Need = 3; Roles = 'ALL'; Ref = 'CIS'; Why = 'Firewall service and key events' },
    @{ Sub = 'Security State Change'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'System time change (4616), startup (4608)' },
    @{ Sub = 'Security System Extension'; Need = 1; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Service installation (4697)' },
    @{ Sub = 'System Integrity'; Need = 3; Roles = 'ALL'; Ref = 'MS, CIS'; Why = 'Lost audit events (4612), integrity failures' }
)
# Subcategories whose absence removes core IR visibility (raises the finding severity)
$KeySubcategories = @('Logon', 'Process Creation', 'Credential Validation', 'Kerberos Authentication Service',
    'Kerberos Service Ticket Operations', 'Security Group Management', 'User Account Management', 'Audit Policy Change',
    'Other Object Access Events', 'Security System Extension', 'Directory Service Access', 'Directory Service Changes',
    'Special Logon', 'Computer Account Management', 'Certification Services')

# Logs shown in the inventory / timeline (Roles: ALL or role code)
$KeyLogDefs = @(
    @{ Name = 'Security'; Roles = 'ALL'; Why = 'Logons, accounts and groups, process creation, audit policy' },
    @{ Name = 'System'; Roles = 'ALL'; Why = 'Services, reboots, log clearing (104)' },
    @{ Name = 'Application'; Roles = 'ALL'; Why = 'Application / AV / backup software events' },
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; Roles = 'ALL'; Why = 'Process, network, file and registry telemetry' },
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; Roles = 'ALL'; Why = 'PowerShell script blocks (4104)' },
    @{ Name = 'Windows PowerShell'; Roles = 'ALL'; Why = 'PowerShell engine start (400), version downgrade' },
    @{ Name = 'PowerShellCore/Operational'; Roles = 'OPT'; Why = 'PowerShell 7 script blocks' },
    @{ Name = 'Microsoft-Windows-TaskScheduler/Operational'; Roles = 'ALL'; Why = 'Scheduled task registration / execution' },
    @{ Name = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Roles = 'ALL'; Why = 'RDP sessions (21/24/25)' },
    @{ Name = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Roles = 'ALL'; Why = 'RDP authentication (1149)' },
    @{ Name = 'Microsoft-Windows-WinRM/Operational'; Roles = 'ALL'; Why = 'WinRM / PowerShell remoting' },
    @{ Name = 'Microsoft-Windows-WMI-Activity/Operational'; Roles = 'ALL'; Why = 'WMI activity and persistence' },
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Roles = 'ALL'; Why = 'Defender detections and tampering' },
    @{ Name = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Roles = 'ALL'; Why = 'Firewall rule changes' },
    @{ Name = 'Microsoft-Windows-Bits-Client/Operational'; Roles = 'ALL'; Why = 'BITS transfer jobs' },
    @{ Name = 'Microsoft-Windows-CodeIntegrity/Operational'; Roles = 'ALL'; Why = 'Driver / code integrity' },
    @{ Name = 'Microsoft-Windows-NTLM/Operational'; Roles = 'ALL'; Why = 'NTLM usage auditing' },
    @{ Name = 'Microsoft-Windows-SMBServer/Audit'; Roles = 'ALL'; Why = 'SMB server audit' },
    @{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Roles = 'ALL'; Why = 'USB device connections' },
    @{ Name = 'Directory Service'; Roles = 'DC'; Why = 'AD DS diagnostics, LDAP binds (2889)' },
    @{ Name = 'DFS Replication'; Roles = 'DC'; Why = 'SYSVOL replication' },
    @{ Name = 'DNS Server'; Roles = 'DNS'; Why = 'DNS server service' },
    @{ Name = 'Microsoft-Windows-DNSServer/Audit'; Roles = 'DNS'; Why = 'DNS zone / record changes' }
)

$RoleNames = @{ DC = 'Domain Controller'; FS = 'File Server'; DNS = 'DNS Server'; DHCP = 'DHCP Server'; CA = 'Certificate Authority (AD CS)';
    IIS = 'Web Server (IIS)'; EXCH = 'Exchange Server'; SQL = 'SQL Server'; HV = 'Hyper-V Host'; ADFS = 'AD FS'; NPS = 'Network Policy Server';
    WSUS = 'WSUS' }

function New-Src([string]$Log, [int[]]$Ids, [string[]]$Audit = @(), [string]$Extra = '', [string]$MinOS = '') {
    return @{ Log = $Log; Ids = $Ids; Audit = $Audit; Extra = $Extra; MinOS = $MinOS }
}
function New-UseCase([string]$Id, [string]$Name, [string]$Tactic, [string]$Mitre, [string]$Roles, [bool]$Key, [object[]]$Sources) {
    return @{ Id = $Id; Name = $Name; Tactic = $Tactic; Mitre = $Mitre; Roles = $Roles; Key = $Key; Sources = $Sources }
}
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$PSOpLog = 'Microsoft-Windows-PowerShell/Operational'
$UseCases = @(
    (New-UseCase 'UC01' 'Successful and failed logons (logon type, source IP)' 'Initial Access' 'T1078, T1110' 'ALL' $true @(
        (New-Src 'Security' @(4624, 4625) @('Logon:3')))),
    (New-UseCase 'UC02' 'NTLM credential validation (spraying, pass-the-hash)' 'Credential Access' 'T1110.003, T1550.002' 'ALL' $true @(
        (New-Src 'Security' @(4776) @('Credential Validation:3')))),
    (New-UseCase 'UC03' 'Account lockouts' 'Credential Access' 'T1110' 'ALL' $false @(
        (New-Src 'Security' @(4740) @('User Account Management:1')))),
    (New-UseCase 'UC04' 'Kerberos TGT requests (AS-REP roasting, spraying)' 'Credential Access' 'T1558.004' 'DC' $true @(
        (New-Src 'Security' @(4768, 4771) @('Kerberos Authentication Service:3')))),
    (New-UseCase 'UC05' 'Kerberos service tickets (Kerberoasting)' 'Credential Access' 'T1558.003' 'DC' $true @(
        (New-Src 'Security' @(4769) @('Kerberos Service Ticket Operations:3')))),
    (New-UseCase 'UC06' 'Directory replication abuse (DCSync)' 'Credential Access' 'T1003.006' 'DC' $true @(
        (New-Src 'Security' @(4662) @('Directory Service Access:1') 'SaclNote'))),
    (New-UseCase 'UC07' 'LSASS memory access (credential dumping)' 'Credential Access' 'T1003.001' 'ALL' $false @(
        (New-Src $SysmonLog @(10)),
        (New-Src 'Security' @(4656) @('Kernel Object:1') 'SaclReq'))),
    (New-UseCase 'UC08' 'Explicit credential use (runas, pivoting)' 'Lateral Movement' 'T1550' 'ALL' $false @(
        (New-Src 'Security' @(4648) @('Logon:1')))),
    (New-UseCase 'UC09' 'Privileged logons (special privileges assigned)' 'Privilege Escalation' 'T1078.002' 'ALL' $true @(
        (New-Src 'Security' @(4672) @('Special Logon:1')))),
    (New-UseCase 'UC10' 'Sensitive privilege use (SeDebug, SeTcb)' 'Privilege Escalation' 'T1134' 'ALL' $false @(
        (New-Src 'Security' @(4673, 4674) @('Sensitive Privilege Use:3')))),
    (New-UseCase 'UC11' 'Process execution with command line' 'Execution' 'T1059, T1204' 'ALL' $true @(
        (New-Src 'Security' @(4688) @('Process Creation:1') 'CmdLine'),
        (New-Src $SysmonLog @(1)))),
    (New-UseCase 'UC12' 'PowerShell script content' 'Execution' 'T1059.001' 'ALL' $true @(
        (New-Src $PSOpLog @(4104) @() 'ScriptBlock'),
        (New-Src $PSOpLog @(4103) @() 'ModuleLog'),
        (New-Src 'PowerShellCore/Operational' @(4104) @() 'PSCoreSB'))),
    (New-UseCase 'UC13' 'PowerShell version 2 downgrade (logging bypass)' 'Defense Evasion' 'T1059.001, T1562' 'ALL' $false @(
        (New-Src 'Windows PowerShell' @(400)))),
    (New-UseCase 'UC14' 'WMI execution and event subscriptions' 'Execution' 'T1047, T1546.003' 'ALL' $false @(
        (New-Src 'Microsoft-Windows-WMI-Activity/Operational' @(5857, 5860, 5861) @() '' '6.3'),
        (New-Src $SysmonLog @(19, 20, 21)))),
    (New-UseCase 'UC15' 'Service installation' 'Persistence' 'T1543.003' 'ALL' $true @(
        (New-Src 'System' @(7045)),
        (New-Src 'Security' @(4697) @('Security System Extension:1') '' '10.0'))),
    (New-UseCase 'UC16' 'Scheduled task creation / modification' 'Persistence' 'T1053.005' 'ALL' $true @(
        (New-Src 'Security' @(4698, 4702) @('Other Object Access Events:1')),
        (New-Src 'Microsoft-Windows-TaskScheduler/Operational' @(106, 140, 141, 200)))),
    (New-UseCase 'UC17' 'Account creation, enabling, password reset' 'Persistence' 'T1136, T1098' 'ALL' $true @(
        (New-Src 'Security' @(4720, 4722, 4724, 4738) @('User Account Management:1')))),
    (New-UseCase 'UC18' 'Privileged group membership changes' 'Persistence' 'T1098' 'ALL' $true @(
        (New-Src 'Security' @(4728, 4732, 4756) @('Security Group Management:1')))),
    (New-UseCase 'UC19' 'Computer account changes (RBCD, noPac)' 'Privilege Escalation' 'T1098' 'DC' $false @(
        (New-Src 'Security' @(4741, 4742) @('Computer Account Management:1')))),
    (New-UseCase 'UC20' 'AD object and GPO modifications' 'Privilege Escalation' 'T1484.001' 'DC' $true @(
        (New-Src 'Security' @(5136, 5137, 5141) @('Directory Service Changes:1')))),
    (New-UseCase 'UC21' 'Certificate requests and issuance (AD CS abuse)' 'Credential Access' 'T1649' 'CA' $true @(
        (New-Src 'Security' @(4886, 4887, 4888) @('Certification Services:3') 'CaAudit'))),
    (New-UseCase 'UC22' 'RDP logons and session activity' 'Lateral Movement' 'T1021.001' 'ALL' $true @(
        (New-Src 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21, 22, 24, 25)),
        (New-Src 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149)),
        (New-Src 'Security' @(4778, 4779) @('Other Logon/Logoff Events:1')))),
    (New-UseCase 'UC23' 'Admin share / SMB share access' 'Lateral Movement' 'T1021.002' 'ALL' $true @(
        (New-Src 'Security' @(5140) @('File Share:1')),
        (New-Src 'Security' @(5145) @('Detailed File Share:1')))),
    (New-UseCase 'UC24' 'WinRM / PowerShell remoting' 'Lateral Movement' 'T1021.006' 'ALL' $false @(
        (New-Src 'Microsoft-Windows-WinRM/Operational' @(6, 91)))),
    (New-UseCase 'UC25' 'NTLM usage (relay, downgrade)' 'Credential Access' 'T1557' 'ALL' $false @(
        (New-Src 'Microsoft-Windows-NTLM/Operational' @(8001, 8002, 8003, 8004) @() 'NtlmAudit' '6.1'))),
    (New-UseCase 'UC26' 'File access on sensitive shares' 'Collection' 'T1039, T1005' 'FS' $true @(
        (New-Src 'Security' @(4663) @('File System:1') 'SaclReq'))),
    (New-UseCase 'UC27' 'Removable storage use' 'Exfiltration' 'T1052.001' 'ALL' $false @(
        (New-Src 'Security' @(4663) @('Removable Storage:1') '' '6.2'),
        (New-Src 'Microsoft-Windows-DriverFrameworks-UserMode/Operational' @(2003, 2100)))),
    (New-UseCase 'UC28' 'Process network connections' 'Command and Control' 'T1071, T1105' 'ALL' $false @(
        (New-Src $SysmonLog @(3)),
        (New-Src 'Security' @(5156) @('Filtering Platform Connection:1')))),
    (New-UseCase 'UC29' 'BITS jobs' 'Persistence' 'T1197' 'ALL' $false @(
        (New-Src 'Microsoft-Windows-Bits-Client/Operational' @(3, 59, 60)))),
    (New-UseCase 'UC30' 'Event log clearing' 'Defense Evasion' 'T1070.001' 'ALL' $true @(
        (New-Src 'Security' @(1102)),
        (New-Src 'System' @(104)))),
    (New-UseCase 'UC31' 'Audit policy tampering' 'Defense Evasion' 'T1562.002' 'ALL' $true @(
        (New-Src 'Security' @(4719) @('Audit Policy Change:1')))),
    (New-UseCase 'UC32' 'Firewall rule changes' 'Defense Evasion' 'T1562.004' 'ALL' $false @(
        (New-Src 'Security' @(4946, 4947, 4948, 4950) @('MPSSVC Rule-Level Policy Change:1')),
        (New-Src 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' @(2004, 2005, 2006, 2033)))),
    (New-UseCase 'UC33' 'Defender detections and tampering' 'Defense Evasion' 'T1562.001' 'ALL' $true @(
        (New-Src 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117, 5001, 5007) @() '' '10.0'))),
    (New-UseCase 'UC34' 'System time change (timestamp manipulation)' 'Defense Evasion' 'T1070.006' 'ALL' $false @(
        (New-Src 'Security' @(4616) @('Security State Change:1')))),
    (New-UseCase 'UC35' 'Driver / unsigned code loading' 'Defense Evasion' 'T1014, T1068' 'ALL' $false @(
        (New-Src $SysmonLog @(6)),
        (New-Src 'Microsoft-Windows-CodeIntegrity/Operational' @(3033, 3063, 3077) @() '' '6.1'))),
    (New-UseCase 'UC36' 'Local user / group enumeration' 'Discovery' 'T1087, T1069' 'ALL' $false @(
        (New-Src 'Security' @(4798, 4799) @('User Account Management:1', 'Security Group Management:1') '' '10.0'))),
    (New-UseCase 'UC37' 'DNS zone / record changes' 'Command and Control' 'T1584.002' 'DNS' $false @(
        (New-Src 'Microsoft-Windows-DNSServer/Audit' @(513, 515, 516, 519, 520, 541) @() '' '6.3')))
)
$TacticOrder = @('Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration')

# Command lines / script blocks that disable or erase logging (-DeepScan) are read from anti-logging-patterns.txt
# next to the script: the attacker strings they contain would make AMSI block this script.
function Get-AntiLoggingPatterns {
    $list = New-Object System.Collections.ArrayList
    if (-not $ScriptPath) { return ,$list }
    $f = Join-Path (Split-Path $ScriptPath -Parent) 'anti-logging-patterns.txt'
    if (-not (Test-Path -LiteralPath $f)) { return ,$list }
    foreach ($line in @(Get-Content -LiteralPath $f)) {
        if (-not $line -or $line.StartsWith('#')) { continue }
        $p = $line.Split("`t")
        if ($p.Count -lt 2) { continue }
        try { [void]$list.Add(@{ Name = $p[0].Trim(); Rx = (New-Object regex($p[1].Trim(), 'IgnoreCase')) }) } catch { }
    }
    return ,$list
}

# =====================================================================================================
#  Generic helpers
# =====================================================================================================
$script:RunLog = New-Object System.Collections.ArrayList
$script:RegLog = New-Object System.Collections.ArrayList
$script:Findings = New-Object System.Collections.ArrayList
$script:ComplianceOn = $false
$script:Workflow = New-Object System.Collections.ArrayList
$SevRank = @{ Critical = 5; High = 4; Medium = 3; Low = 2; Info = 1 }

function Write-Step([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} {1,-5} {2}' -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    [void]$script:RunLog.Add($line)
    $color = 'Gray'
    switch ($Level) { 'STEP' { $color = 'Cyan' } 'OK' { $color = 'Green' } 'WARN' { $color = 'Yellow' } 'ERROR' { $color = 'Red' } }
    Write-Host $line -ForegroundColor $color
}

function Add-Workflow([string]$Check, [string]$Status, [string]$Note = '') {
    [void]$script:Workflow.Add((New-Object PSObject -Property @{ Check = $Check; Status = $Status; Note = $Note }))
}

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Title, [string]$Detail = '', [string]$Evidence = '',
          [string]$Recommendation = '', [string]$Mitre = '')
    [void]$script:Findings.Add((New-Object PSObject -Property @{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail; Evidence = $Evidence
        Recommendation = $Recommendation; Mitre = $Mitre; Rank = $SevRank[$Severity] }))
}

function Import-ComplianceMap([string]$Path) {
    $map = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    foreach ($row in @(Import-Csv -LiteralPath $Path)) {
        $k = ''; if ($row.key) { $k = ([string]$row.key).Trim() }
        if (-not $k -or $k.StartsWith('#')) { continue }
        if (-not $row.framework -or -not $row.control) { continue }
        if (-not $map.ContainsKey($k)) { $map[$k] = New-Object System.Collections.ArrayList }
        [void]$map[$k].Add(([string]$row.framework).Trim() + ':' + ([string]$row.control).Trim())
    }
    if ($map.Count -eq 0) { return $null }
    return $map
}

function Get-ComplianceControls($Map, [string]$Mitre, [string]$Category) {
    $ids = New-Object System.Collections.ArrayList
    if ($Mitre) {
        foreach ($t in @($Mitre -split '[,;\s]+')) {
            if (-not $t) { continue }
            $probe = $t
            while ($probe) {
                if ($Map.ContainsKey($probe)) {
                    foreach ($x in $Map[$probe]) { if (-not $ids.Contains($x)) { [void]$ids.Add($x) } }
                    break
                }
                $cut = $probe.LastIndexOf('.')
                if ($cut -gt 1) { $probe = $probe.Substring(0, $cut) } else { break }
            }
        }
    }
    if ($ids.Count -eq 0 -and $Category) {
        $k = 'category:' + $Category.ToLower()
        if ($Map.ContainsKey($k)) { foreach ($x in $Map[$k]) { if (-not $ids.Contains($x)) { [void]$ids.Add($x) } } }
    }
    return ($ids -join ';')
}

function Num($Value, [string]$Format = '0.##') {
    if ($null -eq $Value) { return '' }
    return ([double]$Value).ToString($Format, $Inv)
}

function Format-Span($Hours) {
    if ($null -eq $Hours) { return 'n/a' }
    $h = [double]$Hours
    if ($h -lt 1) { return ('{0} min' -f [Math]::Round($h * 60)) }
    if ($h -lt 48) { return ((Num $h '0.#') + ' h') }
    if ($h -lt 24 * 120) { return ((Num ($h / 24) '0.#') + ' days') }
    return ((Num ($h / 24 / 30.44) '0.#') + ' months')
}

function Format-Date($Date) {
    if ($null -eq $Date) { return '' }
    return ([datetime]$Date).ToString('yyyy-MM-dd HH:mm:ss', $Inv)
}

function Format-Size($Bytes) {
    if ($null -eq $Bytes) { return '' }
    $b = [double]$Bytes
    if ($b -ge 1GB) { return ((Num ($b / 1GB) '0.##') + ' GB') }
    if ($b -ge 1MB) { return ((Num ($b / 1MB) '0.#') + ' MB') }
    return ((Num ($b / 1KB) '0') + ' KB')
}

function Esc($Text) {
    if ($null -eq $Text) { return '' }
    return (([string]$Text) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;')
}

function Get-Sha256Bytes([byte[]]$Bytes) {
    $alg = [Security.Cryptography.SHA256]::Create()
    try { return (($alg.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $alg.Clear() }
}

function Get-FileSha256([string]$Path) {
    $alg = [Security.Cryptography.SHA256]::Create(); $fs = $null
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        return (($alg.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch { return '' } finally { if ($fs) { $fs.Close() }; $alg.Clear() }
}

function Get-RegValue([string]$Path, [string]$Name) {
    $value = $null
    try { $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { }
    $shown = $value
    if ($null -eq $value) { $shown = '<not set>' }
    elseif ($value -is [byte[]]) { $shown = '<binary, {0} bytes>' -f $value.Length }
    elseif ($value -is [array]) { $shown = ($value -join ' | ') }
    [void]$script:RegLog.Add(('{0} : {1} = {2}' -f $Path, $Name, $shown))
    if ($value -is [array]) { return ,$value }
    return $value
}

function Read-FileTail([string]$Path, [long]$Bytes = 2MB) {
    $fs = $null
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        if ($fs.Length -gt $Bytes) { [void]$fs.Seek(-$Bytes, [IO.SeekOrigin]::End) }
        $text = (New-Object IO.StreamReader($fs)).ReadToEnd()
        return ,($text -split "`r?`n")
    } catch { return ,@() } finally { if ($fs) { $fs.Close() } }
}

function Read-FileHead([string]$Path, [int]$Bytes = 65536) {
    $fs = $null
    try {
        $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        $buf = New-Object byte[] ([int][Math]::Min([long]$Bytes, $fs.Length))
        $n = $fs.Read($buf, 0, $buf.Length)
        $enc = [Text.Encoding]::UTF8
        if ($n -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { $enc = [Text.Encoding]::Unicode }
        return ,($enc.GetString($buf, 0, $n) -split "`r?`n")
    } catch { return ,@() } finally { if ($fs) { $fs.Close() } }
}

function Get-FirstIsoDate([string]$Path) {
    foreach ($line in (Read-FileHead $Path)) {
        if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
            $d = [datetime]::MinValue
            if ([datetime]::TryParseExact($matches[1], 'yyyy-MM-dd HH:mm:ss', $Inv, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$d)) { return $d }
        }
    }
    return $null
}

function Invoke-Native([string]$Exe, [string]$Arguments, [string]$OutFile, [int]$TimeoutSec = 120) {
    $errFile = $OutFile + '.stderr.txt'
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -RedirectStandardOutput $OutFile -RedirectStandardError $errFile -NoNewWindow -PassThru -ErrorAction Stop
        $null = $p.Handle
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; return -1 }
        if ((Test-Path -LiteralPath $errFile) -and (Get-Item -LiteralPath $errFile).Length -eq 0) { Remove-Item -LiteralPath $errFile -Force }
        return $p.ExitCode
    } catch { return -2 }
}

function Get-AuditText($Value) {
    if ($null -eq $Value) { return '' }
    switch ([int]$Value) { 0 { return 'No Auditing' } 1 { return 'Success' } 2 { return 'Failure' } 3 { return 'Success and Failure' } }
    return ''
}

function Get-BitCount([int]$Value) { return ($Value -band 1) + (($Value -band 2) / 2) }

function Get-ShortLogName([string]$Name) {
    $n = $Name -replace '^Microsoft-Windows-', ''
    $n = $n -replace '^TerminalServices-LocalSessionManager', 'RDP-LocalSessionManager' -replace '^TerminalServices-RemoteConnectionManager', 'RDP-RemoteConnectionManager'
    $n = $n -replace '^Windows Firewall With Advanced Security', 'Firewall'
    return $n
}

function Get-Log([string]$Name) {
    $k = $Name.ToLower()
    if ($script:Logs -and $script:Logs.ContainsKey($k)) { return $script:Logs[$k] }
    return $null
}

function Test-RoleApplies([string]$Roles) {
    if ($Roles -eq 'ALL') { return $true }
    foreach ($r in ($Roles -split ',')) { if ($script:Sys.Roles -contains $r.Trim()) { return $true } }
    return $false
}

# =====================================================================================================
#  Event log access (EventLogReader API, classic System.Diagnostics.EventLog fallback without .NET 3.5)
# =====================================================================================================
function New-EventReader([string]$LogName, [string]$XPath, [bool]$Reverse) {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, $script:LogPathType, $XPath)
    $q.ReverseDirection = $Reverse
    return (New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q))
}

function Get-EdgeEvent([string]$LogName, [bool]$Oldest) {
    $reader = $null
    try {
        $reader = New-EventReader $LogName '*' (-not $Oldest)
        $e = $reader.ReadEvent()
        if ($null -ne $e) {
            $r = @{ Time = $e.TimeCreated; RecordId = $e.RecordId }
            $e.Dispose()
            return $r
        }
    } catch { } finally { if ($reader) { $reader.Dispose() } }
    return $null
}

function Convert-EventRecord($e, [string]$LogName) {
    $props = New-Object System.Collections.ArrayList
    try {
        foreach ($p in $e.Properties) {
            $v = $p.Value
            if ($v -is [datetime]) { [void]$props.Add($v.ToUniversalTime().ToString('o')) } else { [void]$props.Add([string]$v) }
        }
    } catch { }
    $user = ''
    try { if ($e.UserId) { $user = $e.UserId.Value } } catch { }
    return @{ Log = $LogName; Id = [int]$e.Id; Time = $e.TimeCreated; RecordId = $e.RecordId; Props = $props.ToArray(); User = $user; Xml = '' }
}

function Get-ClassicEvents([string]$LogName, [int[]]$Ids, [int]$Max) {
    $out = New-Object System.Collections.ArrayList
    try {
        $el = New-Object System.Diagnostics.EventLog($LogName)
        $n = $el.Entries.Count
        $stop = [Math]::Max(0, $n - 50000)
        for ($i = $n - 1; $i -ge $stop -and $out.Count -lt $Max; $i--) {
            $en = $el.Entries[$i]
            $id = [int]($en.InstanceId -band 0xFFFF)
            if ($Ids -contains $id) {
                [void]$out.Add(@{ Log = $LogName; Id = $id; Time = $en.TimeGenerated; RecordId = $en.Index; Props = @($en.ReplacementStrings); User = [string]$en.UserName; Xml = '' })
            }
        }
        $el.Dispose()
    } catch { Write-Step ('Classic query {0} failed: {1}' -f $LogName, $_.Exception.Message) 'WARN' }
    return ,$out
}

function Get-Events([string]$LogName, [int[]]$Ids, [int]$Max = 500, [switch]$WithXml) {
    $out = New-Object System.Collections.ArrayList
    $L = Get-Log $LogName
    if (-not $L -or -not ($L.Records -gt 0)) { return ,$out }
    if (-not $script:HasReader) { $out = Get-ClassicEvents $LogName $Ids $Max; return ,$out }
    $xp = '*[System[(' + (($Ids | ForEach-Object { 'EventID=' + $_ }) -join ' or ') + ')]]'
    $reader = $null
    try {
        $reader = New-EventReader $LogName $xp $true
        while ($out.Count -lt $Max) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            $o = Convert-EventRecord $e $LogName
            if ($WithXml) { try { $o.Xml = $e.ToXml() } catch { } }
            $e.Dispose()
            [void]$out.Add($o)
        }
    } catch {
        Write-Step ('Query {0} failed: {1}' -f $LogName, $_.Exception.Message) 'WARN'
    } finally { if ($reader) { $reader.Dispose() } }
    return ,$out
}

function Get-PropTime($Value) {
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, $Inv, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $d.ToLocalTime() }
    return $null
}

# =====================================================================================================
#  System profile, OS dependent workflow, server roles
# =====================================================================================================
function Get-OsFamily($Nt, [int]$Build, [bool]$IsServer) {
    $k = '{0}.{1}' -f $Nt.Major, $Nt.Minor
    if ($IsServer) {
        switch ($k) { '6.0' { return 'Windows Server 2008' } '6.1' { return 'Windows Server 2008 R2' } '6.2' { return 'Windows Server 2012' } '6.3' { return 'Windows Server 2012 R2' } }
        if ($Nt.Major -ge 10) {
            if ($Build -ge 26100) { return 'Windows Server 2025' }
            if ($Build -ge 20348) { return 'Windows Server 2022' }
            if ($Build -ge 17763) { return 'Windows Server 2019' }
            return 'Windows Server 2016'
        }
    } else {
        switch ($k) { '6.0' { return 'Windows Vista' } '6.1' { return 'Windows 7' } '6.2' { return 'Windows 8' } '6.3' { return 'Windows 8.1' } }
        if ($Nt.Major -ge 10) { if ($Build -ge 22000) { return 'Windows 11' }; return 'Windows 10' }
    }
    return "Windows NT $k"
}

function Get-SystemProfile {
    $sys = @{ Host = $env:COMPUTERNAME; Domain = ''; Caption = ''; Version = ''; Build = 0; NT = $null; Family = ''; ProductType = 3; IsServer = $true
        Boot = $null; UptimeHours = $null; TimeZone = ''; PSHost = $PSVersionTable.PSVersion.ToString(); PSInstalled = $null; Roles = @(); Shares = @()
        RdpEnabled = $false; Admin = $false; User = ''; Arch = $env:PROCESSOR_ARCHITECTURE }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $sys.User = $id.Name
        $sys.Admin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        $v = [version]$os.Version
        $sys.NT = New-Object Version($v.Major, $v.Minor)
        $sys.Build = [int]$os.BuildNumber
        $sys.Caption = ([string]$os.Caption).Trim()
        $sys.Version = [string]$os.Version
        $sys.ProductType = [int]$os.ProductType
        $sys.IsServer = ($sys.ProductType -ne 1)
        $sys.Domain = [string]$cs.Domain
        try { $sys.Boot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime); $sys.UptimeHours = ($script:RunStart - $sys.Boot).TotalHours } catch { }
    } catch {
        $v = [Environment]::OSVersion.Version
        $sys.NT = New-Object Version($v.Major, $v.Minor); $sys.Build = $v.Build; $sys.Version = $v.ToString()
        $pt = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' 'ProductType'
        if ($pt -eq 'WinNT') { $sys.ProductType = 1 } elseif ($pt -eq 'LanmanNT') { $sys.ProductType = 2 }
        $sys.IsServer = ($sys.ProductType -ne 1)
    }
    $sys.Family = Get-OsFamily $sys.NT $sys.Build $sys.IsServer
    if (-not $sys.Caption) { $sys.Caption = $sys.Family }
    try { $sys.TimeZone = [TimeZoneInfo]::Local.DisplayName } catch { $sys.TimeZone = [string](Get-WmiObject Win32_TimeZone).Caption }
    $psv = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' 'PowerShellVersion'
    if (-not $psv) { $psv = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion' }
    try { $sys.PSInstalled = [version]$psv } catch { $sys.PSInstalled = $PSVersionTable.PSVersion }

    # roles
    $roles = New-Object System.Collections.ArrayList
    if ($sys.ProductType -eq 2) { [void]$roles.Add('DC') }
    $map = @{ dns = 'DNS'; dhcpserver = 'DHCP'; certsvc = 'CA'; w3svc = 'IIS'; msexchangeis = 'EXCH'; msexchangetransport = 'EXCH'
        mssqlserver = 'SQL'; vmms = 'HV'; adfssrv = 'ADFS'; ias = 'NPS'; wsusservice = 'WSUS' }
    foreach ($k in $map.Keys) { if ($script:Svc.ContainsKey($k) -and -not ($roles -contains $map[$k])) { [void]$roles.Add($map[$k]) } }
    foreach ($k in $script:Svc.Keys) { if ($k -like 'mssql$*' -and -not ($roles -contains 'SQL')) { [void]$roles.Add('SQL') } }
    $shares = New-Object System.Collections.ArrayList
    try {
        $sk = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares' -ErrorAction Stop
        foreach ($n in $sk.GetValueNames()) {
            if (@('NETLOGON', 'SYSVOL', 'print$') -contains $n) { continue }
            $path = ''
            foreach ($l in @($sk.GetValue($n))) { if ($l -like 'Path=*') { $path = $l.Substring(5) } }
            [void]$shares.Add(@{ Name = $n; Path = $path })
        }
    } catch { }
    if ($shares.Count -gt 0) { [void]$roles.Add('FS') }
    $sys.Shares = $shares.ToArray()
    $sys.Roles = $roles.ToArray()
    $sys.RdpEnabled = ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
    return $sys
}

function Get-Capabilities {
    $nt = $script:Sys.NT
    $c = @{}
    $c.AdvancedAuditGpo = ($nt -ge [version]'6.1')
    $c.CmdLineNative = ($nt -ge [version]'6.3')
    $c.CmdLineHotfix = $false
    if (-not $c.CmdLineNative -and $nt -ge [version]'6.1') {
        $c.CmdLineHotfix = [bool](Get-WmiObject Win32_QuickFixEngineering -Filter "HotFixID='KB3004375'" -ErrorAction SilentlyContinue)
    }
    $c.CmdLineSupported = ($c.CmdLineNative -or $c.CmdLineHotfix)
    $psv = $script:Sys.PSInstalled
    $c.PS5 = ($psv -ge [version]'5.0')
    $c.SbHotfix = $false
    if (-not $c.PS5 -and $psv -ge [version]'4.0') {
        $c.SbHotfix = [bool](Get-WmiObject Win32_QuickFixEngineering -Filter "HotFixID='KB3000850'" -ErrorAction SilentlyContinue)
    }
    $c.ScriptBlockSupported = ($c.PS5 -or $c.SbHotfix)
    $c.Defender = ($nt.Major -ge 10)
    $c.WmiActivity = ($nt -ge [version]'6.3')

    # record the version driven workflow
    $os = $script:Sys.Family
    Add-Workflow 'OS profile' 'Executed' ('{0} (NT {1}, build {2}), installed PowerShell {3}, running PowerShell {4}' -f $os, $nt, $script:Sys.Build, $psv, $script:Sys.PSHost)
    if ($script:HasReader) { Add-Workflow 'Event log API' 'Executed' 'EventLogReader (all channels, XPath queries)' }
    else { Add-Workflow 'Event log API' 'Degraded' '.NET 3.5 event API missing: classic logs only (Security/System/Application)' }
    if ($c.AdvancedAuditGpo) { Add-Workflow 'Advanced audit policy' 'Executed' 'auditpol backup + GPO audit.csv comparison' }
    else { Add-Workflow 'Advanced audit policy' 'Executed' 'Windows 2008: advanced audit only via auditpol / logon script (no GPO audit.csv)' }
    if ($c.CmdLineNative) { Add-Workflow '4688 command line' 'Executed' 'Supported natively' }
    elseif ($c.CmdLineHotfix) { Add-Workflow '4688 command line' 'Executed' 'Supported through KB3004375' }
    else { Add-Workflow '4688 command line' 'Not supported' 'Requires Windows Server 2012 R2 or KB3004375 (2008 R2 / 2012)' }
    if ($c.ScriptBlockSupported) { Add-Workflow 'PowerShell script block logging' 'Executed' ('PowerShell {0}' -f $psv) }
    else { Add-Workflow 'PowerShell script block logging' 'Not supported' ('PowerShell {0}: requires WMF 5.1 (or WMF 4 + KB3000850)' -f $psv) }
    if (-not $c.Defender) { Add-Workflow 'Defender channel' 'Skipped' 'Microsoft Defender event channel exists from Windows Server 2016' }
    if (-not $c.WmiActivity) { Add-Workflow 'WMI-Activity 5857-5861' 'Skipped' 'Detailed WMI activity events exist from Windows Server 2012 R2' }
    return $c
}

# =====================================================================================================
#  Log inventory
# =====================================================================================================
function New-LogEntry([string]$Name) {
    return @{ Name = $Name; Enabled = $true; Mode = ''; MaxBytes = [long]0; Type = ''; Path = ''; Classic = $false; Records = $null
        FileBytes = $null; IsFull = $false; Oldest = $null; Newest = $null; OldestRid = $null; NewestRid = $null; SpanHours = $null
        Rate = $null; CapacityHours = $null; FillPct = $null; Wrapping = $false; Readable = $true; Error = ''; Status = '' }
}

function Complete-LogDerived($e) {
    if ($e.Oldest -and $e.Newest) {
        $span = ($e.Newest - $e.Oldest).TotalHours
        if ($span -lt 0) { $span = 0 }
        $e.SpanHours = $span
        if ($e.Records -gt 0) { $e.Rate = $e.Records / [Math]::Max($span, 1.0 / 60) }
    }
    if ($e.MaxBytes -gt 0 -and $e.FileBytes -gt 0) {
        $e.FillPct = [Math]::Min(100.0, 100.0 * $e.FileBytes / $e.MaxBytes)
        $e.Wrapping = ($e.FillPct -ge 95 -and $e.Mode -eq 'Circular')
        if ($e.SpanHours -gt 0) { $e.CapacityHours = $e.SpanHours * [Math]::Max(1.0, $e.MaxBytes / [double]$e.FileBytes) }
    }
    if (-not $e.Readable) { $e.Status = 'Access denied' }
    elseif (-not $e.Enabled) { $e.Status = 'Disabled' }
    elseif (-not ($e.Records -gt 0)) { $e.Status = 'Empty' }
    elseif ($e.Mode -eq 'Retain' -and $e.IsFull) { $e.Status = 'FULL - new events dropped' }
    elseif ($e.Wrapping) { $e.Status = 'Overwriting oldest events' }
    elseif ($e.Mode -eq 'AutoBackup' -and $e.FillPct -ge 95) { $e.Status = 'Archiving when full' }
    else { $e.Status = 'OK' }
}

function Get-LogInventory {
    $inv = @{}
    if ($script:HasReader) {
        $session = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession
        $names = @()
        try { $names = @($session.GetLogNames()) } catch { Write-Step ('Cannot enumerate event logs: ' + $_.Exception.Message) 'ERROR' }
        foreach ($n in $names) {
            $e = New-LogEntry $n
            try {
                $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($n, $session)
                $e.Enabled = [bool]$cfg.IsEnabled; $e.Mode = [string]$cfg.LogMode; $e.MaxBytes = [long]$cfg.MaximumSizeInBytes
                $e.Type = [string]$cfg.LogType; $e.Classic = [bool]$cfg.IsClassicLog
                $e.Path = [Environment]::ExpandEnvironmentVariables([string]$cfg.LogFilePath)
                $cfg.Dispose()
            } catch { $e.Error = $_.Exception.Message }
            try {
                $info = $session.GetLogInformation($n, $script:LogPathType)
                $e.Records = $info.RecordCount; $e.FileBytes = $info.FileSize; $e.IsFull = [bool]$info.IsLogFull
            } catch { $e.Readable = $false; if (-not $e.Error) { $e.Error = $_.Exception.Message } }
            $inv[$n.ToLower()] = $e
        }
        foreach ($e in $inv.Values) {
            if ($e.Records -gt 0 -and $e.Type -ne 'Analytical' -and $e.Type -ne 'Debug') {
                $o = Get-EdgeEvent $e.Name $true
                $nw = Get-EdgeEvent $e.Name $false
                if ($o) { $e.Oldest = $o.Time; $e.OldestRid = $o.RecordId }
                if ($nw) { $e.Newest = $nw.Time; $e.NewestRid = $nw.RecordId }
            }
            Complete-LogDerived $e
        }
    } else {
        foreach ($el in @([System.Diagnostics.EventLog]::GetEventLogs())) {
            $e = New-LogEntry $el.Log
            try {
                $e.Classic = $true; $e.Type = 'Administrative'; $e.MaxBytes = [long]$el.MaximumKilobytes * 1024
                switch ([string]$el.OverflowAction) { 'OverwriteAsNeeded' { $e.Mode = 'Circular' } 'DoNotOverwrite' { $e.Mode = 'Retain' } default { $e.Mode = [string]$el.OverflowAction } }
                $n = $el.Entries.Count; $e.Records = $n
                if ($n -gt 0) {
                    $e.Oldest = $el.Entries[0].TimeGenerated; $e.OldestRid = $el.Entries[0].Index
                    $e.Newest = $el.Entries[$n - 1].TimeGenerated; $e.NewestRid = $el.Entries[$n - 1].Index
                }
                $f = Get-RegValue ('HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\' + $el.Log) 'File'
                if ($f) { $e.Path = [Environment]::ExpandEnvironmentVariables([string]$f); if (Test-Path -LiteralPath $e.Path) { $e.FileBytes = (Get-Item -LiteralPath $e.Path).Length } }
            } catch { $e.Readable = $false; $e.Error = $_.Exception.Message }
            Complete-LogDerived $e
            $inv[$el.Log.ToLower()] = $e
        }
    }
    return $inv
}

function Get-ArchivedLogs {
    $res = @{}
    $dirs = @{}
    $def = Join-Path $env:SystemRoot 'System32\winevt\Logs'
    $dirs[$def.ToLower()] = $def
    foreach ($e in $script:Logs.Values) {
        if ($e.Path -and ($e.Mode -eq 'AutoBackup' -or $e.Path -notlike "$def*")) { $d = Split-Path $e.Path -Parent; if ($d) { $dirs[$d.ToLower()] = $d } }
    }
    foreach ($d in $dirs.Values) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter 'Archive-*.evt*' -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch '^Archive-(.+)-(\d{4})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{3})\.evtx?$') { continue }
            $log = $matches[1] -replace '%4', '/'
            $ts = (New-Object DateTime([int]$matches[2], [int]$matches[3], [int]$matches[4], [int]$matches[5], [int]$matches[6], [int]$matches[7], [DateTimeKind]::Utc)).ToLocalTime()
            $k = $log.ToLower()
            if (-not $res.ContainsKey($k)) { $res[$k] = @{ Log = $log; Count = 0; Bytes = [long]0; First = $ts; Last = $ts; Folder = $d } }
            $a = $res[$k]
            $a.Count++; $a.Bytes += $f.Length
            if ($ts -lt $a.First) { $a.First = $ts }
            if ($ts -gt $a.Last) { $a.Last = $ts }
        }
    }
    return $res
}

# =====================================================================================================
#  Audit policy
# =====================================================================================================
function Read-AuditCsv([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $map = @{}
    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
        $rows = @($lines | Select-Object -Skip 1 | ConvertFrom-Csv -Header 'Machine', 'Target', 'Sub', 'Guid', 'Incl', 'Excl', 'Value')
        foreach ($r in $rows) {
            $g = [string]$r.Guid
            if ($g -notmatch '^\s*\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?\s*$') { continue }
            $g = '{' + $g.Trim().TrimStart('{').TrimEnd('}').ToUpper() + '}'
            $v = 0
            [void][int]::TryParse(([string]$r.Value).Trim(), [ref]$v)
            $map[$g] = @{ Value = ($v -band 3); Name = [string]$r.Sub }
        }
    } catch { Write-Step ('Cannot parse {0}: {1}' -f $Path, $_.Exception.Message) 'WARN' }
    return $map
}

function Get-AuditPolicyState {
    $st = @{ Available = $false; Effective = @{}; Gpo = $null; LocalGpo = $null; Error = ''; NoLegacy = $null; AllOff = $false }
    $file = Join-Path $script:RawDir 'auditpol_effective.csv'
    $out = & auditpol.exe /backup "/file:$file" 2>&1
    if (-not (Test-Path -LiteralPath $file)) {
        $tmp = Join-Path $env:TEMP ('lga_{0}.csv' -f [guid]::NewGuid().ToString('N'))
        $out = & auditpol.exe /backup "/file:$tmp" 2>&1
        if (Test-Path -LiteralPath $tmp) { Move-Item -LiteralPath $tmp -Destination $file -Force }
    }
    $map = Read-AuditCsv $file
    if ($map -and $map.Count -gt 0) {
        $st.Available = $true
        $st.Effective = $map
        $on = 0; foreach ($v in $map.Values) { if ($v.Value -gt 0) { $on++ } }
        $st.AllOff = ($on -eq 0)
        & auditpol.exe /get /category:* 2>&1 | Out-File -FilePath (Join-Path $script:RawDir 'auditpol_get_all.txt') -Encoding UTF8
    } else {
        $st.Error = (($out | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -notmatch '^System\.Management\.Automation' }) -join ' ').Trim()
        if (-not $st.Error) { $st.Error = 'auditpol returned no data' }
        Write-Step ('Audit policy not readable: ' + $st.Error) 'WARN'
    }
    $gpoFile = Join-Path $env:SystemRoot 'security\audit\audit.csv'
    if (Test-Path -LiteralPath $gpoFile) {
        $st.Gpo = Read-AuditCsv $gpoFile
        Copy-Item -LiteralPath $gpoFile -Destination (Join-Path $script:RawDir 'gpo_applied_audit.csv') -ErrorAction SilentlyContinue
    }
    $lgpo = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'
    if (Test-Path -LiteralPath $lgpo) {
        $st.LocalGpo = Read-AuditCsv $lgpo
        Copy-Item -LiteralPath $lgpo -Destination (Join-Path $script:RawDir 'local_gpo_audit.csv') -ErrorAction SilentlyContinue
    }
    $st.NoLegacy = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
    return $st
}

function Get-EffectiveAudit([string]$SubName) {
    # $null = unknown (not readable), -1 = subcategory not available on this OS
    if (-not $script:Audit.Available) { return $null }
    $s = $script:SubByName[$SubName]
    if (-not $s) { return $null }
    if ($script:Audit.Effective.ContainsKey($s.Guid)) { return [int]$script:Audit.Effective[$s.Guid].Value }
    return -1
}

# =====================================================================================================
#  Logging configuration
# =====================================================================================================
function Get-SysmonState {
    $s = @{ Installed = $false; Driver = ''; DriverState = ''; Service = ''; ServiceState = ''; StartMode = ''; Version = ''; ConfigHash = ''
        Hashing = ''; Renamed = $false; Image = '' }
    $root = $null
    try {
        $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services')
        foreach ($name in $root.GetSubKeyNames()) {
            $pk = $null
            try {
                $pk = $root.OpenSubKey($name + '\Parameters')
                if ($pk -and $null -ne $pk.GetValue('HashingAlgorithm') -and $null -ne $pk.GetValue('Options')) {
                    $s.Installed = $true; $s.Driver = $name
                    $s.Hashing = [string]$pk.GetValue('HashingAlgorithm')
                    $rules = $pk.GetValue('Rules')
                    if ($rules -is [byte[]]) { $s.ConfigHash = Get-Sha256Bytes $rules }
                }
            } catch { } finally { if ($pk) { $pk.Close() } }
            if ($s.Installed) { break }
        }
    } catch { } finally { if ($root) { $root.Close() } }
    foreach ($svc in $script:Svc.Values) {
        if ([string]$svc.Description -eq 'System Monitor service' -or [string]$svc.PathName -match '\\sysmon(64)?a?\.exe') {
            $s.Installed = $true; $s.Service = $svc.Name; $s.ServiceState = $svc.State; $s.StartMode = $svc.StartMode
            $s.Image = ([string]$svc.PathName).Trim('"')
            try { $s.Version = [Diagnostics.FileVersionInfo]::GetVersionInfo($s.Image).FileVersion } catch { }
            break
        }
    }
    if ($s.Driver) {
        try { $d = Get-WmiObject Win32_SystemDriver -Filter ("Name='{0}'" -f $s.Driver) -ErrorAction Stop; if ($d) { $s.DriverState = $d.State } } catch { }
        $s.Renamed = ($s.Driver -ne 'SysmonDrv')
    }
    return $s
}

function Get-LoggingConfig {
    $c = @{}
    $c.CmdLine = ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled') -eq 1)
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $c.ScriptBlock = ((Get-RegValue "$p\ScriptBlockLogging" 'EnableScriptBlockLogging') -eq 1)
    $c.ScriptBlockInvocation = ((Get-RegValue "$p\ScriptBlockLogging" 'EnableScriptBlockInvocationLogging') -eq 1)
    $c.ModuleLogging = ((Get-RegValue "$p\ModuleLogging" 'EnableModuleLogging') -eq 1)
    $names = @()
    try { $mk = Get-Item -LiteralPath "$p\ModuleLogging\ModuleNames" -ErrorAction Stop; $names = @($mk.GetValueNames() | ForEach-Object { [string]$mk.GetValue($_) }) } catch { }
    $c.ModuleNames = ($names -join ', ')
    $c.Transcription = ((Get-RegValue "$p\Transcription" 'EnableTranscripting') -eq 1)
    $c.TranscriptDir = [string](Get-RegValue "$p\Transcription" 'OutputDirectory')
    $c.PSv2Engine = [bool](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion')
    $c.NetFx2 = ((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727' 'Install') -eq 1)
    $c.PSv2Usable = ($c.PSv2Engine -and $c.NetFx2 -and $script:Sys.PSInstalled -ge [version]'3.0')
    $c.PSCoreScriptBlock = ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)

    $c.Sysmon = Get-SysmonState

    # firewall logging (policy overrides local setting)
    $fw = New-Object System.Collections.ArrayList
    foreach ($pr in @(@('Domain', 'DomainProfile', 'DomainProfile'), @('Private', 'PrivateProfile', 'StandardProfile'), @('Public', 'PublicProfile', 'PublicProfile'))) {
        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\' + $pr[1] + '\Logging'
        $loc = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $pr[2] + '\Logging'
        $vals = @{}
        foreach ($n in 'LogDroppedPackets', 'LogSuccessfulConnections', 'LogFilePath', 'LogFileSize') {
            $v = Get-RegValue $pol $n
            if ($null -eq $v) { $v = Get-RegValue $loc $n }
            $vals[$n] = $v
        }
        $path = [string]$vals['LogFilePath']
        if (-not $path) { $path = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' }
        [void]$fw.Add(@{ Profile = $pr[0]; Dropped = ($vals['LogDroppedPackets'] -eq 1); Allowed = ($vals['LogSuccessfulConnections'] -eq 1)
            Path = [Environment]::ExpandEnvironmentVariables($path); SizeKB = $vals['LogFileSize'] })
    }
    $c.Firewall = $fw.ToArray()

    # NTLM auditing
    $c.NtlmIncoming = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic'
    $c.NtlmOutgoing = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic'
    $c.NtlmDomain = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain'
    $c.NtlmAudit = ($c.NtlmIncoming -ge 1 -or $c.NtlmOutgoing -eq 1 -or $c.NtlmDomain -ge 1)

    # Event Log service and known logging kill switches
    $el = $null; if ($script:Svc.ContainsKey('eventlog')) { $el = $script:Svc['eventlog'] }
    $c.EventLogState = ''; $c.EventLogStart = ''; $c.EventLogDisplay = 'Windows Event Log'
    if ($el) { $c.EventLogState = [string]$el.State; $c.EventLogStart = [string]$el.StartMode; $c.EventLogDisplay = [string]$el.DisplayName }
    else { $start = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' 'Start'; if ($start -eq 4) { $c.EventLogStart = 'Disabled' } }
    $c.MiniNt = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNt'
    $al = New-Object System.Collections.ArrayList
    foreach ($sess in 'EventLog-Security', 'EventLog-System', 'EventLog-Application', 'DefenderApiLogger', 'DefenderAuditLogger') {
        $kp = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\' + $sess
        if (-not (Test-Path -LiteralPath $kp)) { continue }
        $start = Get-RegValue $kp 'Start'
        $disabled = New-Object System.Collections.ArrayList
        foreach ($sub in @(Get-ChildItem -LiteralPath $kp -ErrorAction SilentlyContinue)) {
            $en = $sub.GetValue('Enabled')
            if ($null -ne $en -and [int]$en -eq 0) { [void]$disabled.Add($sub.PSChildName) }
        }
        [void]$al.Add(@{ Session = $sess; Start = $start; Disabled = ($disabled.ToArray() -join ', ') })
    }
    $c.Autologger = $al.ToArray()
    $c.LogPaths = @{}
    foreach ($n in 'Security', 'System', 'Application') {
        $L = Get-Log $n
        if ($L -and $L.Path) {
            $default = Join-Path $env:SystemRoot ('System32\winevt\Logs\' + $n + '.evtx')
            $c.LogPaths[$n] = @{ Path = $L.Path; Default = ($L.Path -eq $default) }
        }
    }

    # role specific logging
    $c.CA = @()
    if ($script:Sys.Roles -contains 'CA') {
        $cas = New-Object System.Collections.ArrayList
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -ErrorAction SilentlyContinue)) {
            [void]$cas.Add(@{ Name = $k.PSChildName; AuditFilter = $k.GetValue('AuditFilter') })
        }
        $c.CA = $cas.ToArray()
    }
    if ($script:Sys.Roles -contains 'DNS') {
        $c.DnsLogLevel = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'LogLevel'
        $c.DnsLogPath = [string](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' 'LogFilePath')
        if (-not $c.DnsLogPath) { $c.DnsLogPath = Join-Path $env:SystemRoot 'System32\dns\dns.log' }
    }
    if ($script:Sys.Roles -contains 'DHCP') {
        $c.DhcpAudit = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters' 'ActivityLogFlag'
        $c.DhcpLogPath = [string](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters' 'DhcpLogFilePath')
        if (-not $c.DhcpLogPath) { $c.DhcpLogPath = Join-Path $env:SystemRoot 'System32\dhcp' }
        $c.DhcpLogPath = [Environment]::ExpandEnvironmentVariables($c.DhcpLogPath)
    }
    if ($script:Sys.Roles -contains 'DC') {
        $c.LdapDiag = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' '16 LDAP Interface Events'
    }
    $c.IIS = $null
    if ($script:Sys.Roles -contains 'IIS') {
        $iis = @{ Enabled = $true; Directories = @(); Format = ''; Period = ''; Error = '' }
        try {
            $x = [xml][IO.File]::ReadAllText((Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'))
            $sites = $x.configuration.'system.applicationHost'.sites
            $dirs = New-Object System.Collections.ArrayList
            $sd = $sites.siteDefaults.logFile
            $dd = '%SystemDrive%\inetpub\logs\LogFiles'
            if ($sd) {
                if ($sd.enabled -eq 'false') { $iis.Enabled = $false }
                if ($sd.directory) { $dd = $sd.directory }
                $iis.Format = [string]$sd.logFormat; $iis.Period = [string]$sd.period
            }
            [void]$dirs.Add([Environment]::ExpandEnvironmentVariables($dd))
            foreach ($site in @($sites.site)) {
                if ($site -and $site.logFile -and $site.logFile.directory) {
                    $sdir = [Environment]::ExpandEnvironmentVariables($site.logFile.directory)
                    if (-not ($dirs -contains $sdir)) { [void]$dirs.Add($sdir) }
                }
            }
            $iis.Directories = $dirs.ToArray()
        } catch { $iis.Error = $_.Exception.Message }
        $c.IIS = $iis
    }
    return $c
}

function New-FileSource([string]$Name, [string]$Kind, [object[]]$Files, $Oldest, [string]$Note) {
    if (-not $Files -or $Files.Count -eq 0) { return $null }
    $min = $null; $max = $null; $bytes = [long]0
    foreach ($f in $Files) {
        $bytes += $f.Length
        if (-not $min -or $f.LastWriteTime -lt $min) { $min = $f.LastWriteTime }
        if (-not $max -or $f.LastWriteTime -gt $max) { $max = $f.LastWriteTime }
    }
    if ($Oldest -and $Oldest -lt $min) { $min = $Oldest }
    return @{ Name = $Name; Kind = $Kind; Oldest = $min; Newest = $max; Count = $Files.Count; Bytes = $bytes; Note = $Note }
}

function Get-FileLogSources {
    $res = New-Object System.Collections.ArrayList
    $cfg = $script:Cfg
    # firewall text log
    $paths = @{}
    foreach ($p in $cfg.Firewall) { if ($p.Dropped -or $p.Allowed) { $paths[$p.Path.ToLower()] = $p.Path } }
    foreach ($p in $paths.Values) {
        $files = @(@($p, ($p + '.old')) | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-Item -LiteralPath $_ })
        $first = $null
        foreach ($f in ($files | Sort-Object LastWriteTime)) { $first = Get-FirstIsoDate $f.FullName; if ($first) { break } }
        $src = New-FileSource 'Windows Firewall log' 'firewall' $files $first $p
        if ($src) { [void]$res.Add($src) }
    }
    if ($cfg.IIS) {
        foreach ($d in $cfg.IIS.Directories) {
            if (-not (Test-Path -LiteralPath $d)) { continue }
            $files = @(Get-ChildItem -LiteralPath $d -Recurse -Filter 'u_ex*.log' -ErrorAction SilentlyContinue)
            $oldest = $null
            foreach ($f in $files) {
                if ($f.Name -match '^u_ex(\d{2})(\d{2})(\d{2})') {
                    $t = New-Object DateTime((2000 + [int]$matches[1]), [int]$matches[2], [int]$matches[3])
                    if (-not $oldest -or $t -lt $oldest) { $oldest = $t }
                }
            }
            $src = New-FileSource 'IIS W3C logs' 'iis' $files $oldest $d
            if ($src) { [void]$res.Add($src) }
        }
    }
    if ($cfg.DhcpLogPath -and (Test-Path -LiteralPath $cfg.DhcpLogPath)) {
        $files = @(Get-ChildItem -LiteralPath $cfg.DhcpLogPath -Filter 'Dhcp*SrvLog-*.log' -ErrorAction SilentlyContinue)
        $src = New-FileSource 'DHCP audit logs' 'dhcp' $files $null ($cfg.DhcpLogPath + ' (weekly rotation, start approx.)')
        if ($src) { [void]$res.Add($src) }
    }
    if ($cfg.DnsLogPath -and $cfg.DnsLogLevel -and (Test-Path -LiteralPath $cfg.DnsLogPath)) {
        $f = Get-Item -LiteralPath $cfg.DnsLogPath
        $src = New-FileSource 'DNS debug log' 'dns' @($f) $f.CreationTime $cfg.DnsLogPath
        if ($src) { [void]$res.Add($src) }
    }
    if ($cfg.TranscriptDir -and (Test-Path -LiteralPath $cfg.TranscriptDir)) {
        $files = @(Get-ChildItem -LiteralPath $cfg.TranscriptDir -Recurse -Filter 'PowerShell_transcript*' -ErrorAction SilentlyContinue)
        $src = New-FileSource 'PowerShell transcripts' 'transcript' $files $null $cfg.TranscriptDir
        if ($src) { [void]$res.Add($src) }
    }
    return ,$res
}

# =====================================================================================================
#  Splunk Universal Forwarder and other forwarders
# =====================================================================================================
function Read-ConfFile([string]$Path, [hashtable]$Store, [string]$Label) {
    # callers pass files in precedence order: the first definition of a key wins
    $stanza = 'default'
    $buf = ''
    foreach ($raw in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $line = [string]$raw
        if ($buf) { $line = $buf + $line.TrimStart(); $buf = '' }
        if ($line.EndsWith('\')) { $buf = $line.Substring(0, $line.Length - 1); continue }
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#') -or $t.StartsWith(';')) { continue }
        if ($t -match '^\[(.+)\]$') { $stanza = $matches[1].Trim(); continue }
        if ($t -match '^([^=]+?)\s*=\s*(.*)$') {
            $sk = $stanza.ToLower()
            if (-not $Store.ContainsKey($sk)) { $Store[$sk] = @{ Name = $stanza; Settings = @{} } }
            $k = $matches[1].Trim().ToLower()
            if (-not $Store[$sk].Settings.ContainsKey($k)) { $Store[$sk].Settings[$k] = @{ Value = $matches[2].Trim(); File = $Label } }
        }
    }
}

function Get-SplunkConfFiles([string]$SplunkHome, [string]$Conf) {
    $list = New-Object System.Collections.ArrayList
    $sys = Join-Path $SplunkHome 'etc\system'
    $appsDir = Join-Path $SplunkHome 'etc\apps'
    $names = @()
    if (Test-Path -LiteralPath $appsDir) { $names = @(Get-ChildItem -LiteralPath $appsDir -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.Name }) }
    $sorted = [string[]]$names
    if ($sorted) { [Array]::Sort($sorted, [StringComparer]::Ordinal) }
    $apps = New-Object System.Collections.ArrayList
    foreach ($a in $sorted) {
        $dir = Join-Path $appsDir $a
        $st = @{}
        foreach ($f in @((Join-Path $dir 'local\app.conf'), (Join-Path $dir 'default\app.conf'))) { if (Test-Path -LiteralPath $f) { Read-ConfFile $f $st '' } }
        if ($st.ContainsKey('install') -and $st['install'].Settings.ContainsKey('state') -and $st['install'].Settings['state'].Value -eq 'disabled') { continue }
        [void]$apps.Add($dir)
    }
    $f = Join-Path $sys ('local\' + $Conf); if (Test-Path -LiteralPath $f) { [void]$list.Add($f) }
    foreach ($a in $apps) { $f = Join-Path $a ('local\' + $Conf); if (Test-Path -LiteralPath $f) { [void]$list.Add($f) } }
    foreach ($a in $apps) { $f = Join-Path $a ('default\' + $Conf); if (Test-Path -LiteralPath $f) { [void]$list.Add($f) } }
    $f = Join-Path $sys ('default\' + $Conf); if (Test-Path -LiteralPath $f) { [void]$list.Add($f) }
    return ,$list
}

function Get-ShortConfPath([string]$Path) {
    $h = $script:Splunk.Home
    if ($h -and $Path.StartsWith($h, [StringComparison]::OrdinalIgnoreCase)) { return $Path.Substring($h.Length).TrimStart('\') }
    return $Path
}

function Read-SplunkConf([string]$Conf) {
    # effective configuration: btool when possible, otherwise the .conf files in Splunk precedence order
    $store = @{}
    $exe = Join-Path $script:Splunk.Home 'bin\splunk.exe'
    if (-not $SkipSplunkBtool -and (Test-Path -LiteralPath $exe)) {
        $out = Join-Path $script:RawDir ('splunk_btool_{0}.txt' -f ($Conf -replace '\.conf$', ''))
        $rc = Invoke-Native $exe ('btool {0} list --debug' -f ($Conf -replace '\.conf$', '')) $out 120
        if ($rc -eq 0 -and (Test-Path -LiteralPath $out)) {
            $stanza = $null
            foreach ($line in @(Get-Content -LiteralPath $out -ErrorAction SilentlyContinue)) {
                if ($line -notmatch '^(.+?\.conf)\s+(.*)$') { continue }
                $file = Get-ShortConfPath $matches[1]; $content = $matches[2].Trim()
                if ($content -match '^\[(.+)\]$') {
                    $stanza = $matches[1]; $sk = $stanza.ToLower()
                    if (-not $store.ContainsKey($sk)) { $store[$sk] = @{ Name = $stanza; Settings = @{} } }
                    continue
                }
                if ($stanza -and $content -match '^([^=]+?)\s*=\s*(.*)$') {
                    $k = $matches[1].Trim().ToLower(); $sk = $stanza.ToLower()
                    if (-not $store[$sk].Settings.ContainsKey($k)) { $store[$sk].Settings[$k] = @{ Value = $matches[2].Trim(); File = $file } }
                }
            }
            if ($store.Count -gt 0) { $script:Splunk.Source = 'splunk btool (effective configuration)'; return $store }
        }
        Write-Step ('splunk btool {0} failed (exit {1}) - parsing .conf files' -f $Conf, $rc) 'WARN'
    }
    foreach ($f in (Get-SplunkConfFiles $script:Splunk.Home $Conf)) {
        Read-ConfFile $f $store (Get-ShortConfPath $f)
        Copy-Item -LiteralPath $f -Destination (Join-Path $script:RawDir ('splunk_' + ((Get-ShortConfPath $f) -replace '[\\/:]', '_'))) -ErrorAction SilentlyContinue
    }
    $script:Splunk.Source = '.conf files parsed in Splunk precedence order'
    return $store
}

function ConvertFrom-SplunkFilter([string]$Value) {
    $v = $Value.Trim()
    if ($v -match '^[\d\s,\-]+$') {
        $ranges = New-Object System.Collections.ArrayList
        foreach ($part in ($v -split ',')) {
            $p = $part.Trim()
            if ($p -match '^(\d+)\s*-\s*(\d+)$') { [void]$ranges.Add(@([int]$matches[1], [int]$matches[2])) }
            elseif ($p -match '^\d+$') { [void]$ranges.Add(@([int]$p, [int]$p)) }
        }
        return @{ Type = 'list'; Ranges = $ranges.ToArray() }
    }
    # advanced format: key=<delim>regex<delim> [key=<delim>regex<delim> ...]
    $pairs = New-Object System.Collections.ArrayList
    $i = 0
    while ($i -lt $v.Length) {
        while ($i -lt $v.Length -and [char]::IsWhiteSpace($v[$i])) { $i++ }
        if ($i -ge $v.Length) { break }
        $eq = $v.IndexOf('=', $i)
        if ($eq -lt 0) { break }
        $key = $v.Substring($i, $eq - $i).Trim()
        $i = $eq + 1
        while ($i -lt $v.Length -and $v[$i] -eq ' ') { $i++ }
        if ($i -ge $v.Length) { break }
        $d = $v[$i]
        $end = $v.IndexOf($d, $i + 1)
        if ($end -lt 0) { $end = $v.Length }
        [void]$pairs.Add(@{ Key = $key; Regex = $v.Substring($i + 1, $end - $i - 1) })
        $i = $end + 1
    }
    return @{ Type = 'adv'; Pairs = $pairs.ToArray() }
}

function Test-SplunkFilterEntry($Parsed, [int]$Id) {
    if ($Parsed.Type -eq 'list') {
        foreach ($r in $Parsed.Ranges) { if ($Id -ge $r[0] -and $Id -le $r[1]) { return 'Match' } }
        return 'NoMatch'
    }
    $hasCode = $false; $others = 0
    foreach ($p in $Parsed.Pairs) {
        if ($p.Key -eq 'EventCode') {
            $hasCode = $true
            try { if (-not [regex]::IsMatch([string]$Id, $p.Regex)) { return 'NoMatch' } } catch { $others++ }
        } else { $others++ }
    }
    if ($others -gt 0 -or -not $hasCode) { return 'Conditional' }
    return 'Match'
}

function Get-SplunkFilters($Settings, [string]$Kind) {
    $list = New-Object System.Collections.ArrayList
    foreach ($k in @($Settings.Keys | Sort-Object)) {
        if ($k -match ('^' + $Kind + '\d*$')) {
            $val = [string]$Settings[$k].Value
            if ($val) { [void]$list.Add(@{ Key = $k; Value = $val; File = $Settings[$k].File; Parsed = (ConvertFrom-SplunkFilter $val) }) }
        }
    }
    return ,$list
}

function Get-SplunkInput([string]$Channel) {
    $key = $Channel.ToLower()
    if ($script:SplunkInputCache.ContainsKey($key)) { return $script:SplunkInputCache[$key] }
    $in = $script:Splunk.Inputs
    $stanzaKey = 'wineventlog://' + $key
    $merged = @{}
    foreach ($sn in @($stanzaKey, 'wineventlog', 'default')) {
        if ($in.ContainsKey($sn)) {
            foreach ($k in @($in[$sn].Settings.Keys)) { if (-not $merged.ContainsKey($k)) { $merged[$k] = $in[$sn].Settings[$k] } }
        }
    }
    $res = @{ Channel = $Channel; Exists = $in.ContainsKey($stanzaKey); Disabled = $false; DisabledFile = ''; Index = ''; Settings = $merged
        Whitelists = (Get-SplunkFilters $merged 'whitelist'); Blacklists = (Get-SplunkFilters $merged 'blacklist') }
    if ($merged.ContainsKey('disabled')) {
        $v = ([string]$merged['disabled'].Value).Trim().ToLower()
        if (@('1', 'true', 't', 'yes', 'y') -contains $v) { $res.Disabled = $true; $res.DisabledFile = $merged['disabled'].File }
    }
    if ($merged.ContainsKey('index')) { $res.Index = $merged['index'].Value }
    $script:SplunkInputCache[$key] = $res
    return $res
}

function Test-SplunkEvent([string]$Channel, [int]$Id) {
    $st = Get-SplunkInput $Channel
    if (-not $st.Exists) { return @{ State = 'NotCollected'; Rule = ('no [WinEventLog://{0}] input' -f $Channel) } }
    if ($st.Disabled) { return @{ State = 'Disabled'; Rule = ('input disabled (' + $st.DisabledFile + ')') } }
    $state = 'Forwarded'; $rules = New-Object System.Collections.ArrayList
    if ($st.Whitelists.Count -gt 0) {
        $best = 'NoMatch'; $bestRule = ''
        foreach ($w in $st.Whitelists) {
            $r = Test-SplunkFilterEntry $w.Parsed $Id
            if ($r -eq 'Match') { $best = 'Match'; break }
            if ($r -eq 'Conditional') { $best = 'Conditional'; $bestRule = ('{0} = {1} ({2})' -f $w.Key, $w.Value, $w.File) }
        }
        if ($best -eq 'NoMatch') {
            return @{ State = 'Filtered'; Rule = ('not in whitelist: ' + (($st.Whitelists | ForEach-Object { '{0} = {1} ({2})' -f $_.Key, $_.Value, $_.File }) -join '; ')) }
        }
        if ($best -eq 'Conditional') { $state = 'Conditional'; [void]$rules.Add('allowed only if ' + $bestRule) }
    }
    foreach ($b in $st.Blacklists) {
        $r = Test-SplunkFilterEntry $b.Parsed $Id
        if ($r -eq 'Match') { return @{ State = 'Filtered'; Rule = ('{0} = {1} ({2})' -f $b.Key, $b.Value, $b.File) } }
        if ($r -eq 'Conditional') { $state = 'Conditional'; [void]$rules.Add(('partly dropped by {0} = {1} ({2})' -f $b.Key, $b.Value, $b.File)) }
    }
    return @{ State = $state; Rule = ($rules.ToArray() -join '; ') }
}

function Test-SplunkIds([string]$Channel, [int[]]$Ids) {
    $fwd = New-Object System.Collections.ArrayList; $flt = New-Object System.Collections.ArrayList; $cond = New-Object System.Collections.ArrayList
    $detail = New-Object System.Collections.ArrayList
    $whole = ''
    foreach ($id in $Ids) {
        $r = Test-SplunkEvent $Channel $id
        switch ($r.State) {
            'Forwarded' { [void]$fwd.Add($id) }
            'Conditional' { [void]$cond.Add($id); [void]$detail.Add(('{0}: {1}' -f $id, $r.Rule)) }
            'Filtered' { [void]$flt.Add($id); [void]$detail.Add(('{0}: {1}' -f $id, $r.Rule)) }
            default { $whole = $r.State; [void]$detail.Clear(); [void]$detail.Add($r.Rule) }
        }
        if ($whole) { break }
    }
    if ($whole) { return @{ State = $whole; Detail = ($detail.ToArray() -join '; ') } }
    $state = 'Forwarded'
    if ($flt.Count -eq $Ids.Count) { $state = 'Filtered' }
    elseif ($flt.Count -gt 0) { $state = 'Partial' }
    elseif ($cond.Count -gt 0) { $state = 'Conditional' }
    return @{ State = $state; Detail = ($detail.ToArray() -join '; ') }
}

function Get-SplunkState {
    $st = @{ Installed = $false; Home = ''; Service = ''; ServiceState = ''; StartMode = ''; Version = ''; Source = ''; Inputs = @{}
        DeployServer = ''; OutputServers = ''; Channels = @(); Health = @{}; Error = '' }
    $script:Splunk = $st
    foreach ($s in $script:Svc.Values) {
        if ([string]$s.PathName -match '^"?(.+?)\\bin\\splunkd\.exe') {
            $st.Installed = $true; $st.Home = $matches[1]; $st.Service = $s.Name; $st.ServiceState = [string]$s.State; $st.StartMode = [string]$s.StartMode
            break
        }
    }
    if (-not $st.Installed) {
        foreach ($p in @((Join-Path $env:ProgramFiles 'SplunkUniversalForwarder'), (Join-Path $env:ProgramFiles 'Splunk'))) {
            if (Test-Path -LiteralPath (Join-Path $p 'bin\splunkd.exe')) { $st.Installed = $true; $st.Home = $p; $st.ServiceState = 'service not registered'; break }
        }
    }
    if (-not $st.Installed) { return $st }
    $vf = Join-Path $st.Home 'etc\splunk.version'
    if (Test-Path -LiteralPath $vf) { foreach ($l in @(Get-Content -LiteralPath $vf)) { if ($l -match '^VERSION=(.+)$') { $st.Version = $matches[1].Trim() } } }
    $st.Inputs = Read-SplunkConf 'inputs.conf'
    $outputs = Read-SplunkConf 'outputs.conf'
    $servers = New-Object System.Collections.ArrayList
    foreach ($s in $outputs.Values) {
        if ($s.Name -like 'tcpout*' -and $s.Settings.ContainsKey('server')) { [void]$servers.Add(('[{0}] {1}' -f $s.Name, $s.Settings['server'].Value)) }
        if ($s.Name -like 'httpout*' -and $s.Settings.ContainsKey('uri')) { [void]$servers.Add(('[{0}] {1}' -f $s.Name, $s.Settings['uri'].Value)) }
    }
    $st.OutputServers = ($servers.ToArray() -join '; ')
    $dc = @{}
    foreach ($f in (Get-SplunkConfFiles $st.Home 'deploymentclient.conf')) { Read-ConfFile $f $dc (Get-ShortConfPath $f) }
    foreach ($s in $dc.Values) { if ($s.Settings.ContainsKey('targeturi')) { $st.DeployServer = $s.Settings['targeturi'].Value } }

    $chan = New-Object System.Collections.ArrayList
    foreach ($s in $st.Inputs.Values) {
        if ($s.Name -notmatch '^WinEventLog://(.+)$') { continue }
        $c = $matches[1]
        $in = Get-SplunkInput $c
        $wl = ($in.Whitelists | ForEach-Object { '{0} = {1}' -f $_.Key, $_.Value }) -join "`n"
        $bl = ($in.Blacklists | ForEach-Object { '{0} = {1}' -f $_.Key, $_.Value }) -join "`n"
        $files = @{}
        foreach ($v in $s.Settings.Values) { if ($v.File) { $files[$v.File] = 1 } }
        $opt = New-Object System.Collections.ArrayList
        foreach ($k in 'current_only', 'start_from', 'renderxml', 'evt_resolve_ad_obj') { if ($in.Settings.ContainsKey($k)) { [void]$opt.Add(('{0}={1}' -f $k, $in.Settings[$k].Value)) } }
        [void]$chan.Add(@{ Channel = $c; Disabled = $in.Disabled; Index = $in.Index; Whitelist = $wl; Blacklist = $bl; Options = ($opt.ToArray() -join ', ')
            Files = (@($files.Keys) -join '; ') })
    }
    $st.Channels = @($chan.ToArray() | Sort-Object { $_.Channel })

    # forwarding health from splunkd.log
    $hl = @{ LogFound = $false; LastConnected = $null; OutputErrors24h = 0; Blocked24h = 0; InputErrors24h = 0; Samples = @(); LastLine = $null }
    $log = Join-Path $st.Home 'var\log\splunk\splunkd.log'
    if (Test-Path -LiteralPath $log) {
        $hl.LogFound = $true
        $since = $script:RunStart.AddHours(-24)
        $samples = New-Object System.Collections.ArrayList
        foreach ($l in (Read-FileTail $log 4MB)) {
            if ($l -notmatch '^(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})') { continue }
            $t = [datetime]::MinValue
            if (-not [datetime]::TryParseExact($matches[1], 'MM-dd-yyyy HH:mm:ss', $Inv, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$t)) { continue }
            $hl.LastLine = $t
            if ($l -match 'Connected to idx=') { $hl.LastConnected = $t }
            $recent = ($t -ge $since)
            if ($l -match '\s(ERROR|WARN)\s' -and $l -match 'TcpOutput|AutoLoadBalanced|HttpOutput|Cooked connection') {
                if ($recent) { $hl.OutputErrors24h++; [void]$samples.Add($l) }
            } elseif ($l -match '(?i)paused the data flow|queue .{0,30} is full|blocked=true') {
                if ($recent) { $hl.Blocked24h++; [void]$samples.Add($l) }
            } elseif ($l -match '\sERROR\s' -and $l -match 'WinEventLog') {
                if ($recent) { $hl.InputErrors24h++; [void]$samples.Add($l) }
            }
        }
        $hl.Samples = @($samples.ToArray() | Select-Object -Last 8)
    }
    $st.Health = $hl
    return $st
}

function Get-OtherTelemetry {
    $fwd = @{ wincollect = 'IBM QRadar WinCollect'; nxlog = 'NXLog'; winlogbeat = 'Elastic Winlogbeat'; 'elastic-agent' = 'Elastic Agent'
        healthservice = 'Microsoft Monitoring Agent'; azuremonitoragent = 'Azure Monitor Agent'; wazuhsvc = 'Wazuh agent'; ossecsvc = 'OSSEC agent'
        'fluent-bit' = 'Fluent Bit'; snare = 'Snare agent'; 'arcsight smartconnector' = 'ArcSight connector'; logrhythmsystemmonitor = 'LogRhythm agent' }
    $edr = @{ csagent = 'CrowdStrike Falcon'; csfalconservice = 'CrowdStrike Falcon'; sense = 'Microsoft Defender for Endpoint'; sentinelagent = 'SentinelOne'
        cbdefense = 'Carbon Black'; xagt = 'Trellix (FireEye) HX'; cylancesvc = 'Cylance'; cyserver = 'Cortex XDR'; ekrn = 'ESET'; velociraptor = 'Velociraptor'
        'tanium client' = 'Tanium'; taniumclient = 'Tanium' }
    $res = New-Object System.Collections.ArrayList
    foreach ($k in $fwd.Keys) { if ($script:Svc.ContainsKey($k)) { $s = $script:Svc[$k]; [void]$res.Add(@{ Type = 'Log forwarder'; Product = $fwd[$k]; Service = $s.Name; State = [string]$s.State }) } }
    foreach ($k in $edr.Keys) { if ($script:Svc.ContainsKey($k)) { $s = $script:Svc[$k]; [void]$res.Add(@{ Type = 'EDR / IR agent'; Product = $edr[$k]; Service = $s.Name; State = [string]$s.State }) } }
    $wef = New-Object System.Collections.ArrayList
    try {
        $k = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction Stop
        foreach ($n in $k.GetValueNames()) { [void]$wef.Add([string]$k.GetValue($n)) }
    } catch { }
    return @{ Agents = $res.ToArray(); Wef = $wef.ToArray() }
}

# =====================================================================================================
#  Tampering evidence in the event logs
# =====================================================================================================
function Get-ServiceFromBinary([string]$Xml) {
    if ($Xml -match '<Binary>([0-9A-Fa-f]+)</Binary>') {
        $hex = $matches[1]
        $bytes = New-Object byte[] ([int]($hex.Length / 2))
        for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        return [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
    }
    return ''
}

function Test-NearShutdown($Time, [int]$Minutes = 10) {
    if (-not $Time) { return $false }
    foreach ($t in $script:ShutdownTimes) {
        $d = ($Time - $t.Time).TotalMinutes
        if (($t.Id -eq 6005 -and $d -le 0 -and $d -ge -30) -or ($t.Id -ne 6005 -and [Math]::Abs($d) -le $Minutes)) { return $true }
    }
    return $false
}

function Add-TamperEvent($Time, [string]$Log, [int]$Id, [string]$Kind, [string]$Title, [string]$Detail, [string]$Severity) {
    [void]$script:TamperEvents.Add(@{ Time = $Time; Log = $Log; Id = $Id; Kind = $Kind; Title = $Title; Detail = $Detail; Severity = $Severity })
}

function Get-TamperEvidence {
    $script:TamperEvents = New-Object System.Collections.ArrayList
    $script:ShutdownTimes = New-Object System.Collections.ArrayList
    $sum = @{ Cleared = 0; ClearedOther = @{}; ServiceStops = 0; Lost = 0; PolicyRemovals = 0; PolicyChanges = 0; TimeChanges = 0
        EventLogSvc = 0; SysmonStops = 0; SysmonConfig = 0; DefenderOff = 0; Detections = New-Object System.Collections.ArrayList; PSv2 = 0; PSv2Last = $null; PSv2Sample = '' }

    foreach ($e in (Get-Events 'System' @(1074, 6005, 6006, 6008) 1000)) {
        [void]$script:ShutdownTimes.Add(@{ Time = $e.Time; Id = $e.Id })
        switch ($e.Id) {
            6005 { Add-TamperEvent $e.Time 'System' 6005 'boot' 'System start (Event Log service started)' '' 'Info' }
            6008 { Add-TamperEvent $e.Time 'System' 6008 'crash' 'Unexpected shutdown' 'Previous shutdown was unexpected (crash / power loss / hard reset)' 'Info' }
        }
    }
    foreach ($e in (Get-Events 'Security' @(1100, 1101, 1102, 1104, 1108, 4612, 4715, 4719, 4906) 500)) {
        $p = $e.Props
        switch ($e.Id) {
            1102 {
                $sum.Cleared++
                $who = ''; if ($p.Count -ge 3) { $who = '{0}\{1}' -f $p[2], $p[1] }
                Add-TamperEvent $e.Time 'Security' 1102 'clear' 'Security log cleared' ('by ' + $who) 'Critical'
            }
            1100 {
                if (Test-NearShutdown $e.Time) { continue }
                $sum.ServiceStops++
                Add-TamperEvent $e.Time 'Security' 1100 'svc' 'Event logging service shut down outside a system shutdown' '' 'High'
            }
            { $_ -eq 1101 -or $_ -eq 1104 -or $_ -eq 4612 -or $_ -eq 1108 } {
                $sum.Lost++
                $t = @{ 1101 = 'Audit events dropped by the transport'; 1104 = 'Security log full - events not written'; 4612 = 'Audit queue exhausted - audits discarded'; 1108 = 'Event logging service error' }[$e.Id]
                Add-TamperEvent $e.Time 'Security' $e.Id 'lost' $t '' 'High'
            }
            4719 {
                $sum.PolicyChanges++
                $sub = ''; $chg = ''; $who = ''; $sid = ''
                if ($p.Count -ge 8) {
                    $sid = $p[0]; $who = '{0}\{1}' -f $p[2], $p[1]
                    $g = '{' + ([string]$p[6]).Trim().TrimStart('{').TrimEnd('}').ToUpper() + '}'
                    if ($script:SubByGuid.ContainsKey($g)) { $sub = $script:SubByGuid[$g].Name } else { $sub = $g }
                    $chg = ([string]$p[7]) -replace '%%8448', 'Success removed' -replace '%%8449', 'Success added' -replace '%%8450', 'Failure removed' -replace '%%8451', 'Failure added'
                }
                $sev = 'Medium'
                if ($chg -match 'removed') { $sum.PolicyRemovals++; if ($sid -eq 'S-1-5-18') { $sev = 'High' } else { $sev = 'Critical' } }
                Add-TamperEvent $e.Time 'Security' 4719 'policy' ('Audit policy changed: ' + $sub) ('{0} by {1}' -f $chg, $who) $sev
            }
            4906 { Add-TamperEvent $e.Time 'Security' 4906 'policy' 'CrashOnAuditFail value changed' '' 'Medium' }
            4715 { Add-TamperEvent $e.Time 'Security' 4715 'policy' 'Audit policy (SACL) on an object changed' '' 'Low' }
        }
    }
    foreach ($e in (Get-Events 'Security' @(4616) 300)) {
        $p = $e.Props
        if ($p.Count -ge 6) {
            $a = Get-PropTime $p[4]; $b = Get-PropTime $p[5]
            if ($a -and $b) {
                $delta = ($b - $a).TotalMinutes
                if ([Math]::Abs($delta) -ge 5) {
                    $sum.TimeChanges++
                    $proc = ''; if ($p.Count -ge 8) { $proc = $p[7] }
                    Add-TamperEvent $e.Time 'Security' 4616 'other' ('System time changed by {0} min' -f [Math]::Round($delta)) ('{0} -> {1} by {2}\{3} {4}' -f (Format-Date $a), (Format-Date $b), $p[2], $p[1], $proc) 'Medium'
                }
            }
        }
    }
    foreach ($e in (Get-Events 'System' @(104) 300)) {
        $ch = ''; $who = ''
        if ($e.Props.Count -ge 3) { $ch = [string]$e.Props[2]; $who = '{0}\{1}' -f $e.Props[1], $e.Props[0] }
        if (-not $ch) { $ch = '(unknown log)' }
        if (-not $sum.ClearedOther.ContainsKey($ch)) { $sum.ClearedOther[$ch] = 0 }
        $sum.ClearedOther[$ch]++
        $sev = 'Medium'; if ($ch -match '^(Security|System)$|Sysmon|PowerShell') { $sev = 'High' }
        Add-TamperEvent $e.Time $ch 104 'clear' ('Event log cleared: ' + $ch) ('by ' + $who) $sev
    }

    # Event Log / Sysmon service state changes
    $elName = $script:Cfg.EventLogDisplay
    $sysmonSvc = $script:Cfg.Sysmon.Service
    $sysmonDisplay = ''
    if ($sysmonSvc -and $script:Svc.ContainsKey($sysmonSvc.ToLower())) { $sysmonDisplay = $script:Svc[$sysmonSvc.ToLower()].DisplayName }
    foreach ($e in (Get-Events 'System' @(7034, 7036, 7040) 4000 -WithXml)) {
        $name = ''; $state = ''
        if ($e.Id -eq 7040) { if ($e.Props.Count -ge 4) { $name = [string]$e.Props[3] } }
        else {
            $bin = Get-ServiceFromBinary $e.Xml
            if ($bin -match '^(.+)/(\d+)$') { $name = $matches[1]; $state = $matches[2] }
            elseif ($e.Props.Count -ge 1) { $name = [string]$e.Props[0] }
        }
        $isEl = ($name -eq 'EventLog' -or $name -eq $elName)
        $isSm = ($sysmonSvc -and ($name -eq $sysmonSvc -or $name -eq $sysmonDisplay)) -or $name -match '^Sysmon(64)?$'
        if (-not ($isEl -or $isSm)) { continue }
        $what = 'Sysmon service'; if ($isEl) { $what = 'Event Log service' }
        if ($e.Id -eq 7040) {
            if ($isEl) { $sum.EventLogSvc++ } else { $sum.SysmonStops++ }
            Add-TamperEvent $e.Time 'System' 7040 'svc' ($what + ' start type changed') (($e.Props | Select-Object -First 3) -join ' / ') 'High'
        } elseif ($e.Id -eq 7034) {
            if ($isEl) { $sum.EventLogSvc++ } else { $sum.SysmonStops++ }
            Add-TamperEvent $e.Time 'System' 7034 'svc' ($what + ' terminated unexpectedly') '' 'High'
        } elseif ($state -eq '1' -or ($state -eq '' -and $e.Props.Count -ge 2 -and [string]$e.Props[1] -match 'stop')) {
            if (Test-NearShutdown $e.Time) { continue }
            if ($isEl) { $sum.EventLogSvc++ } else { $sum.SysmonStops++ }
            Add-TamperEvent $e.Time 'System' 7036 'svc' ($what + ' stopped outside a system shutdown') '' 'High'
        }
    }
    foreach ($e in (Get-Events 'Microsoft-Windows-Sysmon/Operational' @(4, 16, 255) 300)) {
        switch ($e.Id) {
            4 { if ($e.Props.Count -ge 2 -and [string]$e.Props[1] -match 'Stop' -and -not (Test-NearShutdown $e.Time)) { $sum.SysmonStops++; Add-TamperEvent $e.Time 'Microsoft-Windows-Sysmon/Operational' 4 'svc' 'Sysmon service stopped' '' 'High' } }
            16 { $sum.SysmonConfig++; Add-TamperEvent $e.Time 'Microsoft-Windows-Sysmon/Operational' 16 'policy' 'Sysmon configuration changed' (($e.Props | Select-Object -Skip 1) -join ' ') 'Medium' }
            255 { Add-TamperEvent $e.Time 'Microsoft-Windows-Sysmon/Operational' 255 'other' 'Sysmon error' (($e.Props | Select-Object -Skip 1) -join ' ') 'Low' }
        }
    }
    foreach ($e in (Get-Events 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117, 5001, 5010, 5012) 300)) {
        if ($e.Id -eq 1116 -or $e.Id -eq 1117) {
            $threat = ''
            foreach ($v in $e.Props) { if ([string]$v -match '^[A-Za-z]+:[A-Za-z0-9]+/\S+') { $threat = [string]$v; break } }
            $path = ''
            foreach ($v in $e.Props) { if ([string]$v -match '^(file|process|regkey|containerfile|amsi|behavior):_') { $path = [string]$v; break } }
            [void]$sum.Detections.Add(@{ Time = $e.Time; Threat = $threat; Path = $path; Id = $e.Id })
            Add-TamperEvent $e.Time 'Microsoft-Windows-Windows Defender/Operational' $e.Id 'other' ('Defender detection: ' + $threat) $path 'High'
        } else {
            $sum.DefenderOff++
            $t = @{ 5001 = 'Defender real-time protection disabled'; 5010 = 'Defender anti-spyware scanning disabled'; 5012 = 'Defender antivirus scanning disabled' }[$e.Id]
            Add-TamperEvent $e.Time 'Microsoft-Windows-Windows Defender/Operational' $e.Id 'svc' $t '' 'High'
        }
    }
    if ($script:Sys.PSInstalled -ge [version]'3.0') {
        foreach ($e in (Get-Events 'Windows PowerShell' @(400) 3000)) {
            $txt = ($e.Props -join ' ')
            if ($txt -match 'EngineVersion=2\.') {
                $sum.PSv2++
                if (-not $sum.PSv2Last -or $e.Time -gt $sum.PSv2Last) {
                    $sum.PSv2Last = $e.Time
                    if ($txt -match 'HostApplication=([^\r\n]+)') { $sum.PSv2Sample = $matches[1].Trim() }
                }
            }
        }
        if ($sum.PSv2 -gt 0) { Add-TamperEvent $sum.PSv2Last 'Windows PowerShell' 400 'other' ('PowerShell 2.0 engine started ({0}x)' -f $sum.PSv2) $sum.PSv2Sample 'High' }
    }
    return $sum
}

# =====================================================================================================
#  Deep scan
# =====================================================================================================
function Invoke-LogDeepScan([string]$LogName, [int]$Max, [double]$GapMin) {
    $r = @{ Log = $LogName; Scanned = 0; Truncated = $false; RidGaps = New-Object System.Collections.ArrayList; RidMissing = [long]0
        TimeGaps = New-Object System.Collections.ArrayList; Backwards = 0; Buckets = @{}; First = $null; Last = $null; Error = ''; Seconds = 0 }
    $L = Get-Log $LogName
    if (-not $L -or -not ($L.Records -gt 0) -or -not $script:HasReader) { $r.Error = 'log not available'; return $r }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $reader = $null
    try {
        $reader = New-EventReader $LogName '*' $false
        $reader.BatchSize = 1024
        $prevRid = $null; $prevT = $null
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            $rid = $e.RecordId; $t = $e.TimeCreated
            $e.Dispose()
            $r.Scanned++
            if ($null -ne $t) {
                $hk = [long][Math]::Floor($t.ToUniversalTime().Ticks / 36000000000.0)
                $r.Buckets[$hk] = $r.Buckets[$hk] + 1
                if (-not $r.First) { $r.First = $t }
                $r.Last = $t
                if ($null -ne $prevT) {
                    $dm = ($t - $prevT).TotalMinutes
                    if ($GapMin -gt 0 -and $dm -gt $GapMin -and $r.TimeGaps.Count -lt 200) {
                        [void]$r.TimeGaps.Add(@{ From = $prevT; To = $t; Minutes = $dm; Explained = (Test-GapExplained $prevT $t) })
                    }
                    if ($dm -lt -5) { $r.Backwards++ }
                }
                $prevT = $t
            }
            if ($null -ne $prevRid -and $null -ne $rid) {
                if ($rid -gt $prevRid + 1) {
                    $r.RidMissing += ($rid - $prevRid - 1)
                    if ($r.RidGaps.Count -lt 200) { [void]$r.RidGaps.Add(@{ AfterRecord = $prevRid; BeforeRecord = $rid; Missing = ($rid - $prevRid - 1); From = $prevT; To = $t }) }
                }
            }
            if ($null -ne $rid) { $prevRid = $rid }
            if ($r.Scanned -ge $Max) { $r.Truncated = $true; break }
            if ($r.Scanned % 200000 -eq 0) { Write-Step ('  {0}: {1:N0} events read' -f $LogName, $r.Scanned) }
        }
    } catch { $r.Error = $_.Exception.Message } finally { if ($reader) { $reader.Dispose() } }
    $r.Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    return $r
}

function Test-GapExplained($From, $To) {
    foreach ($t in $script:ShutdownTimes) { if ($t.Time -ge $From.AddMinutes(-10) -and $t.Time -le $To.AddMinutes(10)) { return $true } }
    return $false
}

function Find-AntiLoggingCommands([int]$MaxPerSource) {
    $hits = New-Object System.Collections.ArrayList
    $sources = @(@('Security', @(4688)), @('Microsoft-Windows-Sysmon/Operational', @(1)), @('Microsoft-Windows-PowerShell/Operational', @(4104)),
        @('Windows PowerShell', @(400, 800)), @('PowerShellCore/Operational', @(4104)))
    foreach ($s in $sources) {
        $L = Get-Log $s[0]
        if (-not $L -or -not ($L.Records -gt 0)) { continue }
        $xp = '*[System[(' + (($s[1] | ForEach-Object { 'EventID=' + $_ }) -join ' or ') + ')]]'
        $reader = $null; $n = 0
        try {
            $reader = New-EventReader $s[0] $xp $true
            while ($n -lt $MaxPerSource -and $hits.Count -lt 300) {
                $e = $reader.ReadEvent()
                if ($null -eq $e) { break }
                $n++
                $txt = ''
                try { $txt = (@($e.Properties | ForEach-Object { [string]$_.Value }) -join ' ') } catch { }
                foreach ($pat in $script:AntiPatterns) {
                    if ($pat.Rx.IsMatch($txt)) {
                        $snippet = $txt; if ($snippet.Length -gt 400) { $snippet = $snippet.Substring(0, 400) + ' ...' }
                        [void]$hits.Add(@{ Time = $e.TimeCreated; Log = $s[0]; Id = [int]$e.Id; Pattern = $pat.Name; Text = $snippet })
                        break
                    }
                }
                $e.Dispose()
            }
        } catch { Write-Step ('Anti-logging search in {0} failed: {1}' -f $s[0], $_.Exception.Message) 'WARN' } finally { if ($reader) { $reader.Dispose() } }
        Write-Step ('  searched {0:N0} events in {1}' -f $n, $s[0])
    }
    return ,$hits
}

# =====================================================================================================
#  Evaluation: audit baseline, detection use cases
# =====================================================================================================
function Get-AuditRows {
    $req = @{}
    foreach ($b in $Baseline) {
        if (-not (Test-RoleApplies $b.Roles)) { continue }
        if ($req.ContainsKey($b.Sub)) { $req[$b.Sub].Need = $req[$b.Sub].Need -bor $b.Need; $req[$b.Sub].Why += '; ' + $b.Why }
        else { $req[$b.Sub] = @{ Need = $b.Need; Why = $b.Why; Ref = $b.Ref } }
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($s in $script:SubOrder) {
        $r = @{ Category = $s.Category; Name = $s.Name; Guid = $s.Guid; Effective = $null; Gpo = $null; LocalGpo = $null; Required = 0; Why = ''; Ref = ''
            Status = ''; GpoMismatch = $false; Supported = $true }
        if ($req.ContainsKey($s.Name)) { $r.Required = $req[$s.Name].Need; $r.Why = $req[$s.Name].Why; $r.Ref = $req[$s.Name].Ref }
        $eff = Get-EffectiveAudit $s.Name
        if ($eff -eq -1) { $r.Supported = $false } elseif ($null -ne $eff) { $r.Effective = $eff }
        if ($script:Audit.Gpo -and $script:Audit.Gpo.ContainsKey($s.Guid)) { $r.Gpo = $script:Audit.Gpo[$s.Guid].Value }
        if ($script:Audit.LocalGpo -and $script:Audit.LocalGpo.ContainsKey($s.Guid)) { $r.LocalGpo = $script:Audit.LocalGpo[$s.Guid].Value }
        if (-not $script:Audit.Available) { $r.Status = 'Unknown' }
        elseif (-not $r.Supported) { $r.Status = 'N/A' }
        else {
            if ($null -ne $r.Gpo -and (($r.Gpo -band $r.Effective) -ne $r.Gpo)) { $r.GpoMismatch = $true }
            if ($r.Required -eq 0) { if ($r.Effective -gt 0) { $r.Status = 'Optional (on)' } else { $r.Status = 'Optional' } }
            else {
                $miss = $r.Required - ($r.Required -band $r.Effective)
                if ($miss -eq 0) { $r.Status = 'OK' } elseif ($miss -eq $r.Required) { $r.Status = 'Missing' } else { $r.Status = 'Partial' }
            }
        }
        [void]$rows.Add($r)
    }
    return ,$rows
}

$StatusRank = @{ 'Covered' = 4; 'Partial' = 3; 'Unknown' = 2; 'Gap' = 1; 'N/A' = 0 }
$SiemRank = @{ 'Forwarded' = 6; 'Conditional' = 5; 'Partial' = 4; 'Filtered' = 3; 'Disabled' = 2; 'NotCollected' = 1; '' = 0 }

function Get-SourceLabel($Src) { return ('{0} {1}' -f (Get-ShortLogName $Src.Log), ($Src.Ids -join '/')) }

function Test-Source($Src) {
    $res = @{ Label = (Get-SourceLabel $Src); Log = $Src.Log; Ids = $Src.Ids; Status = 'Covered'; Reasons = New-Object System.Collections.ArrayList
        SpanHours = $null; Oldest = $null; Siem = ''; SiemDetail = '' }
    $worse = {
        param($s, $why)
        if ($StatusRank[$s] -lt $StatusRank[$res.Status]) { $res.Status = $s }
        if ($why) { [void]$res.Reasons.Add($why) }
    }
    if ($Src.MinOS -and $script:Sys.NT -lt [version]$Src.MinOS) {
        $res.Status = 'N/A'; [void]$res.Reasons.Add(('not available on {0}' -f $script:Sys.Family)); return $res
    }
    $L = Get-Log $Src.Log
    if (-not $L) {
        $why = 'log channel not present'
        if ($Src.Log -eq $SysmonLog) { $why = 'Sysmon is not installed' }
        elseif ($Src.Log -like 'PowerShellCore*') { $why = 'PowerShell 7 logging channel not registered' }
        & $worse 'Gap' $why
        return $res
    }
    if (-not $L.Enabled) { & $worse 'Gap' 'log channel is disabled' }
    elseif (-not $L.Readable) { & $worse 'Unknown' 'log not readable (run as Administrator)' }
    $res.SpanHours = $L.SpanHours; $res.Oldest = $L.Oldest
    foreach ($a in @($Src.Audit)) {
        if (-not $a) { continue }
        $parts = $a.Split(':'); $sub = $parts[0]; $need = [int]$parts[1]
        $eff = Get-EffectiveAudit $sub
        if ($null -eq $eff) { & $worse 'Unknown' 'audit policy not readable (run as Administrator)' }
        elseif ($eff -eq -1) { & $worse 'N/A' ('audit subcategory "{0}" not available on this OS' -f $sub) }
        elseif (($eff -band $need) -eq 0) { & $worse 'Gap' ('audit "{0}" not enabled (needs {1})' -f $sub, (Get-AuditText $need)) }
        elseif (($eff -band $need) -ne $need) { & $worse 'Partial' ('audit "{0}" is {1} only (needs {2})' -f $sub, (Get-AuditText $eff), (Get-AuditText $need)) }
    }
    $cap = $script:Caps; $cfg = $script:Cfg
    switch ($Src.Extra) {
        'CmdLine' {
            if (-not $cap.CmdLineSupported) { & $worse 'Partial' 'command line not supported by this OS (KB3004375 / 2012 R2+)' }
            elseif (-not $cfg.CmdLine) { & $worse 'Partial' 'command line not included in 4688' }
        }
        'ScriptBlock' {
            if (-not $cap.ScriptBlockSupported) { & $worse 'Gap' ('PowerShell {0}: script block logging requires WMF 5.1' -f $script:Sys.PSInstalled) }
            elseif (-not $cfg.ScriptBlock) { & $worse 'Partial' 'script block logging not enabled (only suspicious blocks are auto-logged)' }
        }
        'ModuleLog' { if (-not $cfg.ModuleLogging) { & $worse 'Gap' 'module logging not enabled' } }
        'PSCoreSB' { if (-not $cfg.PSCoreScriptBlock) { & $worse 'Partial' 'PowerShell 7 script block logging policy not enabled' } }
        'SaclReq' { & $worse 'Partial' 'requires SACLs on the audited objects (not verified)' }
        'SaclNote' { [void]$res.Reasons.Add('relies on the default AD domain SACL') }
        'CaAudit' {
            $ok = $false; foreach ($ca in $cfg.CA) { if ([int]$ca.AuditFilter -eq 127) { $ok = $true } }
            if (-not $ok) { & $worse 'Gap' 'CA audit filter is not 127 (certutil -setreg CA\AuditFilter 127)' }
        }
        'NtlmAudit' { if (-not $cfg.NtlmAudit) { & $worse 'Gap' 'NTLM auditing policies not configured' } }
    }
    if ($L.Enabled -and -not ($L.Records -gt 0) -and $L.Readable) { [void]$res.Reasons.Add('log is empty') }
    if ($script:Splunk.Installed) {
        $sr = Test-SplunkIds $Src.Log $Src.Ids
        $res.Siem = $sr.State; $res.SiemDetail = $sr.Detail
    }
    return $res
}

function Get-UseCaseResults {
    $out = New-Object System.Collections.ArrayList
    foreach ($uc in $UseCases) {
        if (-not (Test-RoleApplies $uc.Roles)) { continue }
        $srcs = New-Object System.Collections.ArrayList
        foreach ($s in $uc.Sources) { [void]$srcs.Add((Test-Source $s)) }
        $best = 'N/A'
        foreach ($s in $srcs) { if ($StatusRank[$s.Status] -gt $StatusRank[$best]) { $best = $s.Status } }
        $siem = ''; $siemDetail = ''; $span = $null; $oldest = $null
        foreach ($s in $srcs) {
            if ($s.Status -ne 'Covered' -and $s.Status -ne 'Partial') { continue }
            if ($SiemRank[$s.Siem] -gt $SiemRank[$siem]) { $siem = $s.Siem; $siemDetail = $s.SiemDetail }
            if ($null -ne $s.SpanHours -and ($null -eq $span -or $s.SpanHours -gt $span)) { $span = $s.SpanHours }
            if ($s.Oldest -and (-not $oldest -or $s.Oldest -lt $oldest)) { $oldest = $s.Oldest }
        }
        if (-not $script:Splunk.Installed) { $siem = 'None' }
        [void]$out.Add(@{ Id = $uc.Id; Name = $uc.Name; Tactic = $uc.Tactic; Mitre = $uc.Mitre; Key = $uc.Key; Status = $best; Siem = $siem
            SiemDetail = $siemDetail; SpanHours = $span; Oldest = $oldest; Sources = $srcs.ToArray(); Def = $uc })
    }
    return ,$out
}

# =====================================================================================================
#  Findings
# =====================================================================================================
function Get-AffectedUseCases([string]$SubName) {
    $names = New-Object System.Collections.ArrayList
    foreach ($u in $script:UCResults) {
        foreach ($s in $u.Def.Sources) { foreach ($a in @($s.Audit)) { if ($a -and $a.Split(':')[0] -eq $SubName -and -not ($names -contains $u.Name)) { [void]$names.Add($u.Name) } } }
    }
    return ($names.ToArray() -join '; ')
}

function Build-Findings {
    $sys = $script:Sys; $cfg = $script:Cfg; $sum = $script:TamperSummary; $sp = $script:Splunk
    $sec = Get-Log 'Security'

    # ---- collection context
    if (-not $sys.Admin) {
        Add-Finding 'High' 'Collection' 'Script was not run as Administrator - results are incomplete' 'The Security log, the audit policy and some registry keys cannot be read without administrative rights.' '' 'Re-run from an elevated PowerShell prompt.'
    }
    if (-not $script:HasReader) {
        Add-Finding 'Medium' 'Collection' '.NET 3.5 event log API not available' 'Only classic logs (Security, System, Application) could be analysed; Operational channels were skipped.' '' 'Install .NET Framework 3.5 or analyse the .evtx files offline.'
    }

    # ---- tampering: configuration
    if ($cfg.EventLogState -and $cfg.EventLogState -ne 'Running') {
        Add-Finding 'Critical' 'Tampering' ('Windows Event Log service is ' + $cfg.EventLogState) 'No events are being written while the service is not running.' ('State: {0}, start mode: {1}' -f $cfg.EventLogState, $cfg.EventLogStart) 'Start the service, then investigate who stopped it (System 7036/7040, Security 1100).' 'T1562.002'
    }
    if ($cfg.EventLogStart -eq 'Disabled') {
        Add-Finding 'Critical' 'Tampering' 'Windows Event Log service start type is Disabled' 'Logging stops completely after the next reboot.' ('Start mode: ' + $cfg.EventLogStart) 'Set the start type back to Automatic and investigate the change (System 7040).' 'T1562.002'
    }
    if ($cfg.MiniNt) {
        Add-Finding 'Critical' 'Tampering' 'MiniNt registry key present - Windows believes it is WinPE' 'With HKLM\SYSTEM\CurrentControlSet\Control\MiniNt present the Event Log service does not write events after reboot - a known anti-forensics trick.' 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt exists' 'Remove the key (after imaging the system) and investigate its creation time.' 'T1562.002'
    }
    foreach ($a in $cfg.Autologger) {
        $isSec = ($a.Session -eq 'EventLog-Security')
        if ($null -ne $a.Start -and [int]$a.Start -eq 0) {
            $sev = 'High'; if ($isSec) { $sev = 'Critical' }
            Add-Finding $sev 'Tampering' ('ETW autologger session {0} is disabled (Start = 0)' -f $a.Session) 'The kernel logging session that feeds this log does not start at boot - events are silently lost after a reboot.' ('HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\{0}\Start = 0' -f $a.Session) 'Restore Start = 1 and investigate when the key was changed.' 'T1562.002'
        }
        if ($a.Disabled) {
            $sev = 'Medium'
            if ($isSec -and $a.Disabled -match '54849625-5478-4994-A5BA-3E3B0328C30D') { $sev = 'Critical' }
            elseif ($a.Session -like 'Defender*') { $sev = 'High' }
            Add-Finding $sev 'Tampering' ('Providers disabled in autologger session ' + $a.Session) 'Providers with Enabled = 0 do not deliver events into this log.' ('Disabled provider GUIDs: ' + $a.Disabled) 'Verify against a known-good system; restore Enabled = 1 for providers that should log.' 'T1562.002'
        }
    }
    foreach ($n in @($cfg.LogPaths.Keys)) {
        $lp = $cfg.LogPaths[$n]
        if (-not $lp.Default) {
            Add-Finding 'High' 'Tampering' ('{0} log file location changed' -f $n) 'The log is written to a non-default file - verify the location is expected and protected.' $lp.Path 'Confirm the change was authorised (GPO / change ticket).' 'T1562.002'
        }
    }
    foreach ($n in 'Security', 'System') {
        $L = Get-Log $n
        if ($L -and -not $L.Enabled) { Add-Finding 'Critical' 'Tampering' ($n + ' log is disabled') 'The channel does not accept events.' '' ('wevtutil sl ' + $n + ' /e:true') 'T1562.002' }
        if ($L -and $L.Mode -eq 'Retain' -and $L.IsFull) { Add-Finding 'Critical' 'Tampering' ($n + ' log is full in "do not overwrite" mode') 'New events are being discarded.' ('Size {0} of {1}' -f (Format-Size $L.FileBytes), (Format-Size $L.MaxBytes)) 'Archive and clear the log or switch to overwrite / archive mode.' 'T1562.002' }
    }
    if ($script:Audit.Available -and $script:Audit.AllOff) {
        Add-Finding 'Critical' 'Tampering' 'Audit policy is completely disabled' 'No audit subcategory is enabled - the Security log records almost nothing (typical result of "auditpol /clear").' '' 'Restore the audit policy (GPO refresh: gpupdate /force) and investigate Security 4719 / process events around the change.' 'T1562.002'
    }
    $mis = @($script:AuditRows | Where-Object { $_.GpoMismatch })
    if ($mis.Count -gt 0) {
        $ev = ($mis | ForEach-Object { '{0}: GPO={1}, effective={2}' -f $_.Name, (Get-AuditText $_.Gpo), (Get-AuditText $_.Effective) }) -join '; '
        Add-Finding 'High' 'Tampering' ('Effective audit policy is weaker than the GPO for {0} subcategories' -f $mis.Count) 'The audit policy applied by Group Policy (security\audit\audit.csv) is not in effect - typically a local "auditpol /set" after the last policy refresh.' $ev 'Run gpupdate /force after imaging, then look for auditpol execution (4688 / Sysmon 1) and 4719 events.' 'T1562.002'
    }
    if ($cfg.Sysmon.Installed -and $cfg.Sysmon.Service -and $cfg.Sysmon.ServiceState -ne 'Running') {
        Add-Finding 'High' 'Tampering' ('Sysmon service is ' + $cfg.Sysmon.ServiceState) 'Sysmon is installed but not running - no Sysmon events are produced.' ('Service {0}, driver {1} ({2})' -f $cfg.Sysmon.Service, $cfg.Sysmon.Driver, $cfg.Sysmon.DriverState) 'Start Sysmon and investigate System 7036 / Sysmon 4 events.' 'T1562.001'
    }

    # ---- tampering: events
    if ($sum.Cleared -gt 0) {
        $ev = @($script:TamperEvents | Where-Object { $_.Id -eq 1102 } | Sort-Object { $_.Time } | Select-Object -Last 5 | ForEach-Object { '{0} {1}' -f (Format-Date $_.Time), $_.Detail }) -join '; '
        Add-Finding 'Critical' 'Tampering' ('Security log was cleared {0} time(s)' -f $sum.Cleared) 'Events before the clearing are gone from this system. Any earlier activity must come from the SIEM, backups or other sources.' $ev 'Retrieve the cleared period from Splunk; identify the account and the process that cleared the log.' 'T1070.001'
    }
    if ($sum.ClearedOther.Count -gt 0) {
        $ev = ($sum.ClearedOther.Keys | ForEach-Object { '{0} ({1}x)' -f $_, $sum.ClearedOther[$_] }) -join ', '
        $sev = 'Medium'; foreach ($k in $sum.ClearedOther.Keys) { if ($k -match '^(Security|System)$|Sysmon|PowerShell') { $sev = 'High' } }
        Add-Finding $sev 'Tampering' 'Event logs were cleared (System 104)' 'Log clearing destroys evidence; legitimate clearing is rare on servers.' $ev 'Correlate the time and account with logons and process creation.' 'T1070.001'
    }
    if ($sum.ServiceStops -gt 0 -or $sum.EventLogSvc -gt 0) {
        Add-Finding 'High' 'Tampering' 'Event Log service stopped or reconfigured outside a system shutdown' 'Events are not written while the service is stopped.' ('{0} event(s) - see the tampering events table' -f ($sum.ServiceStops + $sum.EventLogSvc)) 'Identify the account / process behind the change.' 'T1562.002'
    }
    if ($sum.Lost -gt 0) {
        Add-Finding 'High' 'Tampering' 'Audit events were lost (1101 / 1104 / 4612 / 1108)' 'The system reported that security events were dropped - there are holes in the Security log.' ('{0} event(s)' -f $sum.Lost) 'Check the time of the losses against the incident timeline; increase log size.' 'T1562.002'
    }
    if ($sum.PolicyRemovals -gt 0) {
        $crit = @($script:TamperEvents | Where-Object { $_.Id -eq 4719 -and $_.Severity -eq 'Critical' }).Count
        $sev = 'High'; if ($crit -gt 0) { $sev = 'Critical' }
        $ev = @($script:TamperEvents | Where-Object { $_.Id -eq 4719 -and $_.Detail -match 'removed' } | Select-Object -First 8 | ForEach-Object { '{0} {1} {2}' -f (Format-Date $_.Time), $_.Title, $_.Detail }) -join '; '
        Add-Finding $sev 'Tampering' ('Audit policy was weakened {0} time(s) (4719)' -f $sum.PolicyRemovals) 'Audit settings were removed. Changes by a user account (not SYSTEM / GPO) are a strong tampering indicator.' $ev 'Verify each change against GPO changes; investigate the accounts involved.' 'T1562.002'
    }
    if ($sum.TimeChanges -gt 0) {
        Add-Finding 'Medium' 'Tampering' ('System time was changed by 5 minutes or more ({0}x)' -f $sum.TimeChanges) 'Large clock changes distort the timeline and can be used to hide activity.' 'See tampering events (4616)' 'Normalise timestamps around the changes.' 'T1070.006'
    }
    if ($sum.SysmonStops -gt 0) {
        Add-Finding 'High' 'Tampering' 'Sysmon was stopped or reconfigured' 'Sysmon telemetry is missing for the period it was stopped.' ('{0} event(s)' -f $sum.SysmonStops) 'Investigate the stop events and the account behind them.' 'T1562.001'
    }
    if ($sum.SysmonConfig -gt 0) {
        Add-Finding 'Medium' 'Tampering' ('Sysmon configuration changed {0} time(s)' -f $sum.SysmonConfig) 'A modified configuration can exclude attacker activity.' ('Current config hash (SHA-256 of Rules): ' + $cfg.Sysmon.ConfigHash) 'Compare the configuration with the approved version.' 'T1562.001'
    }
    if ($sum.DefenderOff -gt 0) {
        Add-Finding 'High' 'Tampering' ('Microsoft Defender protection was disabled {0} time(s)' -f $sum.DefenderOff) 'Real-time protection / scanning was turned off.' 'Defender 5001 / 5010 / 5012' 'Correlate with process creation and logons at that time.' 'T1562.001'
    }
    if ($sum.Detections.Count -gt 0) {
        $ev = ($sum.Detections | Select-Object -First 8 | ForEach-Object { '{0} {1} {2}' -f (Format-Date $_.Time), $_.Threat, $_.Path }) -join '; '
        Add-Finding 'High' 'Threat activity' ('Microsoft Defender detected {0} threat event(s)' -f $sum.Detections.Count) 'Detections give anchor points for the investigation timeline.' $ev 'Review the detections and the files / processes involved.' 'T1204'
    }
    if ($sum.PSv2 -gt 0) {
        Add-Finding 'High' 'Tampering' ('PowerShell 2.0 engine was used {0} time(s)' -f $sum.PSv2) 'PowerShell 2.0 bypasses script block logging and AMSI - a common logging evasion.' $sum.PSv2Sample 'Remove the PowerShell 2.0 engine feature; investigate the host application that started it.' 'T1059.001'
    }
    if ($sec -and $sec.Readable -and $sec.Newest -and $sys.UptimeHours -gt 1) {
        $age = ($script:RunStart - $sec.Newest).TotalHours
        if ($age -gt 24) { Add-Finding 'High' 'Tampering' ('Security log silent for {0}' -f (Format-Span $age)) 'The newest Security event is older than a day although the system is running - auditing may be disabled or the Event Log service threads suspended (Phant0m-style).' ('Newest event: ' + (Format-Date $sec.Newest)) 'Compare with Splunk; check Event Log service threads with a live response tool.' 'T1562.002' }
        elseif ($age -gt 1) { Add-Finding 'Medium' 'Tampering' ('No Security event in the last {0}' -f (Format-Span $age)) 'Unusual for a busy server; verify that auditing still works.' ('Newest event: ' + (Format-Date $sec.Newest)) 'Generate a test event (e.g. a logon) and confirm it appears.' 'T1562.002' }
    }
    if ($script:Deep) {
        foreach ($d in $script:Deep.Scans) {
            if ($d.RidMissing -gt 0) {
                $ev = ($d.RidGaps | Select-Object -First 5 | ForEach-Object { 'records {0}-{1} ({2} missing) between {3} and {4}' -f $_.AfterRecord, $_.BeforeRecord, $_.Missing, (Format-Date $_.From), (Format-Date $_.To) }) -join '; '
                Add-Finding 'Critical' 'Tampering' ('{0}: {1} event record(s) missing inside the log' -f $d.Log, $d.RidMissing) 'Event record IDs are sequential; gaps inside a log indicate selectively deleted events (e.g. DanderSpritz eventlogedit) or log corruption.' $ev 'Acquire the .evtx file and analyse the gaps (carving of deleted records).' 'T1070.001'
            }
            $un = @($d.TimeGaps | Where-Object { -not $_.Explained })
            if ($un.Count -gt 0 -and ($d.Log -eq 'Security' -or $d.Log -eq $SysmonLog)) {
                $ev = ($un | Sort-Object { $_.Minutes } -Descending | Select-Object -First 5 | ForEach-Object { '{0} -> {1} ({2})' -f (Format-Date $_.From), (Format-Date $_.To), (Format-Span ($_.Minutes / 60)) }) -join '; '
                Add-Finding 'Medium' 'Tampering' ('{0}: {1} period(s) without events not explained by a reboot' -f $d.Log, $un.Count) 'Silent periods on a busy log can mean logging was suspended.' $ev 'Compare the periods with Splunk and other logs.' 'T1562.002'
            }
        }
        if ($script:Deep.Commands.Count -gt 0) {
            $ev = ($script:Deep.Commands | Select-Object -First 6 | ForEach-Object { '{0} [{1} {2}] {3}' -f (Format-Date $_.Time), (Get-ShortLogName $_.Log), $_.Id, $_.Pattern }) -join '; '
            Add-Finding 'Critical' 'Tampering' ('{0} anti-logging command(s) found in process / PowerShell events' -f $script:Deep.Commands.Count) 'Commands that clear logs, change audit policy or disable telemetry were executed.' $ev 'Review the full commands in the deep scan section.' 'T1562'
        }
    }

    # ---- visibility
    foreach ($r in $script:AuditRows) {
        if ($r.Status -ne 'Missing' -and $r.Status -ne 'Partial') { continue }
        $sev = 'Low'
        if ($KeySubcategories -contains $r.Name) { if ($r.Status -eq 'Missing') { $sev = 'High' } else { $sev = 'Medium' } }
        elseif ($r.Status -eq 'Missing') { $sev = 'Medium' }
        $ucs = Get-AffectedUseCases $r.Name
        $succ = 'disable'; $fail = 'disable'
        if ($r.Required -band 1) { $succ = 'enable' }; if ($r.Required -band 2) { $fail = 'enable' }
        if ($r.Effective -band 1) { $succ = 'enable' }; if ($r.Effective -band 2) { $fail = 'enable' }
        $rec = ('auditpol /set /subcategory:"{0}" /success:{1} /failure:{2}  |  GPO: Advanced Audit Policy Configuration > {3} > Audit {4}' -f $r.Guid, $succ, $fail, $r.Category, $r.Name)
        $ev = ('Effective: {0}; required: {1} ({2})' -f (Get-AuditText $r.Effective), (Get-AuditText $r.Required), $r.Ref)
        if ($ucs) { $ev += '; affects: ' + $ucs }
        Add-Finding $sev 'Visibility' ('Audit "{0}" {1}' -f $r.Name, @{ Missing = 'is not enabled'; Partial = 'is only partly enabled' }[$r.Status]) $r.Why $ev $rec ''
    }
    if (-not $script:Caps.CmdLineSupported) {
        Add-Finding 'Medium' 'Visibility' 'Process command lines cannot be logged on this OS version' '4688 events lack the command line, which is essential to understand attacker activity.' $sys.Family 'Install KB3004375 (2008 R2 / 2012) or deploy Sysmon.' 'T1059'
    } elseif (-not $cfg.CmdLine) {
        Add-Finding 'High' 'Visibility' 'Command line is not recorded in process creation events (4688)' 'Without the command line, executed attacker commands cannot be reconstructed.' 'ProcessCreationIncludeCmdLine_Enabled is not 1' 'GPO: Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled' 'T1059'
    }
    if (-not $script:Caps.ScriptBlockSupported) {
        Add-Finding 'High' 'Visibility' ('PowerShell {0} cannot log script content' -f $sys.PSInstalled) 'Script block logging (4104) requires Windows Management Framework 5.1.' '' 'Install WMF 5.1 and enable script block logging.' 'T1059.001'
    } elseif (-not $cfg.ScriptBlock) {
        Add-Finding 'High' 'Visibility' 'PowerShell script block logging is not enabled' 'Only blocks that PowerShell itself flags as suspicious are logged - obfuscated or "clean looking" attacker scripts are missed.' 'EnableScriptBlockLogging is not 1' 'GPO: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging' 'T1059.001'
    }
    if (-not $cfg.ModuleLogging) { Add-Finding 'Low' 'Visibility' 'PowerShell module logging is not enabled' 'Pipeline execution details (4103) are not recorded.' '' 'GPO: Turn on Module Logging, module names = *' 'T1059.001' }
    if ($cfg.PSv2Usable) { Add-Finding 'Medium' 'Visibility' 'PowerShell 2.0 engine is installed' 'Attackers can run "powershell -version 2" to bypass script block logging and AMSI.' 'HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine present, .NET 2.0/3.5 installed' 'Remove the Windows PowerShell 2.0 Engine feature.' 'T1059.001' }
    if (-not $cfg.Sysmon.Installed) { Add-Finding 'Medium' 'Visibility' 'Sysmon is not installed' 'No process-level network, file, registry, image load or LSASS access telemetry beyond native auditing.' '' 'Deploy Sysmon with a maintained configuration (e.g. SwiftOnSecurity / Olaf Hartong modular).' '' }
    $disabled = New-Object System.Collections.ArrayList
    foreach ($d in $KeyLogDefs) {
        if (-not (Test-RoleApplies $d.Roles) -and $d.Roles -ne 'OPT') { continue }
        $L = Get-Log $d.Name
        if ($L -and -not $L.Enabled -and $d.Name -ne 'Security' -and $d.Name -ne 'System') { [void]$disabled.Add($d.Name) }
    }
    if ($disabled.Count -gt 0) {
        Add-Finding 'Medium' 'Visibility' ('{0} useful log channel(s) are disabled' -f $disabled.Count) 'These channels hold evidence for common attacker techniques but are switched off (several are disabled by default).' ($disabled.ToArray() -join '; ') ('wevtutil sl "<channel>" /e:true  (e.g. wevtutil sl "{0}" /e:true)' -f $disabled[0]) ''
    }
    if (-not $cfg.NtlmAudit) { Add-Finding 'Low' 'Visibility' 'NTLM usage auditing is not configured' 'NTLM relay / downgrade activity is not visible in Microsoft-Windows-NTLM/Operational.' '' 'GPO: Network security: Restrict NTLM: Audit incoming NTLM traffic / Audit NTLM authentication in this domain' 'T1557' }
    $fwOn = @($cfg.Firewall | Where-Object { $_.Dropped -or $_.Allowed })
    if ($fwOn.Count -eq 0) { Add-Finding 'Low' 'Visibility' 'Windows Firewall logging is disabled' 'No record of allowed / dropped connections on the host.' '' 'Enable logging of dropped (and ideally successful) connections, size >= 16 MB.' '' }
    if ($script:Audit.Available -and $script:Caps.AdvancedAuditGpo -and $cfg -and $script:Audit.NoLegacy -ne 1) {
        Add-Finding 'Low' 'Visibility' 'Legacy audit policy can override the advanced audit policy' 'SCENoApplyLegacyAuditPolicy is not set - legacy category settings may overwrite subcategory settings.' ('SCENoApplyLegacyAuditPolicy = ' + $script:Audit.NoLegacy) 'GPO: Audit: Force audit policy subcategory settings to override audit policy category settings = Enabled' ''
    }
    foreach ($ca in $cfg.CA) {
        if ([int]$ca.AuditFilter -ne 127) { Add-Finding 'High' 'Visibility' ('AD CS audit filter for "{0}" is {1}' -f $ca.Name, $ca.AuditFilter) 'Certificate Services events (4886/4887/4888) are only generated when the CA audit filter is enabled.' ('AuditFilter = ' + $ca.AuditFilter) 'certutil -setreg CA\AuditFilter 127 ; restart CertSvc' 'T1649' }
    }
    if ($sys.Roles -contains 'DNS' -and -not $cfg.DnsLogLevel) {
        Add-Finding 'Low' 'Visibility' 'DNS server debug / query logging is not enabled' 'Client DNS queries (C2, exfiltration over DNS) are not recorded on the server.' '' 'Enable DNS analytical logging (2012 R2+) or debug logging with a size limit.' 'T1071.004'
    }
    if ($sys.Roles -contains 'DHCP' -and $cfg.DhcpAudit -ne 1) { Add-Finding 'Medium' 'Visibility' 'DHCP audit logging is disabled' 'IP to host mapping for the investigation is not available.' '' 'Enable DHCP audit logging (Set-DhcpServerAuditLog -Enable $true).' '' }
    if ($cfg.IIS -and -not $cfg.IIS.Enabled) { Add-Finding 'High' 'Visibility' 'IIS logging is disabled' 'Web requests (web shells, exploitation) are not recorded.' '' 'Enable W3C logging for all sites, include all fields.' 'T1505.003' }

    # ---- retention / coverage
    if ($sec -and $sec.Readable -and $sec.Oldest) {
        $hist = ($script:RunStart - $sec.Oldest).TotalHours
        $fw = Test-SplunkHealthy 'Security'
        $note = ''; if ($fw) { $note = ' Splunk receives the Security log, so older events should be available there.' }
        if ($hist -lt 24) { $sev = 'High'; if ($fw) { $sev = 'Medium' }; Add-Finding $sev 'Retention' ('Security log only reaches back {0}' -f (Format-Span $hist)) ('At the current rate of {0} events/hour the log overwrites itself quickly.{1}' -f (Num $sec.Rate '0'), $note) ('Oldest event {0}; size {1} of {2}' -f (Format-Date $sec.Oldest), (Format-Size $sec.FileBytes), (Format-Size $sec.MaxBytes)) 'Collect the log immediately; increase the maximum size (>= 1 GB, DC up to 4 GB) or enable archiving.' '' }
        elseif ($hist -lt 168) { $sev = 'Medium'; if ($fw) { $sev = 'Low' }; Add-Finding $sev 'Retention' ('Security log only reaches back {0}' -f (Format-Span $hist)) ('Less than a week of local history.' + $note) ('Oldest event ' + (Format-Date $sec.Oldest)) 'Increase the maximum size or enable archiving.' '' }
        $minSize = 196MB; if ($sys.Roles -contains 'DC') { $minSize = 1GB }
        if ($sec.MaxBytes -gt 0 -and $sec.MaxBytes -lt 20MB) { Add-Finding 'High' 'Tampering' ('Security log maximum size is only {0}' -f (Format-Size $sec.MaxBytes)) 'An abnormally small maximum size makes evidence disappear within minutes - check whether it was reduced on purpose.' '' 'wevtutil sl Security /ms:1073741824' 'T1562.002' }
        elseif ($sec.MaxBytes -gt 0 -and $sec.MaxBytes -lt $minSize) { Add-Finding 'Medium' 'Retention' ('Security log maximum size {0} is below the recommended {1}' -f (Format-Size $sec.MaxBytes), (Format-Size $minSize)) 'CIS recommends at least 196 MB; domain controllers need 1-4 GB.' '' ('wevtutil sl Security /ms:{0}' -f [long]$minSize) '' }
    }
    if ($script:Suspect) {
        $short = New-Object System.Collections.ArrayList
        foreach ($n in 'Security', 'System', $SysmonLog, $PSOpLog) {
            $L = Get-Log $n
            if ($L -and $L.Oldest -and $L.Oldest -gt $script:Suspect) { [void]$short.Add(('{0} starts {1} ({2} too late)' -f (Get-ShortLogName $n), (Format-Date $L.Oldest), (Format-Span ($L.Oldest - $script:Suspect).TotalHours))) }
        }
        if ($short.Count -gt 0) { Add-Finding 'High' 'Retention' 'Key logs do not reach back to the suspected start of the incident' ('Suspected start: ' + (Format-Date $script:Suspect)) ($short.ToArray() -join '; ') 'Obtain the missing period from Splunk, archived .evtx files, backups or volume shadow copies.' '' }
    }
    $arch = @($script:Archives.Values)
    if ($arch.Count -gt 0) {
        $ev = ($arch | ForEach-Object { '{0}: {1} file(s), {2} - {3}' -f $_.Log, $_.Count, (Format-Date $_.First), (Format-Date $_.Last) }) -join '; '
        Add-Finding 'Info' 'Retention' 'Archived event log files found' 'Archived .evtx files extend the available history - collect them with the live logs.' $ev 'Copy the Archive-*.evtx files.' ''
    }

    # ---- SIEM
    $other = $script:Other
    if (-not $sp.Installed) {
        if ($other.Wef.Count -gt 0) { Add-Finding 'Medium' 'SIEM' 'No Splunk forwarder - logs are forwarded with Windows Event Forwarding' 'Which events the WEF subscriptions collect cannot be determined on this host.' ($other.Wef -join '; ') 'Check the subscriptions on the collector.' '' }
        elseif (@($other.Agents | Where-Object { $_.Type -eq 'Log forwarder' }).Count -gt 0) { Add-Finding 'Medium' 'SIEM' 'No Splunk forwarder - another log forwarder is installed' 'Its filtering could not be analysed.' (($other.Agents | Where-Object { $_.Type -eq 'Log forwarder' } | ForEach-Object { $_.Product }) -join ', ') 'Review the forwarder configuration manually.' '' }
        else { Add-Finding 'High' 'SIEM' 'No log forwarding found - local logs are the only copy' 'Events that are overwritten or cleared locally are lost for good.' '' 'Forward at least the Security, System, Sysmon and PowerShell logs to the SIEM.' '' }
    } else {
        if ($sp.ServiceState -ne 'Running') { Add-Finding 'Critical' 'SIEM' ('Splunk forwarder service is ' + $sp.ServiceState) 'No events are forwarded while the service is not running - possible tampering.' ('{0} ({1})' -f $sp.Service, $sp.StartMode) 'Start the service; check System 7036/7040 for who stopped it.' 'T1562.006' }
        elseif ($sp.StartMode -eq 'Disabled') { Add-Finding 'High' 'SIEM' 'Splunk forwarder start type is Disabled' 'Forwarding stops after the next reboot.' '' 'Set the start type to Automatic.' 'T1562.006' }
        $h = $sp.Health
        if ($h.OutputErrors24h -gt 0 -or $h.Blocked24h -gt 0) {
            Add-Finding 'High' 'SIEM' 'Splunk forwarder reports output errors / blocked queues' 'Events may be logged locally but not reach Splunk.' (('{0} output error(s), {1} blocked message(s) in the last 24 h; last connection to an indexer: {2}' -f $h.OutputErrors24h, $h.Blocked24h, (Format-Date $h.LastConnected))) 'Check connectivity to the indexers and the forwarder queues (splunkd.log).' ''
        }
        $secIn = Get-SplunkInput 'Security'
        if (-not $secIn.Exists -or $secIn.Disabled) { Add-Finding 'High' 'SIEM' 'Security log is not forwarded to Splunk' 'The forwarder has no enabled [WinEventLog://Security] input.' $secIn.DisabledFile 'Enable the Security input in Splunk_TA_windows (local/inputs.conf).' '' }
        $filtered = New-Object System.Collections.ArrayList; $cond = New-Object System.Collections.ArrayList
        foreach ($u in $script:UCResults) {
            if ($u.Status -ne 'Covered' -and $u.Status -ne 'Partial') { continue }
            foreach ($s in $u.Sources) {
                if ($s.Status -ne 'Covered' -and $s.Status -ne 'Partial') { continue }
                if ($s.Siem -eq 'Filtered' -or $s.Siem -eq 'Partial') { [void]$filtered.Add(('{0} [{1}]: {2}' -f $u.Name, $s.Label, $s.SiemDetail)) }
                elseif ($s.Siem -eq 'Conditional') { [void]$cond.Add(('{0} [{1}]: {2}' -f $u.Name, $s.Label, $s.SiemDetail)) }
            }
        }
        if ($filtered.Count -gt 0) { Add-Finding 'High' 'SIEM' ('{0} logged detection source(s) are filtered out before Splunk' -f $filtered.Count) 'These events are written locally but dropped by inputs.conf whitelist / blacklist rules, so the SOC cannot see them and they are lost once the local log rolls over.' ($filtered.ToArray() -join ' | ') 'Remove the event IDs from the blacklist / add them to the whitelist on the deployment server app.' '' }
        if ($cond.Count -gt 0) { Add-Finding 'Medium' 'SIEM' ('{0} detection source(s) are only partly forwarded (conditional filters)' -f $cond.Count) 'Regex-based filters drop part of these events (e.g. the default 4662 blacklist of Splunk_TA_windows drops DCSync-relevant events).' ($cond.ToArray() -join ' | ') 'Review the regex filters against the detection needs.' '' }
        $notColl = New-Object System.Collections.ArrayList
        foreach ($d in $KeyLogDefs) {
            if ($d.Name -eq 'Application') { continue }
            $L = Get-Log $d.Name
            if (-not $L -or -not $L.Enabled -or -not ($L.Records -gt 0)) { continue }
            $in = Get-SplunkInput $d.Name
            if (-not $in.Exists -or $in.Disabled) { [void]$notColl.Add($d.Name) }
        }
        if ($notColl.Count -gt 0) { Add-Finding 'Medium' 'SIEM' ('{0} local log(s) with evidence are not collected by Splunk' -f $notColl.Count) 'These logs exist and contain events but have no enabled Splunk input.' ($notColl.ToArray() -join '; ') 'Add [WinEventLog://<channel>] inputs for them.' '' }
    }
}

function Test-SplunkHealthy([string]$Channel) {
    $sp = $script:Splunk
    if (-not $sp.Installed -or $sp.ServiceState -ne 'Running') { return $false }
    if ($sp.Health.OutputErrors24h -gt 0 -or $sp.Health.Blocked24h -gt 0) { return $false }
    $in = Get-SplunkInput $Channel
    return ($in.Exists -and -not $in.Disabled)
}

# =====================================================================================================
#  Score
# =====================================================================================================
function Get-Score {
    $areas = New-Object System.Collections.ArrayList
    $pen = @{ Critical = 15; High = 7; Medium = 3; Low = 1; Info = 0 }

    $t = 25.0; $crit = 0
    foreach ($f in $script:Findings) { if ($f.Category -eq 'Tampering') { $t -= $pen[$f.Severity]; if ($f.Severity -eq 'Critical') { $crit++ } } }
    $t = [Math]::Max(0, $t)
    [void]$areas.Add(@{ Name = 'Integrity (no tampering)'; Score = $t; Max = 25; Note = ('{0} tampering finding(s), {1} critical' -f @($script:Findings | Where-Object { $_.Category -eq 'Tampering' }).Count, $crit) })

    $tot = 0; $ok = 0
    foreach ($r in $script:AuditRows) {
        if ($r.Required -eq 0 -or $r.Status -eq 'N/A') { continue }
        $tot += Get-BitCount $r.Required
        if ($null -ne $r.Effective) { $ok += Get-BitCount ($r.Required -band $r.Effective) }
    }
    $a = 0.0; $note = 'audit policy not readable'
    if ($script:Audit.Available -and $tot -gt 0) { $a = 25.0 * $ok / $tot; $note = ('{0} of {1} required settings in place' -f $ok, $tot) }
    [void]$areas.Add(@{ Name = 'Audit policy vs. role baseline'; Score = $a; Max = 25; Note = $note })

    $cfg = $script:Cfg; $v = 0.0
    if ($cfg.CmdLine -and $script:Caps.CmdLineSupported) { $v += 4 }
    if ($cfg.ScriptBlock -and $script:Caps.ScriptBlockSupported) { $v += 4 }
    if ($cfg.Sysmon.Installed -and $cfg.Sysmon.ServiceState -eq 'Running') { $v += 4 }
    if ($cfg.ModuleLogging) { $v += 1 }
    $ts = Get-Log 'Microsoft-Windows-TaskScheduler/Operational'; if ($ts -and $ts.Enabled) { $v += 1 }
    if (-not $cfg.PSv2Usable) { $v += 1 }
    [void]$areas.Add(@{ Name = 'Extended visibility (cmdline, PowerShell, Sysmon)'; Score = $v; Max = 15; Note = 'command line 4, script blocks 4, Sysmon 4, module logging / TaskScheduler / no PSv2 1 each' })

    $s = 0.0; $sp = $script:Splunk
    if ($sp.Installed) {
        $n = 0; $got = 0.0
        foreach ($u in $script:UCResults) {
            if ($u.Status -ne 'Covered' -and $u.Status -ne 'Partial') { continue }
            $n++
            switch ($u.Siem) { 'Forwarded' { $got += 1 } 'Conditional' { $got += 0.6 } 'Partial' { $got += 0.5 } }
        }
        if ($n -gt 0) { $s = 16.0 * $got / $n }
        if ($sp.ServiceState -eq 'Running') { $s += 2 } else { $s = 0 }
        if ($sp.ServiceState -eq 'Running' -and $sp.Health.OutputErrors24h -eq 0 -and $sp.Health.Blocked24h -eq 0) { $s += 2 }
        $note = ('Splunk UF {0}: {1:0}% of locally logged use cases reach the SIEM' -f $sp.Version, $(if ($n) { 100 * $got / $n } else { 0 }))
    } elseif ($script:Other.Wef.Count -gt 0 -or @($script:Other.Agents | Where-Object { $_.Type -eq 'Log forwarder' }).Count -gt 0) { $s = 8; $note = 'forwarding present but filtering unknown' }
    else { $note = 'no log forwarding' }
    [void]$areas.Add(@{ Name = 'SIEM forwarding'; Score = $s; Max = 20; Note = $note })

    $c = 0.0; $sec = Get-Log 'Security'; $note = 'Security log not readable'
    if ($sec -and $sec.Readable -and $sec.Oldest) {
        $hist = ($script:RunStart - $sec.Oldest).TotalHours
        if ($script:Suspect) { if ($sec.Oldest -le $script:Suspect) { $c += 6 } }
        elseif ($hist -ge 720) { $c += 6 } elseif ($hist -ge 168) { $c += 4.5 } elseif ($hist -ge 24) { $c += 3 } elseif ($hist -ge 4) { $c += 1.5 }
        $minSize = 196MB; if ($script:Sys.Roles -contains 'DC') { $minSize = 1GB }
        if ($sec.MaxBytes -ge $minSize) { $c += 3 }
        $note = ('Security history {0}, max size {1}' -f (Format-Span $hist), (Format-Size $sec.MaxBytes))
    }
    $bad = 0
    foreach ($n in 'Security', 'System', 'Application') { $L = Get-Log $n; if (-not $L -or -not $L.Enabled -or ($L.Mode -eq 'Retain' -and $L.IsFull)) { $bad++ } }
    if ($bad -eq 0) { $c += 3 }
    if ($script:Archives.Count -gt 0 -or ($sec -and $sec.Mode -eq 'AutoBackup')) { $c += 3 } elseif ($sec -and -not $sec.Wrapping) { $c += 1.5 }
    [void]$areas.Add(@{ Name = 'Local log coverage and health'; Score = $c; Max = 15; Note = $note })

    $total = 0.0; foreach ($x in $areas) { $total += $x.Score }
    $total = [Math]::Round($total)
    $capped = $false
    if ($crit -gt 0 -and $total -gt 59) { $total = 59; $capped = $true }
    $grade = 'F'; $label = 'Insufficient'
    if ($total -ge 90) { $grade = 'A'; $label = 'Good' } elseif ($total -ge 75) { $grade = 'B'; $label = 'Adequate' } elseif ($total -ge 60) { $grade = 'C'; $label = 'Limited' } elseif ($total -ge 40) { $grade = 'D'; $label = 'Poor' }
    return @{ Total = $total; Grade = $grade; Label = $label; Capped = $capped; Areas = $areas.ToArray(); Complete = ($script:Sys.Admin -and $script:Audit.Available) }
}

function Get-Verdict {
    $sc = $script:Score; $parts = New-Object System.Collections.ArrayList
    [void]$parts.Add(('IR readiness {0} ({1}, {2}/100).' -f $sc.Grade, $sc.Label, $sc.Total))
    if ($sc.Capped) { [void]$parts.Add('The grade is capped at D because critical tampering indicators were found.') }
    $sec = Get-Log 'Security'
    if ($sec -and $sec.Readable -and $sec.Oldest) { [void]$parts.Add(('The local Security log reaches back {0} (oldest event {1}).' -f (Format-Span ($script:RunStart - $sec.Oldest).TotalHours), (Format-Date $sec.Oldest))) }
    $uc = $script:UCResults
    [void]$parts.Add(('{0} of {1} applicable detection use cases are fully covered, {2} partially, {3} not at all.' -f @($uc | Where-Object { $_.Status -eq 'Covered' }).Count, $uc.Count, @($uc | Where-Object { $_.Status -eq 'Partial' }).Count, @($uc | Where-Object { $_.Status -eq 'Gap' }).Count))
    $sp = $script:Splunk
    if ($sp.Installed) {
        $fw = @($uc | Where-Object { $_.Siem -eq 'Forwarded' }).Count
        [void]$parts.Add(('Splunk forwarder {0}; {1} use case(s) fully forwarded.' -f $sp.ServiceState.ToLower(), $fw))
    } else { [void]$parts.Add('No Splunk forwarder was found on this host.') }
    $tc = @($script:Findings | Where-Object { $_.Category -eq 'Tampering' -and ($_.Severity -eq 'Critical' -or $_.Severity -eq 'High') }).Count
    if ($tc -gt 0) { [void]$parts.Add(('{0} high / critical tampering indicator(s) - absence of evidence on this host must not be taken as evidence of absence.' -f $tc)) }
    else { [void]$parts.Add('No high-severity tampering indicators were found in the available logs.') }
    if (-not $sc.Complete) { [void]$parts.Add('Results are incomplete (no administrative rights or audit policy not readable).') }
    return ($parts.ToArray() -join ' ')
}

# =====================================================================================================
#  JSON (PowerShell 2.0 has no ConvertTo-Json)
# =====================================================================================================
function ConvertTo-JsonString([string]$s) {
    $e = $s -replace '\\', '\\' -replace '"', '\"' -replace "`r", '\r' -replace "`n", '\n' -replace "`t", '\t' -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    return '"' + $e + '"'
}

function ConvertTo-JsonLite($Obj, [int]$Depth = 0) {
    if ($Depth -gt 14) { return '"..."' }
    if ($null -eq $Obj) { return 'null' }
    if ($Obj -is [bool]) { if ($Obj) { return 'true' } else { return 'false' } }
    if ($Obj -is [datetime]) { return ('"' + $Obj.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv) + '"') }
    if ($Obj -is [int] -or $Obj -is [long] -or $Obj -is [int16] -or $Obj -is [uint32] -or $Obj -is [uint64] -or $Obj -is [byte]) { return ([long]$Obj).ToString($Inv) }
    if ($Obj -is [double] -or $Obj -is [single] -or $Obj -is [decimal]) {
        $d = [double]$Obj
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return 'null' }
        return $d.ToString('0.####', $Inv)
    }
    if ($Obj -is [string] -or $Obj -is [char] -or $Obj -is [guid] -or $Obj -is [version] -or $Obj -is [enum] -or $Obj -is [timespan]) { return (ConvertTo-JsonString ([string]$Obj)) }
    if ($Obj -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($k in @($Obj.Keys)) { [void]$parts.Add((ConvertTo-JsonString ([string]$k)) + ':' + (ConvertTo-JsonLite $Obj[$k] ($Depth + 1))) }
        return '{' + ($parts.ToArray() -join ',') + '}'
    }
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($p in $Obj.PSObject.Properties) { [void]$parts.Add((ConvertTo-JsonString $p.Name) + ':' + (ConvertTo-JsonLite $p.Value ($Depth + 1))) }
        return '{' + ($parts.ToArray() -join ',') + '}'
    }
    if ($Obj -is [System.Collections.IEnumerable]) {
        $parts = New-Object System.Collections.ArrayList
        foreach ($i in $Obj) { [void]$parts.Add((ConvertTo-JsonLite $i ($Depth + 1))) }
        return '[' + ($parts.ToArray() -join ',') + ']'
    }
    return (ConvertTo-JsonString ([string]$Obj))
}

# =====================================================================================================
#  HTML report
# =====================================================================================================
$ReportCss = @'
:root{--bg:#f3f5f8;--card:#ffffff;--text:#1b2430;--muted:#5f6b7a;--border:#dde3ea;--head:#0f2742;--head-text:#ffffff;--accent:#1d63d8;
--crit:#9f1239;--high:#dc2626;--med:#d97706;--low:#2563eb;--info:#64748b;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--off:#a3acb9;--na:#94a3b8;
--grid:#e6eaf0;--row:#f7f9fb}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--text:#e6edf3;--muted:#9aa7b4;--border:#2d3540;--head:#0b1f36;--row:#1b222c;--grid:#2a323d;--off:#5b6573;--accent:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.wrap{max-width:1260px;margin:0 auto;padding:0 18px}
header.top{background:var(--head);color:var(--head-text);padding:22px 0 18px}
header .brand{font-size:12px;letter-spacing:.12em;text-transform:uppercase;opacity:.75}
header h1{margin:4px 0 6px;font-size:26px}
header .meta{font-size:13px;opacity:.88}
nav.toc{display:flex;flex-wrap:wrap;gap:6px;margin:16px 0}
nav.toc a{color:var(--accent);background:var(--card);border:1px solid var(--border);border-radius:16px;padding:3px 12px;text-decoration:none;font-size:13px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;margin:0 0 18px}
.card h2{margin:0 0 4px;font-size:19px}
.card h3{margin:16px 0 6px;font-size:15px}
.card .sub{color:var(--muted);margin:0 0 14px;font-size:13px}
.grid-sum{display:grid;grid-template-columns:210px 1fr 1fr;gap:22px;align-items:start}
@media (max-width:960px){.grid-sum{grid-template-columns:1fr}}
.gauge .track{stroke:var(--grid)} .gauge text{fill:var(--text)}
.area{margin:0 0 11px} .area .lbl{display:flex;justify-content:space-between;font-size:13px;gap:8px} .area .note{font-size:11px;color:var(--muted)}
.bar{height:8px;background:var(--grid);border-radius:4px;overflow:hidden;margin-top:3px} .bar>span{display:block;height:100%;border-radius:4px}
.kpis{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.kpi{border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:var(--row)}
.kpi .v{font-size:20px;font-weight:650} .kpi .k{font-size:12px;color:var(--muted)}
.verdict{border-left:4px solid var(--accent);background:var(--row);padding:10px 14px;margin:16px 0 0;border-radius:4px}
.tw{overflow-x:auto}
table.t{width:100%;border-collapse:collapse;font-size:13px}
table.t th{text-align:left;background:var(--row);color:var(--muted);font-weight:600;padding:7px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
table.t td{padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
table.t tr:hover td{background:var(--row)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.b-Critical{background:var(--crit)} .b-High{background:var(--high)} .b-Medium{background:var(--med)} .b-Low{background:var(--low)} .b-Info{background:var(--info)}
.b-ok{background:var(--ok)} .b-warn{background:var(--warn)} .b-bad{background:var(--bad)} .b-na{background:var(--na)}
.muted{color:var(--muted)} .mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;word-break:break-all} .small{font-size:12px} .nowrap{white-space:nowrap}
details{margin:8px 0} summary{cursor:pointer;font-weight:600;color:var(--accent)}
.tl{width:100%;height:auto;display:block}
.tl .lbl{fill:var(--text);font-size:12px} .tl .axis{fill:var(--muted);font-size:11px} .tl .gridl{stroke:var(--grid);stroke-width:1}
.tl .rowbg{fill:var(--row)} .tl .good{fill:var(--ok)} .tl .warn{fill:var(--warn)} .tl .bad{fill:var(--bad)} .tl .off{fill:var(--off)}
.tl .m-clear{fill:#dc2626;stroke:#fff;stroke-width:1.5} .tl .m-policy{fill:#f97316;stroke:#fff;stroke-width:1.5} .tl .m-svc{fill:#9333ea;stroke:#fff;stroke-width:1.5}
.tl .m-lost{fill:#facc15;stroke:#333;stroke-width:1} .tl .m-other{fill:#0ea5e9;stroke:#fff;stroke-width:1.5}
.tl .boot{stroke:var(--muted);stroke-dasharray:3 3} .tl .crash{stroke:#dc2626;stroke-dasharray:2 3} .tl .nowl{stroke:var(--text);stroke-width:1.5} .tl .suspect{stroke:#dc2626;stroke-width:2}
.tl .gap{fill:#dc2626;opacity:.35} .tl .hist{fill:var(--accent)} .tl .susp-t{fill:#dc2626;font-size:11px;font-weight:600}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted);margin:8px 0 2px}
.legend i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:-2px}
.legend i.dot{border-radius:50%}
.filter{width:300px;max-width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--card);color:var(--text);margin:0 0 8px}
.kv{display:grid;grid-template-columns:minmax(160px,280px) 1fr;gap:4px 14px;font-size:13px} .kv>div:nth-child(odd){color:var(--muted)}
.tag{display:inline-block;background:var(--row);border:1px solid var(--border);border-radius:4px;padding:0 6px;margin:1px 2px;font-size:12px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:16px 0 40px}
@media print{nav.toc,.filter{display:none} body{background:#fff} .card{break-inside:avoid-page;border-color:#ccc}}
'@

$ReportJs = @'
document.querySelectorAll('input.filter').forEach(function(inp){inp.addEventListener('input',function(){var q=inp.value.toLowerCase();var t=document.getElementById(inp.getAttribute('data-table'));if(!t)return;t.querySelectorAll('tbody tr').forEach(function(r){r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';});});});
'@

function A([string]$s) { [void]$script:SB.Append($s) }

function Get-Badge([string]$Text, [string]$Class) { return ('<span class="badge b-{0}">{1}</span>' -f $Class, (Esc $Text)) }

function Get-StatusBadge([string]$Status) {
    $cls = 'na'
    switch ($Status) {
        'Covered' { $cls = 'ok' } 'OK' { $cls = 'ok' } 'Forwarded' { $cls = 'ok' } 'Optional (on)' { $cls = 'ok' }
        'Partial' { $cls = 'warn' } 'Conditional' { $cls = 'warn' } 'Overwriting oldest events' { $cls = 'warn' } 'Archiving when full' { $cls = 'warn' }
        'Gap' { $cls = 'bad' } 'Missing' { $cls = 'bad' } 'Filtered' { $cls = 'bad' } 'NotCollected' { $cls = 'bad' } 'Disabled' { $cls = 'bad' }
        'FULL - new events dropped' { $cls = 'bad' } 'Access denied' { $cls = 'bad' }
    }
    $label = $Status
    if ($Status -eq 'NotCollected') { $label = 'Not collected' } elseif ($Status -eq 'None') { $label = 'No forwarder' } elseif (-not $Status) { $label = 'n/a' }
    return (Get-Badge $label $cls)
}

function Get-CoverageClass($Oldest, [bool]$Enabled) {
    if (-not $Enabled -or -not $Oldest) { return 'off' }
    if ($script:Suspect) { if ($Oldest -le $script:Suspect) { return 'good' } else { return 'bad' } }
    $h = ($script:RunStart - $Oldest).TotalHours
    if ($h -ge 168) { return 'good' }
    if ($h -ge 24) { return 'warn' }
    return 'bad'
}

function Get-TimelineRows {
    $rows = New-Object System.Collections.ArrayList
    $byLog = @{}
    foreach ($d in $KeyLogDefs) {
        $L = Get-Log $d.Name
        if (-not $L) { continue }
        if (-not ($L.Records -gt 0) -and @('Security', 'System', 'Application') -notcontains $d.Name) { continue }
        $tip = '{0}: {1}' -f $d.Name, $L.Status
        if ($L.Oldest) { $tip = '{0}&#10;{1}  ->  {2}  ({3})&#10;{4:N0} events, {5} of {6}, {7}' -f (Esc $d.Name), (Format-Date $L.Oldest), (Format-Date $L.Newest), (Format-Span $L.SpanHours), $L.Records, (Format-Size $L.FileBytes), (Format-Size $L.MaxBytes), $L.Status }
        else { $tip = Esc $tip }
        $row = @{ Label = (Get-ShortLogName $d.Name); Full = $d.Name; Oldest = $L.Oldest; Newest = $L.Newest; Class = (Get-CoverageClass $L.Oldest $L.Enabled)
            Tip = $tip; Markers = New-Object System.Collections.ArrayList; Gaps = New-Object System.Collections.ArrayList; Note = '' }
        if (-not $L.Readable) { $row.Note = 'access denied' } elseif (-not $L.Enabled) { $row.Note = 'disabled' } elseif (-not ($L.Records -gt 0)) { $row.Note = 'empty' }
        [void]$rows.Add($row); $byLog[$d.Name.ToLower()] = $row
    }
    foreach ($a in $script:Archives.Values) {
        $tip = '{0} archived .evtx files: {1} file(s), {2}&#10;archived between {3} and {4}' -f (Esc $a.Log), $a.Count, (Format-Size $a.Bytes), (Format-Date $a.First), (Format-Date $a.Last)
        [void]$rows.Add(@{ Label = ((Get-ShortLogName $a.Log) + ' (archives)'); Full = $a.Log; Oldest = $a.First; Newest = $a.Last; Class = (Get-CoverageClass $a.First $true); Tip = $tip
            Markers = New-Object System.Collections.ArrayList; Gaps = New-Object System.Collections.ArrayList; Note = '' })
    }
    foreach ($f in $script:FileSources) {
        $tip = '{0}: {1} file(s), {2}&#10;{3} -> {4}&#10;{5}' -f (Esc $f.Name), $f.Count, (Format-Size $f.Bytes), (Format-Date $f.Oldest), (Format-Date $f.Newest), (Esc $f.Note)
        [void]$rows.Add(@{ Label = $f.Name; Full = $f.Name; Oldest = $f.Oldest; Newest = $f.Newest; Class = (Get-CoverageClass $f.Oldest $true); Tip = $tip
            Markers = New-Object System.Collections.ArrayList; Gaps = New-Object System.Collections.ArrayList; Note = '' })
    }
    foreach ($t in $script:TamperEvents) {
        if ($t.Kind -eq 'boot' -or $t.Kind -eq 'crash' -or -not $t.Time) { continue }
        $k = $t.Log.ToLower()
        $row = $null
        if ($byLog.ContainsKey($k)) { $row = $byLog[$k] } elseif ($byLog.ContainsKey('system')) { $row = $byLog['system'] }
        if ($row) { [void]$row.Markers.Add($t) }
    }
    if ($script:Deep) {
        foreach ($d in $script:Deep.Scans) {
            $k = $d.Log.ToLower()
            if ($byLog.ContainsKey($k)) { foreach ($g in $d.TimeGaps) { [void]$byLog[$k].Gaps.Add($g) } }
        }
    }
    return ,$rows
}

function Get-TLX($Time) {
    $s = $script:TLx
    $age = ($s.Now - $Time).TotalHours
    if ($age -lt 0) { $age = 0 }
    if ($age -gt $s.Max) { $age = $s.Max }
    if ($s.Mode -eq 'log') { return $s.L + $s.W * (1 - [Math]::Log10(1 + $age) / $s.Den) }
    return $s.L + $s.W * (1 - $age / $s.Max)
}

function Get-TimelineSvg($Rows, [string]$Mode, [double]$WindowHours) {
    if ($Rows.Count -eq 0) { return '<p class="muted">No log data available for the timeline.</p>' }
    $now = $script:RunStart
    $W = 1180; $LW = 290; $RM = 14; $top = 30; $rowH = 26
    $plotW = $W - $LW - $RM
    $H = $top + $Rows.Count * $rowH + 26
    $maxAge = 24.0
    if ($Mode -eq 'log') {
        foreach ($r in $Rows) { if ($r.Oldest) { $a = ($now - $r.Oldest).TotalHours; if ($a -gt $maxAge) { $maxAge = $a } } }
        if ($script:Suspect) { $a = ($now - $script:Suspect).TotalHours; if ($a -gt $maxAge) { $maxAge = $a } }
        $maxAge = $maxAge * 1.1
    } else { $maxAge = $WindowHours }
    $script:TLx = @{ Mode = $Mode; Now = $now; Max = $maxAge; L = $LW; W = $plotW; Den = [Math]::Log10(1 + $maxAge) }
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append(('<svg class="tl" viewBox="0 0 {0} {1}" role="img" aria-label="Log coverage timeline">' -f $W, $H))
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        if ($i % 2 -eq 1) { [void]$sb.Append(('<rect class="rowbg" x="0" y="{0}" width="{1}" height="{2}"/>' -f ($top + $i * $rowH), $W, $rowH)) }
    }
    # axis
    $ticks = New-Object System.Collections.ArrayList
    if ($Mode -eq 'log') {
        foreach ($t in @(@(0, 'now'), @(1, '1h'), @(6, '6h'), @(24, '1d'), @(72, '3d'), @(168, '1w'), @(720, '30d'), @(2160, '90d'), @(4380, '6mo'), @(8760, '1y'), @(17520, '2y'), @(43800, '5y'))) {
            if ($t[0] -le $maxAge) { [void]$ticks.Add(@($now.AddHours(-$t[0]), $t[1])) }
        }
    } else {
        $step = 24; if ($WindowHours -le 48) { $step = 6 }
        for ($hh = 0; $hh -le $WindowHours; $hh += $step) {
            $tt = $now.AddHours(-$hh)
            $lab = $tt.ToString('MM-dd', $Inv); if ($step -lt 24) { $lab = $tt.ToString('dd HH:mm', $Inv) }
            if ($hh -eq 0) { $lab = 'now' }
            [void]$ticks.Add(@($tt, $lab))
        }
    }
    foreach ($t in $ticks) {
        $x = Num (Get-TLX $t[0]) '0.#'
        [void]$sb.Append(('<line class="gridl" x1="{0}" y1="{1}" x2="{0}" y2="{2}"/>' -f $x, ($top - 6), ($H - 20)))
        [void]$sb.Append(('<text class="axis" x="{0}" y="{1}" text-anchor="middle">{2}</text>' -f $x, ($H - 6), (Esc $t[1])))
        [void]$sb.Append(('<text class="axis" x="{0}" y="{1}" text-anchor="middle">{2}</text>' -f $x, ($top - 12), (Esc $t[1])))
    }
    # reboot / crash lines
    foreach ($t in $script:TamperEvents) {
        if (($t.Kind -ne 'boot' -and $t.Kind -ne 'crash') -or -not $t.Time) { continue }
        if (($now - $t.Time).TotalHours -gt $maxAge) { continue }
        $x = Num (Get-TLX $t.Time) '0.#'
        [void]$sb.Append(('<line class="{0}" x1="{1}" y1="{2}" x2="{1}" y2="{3}"><title>{4} {5}</title></line>' -f $t.Kind, $x, $top, ($top + $Rows.Count * $rowH), (Format-Date $t.Time), (Esc $t.Title)))
    }
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $r = $Rows[$i]; $y = $top + $i * $rowH
        $lab = $r.Label; if ($lab.Length -gt 44) { $lab = $lab.Substring(0, 42) + '..' }
        [void]$sb.Append(('<text class="lbl" x="6" y="{0}"><title>{1}</title>{2}</text>' -f ($y + 17), (Esc $r.Full), (Esc $lab)))
        if ($r.Oldest -and $r.Newest) {
            if ($Mode -ne 'log' -and ($now - $r.Newest).TotalHours -gt $maxAge) {
                [void]$sb.Append(('<text class="axis" x="{0}" y="{1}">no events in this window (newest {2})</text>' -f ($LW + 6), ($y + 17), (Format-Date $r.Newest)))
            } else {
                $x1 = Get-TLX $r.Oldest; $x2 = Get-TLX $r.Newest
                $w = [Math]::Max(3, $x2 - $x1)
                [void]$sb.Append(('<rect class="{0}" x="{1}" y="{2}" width="{3}" height="12" rx="3"><title>{4}</title></rect>' -f $r.Class, (Num $x1 '0.#'), ($y + 7), (Num $w '0.#'), $r.Tip))
            }
        } else {
            $note = $r.Note; if (-not $note) { $note = 'no events' }
            [void]$sb.Append(('<text class="axis" x="{0}" y="{1}">{2}</text>' -f ($LW + 6), ($y + 17), (Esc $note)))
        }
        foreach ($g in $r.Gaps) {
            if (($now - $g.To).TotalHours -gt $maxAge) { continue }
            $gx1 = Get-TLX $g.From; $gx2 = Get-TLX $g.To
            $exp = 'unexplained'; if ($g.Explained) { $exp = 'reboot in between' }
            [void]$sb.Append(('<rect class="gap" x="{0}" y="{1}" width="{2}" height="20"><title>No events {3} -> {4} ({5}, {6})</title></rect>' -f (Num $gx1 '0.#'), ($y + 3), (Num ([Math]::Max(2, $gx2 - $gx1)) '0.#'), (Format-Date $g.From), (Format-Date $g.To), (Format-Span ($g.Minutes / 60)), $exp))
        }
        foreach ($m in $r.Markers) {
            if (($now - $m.Time).TotalHours -gt $maxAge) { continue }
            $mx = Num (Get-TLX $m.Time) '0.#'
            [void]$sb.Append(('<circle class="m-{0}" cx="{1}" cy="{2}" r="5"><title>{3}  [{4} {5}]&#10;{6}&#10;{7}</title></circle>' -f $m.Kind, $mx, ($y + 13), (Format-Date $m.Time), (Esc (Get-ShortLogName $m.Log)), $m.Id, (Esc $m.Title), (Esc $m.Detail)))
        }
    }
    if ($script:Suspect -and ($now - $script:Suspect).TotalHours -le $maxAge) {
        $sx = Num (Get-TLX $script:Suspect) '0.#'
        [void]$sb.Append(('<line class="suspect" x1="{0}" y1="{1}" x2="{0}" y2="{2}"><title>Suspected start {3}</title></line>' -f $sx, ($top - 4), ($top + $Rows.Count * $rowH), (Format-Date $script:Suspect)))
        [void]$sb.Append(('<text class="susp-t" x="{0}" y="{1}" text-anchor="end">suspected start</text>' -f $sx, ($top + $Rows.Count * $rowH + 12)))
    }
    $nx = Num ($LW + $plotW) '0.#'
    [void]$sb.Append(('<line class="nowl" x1="{0}" y1="{1}" x2="{0}" y2="{2}"><title>Collection time {3}</title></line>' -f $nx, ($top - 4), ($top + $Rows.Count * $rowH), (Format-Date $now)))
    [void]$sb.Append('</svg>')
    return $sb.ToString()
}

function Get-HistogramSvg($Scan) {
    $keys = @($Scan.Buckets.Keys | Sort-Object)
    if ($keys.Count -lt 2) { return '<p class="muted small">Not enough data for a volume chart.</p>' }
    $first = [long]$keys[0]; $last = [long]$keys[$keys.Count - 1]
    $hours = $last - $first + 1
    $agg = [long][Math]::Max(1, [Math]::Ceiling($hours / 360.0))
    $nb = [int][Math]::Ceiling($hours / [double]$agg)
    $bins = @{}
    foreach ($k in $keys) { $b = [long][Math]::Floor(([long]$k - $first) / [double]$agg); $bins[$b] = $bins[$b] + $Scan.Buckets[$k] }
    $max = 1; foreach ($v in $bins.Values) { if ($v -gt $max) { $max = $v } }
    $W = 1180; $L = 60; $R = 10; $Hh = 90; $plot = $W - $L - $R; $bw = $plot / [double]$nb
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append(('<svg class="tl" viewBox="0 0 {0} {1}" role="img" aria-label="Events per period">' -f $W, ($Hh + 22)))
    [void]$sb.Append(('<text class="axis" x="0" y="12">{0:N0}/{1}h</text><text class="axis" x="0" y="{2}">0</text>' -f $max, $agg, $Hh))
    for ($i = 0; $i -lt $nb; $i++) {
        $start = (New-Object DateTime([long](($first + $i * $agg) * 36000000000), ([DateTimeKind]::Utc))).ToLocalTime()
        $v = $bins[[long]$i]
        $x = Num ($L + $i * $bw) '0.##'
        if (-not $v) {
            [void]$sb.Append(('<rect class="gap" x="{0}" y="{1}" width="{2}" height="{3}"><title>{4}: no events</title></rect>' -f $x, 4, (Num ([Math]::Max(1, $bw)) '0.##'), ($Hh - 4), (Format-Date $start)))
            continue
        }
        $h = [Math]::Max(1, ($Hh - 6) * $v / $max)
        [void]$sb.Append(('<rect class="hist" x="{0}" y="{1}" width="{2}" height="{3}"><title>{4}: {5:N0} events</title></rect>' -f $x, (Num ($Hh - $h) '0.#'), (Num ([Math]::Max(1, $bw - 0.5)) '0.##'), (Num $h '0.#'), (Format-Date $start), $v))
    }
    $s1 = (New-Object DateTime([long]($first * 36000000000), ([DateTimeKind]::Utc))).ToLocalTime()
    $s2 = (New-Object DateTime([long](($last + 1) * 36000000000), ([DateTimeKind]::Utc))).ToLocalTime()
    [void]$sb.Append(('<text class="axis" x="{0}" y="{1}">{2}</text><text class="axis" x="{3}" y="{1}" text-anchor="end">{4}</text></svg>' -f $L, ($Hh + 16), (Format-Date $s1), ($W - $R), (Format-Date $s2)))
    return $sb.ToString()
}

function Get-GaugeSvg($Score, [string]$Grade) {
    $color = '#dc2626'
    if ($Score -ge 90) { $color = '#16a34a' } elseif ($Score -ge 75) { $color = '#65a30d' } elseif ($Score -ge 60) { $color = '#d97706' } elseif ($Score -ge 40) { $color = '#ea580c' }
    $circ = 2 * [Math]::PI * 52
    $dash = $circ * [Math]::Max(0, [Math]::Min(100, $Score)) / 100
    return ('<svg class="gauge" viewBox="0 0 140 140" width="190" height="190" role="img" aria-label="Score {0} of 100"><circle class="track" cx="70" cy="70" r="52" fill="none" stroke-width="13"/><circle cx="70" cy="70" r="52" fill="none" stroke="{1}" stroke-width="13" stroke-linecap="round" stroke-dasharray="{2} {3}" transform="rotate(-90 70 70)"/><text x="70" y="72" text-anchor="middle" font-size="34" font-weight="700">{0}</text><text x="70" y="94" text-anchor="middle" font-size="14" font-weight="600">Grade {4}</text></svg>' -f $Score, $color, (Num $dash '0.#'), (Num $circ '0.#'), $Grade)
}

function Get-AreaColor([double]$Ratio) {
    if ($Ratio -ge 0.85) { return 'var(--ok)' }
    if ($Ratio -ge 0.6) { return '#65a30d' }
    if ($Ratio -ge 0.4) { return 'var(--warn)' }
    return 'var(--bad)'
}

function New-HtmlReport {
    $script:SB = New-Object Text.StringBuilder
    $sys = $script:Sys; $sc = $script:Score; $cfg = $script:Cfg; $sp = $script:Splunk
    $roles = @($sys.Roles | ForEach-Object { $RoleNames[$_] })
    if ($roles.Count -eq 0) { $roles = @('Member server / workstation') }
    A ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="author" content="secamin; co-author and contributor: HXM14"><meta name="generator" content="secamin/log-gap-analysis Invoke-LogGapAnalysis.ps1 v{0} (https://github.com/secamin, https://github.com/HXM14)">' -f $ScriptVersion)
    A ('<title>Logging Gap Analysis - {0}</title><style>{1}</style></head><body>' -f (Esc $sys.Host), $ReportCss)
    A '<header class="top"><div class="wrap"><div class="brand">Windows Logging Gap Analysis &middot; Incident Response</div>'
    A ('<h1>{0}</h1><div class="meta">{1} &middot; {2} &middot; {3}<br>Collected {4} ({5}) by {6} &middot; tool v{7}</div></div></header>' -f (Esc $sys.Host), (Esc $sys.Caption), (Esc ($roles -join ', ')), (Esc $sys.Domain), (Format-Date $script:RunStart), (Esc $sys.TimeZone), (Esc $sys.User), $ScriptVersion)
    A '<main class="wrap"><nav class="toc"><a href="#summary">Summary</a><a href="#findings">Findings</a><a href="#timeline">Timeline</a><a href="#coverage">Detection coverage</a><a href="#siem">SIEM / Splunk</a><a href="#audit">Audit policy</a><a href="#logs">Log inventory</a><a href="#config">Logging configuration</a><a href="#events">Tampering events</a><a href="#access">Privileged access</a>'
    if ($script:Deep) { A '<a href="#deep">Deep scan</a>' }
    A '<a href="#collection">Collection</a></nav>'

    # ---- summary
    $uc = $script:UCResults
    $nCrit = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $nHigh = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $sec = Get-Log 'Security'
    $secHist = 'n/a'; if ($sec -and $sec.Oldest) { $secHist = Format-Span ($script:RunStart - $sec.Oldest).TotalHours }
    $spState = 'Not installed'; if ($sp.Installed) { $spState = $sp.ServiceState }
    A '<section id="summary" class="card"><h2>Summary</h2><p class="sub">Overall readiness of this host''s logging for incident response.</p><div class="grid-sum"><div>'
    A (Get-GaugeSvg $sc.Total $sc.Grade)
    A ('<div class="grade" style="text-align:center">{0}</div></div><div>' -f (Esc $sc.Label))
    foreach ($a in $sc.Areas) {
        $ratio = 0; if ($a.Max -gt 0) { $ratio = $a.Score / $a.Max }
        A ('<div class="area"><div class="lbl"><span>{0}</span><span>{1} / {2}</span></div><div class="bar"><span style="width:{3}%;background:{4}"></span></div><div class="note">{5}</div></div>' -f (Esc $a.Name), (Num $a.Score '0.#'), $a.Max, (Num (100 * $ratio) '0'), (Get-AreaColor $ratio), (Esc $a.Note))
    }
    A '</div><div class="kpis">'
    A ('<div class="kpi"><div class="v" style="color:var(--crit)">{0}</div><div class="k">Critical findings</div></div>' -f $nCrit)
    A ('<div class="kpi"><div class="v" style="color:var(--high)">{0}</div><div class="k">High findings</div></div>' -f $nHigh)
    A ('<div class="kpi"><div class="v">{0} / {1}</div><div class="k">Use cases covered (partial {2}, gap {3})</div></div>' -f @($uc | Where-Object { $_.Status -eq 'Covered' }).Count, $uc.Count, @($uc | Where-Object { $_.Status -eq 'Partial' }).Count, @($uc | Where-Object { $_.Status -eq 'Gap' }).Count)
    A ('<div class="kpi"><div class="v">{0}</div><div class="k">Security log history</div></div>' -f (Esc $secHist))
    A ('<div class="kpi"><div class="v">{0}</div><div class="k">Splunk forwarder</div></div>' -f (Esc $spState))
    A ('<div class="kpi"><div class="v">{0}</div><div class="k">Tampering indicators</div></div>' -f @($script:Findings | Where-Object { $_.Category -eq 'Tampering' }).Count)
    A '</div></div>'
    A ('<div class="verdict">{0}</div></section>' -f (Esc (Get-Verdict)))

    # ---- findings
    A '<section id="findings" class="card"><h2>Findings</h2><p class="sub">Sorted by severity. Each finding includes the evidence and a recommended action.</p>'
    A ('<input class="filter" data-table="tf" placeholder="Filter findings..."><div class="tw"><table class="t" id="tf"><thead><tr><th style="width:80px">Severity</th><th style="width:100px">Category</th><th style="width:32%">Finding</th><th>Evidence</th><th style="width:26%">Recommendation</th>{0}</tr></thead><tbody>' -f $(if ($script:ComplianceOn) { '<th style="width:12%">Controls</th>' } else { '' }))
    foreach ($f in ($script:Findings | Sort-Object @{ Expression = { $_.Rank }; Descending = $true }, Category)) {
        $mitre = ''; if ($f.Mitre) { $mitre = ' <span class="tag">' + (Esc $f.Mitre) + '</span>' }
        $comp = ''; if ($script:ComplianceOn) { $comp = '<td class="small">' + (Esc $f.Compliance) + '</td>' }
        A ('<tr><td>{0}</td><td class="nowrap">{1}</td><td><b>{2}</b>{3}<div class="small muted">{4}</div></td><td class="small">{5}</td><td class="small">{6}</td>{7}</tr>' -f (Get-Badge $f.Severity $f.Severity), (Esc $f.Category), (Esc $f.Title), $mitre, (Esc $f.Detail), (Esc $f.Evidence), (Esc $f.Recommendation), $comp)
    }
    $colSpan = 5; if ($script:ComplianceOn) { $colSpan = 6 }
    if ($script:Findings.Count -eq 0) { A ('<tr><td colspan="{0}" class="muted">No findings.</td></tr>' -f $colSpan) }
    A '</tbody></table></div></section>'

    # ---- timeline
    $rows = Get-TimelineRows
    A '<section id="timeline" class="card"><h2>Log coverage timeline</h2><p class="sub">Each bar spans the oldest to the newest event of a log. Hover for details. Markers show tampering-relevant events, dashed lines are reboots.</p>'
    A '<div class="legend"><span><i style="background:var(--ok)"></i>reaches back &ge; 7 days (or to the suspected start)</span><span><i style="background:var(--warn)"></i>1 - 7 days</span><span><i style="background:var(--bad)"></i>&lt; 1 day (or misses the suspected start)</span><span><i style="background:var(--off)"></i>disabled / empty</span>'
    A '<span><i class="dot" style="background:#dc2626"></i>log cleared</span><span><i class="dot" style="background:#f97316"></i>policy / config change</span><span><i class="dot" style="background:#9333ea"></i>service stop / disable</span><span><i class="dot" style="background:#facc15"></i>events lost</span><span><i class="dot" style="background:#0ea5e9"></i>other</span>'
    if ($script:Deep) { A '<span><i style="background:#dc2626;opacity:.35"></i>period without events (deep scan)</span>' }
    A '</div><h3>Full history (logarithmic time axis - recent hours are wider)</h3>'
    A (Get-TimelineSvg $rows 'log' 0)
    $win = 168.0
    if ($script:Suspect) { $win = [Math]::Max(48, ($script:RunStart - $script:Suspect).TotalHours * 1.05) }
    A ('<h3>Last {0} (linear time axis)</h3>' -f (Format-Span $win))
    A (Get-TimelineSvg $rows 'linear' $win)
    A '</section>'

    # ---- coverage
    A '<section id="coverage" class="card"><h2>Detection coverage (MITRE ATT&amp;CK)</h2><p class="sub">Whether the current logging can support each detection / investigation use case on this host, whether the evidence reaches Splunk, and how far back the source log goes.</p>'
    A '<input class="filter" data-table="tu" placeholder="Filter use cases..."><div class="tw"><table class="t" id="tu"><thead><tr><th>Use case</th><th>Local logging</th><th>Evidence sources</th><th>Splunk</th><th>History</th></tr></thead><tbody>'
    foreach ($tac in $TacticOrder) {
        $items = @($uc | Where-Object { $_.Tactic -eq $tac })
        if ($items.Count -eq 0) { continue }
        A ('<tr><td colspan="5" style="background:var(--row);font-weight:650">{0}</td></tr>' -f (Esc $tac))
        foreach ($u in $items) {
            $srcHtml = New-Object Text.StringBuilder
            foreach ($s in $u.Sources) {
                $why = ''; if ($s.Reasons.Count -gt 0) { $why = ' <span class="muted">- ' + (Esc ($s.Reasons.ToArray() -join '; ')) + '</span>' }
                [void]$srcHtml.Append(('<div class="small">{0} <span class="mono">{1}</span>{2}</div>' -f (Get-StatusBadge $s.Status), (Esc $s.Label), $why))
            }
            $siemDetail = ''; if ($u.SiemDetail) { $siemDetail = '<div class="small muted">' + (Esc $u.SiemDetail) + '</div>' }
            $hist = ''; if ($u.Oldest) { $hist = Format-Span ($script:RunStart - $u.Oldest).TotalHours }
            $key = ''; if ($u.Key) { $key = ' <span class="tag">key</span>' }
            A ('<tr><td><b>{0}</b>{1}<div class="small muted">{2} &middot; {3}</div></td><td>{4}</td><td>{5}</td><td>{6}{7}</td><td class="nowrap">{8}</td></tr>' -f (Esc $u.Name), $key, (Esc $u.Id), (Esc $u.Mitre), (Get-StatusBadge $u.Status), $srcHtml.ToString(), (Get-StatusBadge $u.Siem), $siemDetail, (Esc $hist))
        }
    }
    A '</tbody></table></div></section>'

    # ---- SIEM
    A '<section id="siem" class="card"><h2>SIEM forwarding (Splunk)</h2>'
    if ($sp.Installed) {
        A ('<p class="sub">Configuration source: {0}. Event IDs are evaluated against the whitelist / blacklist rules of each [WinEventLog://...] input.</p>' -f (Esc $sp.Source))
        $h = $sp.Health
        A '<div class="kv">'
        A ('<div>Install folder</div><div class="mono">{0}</div><div>Version</div><div>{1}</div><div>Service</div><div>{2} - {3} ({4})</div>' -f (Esc $sp.Home), (Esc $sp.Version), (Esc $sp.Service), (Esc $sp.ServiceState), (Esc $sp.StartMode))
        A ('<div>Deployment server</div><div class="mono">{0}</div><div>Output (indexers)</div><div class="mono">{1}</div>' -f (Esc $sp.DeployServer), (Esc $sp.OutputServers))
        if ($h.LogFound) {
            A ('<div>Last connection to an indexer</div><div>{0}</div><div>Output errors / blocked (24 h)</div><div>{1} / {2}</div><div>Event log input errors (24 h)</div><div>{3}</div>' -f (Format-Date $h.LastConnected), $h.OutputErrors24h, $h.Blocked24h, $h.InputErrors24h)
        } else { A '<div>splunkd.log</div><div class="muted">not found</div>' }
        A '</div>'
        if ($h.Samples.Count -gt 0) { A ('<details><summary>Recent splunkd.log problems</summary><pre class="mono small">{0}</pre></details>' -f (Esc ($h.Samples -join "`n"))) }
        A '<h3>Event log inputs</h3><div class="tw"><table class="t"><thead><tr><th>Channel</th><th>State</th><th>Index</th><th>Whitelist</th><th>Blacklist</th><th>Options</th><th>Defined in</th></tr></thead><tbody>'
        foreach ($c in $sp.Channels) {
            $state = 'Enabled'; $cls = 'ok'; if ($c.Disabled) { $state = 'Disabled'; $cls = 'bad' }
            A ('<tr><td class="mono">{0}</td><td>{1}</td><td>{2}</td><td class="mono">{3}</td><td class="mono">{4}</td><td class="small">{5}</td><td class="small mono">{6}</td></tr>' -f (Esc $c.Channel), (Get-Badge $state $cls), (Esc $c.Index), ((Esc $c.Whitelist) -replace "`n", '<br>'), ((Esc $c.Blacklist) -replace "`n", '<br>'), (Esc $c.Options), (Esc $c.Files))
        }
        if ($sp.Channels.Count -eq 0) { A '<tr><td colspan="7" class="muted">No [WinEventLog://...] inputs found.</td></tr>' }
        A '</tbody></table></div>'
        A '<h3>Detection-relevant event IDs</h3><p class="sub">Result for every event ID used by an applicable use case.</p><div class="tw"><table class="t"><thead><tr><th>Log</th><th>Event ID</th><th>Locally logged</th><th>Splunk</th><th>Rule</th></tr></thead><tbody>'
        $seen = @{}
        foreach ($u in $uc) {
            foreach ($s in $u.Sources) {
                if ($s.Status -eq 'N/A') { continue }
                foreach ($id in $s.Ids) {
                    $k = '{0}|{1}' -f $s.Log, $id
                    if ($seen.ContainsKey($k)) { continue }
                    $seen[$k] = 1
                    $r = Test-SplunkEvent $s.Log $id
                    A ('<tr><td class="mono">{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="small mono">{4}</td></tr>' -f (Esc (Get-ShortLogName $s.Log)), $id, (Get-StatusBadge $s.Status), (Get-StatusBadge $r.State), (Esc $r.Rule))
                }
            }
        }
        A '</tbody></table></div>'
    } else {
        A '<p class="sub">No Splunk Universal Forwarder was found on this host (service with splunkd.exe or default install folder).</p>'
    }
    $ot = $script:Other
    if ($ot.Agents.Count -gt 0 -or $ot.Wef.Count -gt 0) {
        A '<h3>Other forwarders and telemetry agents</h3><div class="tw"><table class="t"><thead><tr><th>Type</th><th>Product</th><th>Service</th><th>State</th></tr></thead><tbody>'
        foreach ($a in $ot.Agents) { A ('<tr><td>{0}</td><td>{1}</td><td class="mono">{2}</td><td>{3}</td></tr>' -f (Esc $a.Type), (Esc $a.Product), (Esc $a.Service), (Esc $a.State)) }
        foreach ($w in $ot.Wef) { A ('<tr><td>Windows Event Forwarding</td><td>Subscription manager</td><td class="mono" colspan="2">{0}</td></tr>' -f (Esc $w)) }
        A '</tbody></table></div>'
    }
    A '</section>'

    # ---- audit policy
    A '<section id="audit" class="card"><h2>Audit policy</h2>'
    if ($script:Audit.Available) {
        $gpoNote = 'No GPO advanced audit policy (security\audit\audit.csv) found.'
        if ($script:Audit.Gpo) { $gpoNote = 'The GPO column shows the advanced audit policy delivered by Group Policy; a red row means the effective setting is weaker (possible local tampering).' }
        A ('<p class="sub">Effective policy (auditpol) compared with the built-in baseline for the detected role(s). {0}</p>' -f (Esc $gpoNote))
    } else { A ('<p class="sub">The audit policy could not be read: {0}</p>' -f (Esc $script:Audit.Error)) }
    A '<input class="filter" data-table="ta" placeholder="Filter subcategories..."><div class="tw"><table class="t" id="ta"><thead><tr><th>Category</th><th>Subcategory</th><th>Effective</th><th>GPO</th><th>Baseline</th><th>Status</th><th>Why it matters</th></tr></thead><tbody>'
    foreach ($r in $script:AuditRows) {
        $style = ''; if ($r.GpoMismatch) { $style = ' style="background:rgba(220,38,38,.12)"' }
        $gpo = ''; if ($null -ne $r.Gpo) { $gpo = Get-AuditText $r.Gpo }
        $req = ''; if ($r.Required -gt 0) { $req = (Get-AuditText $r.Required) + ' <span class="muted small">(' + (Esc $r.Ref) + ')</span>' }
        A ('<tr{0}><td class="small muted">{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td class="small">{7}</td></tr>' -f $style, (Esc $r.Category), (Esc $r.Name), (Esc (Get-AuditText $r.Effective)), (Esc $gpo), $req, (Get-StatusBadge $r.Status), (Esc $r.Why))
    }
    A '</tbody></table></div></section>'

    # ---- log inventory
    A '<section id="logs" class="card"><h2>Log inventory</h2><p class="sub">Key logs first. "Capacity" estimates how much history the log can hold at the current event rate.</p>'
    A '<input class="filter" data-table="tl" placeholder="Filter logs..."><div class="tw"><table class="t" id="tl"><thead><tr><th>Log</th><th>Status</th><th>Oldest</th><th>Newest</th><th>History</th><th>Events</th><th>Events/h</th><th>Size / max</th><th>Mode</th><th>Capacity</th></tr></thead><tbody>'
    $keyNames = @($KeyLogDefs | ForEach-Object { $_.Name.ToLower() })
    $ordered = New-Object System.Collections.ArrayList
    foreach ($d in $KeyLogDefs) { $L = Get-Log $d.Name; if ($L) { [void]$ordered.Add(@{ L = $L; Key = $true; Why = $d.Why }) } elseif (Test-RoleApplies $d.Roles) { [void]$ordered.Add(@{ L = $null; Key = $true; Why = $d.Why; Name = $d.Name }) } }
    foreach ($L in ($script:Logs.Values | Where-Object { $_.Records -gt 0 -and -not ($keyNames -contains $_.Name.ToLower()) } | Sort-Object { $_.Name })) { [void]$ordered.Add(@{ L = $L; Key = $false; Why = '' }) }
    foreach ($o in $ordered) {
        $L = $o.L
        if (-not $L) {
            A ('<tr><td><b>{0}</b><div class="small muted">{1}</div></td><td>{2}</td><td colspan="8" class="muted small">channel not present on this system</td></tr>' -f (Esc $o.Name), (Esc $o.Why), (Get-Badge 'Missing' 'na'))
            continue
        }
        $name = Esc $L.Name; if ($o.Key) { $name = '<b>' + $name + '</b><div class="small muted">' + (Esc $o.Why) + '</div>' }
        $hist = ''; if ($L.Oldest) { $hist = Format-Span ($script:RunStart - $L.Oldest).TotalHours }
        $fill = ''; if ($null -ne $L.FillPct) { $fill = ' (' + (Num $L.FillPct '0') + '%)' }
        $rec = ''; if ($null -ne $L.Records) { $rec = '{0:N0}' -f $L.Records }
        A ('<tr><td>{0}</td><td>{1}</td><td class="nowrap small">{2}</td><td class="nowrap small">{3}</td><td class="nowrap">{4}</td><td>{5}</td><td>{6}</td><td class="nowrap small">{7} / {8}{9}</td><td class="small">{10}</td><td class="nowrap">{11}</td></tr>' -f $name, (Get-StatusBadge $L.Status), (Format-Date $L.Oldest), (Format-Date $L.Newest), $hist, $rec, (Num $L.Rate '0.#'), (Format-Size $L.FileBytes), (Format-Size $L.MaxBytes), $fill, (Esc $L.Mode), (Format-Span $L.CapacityHours))
    }
    A '</tbody></table></div>'
    if ($script:Archives.Count -gt 0 -or $script:FileSources.Count -gt 0) {
        A '<h3>Archived event logs and file based logs</h3><div class="tw"><table class="t"><thead><tr><th>Source</th><th>Files</th><th>Size</th><th>From</th><th>To</th><th>Location</th></tr></thead><tbody>'
        foreach ($a in $script:Archives.Values) { A ('<tr><td>{0} (archived .evtx)</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td class="mono small">{5}</td></tr>' -f (Esc $a.Log), $a.Count, (Format-Size $a.Bytes), (Format-Date $a.First), (Format-Date $a.Last), (Esc $a.Folder)) }
        foreach ($f in $script:FileSources) { A ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td class="mono small">{5}</td></tr>' -f (Esc $f.Name), $f.Count, (Format-Size $f.Bytes), (Format-Date $f.Oldest), (Format-Date $f.Newest), (Esc $f.Note)) }
        A '</tbody></table></div>'
    }
    A '</section>'

    # ---- configuration
    A '<section id="config" class="card"><h2>Logging configuration</h2><p class="sub">Settings that decide what is logged, read from the registry and services.</p><div class="kv">'
    $yn = { param($b) if ($b) { 'Enabled' } else { 'Not enabled' } }
    A ('<div>4688 command line</div><div>{0}{1}</div>' -f (& $yn $cfg.CmdLine), $(if (-not $script:Caps.CmdLineSupported) { ' <span class="muted">(not supported on this OS)</span>' } else { '' }))
    A ('<div>PowerShell installed / running</div><div>{0} / {1}</div>' -f (Esc $sys.PSInstalled), (Esc $sys.PSHost))
    A ('<div>Script block logging</div><div>{0}{1}</div>' -f (& $yn $cfg.ScriptBlock), $(if ($cfg.ScriptBlockInvocation) { ' (+ invocation logging)' } else { '' }))
    A ('<div>Module logging</div><div>{0} {1}</div>' -f (& $yn $cfg.ModuleLogging), (Esc $cfg.ModuleNames))
    A ('<div>Transcription</div><div>{0} <span class="mono">{1}</span></div>' -f (& $yn $cfg.Transcription), (Esc $cfg.TranscriptDir))
    A ('<div>PowerShell 2.0 engine usable</div><div>{0}</div>' -f $(if ($cfg.PSv2Usable) { 'Yes (downgrade possible)' } else { 'No' }))
    $sm = $cfg.Sysmon
    if ($sm.Installed) { A ('<div>Sysmon</div><div>{0} {1} ({2}), driver {3} ({4}){5}<div class="small mono">config hash {6}</div></div>' -f (Esc $sm.Service), (Esc $sm.Version), (Esc $sm.ServiceState), (Esc $sm.Driver), (Esc $sm.DriverState), $(if ($sm.Renamed) { ' <span class="tag">renamed</span>' } else { '' }), (Esc $sm.ConfigHash)) }
    else { A '<div>Sysmon</div><div>Not installed</div>' }
    A ('<div>Windows Event Log service</div><div>{0} ({1})</div>' -f (Esc $cfg.EventLogState), (Esc $cfg.EventLogStart))
    A ('<div>MiniNt key</div><div>{0}</div>' -f $(if ($cfg.MiniNt) { '<b style="color:var(--bad)">PRESENT</b>' } else { 'absent' }))
    foreach ($a in $cfg.Autologger) { A ('<div>Autologger {0}</div><div>Start = {1}{2}</div>' -f (Esc $a.Session), (Esc $a.Start), $(if ($a.Disabled) { ', disabled providers: <span class="mono">' + (Esc $a.Disabled) + '</span>' } else { '' })) }
    foreach ($p in $cfg.Firewall) { A ('<div>Firewall log ({0})</div><div>dropped: {1}, allowed: {2} <span class="mono small">{3}</span></div>' -f $p.Profile, $(if ($p.Dropped) { 'yes' } else { 'no' }), $(if ($p.Allowed) { 'yes' } else { 'no' }), (Esc $p.Path)) }
    A ('<div>NTLM auditing</div><div>incoming={0}, outgoing={1}, domain={2}</div>' -f (Esc $cfg.NtlmIncoming), (Esc $cfg.NtlmOutgoing), (Esc $cfg.NtlmDomain))
    A ('<div>Legacy audit override</div><div>SCENoApplyLegacyAuditPolicy = {0}</div>' -f (Esc $script:Audit.NoLegacy))
    A ('<div>RDP</div><div>{0}</div>' -f $(if ($sys.RdpEnabled) { 'enabled' } else { 'disabled' }))
    foreach ($ca in $cfg.CA) { A ('<div>AD CS audit filter ({0})</div><div>{1}</div>' -f (Esc $ca.Name), (Esc $ca.AuditFilter)) }
    if ($sys.Roles -contains 'DNS') { A ('<div>DNS debug logging</div><div>LogLevel = {0} <span class="mono small">{1}</span></div>' -f (Esc $cfg.DnsLogLevel), (Esc $cfg.DnsLogPath)) }
    if ($sys.Roles -contains 'DHCP') { A ('<div>DHCP audit log</div><div>{0} <span class="mono small">{1}</span></div>' -f (Esc $cfg.DhcpAudit), (Esc $cfg.DhcpLogPath)) }
    if ($cfg.IIS) { A ('<div>IIS logging</div><div>{0}, format {1}, period {2} <span class="mono small">{3}</span></div>' -f $(if ($cfg.IIS.Enabled) { 'enabled' } else { 'DISABLED' }), (Esc $cfg.IIS.Format), (Esc $cfg.IIS.Period), (Esc ($cfg.IIS.Directories -join '; '))) }
    if ($sys.Roles -contains 'DC') { A ('<div>LDAP interface diagnostics</div><div>{0}</div>' -f (Esc $cfg.LdapDiag)) }
    if ($sys.Shares.Count -gt 0) { A ('<div>File shares</div><div>{0}</div>' -f (($sys.Shares | ForEach-Object { '<span class="tag">' + (Esc $_.Name) + '</span>' }) -join ' ')) }
    A '</div></section>'

    # ---- tampering events
    A '<section id="events" class="card"><h2>Tampering-relevant events</h2><p class="sub">Events found in the logs that indicate log clearing, audit / logging changes, lost events, service stops, time changes, Defender activity and PowerShell downgrades (reboots omitted).</p>'
    A '<input class="filter" data-table="te" placeholder="Filter events..."><div class="tw"><table class="t" id="te"><thead><tr><th>Time</th><th>Severity</th><th>Log</th><th>ID</th><th>Event</th><th>Details</th></tr></thead><tbody>'
    $evs = @($script:TamperEvents | Where-Object { $_.Kind -ne 'boot' } | Sort-Object { $_.Time } -Descending)
    foreach ($t in $evs) { A ('<tr><td class="nowrap small">{0}</td><td>{1}</td><td class="small">{2}</td><td>{3}</td><td>{4}</td><td class="small mono">{5}</td></tr>' -f (Format-Date $t.Time), (Get-Badge $t.Severity $t.Severity), (Esc (Get-ShortLogName $t.Log)), $t.Id, (Esc $t.Title), (Esc $t.Detail)) }
    if ($evs.Count -eq 0) { A '<tr><td colspan="6" class="muted">No tampering-relevant events found in the available logs.</td></tr>' }
    A '</tbody></table></div></section>'

    # ---- privileged access and interactive logons
    Add-AccessReportSection

    # ---- deep scan
    if ($script:Deep) {
        A ('<section id="deep" class="card"><h2>Deep scan</h2><p class="sub">Complete read of the key logs (max {0:N0} events each). Record-ID gaps indicate deleted events; periods without events longer than {1} minutes are listed.</p>' -f $DeepScanMaxEvents, $GapMinutes)
        foreach ($d in $script:Deep.Scans) {
            A ('<h3>{0}</h3><p class="small muted">{1:N0} events read in {2} s{3}; {4} record(s) missing in {5} gap(s); {6} time gap(s); {7} backwards time jump(s). {8}</p>' -f (Esc $d.Log), $d.Scanned, $d.Seconds, $(if ($d.Truncated) { ' (truncated)' } else { '' }), $d.RidMissing, $d.RidGaps.Count, $d.TimeGaps.Count, $d.Backwards, (Esc $d.Error))
            A (Get-HistogramSvg $d)
            if ($d.RidGaps.Count -gt 0) {
                A '<details open><summary>Record ID gaps</summary><table class="t"><thead><tr><th>After record</th><th>Before record</th><th>Missing</th><th>From</th><th>To</th></tr></thead><tbody>'
                foreach ($g in $d.RidGaps) { A ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f $g.AfterRecord, $g.BeforeRecord, $g.Missing, (Format-Date $g.From), (Format-Date $g.To)) }
                A '</tbody></table></details>'
            }
            if ($d.TimeGaps.Count -gt 0) {
                A '<details><summary>Periods without events</summary><table class="t"><thead><tr><th>From</th><th>To</th><th>Duration</th><th>Explained by reboot</th></tr></thead><tbody>'
                foreach ($g in ($d.TimeGaps | Sort-Object { $_.Minutes } -Descending)) { A ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (Format-Date $g.From), (Format-Date $g.To), (Format-Span ($g.Minutes / 60)), $(if ($g.Explained) { 'yes' } else { '<b>no</b>' })) }
                A '</tbody></table></details>'
            }
        }
        A '<h3>Anti-logging commands</h3>'
        if ($script:Deep.Commands.Count -gt 0) {
            A '<div class="tw"><table class="t"><thead><tr><th>Time</th><th>Log</th><th>ID</th><th>Pattern</th><th>Event data</th></tr></thead><tbody>'
            foreach ($c in $script:Deep.Commands) { A ('<tr><td class="nowrap small">{0}</td><td class="small">{1}</td><td>{2}</td><td>{3}</td><td class="mono small">{4}</td></tr>' -f (Format-Date $c.Time), (Esc (Get-ShortLogName $c.Log)), $c.Id, (Esc $c.Pattern), (Esc $c.Text)) }
            A '</tbody></table></div>'
        } else { A '<p class="muted">No anti-logging commands found in 4688, Sysmon 1, PowerShell 4104 / 400 / 800 events.</p>' }
        A '</section>'
    }

    # ---- collection
    A '<section id="collection" class="card"><h2>Collection details and limitations</h2><div class="kv">'
    A ('<div>Host</div><div>{0} ({1})</div><div>Operating system</div><div>{2} - version {3}, build {4}, {5}</div>' -f (Esc $sys.Host), (Esc $sys.Domain), (Esc $sys.Caption), (Esc $sys.Version), $sys.Build, (Esc $sys.Arch))
    A ('<div>Last boot</div><div>{0}</div><div>Run as</div><div>{1} (administrator: {2})</div>' -f (Format-Date $sys.Boot), (Esc $sys.User), $sys.Admin)
    A ('<div>Collection started / duration</div><div>{0} / {1} s</div>' -f (Format-Date $script:RunStart), [Math]::Round(((Get-Date) - $script:RunStart).TotalSeconds))
    A ('<div>Suspected start</div><div>{0}</div><div>Deep scan</div><div>{1}</div>' -f $(if ($script:Suspect) { Format-Date $script:Suspect } else { 'not given' }), $(if ($DeepScan) { 'yes' } else { 'no' }))
    A ('<div>Author</div><div>secamin &middot; <a href="https://github.com/secamin">github.com/secamin</a> (SIEM Detection Content)</div><div>Co-author and contributor</div><div>HXM14 &middot; <a href="https://github.com/HXM14">github.com/HXM14</a></div>')
    A ('<div>Tool</div><div>Invoke-LogGapAnalysis.ps1 v{0} <span class="mono small">SHA-256 {1}</span></div>' -f $ScriptVersion, (Esc $script:ScriptHash))
    A '</div><h3>OS dependent workflow</h3><div class="tw"><table class="t"><thead><tr><th>Check</th><th>Status</th><th>Note</th></tr></thead><tbody>'
    foreach ($w in $script:Workflow) { A ('<tr><td>{0}</td><td>{1}</td><td class="small">{2}</td></tr>' -f (Esc $w.Check), (Esc $w.Status), (Esc $w.Note)) }
    A '</tbody></table></div><h3>Limitations</h3><ul class="small">'
    A '<li>The script runs on a possibly compromised host: a rootkit or a modified OS can hide information from it. A clean result is not proof that the host is clean.</li>'
    A '<li>Running the script generates events itself (e.g. 4688 / 4104 / 4672) - their time is the collection time shown above.</li>'
    A '<li>Detection coverage shows whether the required events <i>can</i> be produced; object-access use cases additionally need SACLs, which are not verified.</li>'
    A '<li>Splunk filtering is evaluated from inputs.conf; regex rules on fields other than EventCode are reported as conditional. Index-time filtering (props/transforms on indexers or heavy forwarders) is not visible from this host.</li>'
    A '<li>The baseline merges public guidance (Microsoft audit policy recommendations, CIS benchmarks, ASD event logging guidance) for the detected roles.</li>'
    A '</ul></section></main>'
    A ('<footer>Windows Logging Gap Analysis v{0} &middot; generated {1} &middot; read-only collection<br>by <a href="https://github.com/secamin">secamin</a> &middot; co-author and contributor <a href="https://github.com/HXM14">HXM14</a> &middot; secamin/log-gap-analysis</footer>' -f $ScriptVersion, (Format-Date (Get-Date)))
    A ('<script>{0}</script></body></html>' -f $ReportJs)
    return $script:SB.ToString()
}

# =====================================================================================================
#  Output
# =====================================================================================================
function Write-TextFile([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($true)))
}

function Export-Results {
    $out = $script:OutDir
    $sys = $script:Sys
    if ($ComplianceMap) {
        $mapPath = $ComplianceMapPath
        if (-not $mapPath) {
            $toolRoot = Split-Path -Parent (Split-Path -Parent $ScriptPath)
            $mapPath = Join-Path (Join-Path $toolRoot 'compliance') 'control-map.csv'
        }
        $map = Import-ComplianceMap $mapPath
        if ($map) {
            $script:ComplianceOn = $true
            foreach ($f in $script:Findings) {
                $f | Add-Member -MemberType NoteProperty -Name Compliance -Value (Get-ComplianceControls $map $f.Mitre $f.Category) -Force
            }
        } else {
            Write-Host ('Compliance map not found or empty: ' + $mapPath + ' - continuing without control mapping') -ForegroundColor Yellow
        }
    }
    Write-TextFile (Join-Path $out 'report.html') (New-HtmlReport)

    $fCols = @('Severity', 'Category', 'Title', 'Detail', 'Evidence', 'Recommendation', 'Mitre')
    if ($script:ComplianceOn) { $fCols += 'Compliance' }
    $script:Findings | Sort-Object @{ Expression = { $_.Rank }; Descending = $true } | Select-Object $fCols |
        Export-Csv -Path (Join-Path $out 'findings.csv') -NoTypeInformation -Encoding UTF8
    $script:UCResults | ForEach-Object {
        New-Object PSObject -Property @{ Id = $_.Id; UseCase = $_.Name; Tactic = $_.Tactic; Mitre = $_.Mitre; Local = $_.Status; Splunk = $_.Siem
            HistoryHours = (Num $_.SpanHours '0.#'); Sources = (($_.Sources | ForEach-Object { '{0}={1} ({2})' -f $_.Label, $_.Status, ($_.Reasons.ToArray() -join '; ') }) -join ' | ')
            SplunkDetail = $_.SiemDetail }
    } | Select-Object Id, UseCase, Tactic, Mitre, Local, Splunk, HistoryHours, Sources, SplunkDetail | Export-Csv -Path (Join-Path $out 'usecases.csv') -NoTypeInformation -Encoding UTF8
    $script:Logs.Values | Sort-Object { $_.Name } | ForEach-Object {
        New-Object PSObject -Property @{ Log = $_.Name; Enabled = $_.Enabled; Status = $_.Status; Mode = $_.Mode; MaxBytes = $_.MaxBytes; FileBytes = $_.FileBytes
            FillPct = (Num $_.FillPct '0.#'); Records = $_.Records; Oldest = (Format-Date $_.Oldest); Newest = (Format-Date $_.Newest); SpanHours = (Num $_.SpanHours '0.##')
            EventsPerHour = (Num $_.Rate '0.##'); CapacityHours = (Num $_.CapacityHours '0.#'); Type = $_.Type; Path = $_.Path }
    } | Select-Object Log, Enabled, Status, Mode, MaxBytes, FileBytes, FillPct, Records, Oldest, Newest, SpanHours, EventsPerHour, CapacityHours, Type, Path |
        Export-Csv -Path (Join-Path $out 'logs.csv') -NoTypeInformation -Encoding UTF8
    $script:AuditRows | ForEach-Object {
        New-Object PSObject -Property @{ Category = $_.Category; Subcategory = $_.Name; Guid = $_.Guid; Effective = (Get-AuditText $_.Effective); Gpo = (Get-AuditText $_.Gpo)
            Baseline = (Get-AuditText $_.Required); Status = $_.Status; GpoMismatch = $_.GpoMismatch; Reference = $_.Ref }
    } | Select-Object Category, Subcategory, Guid, Effective, Gpo, Baseline, Status, GpoMismatch, Reference | Export-Csv -Path (Join-Path $out 'auditpolicy.csv') -NoTypeInformation -Encoding UTF8
    if ($script:Splunk.Installed) {
        $script:Splunk.Channels | ForEach-Object { New-Object PSObject -Property @{ Channel = $_.Channel; Disabled = $_.Disabled; Index = $_.Index; Whitelist = $_.Whitelist; Blacklist = $_.Blacklist; Options = $_.Options; Files = $_.Files } } |
            Select-Object Channel, Disabled, Index, Whitelist, Blacklist, Options, Files | Export-Csv -Path (Join-Path $out 'splunk_inputs.csv') -NoTypeInformation -Encoding UTF8
    }
    $script:TamperEvents | Sort-Object { $_.Time } | ForEach-Object { New-Object PSObject -Property @{ Time = (Format-Date $_.Time); Severity = $_.Severity; Log = $_.Log; Id = $_.Id; Event = $_.Title; Detail = $_.Detail } } |
        Select-Object Time, Severity, Log, Id, Event, Detail | Export-Csv -Path (Join-Path $out 'tampering_events.csv') -NoTypeInformation -Encoding UTF8
    Export-AccessResults $out

    $ucJson = New-Object System.Collections.ArrayList
    foreach ($u in $script:UCResults) {
        $srcs = @($u.Sources | ForEach-Object { @{ Source = $_.Label; Status = $_.Status; Reasons = $_.Reasons.ToArray(); Splunk = $_.Siem; SplunkDetail = $_.SiemDetail } })
        [void]$ucJson.Add(@{ Id = $u.Id; Name = $u.Name; Tactic = $u.Tactic; Mitre = $u.Mitre; Status = $u.Status; Splunk = $u.Siem; HistoryHours = $u.SpanHours; Sources = $srcs })
    }
    $splunk = @{}
    foreach ($k in $script:Splunk.Keys) { if ($k -ne 'Inputs') { $splunk[$k] = $script:Splunk[$k] } }
    $results = @{ Tool = 'Invoke-LogGapAnalysis'; ToolId = $ScriptToolId; Author = $ScriptAuthor; CoAuthor = $ScriptCoAuthor; Repository = $ScriptRepo; CoAuthorRepository = $ScriptCoAuthorRepo; Version = $ScriptVersion; Collected = $script:RunStart; SuspectedStart = $script:Suspect
        System = $sys; Capabilities = $script:Caps; Score = $script:Score; Verdict = (Get-Verdict); Findings = $script:Findings.ToArray(); UseCases = $ucJson.ToArray()
        AuditPolicy = $script:AuditRows.ToArray(); Logs = @($script:Logs.Values); Archives = @($script:Archives.Values); FileSources = $script:FileSources.ToArray()
        LoggingConfig = $script:Cfg; Splunk = $splunk; OtherTelemetry = $script:Other; TamperingEvents = $script:TamperEvents.ToArray(); DeepScan = $script:Deep
        PrivilegedAccess = $script:Priv; Workflow = $script:Workflow.ToArray() }
    Write-TextFile (Join-Path $out 'results.json') (ConvertTo-JsonLite $results)

    Write-TextFile (Join-Path $script:RawDir 'registry_values.txt') ($script:RegLog.ToArray() -join "`r`n")
    Write-TextFile (Join-Path $out 'collection.log') ($script:RunLog.ToArray() -join "`r`n")
    $man = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-ChildItem -LiteralPath $out -Recurse | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'manifest_sha256.txt' })) {
        [void]$man.Add(('{0}  {1}' -f (Get-FileSha256 $f.FullName), $f.FullName.Substring($out.Length + 1)))
    }
    Write-TextFile (Join-Path $out 'manifest_sha256.txt') ($man.ToArray() -join "`r`n")
}

# =====================================================================================================
#  Privileged access: local administrators, local accounts, interactive logons (added in v1.1.0)
#  ADSI (WinNT provider) + event log only - works on Windows PowerShell 2.0 / Server 2008, read-only.
# =====================================================================================================
$PrivGroupDefs = @(
    @{ Sid = 'S-1-5-32-544'; Roles = 'ALL'; Why = 'Full control of the host' },
    @{ Sid = 'S-1-5-32-555'; Roles = 'ALL'; Why = 'RDP logon right' },
    @{ Sid = 'S-1-5-32-580'; Roles = 'ALL'; Why = 'WinRM / PowerShell remoting' },
    @{ Sid = 'S-1-5-32-551'; Roles = 'ALL'; Why = 'Backup privilege - can read any file (SAM, NTDS.dit)' },
    @{ Sid = 'S-1-5-32-549'; Roles = 'DC'; Why = 'Server Operators - logon to and service control on DCs' },
    @{ Sid = 'S-1-5-32-548'; Roles = 'DC'; Why = 'Account Operators - manage most domain accounts' }
)
# DC global / universal groups whose membership changes are reported (RID suffix of the domain SID)
$PrivDomainRids = @{ '512' = 'Domain Admins'; '518' = 'Schema Admins'; '519' = 'Enterprise Admins'; '520' = 'Group Policy Creator Owners'; '526' = 'Key Admins'; '527' = 'Enterprise Key Admins' }
$LogonTypeNames = @{ 2 = 'Interactive'; 7 = 'Unlock'; 9 = 'NewCredentials (runas /netonly)'; 10 = 'RDP'; 11 = 'Cached interactive'; 12 = 'Cached RDP'; 13 = 'Cached unlock'; 3 = 'Network' }

function Get-AdsProp($Obj, [string]$Name) {
    try { return $Obj.GetType().InvokeMember($Name, 'GetProperty', $null, $Obj, $null) } catch { return $null }
}

function Get-SidName([string]$Sid) {
    if (-not $Sid -or $Sid -eq '-') { return '' }
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $n = ''
    try { $n = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
    $script:SidNameCache[$Sid] = $n
    return $n
}

function Test-PublicIp([string]$Ip) {
    if (-not $Ip -or $Ip -eq '-' -or $Ip -eq 'LOCAL') { return $false }
    $s = $Ip.Trim(); if ($s -like '::ffff:*') { $s = $s.Substring(7) }
    $a = $null
    if (-not [Net.IPAddress]::TryParse($s, [ref]$a)) { return $false }
    if ($a.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        $l = $s.ToLower()
        return -not ($l -eq '::1' -or $l.StartsWith('fe80') -or $l.StartsWith('fc') -or $l.StartsWith('fd') -or $l.StartsWith('fec0'))
    }
    $b = $a.GetAddressBytes()
    if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    return $true
}

function Get-EventsXPath([string]$LogName, [string]$XPath, [int]$Max, [int[]]$ClassicIds) {
    $out = New-Object System.Collections.ArrayList
    $L = Get-Log $LogName
    if (-not $L -or -not ($L.Records -gt 0)) { return ,$out }
    if (-not $script:HasReader) { $out = Get-ClassicEvents $LogName $ClassicIds $Max; return ,$out }
    $reader = $null
    try {
        $reader = New-EventReader $LogName $XPath $true
        while ($out.Count -lt $Max) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            [void]$out.Add((Convert-EventRecord $e $LogName))
            $e.Dispose()
        }
        if ($out.Count -ge $Max) { [void]$script:Priv.Notes.Add(('{0}: only the newest {1:N0} matching events were read (-LogonMaxEvents)' -f $LogName, $Max)) }
    } catch { Write-Step ('Query {0} failed: {1}' -f $LogName, $_.Exception.Message) 'WARN' } finally { if ($reader) { $reader.Dispose() } }
    return ,$out
}

function Get-AdsMemberInfo($m) {
    $path = [string](Get-AdsProp $m 'ADsPath'); $cls = [string](Get-AdsProp $m 'Class')
    $sid = ''; $b = Get-AdsProp $m 'objectSid'
    if ($b -is [byte[]]) { try { $sid = (New-Object Security.Principal.SecurityIdentifier($b, 0)).Value } catch { } }
    $parts = @(($path -replace '^WinNT://', '').Split('/'))
    $scope = 'Domain'; $name = ''
    if ($parts.Count -ge 3) { $scope = 'Local'; $name = '{0}\{1}' -f $parts[$parts.Count - 2], $parts[$parts.Count - 1] }
    elseif ($parts.Count -eq 2) { $name = '{0}\{1}' -f $parts[0], $parts[1] }
    else { $name = $parts[0]; $scope = 'Unresolved' }
    if ($scope -ne 'Unresolved' -and $sid -and -not $sid.StartsWith('S-1-5-21-')) { $scope = 'Well-known' }
    if ($scope -eq 'Domain' -and $sid -and (Get-SidName $sid) -eq '') { $scope = 'Unresolved' }
    if ($script:Sys.Roles -contains 'DC' -and $scope -eq 'Domain') { $scope = 'Domain (DC)' }
    $o = @{ Name = $name; Sid = $sid; Class = $cls; Scope = $scope; Path = $path; Enabled = $null; PwdNeverExpires = $null; PwdNotRequired = $null
        PwdAgeDays = $null; LastLogon = $null; Rid500 = ($sid -match '-500$') }
    if ($scope -eq 'Local' -and $cls -eq 'User') {
        $f = Get-AdsProp $m 'UserFlags'
        if ($null -ne $f) { $f = [int]$f; $o.Enabled = -not [bool]($f -band 0x2); $o.PwdNeverExpires = [bool]($f -band 0x10000); $o.PwdNotRequired = [bool]($f -band 0x20) }
        $pa = Get-AdsProp $m 'PasswordAge'; if ($null -ne $pa) { $o.PwdAgeDays = [Math]::Round([double]$pa / 86400, 0) }
        $ll = Get-AdsProp $m 'LastLogin'; if ($ll -is [datetime]) { $o.LastLogon = $ll }
    }
    return $o
}

function Expand-AdsGroup([string]$AdsPath, [string]$GroupName, [string]$Via, [int]$Depth, $Out, $Seen) {
    if ($Depth -gt 5 -or $Seen.ContainsKey($AdsPath.ToLower())) { return }
    $Seen[$AdsPath.ToLower()] = $true
    $members = @()
    try { $grp = [ADSI]($AdsPath + ',group'); $members = @($grp.psbase.Invoke('Members')) }
    catch { [void]$script:Priv.Notes.Add(('Cannot enumerate {0}: {1}' -f $AdsPath, $_.Exception.Message)); return }
    foreach ($m in $members) {
        $i = $null
        try { $i = Get-AdsMemberInfo $m } catch { continue }
        $i.Group = $GroupName; $i.Via = $Via; $i.Expanded = $null
        [void]$Out.Add($i)
        if ($i.Class -ne 'Group') { continue }
        $sub = $i.Name; if ($Via -ne 'direct') { $sub = $Via + ' > ' + $i.Name }
        if ($i.Scope -eq 'Local') { $i.Expanded = $true; Expand-AdsGroup $i.Path $GroupName $sub ($Depth + 1) $Out $Seen }
        elseif ($i.Scope -like 'Domain*' -and ($script:ExpandDomain -or $script:Sys.Roles -contains 'DC')) {
            $i.Expanded = $true; Expand-AdsGroup $i.Path $GroupName $sub ($Depth + 1) $Out $Seen
        } elseif ($i.Scope -like 'Domain*') { $i.Expanded = $false }
    }
}

function Get-PrivilegedGroups {
    $groups = New-Object System.Collections.ArrayList
    foreach ($d in $PrivGroupDefs) {
        if (-not (Test-RoleApplies $d.Roles)) { continue }
        $gname = Get-SidName $d.Sid
        if (-not $gname) { continue }                                      # group does not exist on this OS
        $short = $gname.Split('\')[-1]
        $members = New-Object System.Collections.ArrayList
        Expand-AdsGroup ('WinNT://{0}/{1}' -f $env:COMPUTERNAME, $short) $short 'direct' 0 $members @{}
        $users = @($members | Where-Object { $_.Class -ne 'Group' })
        $uniq = @{}; foreach ($u in $users) { $k = $u.Sid; if (-not $k) { $k = $u.Name }; $uniq[$k] = $true }
        [void]$groups.Add(@{ Name = $short; Sid = $d.Sid; Why = $d.Why; Members = $members.ToArray()
            Direct = @($members | Where-Object { $_.Via -eq 'direct' }).Count; EffectiveUsers = $uniq.Count
            Unexpanded = @($members | Where-Object { $_.Expanded -eq $false }).Count })
    }
    return ,$groups
}

function Get-LocalAccounts {
    $out = New-Object System.Collections.ArrayList
    if ($script:Sys.Roles -contains 'DC') { return ,$out }                 # a DC has no local SAM accounts
    try {
        $comp = [ADSI]('WinNT://{0},computer' -f $env:COMPUTERNAME)
        foreach ($c in $comp.psbase.Children) {
            if ($c.psbase.SchemaClassName -ne 'User') { continue }
            $o = Get-AdsMemberInfo $c.psbase.NativeObject
            $o.Name = '{0}\{1}' -f $env:COMPUTERNAME, ([string]$c.psbase.Name)
            $o.Scope = 'Local'
            $o.Description = [string](Get-AdsProp $c.psbase.NativeObject 'Description')
            [void]$out.Add($o)
        }
    } catch { [void]$script:Priv.Notes.Add('Cannot enumerate local accounts: ' + $_.Exception.Message) }
    return ,$out
}

function Get-LapsState {
    $r = @{ Legacy = $false; Windows = $false; Text = 'not configured' }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') -eq 1) { $r.Legacy = $true }
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') {
        $bd = Get-RegValue $p 'BackupDirectory'
        if ($null -ne $bd -and [int]$bd -gt 0) { $r.Windows = $true; $r.Target = @{ 1 = 'Entra ID'; 2 = 'Active Directory' }[[int]$bd] }
    }
    if ($r.Windows) { $r.Text = 'Windows LAPS (' + $r.Target + ')' } elseif ($r.Legacy) { $r.Text = 'legacy Microsoft LAPS (AdmPwd)' }
    if ($script:Sys.Roles -contains 'DC') { $r.Text = 'n/a on a domain controller (DSRM only)' }
    return $r
}

function Get-UserProfiles {
    $out = New-Object System.Collections.ArrayList
    try {
        $pl = Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop
        foreach ($k in $pl) {
            $sid = $k.PSChildName
            if (-not $sid.StartsWith('S-1-5-21-') -and -not $sid.StartsWith('S-1-12-1-')) { continue }
            $path = [string]$k.GetValue('ProfileImagePath')
            $created = $null; $lastUse = $null
            try { $created = (Get-Item -LiteralPath $path -Force -ErrorAction Stop).CreationTime } catch { }
            try { $lastUse = (Get-Item -LiteralPath (Join-Path $path 'NTUSER.DAT') -Force -ErrorAction Stop).LastWriteTime } catch { }
            $hi = $k.GetValue('LocalProfileLoadTimeHigh'); $lo = $k.GetValue('LocalProfileLoadTimeLow')
            if ($null -ne $hi -and $null -ne $lo) {
                try { $ft = [long][BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$hi), 0) * 4294967296 + [long][BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$lo), 0); if ($ft -gt 0) { $lt = [datetime]::FromFileTime($ft); if (-not $lastUse -or $lt -gt $lastUse) { $lastUse = $lt } } } catch { }
            }
            $name = Get-SidName $sid
            [void]$out.Add(@{ Sid = $sid; Name = $name; Path = $path; Created = $created; LastUse = $lastUse; Orphaned = (-not $name) })
        }
    } catch { [void]$script:Priv.Notes.Add('Cannot read ProfileList: ' + $_.Exception.Message) }
    return ,$out
}

function Get-CurrentSessions {
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($s in @(Get-WmiObject -Query 'SELECT LogonId, LogonType, StartTime FROM Win32_LogonSession WHERE LogonType = 2 OR LogonType = 10 OR LogonType = 11' -ErrorAction Stop)) {
            $q = "ASSOCIATORS OF {Win32_LogonSession.LogonId='" + $s.LogonId + "'} WHERE AssocClass=Win32_LoggedOnUser Role=Dependent"
            foreach ($a in @(Get-WmiObject -Query $q -ErrorAction SilentlyContinue)) {
                $st = $null; try { $st = [Management.ManagementDateTimeConverter]::ToDateTime($s.StartTime) } catch { }
                [void]$out.Add(@{ User = ('{0}\{1}' -f $a.Domain, $a.Name); Sid = [string]$a.SID; Type = [string]$LogonTypeNames[[int]$s.LogonType]; Start = $st })
            }
        }
    } catch { [void]$script:Priv.Notes.Add('Cannot list logon sessions: ' + $_.Exception.Message) }
    return ,$out
}

function Get-UserEntry([string]$Sid, [string]$Name) {
    $nk = ''; if ($Name) { $nk = $Name.ToLower() }
    if ($Sid -and $Sid.StartsWith('S-1-5-21-')) {
        $key = $Sid
        # an entry first created by name (RDP channel) is moved to the SID entry once the SID is known
        if ($nk -and $script:UserByName.ContainsKey($nk)) {
            $old = $script:UserByName[$nk]
            if ($old -like 'n:*' -and $script:Users.ContainsKey($old) -and -not $script:Users.ContainsKey($key)) { $script:Users[$key] = $script:Users[$old]; $script:Users.Remove($old); $script:Users[$key].Sid = $Sid }
        }
    } elseif ($nk -and $script:UserByName.ContainsKey($nk)) { $key = $script:UserByName[$nk] }
    else { $key = 'n:' + $nk }
    if (-not $script:Users.ContainsKey($key)) {
        $script:Users[$key] = @{ User = $Name; Sid = $Sid; Logons = 0; Sessions = 0; Types = @{}; First = $null; Last = $null; Ips = @{}; Hosts = @{}
            Failed = 0; Elevated = $false; Sources = @{}; Admin = ''; LoggedOnNow = $false; ProfileCreated = $null; ProfileLastUse = $null; Local = $false }
    }
    if ($nk) { $script:UserByName[$nk] = $key }
    $u = $script:Users[$key]
    if ($Sid -and -not $u.Sid) { $u.Sid = $Sid }
    if ($Name -and -not $u.User) { $u.User = $Name }
    return $u
}

function Add-UserSeen($u, $Time, [string]$Source) {
    if ($Time) { if (-not $u.First -or $Time -lt $u.First) { $u.First = $Time }; if (-not $u.Last -or $Time -gt $u.Last) { $u.Last = $Time } }
    $u.Sources[$Source] = $true
}

function Test-SkipAccount([string]$Sid, [string]$Name) {
    if ($Sid -eq 'S-1-5-18' -or $Sid -eq 'S-1-5-19' -or $Sid -eq 'S-1-5-20' -or $Sid -eq 'S-1-5-7') { return $true }
    $n = $Name.Split('\')[-1]
    return ($n -like 'DWM-*' -or $n -like 'UMFD-*' -or $n -like '*$' -or $n -eq 'ANONYMOUS LOGON' -or $n -eq '-' -or $n -eq '')
}

function Get-PrivilegedAccess {
    $script:Priv = @{ Available = $true; Notes = (New-Object System.Collections.ArrayList); Groups = @(); LocalAccounts = @(); Laps = $null; Profiles = @()
        Sessions = @(); Users = @(); Changes = (New-Object System.Collections.ArrayList); FailedBySource = @(); NetOnly = (New-Object System.Collections.ArrayList)
        Window = @{ Oldest = $null; Events = 0 } }
    $script:SidNameCache = @{}; $script:Users = @{}; $script:UserByName = @{}

    Write-Step '  local groups and accounts (ADSI)'
    $script:Priv.Groups = (Get-PrivilegedGroups).ToArray()
    $script:Priv.LocalAccounts = (Get-LocalAccounts).ToArray()
    foreach ($a in $script:Priv.LocalAccounts) { if ($a.Sid -and -not $script:LocalDomainSid) { $script:LocalDomainSid = $a.Sid.Substring(0, $a.Sid.LastIndexOf('-')) } }
    $script:Priv.Laps = Get-LapsState
    $script:Priv.Profiles = (Get-UserProfiles).ToArray()
    $script:Priv.Sessions = (Get-CurrentSessions).ToArray()

    $adminSids = @{}; $adminNames = @{}
    foreach ($g in $script:Priv.Groups) { if ($g.Sid -ne 'S-1-5-32-544') { continue }
        foreach ($m in $g.Members) { if ($m.Class -eq 'Group') { continue }; if ($m.Sid) { $adminSids[$m.Sid] = $m.Via }; $adminNames[$m.Name.ToLower()] = $m.Via } }
    $adminGroupSids = @{}
    foreach ($g in $script:Priv.Groups) { if ($g.Sid -ne 'S-1-5-32-544') { continue }; foreach ($m in $g.Members) { if ($m.Class -eq 'Group' -and $m.Sid) { $adminGroupSids[$m.Sid] = $m.Name } } }

    # ---- Security: successful interactive / RDP / cached / unlock / runas-netonly logons
    $types = @(2, 7, 9, 10, 11, 12, 13)
    $tx = ($types | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or '
    Write-Step '  interactive logons (4624)'
    $ev = Get-EventsXPath 'Security' ("*[System[(EventID=4624)]] and *[EventData[($tx)]]") $LogonMaxEvents @(4624)
    $elevIds = @{}
    foreach ($e in $ev) {
        $p = $e.Props; if ($p.Count -lt 19) { continue }
        $lt = 0; [void][int]::TryParse([string]$p[8], [ref]$lt)
        if (-not ($types -contains $lt)) { continue }                          # classic fallback returns all types
        $sid = [string]$p[4]; $name = '{0}\{1}' -f $p[6], $p[5]
        if (Test-SkipAccount $sid $name) { continue }
        $script:Priv.Window.Events++
        if (-not $script:Priv.Window.Oldest -or $e.Time -lt $script:Priv.Window.Oldest) { $script:Priv.Window.Oldest = $e.Time }
        $ip = [string]$p[18]; $ws = [string]$p[11]
        if ($lt -eq 9) {
            # runas /netonly or pass-the-hash / overpass-the-hash (mimikatz sekurlsa::pth uses logon process "seclogo")
            [void]$script:Priv.NetOnly.Add(@{ Time = $e.Time; User = $name; Process = [string]$p[17]; LogonProcess = ([string]$p[9]).Trim(); Outbound = $(if ($p.Count -ge 24) { '{0}\{1}' -f $p[23], $p[22] } else { '' }) })
            continue
        }
        $u = Get-UserEntry $sid $name
        $u.Logons++; $tn = $LogonTypeNames[$lt]; if (-not $tn) { $tn = 'type ' + $lt }; $u.Types[$tn] = 1 + [int]$u.Types[$tn]
        if ($ip -and $ip -ne '-' -and $ip -ne '127.0.0.1' -and $ip -ne '::1') { $u.Ips[$ip] = 1 + [int]$u.Ips[$ip] }
        if ($ws -and $ws -ne '-') { $u.Hosts[$ws] = $true }
        if ($p.Count -ge 27 -and [string]$p[26] -eq '%%1842') { $u.Elevated = $true }
        $elevIds[[string]$p[7]] = $u
        Add-UserSeen $u $e.Time 'Security 4624'
    }
    # ---- 4672 (special privileges) for the same logon IDs - marks admin sessions on systems without ElevatedToken
    if ($script:Users.Count -gt 0 -and $script:Priv.Window.Oldest -and $script:HasReader) {
        $since = $script:Priv.Window.Oldest.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        foreach ($e in (Get-EventsXPath 'Security' ("*[System[(EventID=4672) and TimeCreated[@SystemTime>='$since']]]") ($LogonMaxEvents * 2) @(4672))) {
            if ($e.Props.Count -ge 4) { $k = [string]$e.Props[3]; if ($elevIds.ContainsKey($k)) { $elevIds[$k].Elevated = $true } }
        }
    }
    # ---- failed logons (interactive, RDP and network - with NLA a failed RDP logon is logged as type 3)
    Write-Step '  failed logons (4625)'
    $fails = @{}
    foreach ($e in (Get-EventsXPath 'Security' '*[System[(EventID=4625)]]' 20000 @(4625))) {
        $p = $e.Props; if ($p.Count -lt 20) { continue }
        $lt = 0; [void][int]::TryParse([string]$p[10], [ref]$lt)
        $name = '{0}\{1}' -f $p[6], $p[5]; $ip = [string]$p[19]; if (-not $ip -or $ip -eq '-') { $ip = '(local)' }
        if (@(2, 7, 10, 11) -contains $lt) {
            # count only for accounts that also have successful logon evidence - guessed user names are listed per source below
            $fs = [string]$p[4]; $fk = $null
            if ($script:Users.ContainsKey($fs)) { $fk = $fs } elseif ($script:UserByName.ContainsKey($name.ToLower())) { $fk = $script:UserByName[$name.ToLower()] }
            if ($fk) { $script:Users[$fk].Failed++ }
        }
        $k = $ip
        if (-not $fails.ContainsKey($k)) { $fails[$k] = @{ Source = $ip; Count = 0; Users = @{}; Types = @{}; First = $e.Time; Last = $e.Time; Public = (Test-PublicIp $ip) } }
        $tn = $LogonTypeNames[$lt]; if (-not $tn) { $tn = 'type ' + $lt }
        $f = $fails[$k]; $f.Count++; $f.Users[[string]$p[5]] = $true; $f.Types[$tn] = $true
        if ($e.Time -lt $f.First) { $f.First = $e.Time }; if ($e.Time -gt $f.Last) { $f.Last = $e.Time }
    }
    $script:Priv.FailedBySource = @($fails.Values | Sort-Object { $_.Count } -Descending)

    # ---- RDP channels (often retained longer than Security, and independent of the audit policy)
    Write-Step '  RDP session history'
    foreach ($e in (Get-EventsXPath 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' '*[System[(EventID=21 or EventID=25)]]' 10000 @(21, 25))) {
        $p = $e.Props; if ($p.Count -lt 3) { continue }
        $name = [string]$p[0]; if (Test-SkipAccount '' $name) { continue }
        $u = Get-UserEntry '' $name; $u.Sessions++
        $addr = [string]$p[2]
        if ($addr -and $addr -ne 'LOCAL') { $u.Ips[$addr] = 1 + [int]$u.Ips[$addr]; $u.Types['RDP'] = 1 + [int]$u.Types['RDP'] } else { $u.Types['Console'] = 1 + [int]$u.Types['Console'] }
        Add-UserSeen $u $e.Time 'RDP session (LSM 21/25)'
    }
    foreach ($e in (Get-EventsXPath 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' '*[System[(EventID=1149)]]' 10000 @(1149))) {
        $p = $e.Props; if ($p.Count -lt 3) { continue }
        $name = '{0}\{1}' -f $p[1], $p[0]; if (-not $p[1]) { $name = [string]$p[0] }
        if (Test-SkipAccount '' $name) { continue }
        $u = Get-UserEntry '' $name
        if ($p[2]) { $u.Ips[[string]$p[2]] = 1 + [int]$u.Ips[[string]$p[2]] }
        Add-UserSeen $u $e.Time 'RDP authentication (RCM 1149)'
    }
    # ---- profiles: first interactive logon ever (profile created) and last use - survive log rollover
    foreach ($pr in $script:Priv.Profiles) {
        $nm = $pr.Name; if (-not $nm) { $nm = $pr.Sid }
        $u = Get-UserEntry $pr.Sid $nm
        $u.ProfileCreated = $pr.Created; $u.ProfileLastUse = $pr.LastUse; $u.Sources['Profile'] = $true
        if ($pr.Orphaned) { $u.Sources['Profile (account deleted / unresolvable)'] = $true }
    }
    foreach ($s in $script:Priv.Sessions) { $u = Get-UserEntry $s.Sid $s.User; $u.LoggedOnNow = $true; $u.Sources['Logged on now'] = $true }

    # ---- admin flag per user
    foreach ($u in $script:Users.Values) {
        if ($u.Sid -and $adminSids.ContainsKey($u.Sid)) { $u.Admin = 'Member (' + $adminSids[$u.Sid] + ')' }
        elseif ($u.User -and $adminNames.ContainsKey($u.User.ToLower())) { $u.Admin = 'Member (' + $adminNames[$u.User.ToLower()] + ')' }
        elseif ($u.Elevated) { $u.Admin = 'Privileged token' }
        if ($u.Sid) { $dom = $u.Sid.Substring(0, $u.Sid.LastIndexOf('-')); $u.Local = ($script:LocalDomainSid -and $dom -eq $script:LocalDomainSid) }
    }
    $script:Priv.Users = @($script:Users.Values | Sort-Object { if ($_.Last) { $_.Last } elseif ($_.ProfileLastUse) { $_.ProfileLastUse } else { [datetime]::MinValue } } -Descending)

    # ---- account and privileged group changes
    Write-Step '  account / group membership changes'
    $privSids = @{}; foreach ($d in $PrivGroupDefs) { $privSids[$d.Sid] = $true }
    foreach ($e in (Get-EventsXPath 'Security' '*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 or EventID=4781 or EventID=4732 or EventID=4733 or EventID=4728 or EventID=4729 or EventID=4756 or EventID=4757)]]' 5000 @(4720, 4722, 4724, 4726, 4781, 4732, 4733, 4728, 4729, 4756, 4757))) {
        $p = $e.Props; $c = $null
        switch ($e.Id) {
            { @(4732, 4733, 4728, 4729, 4756, 4757) -contains $_ } {
                if ($p.Count -lt 8) { break }
                $gsid = [string]$p[4]; $rid = $gsid.Split('-')[-1]
                $isPriv = $privSids.ContainsKey($gsid) -or ($gsid.StartsWith('S-1-5-21-') -and $PrivDomainRids.ContainsKey($rid)) -or $adminGroupSids.ContainsKey($gsid)
                if (-not $isPriv) { break }
                $member = [string]$p[0]; $msid = [string]$p[1]
                if (-not $member -or $member -eq '-') { $member = Get-SidName $msid; if (-not $member) { $member = $msid } }
                $act = 'added to'; if (@(4733, 4729, 4757) -contains $e.Id) { $act = 'removed from' }
                $c = @{ Kind = $act; Account = $member; AccountSid = $msid; Target = ('{0}\{1}' -f $p[3], $p[2]); By = ('{0}\{1}' -f $p[7], $p[6]) }
            }
            4781 { if ($p.Count -ge 7) { $c = @{ Kind = 'renamed'; Account = ('{0} -> {1}' -f $p[0], $p[1]); AccountSid = [string]$p[3]; Target = ''; By = ('{0}\{1}' -f $p[6], $p[5]) } } }
            default {
                if ($p.Count -lt 6) { break }
                $k = @{ 4720 = 'account created'; 4722 = 'account enabled'; 4724 = 'password reset'; 4726 = 'account deleted' }[$e.Id]
                $c = @{ Kind = $k; Account = ('{0}\{1}' -f $p[1], $p[0]); AccountSid = [string]$p[2]; Target = ''; By = ('{0}\{1}' -f $p[5], $p[4]) }
            }
        }
        if ($c) {
            $c.Time = $e.Time; $c.Id = $e.Id
            $c.AfterSuspect = [bool]($script:Suspect -and $e.Time -ge $script:Suspect)
            [void]$script:Priv.Changes.Add($c)
        }
    }
    $secL = Get-Log 'Security'
    if (-not $script:Sys.Admin -or -not $secL -or -not $secL.Readable) { [void]$script:Priv.Notes.Add('Security log not readable - logon history comes only from RDP channels and profiles') }
    Add-Workflow 'Privileged access and logons' 'Executed' ('{0} group(s), {1} user(s) with logon evidence' -f $script:Priv.Groups.Count, $script:Priv.Users.Count)
}

function Add-AccessFindings {
    $P = $script:Priv; if (-not $P) { return }
    $adm = $null; foreach ($g in $P.Groups) { if ($g.Sid -eq 'S-1-5-32-544') { $adm = $g } }
    $isDC = $script:Sys.Roles -contains 'DC'
    if ($adm) {
        $users = @($adm.Members | Where-Object { $_.Class -ne 'Group' })
        $ev = (@($adm.Members | Where-Object { $_.Via -eq 'direct' } | ForEach-Object { $_.Name }) -join '; ')
        $sev = 'Info'; if ($adm.EffectiveUsers -gt 10) { $sev = 'Medium' } elseif ($adm.EffectiveUsers -gt 5) { $sev = 'Low' }
        $more = ''; if ($adm.Unexpanded -gt 0) { $more = (' {0} domain group(s) not expanded (use -ExpandDomainGroups or check them in AD).' -f $adm.Unexpanded) }
        Add-Finding $sev 'Access' ('Local Administrators: {0} direct member(s), {1} effective account(s)' -f $adm.Direct, $adm.EffectiveUsers) ('Every effective member can control this host, dump credentials and disable logging.' + $more) $ev 'Reduce to a dedicated admin group per server tier; remove personal and service accounts that do not need it.' 'T1078'
        $locEn = @($users | Where-Object { $_.Scope -eq 'Local' -and $_.Enabled })
        if ($locEn.Count -gt 0 -and -not $isDC) {
            $sev = 'Medium'; if (-not $P.Laps.Legacy -and -not $P.Laps.Windows) { $sev = 'High' }
            Add-Finding $sev 'Access' ('{0} enabled local account(s) with administrator rights' -f $locEn.Count) ('Local admin passwords are often shared across servers and allow lateral movement with pass-the-hash. LAPS: ' + $P.Laps.Text + '.') (($locEn | ForEach-Object { '{0} (password age {1} d{2})' -f $_.Name, $_.PwdAgeDays, $(if ($_.PwdNeverExpires) { ', never expires' } else { '' }) }) -join '; ') 'Rotate these passwords now (assume they are known to the attacker); deploy Windows LAPS; deny network / RDP logon for local accounts (S-1-5-114).' 'T1078.003'
        }
        $unres = @($adm.Members | Where-Object { $_.Scope -eq 'Unresolved' })
        if ($unres.Count -gt 0) { Add-Finding 'Low' 'Access' ('{0} unresolvable SID(s) in local Administrators' -f $unres.Count) 'Deleted accounts or a domain / trust that cannot be reached. An orphaned SID can be reused by SID-history abuse.' (($unres | ForEach-Object { $_.Sid }) -join '; ') 'Identify and remove the orphaned entries.' 'T1134.005' }
    }
    $rdp = $null; foreach ($g in $P.Groups) { if ($g.Sid -eq 'S-1-5-32-555') { $rdp = $g } }
    if ($rdp -and @($rdp.Members | Where-Object { $_.Sid -eq 'S-1-5-11' -or $_.Sid -eq 'S-1-1-0' -or $_.Name -match '\\Domain Users$' }).Count -gt 0) {
        Add-Finding 'High' 'Access' 'Remote Desktop Users contains Everyone / Authenticated Users / Domain Users' 'Any domain account can open an RDP session on this server.' (($rdp.Members | ForEach-Object { $_.Name }) -join '; ') 'Restrict RDP to named admin groups.' 'T1021.001'
    }
    # account / membership changes in the retained logs
    $adds = @($P.Changes | Where-Object { $_.Kind -eq 'added to' })
    if ($adds.Count -gt 0) {
        $sev = 'High'; if (@($adds | Where-Object { $_.AfterSuspect }).Count -gt 0) { $sev = 'Critical' }
        Add-Finding $sev 'Access' ('{0} account(s) added to privileged groups within the retained logs' -f $adds.Count) 'Membership in Administrators / RDP / Backup Operators (or Domain Admins on a DC) is a common persistence and privilege escalation step.' (($adds | Select-Object -First 15 | ForEach-Object { '{0}: {1} -> {2} by {3}' -f (Format-Date $_.Time), $_.Account, $_.Target, $_.By }) -join '; ') 'Confirm each change with its owner and change ticket; remove unexplained memberships and investigate the account that made them.' 'T1098'
    }
    $created = @($P.Changes | Where-Object { $_.Kind -eq 'account created' -or $_.Kind -eq 'account enabled' })
    if ($created.Count -gt 0) {
        $sev = 'Medium'; if (@($created | Where-Object { $_.AfterSuspect }).Count -gt 0) { $sev = 'High' }
        Add-Finding $sev 'Access' ('{0} account(s) created or enabled within the retained logs' -f $created.Count) 'New or re-enabled accounts can be attacker persistence.' (($created | Select-Object -First 15 | ForEach-Object { '{0}: {1} {2} by {3}' -f (Format-Date $_.Time), $_.Kind, $_.Account, $_.By }) -join '; ') 'Validate each account against change records.' 'T1136.001'
    }
    # interactive logons
    $adminUsers = @($P.Users | Where-Object { $_.Admin -and ($_.Logons -gt 0 -or $_.Sessions -gt 0) })
    if ($P.Users.Count -gt 0) {
        $win = 'the retained logs'; if ($P.Window.Oldest) { $win = 'since ' + (Format-Date $P.Window.Oldest) }
        Add-Finding 'Info' 'Access' ('{0} account(s) with interactive / RDP logon evidence, {1} with administrator rights' -f @($P.Users | Where-Object { $_.Logons -gt 0 -or $_.Sessions -gt 0 }).Count, $adminUsers.Count) ('Security 4624 types 2/7/10/11, RDP channels and user profiles, ' + $win + '. See the Privileged access section.') (($adminUsers | Select-Object -First 15 | ForEach-Object { '{0} (last {1})' -f $_.User, (Format-Date $_.Last) }) -join '; ') 'Confirm that every interactive admin logon is expected; interactive logons leave reusable credentials in LSASS.' 'T1078'
    }
    $pub = @($P.Users | Where-Object { $u = $_; @($u.Ips.Keys | Where-Object { Test-PublicIp $_ }).Count -gt 0 })
    if ($pub.Count -gt 0) { Add-Finding 'High' 'Access' ('Interactive / RDP logons from public IP addresses ({0} account(s))' -f $pub.Count) 'RDP from the Internet is a top initial access vector for ransomware operators.' (($pub | ForEach-Object { $u = $_; '{0}: {1}' -f $u.User, (@($u.Ips.Keys | Where-Object { Test-PublicIp $_ }) -join ', ') }) -join '; ') 'Block RDP from the Internet (VPN / RD Gateway with MFA); check these sources against threat intelligence.' 'T1133' }
    if ($script:Suspect) {
        $newU = @($P.Users | Where-Object { ($_.ProfileCreated -and $_.ProfileCreated -ge $script:Suspect) -or ($_.First -and $_.First -ge $script:Suspect -and $P.Window.Oldest -and $P.Window.Oldest -lt $script:Suspect) })
        if ($newU.Count -gt 0) { Add-Finding 'High' 'Access' ('{0} account(s) logged on interactively for the first time after the suspected start' -f $newU.Count) 'The profile was created, or the first logon in a log that reaches back further appears, after -SuspectedStart.' (($newU | ForEach-Object { '{0} (first {1}, profile {2})' -f $_.User, (Format-Date $_.First), (Format-Date $_.ProfileCreated) }) -join '; ') 'Treat these accounts as compromised until explained.' 'T1078' }
    }
    $pth = @($P.NetOnly | Where-Object { $_.LogonProcess -eq 'seclogo' })
    if ($pth.Count -gt 0) { Add-Finding 'High' 'Access' ('{0} NewCredentials logon(s) (type 9, seclogo)' -f $pth.Count) 'Produced by runas /netonly - and by pass-the-hash / overpass-the-hash tools such as mimikatz sekurlsa::pth.' (($pth | Select-Object -First 10 | ForEach-Object { '{0}: {1} via {2}' -f (Format-Date $_.Time), $_.User, $_.Process }) -join '; ') 'Check whether an administrator used runas /netonly at these times; otherwise investigate the process and the outbound credentials.' 'T1550.002' }
    $bf = @($P.FailedBySource | Where-Object { $_.Count -ge 20 })
    if ($bf.Count -gt 0) {
        $sev = 'Medium'; if (@($bf | Where-Object { $_.Public }).Count -gt 0) { $sev = 'High' }
        Add-Finding $sev 'Access' ('{0} source(s) with 20 or more failed logons' -f $bf.Count) 'Password guessing / spraying. With NLA, failed RDP logons appear as type 3.' (($bf | Select-Object -First 10 | ForEach-Object { '{0}: {1} failures, {2} account(s)' -f $_.Source, $_.Count, $_.Users.Count }) -join '; ') 'Check whether any of these sources later logged on successfully.' 'T1110'
    }
    $orph = @($P.Profiles | Where-Object { $_.Orphaned })
    if ($orph.Count -gt 0) { Add-Finding 'Low' 'Access' ('{0} user profile(s) of deleted or unresolvable accounts' -f $orph.Count) 'An account logged on interactively in the past and no longer resolves - attackers delete accounts they created.' (($orph | ForEach-Object { '{0} (created {1}, last use {2})' -f $_.Sid, (Format-Date $_.Created), (Format-Date $_.LastUse) }) -join '; ') 'Resolve the SIDs in AD (deleted objects) and check the profile folders.' 'T1070' }
}

function Add-AccessReportSection {
    $P = $script:Priv; if (-not $P) { return }
    A '<section id="access" class="card"><h2>Privileged access and interactive logons</h2><p class="sub">Who can administer this host (local groups expanded through nesting), local accounts, and every account with interactive, RDP or cached logon evidence - from the Security log, the RDP channels (often retained longer) and user profiles (first and last use survive log rollover).</p><div class="kv">'
    foreach ($g in $P.Groups) {
        $ex = ''; if ($g.Unexpanded -gt 0) { $ex = (' &middot; <span class="muted">{0} domain group(s) not expanded</span>' -f $g.Unexpanded) }
        A ('<div>{0}</div><div><b>{1}</b> effective account(s), {2} direct member(s){3} <span class="small muted">- {4}</span></div>' -f (Esc $g.Name), $g.EffectiveUsers, $g.Direct, $ex, (Esc $g.Why))
    }
    A ('<div>LAPS</div><div>{0}</div><div>RDP enabled</div><div>{1}</div>' -f (Esc $P.Laps.Text), $script:Sys.RdpEnabled)
    A ('<div>Interactive sessions now</div><div>{0}</div>' -f (Esc ((@($P.Sessions | ForEach-Object { '{0} ({1}, since {2})' -f $_.User, $_.Type, (Format-Date $_.Start) }) -join '; '))))
    $w = 'no Security logon events read'; if ($P.Window.Oldest) { $w = ('{0:N0} logon events since {1}' -f $P.Window.Events, (Format-Date $P.Window.Oldest)) }
    A ('<div>Security logon window</div><div>{0}</div></div>' -f (Esc $w))

    A '<h3>Privileged group members</h3><input class="filter" data-table="tpg" placeholder="Filter members..."><div class="tw"><table class="t" id="tpg"><thead><tr><th>Group</th><th>Member</th><th>Type</th><th>Via</th><th>Enabled</th><th>Password</th><th>Last logon (local)</th><th>SID</th></tr></thead><tbody>'
    foreach ($g in $P.Groups) { foreach ($m in $g.Members) {
        $en = ''; if ($null -ne $m.Enabled) { if ($m.Enabled) { $en = Get-Badge 'Enabled' 'warn' } else { $en = Get-Badge 'Disabled' 'ok' } }
        $pw = ''; if ($null -ne $m.PwdAgeDays) { $pw = ('{0} d' -f $m.PwdAgeDays); if ($m.PwdNeverExpires) { $pw += ', never expires' }; if ($m.PwdNotRequired) { $pw += ', not required' } }
        $typ = '{0} {1}' -f $m.Scope, $m.Class.ToLower(); if ($m.Expanded -eq $false) { $typ += ' (not expanded)' }; if ($m.Rid500) { $typ += ' - built-in Administrator' }
        A ('<tr><td>{0}</td><td><b>{1}</b></td><td class="small">{2}</td><td class="small">{3}</td><td>{4}</td><td class="small nowrap">{5}</td><td class="small nowrap">{6}</td><td class="mono small">{7}</td></tr>' -f (Esc $g.Name), (Esc $m.Name), (Esc $typ), (Esc $m.Via), $en, (Esc $pw), (Format-Date $m.LastLogon), (Esc $m.Sid))
    } }
    A '</tbody></table></div>'

    if ($P.LocalAccounts.Count -gt 0) {
        A '<h3>Local accounts</h3><div class="tw"><table class="t"><thead><tr><th>Account</th><th>Enabled</th><th>Local admin</th><th>Password age</th><th>Last logon</th><th>Description</th></tr></thead><tbody>'
        foreach ($a in $P.LocalAccounts) {
            $isA = @($P.Groups | Where-Object { $_.Sid -eq 'S-1-5-32-544' } | ForEach-Object { $_.Members } | Where-Object { $_.Sid -eq $a.Sid }).Count -gt 0
            $en = Get-Badge 'Disabled' 'ok'; if ($a.Enabled) { $en = Get-Badge 'Enabled' $(if ($isA) { 'warn' } else { 'na' }) }
            $pw = ''; if ($null -ne $a.PwdAgeDays) { $pw = ('{0} d' -f $a.PwdAgeDays); if ($a.PwdNeverExpires) { $pw += ', never expires' } }
            A ('<tr><td><b>{0}</b>{1}</td><td>{2}</td><td>{3}</td><td class="small nowrap">{4}</td><td class="small nowrap">{5}</td><td class="small">{6}</td></tr>' -f (Esc $a.Name), $(if ($a.Rid500) { ' <span class="small muted">(RID 500)</span>' } else { '' }), $en, $(if ($isA) { Get-Badge 'Yes' 'bad' } else { '' }), (Esc $pw), (Format-Date $a.LastLogon), (Esc $a.Description))
        }
        A '</tbody></table></div>'
    }

    A '<h3>Accounts with interactive / RDP logon evidence</h3><p class="small muted">Logons = Security 4624 (types 2, 7, 10, 11, 12, 13). Sessions = RDP LocalSessionManager 21 / 25. Profile created is the first interactive logon ever on this host. Admin = member of local Administrators, or a privileged token (4672 / ElevatedToken).</p>'
    A '<input class="filter" data-table="tiu" placeholder="Filter accounts..."><div class="tw"><table class="t" id="tiu"><thead><tr><th>Account</th><th>Admin</th><th>Logons / sessions</th><th>Types</th><th>First seen</th><th>Last seen</th><th>Source IPs</th><th>Failed</th><th>Profile created / last use</th><th>Evidence</th></tr></thead><tbody>'
    foreach ($u in $P.Users) {
        $adm = ''; if ($u.Admin) { $adm = Get-Badge 'Admin' 'bad'; $adm += ('<div class="small muted">{0}</div>' -f (Esc $u.Admin)) }
        $now = ''; if ($u.LoggedOnNow) { $now = ' ' + (Get-Badge 'logged on now' 'warn') }
        $types = (@($u.Types.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $u.Types[$_] }) -join ', ')
        $ips = (@($u.Ips.Keys | Sort-Object { $u.Ips[$_] } -Descending | Select-Object -First 6 | ForEach-Object { $t = '{0} ({1})' -f $_, $u.Ips[$_]; if (Test-PublicIp $_) { '<b style="color:#c0392b">' + (Esc $t) + ' public</b>' } else { Esc $t } }) -join '<br>')
        $loc = ''; if ($u.Local) { $loc = ' <span class="small muted">(local)</span>' }
        A ('<tr><td><b>{0}</b>{1}{2}<div class="mono small muted">{3}</div></td><td>{4}</td><td class="nowrap">{5} / {6}</td><td class="small">{7}</td><td class="small nowrap">{8}</td><td class="small nowrap">{9}</td><td class="small mono">{10}</td><td>{11}</td><td class="small nowrap">{12}<br>{13}</td><td class="small">{14}</td></tr>' -f (Esc $u.User), $loc, $now, (Esc $u.Sid), $adm, $u.Logons, $u.Sessions, (Esc $types), (Format-Date $u.First), (Format-Date $u.Last), $ips, $(if ($u.Failed) { $u.Failed } else { '' }), (Format-Date $u.ProfileCreated), (Format-Date $u.ProfileLastUse), (Esc (@($u.Sources.Keys | Sort-Object) -join ', ')))
    }
    if ($P.Users.Count -eq 0) { A '<tr><td colspan="10" class="muted">No interactive logon evidence found.</td></tr>' }
    A '</tbody></table></div>'

    A '<h3>Account and privileged group changes</h3><div class="tw"><table class="t"><thead><tr><th>Time</th><th>ID</th><th>Change</th><th>Account</th><th>Group</th><th>By</th></tr></thead><tbody>'
    foreach ($c in @($P.Changes | Sort-Object { $_.Time } -Descending)) {
        $flag = ''; if ($c.AfterSuspect) { $flag = ' ' + (Get-Badge 'after suspected start' 'bad') }
        A ('<tr><td class="small nowrap">{0}</td><td>{1}</td><td>{2}{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f (Format-Date $c.Time), $c.Id, (Esc $c.Kind), $flag, (Esc $c.Account), (Esc $c.Target), (Esc $c.By))
    }
    if ($P.Changes.Count -eq 0) { A '<tr><td colspan="6" class="muted">No account creation or privileged group membership change in the retained Security log.</td></tr>' }
    A '</tbody></table></div>'

    if ($P.FailedBySource.Count -gt 0) {
        A '<h3>Failed logons by source (4625)</h3><div class="tw"><table class="t"><thead><tr><th>Source</th><th>Failures</th><th>Accounts</th><th>Logon types</th><th>First</th><th>Last</th></tr></thead><tbody>'
        foreach ($f in @($P.FailedBySource | Select-Object -First 25)) {
            $src = Esc $f.Source; if ($f.Public) { $src = '<b>' + $src + '</b> ' + (Get-Badge 'public' 'bad') }
            A ('<tr><td class="mono">{0}</td><td>{1}</td><td class="small">{2}</td><td class="small">{3}</td><td class="small nowrap">{4}</td><td class="small nowrap">{5}</td></tr>' -f $src, $f.Count, (Esc ((@($f.Users.Keys) | Select-Object -First 8) -join ', ')), (Esc (@($f.Types.Keys) -join ', ')), (Format-Date $f.First), (Format-Date $f.Last))
        }
        A '</tbody></table></div>'
    }
    if ($P.NetOnly.Count -gt 0) {
        A '<h3>NewCredentials logons (type 9 - runas /netonly, pass-the-hash)</h3><div class="tw"><table class="t"><thead><tr><th>Time</th><th>Account</th><th>Outbound credentials</th><th>Logon process</th><th>Process</th></tr></thead><tbody>'
        foreach ($n in @($P.NetOnly | Select-Object -First 100)) { A ('<tr><td class="small nowrap">{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td class="mono small">{4}</td></tr>' -f (Format-Date $n.Time), (Esc $n.User), (Esc $n.Outbound), (Esc $n.LogonProcess), (Esc $n.Process)) }
        A '</tbody></table></div>'
    }
    if ($P.Notes.Count -gt 0) { A ('<ul class="small muted">{0}</ul>' -f ((@($P.Notes) | ForEach-Object { '<li>' + (Esc $_) + '</li>' }) -join '')) }
    A '</section>'
}

function Export-AccessResults([string]$Out) {
    $P = $script:Priv; if (-not $P) { return }
    $rows = New-Object System.Collections.ArrayList
    foreach ($g in $P.Groups) { foreach ($m in $g.Members) {
        [void]$rows.Add((New-Object PSObject -Property @{ Group = $g.Name; Member = $m.Name; Sid = $m.Sid; Class = $m.Class; Scope = $m.Scope; Via = $m.Via
            Enabled = $m.Enabled; PwdAgeDays = $m.PwdAgeDays; PwdNeverExpires = $m.PwdNeverExpires; LastLogon = (Format-Date $m.LastLogon); Expanded = $m.Expanded }))
    } }
    $rows | Select-Object Group, Member, Sid, Class, Scope, Via, Enabled, PwdAgeDays, PwdNeverExpires, LastLogon, Expanded | Export-Csv -Path (Join-Path $Out 'privileged_groups.csv') -NoTypeInformation -Encoding UTF8
    $P.Users | ForEach-Object { $u = $_
        New-Object PSObject -Property @{ Account = $u.User; Sid = $u.Sid; Admin = $u.Admin; Local = $u.Local; Logons = $u.Logons; RdpSessions = $u.Sessions; Failed = $u.Failed
            Types = (@($u.Types.Keys | ForEach-Object { '{0}={1}' -f $_, $u.Types[$_] }) -join '; '); FirstSeen = (Format-Date $u.First); LastSeen = (Format-Date $u.Last)
            SourceIPs = (@($u.Ips.Keys | ForEach-Object { '{0}={1}' -f $_, $u.Ips[$_] }) -join '; '); Workstations = (@($u.Hosts.Keys) -join '; ')
            ProfileCreated = (Format-Date $u.ProfileCreated); ProfileLastUse = (Format-Date $u.ProfileLastUse); LoggedOnNow = $u.LoggedOnNow; Evidence = (@($u.Sources.Keys) -join '; ') }
    } | Select-Object Account, Sid, Admin, Local, Logons, RdpSessions, Failed, Types, FirstSeen, LastSeen, SourceIPs, Workstations, ProfileCreated, ProfileLastUse, LoggedOnNow, Evidence |
        Export-Csv -Path (Join-Path $Out 'interactive_logons.csv') -NoTypeInformation -Encoding UTF8
    $P.Changes | Sort-Object { $_.Time } | ForEach-Object { New-Object PSObject -Property @{ Time = (Format-Date $_.Time); Id = $_.Id; Change = $_.Kind; Account = $_.Account; AccountSid = $_.AccountSid; Group = $_.Target; By = $_.By; AfterSuspectedStart = $_.AfterSuspect } } |
        Select-Object Time, Id, Change, Account, AccountSid, Group, By, AfterSuspectedStart | Export-Csv -Path (Join-Path $Out 'account_changes.csv') -NoTypeInformation -Encoding UTF8
}

function Invoke-Phase([string]$Name, [scriptblock]$Block) {
    Write-Step $Name 'STEP'
    try { & $Block } catch {
        Write-Step ('{0} failed: {1} {2}' -f $Name, $_.Exception.Message, ($_.InvocationInfo.PositionMessage -replace '\s+', ' ')) 'ERROR'
        Add-Workflow $Name 'Error' $_.Exception.Message
    }
}

# =====================================================================================================
#  Main
# =====================================================================================================
$script:OutputGiven = [bool]$OutputPath
if (-not $OutputPath) { $OutputPath = (Get-Location -PSProvider FileSystem).ProviderPath }
if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
$script:OutDir = Join-Path $OutputPath ('LogGapAnalysis_{0}_{1}' -f $env:COMPUTERNAME, $script:RunStart.ToString('yyyyMMdd_HHmmss'))
$script:RawDir = Join-Path $script:OutDir 'raw'
New-Item -ItemType Directory -Path $script:RawDir -Force | Out-Null

Write-Host ''
Write-Host ('  Windows Logging Gap Analysis v{0}  -  {1}' -f $ScriptVersion, $env:COMPUTERNAME) -ForegroundColor Cyan
Write-Host ('  by {0} ({1})  -  co-author and contributor {2} ({3})' -f $ScriptAuthor, $ScriptRepo, $ScriptCoAuthor, $ScriptCoAuthorRepo) -ForegroundColor DarkCyan
Write-Host ('  Output: {0}' -f $script:OutDir) -ForegroundColor Cyan
Write-Host ''
$script:ScriptHash = ''; if ($ScriptPath) { $script:ScriptHash = Get-FileSha256 $ScriptPath }
$script:Svc = @{}
try { foreach ($s in @(Get-WmiObject Win32_Service -ErrorAction Stop)) { $script:Svc[$s.Name.ToLower()] = $s } } catch { Write-Step ('Cannot list services: ' + $_.Exception.Message) 'WARN' }
$script:Logs = @{}; $script:Archives = @{}; $script:FileSources = New-Object System.Collections.ArrayList
$script:Audit = @{ Available = $false; Effective = @{}; Gpo = $null; LocalGpo = $null; Error = 'not collected'; NoLegacy = $null; AllOff = $false }
$script:Cfg = @{ Sysmon = @{ Installed = $false }; Firewall = @(); Autologger = @(); LogPaths = @{}; CA = @() }
$script:Splunk = @{ Installed = $false; Inputs = @{}; Channels = @(); Health = @{} }; $script:SplunkInputCache = @{}
$script:Other = @{ Agents = @(); Wef = @() }
$script:TamperEvents = New-Object System.Collections.ArrayList; $script:ShutdownTimes = New-Object System.Collections.ArrayList
$script:TamperSummary = @{ Cleared = 0; ClearedOther = @{}; ServiceStops = 0; Lost = 0; PolicyRemovals = 0; PolicyChanges = 0; TimeChanges = 0; EventLogSvc = 0
    SysmonStops = 0; SysmonConfig = 0; DefenderOff = 0; Detections = (New-Object System.Collections.ArrayList); PSv2 = 0; PSv2Last = $null; PSv2Sample = '' }
$script:Deep = $null
$script:Priv = $null; $script:LocalDomainSid = $null; $script:ExpandDomain = [bool]$ExpandDomainGroups; $script:SidNameCache = @{}

Invoke-Phase 'System profile and roles' {
    $script:Sys = Get-SystemProfile
    $script:Caps = Get-Capabilities
    $r = @($script:Sys.Roles | ForEach-Object { $RoleNames[$_] }) -join ', '
    if (-not $r) { $r = 'no server role detected' }
    Write-Step ('{0} | {1} | admin: {2}' -f $script:Sys.Family, $r, $script:Sys.Admin) 'OK'
    if (-not $script:Sys.Admin) { Write-Step 'Not running as Administrator - Security log and audit policy will not be readable' 'WARN' }
    if (-not $script:OutputGiven) { Write-Step 'No -OutputPath given: results are written to the current directory on this host' 'WARN' }
}
Invoke-Phase 'Event log inventory' {
    $script:Logs = Get-LogInventory
    $script:Archives = Get-ArchivedLogs
    $withData = @($script:Logs.Values | Where-Object { $_.Records -gt 0 }).Count
    Write-Step ('{0} logs, {1} with events, {2} archived log set(s)' -f $script:Logs.Count, $withData, $script:Archives.Count) 'OK'
}
Invoke-Phase 'Audit policy' {
    $script:Audit = Get-AuditPolicyState
    if ($script:Audit.Available) { Write-Step ('{0} subcategories read; GPO audit.csv: {1}' -f $script:Audit.Effective.Count, [bool]$script:Audit.Gpo) 'OK' }
}
Invoke-Phase 'Logging configuration' {
    $script:Cfg = Get-LoggingConfig
    $script:FileSources = Get-FileLogSources
    Write-Step ('cmdline: {0}, script blocks: {1}, Sysmon: {2}' -f $script:Cfg.CmdLine, $script:Cfg.ScriptBlock, $script:Cfg.Sysmon.Installed) 'OK'
}
Invoke-Phase 'SIEM forwarding' {
    $script:Splunk = Get-SplunkState
    $script:Other = Get-OtherTelemetry
    if ($script:Splunk.Installed) { Write-Step ('Splunk UF {0} ({1}), {2} event log input(s)' -f $script:Splunk.Version, $script:Splunk.ServiceState, $script:Splunk.Channels.Count) 'OK' }
    else { Write-Step 'No Splunk forwarder found' 'OK' }
}
Invoke-Phase 'Tampering evidence' {
    $script:TamperSummary = Get-TamperEvidence
    Write-Step ('{0} tampering-relevant event(s)' -f @($script:TamperEvents | Where-Object { $_.Kind -ne 'boot' }).Count) 'OK'
}
Invoke-Phase 'Privileged access and logons' {
    Get-PrivilegedAccess
    $adm = @($script:Priv.Groups | Where-Object { $_.Sid -eq 'S-1-5-32-544' })
    $n = 0; if ($adm.Count) { $n = $adm[0].EffectiveUsers }
    Write-Step ('local Administrators: {0} effective account(s); {1} account(s) with interactive logon evidence ({2} admin); {3} account / group change(s)' -f $n, $script:Priv.Users.Count, @($script:Priv.Users | Where-Object { $_.Admin }).Count, $script:Priv.Changes.Count) 'OK'
}
if ($DeepScan) {
    Invoke-Phase 'Deep scan' {
        $scans = New-Object System.Collections.ArrayList
        foreach ($n in @('Security', 'System', $SysmonLog, $PSOpLog)) {
            if (-not (Get-Log $n)) { continue }
            Write-Step ('  reading {0} ...' -f $n)
            $gm = 0; if ($n -eq 'Security' -or $n -eq $SysmonLog) { $gm = $GapMinutes }
            [void]$scans.Add((Invoke-LogDeepScan $n $DeepScanMaxEvents $gm))
        }
        $script:AntiPatterns = Get-AntiLoggingPatterns
        $cmds = New-Object System.Collections.ArrayList
        if ($script:AntiPatterns.Count -gt 0) { $cmds = Find-AntiLoggingCommands ([Math]::Min($DeepScanMaxEvents, 500000)) }
        else { Add-Workflow 'Anti-logging command search' 'Skipped' 'anti-logging-patterns.txt not found next to the script' }
        $script:Deep = @{ Scans = $scans.ToArray(); Commands = $cmds.ToArray(); Patterns = $script:AntiPatterns.Count }
        Add-Workflow 'Deep scan' 'Executed' ('{0} log(s) read completely' -f $scans.Count)
    }
} else { Add-Workflow 'Deep scan' 'Skipped' 'Use -DeepScan for record-ID gaps, silent periods, event volume and anti-logging commands' }
Invoke-Phase 'Evaluation' {
    $script:AuditRows = Get-AuditRows
    $script:UCResults = Get-UseCaseResults
    Build-Findings
    Add-AccessFindings
    $script:Score = Get-Score
    Write-Step ('Score {0}/100 (grade {1}), {2} finding(s)' -f $script:Score.Total, $script:Score.Grade, $script:Findings.Count) 'OK'
}
Invoke-Phase 'Writing report' {
    Export-Results
    Write-Step ('Report: ' + (Join-Path $script:OutDir 'report.html')) 'OK'
}

Write-Host ''
if ($script:Score) {
    $c = 'Red'; if ($script:Score.Total -ge 75) { $c = 'Green' } elseif ($script:Score.Total -ge 60) { $c = 'Yellow' }
    Write-Host ('  IR readiness: {0}/100  grade {1} ({2})' -f $script:Score.Total, $script:Score.Grade, $script:Score.Label) -ForegroundColor $c
    foreach ($f in ($script:Findings | Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' } | Sort-Object @{ Expression = { $_.Rank }; Descending = $true } | Select-Object -First 10)) {
        Write-Host ('  [{0}] {1}' -f $f.Severity, $f.Title) -ForegroundColor $(if ($f.Severity -eq 'Critical') { 'Red' } else { 'Yellow' })
    }
}
Write-Host ('  Report: {0}' -f (Join-Path $script:OutDir 'report.html')) -ForegroundColor Cyan
Write-Host ''
