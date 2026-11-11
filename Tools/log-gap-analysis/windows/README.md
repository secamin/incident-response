# Windows Logging Gap Analysis

Author: **secamin** (SIEM Detection Content) - <https://github.com/secamin>  
Co-author and contributor: **HXM14** - <https://github.com/HXM14>  
Tool ID: `secamin/log-gap-analysis` (Windows)

`Invoke-LogGapAnalysis.ps1` runs **locally on a (potentially compromised) Windows server**. It answers five questions
for the incident:

1. **Time frame:** how far back does each event log go, and how fast is it overwritten?
2. **Visibility:** which detection use cases (MITRE ATT&CK) can the current audit and logging policy support?
3. **Tampering:** was logging weakened, cleared or switched off?
4. **SIEM:** which channels and event IDs actually reach Splunk (Universal Forwarder `inputs.conf` filters)?
5. **Access:** who holds local admin / RDP rights, and which accounts logged on interactively - when and from where?

The script is read-only and needs nothing installed: it uses only what ships with Windows. It works with Windows PowerShell 2.0 and later
on Windows Server 2008 and later. It detects the Windows version first and runs the checks that apply to it; features the OS
cannot provide are reported as *not supported*, not as gaps.

## Files

| File | Purpose |
|---|---|
| `Invoke-LogGapAnalysis.ps1` | the tool |
| `anti-logging-patterns.txt` | regexes for the `-DeepScan` command search (wevtutil cl, auditpol /set, Phant0m ...). These attacker strings are kept outside the script because AMSI / Defender blocks a .ps1 that contains them. If the file is missing, only that search is skipped. |

Copy both files together.

## Run

### Step by step

1. **Copy the files** to the server, all into the same folder, e.g. `C:\IR\LogGap`. On a host you suspect is compromised,
   run it from a USB drive or a network share instead (e.g. `E:\LogGap`).
2. **Open PowerShell as Administrator:** Start > type `powershell` > right-click **Windows PowerShell** > **Run as administrator**.
   Without admin rights the Security log, the audit policy and the logon history cannot be read.
3. **Go to the folder and unblock the downloaded files:**

   ```powershell
   cd C:\IR\LogGap
   Get-ChildItem | Unblock-File
   ```

   On Server 2008 (PowerShell 2.0) `Unblock-File` does not exist. Instead, right-click each file > **Properties** > tick **Unblock** > OK.
4. **Run it.** Quick check (about 1-3 minutes):

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-LogGapAnalysis.ps1 -OutputPath E:\IR
   ```

   Full incident run with the suspected start date and the deep scan (5-30 minutes on large logs):

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-LogGapAnalysis.ps1 -OutputPath E:\IR -SuspectedStart 2026-10-15 -DeepScan
   ```

   On a domain member server that can reach a DC, add `-ExpandDomainGroups` to see the users inside nested domain groups
   (e.g. Domain Admins in local Administrators).
5. **Open the result:** `<OutputPath>\LogGapAnalysis_<SERVER>_<date_time>\report.html` opens in any browser and works offline.
   The CSV files in the same folder open in Excel.

### Troubleshooting

| Problem | Fix |
|---|---|
| "Running scripts is disabled on this system" | Start it with `powershell.exe -ExecutionPolicy Bypass -File ...` as shown above, not as `.\Invoke-LogGapAnalysis.ps1` |
| Defender / AMSI blocks the script | Make sure `anti-logging-patterns.txt` is a separate file and not pasted into the script. If it is still blocked, add a temporary exclusion for the folder according to your SOC process |
| Security log / audit policy shown as *unknown* | The prompt was not elevated - re-run as Administrator |
| Red `ERROR` lines in the console | That check failed and the script continues. Details are in `collection.log` in the result folder |
| Run takes very long | Leave out `-DeepScan`, or lower `-DeepScanMaxEvents` / `-LogonMaxEvents` |

### Parameters

| Parameter | Meaning |
|---|---|
| `-OutputPath` | where the result folder is created. Default: the **current directory**. On a compromised host prefer a USB drive or a share. |
| `-SuspectedStart` | `yyyy-MM-dd` or `"yyyy-MM-dd HH:mm"`. Each log is checked for whether it still reaches back to this time; the time is drawn on the timeline. |
| `-DeepScan` | reads Security, System, Sysmon and PowerShell completely. It finds missing event record IDs (deleted events), periods without events, events per hour, and anti-logging commands. It can take minutes. |
| `-DeepScanMaxEvents` | cap per log for `-DeepScan` (default 2,000,000) |
| `-GapMinutes` | `-DeepScan`: report Security / Sysmon silences longer than this (default 60) |
| `-SkipSplunkBtool` | parse Splunk `.conf` files directly instead of running `splunk.exe btool` |
| `-ExpandDomainGroups` | also expand domain groups inside local Administrators / RDP Users (needs a reachable DC; always on for a DC) |
| `-LogonMaxEvents` | newest interactive logon events (4624) read from the Security log (default 50,000) |
| `-ComplianceMap` | add the SOC 2 / ISO 27001 controls each finding is evidence for, as an extra `Compliance` field and a `Controls` column. Output is unchanged without it. See [compliance](../compliance/README.md) |
| `-ComplianceMapPath` | use a different control map than `compliance/control-map.csv` |

Without administrator rights the script still runs, but the Security log and the audit policy are reported as *unknown*.
A 32-bit PowerShell session is re-launched as 64-bit automatically.

## Output: `LogGapAnalysis_<HOST>_<yyyyMMdd_HHmmss>\`

| File | Content |
|---|---|
| `report.html` | self-contained report that works offline: score and grade, findings, timeline, ATT&CK coverage matrix, Splunk analysis, audit policy, log inventory, configuration, tampering events, deep scan |
| `results.json` | everything, machine readable |
| `findings.csv`, `usecases.csv`, `logs.csv`, `auditpolicy.csv`, `splunk_inputs.csv`, `tampering_events.csv` | tables for Excel / aggregation across servers |
| `privileged_groups.csv`, `interactive_logons.csv`, `account_changes.csv` | local admin / RDP group members, per-account logon history, account and group changes |
| `raw\` | auditpol backup, GPO `audit.csv`, Splunk btool / .conf copies, every registry value read |
| `collection.log`, `manifest_sha256.txt` | executed steps and SHA-256 of every output file |

## What is checked

* **Log inventory:** for every channel: oldest and newest event, history, events per hour, size against maximum, mode
  (overwrite / archive / retain), estimated capacity, and whether it is full or overwriting. Also archived `Archive-*.evtx` files and
  file-based logs (firewall, IIS, DHCP, DNS debug log, PowerShell transcripts).
* **Audit policy:** the effective `auditpol` settings compared with a built-in baseline for the detected role (DC, file server,
  CA, DNS ...). The baseline is assembled from Microsoft's audit policy recommendations, the CIS benchmarks and ASD guidance.
  The script also compares the effective policy with the policy delivered by GPO (`%SystemRoot%\security\audit\audit.csv`): if
  the effective policy is weaker, the policy was probably changed locally.
* **Logging configuration:** 4688 command line, PowerShell script block / module logging / transcription, the PowerShell 2.0
  engine, Sysmon (including renamed drivers and the config hash), firewall logging, NTLM auditing, the AD CS audit filter, DNS / DHCP / IIS logging.
* **Tampering:** Event Log service stopped or disabled, MiniNt key, disabled ETW autologgers (Security / Defender), redirected
  log files, and these events: log clearing (1102 / 104), audit policy weakened (4719), lost events (1101 / 1104 / 4612), service
  stops outside a shutdown, time changes, Sysmon stopped or reconfigured, Defender disabled or detections, PowerShell 2.0
  downgrades, and a Security log that has gone silent.
* **Privileged access and logons:**
  * **Groups:** members of Administrators, Remote Desktop Users, Remote Management Users and Backup Operators (plus Server / Account
    Operators on a DC). Nested groups are expanded, and the report shows the nesting path.
  * **Local accounts:** enabled / disabled, password age, password never expires, last logon, the built-in RID 500 account, and LAPS (legacy or Windows LAPS).
  * **Logon history:** one row per account with interactive (2), RDP (10), cached (11) and unlock (7) logons, first / last seen and source IPs. Each
    row also shows whether the account is an admin, through group membership or a privileged token (4672 / ElevatedToken).
  * **Other logon evidence:** the RDP channels (LocalSessionManager 21/25, RemoteConnectionManager 1149) and user profiles (profile created =
    first interactive logon ever, last use) cover the time after the Security log has rolled over. The report also lists the sessions logged on now.
  * **Changes and attacks:** accounts created / enabled / renamed and members added to privileged groups (4720/4722/4781/4732/4728/4756),
    flagged when they happened after `-SuspectedStart`. It also reports NewCredentials logons (type 9, `seclogo`: runas /netonly or pass-the-hash),
    failed logons per source, logons from public IPs, and profiles of deleted accounts.
  * Findings in this area use the category **Access**. They do not change the logging score.
* **Splunk:** forwarder service, version, deployment server, indexers and `splunkd.log` health. For every event ID used by a
  use case it reports Forwarded / Conditional / Filtered / Not collected and names the responsible `whitelist` / `blacklist`
  rule and file.

## Score (0-100, grade A-F)

| Area | Points |
|---|---|
| Integrity (no tampering findings) | 25 |
| Audit policy against the role baseline | 25 |
| Extended visibility (command line, script blocks, Sysmon ...) | 15 |
| SIEM forwarding of the locally logged use cases | 20 |
| Local log coverage and health | 15 |

Grades: A >= 90, B >= 75, C >= 60, D >= 40, F < 40. Any critical tampering finding caps the score at 59 (grade D).

## Limitations

* A rootkit on the host can hide data from the script. A clean result is not proof that the host is clean.
* Running the script creates events itself (4688, 4104, 4672) at the collection time.
* Object-access use cases also need SACLs, which the script does not verify.
* Splunk filtering done on indexers or heavy forwarders (props / transforms) is not visible from the endpoint.
