# Log Gap Analysis

Read-only logging gap analysis for incident response. Run it locally on a (potentially compromised) host to find out:

1. **Time frame** - how far back each log goes and how fast it is overwritten or rotated
2. **Visibility** - which MITRE ATT&CK detection use cases the current audit / logging configuration supports
3. **Tampering** - whether logging was weakened, cleared or switched off
4. **SIEM** - which logs and event IDs actually reach Splunk (Universal Forwarder `inputs.conf`)
5. **Access** - who holds admin / root rights and which accounts logged on, when and from where

Each run produces a self-contained `report.html` (score 0-100, grade A-F, findings, timeline, coverage matrix), `results.json`, CSV tables and a SHA-256 manifest.

| Folder | Script | Requirements |
|---|---|---|
| [windows/](windows/) | `Invoke-LogGapAnalysis.ps1` + `anti-logging-patterns.txt` | Windows Server 2008+ / Windows 10+, PowerShell 2.0+, run as Administrator |
| [linux/](linux/) | `linux-log-gap-analysis.sh` + `anti-logging-patterns-linux.txt` | RHEL / CentOS / Rocky / Alma 6-9, Ubuntu, Debian, SLES, Amazon Linux; bash 4+, run as root |

## Quick start

```powershell
# Windows - elevated PowerShell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-LogGapAnalysis.ps1 -OutputPath E:\IR -SuspectedStart 2026-10-15 -DeepScan
```

```bash
# Linux - as root
bash linux-log-gap-analysis.sh -o /mnt/usb/IR -s 2026-10-15 -d
```

See the README in each folder for step-by-step instructions, troubleshooting and what is checked.

Both tools are read-only and need nothing installed. A clean result is not proof that a host is clean: a rootkit can hide data from the script.

## Sample report

Screenshots from real runs on a Windows 11 workstation and an Ubuntu (WSL) host. Host names, account names, SIDs and IP
addresses are replaced with demo values. Both reports are single offline HTML files with filterable tables.

### Windows

**Summary** - readiness score and grade, score per area, key numbers and a verdict:

![Windows report - summary](docs/screenshots/windows-overview.png)

**Findings** - sorted by severity, each with ATT&CK technique, evidence and the exact fix (GPO path or auditpol command):

![Windows report - findings](docs/screenshots/windows-findings.png)

**Log coverage timeline** - how far back every log reaches, with reboots and tampering events:

![Windows report - timeline](docs/screenshots/windows-timeline.png)

**Detection coverage (MITRE ATT&CK)** - which use cases the logging supports, the evidence sources and whether they reach Splunk:

![Windows report - detection coverage](docs/screenshots/windows-coverage.png)

**Privileged access and interactive logons** - local admins (nested groups expanded), local accounts and logon history:

![Windows report - privileged access](docs/screenshots/windows-access.png)

### Linux

**Summary:**

![Linux report - summary](docs/screenshots/linux-overview.png)

**Findings:**

![Linux report - findings](docs/screenshots/linux-findings.png)

**auditd rules against the IR baseline** - status of each rule, with a ready-to-use rule for every gap:

![Linux report - auditd rules](docs/screenshots/linux-audit.png)

## Authors

- **Author:** [secamin](https://github.com/secamin) - SIEM Detection Content
- **Co-author and contributor:** [HXM14](https://github.com/HXM14)
