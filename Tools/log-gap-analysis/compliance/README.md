# Compliance control mapping

Every finding the tool produces already carries a MITRE ATT&CK technique. This folder adds a second
reading of the same finding: which SOC 2 and ISO 27001 controls the gap is evidence for or against.

The mapping is data, not code. Adding a framework is editing a CSV, not touching the scripts.

## Use it

Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-LogGapAnalysis.ps1 -OutputPath E:\IR -ComplianceMap
```

Linux:

```bash
sudo bash linux-log-gap-analysis.sh -o /mnt/usb/IR -c
```

Both add a `Compliance` field to every finding in `findings.csv` and `results.json`, and a `Controls`
column to the findings table in `report.html`. The value is a semicolon separated list of
`framework:control` pairs, for example `soc2:CC7.2;soc2:CC7.3;iso27001:A.8.15`. Without the flag,
output is unchanged, so nothing that parses the current files breaks.

`-ComplianceMapPath <file>` (Windows) and `COMPLIANCE_MAP=<file>` (Linux, environment) point at a
different map. The default is `compliance/control-map.csv` next to the two tool folders.

## How a finding is resolved

1. The finding's technique is looked up exactly. `T1562.002` maps to `T1562.002`.
2. If the technique is not listed, the parent is tried. `T1562.002` falls back to `T1562`.
3. If the finding has no technique, or none of its techniques are listed, the category default is
   used: `category:tampering`, `category:visibility`, and so on.

Step 3 exists because some findings are about the state of the collection rather than an attacker
technique. "The script was not run as administrator" is a caveat, not an ATT&CK technique, and it
should still tell the auditor which control is affected.

## What is mapped

| Framework | Controls used |
|---|---|
| SOC 2 (2017, 2022 points of focus) | CC6.1 logical access, CC6.2 registration and authorisation, CC7.1 configuration and vulnerability detection, CC7.2 monitoring, CC7.3 evaluation of security events |
| ISO/IEC 27001:2022 | A.5.15 access control, A.8.15 logging, A.8.16 monitoring activities |

The split is deliberately narrow. CC7.2 and CC7.3 carry anything about whether logging and monitoring
would notice an attack. CC6.1 and CC6.2 carry access control findings, because a logon record is an
access-control artifact before it is a detection artifact. A.8.15 covers whether the record exists,
A.8.16 whether anyone is watching it.

## What this is not

It is not an audit opinion, a control test, or a score. A finding marked CC7.2 means the gap sits in
the evidence an auditor would ask for when testing monitoring. It does not mean the control failed.
Controls are tested against a whole environment, and this tool sees one host.

Nothing in the CSV is generated from the tool's own output. It was written from the ATT&CK technique
that each finding already cites, so the tool cannot agree with itself.

## Changing it

Add a row per key, framework and control:

```
T1562.002,soc2,CC7.2
T1562.002,iso27001,A.8.15
```

Then run the check:

```bash
python compliance/test_control_map.py
```

It fails if a row is malformed, if a key or a control is duplicated, if a technique the scripts emit is
missing from the map, or if a finding category has no default. That last one is the useful test: it
means the map cannot silently fall behind the scripts.
