# Linux Logging Gap Analysis

Author: **secamin** (SIEM Detection Content) - <https://github.com/secamin>  
Co-author and contributor: **HXM14** - <https://github.com/HXM14>  
Tool ID: `secamin/log-gap-analysis` (Linux)

`linux-log-gap-analysis.sh` runs **locally on a (potentially compromised) Linux server**. It is the Linux counterpart of
`Invoke-LogGapAnalysis.ps1` and answers five questions for the incident:

1. **Time frame:** how far back does each log go (all rotations), and how fast is it rotated away?
2. **Visibility:** which detection use cases (MITRE ATT&CK) can the current auditd and logging configuration support?
3. **Tampering:** was logging weakened, cleared or switched off?
4. **SIEM:** which log files actually reach Splunk (Universal Forwarder `inputs.conf`), or another forwarder?
5. **Access:** who has root / sudo rights, and which accounts logged on - when and from where?

The script is read-only and needs nothing installed: bash 4.0+, coreutils, grep, sed and awk (gawk **or** mawk).
It works on RHEL / CentOS / Rocky / Alma / Oracle Linux 6-9, Fedora, Ubuntu 14.04+, Debian 8+, SLES 12+ and Amazon Linux.
AIX, Solaris and HP-UX are not supported (different audit and log systems).

## Files

| File | Purpose |
|---|---|
| `linux-log-gap-analysis.sh` | the tool |
| `anti-logging-patterns-linux.txt` | regexes for the `-d` command search (history -c, auditctl -D, truncate /var/log, utmp cleaners ...). Kept separate so the list can be tuned. If it is missing, only that search is skipped. |

Copy both files together.

## Run

### Step by step

1. **Copy the files** to the server into one folder, for example with `scp` or WinSCP:

   ```bash
   scp linux-log-gap-analysis.sh anti-logging-patterns-linux.txt admin@server:/tmp/loggap/
   ```

   On a host you suspect is compromised, run it from a USB drive or an NFS / SMB mount instead, and write the result there too.
2. **Log on and become root.** Without root the auth / audit logs, `auditctl`, `/etc/shadow` and the deleted-file check cannot be read.

   ```bash
   ssh admin@server
   sudo -i
   cd /tmp/loggap
   ```
3. **Fix line endings if the files came from Windows** (Notepad / Outlook / OneDrive can add CRLF - the script then fails with `$'\r': command not found`):

   ```bash
   sed -i 's/\r$//' linux-log-gap-analysis.sh anti-logging-patterns-linux.txt
   ```
4. **Run it.** Quick check (about 1-2 minutes):

   ```bash
   bash linux-log-gap-analysis.sh -o /mnt/usb/IR
   ```

   Full incident run with the suspected start date and the deep scan (minutes, depending on log size):

   ```bash
   bash linux-log-gap-analysis.sh -o /mnt/usb/IR -s 2026-10-15 -d
   ```

   Run it with `bash`, not `sh` - on Debian / Ubuntu `sh` is dash and will fail.
5. **Copy the result to your workstation** and open `report.html` in any browser (works offline):

   ```bash
   # on your workstation
   scp -r admin@server:/mnt/usb/IR/LinuxLogGap_<HOST>_<date_time> .
   ```

   The CSV files in the same folder open in Excel and can be combined across servers.

### Troubleshooting

| Problem | Fix |
|---|---|
| `$'\r': command not found` or `syntax error near unexpected token` | The file has Windows line endings - run the `sed -i 's/\r$//'` command from step 3 |
| `This script needs bash 4.0 or later` / errors under `sh` | Start it with `bash linux-log-gap-analysis.sh`, not `sh` or `./` on systems where bash is old (RHEL 5) |
| `Permission denied` | Use `bash linux-log-gap-analysis.sh ...` (no execute bit needed) or `chmod +x` it; the output folder must be writable |
| Security-relevant values shown as *unknown* / auth log *Unreadable* | Not run as root - use `sudo -i` first |
| `utmpdump not available` finding | Install util-linux (sysvinit-tools on RHEL 6), or analyse wtmp offline. The rest of the report is unaffected |
| Run takes very long | Leave out `-d`, or lower `-m` (lines read per log in the deep scan) |

### Options

| Option | Meaning |
|---|---|
| `-o DIR` | where the result folder is created. Default: the **current directory**. On a compromised host prefer a USB drive or a share. |
| `-s START` | `YYYY-MM-DD` or `"YYYY-MM-DD HH:MM"` (local time). Each log is checked for whether it still reaches back to this time; drawn on the timeline; changes after it are flagged. |
| `-d` | deep scan: reads auth / syslog / audit logs completely (or the journal). It finds time gaps, backwards time jumps, audit serial number gaps (deleted records), zeroed wtmp records, and anti-logging commands. Also runs `journalctl --verify`. |
| `-g MIN` | deep scan: report silences longer than MIN minutes (default 60) |
| `-m LINES` | deep scan: maximum lines read per log (default 5,000,000) |
| `-p FILE` | other pattern file (default: `anti-logging-patterns-linux.txt` next to the script) |

## Output: `LinuxLogGap_<HOST>_<yyyyMMdd_HHmmss>/`

| File | Content |
|---|---|
| `report.html` | self-contained report: score and grade, findings, timeline, ATT&CK coverage matrix, SIEM, auditd rules, log inventory, configuration, tampering events, privileged access, deep scan |
| `results.json` | everything, machine readable |
| `findings.csv`, `usecases.csv`, `logs.csv`, `auditrules.csv`, `splunk_inputs.csv`, `tampering_events.csv` | same tables as the Windows tool |
| `privileged_accounts.csv`, `logons.csv`, `failed_logons.csv`, `account_changes.csv`, `ssh_keys.csv`, `sudo_usage.csv` | access tables; `anti_logging_commands.csv` with `-d` |
| `raw/` | auditctl -s / -l, persistent audit rules, auditd.conf, sshd -T, effective sudoers, passwd / group (no shadow hashes), journald / rsyslog config, Splunk btool output, process list |
| `collection.log`, `manifest_sha256.txt` | executed steps and SHA-256 of every output file |

## What is checked

* **Log inventory:** auth.log / secure, syslog / messages, audit.log, kern, cron, package logs, wtmp / btmp / lastlog, web access
  logs (web servers) and the systemd journal. For each: oldest and newest entry across all rotations (also .gz / .xz / .bz2), size,
  lines per hour, the logrotate rule or auditd `num_logs` x `max_log_file`, and the estimated capacity.
  Extra auth destinations are read from the rsyslog configuration.
* **auditd:** installed / running / kernel enabled flag, lost events, backlog limit, immutable mode, `audit=0` on the kernel command
  line, `auditd.conf` actions (`disk_full_action`, `write_logs` ...). The loaded rules (`auditctl -l`) and the rules on disk are compared
  with a 21-rule IR baseline (execve, identity files, sudoers, sshd_config, cron, systemd, kernel modules, time, audit config, login
  records, ld.so.preload, root SSH keys, PAM ...). The report gives an example rule for every missing item. Rules that are on disk but
  not loaded indicate `auditctl -D` at runtime.
* **Logging configuration:** syslog daemon, journald storage (volatile / persistent), sshd LogLevel / PermitRootLogin / PasswordAuthentication,
  shell history timestamps, history disabled in profile files or linked to /dev/null, process accounting, `/etc/ld.so.preload`, EDR and
  log shippers (Cortex XDR, CrowdStrike, Defender, SentinelOne, Carbon Black, Trend, Sysmon for Linux, Wazuh, Filebeat, Fluent Bit ...).
* **Tampering:** log files deleted while still open by a process (recoverable from `/proc/<pid>/fd`), immutable log files, missing / emptied
  auth log and wtmp. It also reads these events with time and user: audit rules removed / auditing disabled, auditd / rsyslog / journald
  stopped outside a shutdown, kernel audit backlog overflows, time changes and journal vacuum. With `-d` it adds audit serial gaps,
  silences, backwards time jumps, zeroed wtmp records and anti-logging commands from audit EXECVE records, shell histories and sudo logs.
* **SIEM:** Splunk UF home, version, running state, indexers, deployment server and `splunkd.log` output errors. For every log file it
  reports Forwarded / Filtered / Not collected and names the responsible `[monitor://...]` stanza, `whitelist` / `blacklist` or
  `disabled`. It also checks `journald://` inputs, rsyslog / syslog-ng forwarding targets and auditd `au-remote`.
* **Privileged access and logons:**
  * **Root and sudo rights:** UID 0 accounts, members of sudo / wheel / admin / root, sudoers entries (full root, NOPASSWD, groups and User_Alias expanded),
    and root-equivalent groups (docker / lxd / libvirt / disk).
  * **Accounts and keys:** accounts with a login shell, password state (empty / locked / set) and last change, and lastlog. For every SSH authorized_keys file it
    lists the key count, modification time, comments and forced commands.
  * **Logons:** one row per account from wtmp (all rotations) and auth log `Accepted ...` lines, with first / last seen, source IPs (public marked) and method.
  * **Failed logons:** counted per source from the auth log and btmp. A brute-force source that later logged on successfully is a Critical finding.
  * **sudo / su:** use and denied attempts per account.
  * **Account and group changes:** useradd / usermod / userdel / passwd from the auth log and auditd ADD_USER / USER_MGMT ...
  * Findings in this area use the category **Access** and do not change the logging score.

## Score (0-100, grade A-F)

| Area | Points |
|---|---|
| Integrity (no tampering findings) | 25 |
| auditd rules against the baseline (key rules weighted double) | 25 |
| Extended visibility (execve audit, EDR, sshd VERBOSE, history timestamps, persistent journal) | 15 |
| SIEM forwarding of the locally logged use cases | 20 |
| Local log coverage and health | 15 |

Grades: A >= 90, B >= 75, C >= 60, D >= 40, F < 40. Any critical tampering finding caps the score at 59 (grade D).

## Limitations

* A rootkit (kernel module or ld.so.preload) can hide files, processes and log lines from the script. A clean result is not proof that
  the host is clean.
* Running the script creates events itself (sudo in the auth log, EXECVE records) at the collection time.
* Syslog lines without a year are assigned to the current year (previous year if that would be in the future).
* Audit serial gaps can also be caused by `never` rules or by load. Check the lost counter before concluding that records were deleted.
* Splunk filtering done on indexers or heavy forwarders (props / transforms) is not visible from the host. Syslog and agent forwarding
  is detected but cannot be verified per log.
