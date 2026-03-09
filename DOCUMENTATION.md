# GOD EYE - Data Pipeline Documentation

hackxolotl's Lab

---

## Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Dataset Origin](#3-dataset-origin)
4. [Source File Types](#4-source-file-types)
5. [Ingestion Pipeline](#5-ingestion-pipeline)
6. [Phase Classification Logic](#6-phase-classification-logic)
7. [Data Validity Per Source Type](#7-data-validity-per-source-type)
8. [Known Limitations](#8-known-limitations)
9. [Validation Methods](#9-validation-methods)
10. [Running the Platform](#10-running-the-platform)
11. [Database Schema Reference](#11-database-schema-reference)

---

## 1. Project Overview

GOD EYE is a cybersecurity scenario analytics platform designed to ingest, normalize, and visualize raw telemetry from controlled cybersecurity exercises (Red Team / Blue Team capture-the-flag scenarios). It provides:

- A unified timeline of all recorded actions across multiple data sources
- Attack phase progression per participant mapped to MITRE ATT&CK tactics
- Per-user behavior analysis and command browsing
- Host, user, and tool relationship graphs
- Alert and anomaly review with severity ratings
- Media file linkage (video recordings, PCAP captures, terminal sessions)

The platform ingests data once via `ingest_v2.py` into a SQLite database (`godeye_v2.db`), then serves it via a FastAPI backend (`api/main.py`) to a single-page HTML5 dashboard (`frontend/index.html`).

---

## 2. Architecture

```
/tmp/obsidian_full/P003/          Raw source data (read-only)
         |
         v
   ingest_v2.py                   One-time ingestion script
         |
         v
data/godeye_v2.db                 SQLite database (423,444 events)
         |
         v
   api/main.py                    FastAPI HTTP server (port 8000)
         |
         v
frontend/index.html               Browser dashboard (single file SPA)
```

Data flows in one direction: raw files -> normalized events in DB -> API endpoints -> dashboard visualizations. There is no write-back from the dashboard to the database. Re-ingestion requires deleting the DB and re-running `ingest_v2.py`.

---

## 3. Dataset Origin

The dataset originates from a controlled cybersecurity exercise environment hosted at participant path `/tmp/obsidian_full/P003`. It contains data from a single exercise cohort (P003) with multiple participants and scenario runs.

### Directory Structure

```
/tmp/obsidian_full/P003/
├── user0003/
│   └── training/1/              Training scenario (1 run)
│       ├── <host-dirs>/         One directory per monitored host
│       └── atkr-kali/           Attacker machine
├── user2003/
│   └── ckc1/1/                  Cyber Kill Chain scenario 1
│       ├── <host-dirs>/
│       └── atkr-kali/
├── user4002/
│   └── ckc2/1/                  Cyber Kill Chain scenario 2
│       ├── <host-dirs>/
│       └── atkr-kali/
└── user4002.orig/
    └── ckc2/1/                  CKC2 original (larger unprocessed capture)
        ├── <host-dirs>/
        └── atkr-kali/
```

### Participants

| participant_id | scenario   | events   | notes                             |
|----------------|------------|----------|-----------------------------------|
| user0003       | training   | 7,416    | Has UAT keystroke files           |
| user2003       | ckc1       | 50,408   | No UAT files                      |
| user4002       | ckc2       | 71,346   | No UAT files                      |
| user4002.orig  | ckc2       | 293,812  | Larger original capture of ckc2   |

The `participant_id` is extracted from the directory name via regex `user\d{4}(\.orig)?`.

### Scenario Types

- **training**: Introductory scenario. Contains UAT keylogger data because the training setup included keylogger agents on student workstations.
- **ckc1 / ckc2**: Cyber Kill Chain scenarios. No UAT data; richer network and behavior tracking logs.

---

## 4. Source File Types

The ingestion engine recognizes the following file types, each parsed by a dedicated function:

| File name / pattern     | Parser function         | What it captures                                                   | Source |
|-------------------------|-------------------------|--------------------------------------------------------------------|--------|
| `auth.log`              | `parse_auth_log`        | SSH logins, sudo commands, PAM sessions, user creation, cron jobs  | Linux syslog (auth facility) |
| `syslog`                | `parse_syslog`          | System-level events: kernel, systemd, Docker, NetworkManager, UFW  | Linux syslog |
| `bt.jsonl`              | `parse_bt_jsonl`        | Behavior tracking JSON lines: rootkit activity, honeypot triggers, Docker exec, SSH intercepts | Custom exercise sensor |
| `bt.log`                | `parse_syslog`          | Text companion to bt.jsonl, parsed as syslog-style                 | Custom exercise sensor |
| `sensor.log`            | `parse_sensor_log`      | Raw packet observations, attack status markers, SSH intercepts, HTTP traffic indicators | Custom exercise sensor |
| `eve.json`              | `parse_suricata_eve`    | Network alerts, flows, HTTP, SSH, DNS, file transfer events        | Suricata IDS |
| `fast.log`              | `parse_suricata_fast`   | Suricata text-format alerts with SID, priority, src/dst            | Suricata IDS |
| `zeek/conn.log`         | `parse_zeek_conn`       | Full network connection records (5-tuple + duration + state)       | Zeek NSM |
| `zeek/http.log`         | `parse_zeek_http`       | HTTP requests: method, URI, user-agent, status code               | Zeek NSM |
| `zeek/ssh.log`          | `parse_zeek_ssh`        | SSH sessions with auth success/failure                             | Zeek NSM |
| `zeek/dns.log`          | `parse_zeek_dns`        | DNS queries with query name and record type                        | Zeek NSM |
| `zeek/notice.log`       | `parse_zeek_notice`     | Zeek-generated notices (port scans, policy violations) mapped to `recon` | Zeek NSM |
| `zeek/files.log`        | `parse_zeek_files`      | Files transferred over network with MD5/SHA1/SHA256 hashes         | Zeek NSM |
| `zeek/weird.log`        | `parse_zeek_weird`      | TCP/protocol anomalies detected by Zeek                            | Zeek NSM |
| `UAT-*.tsv`             | `parse_uat`             | Keystroke-level input reconstructed into typed commands            | UAT keylogger agent |
| `*.cast`                | `parse_cast`            | Commands extracted from asciinema terminal recordings              | asciinema |
| `hacktools.log`         | `parse_hacktools`       | Apache-style HTTP log for tool download server                     | Apache/Nginx access log |
| `apt.log`               | `parse_apt_log`         | Apache access log of attacker-controlled APT mirror; records which victim hosts fetched the GPG key, repo indexes, and downloaded `.deb` packages (nmap, python3-pip, etc.) — mapped to `initial_access` (key/index fetches) and `execution` (package downloads) | Apache/Flask access log |
| `*.pcap`                | (registered as media)   | Network packet capture — not parsed, registered as a media event   | tcpdump/Wireshark |
| `*.ogv`                 | (registered as media)   | Video screen recording — not parsed, registered as a media event   | recordmydesktop |

Binary files (`.pcap`, `.ogv`) are not parsed for events. They are registered as single `media` source-type events so the dashboard can link to them.

---

## 5. Ingestion Pipeline

The ingestion is performed by `ingest_v2.py`, run once as a standalone script. The pipeline has the following stages:

### Stage 1 — File Discovery

```python
all_files = list(data_root.rglob('*'))
```

All files under `/tmp/obsidian_full/P003` are enumerated recursively. The list is sorted before processing to ensure deterministic ordering.

### Stage 2 — Path Metadata Extraction (`parse_path_meta`)

For every file, three metadata fields are extracted from the file path:

- **participant_id**: matched by regex `user\d{4}(\.orig)?` against path components
- **scenario_name**: matched against the set `{training, ckc1, ckc2, ckc3}`
- **source_host**: the immediate parent directory of the file (e.g. `atkr-kali`, `sec-admin-workstation-1`)

### Stage 3 — Parser Dispatch

Files are routed to parsers by filename:

```
auth.log       -> parse_auth_log
bt.jsonl       -> parse_bt_jsonl
bt.log         -> parse_syslog
sensor.log     -> parse_sensor_log
syslog         -> parse_syslog
eve.json       -> parse_suricata_eve
fast.log       -> parse_suricata_fast
zeek/conn.log  -> parse_zeek_conn
zeek/http.log  -> parse_zeek_http
zeek/ssh.log   -> parse_zeek_ssh
zeek/dns.log   -> parse_zeek_dns
zeek/notice.log -> parse_zeek_notice
zeek/files.log -> parse_zeek_files
zeek/weird.log -> parse_zeek_weird
*.cast         -> parse_cast
UAT-*.tsv      -> parse_uat
*.pcap / *.ogv -> registered as single media event
```

Unrecognized files are silently skipped.

### Stage 4 — Event Construction (`make_event`)

Every parser yields Python dicts. Each dict is passed through `make_event`, which performs three normalization steps before the event is inserted:

1. **User normalization** (`clean_user`): strips PAM noise (`pam_unix(sudo:session):`, etc.), extracts the actual username using regex patterns (`for user X`, `user=X`, `USER=X`, etc.), and validates against a blacklist of non-user strings.

2. **Command extraction** (`extract_command`): if no explicit command was parsed, tries 7 regex patterns against the `raw_data` field to extract a command string (`COMMAND=`, `CMD=`, `"cmd":`, `Executing:`, etc.).

3. **Phase classification** (`classify_phase`): assigns MITRE ATT&CK phase, tactic, and technique (see Section 6).

### Stage 5 — Buffered Database Insertion

Events are inserted into SQLite in batches of 2,000 using `executemany`. The database uses WAL journal mode and NORMAL synchronous setting for write performance.

```
Events per batch: 2,000
Journal mode: WAL
Synchronous: NORMAL
```

### Stage 6 — Summary Statistics

After ingestion completes, the script queries the database and prints a summary: total events, events with commands, events with typed_text, breakdown by participant, attack phase, and top users.

---

## 6. Phase Classification Logic

Attack phase is assigned by `classify_phase(command, action_name, tool, raw_data='')`. The function operates in four ordered tiers. The first matching tier wins; if nothing matches, `phase = 'unknown'`.

### Tier 1 — Action-Name Fast Path

Before any regex work, the function checks whether `action_name` maps directly to a phase. These 17 rules cover event types whose action_name alone is sufficient to determine the phase, regardless of command content.

| action_name         | Phase                | MITRE Tactic | MITRE Technique |
|---------------------|----------------------|--------------|-----------------|
| `sudo_execution`    | privilege_escalation | TA0004       | T1548           |
| `sudo_session`      | privilege_escalation | TA0004       | T1548           |
| `user_created`      | persistence          | TA0003       | T1136           |
| `password_changed`  | credential_access    | TA0006       | T1098           |
| `python_execution`  | execution            | TA0002       | T1059           |
| `tool_accessed`     | execution            | TA0002       | T1204           |
| `terminal_command`  | reconnaissance       | TA0043       | T1595           |
| `ui_activity`       | discovery            | TA0007       | T1046           |
| `file_detected`     | collection           | TA0009       | T1005           |
| `ids_notice`        | discovery            | TA0007       | T1046           |
| `capture_loss`      | defense_evasion      | TA0005       | T1562           |
| `video_recording`   | collection           | TA0009       | T1113           |
| `suricata_anomaly`  | defense_evasion      | TA0005       | T1562           |
| `attack_status`     | command_and_control  | TA0011       | T1071           |
| `triggered_query`   | command_and_control  | TA0011       | T1071           |
| `ssh_intercept`     | command_and_control  | TA0011       | T1071           |
| `cron_job`          | persistence          | TA0003       | T1053           |

### Tier 2 — Action-Name + raw_data Sub-Classification

For action_name values that are too generic to classify alone, the raw log line (`raw_data`) is inspected.

**`session` (auth/session events)**

| Condition in raw_data | Phase                | Tactic | Technique |
|-----------------------|----------------------|--------|-----------|
| contains `sshd`       | lateral_movement     | TA0008 | T1021     |
| contains `cron`       | persistence          | TA0003 | T1053     |
| contains `sudo`       | privilege_escalation | TA0004 | T1548     |
| none of the above     | falls through to Tier 3 | — | —      |

**`ids_alert` (Suricata alert events)**

| Condition in raw_data | Phase            | Tactic | Technique |
|-----------------------|------------------|--------|-----------|
| contains `ssh`        | lateral_movement | TA0008 | T1021     |
| otherwise             | discovery        | TA0007 | T1046     |

**`http_traffic` (Suricata and sensor HTTP events)**

| Condition in raw_data                         | Phase          | Tactic | Technique |
|-----------------------------------------------|----------------|--------|-----------|
| contains `tomcatwar`, `cmd=`, or `webshell`   | execution      | TA0002 | T1190     |
| otherwise                                     | initial_access | TA0001 | T1190     |

**`sensor_packet` (custom exercise sensor packet records)**

Rules evaluated in order; first match wins:

| Condition                                              | Phase                | Tactic | Technique |
|--------------------------------------------------------|----------------------|--------|-----------|
| raw_data contains known attacker IP (122.10.11.101, 122.10.11.102, 114.0.194.2, 114.231.10.3) | command_and_control | TA0011 | T1071 |
| raw_data contains `sec-workstation`                   | discovery            | TA0007 | T1046     |
| raw_data contains `payload` + `username` or `password`| credential_access    | TA0006 | T1110     |
| raw_data contains `rtriggerd_query` or `attack_status`| command_and_control  | TA0011 | T1071     |
| none of the above                                     | falls through to Tier 3 | — | —      |

**`kernel_event` (syslog kernel events)**

| Condition in raw_data   | Phase       | Tactic | Technique |
|-------------------------|-------------|--------|-----------|
| contains `rootkit`      | persistence | TA0003 | T1547     |
| contains `promiscuous`  | collection  | TA0009 | T1040     |
| none of the above       | falls through to Tier 3 | — | — |

**`syslog_event` (general syslog events)**

| Condition in raw_data   | Phase               | Tactic | Technique |
|-------------------------|---------------------|--------|-----------|
| contains `runevents`    | command_and_control | TA0011 | T1071     |
| otherwise               | falls through to Tier 3 | — | —     |

### Tier 3 — PHASE_RULES Regex Table

If Tiers 1 and 2 do not match, the function concatenates `command`, `action_name`, and `tool` into a single lowercase string and tests it against 23 ordered regex rules. First match wins.

| # | Pattern (regex, case-insensitive)                                              | Phase                | MITRE Tactic | MITRE Technique |
|---|--------------------------------------------------------------------------------|----------------------|--------------|-----------------|
| 1 | `nmap\|masscan\|ping\|arp-scan\|netdiscover\|fping\|unicornscan`               | recon                | TA0043       | T1046           |
| 2 | `whois\|host\|dig\|nslookup\|theHarvester\|amass\|subfinder\|dnsrecon`        | recon                | TA0043       | T1018           |
| 3 | `nikto\|dirbuster\|gobuster\|dirb\|ffuf\|wfuzz\|feroxbuster`                  | recon                | TA0043       | T1595           |
| 4 | `sqlmap\|sqli\|sql.*injection`                                                 | initial_access       | TA0001       | T1190           |
| 5 | `hydra\|medusa\|john\|hashcat\|cupp\|bruteforce\|brute.?force\|password.*spray` | initial_access     | TA0001       | T1110           |
| 6 | `exploit\|msf\|msfconsole\|msfvenom\|metasploit\|CVE-`                        | initial_access       | TA0001       | T1203           |
| 7 | `ssh\s\|sshpass\|ssh -i\|ssh -o`                                              | lateral_movement     | TA0008       | T1021.004       |
| 8 | `wget\|curl.*download\|scp \|sftp \|rsync`                                    | lateral_movement     | TA0008       | T1570           |
| 9 | `nc \|netcat\|ncat\|socat\|reverse.?shell\|bind.?shell`                       | command_and_control  | TA0011       | T1059           |
| 10 | `whoami\|id\b\|uname\|hostname\|ifconfig\|ip addr\|ip route\|cat /etc/passwd` | discovery           | TA0007       | T1033           |
| 11 | `ps aux\|ps -ef\|top\b\|pstree\|lsof\|netstat\|ss -`                         | discovery            | TA0007       | T1057           |
| 12 | `ls -la\|find /\|locate\b\|which\b\|cat /etc\|cat /proc`                     | discovery            | TA0007       | T1083           |
| 13 | `sudo\s\|su\s\|su -\|sudo -i\|sudo su\|pkexec`                               | privilege_escalation | TA0004       | T1548.003       |
| 14 | `chmod\s\|chown\s\|setuid\|SUID\|capabilities`                               | privilege_escalation | TA0004       | T1548           |
| 15 | `crontab\|cron\b\|/etc/cron\|systemctl enable\|at\s\d`                        | persistence          | TA0003       | T1053           |
| 16 | `rootkit\|insmod\|modprobe\|/proc/modules\|lsmod`                             | persistence          | TA0003       | T1547           |
| 17 | `useradd\|adduser\|usermod\|passwd\s\|/etc/shadow`                            | persistence          | TA0003       | T1136           |
| 18 | `tar czf\|zip\s\|gzip\s\|encrypt\|openssl.*-e\|gpg -c`                       | exfiltration         | TA0010       | T1560           |
| 19 | `curl.*PUT\|curl.*POST\|wget.*post\|nc.*\d{1,3}\.\d{1,3}\|ftp\s`             | exfiltration         | TA0010       | T1048           |
| 20 | `rm -rf\|shred\|wipe\|dd.*if=/dev/zero\|history -c\|unset HISTFILE`          | defense_evasion      | TA0005       | T1070           |
| 21 | `iptables\|ufw\s\|firewall\|setenforce\s0\|apparmor`                         | defense_evasion      | TA0005       | T1562           |
| 22 | `docker\s\|kubectl\s\|podman\s`                                               | execution            | TA0002       | T1610           |
| 23 | `python\s\|python3\s\|perl\s\|ruby\s\|php\s\|bash\s\|sh\s`                  | execution            | TA0002       | T1059           |

### Tier 4 — Keyword Fallback

If no regex pattern matches, the concatenated text is checked for plain keywords:

| Keyword in text      | Assigned phase       | Tactic  | Technique |
|----------------------|----------------------|---------|-----------|
| `rootkit`            | persistence          | TA0003  | T1547     |
| `honeypot`           | initial_access       | TA0001  | T1190     |
| `login` or `auth`    | initial_access       | TA0001  | T1078     |
| `network` or `flow`  | recon                | TA0043  | T1046     |
| `docker`             | execution            | TA0002  | T1610     |

### Final Fallback

If no tier matches: `phase = 'unknown'`, tactic and technique are empty strings.

### Remaining `unknown` Events (22.3% of total)

After applying all classification rules, 94,613 of 423,444 events remain `unknown`. These fall into six buckets that cannot be meaningfully classified as attack phases because they are genuine infrastructure noise with no attack signal:

| source_type | action_name      | count  | Reason                                                       |
|-------------|------------------|--------|--------------------------------------------------------------|
| syslog      | syslog_event     | 73,914 | rtkit-daemon, dbus, pulseaudio, NetworkManager — OS noise   |
| syslog      | systemd_event    | 18,220 | systemd service lifecycle on atkr-kali — infrastructure     |
| suricata    | ids_stats        | 1,921  | Suricata internal telemetry counters — not attack events     |
| syslog      | kernel_event     | 433    | Docker/network kernel events on ccr15y — infrastructure      |
| sensor      | sensor_packet    | 121    | Empty PAYLOAD `{}` records — no content to classify         |
| auth        | session          | 4      | Edge cases not matching sshd/cron/sudo patterns              |

Assigning arbitrary phases to these events would reduce analytical accuracy. The `unknown` label is correct for this residual set.

---

## 7. Data Validity Per Source Type

### HIGH Validity

| Source         | Why high validity                                                                                                          |
|----------------|-----------------------------------------------------------------------------------------------------------------------------|
| `auth.log`     | Linux kernel-generated. Timestamps from system clock. Structured syslog format. SSH login/logout, sudo commands are reliable. User extraction patterns well-tested against Linux PAM messages. |
| `zeek/ssh.log` | Zeek NSM captures sessions passively from network. Auth success/failure is read from the SSH protocol state machine. Timestamps are Unix epoch floats — no year ambiguity. |
| `zeek/http.log`| Same passive capture reliability. HTTP method, URI, status code are parsed from protocol. Fields are always tab-separated per Zeek spec. |
| `suricata eve.json (alerts)` | Suricata rules are written by analysts; alert signatures represent deliberate detection logic. Severity is an integer from the rule definition (1=highest). |

### MEDIUM Validity

| Source         | Why medium validity                                                                                                          |
|----------------|------------------------------------------------------------------------------------------------------------------------------|
| `syslog`       | Year is inferred from file mtime (not embedded in syslog format). If a file was modified after exercise, year is wrong. Service extraction is heuristic (`svc.split('/')[0]`). |
| `zeek/conn.log`| Reliable timestamps and 5-tuple. However, `action_name = 'flow'` for all records means phase is always `unknown` unless dest port implies a known service — which the classifier does not currently use. |
| `bt.jsonl`     | Custom sensor format; fields depend on what the exercise instrumentation chose to log. Message parsing for command extraction uses generic regex that may miss edge cases. Alert severity for rootkit events is hardcoded as 7 (rootkit) or 5 (other). |
| `sensor.log`   | Mixed format (Python dict literals and JSON). The `ast.literal_eval` fallback for malformed lines is fragile. ATTACK_STATUS and RTRIGGERD markers are reliable indicators but require matching against expected exercise playbook. |
| `UAT-*.tsv`    | Keystroke reconstruction is heuristic. BackSpace handling replays the correct char deletion. Special keys (arrows, Ctrl, etc.) are discarded. Window title user extraction (`user@host:path` pattern) works for standard terminal emulators but may miss non-standard titles. |

### LOW Validity

| Source          | Why low validity                                                                                                           |
|-----------------|----------------------------------------------------------------------------------------------------------------------------|
| `*.cast`        | Commands are extracted by matching shell prompt patterns (`$ `, `# `, `>>> `) in the terminal output stream. ANSI escape codes are stripped, but partial writes and terminal redraws can produce false command fragments. Timestamp resolution is only to the start of the session (header timestamp), not per-command. |
| `hacktools.log` | Apache access log from a local tool server. Only tells us which URLs were requested, not whether tools were actually run. A 200 response means the file was served; it does not confirm execution. |
| `suricata eve.json (flows/stats)` | Flow and stats events carry no semantic meaning about what the attacker did. They fill the timeline but contribute nothing to phase or behavior analysis. |

---

## 8. Known Limitations

### 1. 22.3% Unknown Phase Rate

94,613 of 423,444 events (22.3%) remain `phase = 'unknown'` after 31 classification rules were applied in-place. As documented in Section 6, the residual unknowns are genuine infrastructure noise (rtkit-daemon, dbus, pulseaudio, NetworkManager, systemd lifecycle, Suricata telemetry counters, empty sensor packets). No meaningful MITRE phase can be assigned to them without fabricating signal. The prior rate was 78.6% (333,219 / 423,444) before classification work; 238,606 events were reclassified in three batches of SQL UPDATEs.

### 2. Phase Classification is Heuristic

The `PHASE_RULES` regex table was written by hand to cover common attacker tool names and command patterns. It has several failure modes:

- **False positives**: `bash ` or `sh ` (rule 23) matches virtually any shell invocation, including benign system scripts. These will be labeled `execution` even if they are not attacker activity.
- **False negatives**: custom or renamed tools will not match. An attacker using a custom port scanner or a renamed binary will show as `unknown`.
- **Order dependency**: rules are evaluated first-match-wins. A command matching both rule 7 (`ssh`) and rule 10 (`whoami`) will only get `lateral_movement` if `ssh` appears first in the command string.
- **No context**: each event is classified independently. There is no sequence modeling or cross-event context.

### 3. Timestamp Year Inference

`auth.log` and `syslog` use the format `Aug 15 12:00:00` without a year. The ingestion script infers the year from the file's mtime (`file.stat().st_mtime`). If the file was copied or touched after the exercise, the year will be wrong and timeline ordering will be incorrect.

### 4. UAT Data Only in Training Scenario

UAT keystroke files (`UAT-*.tsv`) are only present under `user0003/training`. The other participants (ckc1, ckc2) have no UAT data. The `typed_text` field is therefore only populated for training scenario events.

### 5. No Manual Ground Truth Labels

There is no manually verified ground truth for attack phase per event. All phase labels come from the heuristic classifier. The exercise playbook (if available) would be needed to validate labels.

### 6. `user4002.orig` Dominates Event Count

`user4002.orig` contains 293,812 events (69% of the total), most of which appear to be repetitive network flow records. Aggregations and statistics can be misleading if this participant is not filtered or weighted appropriately.

### 7. Integer Alert Severity — Not Strings

Alert severity values in the database are integers, not strings. The mapping is:
- `>= 6` → HIGH (typically 7 for rootkit, 8 for ATTACK_STATUS/attack_indicator)
- `3–5` → MEDIUM
- `< 3` → LOW
- `0` → no alert / informational

Suricata severity follows its own convention: `1` = highest severity, `3` = lowest. This is inverted from the bt.jsonl convention. The ingestion script does not normalize these — raw Suricata severity values are stored as-is.

---

## 9. Validation Methods

Because no ground truth labels exist, validation must be done by cross-referencing multiple independent sources:

### Method 1 — Asciinema Recordings

`.cast` files are terminal session recordings. Any command visible in the cast recording that is also present in `auth.log` (via sudo) or Zeek (as an outbound connection) provides cross-source corroboration. A command appearing in at least two independent sources has higher confidence.

### Method 2 — Timeline Coherence

Phases should follow a logical progression: recon typically precedes initial_access, which precedes lateral_movement, which precedes persistence. Sort events by timestamp for a participant and inspect whether the phase sequence is plausible. Random or reversed phase ordering suggests misclassification.

### Method 3 — Exercise Playbook Cross-Reference

If the exercise playbook (step-by-step instructions given to participants) is available, it defines exactly which tools and commands should be run at each step. Matching playbook steps against the command browser in the dashboard allows direct verification of whether events were captured and correctly classified.

### Method 4 — Multi-Source Corroboration

For a given participant and time window, check whether the same action is recorded in multiple sources. For example, an SSH login should appear in:
- `auth.log` as an `Accepted` line
- `zeek/ssh.log` as an `ssh_session` with `result=success`
- `suricata eve.json` as a `suricata_ssh` event

If all three agree, confidence in that event is high. If only one source records it, treat it as lower confidence.

### Method 5 — User Consistency Check

Query events for a specific user and time window. Check whether the `source_host` and `src_ip` values are consistent with where that user is expected to be. An attacker user appearing on a workstation host is suspicious and may indicate lateral movement was detected.

---

## 10. Running the Platform

### Prerequisites

- Python 3.9+
- `fastapi`, `uvicorn` packages installed

### First-Time Database Build (only needed if DB does not exist)

```bash
cd /home/vidzalex/Desktop/research/GODEYE
python3 ingest_v2.py
```

This will:
1. Delete the existing `data/godeye_v2.db` if present
2. Walk all files under `/tmp/obsidian_full/P003`
3. Parse and normalize 423,444 events
4. Write them to `data/godeye_v2.db`
5. Print a summary table

Expected runtime: approximately 2-5 minutes depending on hardware.

### Starting the API Server

```bash
cd /home/vidzalex/Desktop/research/GODEYE
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

For background operation:

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 > /tmp/godeye_server.log 2>&1 &
```

### Accessing the Dashboard

Open in a browser:

```
http://localhost:8000/dashboard
```

Health check endpoint:

```
http://localhost:8000/api/health
```

Expected response: `{"status":"healthy","total_events":423444}`

### API Endpoints

| Endpoint                                    | Description                                         |
|---------------------------------------------|-----------------------------------------------------|
| `GET /api/health`                           | Server health and total event count                 |
| `GET /api/participants`                     | List of participant IDs and event counts            |
| `GET /api/overview`                         | Event counts by source type and attack phase        |
| `GET /api/timeline?participant=X`           | Events grouped by hour for participant X            |
| `GET /api/phase_progression?participant=X`  | Phase event counts in sequence order                |
| `GET /api/commands?participant=X`           | Command events for participant X                    |
| `GET /api/alerts?participant=X`             | Alert events filtered by severity threshold         |
| `GET /api/users?participant=X`              | Top users by event count for participant X          |
| `GET /api/hosts?participant=X`              | Top hosts by event count for participant X          |
| `GET /api/behavior?participant=X`           | Behavior tracking and anomaly events                |
| `GET /api/network?participant=X`            | Network flow summary for participant X              |
| `GET /api/media?participant=X`              | Media files (PCAP, video, cast) for participant X   |
| `GET /api/relationships?participant=X`      | Host-user-tool relationship graph data              |
| `GET /api/events?participant=X&phase=Y`     | Raw event browser with filtering                    |

---

## 11. Database Schema Reference

Database file: `data/godeye_v2.db`  
Table: `events`  
Total rows: 423,444  
Indexes: `timestamp_utc`, `participant_id`, `scenario_name`, `attack_phase`, `source_host`, `user`, `tool`, `action_name`, `source_type`

| Column          | Type    | Description                                                                                              |
|-----------------|---------|----------------------------------------------------------------------------------------------------------|
| `event_id`      | TEXT    | UUID v4, primary key                                                                                     |
| `participant_id`| TEXT    | Exercise participant: `user0003`, `user2003`, `user4002`, `user4002.orig`                                |
| `scenario_name` | TEXT    | Scenario: `training`, `ckc1`, `ckc2`                                                                    |
| `timestamp_utc` | TEXT    | ISO 8601 datetime string (UTC). Empty string if source did not provide a parseable timestamp.            |
| `source_type`   | TEXT    | Parser origin: `auth`, `syslog`, `bt_jsonl`, `sensor`, `suricata`, `zeek`, `uat`, `terminal_recording`, `hacktools`, `media` |
| `source_file`   | TEXT    | Absolute path to the source file this event was parsed from                                              |
| `source_host`   | TEXT    | Hostname of the machine this event was recorded on (from directory name)                                 |
| `src_ip`        | TEXT    | Source IP address (network events). Empty for host-based events.                                         |
| `src_port`      | INTEGER | Source port. Default 0.                                                                                  |
| `dest_ip`       | TEXT    | Destination IP address (network events).                                                                 |
| `dest_port`     | INTEGER | Destination port. Default 0.                                                                             |
| `protocol`      | TEXT    | Network protocol: `tcp`, `udp`, `icmp`, etc.                                                             |
| `user`          | TEXT    | OS-level username, cleaned and normalized. Empty if not extractable.                                     |
| `action_category`| TEXT   | High-level category: `authentication`, `execution`, `network`, `detection`, `persistence`, `system`, `web_access`, `behavior`, `media`, `file_transfer` |
| `action_name`   | TEXT    | Specific action label: `login`, `sudo_execution`, `ssh_session`, `ids_alert`, `rootkit_activity`, `terminal_command`, etc. |
| `tool`          | TEXT    | Tool or service involved: `ssh`, `sudo`, `zeek`, `suricata`, `docker`, `terminal`, `nmap`, etc.          |
| `result`        | TEXT    | Outcome: `success`, `failure`. Empty if not determinable.                                                |
| `command`       | TEXT    | Command string extracted from the event. Empty for network-only events.                                  |
| `typed_text`    | TEXT    | Reconstructed typed input from UAT keystroke logs. Only populated for `user0003` training scenario.      |
| `arguments`     | TEXT    | Command arguments (not currently extracted separately; use `command` field).                              |
| `working_dir`   | TEXT    | Working directory at time of command. Not extracted by current parsers.                                  |
| `process_id`    | INTEGER | OS process ID from syslog PID field. Default 0.                                                          |
| `attack_phase`  | TEXT    | MITRE ATT&CK phase: `recon`, `initial_access`, `lateral_movement`, `privilege_escalation`, `persistence`, `discovery`, `execution`, `command_and_control`, `exfiltration`, `defense_evasion`, `unknown` |
| `mitre_tactic`  | TEXT    | MITRE tactic ID (e.g. `TA0043`). Empty if phase is `unknown`.                                            |
| `mitre_technique`| TEXT   | MITRE technique ID (e.g. `T1046`). Empty if phase is `unknown`.                                          |
| `alert_type`    | TEXT    | Alert signature or type string. Populated for Suricata alerts, bt.jsonl rootkit events, sensor ATTACK_STATUS. |
| `alert_severity`| INTEGER | Alert severity integer. Suricata: 1=high, 3=low. bt.jsonl/sensor: 7-8=high, 5=medium, 3=low, 0=none.    |
| `detection_source`| TEXT  | Who detected this event: `behavior_tracking` for bt.jsonl events. Empty otherwise.                       |
| `http_method`   | TEXT    | HTTP verb: `GET`, `POST`, `PUT`, `DELETE`. Populated for Zeek HTTP, Suricata HTTP, hacktools events.      |
| `url`           | TEXT    | Request URI or DNS query. Populated for HTTP and DNS events.                                             |
| `user_agent`    | TEXT    | HTTP User-Agent string. Populated for Zeek and Suricata HTTP events.                                     |
| `http_status`   | INTEGER | HTTP response code. Default 0.                                                                           |
| `raw_data`      | TEXT    | The original unparsed log line or JSON string this event was derived from.                               |
| `extra_data`    | TEXT    | JSON string with additional fields that do not fit the main schema. Used by Zeek conn events for `service`, `duration`, `conn_state`. |
