# SANN — Cybersecurity Scenario Analytics Platform

> Research instrument for the post-hoc analysis of full-stack red-team / CTF sessions.
> Synchronizes screen recordings with multi-source telemetry under a unified MITRE ATT&CK lens.

![SANN Interface](TH.png)

---

## Table of contents

1. [Motivation](#1-motivation)
2. [What SANN is](#2-what-sann-is)
3. [System architecture](#3-system-architecture)
4. [Data model](#4-data-model)
5. [Ingestion pipeline (`ingest_v2.py`)](#5-ingestion-pipeline-ingest_v2py)
6. [MITRE ATT&CK classification methodology](#6-mitre-attck-classification-methodology)
7. [Post-processing pipeline (`import_manager.py`)](#7-post-processing-pipeline-import_managerpy)
8. [API layer (`api/main.py`)](#8-api-layer-apimainpy)
9. [Multi-project isolation model](#9-multi-project-isolation-model)
10. [Frontend HUD (`frontend/palantir.html`)](#10-frontend-hud-frontendpalantirhtml)
11. [Synchronization logic (video ↔ cast ↔ cursor)](#11-synchronization-logic-video--cast--cursor)
12. [Installation](#12-installation)
13. [Usage workflows](#13-usage-workflows)
14. [Dataset layout](#14-dataset-layout)
15. [API reference](#15-api-reference)
16. [Security hardening](#16-security-hardening)
17. [Validation methodology](#17-validation-methodology)
18. [Reproducibility](#18-reproducibility)
19. [Known limitations](#19-known-limitations)
20. [Troubleshooting](#20-troubleshooting)
21. [Repository layout](#21-repository-layout)
22. [License](#22-license)

---

## 1. Motivation

In red-team / pentest / CTF evaluations I routinely deal with sessions that produce **dozens of parallel observation streams** — a screen recording of the attacker's workstation, asciinema casts of every terminal they opened, kernel-level syslog from the victim hosts, authentication logs, Suricata IDS alerts, Zeek connection logs, honeytrap behavior events, raw `sensor_packet` captures, UAT keylogger files, and APT repository / hacktools metadata. Existing tooling forced me to choose between:

- **Reviewing the video** (rich semantics, no querying)
- **Reading the logs in a SIEM** (queryable, no temporal-visual anchor)
- **Replaying a single cast file** (terminal only, no surrounding context)

There was no way to ask the question that matters most in this domain — *"what was the attacker actually doing on screen at the precise moment Suricata fired alert X, and which kernel events were that command producing?"* — without manually time-aligning multiple windows on a desktop.

SANN exists to **collapse all of those streams onto a single synchronized cursor**, to classify every event under a common taxonomy (MITRE ATT&CK), and to make the result browsable as a single web app. The unit of analysis is the **participant session**: one user (`user2003`, `user4002`, …) producing one video + N casts + arbitrary log streams, optionally grouped into a **project** (a multi-participant scenario such as `P003` or `P032`).

The platform is meant for **research and after-action review**, not real-time defense. It is offline, single-tenant, and runs against pre-captured datasets.

---

## 2. What SANN is

A self-contained system with four layers:

| Layer | Component | Role |
|---|---|---|
| Data ingest | `ingest_v2.py` | Parsers for ~10 telemetry formats → unified SQLite schema |
| Post-processing | `import_manager.py` | Timezone repair, year inference, dedup, taxonomy normalization, media registry rebuild, validation |
| Backend API | `api/main.py` (FastAPI) | ~40 endpoints with strict per-project isolation |
| Frontend HUD | `frontend/palantir.html` | Single-page web app: video + cast + scrubber + 6 live panels + MITRE ribbon |

### Capabilities

- **Ingest** asciinema casts (`.cast`), OGV/WebM screen recordings, syslog, `auth.log`, Suricata `eve.json`, Zeek `conn.log`, honeytrap `bt.jsonl`, sensor packet logs, UAT keylogger TSVs, hacktools logs, apt-repo logs, raw PCAPs (metadata only).
- **Classify** every event against the **MITRE ATT&CK enterprise tactics** (14 tactics + `unknown`), with the resolved `mitre_tactic` (e.g. `TA0001`) and `mitre_technique` (e.g. `T1190`) stored alongside the row.
- **Stream-transcode** OGV/Theora video to VP8 WebM on the fly via `ffmpeg`, because Chrome/Edge dropped Theora support — without ffmpeg there is no way to play Asciinema-companion recordings in a modern browser.
- **Synchronize** asciinema cast playback with the screen recording: scrubbing the master cursor seeks both; switching panes between `VIDEO` and `TERMINAL CAST` aligns them to the same wall-clock instant.
- **Per-project isolation**: each scenario gets its own SQLite DB (`data/project_<id>.db`) plus a dual-write into a combined corpus DB (`data/godeye_v2.db`) keyed by `project_id`, so cross-project queries and single-project views are both first-class.
- **ZIP upload** workflow for collaborators: drop a `.zip` containing a `user<id>/...` tree into the UI and the entire ingest + post-processing pipeline runs in a background thread; status is polled until the project transitions to `ready`.

---

## 3. System architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Raw dataset (filesystem)                                            │
│  └─ user<id>/                                                        │
│       ├─ *.cast, recording.{ogv,webm}                                │
│       ├─ syslog, auth.log, eve.json, conn.log, bt.jsonl, *.tsv, …    │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼  (subprocess)
┌──────────────────────────────────────────────────────────────────────┐
│  ingest_v2.py                                                        │
│  • parse_<format>() for each source type                             │
│  • classify_phase() → MITRE ATT&CK (tactic, technique)               │
│  • Dual-write: project DB + main DB (stamped with project_id)        │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  import_manager.py                                                   │
│  • dedupe_orig_participants()                                        │
│  • fix_recon_taxonomy()       (legacy "recon" → "reconnaissance")    │
│  • fix_suricata_timestamps()  (per-file TZ offset detection)         │
│  • fix_syslog_years()         (year inferred from cast headers)      │
│  • rebuild_media_registry()                                          │
│  • validate()                                                        │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  data/                                                               │
│  ├─ godeye_v2.db                  ← main corpus, all projects merged │
│  ├─ project_<id>.db               ← per-project isolated DB          │
│  └─ project_<id>.db (one per scenario)                               │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼  qp(project_id, sql)
┌──────────────────────────────────────────────────────────────────────┐
│  api/main.py  (FastAPI)                                              │
│  • /api/health, /api/projects, /api/projects/upload                  │
│  • /api/participants, /api/phases, /api/timeline, /api/alerts,       │
│    /api/network, /api/commands, /api/hosts, /api/events/stream …    │
│  • /api/media/{video, cast_raw, list, cast_list, keylogger}          │
│  • /api/timeline/{sync, playback}                                    │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼  HTTP (CORS-restricted)
┌──────────────────────────────────────────────────────────────────────┐
│  frontend/palantir.html                                              │
│  • Top bar: PROJECT, PARTICIPANT, ⊕ ZIP, MITRE phase ribbon          │
│  • Media zone: <video> (transcoded WebM) or asciinema-player         │
│  • Master scrubber + heatmap                                         │
│  • 6 live panels: Terminal, Auth, Syslog, Network, Keylogger, PCAP   │
└──────────────────────────────────────────────────────────────────────┘
```

The design is intentionally **flat and procedural** — no ORM, no client framework, no build step. Each file is independently runnable for debugging.

---

## 4. Data model

### `events` table (35 columns)

The central table. Every row is a single observed action / packet / alert / log line, regardless of source.

| Column | Type | Description |
|---|---|---|
| `event_id` | TEXT PK | UUIDv4 |
| `participant_id` | TEXT | `userNNNN` — the user whose session produced the event |
| `scenario_name` | TEXT | `ckc1`, `ckc2`, `training`, etc. (kill-chain phase shorthand) |
| `timestamp_utc` | TEXT | ISO-8601 in UTC, naive form (e.g. `2025-08-15T19:07:17.115520`). Stored without timezone marker for lexicographic ordering |
| `source_type` | TEXT | `terminal_recording`, `auth`, `syslog`, `suricata`, `bt_jsonl`, `zeek`, `sensor`, `uat`, `hacktools`, `apt_repo`, `media` |
| `source_file` | TEXT | Original file path (for audit; stripped from API responses) |
| `source_host` | TEXT | Hostname that emitted the event |
| `src_ip`, `dest_ip` | TEXT | L3 endpoints if applicable |
| `src_port`, `dest_port` | INT | L4 endpoints |
| `protocol` | TEXT | `TCP`, `UDP`, `HTTP`, `SSH`, `DNS`, … |
| `command` | TEXT | The reconstructed shell command, if extractable |
| `typed_text` | TEXT | Keylogger text (UAT only) |
| `user` | TEXT | OS user the action was performed as |
| `action_category` | TEXT | `network`, `system`, `authentication`, `web_access`, `behavior`, `detection`, … |
| `action_name` | TEXT | Finer-grained label: `suricata_alert`, `http_traffic`, `sudo_execution`, … |
| `tool` | TEXT | Tool identified from command or context: `nmap`, `metasploit`, `suricata`, `ssh`, … |
| `attack_phase` | TEXT | One of 14 MITRE tactics + `unknown` |
| `mitre_tactic` | TEXT | `TA0043`, `TA0001`, … |
| `mitre_technique` | TEXT | `T1046`, `T1190`, … |
| `alert_type` | TEXT | Suricata signature, honeytrap behavior indicator, … |
| `alert_severity` | INT | 0–10 |
| `url`, `http_method`, `http_status`, `user_agent` | TEXT/INT | HTTP fields when source is web-related |
| `working_dir` | TEXT | Cwd at time of command, when known |
| `raw_data` | TEXT | Original line / JSON of the event, for cross-checking |
| `project_id` | TEXT | Project scope key (key innovation — see §9) |

### `media_registry` table

One row per playable / scrubable artifact: video, terminal cast, keylogger TSV. The table lives **only in the main DB**, never in per-project DBs, but every row carries a `project_id` for filtering.

| Column | Description |
|---|---|
| `media_id` | Stable SHA-1 (8 chars) of `participant + media_type + filename` |
| `participant_id` | Owner |
| `scenario_name` | Same as in `events` |
| `media_type` | `video`, `terminal`, `keylogger` |
| `source_file` | Absolute path (not exposed via API) |
| `source_host` | Recording host |
| `start_timestamp`, `end_timestamp` | ISO timestamps |
| `start_unix`, `end_unix` | Epoch floats (faster scrubbing) |
| `duration_seconds` | Float |
| `panel` | UI hint (`video`, `terminal`, …) |
| `project_id` | Project scope key |

### `projects` table

| Column | Description |
|---|---|
| `project_id` | 8-char hex |
| `name`, `description`, `project_type` (`dataset`/`filter`) | metadata |
| `data_path` | Root directory of the participant trees |
| `attacker_ips` | Comma-separated; used for `sensor_packet` C2 classification |
| `db_path` | Path to `project_<id>.db` |
| `filter_json` | For `filter`-type projects (saved query views) |
| `status` | `ingesting` / `ready` / `error` |
| `event_count`, `created_at`, `updated_at` | bookkeeping |

---

## 5. Ingestion pipeline (`ingest_v2.py`)

The ingester is a single Python script — argparse CLI, no daemon, no queue. It is invoked by `import_manager.py` and by the API's `/api/projects/upload` endpoint via `subprocess` using `sys.executable` (so a venv is honored).

### Parser dispatch

For each file discovered under `data_root/`, the filename is matched against a dispatch table to pick a parser:

```python
PARSER_DISPATCH = {
    'eve.json':       parse_suricata_eve,
    '*.cast':         parse_cast_file,
    'auth.log':       parse_auth_log,
    'syslog':         parse_syslog,
    'conn.log':       parse_zeek_conn,
    'bt.jsonl':       parse_bt_jsonl,
    'sensor*.log':    parse_sensor_log,
    'UAT-*.tsv':      parse_uat_log,
    'hacktools.log':  parse_hacktools,
    'apt.log':        parse_apt_log,
}
```

Each parser is an **iterator** that yields event dicts conforming to the schema. The driver feeds the dict through `make_event()` (which fills defaults and stamps `project_id`) and into the buffered `DBv2.insert()`.

### Key parser design decisions

**`parse_suricata_eve` — timezone handling**
Suricata writes `timestamp` with an explicit offset (`2025-08-15T11:25:23.826914-0400`). Earlier versions of the parser stripped the offset and stored the local time as if it were UTC, which made Suricata events appear 4 hours before the screen recording for any host running EDT. The current implementation:

```python
normalized = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', ts_raw)
dt = datetime.fromisoformat(normalized.replace('Z', '+00:00'))
ts_utc = dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
```

The regex inserts the colon that Python 3.11+'s `fromisoformat` requires (`-0400` → `-04:00`), parses with the offset preserved, converts to UTC, then strips the tz marker for storage. The naive form is intentional: every other field in the schema is naive UTC, so lexicographic string comparisons (`BETWEEN '2025-08-15T19:07:17' AND '2025-08-15T19:39:53'`) produce the right ordering without parsing.

**`parse_sensor_log` — Python dict-literal lines**
`sensor.log` lines look like `{'time': 1755291832.49, 'type': 'PACKET', 'data': {'src_ip': '10.0.0.1', ...}}`. They are **not** JSON — the keys use single quotes and Python booleans (`True`/`False`). Naive `json.loads(line.replace("'", '"'))` corrupts payloads that contain apostrophes (e.g. `"can't"` in HTTP bodies). The parser now tries `ast.literal_eval` first (which natively understands Python dict literals) and only falls back to the JSON-with-quote-swap heuristic on failure.

**`parse_sensor_log` — C2 classification by attacker IP**
The dataset's notion of "the attacker" is encoded in a per-project `attacker_ips` field. When a `sensor_packet` event has either `src_ip` or `dst_ip` in this set, it is reclassified as `command_and_control`. This is a heuristic — it presumes the attacker IPs are known a priori (typical in lab settings where the red team uses fixed VPS IPs).

**`parse_cast_file` — command extraction from terminal recordings**
asciinema cast files are JSONL of `[t_offset, "o", "<terminal bytes>"]`. To recover commands I treat the prompt regex `(?:[\$#]\s+|>>>\s+)(.+)` as a delimiter and accumulate output between prompts. The same regex extracts the cwd from the prompt when a path is shown (e.g. `user@kali:~/Documents# `). Commands are then fed into `classify_phase()` for MITRE labeling.

**`parse_syslog` / `parse_auth_log` — missing year**
The classic syslog format (`Aug 15 19:07:17 host kernel: ...`) does not carry a year. `ingest_v2.py` infers the year from the file's mtime; `import_manager.fix_syslog_years()` then cross-checks against the cast header's epoch timestamp (which **does** include the year) and shifts the rows if the inferred year is wrong (typical when datasets are copied between filesystems and mtimes are reset to "now").

**`parse_bt_jsonl` — honeytrap behavior events**
Behavior tracker events carry a top-level `timestamp` in ISO form (already UTC, with `Z`). They include a behavioral category (`rootkit`, `malware`, `lateral_movement`, …) that maps directly into a MITRE phase via `BT_ACTION_MAP`.

**Robustness**
Every parser wraps its body in `try/except Exception` so a single malformed line never aborts a multi-million-row ingest. Lines that fail are skipped; a count is implicit in the final summary delta.

### Dual-write to main DB

When `--main-db` and `--project-id` are both supplied (the API always does this), the ingester opens a second `DBv2` instance pointing at the main corpus and writes every event to **both** DBs, stamping the main-DB row with the `project_id`. The startup hook first deletes any rows for that `project_id` so re-ingests are idempotent.

---

## 6. MITRE ATT&CK classification methodology

### Goal
Classify each event into one of the 14 MITRE ATT&CK Enterprise tactics (`TA00XX`) and, where possible, identify the technique (`TXXXX`).

### Approach
A **two-stage hybrid** of fast lookup + regex:

1. **Action-name fast path** — A dict `_ACTION_PHASE` keyed on the normalized `action_name` returns a `(phase, tactic, technique)` tuple in O(1) for events whose source already labels them (e.g. `sudo_execution` → `privilege_escalation/TA0004/T1548`).

2. **Regex rules over command text** — `PHASE_RULES` is an ordered list of `(regex, phase, tactic, technique)`. The first match wins. Examples:

   ```python
   (r'nmap|masscan|netdiscover|fping',          'reconnaissance', 'TA0043', 'T1046'),
   (r'sqlmap|sqli|sql.*injection',              'initial_access', 'TA0001', 'T1190'),
   (r'hydra|medusa|john|hashcat|bruteforce',    'initial_access', 'TA0001', 'T1110'),
   (r'crontab|/etc/cron|systemctl enable',      'persistence',    'TA0003', 'T1053'),
   (r'sudo\s|su\s|pkexec',                      'privilege_escalation', 'TA0004', 'T1548.003'),
   (r'iptables|ufw\s|setenforce\s0',            'defense_evasion','TA0005', 'T1562'),
   (r'rm -rf|shred|history -c|unset HISTFILE',  'defense_evasion','TA0005', 'T1070'),
   (r'curl.*PUT|wget.*post|ftp\s',              'exfiltration',   'TA0010', 'T1048'),
   ```

3. **Fallback constants** for honeypot interactions (`HONEYPOT_PHASE = 'initial_access'`), rootkit indicators (`ROOTKIT_PHASE = 'persistence'`), and brute-force events (`BRUTEFORCE_PHASE = 'initial_access'`).

4. **Validation gate**: every classified phase is checked against a `MITRE_TACTICS` whitelist of the 14 canonical labels. Invalid labels collapse to `unknown` rather than polluting the dataset.

### Why not ML?

I evaluated text-classification approaches (`BERT`-style intent classifiers trained on the ATT&CK procedure examples corpus) and ruled them out for this iteration because:

- The training corpus per tactic is small (~100s of examples), unbalanced, and biased toward English narrative procedure descriptions, not raw shell commands.
- Latency: the ingester processes 100k–500k events per project; a transformer inference is 2–3 orders of magnitude slower than regex.
- Interpretability: in research review I want to be able to point at the literal rule that fired. Regex matches are auditable, embedding-based decisions are not.

Regex labels are **monotonically improvable**: when a session produces miscategorized events, the fix is a one-line addition to `PHASE_RULES` plus a re-run of `import_manager.py --skip-ingest` (which re-classifies in-place by re-running the labeler over `command`).

### Known shortcomings
- The regex set is biased toward Linux red-team tooling (the dataset I was building for); macOS/Windows-specific tooling would need new rules.
- `unknown` is the modal label for `bt_jsonl` events that don't match a `BT_ACTION_MAP` key — these are behavior-tracker indicators with no clear ATT&CK mapping, and conservatively defaulting to `unknown` is preferable to over-claiming.
- Multi-tactic actions (e.g. `nmap` against an internal host = simultaneous `discovery` + `reconnaissance`) collapse to a single label.

---

## 7. Post-processing pipeline (`import_manager.py`)

After raw ingest, `import_manager.py` runs a deterministic chain of repair passes against the resulting SQLite. Each step is idempotent (safe to re-run with `--skip-ingest`).

| Step | Function | What it does |
|---|---|---|
| 1 | `dedupe_orig_participants` | Removes events from `*.orig` participant directories (re-runs of the same session) |
| 2 | `fix_recon_taxonomy` | `UPDATE events SET attack_phase='reconnaissance' WHERE attack_phase='recon'` (legacy label cleanup) |
| 3 | `fix_suricata_timestamps` | For each participant, reads the first eve.json to detect the `±HHMM` offset, then SQL-updates all suricata rows by adding/subtracting the corresponding interval. Catches DBs ingested before the parser TZ fix |
| 4 | `rebuild_media_registry` | `DELETE FROM media_registry; INSERT ...` from disk scan. Cast duration is read from the last frame's `t_offset`; video duration from `ffprobe -show_format` |
| 5 | `fix_syslog_years` | For each participant, the expected year is taken from the cast header epoch; any syslog/auth row whose stored year disagrees is updated by `±N years` via SQL string-arithmetic on the `timestamp_utc` substring |
| 6 | `validate` | For each participant with a video, verifies that at least 2 of the 6 panel sources have events inside the video window. Logs `OK` / `EMPTY` per (participant, panel) and warns if `terminal_recording` doesn't start within 60s of the video |

### `run_full_pipeline(project_id, data_root, db_path, attacker_ips, main_db)`

A public function callable from the API. Wraps the full chain in a try/except that updates `projects.status` to `ingesting` → `ready` (or `error`) so the UI's polling loop sees the transition. The API's `/api/projects/upload` invokes this through a background thread and triggers `sync_media_for_project` afterward.

---

## 8. API layer (`api/main.py`)

FastAPI, ~40 endpoints. Two notable helpers:

### `q(sql, params)` — main-DB query
```python
def q(sql, params=()):
    con = get_con()           # main DB connection
    try:
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return []          # graceful empty result on fresh install
        raise
    finally:
        con.close()
```

### `qp(project_id, sql, params)` — project-scoped query
```python
def qp(project_id, sql, params=()):
    con = get_project_con(project_id)   # project DB if id given & exists, else main DB
    # Same exception-handling envelope as q()
```

`get_project_con()` is the gatekeeper that enforces isolation: if `project_id` is non-empty but doesn't resolve to a known project in the `projects` table, it raises `HTTPException(404)` rather than silently falling back to the main DB. This prevents a typo in a `project_id` query parameter from accidentally returning combined-corpus data when the consumer expected a single project's view.

### Bootstrap migration

A `@app.on_event("startup")` hook:

1. Creates the data directory if absent.
2. Creates the `projects` and `media_registry` tables in the main DB if absent (idempotent `CREATE TABLE IF NOT EXISTS`).
3. Adds missing columns to existing tables (`attacker_ips` on `projects`, `project_id` on `events` and `media_registry`) so older DBs are upgraded on first start.
4. Skips the `events`-table column addition when `events` doesn't exist yet — the ingester creates it on first ingest with the full schema, including `project_id`.

The bootstrap allows the server to start **on a completely empty `data/` directory**: every event-related endpoint returns `[]` or `{count: 0}` until the first ZIP upload arrives.

### `LIMIT` clamping

Every endpoint that accepts a `limit` parameter clamps to `min(limit, 10000)`. The clamping happens at the Python level and the SQL uses a `?` placeholder (parametrized) — both belt and suspenders, since the `int` type already prevents SQL injection.

### CORS

Allowed origins are configured via the `GODEYE_CORS_ORIGINS` env var (comma-separated). The default list is `http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000`. There is no wildcard.

---

## 9. Multi-project isolation model

This is the only piece of the architecture that warrants its own section.

### Why two DBs per project?

I wanted two things at the same time:

- **Hard isolation per project** — a researcher can hand a single SQLite file (`project_<id>.db`) to a collaborator and that file is fully self-contained. No cross-project leakage is possible because the data simply isn't there.
- **Cross-project queries** — for meta-analysis (e.g. "across all CKC1 scenarios, what fraction of participants used `sqlmap` in the first hour?") I want a single corpus to query.

The compromise is **dual-write**: every event lands in both `project_<id>.db` and the main `godeye_v2.db`, with the latter copy carrying `project_id` in its row. Storage doubles, but this is acceptable at the scales we deal with (a typical session is 100k–300k rows; 6 sessions × dual-write ≈ 2M rows, well within SQLite's comfort zone).

### Query routing

| Endpoint receives | Routed to | Filter |
|---|---|---|
| `project_id="da2c86c9"` | `project_da2c86c9.db` | (none — DB itself is the filter) |
| `project_id=""` | `godeye_v2.db` | (none — combined corpus) |
| `project_id="bogus"` | — | HTTP 404 |

### `media_registry` is a special case

Media (video, casts, keylogger files) is small and **lives only in the main DB**. Project DBs do not have a `media_registry` table. Endpoints that need media join on `(participant_id, project_id)` against the main DB. This avoids replicating large file paths and keeps the per-project DBs purely about events.

### Deletion

`DELETE /api/projects/{id}` removes:
- The row in `projects`
- Every `events` row in the main DB with `project_id = <id>`
- Every `media_registry` row in the main DB with `project_id = <id>`
- The `project_<id>.db` file (after a path-traversal check that the file is under `data/`)

---

## 10. Frontend HUD (`frontend/palantir.html`)

Single HTML file, ~64KB. No build tooling. Dependencies (asciinema-player CSS+JS) are loaded from a CDN. State lives in a single `S` object; rendering is direct DOM manipulation.

### Top bar

- **PROJECT** dropdown — switching it triggers a full state teardown: pauses the video, removes its `src`, calls `dispose()` on the asciinema player, clears the 6 panel bodies, resets the cursor, and refetches the participant list for the new project. Failure to do this teardown was the source of many early bugs (cast players leaking, ffmpeg processes orphaned).
- **PARTICIPANT** dropdown — similar but narrower teardown (video pause + cast dispose + panel clear + load new participant's media and timeline).
- **⊕ ZIP** button — opens an upload modal (name, attacker IPs, file picker). On submit, POSTs multipart to `/api/projects/upload`, polls `/api/projects/{id}/status` every 2s until `ready` or `error`, then reloads the project dropdown.

### MITRE phase ribbon

14 pills + an `unknown` pill, each with `data-phase="<tactic>"`. The currently-active phase is computed in `updatePhaseBadge()` from `S.heatBuckets[idx].dominant_phase` and toggled via a CSS `.active` class. When the cursor is over a bucket with `total == 0` (or the bucket array is empty), all pills are deactivated.

### Master scrubber

A `<canvas>` heatmap drawn from `/api/timeline/playback` returns `phases[]` (buckets across the full video timeline, each with `total` and `dominant_phase`). Each bucket is rendered as a vertical bar whose color comes from `phasePalette[dominant_phase]` and whose height encodes density. A separate `<canvas>` layer draws the media ranges (video and cast spans) and the cursor. Drag-to-scrub updates `S.cursorEpoch` and triggers `fetchAllPanels()` when the delta exceeds 3 seconds.

### Six event panels

Each panel fetches from `/api/events/stream` filtered to its source types and the ±120s window around `cursorEpoch`:

| Panel | Sources |
|---|---|
| TERMINAL | `terminal_recording` |
| AUTH | `auth` |
| SYSLOG | `syslog` |
| NETWORK | `suricata,bt_jsonl` |
| KEYLOGGER | `uat` |
| PCAP | `zeek,sensor` |

Panel renderers share a `_panelUpdate(body, cnt, html, total, unit)` helper that:
- Shows `X of Y (last 200)` when `total > 200`, otherwise just `total unit`.
- **Preserves scroll position** unless the user is already scrolled to the bottom, so refetching doesn't yank you out of context mid-read.
- Highlights "near" events (within 2s of cursor) with a CSS class `.event-near`.

PCAP applies an additional filter that drops `sensor_packet` events without `src_ip` and `dest_ip` and without a useful `action_name`. These are noise (raw L2 frames with no extractable semantics) and would otherwise drown the panel in useless rows.

### Error UX

`showToast(msg, type)` renders a transient fixed-position notice (4s timeout) with red/yellow/green styling. Used by:

- The video stream error handler — `vid.onerror` fires when ffmpeg is missing or the file is unreadable. There is also a 30s safety timeout that hides the loading overlay and shows a toast if `canplay` never fires.
- The ZIP upload modal — surfaces server-side validation errors.
- The fetch wrapper for any 4xx/5xx response.

---

## 11. Synchronization logic (video ↔ cast ↔ cursor)

The "master cursor" is `S.cursorEpoch` — a Unix epoch float that all UI elements derive from.

### Tick loop (`setInterval(..., 250ms)`)

- If `mediaMode === 'video'` and the video is playing: `cursorEpoch = videoStartEpoch + S.videoStreamT + vid.currentTime`.
- If `mediaMode === 'cast'` and the cast player exists: `cursorEpoch = castStartEpoch + castPlayer.getCurrentTime()`. The cast player API differs between asciinema-player v2 (method) and v3 (property), so the call falls back to `castPlayer.currentTime` if `getCurrentTime` isn't a function.

### Seeking

- **Drag-to-scrub** on the scrubber → `S.cursorEpoch = …` directly, then a `syncMediaToCursor()` call seeks the active media to `cursor - mediaStart`.
- **Native `<video>` seek bar** → `vid.onseeked` fires after a manual seek and updates the cursor (skipped if the user is currently dragging the scrubber, to avoid loops).
- **Pill switch** (VIDEO ⇄ TERMINAL CAST) → calls `syncCastToCursor()` or `syncVideoToCursor()` so the newly-shown medium aligns with the cursor.

### Video stream seek

OGV/Theora doesn't seek natively in Chrome, so seeking is implemented by **re-launching ffmpeg with `-ss <offset>`** and reloading the `<video>` source. `_reloadVideoStream(pid, tOffset)` builds the URL `/api/media/video/<pid>?t=<offset>&project_id=<id>`, sets it on the element, and shows a "TRANSCODING…" overlay until `vid.oncanplay` fires (or the 30s safety timeout trips).

### Why a tick loop instead of `requestAnimationFrame`?

The data fetch granularity is 5 seconds (panel refetch threshold). A 250ms tick is more than enough for cursor smoothness while avoiding the per-frame work of an animation loop. It also makes the loop easy to reason about under the debugger.

---

## 12. Installation

### Requirements

- **Python 3.11+** (uses `datetime.fromisoformat` with offset notation that was added in 3.11)
- **ffmpeg + ffprobe** — `sudo apt install ffmpeg`. Without ffmpeg the video panel cannot transcode OGV; pure `.webm` datasets will still work via direct file serving.
- A reasonably modern browser (Chromium-family or Firefox).

### Setup

```bash
git clone https://github.com/vidzza/SANN.git
cd SANN/updateF1            # or the repo root if upstream merged
pip install -r requirements.txt
```

### Configuration

Copy the template and edit:

```bash
cp .env.example .env
```

Variables:

| Variable | Default | Purpose |
|---|---|---|
| `GODEYE_DATA_ROOT` | `/tmp/obsidian_full/P003` | Root of the default dataset on disk |
| `GODEYE_DB_PATH` | `data/godeye_v2.db` | Main SQLite corpus path |
| `GODEYE_ATTACKER_IPS` | (P003 defaults) | Comma-separated attacker IPs for `sensor_packet` C2 classification |
| `GODEYE_CORS_ORIGINS` | `localhost:8000,127.0.0.1:8000,localhost:3000` | CORS allowlist (comma-separated) |

The same `.env` is loaded by `ingest_v2.py`, `import_manager.py`, and `api/main.py`.

### Starting the server (empty)

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Then open **http://localhost:8000/threat**. The server runs against an empty corpus until you upload a ZIP or run the ingestion pipeline.

---

## 13. Usage workflows

### A — Upload a session via ZIP (recommended for collaborators)

1. Zip up the dataset folder. The archive root should contain one or more `user<id>/...` subdirectories matching §14.
2. In the UI top bar, click **⊕ ZIP**.
3. Fill in name (e.g. `P032`), optional attacker IPs, pick the ZIP, **Upload**.
4. The status dialog polls `/api/projects/<id>/status` until `ready` (30s–5min depending on size).
5. The new project appears in the **PROJECT** dropdown.

Behind the scenes:
- The API extracts the ZIP into `data/uploads/dataset_<id>/`.
- A background thread runs `import_manager.py --data-root … --db … --project-id <id> --main-db …`.
- On success, `sync_media_for_project(<id>)` is called to populate the `media_registry`.
- `projects.status` transitions `ingesting` → `ready` (or `error`).

### B — Ingest directly from a local dataset

```bash
# Edit .env first so GODEYE_DATA_ROOT points at your dataset
python3 import_manager.py
```

This runs the full pipeline against the default dataset and produces `data/godeye_v2.db`. For an isolated project:

```bash
python3 import_manager.py \
  --data-root /path/to/P032 \
  --db data/project_9c4cee20.db \
  --project-id 9c4cee20 \
  --main-db data/godeye_v2.db \
  --attacker-ips "128.16.11.9,114.0.194.2"
```

### C — Re-run post-processing without re-ingesting

```bash
python3 import_manager.py --skip-ingest
```

Useful after editing `PHASE_RULES` or fixing a bug in `fix_suricata_timestamps`. Operates on the existing DB in place.

### D — Programmatic project creation (no UI)

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "P032",
    "project_type": "dataset",
    "data_path": "/path/to/P032",
    "attacker_ips": "128.16.11.9,114.0.194.2"
  }'
# returns {"project_id": "9c4cee20", ...}

curl -X POST http://localhost:8000/api/projects/9c4cee20/ingest
```

---

## 14. Dataset layout

The ingester scans for files anywhere under `user<id>/`, so the exact intermediate structure is flexible. The set of files SANN looks for:

```
dataset_root/
└── user<id>/
    └── <scenario>/<run>/<host>/
        ├── *.cast              # asciinema terminal recordings
        ├── UAT-*.tsv           # keylogger / typed-text TSV
        ├── auth.log            # SSH / sudo / PAM events
        ├── syslog              # systemd / kernel logs
        ├── eve.json            # Suricata IDS / NSM events
        ├── bt.jsonl            # honeytrap / behavior tracker
        ├── conn.log            # Zeek connection log (JSONL)
        ├── sensor*.log         # raw sensor_packet logs
        ├── recording.ogv       # screen recording (or recording.webm)
        ├── *.pcap              # raw packet capture (metadata only)
        ├── hacktools.log       # red-team tool invocations
        └── apt.log             # apt-repo activity
```

**No file is mandatory.** Missing files simply don't populate their panel. The validation pass in `import_manager.py` will WARN about empty panels but won't fail the import.

The `scenario_name` is derived from the directory immediately under `user<id>/` (commonly `training`, `ckc1`, `ckc2`, `ckc2c` for kill-chain stages).

---

## 15. API reference

All endpoints accept `?project_id=<id>` to scope queries to a single project. Omit it to query the combined corpus.

### Health & projects

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness + total event count |
| GET | `/api/projects` | List projects with status and event counts |
| POST | `/api/projects` | Create a project from a local folder |
| POST | `/api/projects/upload` | Create a project from a ZIP upload |
| GET | `/api/projects/{id}/status` | Poll ingest status |
| POST | `/api/projects/{id}/ingest` | Re-ingest a dataset project |
| POST | `/api/projects/{id}/sync_media` | Rebuild media registry for a project |
| DELETE | `/api/projects/{id}` | Delete project + events + media |
| GET | `/api/projects/{id}/tree` | Filesystem tree of the project |
| GET | `/api/projects/{id}/export/sqlite` | Download a snapshot of the project DB |

### Events & stats

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/participants` | Per-participant event totals and phase breakdown |
| GET | `/api/participants/{pid}` | One participant's detail |
| GET | `/api/participants/{pid}/phases` | Phase breakdown for one participant |
| GET | `/api/participants/{pid}/commands` | Commands used by one participant |
| GET | `/api/participants/{pid}/timeline` | Per-participant timeline |
| GET | `/api/phases` | Phase distribution across the project |
| GET | `/api/phases/{phase}` | All events of one MITRE phase |
| GET | `/api/timeline` | Timeline events (filterable by participant / phase / host) |
| GET | `/api/alerts` | IDS alerts |
| GET | `/api/network` | Top src/dst IPs and ports |
| GET | `/api/commands` | Distinct commands run |
| GET | `/api/commands/top` | Most frequent commands |
| GET | `/api/users` | OS users observed |
| GET | `/api/hosts` | Host activity summary |
| GET | `/api/relationships` | Graph: participant → host → user relationships |
| GET | `/api/behavior/{pid}` | Behavior tracker events for a participant |
| GET | `/api/search?q=<term>` | Cross-field text search |
| GET | `/api/events/stream` | Filtered event stream with time window + source filters |
| GET | `/api/events/{event_id}` | One full event row |
| GET | `/api/stats` | Aggregate statistics for a project |
| GET | `/api/stats/participant` | Per-participant aggregate stats |
| GET | `/api/analysis/overview` | Overview tile data |

### Media & timeline

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/media` | Media registry entries (filterable) |
| GET | `/api/media/list?participant_id=…` | Media for one participant |
| GET | `/api/media/cast_list?participant_id=…` | All cast files for a participant |
| GET | `/api/media/cast_raw/{media_id}` | Raw asciinema cast (for `asciinema-player`) |
| GET | `/api/media/cast/{media_id}` | Parsed cast frames |
| GET | `/api/media/video/{participant_id}?t=<seek>` | Stream video (OGV → VP8 WebM on the fly) |
| GET | `/api/media/keylogger?participant_id=…` | Parsed UAT keylogger rows |
| GET | `/api/timeline/sync` | Media items + event markers for the scrubber |
| GET | `/api/timeline/playback` | Per-second playback frame (video, terminal, panels) |
| GET | `/api/timeline/events` | Events for the timeline (legacy alias) |
| GET | `/api/timeline/cast/{media_id}` | Cast events on the timeline |
| GET | `/api/timeline/uat/{media_id}` | UAT events on the timeline |
| GET | `/api/timeline/pcap/{media_id}` | PCAP events on the timeline |

---

## 16. Security hardening

The server is meant to run on `localhost` for analysis. Even so, several defensive measures are in place:

| Mitigation | Where | Why |
|---|---|---|
| CORS allowlist | `CORSMiddleware`, env-configurable | Prevent browser-based cross-origin probes |
| Path traversal block | `create_project` validates `data_path` resolves under `GODEYE_DATA_ROOT.parent` | Stop API consumers from ingesting `/etc/passwd` |
| `attacker_ips` regex | `^[\d.:a-fA-F/,]+$` | Block shell injection via the IP field that is later interpolated into a subprocess argv |
| LIMIT clamping | Every `limit` param `min(limit, 10000)` | Bound query cost; even though `int` already prevents SQLi |
| `LIMIT ?` parametrization | All event-streaming queries | Belt-and-suspenders parametrization |
| `project_id` 404 | `get_project_con` raises if id not in `projects` | Prevent silent main-DB fallback on a typo |
| `source_file` stripping | All media endpoints | Don't leak filesystem layout to the client |
| `sys.executable` subprocess | Both ingest invocations | Honors active venv; doesn't rely on a `python3` symlink |
| `tempfile.mkstemp` | Project export | Avoid predictable `/tmp/<id>.db` race / overwrite |
| Strict project DB unlink | `delete_project` resolves and checks under `data/` | Stop `db_path` field tampering from deleting arbitrary files |
| Bare `except:` audit | Replaced with explicit `except Exception` in parsers | Prevent masking of `KeyboardInterrupt` and bugs |

---

## 17. Validation methodology

I treat data correctness as a first-class concern because the entire point of the tool is to support claims about attacker behavior — and incorrect time alignment would invalidate every claim.

### Triple-pass automated validation

For each (participant, panel) pair the validation pass asserts:

1. **At least 2 of 6 panels populated within the video window** — sessions where this fails are flagged in the import log.
2. **Terminal events start within 60s of video start** — confirms cast/video alignment. Drift >300s emits a warning.
3. **Suricata events fall inside the video window** — catches lingering TZ bugs.

### Manual verification queries

```bash
# Distinct phases — should be subset of the 14 MITRE tactics + 'unknown'
sqlite3 data/godeye_v2.db "SELECT DISTINCT attack_phase FROM events"

# Project consistency: main DB row count = sum of project DB row counts
sqlite3 data/godeye_v2.db "SELECT project_id, COUNT(*) FROM events GROUP BY project_id"

# Suricata alignment per participant
sqlite3 data/godeye_v2.db "
  SELECT participant_id,
         MIN(timestamp_utc) AS first_alert,
         MAX(timestamp_utc) AS last_alert
  FROM events
  WHERE source_type='suricata'
  GROUP BY participant_id"
```

### End-to-end test (clean install)

The repository ships with a smoke-test workflow that:

1. Boots the server against an empty `data/` directory.
2. Verifies `/api/health` returns `total_events: 0`.
3. Uploads a synthetic ZIP via `/api/projects/upload`.
4. Polls `/api/projects/<id>/status` until `ready`.
5. Confirms the new project appears in `/api/projects` with `event_count > 0` and `/api/participants?project_id=<id>` enumerates the expected participants.

---

## 18. Reproducibility

- **All ingestion is deterministic** — same input files always produce the same DB rows (no random IDs except `event_id`, which is UUIDv4; subsequent passes match on `(participant_id, timestamp_utc, source_type, action_name)` for dedup).
- **Schema versioning** — the `events` table has been frozen at 35 columns; new fields go into the `raw_data` JSON blob to avoid breaking downstream queries.
- **Pinned dependencies** — `requirements.txt` pins `fastapi==0.109.0`, `uvicorn[standard]==0.27.0`, `python-dateutil==2.8.2`. No transitive surprises.
- **Single-file frontend** — no `node_modules`, no build step, no version churn.
- **`import_manager.py --skip-ingest`** — every post-processing step is idempotent, so a researcher can re-apply corrections without redoing the multi-hour ingest.

---

## 19. Known limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| MITRE classifier is regex-based and Linux-biased | Windows/macOS commands may fall to `unknown` | Add rules to `PHASE_RULES`; rerun with `--skip-ingest` |
| `sensor_packet` is noisy | PCAP panel can be overwhelmed | Frontend filters out entries with no IPs and no semantic `action_name` |
| OGV transcoding is CPU-intensive | First playback can take 5–10s on slow hosts | The UI shows a TRANSCODING overlay; 30s safety timeout |
| Cast files with binary control sequences | Some commands aren't recovered | Acknowledged limitation; raw output is available via the cast player |
| `media_registry` lives only in main DB | Cannot fully isolate media metadata per project | By design — media files are referenced via project DB joins on `(participant_id, project_id)` |
| Single-tenant assumption | No authentication | Bind to `localhost`; use SSH tunneling for remote access |
| SQLite scaling | Tested up to ~500k events per project; ~2M combined | For larger corpora, the schema would migrate to Postgres |

---

## 20. Troubleshooting

**Video shows "Transcoding for browser compatibility..." forever**
Missing `ffmpeg`. Install with `sudo apt install ffmpeg` and reload. The overlay now times out after 30s with a toast notification instead of hanging.

**A panel is empty but I expected data**
Confirm the cursor is inside the video window for that participant. Panels show events within ±120s of the cursor. The `import_manager.py` validation pass logs each (participant, panel) coverage during ingest — rerun with `--skip-ingest` to see the matrix.

**Suricata events are off by 4 hours**
If your DB was ingested before the TZ fix, run `python3 import_manager.py --skip-ingest`. The `fix_suricata_timestamps` pass detects the offset from the eve.json source file and corrects existing rows in place.

**A ZIP upload's media doesn't show up**
The upload endpoint kicks off ingest in a background thread, then triggers `sync_media_for_project` once ingest finishes. If `status=ready` but the media list is empty, call `POST /api/projects/{id}/sync_media` manually.

**CORS errors in the browser console**
Add the origin to `GODEYE_CORS_ORIGINS` in `.env` (comma-separated) and restart the server.

**`HTTP 404` from `/api/participants?project_id=<id>`**
The project ID doesn't exist in the `projects` table. List with `GET /api/projects`. This is intentional — a typo no longer silently returns the combined corpus.

**Ingestion subprocess fails silently**
The API runs ingest under `subprocess.run(..., stdout=DEVNULL, stderr=DEVNULL)` to avoid blocking the request thread. For debugging, run `import_manager.py` directly from the CLI with the same arguments to see the logs.

---

## 21. Repository layout

```
updateF1/
├── api/
│   └── main.py            # FastAPI server — all endpoints, bootstrap, helpers
├── frontend/
│   ├── palantir.html      # main HUD (served at /threat)
│   ├── index.html         # legacy / alternate dashboard
│   └── timeline.html      # standalone timeline view
├── data/                  # SQLite DBs land here (gitignored except .gitkeep)
├── ingest_v2.py           # ingestion engine (parsers + MITRE classifier)
├── import_manager.py      # post-processing pipeline (dedup, TZ fix, validation)
├── requirements.txt       # pinned Python deps
├── .env.example           # config template
└── README.md              # this file
```

---

## 22. License

Internal research instrument. Not for redistribution without permission. Cite as:

> SANN — Cybersecurity Scenario Analytics Platform. Vidzza, 2026. https://github.com/vidzza/SANN
