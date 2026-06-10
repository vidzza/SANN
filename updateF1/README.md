# SANN

**Cybersecurity Scenario Analytics Platform.** SANN ingests raw red-team / CTF telemetry (screen recordings, terminal casts, keyloggers, syslog, auth logs, IDS alerts, packet captures, behavior tracker events) and presents it in a single synchronized HUD — video playback, terminal cast replay, and six event panels all moving on the same timeline.

![SANN Interface](TH.png)

---

## What it does

I built SANN to make sense of full-stack pentest recordings — the kind where you have hours of screen video plus dozens of log streams from every layer of the stack, and you need to figure out **what the attacker actually did, when, and why**.

The platform:

- **Ingests** raw telemetry from a participant's session: asciinema casts, OGV/WebM video, syslog/auth, Suricata `eve.json`, Zeek `conn.log`, sensor packet logs, behavior tracker (`bt.jsonl`) events, keylogger UAT files, hacktools / apt logs.
- **Classifies** every event against the **MITRE ATT&CK** taxonomy (14 tactics) using regex rules over commands, action names, and tools.
- **Stores** everything in SQLite with a unified schema (`events` table, 35 columns covering command, src/dst IPs, MITRE tactic/technique, host, user, phase, etc.) plus a `media_registry` table for video/cast metadata.
- **Serves** the data through a FastAPI backend with ~40 endpoints, with strict per-project isolation.
- **Visualizes** it in a single-page HTML frontend (no build step) showing video + cast + timeline + 6 live event panels (Terminal, Auth, Syslog, Network, Keylogger, PCAP), all synchronized to a master cursor.
- **Supports multiple datasets** ("projects") with isolated databases, switchable from the UI.
- **Accepts ZIP uploads** so a teammate can drop a new scenario archive into the UI and have it ingested, classified, and ready to browse in minutes.

---

## Requirements

- **Python 3.11+**
- **ffmpeg + ffprobe** (used for video transcoding and duration probing):
  ```bash
  sudo apt install ffmpeg
  ```
- A raw dataset directory (not included — see Dataset layout below). For ZIP uploads no pre-existing dataset is required.

---

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server (no data needed yet)
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# 3. Open the UI
#    http://localhost:8000/threat
```

That gets you a running platform with an empty database. From here either:
- **Upload a ZIP** through the `⊕ ZIP` button in the top bar (recommended for teammates), or
- **Point at an existing dataset folder** and run the ingest pipeline directly (see below).

---

## Uploading a dataset via ZIP (easiest)

1. Zip up your dataset folder. The ZIP should contain one or more `user<id>/...` subdirectories with the file layout described below.
2. In the UI top bar, click **⊕ ZIP**.
3. Fill in the project name (e.g. `P032`), optionally the attacker IPs (comma-separated), pick the ZIP file, hit **Upload**.
4. The status dialog will poll until the project is `ready` (typically 30s – 5min depending on size). Then it appears in the **PROJECT** dropdown and you can browse it.

Behind the scenes the upload endpoint extracts the ZIP, runs the full ingestion pipeline (`ingest_v2.py` + `import_manager.py` post-processing), and syncs the media registry. The project DB lives in `data/project_<id>.db`; all events are also dual-written into the main corpus `data/godeye_v2.db` with their `project_id` stamped.

---

## Setting up a dataset from disk

For larger datasets it's faster to ingest directly from a local folder rather than zipping it first.

### 1. Configure paths

```bash
cp .env.example .env
```

Edit `.env`:

```
GODEYE_DATA_ROOT=/path/to/your/dataset
GODEYE_DB_PATH=/path/to/data/godeye_v2.db
```

### 2. Dataset layout

```
dataset/
└── user<id>/
    └── <any-layout>/
        ├── *.cast           # asciinema terminal recording
        ├── UAT-*.tsv        # keylogger / typed-text log
        ├── auth.log         # SSH / sudo / login auth events
        ├── syslog           # system logs
        ├── eve.json         # Suricata IDS / NSM events
        ├── bt.jsonl         # honeytrap / behavior-tracker events
        ├── conn.log         # Zeek connection log (JSONL)
        ├── recording.ogv    # screen recording (or .webm)
        └── *.pcap           # raw packet capture
```

No file is mandatory — anything missing just doesn't show up in its panel. SANN auto-discovers files by scanning under `user<id>/`.

### 3. Ingest

```bash
python3 import_manager.py
```

This runs the full pipeline:
1. `ingest_v2.py` — parses every supported file into the unified `events` table
2. `.orig` deduplication — drops re-runs of the same session
3. Taxonomy normalization — collapses legacy `recon` labels into MITRE `reconnaissance`
4. Suricata timezone fix — converts `eve.json` offsets to UTC so events align with the video window
5. `media_registry` rebuild — auto-detects video, casts, keylogger files and links them to the timeline
6. Syslog/auth year repair — infers the correct year from cast header timestamps when syslog lines lack one
7. Validation — confirms every participant has events landing inside their video window across all 6 panels

If you've already ingested and only want to re-run the post-processing / validation:

```bash
python3 import_manager.py --skip-ingest
```

### 4. Start the server

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000/threat** in Chrome / Edge / Firefox.

---

## Using the UI

The HUD is divided into:

- **Top bar** — `PROJECT` selector (switch between datasets), `PARTICIPANT` selector (the user whose session you're watching), `⊕ ZIP` (upload a new project), and the MITRE phase ribbon (14 ATT&CK tactics, highlighting the currently dominant one at the cursor position).
- **Media zone** — switchable between `VIDEO` (the screen recording) and `TERMINAL CAST` (asciinema playback). The two stay in sync: scrub one and the other follows.
- **Master scrubber** — heatmap of event density along the full session timeline, color-coded by dominant MITRE tactic per bucket. Drag the cursor anywhere to jump.
- **Six event panels** (live-filtered to a ±120s window around the cursor):
  - **TERMINAL** — commands extracted from the cast file
  - **AUTH** — SSH / sudo / PAM events from `auth.log`
  - **SYSLOG** — system events
  - **NETWORK** — Suricata IDS alerts + honeytrap behavior events
  - **KEYLOGGER** — typed text from UAT files (clickable rows jump the cursor)
  - **PCAP** — Zeek flows + sensor packet captures (filtered to drop empty / noisy entries)
- **Phase ribbon** — clicking a tactic chip filters / highlights events of that phase.

Panels show `X of Y (last 200)` when more than 200 events are in the window. Scroll position is preserved during refetches so you don't get yanked to the bottom mid-read.

---

## Multiple projects (datasets)

SANN supports any number of isolated projects. The **PROJECT** dropdown in the top bar switches between them. Each project has:

- Its own SQLite database at `data/project_<id>.db`
- A row in the main `projects` table with name, data path, attacker IPs, status, and event count
- All events also dual-written into the main `godeye_v2.db` corpus, stamped with `project_id` so the corpus stays useful for cross-project queries

### Creating a project from a folder via API

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "P032",
    "project_type": "dataset",
    "data_path": "/path/to/P032",
    "attacker_ips": "128.16.11.9,114.0.194.2"
  }'
```

Then trigger ingestion:

```bash
curl -X POST http://localhost:8000/api/projects/<project_id>/ingest
```

Or just use the ZIP upload flow in the UI — it does both steps in one shot.

### Deleting a project

Deleting through the UI (or `DELETE /api/projects/<project_id>`) removes:
- The row in `projects`
- All `events` rows with that `project_id` in the main DB
- All `media_registry` rows with that `project_id`
- The standalone `data/project_<id>.db` file

---

## Repository layout

```
updateF1/
├── api/
│   └── main.py            # FastAPI server — all endpoints
├── frontend/
│   ├── palantir.html      # main HUD (the one served at /threat)
│   ├── index.html         # legacy / alternate dashboard
│   └── timeline.html      # standalone timeline view
├── data/                  # SQLite DBs land here (gitignored)
├── ingest_v2.py           # ingestion engine (parsers + MITRE classifier)
├── import_manager.py      # post-processing pipeline (dedup, TZ fix, validation)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GODEYE_DATA_ROOT` | `/tmp/obsidian_full/P003` | Root of the default dataset on disk |
| `GODEYE_DB_PATH` | `data/godeye_v2.db` | Main SQLite corpus path |
| `GODEYE_ATTACKER_IPS` | (P003 defaults) | Comma-separated attacker IPs for `sensor_packet` C2 classification |
| `GODEYE_CORS_ORIGINS` | `localhost:8000,127.0.0.1:8000,localhost:3000` | CORS allowlist (comma-separated) |

Put them in a `.env` file at the repo root; the API and CLI tools both auto-load it.

---

## API overview

All endpoints accept `?project_id=<id>` to scope queries to a single project. Omit it and you query the combined corpus.

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
| GET | `/api/participants` | Per-participant event totals and phase breakdown |
| GET | `/api/phases` | Phase distribution across the project |
| GET | `/api/timeline` | Timeline events (filterable by participant / phase / host) |
| GET | `/api/alerts` | IDS alerts |
| GET | `/api/network` | Top src/dst IPs and ports |
| GET | `/api/commands` | Distinct commands run |
| GET | `/api/hosts` | Host activity summary |
| GET | `/api/events/stream` | Filtered event stream with time window + source filters |
| GET | `/api/timeline/sync` | Media items + event markers for the timeline scrubber |
| GET | `/api/timeline/playback` | Full per-second playback frame (video, terminal, panels) |
| GET | `/api/media/list` | Media registry entries for a participant |
| GET | `/api/media/video/{pid}` | Stream video (OGV → VP8 WebM transcode on the fly) |
| GET | `/api/media/cast_raw/{media_id}` | Raw asciinema cast for `asciinema-player` |
| GET | `/api/media/cast_list` | All cast files for a participant |

---

## Security

The server is meant to run on `localhost` for analysis. Even so, several defensive measures are in place:

- **CORS allowlist** — only the origins in `GODEYE_CORS_ORIGINS` get the `Access-Control-Allow-Origin` header.
- **Path traversal prevention** — `data_path` on project create must resolve under `GODEYE_DATA_ROOT.parent`.
- **`attacker_ips` validation** — only IPv4/IPv6/CIDR characters allowed; shell injection attempts are rejected with 400.
- **LIMIT clamping** — all `LIMIT` parameters are clamped to ≤10,000 to prevent runaway queries.
- **Strict project isolation** — invalid `project_id` returns 404 instead of falling back to the main corpus, so a typo can't accidentally leak cross-project data.
- **No filesystem path leaks** — `source_file` paths are stripped from API responses; only filenames or `media_id` references are exposed.
- **Subprocess hardening** — ingest subprocesses use `sys.executable` (current venv) instead of hardcoded `python3`; export files use `tempfile.mkstemp` instead of predictable `/tmp` paths.

---

## Troubleshooting

**Video shows "Transcoding for browser compatibility..." forever**
You're missing `ffmpeg`. Install it (`sudo apt install ffmpeg`) and reload the page. The overlay now times out after 30s with a toast notification instead of hanging.

**A panel is empty but I expected data**
Check the cursor is inside the video window for that participant. Panels show events within ±120s of the cursor. The `import_manager.py` validation pass logs each participant's panel coverage during ingest — re-run it with `--skip-ingest` to see the status.

**Suricata events are off by 4 hours**
The ingester now converts `eve.json` timestamps (which carry an explicit `-0400` / etc. offset) to UTC before storing. If you have an older DB, re-run `import_manager.py --skip-ingest` to apply the timezone fix to existing rows.

**A new ZIP upload's media doesn't show up**
The upload endpoint kicks off ingest in a background thread and then triggers `sync_media_for_project` once ingest finishes. If the project shows `status=ready` but no media is registered, hit `POST /api/projects/{id}/sync_media` manually — that scans the data folder and rebuilds the registry.

**CORS errors in the browser console**
Add your origin to `GODEYE_CORS_ORIGINS` in `.env` (comma-separated) and restart the server.

---

## License

Internal tool. Not for redistribution without permission.
