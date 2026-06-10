"""
SANN API — FastAPI server backed by sann.db
"""

import asyncio
import csv
import io
import json
import shutil
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query, Body, Request, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import os as _os
from pathlib import Path as _Path

def _load_env_file():
    env_file = _Path(__file__).parent.parent / '.env'
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, _, v = line.partition('=')
                _os.environ.setdefault(k.strip(), v.strip())

_load_env_file()

DB_PATH = Path(_os.environ.get('SANN_DB_PATH',
              str(Path(__file__).parent.parent / "data" / "sann.db")))
FRONTEND_PATH = Path(__file__).parent.parent / "frontend"
MEDIA_ROOT = Path(_os.environ.get('SANN_DATA_ROOT', '/tmp/obsidian_full/P003'))

app = FastAPI(
    title="SANN API",
    description="SANN — Cybersecurity Scenario Analytics Platform",
    version="2.0.0",
)

import logging as _logging
_logger = _logging.getLogger("sann.api")

_CORS_ORIGINS = [o.strip() for o in _os.environ.get(
    "SANN_CORS_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Startup — ensure all required tables exist in the DB
# ---------------------------------------------------------------------------

_BOOTSTRAP_SQL = [
    """CREATE TABLE IF NOT EXISTS projects (
        project_id   TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        description  TEXT DEFAULT '',
        project_type TEXT NOT NULL,
        data_path    TEXT DEFAULT '',
        filter_json  TEXT DEFAULT '{}',
        db_path      TEXT DEFAULT '',
        attacker_ips TEXT DEFAULT '',
        created_at   TEXT,
        updated_at   TEXT,
        event_count  INTEGER DEFAULT 0,
        status       TEXT DEFAULT 'ready'
    )""",
    """CREATE TABLE IF NOT EXISTS media_registry (
        media_id         TEXT PRIMARY KEY,
        participant_id   TEXT,
        scenario_name    TEXT,
        media_type       TEXT,
        source_file      TEXT,
        source_host      TEXT,
        start_timestamp  TEXT,
        start_unix       REAL,
        end_timestamp    TEXT,
        end_unix         REAL,
        duration_seconds REAL,
        panel            TEXT,
        project_id       TEXT DEFAULT ''
    )""",
]


@app.on_event("startup")
async def _bootstrap_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        con = sqlite3.connect(str(DB_PATH))
        for sql in _BOOTSTRAP_SQL:
            con.execute(sql)
        # events table is created by ingest_v2.py at first ingest; the migrations
        # below only run if it already exists.
        proj_cols = {r[1] for r in con.execute("PRAGMA table_info(projects)").fetchall()}
        if proj_cols and "attacker_ips" not in proj_cols:
            con.execute("ALTER TABLE projects ADD COLUMN attacker_ips TEXT DEFAULT ''")
        ev_cols = {r[1] for r in con.execute("PRAGMA table_info(events)").fetchall()}
        if ev_cols and "project_id" not in ev_cols:
            con.execute("ALTER TABLE events ADD COLUMN project_id TEXT DEFAULT ''")
            con.execute("CREATE INDEX IF NOT EXISTS idx_project ON events(project_id, timestamp_utc)")
        mr_cols = {r[1] for r in con.execute("PRAGMA table_info(media_registry)").fetchall()}
        if mr_cols and "project_id" not in mr_cols:
            con.execute("ALTER TABLE media_registry ADD COLUMN project_id TEXT DEFAULT ''")
        con.commit()
        con.close()
    except Exception as e:
        _logger.warning(f"Bootstrap migration warning: {e}")


# ---------------------------------------------------------------------------
# Media discovery helpers
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import subprocess as _subprocess

def _stable_id(s: str) -> str:
    return _hashlib.sha1(s.encode()).hexdigest()[:8]

def _unix_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

def _cast_header_ts(cast_path: Path) -> Optional[float]:
    try:
        with cast_path.open() as f:
            hdr = json.loads(f.readline())
        return float(hdr.get('timestamp') or 0) or None
    except Exception:
        return None

def _cast_duration(cast_path: Path) -> float:
    last = 0.0
    try:
        with cast_path.open() as f:
            f.readline()  # skip header
            for line in f:
                try:
                    row = json.loads(line)
                    if isinstance(row, list) and len(row) >= 1:
                        last = max(last, float(row[0]))
                except Exception:
                    pass
    except Exception:
        pass
    return last

def _video_duration(video_path: Path) -> Optional[float]:
    try:
        out = _subprocess.check_output(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(video_path)],
            stderr=_subprocess.DEVNULL, timeout=15
        )
        return float(out.strip())
    except Exception:
        return None

def _discover_media(data_root: Path, participants: list) -> list:
    """Return list of media_registry row dicts for given participants under data_root."""
    rows = []
    for pid, scenario in participants:
        pid_dir = data_root / pid
        if not pid_dir.exists():
            continue

        cast_entries = []
        for c in sorted(pid_dir.rglob('*.cast')):
            ts = _cast_header_ts(c)
            if ts:
                cast_entries.append((c, ts, _cast_duration(c), c.parent.name))

        # video
        video_candidates = list(pid_dir.rglob('recording.webm')) + list(pid_dir.rglob('recording.ogv'))
        video_file = video_candidates[0] if video_candidates else None

        if video_file:
            video_start = min(e[1] for e in cast_entries) if cast_entries else video_file.stat().st_mtime
            video_dur = _video_duration(video_file)
            if video_dur is None:
                video_dur = max((e[1] + e[2]) - video_start for e in cast_entries) if cast_entries else 0
            rows.append({
                'media_id':        _stable_id(pid + ':video'),
                'participant_id':  pid,
                'scenario_name':   scenario,
                'media_type':      'video',
                'source_file':     str(video_file),
                'source_host':     video_file.parent.name,
                'start_timestamp': _unix_to_iso(video_start),
                'start_unix':      video_start,
                'end_timestamp':   _unix_to_iso(video_start + video_dur),
                'end_unix':        video_start + video_dur,
                'duration_seconds': video_dur,
                'panel':           'video',
            })

        for c, ts, dur, host in cast_entries:
            rows.append({
                'media_id':        _stable_id(pid + ':cast:' + c.name),
                'participant_id':  pid,
                'scenario_name':   scenario,
                'media_type':      'terminal',
                'source_file':     str(c),
                'source_host':     host,
                'start_timestamp': _unix_to_iso(ts),
                'start_unix':      ts,
                'end_timestamp':   _unix_to_iso(ts + dur),
                'end_unix':        ts + dur,
                'duration_seconds': dur,
                'panel':           'terminal',
            })
    return rows


def _write_media_rows(rows: list, project_id: str = ""):
    """Insert/replace media rows into the main DB's media_registry."""
    if not rows:
        return
    if project_id:
        for r in rows:
            r['project_id'] = project_id
    con = sqlite3.connect(str(DB_PATH))
    con.executemany("""
        INSERT OR REPLACE INTO media_registry
        (media_id, participant_id, scenario_name, media_type, source_file, source_host,
         start_timestamp, start_unix, end_timestamp, end_unix, duration_seconds, panel,
         project_id)
        VALUES (:media_id, :participant_id, :scenario_name, :media_type, :source_file,
                :source_host, :start_timestamp, :start_unix, :end_timestamp, :end_unix,
                :duration_seconds, :panel, :project_id)
    """, [{**r, 'project_id': r.get('project_id', '')} for r in rows])
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------

def get_con() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def get_project_con(project_id: str = "") -> sqlite3.Connection:
    """Return connection to project DB if project_id given and DB exists, else main DB.
    Raises 404 if project_id is given but does not exist (prevents cross-project leaks)."""
    if project_id:
        try:
            con = sqlite3.connect(str(DB_PATH))
            row = con.execute("SELECT db_path FROM projects WHERE project_id=?", (project_id,)).fetchone()
            con.close()
            if row and row[0] and Path(row[0]).exists():
                pc = sqlite3.connect(row[0])
                pc.row_factory = sqlite3.Row
                return pc
            raise HTTPException(404, f"Project not found: {project_id}")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(500, f"Database error accessing project {project_id}")
    return get_con()


def q(sql: str, params = ()) -> List[dict]:
    con = get_con()
    try:
        cur = con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return []
        raise
    finally:
        con.close()


def qp(project_id: str, sql: str, params = ()) -> List[dict]:
    """Like q() but uses project DB when project_id is provided."""
    con = get_project_con(project_id)
    try:
        cur = con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return []
        raise
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {"platform": "SANN", "version": "2.0.0"}


@app.get("/api/health")
async def health():
    try:
        result = q("SELECT COUNT(*) as n FROM events")
        n = result[0]["n"] if result else 0
        return {"status": "healthy", "total_events": n}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------

@app.get("/api/participants")
async def get_participants(project_id: str = ""):
    """List all participants with event counts and phase coverage."""
    rows = qp(project_id, """
        SELECT
            participant_id,
            scenario_name,
            COUNT(*) as total_events,
            COUNT(DISTINCT source_host) as unique_hosts,
            COUNT(DISTINCT user) as unique_users,
            COUNT(CASE WHEN command != '' AND command IS NOT NULL THEN 1 END) as command_count,
            COUNT(CASE WHEN typed_text != '' AND typed_text IS NOT NULL THEN 1 END) as typed_text_count,
            MIN(NULLIF(timestamp_utc, '')) as first_seen,
            MAX(timestamp_utc) as last_seen
        FROM events
        WHERE participant_id != '' AND participant_id IS NOT NULL
        GROUP BY participant_id
        ORDER BY participant_id
    """)

    # Add phase breakdown per participant
    phases = qp(project_id, """
        SELECT participant_id, attack_phase, COUNT(*) as n
        FROM events
        GROUP BY participant_id, attack_phase
        ORDER BY participant_id, n DESC
    """)

    phase_map: dict = {}
    for p in phases:
        pid = p["participant_id"]
        if pid not in phase_map:
            phase_map[pid] = {}
        phase_map[pid][p["attack_phase"] or "unknown"] = p["n"]

    for row in rows:
        row["phases"] = phase_map.get(row["participant_id"], {})

    return {"participants": rows}


@app.get("/api/participants/{participant_id}")
async def get_participant(participant_id: str, project_id: str = ""):
    """Full detail for one participant."""
    base = qp(project_id, """
        SELECT
            participant_id, scenario_name,
            COUNT(*) as total_events,
            COUNT(DISTINCT source_host) as unique_hosts,
            COUNT(DISTINCT user) as unique_users,
            COUNT(CASE WHEN command != '' AND command IS NOT NULL THEN 1 END) as command_count,
            COUNT(CASE WHEN typed_text != '' AND typed_text IS NOT NULL THEN 1 END) as typed_text_count,
            MIN(NULLIF(timestamp_utc, '')) as first_seen,
            MAX(timestamp_utc) as last_seen
        FROM events
        WHERE participant_id = ?
        GROUP BY participant_id
    """, (participant_id,))

    if not base:
        raise HTTPException(status_code=404, detail="Participant not found")

    result = base[0]

    result["phases"] = qp(project_id, """
        SELECT attack_phase, mitre_tactic, COUNT(*) as n
        FROM events
        WHERE participant_id = ?
        GROUP BY attack_phase, mitre_tactic
        ORDER BY n DESC
    """, (participant_id,))

    result["hosts"] = qp(project_id, """
        SELECT source_host, COUNT(*) as n
        FROM events
        WHERE participant_id = ?
        GROUP BY source_host
        ORDER BY n DESC
    """, (participant_id,))

    result["users"] = qp(project_id, """
        SELECT user, COUNT(*) as n
        FROM events
        WHERE participant_id = ? AND user != '' AND user IS NOT NULL
        GROUP BY user
        ORDER BY n DESC
        LIMIT 20
    """, (participant_id,))

    result["top_tools"] = qp(project_id, """
        SELECT tool, COUNT(*) as n
        FROM events
        WHERE participant_id = ? AND tool != '' AND tool IS NOT NULL
        GROUP BY tool
        ORDER BY n DESC
        LIMIT 20
    """, (participant_id,))

    result["action_categories"] = qp(project_id, """
        SELECT action_category, COUNT(*) as n
        FROM events
        WHERE participant_id = ?
        GROUP BY action_category
        ORDER BY n DESC
    """, (participant_id,))

    result["hourly_activity"] = qp(project_id, """
        SELECT
            CAST(SUBSTR(timestamp_utc, 12, 2) AS INTEGER) as hour,
            COUNT(*) as n
        FROM events
        WHERE participant_id = ? AND timestamp_utc IS NOT NULL AND timestamp_utc != ''
        GROUP BY hour
        ORDER BY hour
    """, (participant_id,))

    return result


@app.get("/api/participants/{participant_id}/phases")
async def get_participant_phases(participant_id: str, project_id: str = ""):
    """Phase timeline — ordered events grouped by attack phase."""
    events = qp(project_id, """
        SELECT
            timestamp_utc, source_host, user, action_category, action_name,
            tool, command, typed_text, attack_phase, mitre_tactic, mitre_technique,
            src_ip, dest_ip, protocol, alert_type, alert_severity, raw_data
        FROM events
        WHERE participant_id = ?
          AND timestamp_utc IS NOT NULL AND timestamp_utc != ''
        ORDER BY timestamp_utc ASC
        LIMIT 5000
    """, (participant_id,))

    # Group by phase, preserve order
    phase_order = [
        "recon", "initial_access", "lateral_movement", "privilege_escalation",
        "persistence", "discovery", "execution", "command_and_control",
        "exfiltration", "defense_evasion", "unknown"
    ]

    grouped: dict = {ph: [] for ph in phase_order}
    for ev in events:
        ph = ev.get("attack_phase") or "unknown"
        if ph not in grouped:
            grouped[ph] = []
        grouped[ph].append(ev)

    phases_out = []
    for ph in phase_order:
        evs = grouped[ph]
        if evs:
            phases_out.append({
                "phase": ph,
                "count": len(evs),
                "first_seen": evs[0]["timestamp_utc"],
                "last_seen": evs[-1]["timestamp_utc"],
                "events": evs[:200],  # cap per phase for API response size
            })

    return {"participant_id": participant_id, "phases": phases_out}


@app.get("/api/participants/{participant_id}/commands")
async def get_participant_commands(
    participant_id: str,
    phase: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = 500,
    project_id: str = "",
):
    """All extracted commands for a participant."""
    conds = ["participant_id = ?", "command != ''", "command IS NOT NULL"]
    params: list = [participant_id]

    if phase:
        conds.append("attack_phase = ?")
        params.append(phase)
    if host:
        conds.append("source_host = ?")
        params.append(host)

    where = " AND ".join(conds)
    limit = min(limit, 10000)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, source_host, user, attack_phase,
               mitre_tactic, mitre_technique, tool, command, arguments, working_dir
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc ASC
        LIMIT ?
    """, tuple(params + [limit]))

    return {"participant_id": participant_id, "commands": rows, "total": len(rows)}


@app.get("/api/participants/{participant_id}/typed")
async def get_participant_typed(participant_id: str, project_id: str = ""):
    """Reconstructed UAT keystrokes for a participant."""
    rows = qp(project_id, """
        SELECT timestamp_utc, source_host, user, typed_text, command, attack_phase
        FROM events
        WHERE participant_id = ?
          AND typed_text != '' AND typed_text IS NOT NULL
        ORDER BY timestamp_utc ASC
    """, (participant_id,))
    return {"participant_id": participant_id, "typed_text": rows}


@app.get("/api/participants/{participant_id}/timeline")
async def get_participant_timeline(
    participant_id: str,
    limit: int = 2000,
    project_id: str = "",
):
    """Full timeline for a participant, lightweight fields."""
    limit = min(limit, 10000)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, source_host, user, action_category, action_name,
               tool, command, attack_phase, alert_severity, src_ip, dest_ip
        FROM events
        WHERE participant_id = ?
          AND timestamp_utc IS NOT NULL AND timestamp_utc != ''
        ORDER BY timestamp_utc ASC
        LIMIT ?
    """, (participant_id, limit))
    return {"participant_id": participant_id, "timeline": rows}


# ---------------------------------------------------------------------------
# Phases (global)
# ---------------------------------------------------------------------------

@app.get("/api/phases")
async def get_phases(project_id: str = ""):
    """Global phase distribution across all participants."""
    rows = qp(project_id, """
        SELECT attack_phase, participant_id, COUNT(*) as n
        FROM events
        GROUP BY attack_phase, participant_id
        ORDER BY attack_phase, n DESC
    """)

    # Pivot by phase
    phase_map: dict = {}
    for r in rows:
        ph = r["attack_phase"] or "unknown"
        if ph not in phase_map:
            phase_map[ph] = {"phase": ph, "total": 0, "by_participant": {}}
        phase_map[ph]["total"] += r["n"]
        phase_map[ph]["by_participant"][r["participant_id"]] = r["n"]

    order = [
        "reconnaissance", "resource_development", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion", "credential_access",
        "discovery", "lateral_movement", "collection", "command_and_control",
        "exfiltration", "impact", "unknown",
    ]
    result = []
    for ph in order:
        if ph in phase_map:
            result.append(phase_map[ph])
    # Append any phases not in the canonical order
    for ph, data in phase_map.items():
        if ph not in order:
            result.append(data)

    return {"phases": result}


@app.get("/api/phases/{phase}")
async def get_phase_events(
    phase: str,
    participant_id: Optional[str] = None,
    limit: int = 200,
    project_id: str = "",
):
    """Events for a specific attack phase."""
    conds = ["attack_phase = ?"]
    params: list = [phase]
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    limit = min(limit, 10000)
    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, participant_id, source_host, user,
               action_name, tool, command, typed_text,
               mitre_tactic, mitre_technique, src_ip, dest_ip,
               alert_type, alert_severity
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc ASC
        LIMIT ?
    """, tuple(params) + (limit,))

    return {"phase": phase, "events": rows, "total": len(rows)}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.get("/api/commands")
async def get_commands(
    participant_id: Optional[str] = None,
    phase: Optional[str] = None,
    host: Optional[str] = None,
    q_str: Optional[str] = Query(None, alias="q"),
    limit: int = 200,
    project_id: str = "",
):
    """Searchable command browser across all participants."""
    conds = ["command != ''", "command IS NOT NULL"]
    params: list = []

    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)
    if phase:
        conds.append("attack_phase = ?")
        params.append(phase)
    if host:
        conds.append("source_host = ?")
        params.append(host)
    if q_str:
        conds.append("command LIKE ?")
        params.append(f"%{q_str}%")

    limit = min(limit, 10000)
    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, participant_id, source_host, user,
               attack_phase, mitre_tactic, tool, command, arguments, working_dir
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc ASC
        LIMIT ?
    """, tuple(params) + (limit,))

    return {"commands": rows, "total": len(rows)}


@app.get("/api/commands/top")
async def get_top_commands(
    participant_id: Optional[str] = None,
    limit: int = 30,
    project_id: str = "",
):
    """Most frequent commands."""
    conds = ["command != ''", "command IS NOT NULL", "LENGTH(command) > 4"]
    params: list = []
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    limit = min(limit, 10000)
    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT command, attack_phase, COUNT(*) as n
        FROM events
        WHERE {where}
        GROUP BY command
        ORDER BY n DESC
        LIMIT ?
    """, tuple(params) + (limit,))
    return {"top_commands": rows}


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.get("/api/users")
async def get_users(participant_id: Optional[str] = None, project_id: str = ""):
    """All users with activity counts."""
    conds = ["user != ''", "user IS NOT NULL"]
    params: list = []
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT user, participant_id,
               COUNT(*) as event_count,
               COUNT(DISTINCT source_host) as host_count,
               COUNT(CASE WHEN command != '' AND command IS NOT NULL THEN 1 END) as command_count,
               MIN(NULLIF(timestamp_utc, '')) as first_seen,
               MAX(timestamp_utc) as last_seen
        FROM events
        WHERE {where}
        GROUP BY user, participant_id
        ORDER BY event_count DESC
        LIMIT 50
    """, tuple(params))
    return {"users": rows}


@app.get("/api/users/{username}")
async def get_user_detail(username: str, project_id: str = ""):
    """Detailed activity for a specific username."""
    base = qp(project_id, """
        SELECT user, participant_id,
               COUNT(*) as total_events,
               COUNT(DISTINCT source_host) as host_count,
               MIN(NULLIF(timestamp_utc, '')) as first_seen,
               MAX(timestamp_utc) as last_seen
        FROM events
        WHERE user = ?
        GROUP BY participant_id
    """, (username,))

    if not base:
        raise HTTPException(status_code=404, detail="User not found")

    phases = qp(project_id, """
        SELECT attack_phase, COUNT(*) as n
        FROM events WHERE user = ?
        GROUP BY attack_phase ORDER BY n DESC
    """, (username,))

    commands = qp(project_id, """
        SELECT timestamp_utc, source_host, participant_id,
               attack_phase, command, tool
        FROM events
        WHERE user = ? AND command != '' AND command IS NOT NULL
        ORDER BY timestamp_utc ASC
        LIMIT 100
    """, (username,))

    return {"user": username, "by_participant": base, "phases": phases, "commands": commands}


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

@app.get("/api/hosts")
async def get_hosts(participant_id: Optional[str] = None, project_id: str = ""):
    """All hosts with event counts."""
    conds = ["source_host != ''", "source_host IS NOT NULL"]
    params: list = []
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT source_host, participant_id, scenario_name,
               COUNT(*) as event_count,
               COUNT(DISTINCT user) as user_count,
               COUNT(CASE WHEN alert_type != '' AND alert_type IS NOT NULL THEN 1 END) as alert_count
        FROM events
        WHERE {where}
        GROUP BY source_host, participant_id
        ORDER BY event_count DESC
    """, tuple(params))
    return {"hosts": rows}


@app.get("/api/hosts/{host}")
async def get_host_detail(host: str, participant_id: Optional[str] = None, project_id: str = ""):
    """Detailed breakdown for a host."""
    conds = ["source_host = ?"]
    params: list = [host]
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    where = " AND ".join(conds)

    phase_dist = qp(project_id, f"SELECT attack_phase, COUNT(*) n FROM events WHERE {where} GROUP BY attack_phase ORDER BY n DESC", tuple(params))
    users = qp(project_id, f"SELECT user, COUNT(*) n FROM events WHERE {where} AND user != '' AND user IS NOT NULL GROUP BY user ORDER BY n DESC LIMIT 20", tuple(params))
    tools = qp(project_id, f"SELECT tool, COUNT(*) n FROM events WHERE {where} AND tool != '' AND tool IS NOT NULL GROUP BY tool ORDER BY n DESC LIMIT 20", tuple(params))
    alerts = qp(project_id, f"SELECT alert_type, alert_severity, timestamp_utc, raw_data FROM events WHERE {where} AND alert_type != '' AND alert_type IS NOT NULL ORDER BY timestamp_utc DESC LIMIT 50", tuple(params))
    timeline = qp(project_id, f"SELECT timestamp_utc, user, action_category, action_name, tool, command, attack_phase FROM events WHERE {where} AND timestamp_utc != '' AND timestamp_utc IS NOT NULL ORDER BY timestamp_utc ASC LIMIT 500", tuple(params))

    return {
        "host": host,
        "phase_distribution": phase_dist,
        "users": users,
        "tools": tools,
        "alerts": alerts,
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@app.get("/api/timeline")
async def get_timeline(
    participant_id: Optional[str] = None,
    phase: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = 2000,
    project_id: str = "",
):
    """Global timeline with optional filters."""
    conds = ["timestamp_utc IS NOT NULL", "timestamp_utc != ''"]
    params: list = []

    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)
    if phase:
        conds.append("attack_phase = ?")
        params.append(phase)
    if host:
        conds.append("source_host = ?")
        params.append(host)

    where = " AND ".join(conds)
    limit = min(limit, 10000)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, participant_id, source_host, user,
               action_category, action_name, tool, command,
               attack_phase, mitre_tactic, mitre_technique,
               src_ip, dest_ip, alert_type, alert_severity
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc ASC
        LIMIT ?
    """, tuple(params + [limit]))
    return {"timeline": rows}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def get_alerts(participant_id: Optional[str] = None, severity: Optional[str] = None, project_id: str = ""):
    conds = ["alert_type != ''", "alert_type IS NOT NULL"]
    params: list = []
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)
    if severity:
        conds.append("alert_severity = ?")
        params.append(severity)

    where = " AND ".join(conds)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, participant_id, source_host, user,
               alert_type, alert_severity, detection_source,
               src_ip, dest_ip, raw_data
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc DESC
        LIMIT 500
    """, tuple(params))
    return {"alerts": rows}


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

@app.get("/api/relationships")
async def get_relationships(participant_id: Optional[str] = None, project_id: str = ""):
    """Entity graph data: host-user, host-tool, user-tool, ip-host."""
    pid_cond = "AND participant_id = ?" if participant_id else ""
    pid_param = (participant_id,) if participant_id else ()

    host_users = qp(project_id, f"""
        SELECT source_host as source, user as target, COUNT(*) as weight
        FROM events
        WHERE source_host != '' AND source_host IS NOT NULL
          AND user != '' AND user IS NOT NULL {pid_cond}
        GROUP BY source_host, user ORDER BY weight DESC LIMIT 100
    """, pid_param)

    host_tools = qp(project_id, f"""
        SELECT source_host as source, tool as target, COUNT(*) as weight
        FROM events
        WHERE source_host != '' AND source_host IS NOT NULL
          AND tool != '' AND tool IS NOT NULL {pid_cond}
        GROUP BY source_host, tool ORDER BY weight DESC LIMIT 100
    """, pid_param)

    user_tools = qp(project_id, f"""
        SELECT user as source, tool as target, COUNT(*) as weight
        FROM events
        WHERE user != '' AND user IS NOT NULL
          AND tool != '' AND tool IS NOT NULL {pid_cond}
        GROUP BY user, tool ORDER BY weight DESC LIMIT 100
    """, pid_param)

    ip_hosts = qp(project_id, f"""
        SELECT src_ip as source, source_host as target, COUNT(*) as weight
        FROM events
        WHERE src_ip != '' AND src_ip IS NOT NULL
          AND src_ip != '0.0.0.0'
          AND source_host != '' AND source_host IS NOT NULL {pid_cond}
        GROUP BY src_ip, source_host ORDER BY weight DESC LIMIT 100
    """, pid_param)

    return {
        "host_user": host_users,
        "host_tool": host_tools,
        "user_tool": user_tools,
        "ip_host": ip_hosts,
    }


# ---------------------------------------------------------------------------
# Videos / Media
# ---------------------------------------------------------------------------

@app.get("/api/media")
async def get_media(participant_id: Optional[str] = None, project_id: str = ""):
    """All video and terminal recording references."""
    conds: list = []
    params: list = []
    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)
    if project_id:
        conds.append("project_id = ?")
        params.append(project_id)

    where = " AND ".join(conds) if conds else "1=1"
    rows = q(f"""
        SELECT media_id, participant_id, source_host,
               media_type, start_timestamp, duration_seconds, panel
        FROM media_registry
        WHERE {where}
        ORDER BY participant_id, start_timestamp
    """, tuple(params))
    return {"media": rows}


# ---------------------------------------------------------------------------
# Stats / Overview
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def get_stats(project_id: str = ""):
    def _scalar(sql: str, key: str = "n", default=0):
        r = qp(project_id, sql)
        return r[0][key] if r else default

    total = _scalar("SELECT COUNT(*) n FROM events")
    by_participant = qp(project_id, "SELECT participant_id, COUNT(*) n FROM events GROUP BY participant_id ORDER BY n DESC")
    by_phase = qp(project_id, "SELECT attack_phase, COUNT(*) n FROM events GROUP BY attack_phase ORDER BY n DESC")
    by_source = qp(project_id, "SELECT source_type, COUNT(*) n FROM events GROUP BY source_type ORDER BY n DESC")
    by_category = qp(project_id, "SELECT action_category, COUNT(*) n FROM events GROUP BY action_category ORDER BY n DESC")
    commands = _scalar("SELECT COUNT(*) n FROM events WHERE command != '' AND command IS NOT NULL")
    typed = _scalar("SELECT COUNT(*) n FROM events WHERE typed_text != '' AND typed_text IS NOT NULL")
    alerts = _scalar("SELECT COUNT(*) n FROM events WHERE alert_type != '' AND alert_type IS NOT NULL")
    tr_rows = qp(project_id, "SELECT MIN(timestamp_utc) t0, MAX(timestamp_utc) t1 FROM events WHERE timestamp_utc != '' AND timestamp_utc IS NOT NULL")
    time_range = tr_rows[0] if tr_rows else {"t0": None, "t1": None}

    return {
        "total_events": total,
        "with_commands": commands,
        "with_typed_text": typed,
        "with_alerts": alerts,
        "time_range": time_range,
        "by_participant": by_participant,
        "by_phase": by_phase,
        "by_source_type": by_source,
        "by_action_category": by_category,
    }


@app.get("/api/analysis/overview")
async def analysis_overview(project_id: str = ""):
    """Backward-compat overview endpoint."""
    return await get_stats(project_id=project_id)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@app.get("/api/search")
async def search(
    q_str: str = Query(..., alias="q"),
    participant_id: Optional[str] = None,
    limit: int = 100,
    project_id: str = "",
):
    conds = [
        "(command LIKE ? OR action_name LIKE ? OR tool LIKE ? OR user LIKE ? OR raw_data LIKE ?)"
    ]
    like = f"%{q_str}%"
    params: list = [like, like, like, like, like]

    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    where = " AND ".join(conds)
    limit = min(limit, 10000)
    rows = qp(project_id, f"""
        SELECT timestamp_utc, participant_id, source_host, user,
               action_name, tool, command, attack_phase, alert_type
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc DESC
        LIMIT ?
    """, tuple(params + [limit]))
    return {"results": rows, "total": len(rows)}


# ---------------------------------------------------------------------------
# Single event
# ---------------------------------------------------------------------------

@app.get("/api/events/stream")
async def events_stream(
    participant_id: str,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    source_type: Optional[str] = None,
    limit: int = 500,
    project_id: str = "",
):
    """Windowed event query for Palantir UI. Registered before {event_id} to avoid route conflict."""
    conds = ["participant_id = ?", "timestamp_utc != ''", "timestamp_utc IS NOT NULL"]
    params: list = [participant_id]
    if source_type:
        types = [t.strip() for t in source_type.split(",") if t.strip()]
        placeholders = ",".join(["?"] * len(types))
        conds.append(f"source_type IN ({placeholders})")
        params.extend(types)
    if from_ts:
        conds.append("timestamp_utc >= ?")
        params.append(from_ts)
    if to_ts:
        conds.append("timestamp_utc <= ?")
        params.append(to_ts)
    where = " AND ".join(conds)
    rows = qp(
        project_id,
        f"""SELECT timestamp_utc, source_type, action_name, command, typed_text,
                   user, source_host, attack_phase, src_ip, dest_ip, dest_port,
                   protocol, alert_type, alert_severity, url, http_method,
                   http_status, tool, working_dir, mitre_tactic, mitre_technique,
                   raw_data
            FROM events
            WHERE {where}
            ORDER BY timestamp_utc
            LIMIT ?""",
        tuple(params + [limit]),
    )
    return {"events": rows, "count": len(rows)}


@app.get("/api/events/{event_id}")
async def get_event(event_id: str, project_id: str = ""):
    rows = qp(project_id, "SELECT * FROM events WHERE event_id = ?", (event_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Event not found")
    return rows[0]


# ---------------------------------------------------------------------------
# Network activity
# ---------------------------------------------------------------------------

@app.get("/api/network")
async def get_network(participant_id: Optional[str] = None, project_id: str = ""):
    pid_cond = "AND participant_id = ?" if participant_id else ""
    pid_param = (participant_id,) if participant_id else ()

    src_ips = qp(project_id, f"""
        SELECT src_ip, COUNT(*) n FROM events
        WHERE src_ip != '' AND src_ip IS NOT NULL AND src_ip != '0.0.0.0' {pid_cond}
        GROUP BY src_ip ORDER BY n DESC LIMIT 30
    """, pid_param)
    dest_ips = qp(project_id, f"""
        SELECT dest_ip, COUNT(*) n FROM events
        WHERE dest_ip != '' AND dest_ip IS NOT NULL AND dest_ip != '0.0.0.0' {pid_cond}
        GROUP BY dest_ip ORDER BY n DESC LIMIT 30
    """, pid_param)
    protocols = qp(project_id, f"""
        SELECT protocol, COUNT(*) n FROM events
        WHERE protocol != '' AND protocol IS NOT NULL {pid_cond}
        GROUP BY protocol ORDER BY n DESC
    """, pid_param)
    top_connections = qp(project_id, f"""
        SELECT src_ip, dest_ip, protocol, COUNT(*) n FROM events
        WHERE src_ip != '' AND src_ip IS NOT NULL
          AND dest_ip != '' AND dest_ip IS NOT NULL
          AND src_ip != '0.0.0.0' AND dest_ip != '0.0.0.0' {pid_cond}
        GROUP BY src_ip, dest_ip, protocol
        ORDER BY n DESC LIMIT 50
    """, pid_param)

    return {
        "source_ips": src_ips,
        "destination_ips": dest_ips,
        "protocols": protocols,
        "top_connections": top_connections,
    }


# ---------------------------------------------------------------------------
# Bias / behavior analysis
# ---------------------------------------------------------------------------

@app.get("/api/behavior/{participant_id}")
async def get_behavior(participant_id: str, project_id: str = ""):
    """Behavioral heatmap data for a participant."""

    hourly = qp(project_id, """
        SELECT CAST(SUBSTR(timestamp_utc, 12, 2) AS INTEGER) as hour,
               attack_phase, COUNT(*) n
        FROM events
        WHERE participant_id = ?
          AND timestamp_utc IS NOT NULL AND timestamp_utc != ''
        GROUP BY hour, attack_phase
        ORDER BY hour
    """, (participant_id,))

    tool_usage = qp(project_id, """
        SELECT tool, attack_phase, COUNT(*) n
        FROM events
        WHERE participant_id = ? AND tool != '' AND tool IS NOT NULL
        GROUP BY tool, attack_phase
        ORDER BY n DESC LIMIT 30
    """, (participant_id,))

    phase_sequence = qp(project_id, """
        SELECT timestamp_utc, attack_phase, action_category
        FROM events
        WHERE participant_id = ?
          AND timestamp_utc IS NOT NULL AND timestamp_utc != ''
          AND attack_phase != 'unknown' AND attack_phase IS NOT NULL
        ORDER BY timestamp_utc ASC
        LIMIT 1000
    """, (participant_id,))

    user_activity = qp(project_id, """
        SELECT user, action_category, COUNT(*) n
        FROM events
        WHERE participant_id = ? AND user != '' AND user IS NOT NULL
        GROUP BY user, action_category
        ORDER BY n DESC LIMIT 50
    """, (participant_id,))

    return {
        "participant_id": participant_id,
        "hourly_by_phase": hourly,
        "tool_usage": tool_usage,
        "phase_sequence": phase_sequence,
        "user_activity": user_activity,
    }


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    project_type: str          # "dataset" or "filter"
    data_path: str = ""        # for dataset type
    filter_json: dict = {}     # for filter type
    attacker_ips: str = ""     # comma-separated IPs for sensor_packet classification


def _project_db_path(project_id: str) -> Path:
    return DB_PATH.parent / f"project_{project_id}.db"


def _normalize_path_input(raw: str) -> str:
    r"""Translate Windows/WSL-style paths to POSIX paths the server can resolve.

    Handles:
      - \\wsl.localhost\<distro>\path  -> /path  (server already runs inside WSL)
      - \\wsl$\<distro>\path           -> /path
      - C:\path\to\thing               -> /mnt/c/path/to/thing
      - mixed backslashes              -> forward slashes
    """
    if not raw:
        return raw
    import re as _re
    s = raw.strip().strip('"').strip("'")
    m = _re.match(r'^\\\\wsl(?:\.localhost|\$)\\[^\\/]+[\\/](.*)$', s, _re.IGNORECASE)
    if m:
        s = '/' + m.group(1).replace('\\', '/')
    elif _re.match(r'^[A-Za-z]:[\\/]', s):
        drive = s[0].lower()
        rest = s[3:].replace('\\', '/')
        s = f'/mnt/{drive}/{rest}'
    else:
        s = s.replace('\\', '/')
    if s.startswith('~'):
        s = str(Path(s).expanduser())
    return s


def _is_archive_path(p: Path) -> bool:
    n = p.name.lower()
    return n.endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2'))


def _extract_archive(src: Path, dest: Path) -> Path:
    """Extract zip/tar into dest. If the archive has a single top-level dir, return it."""
    import zipfile as _zf, tarfile as _tf
    dest.mkdir(parents=True, exist_ok=True)
    name = src.name.lower()
    if name.endswith('.zip'):
        with _zf.ZipFile(src) as zf:
            zf.extractall(str(dest))
    else:
        with _tf.open(src) as tf:
            tf.extractall(str(dest))
    entries = [e for e in dest.iterdir() if not e.name.startswith('.')]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def _allowed_data_roots() -> list:
    """List of paths under which a user-supplied data_path is accepted."""
    roots = []
    env = _os.environ.get('SANN_ALLOWED_DATA_ROOTS', '')
    if env:
        for r in env.split(','):
            r = r.strip()
            if r:
                try: roots.append(Path(r).resolve())
                except Exception: pass
    try: roots.append(MEDIA_ROOT.parent.resolve())
    except Exception: pass
    home = _os.environ.get('HOME', '')
    if home:
        try: roots.append(Path(home).resolve())
        except Exception: pass
    for extra in ('/mnt', '/tmp'):
        try: roots.append(Path(extra).resolve())
        except Exception: pass
    try: roots.append((DB_PATH.parent / 'uploads').resolve())
    except Exception: pass
    seen, dedup = set(), []
    for r in roots:
        s = str(r)
        if s not in seen:
            seen.add(s)
            dedup.append(r)
    return dedup


def _path_under_any(p: Path, roots) -> bool:
    sp = str(p)
    for r in roots:
        sr = str(r)
        if sp == sr or sp.startswith(sr + '/'):
            return True
    return False


def _build_project_query(filter_json: dict):
    """Return (where_clause, params) for a filter-type project."""
    clauses = []
    params = []
    pids = filter_json.get("participant_ids", [])
    if pids:
        placeholders = ",".join("?" * len(pids))
        clauses.append(f"participant_id IN ({placeholders})")
        params.extend(pids)
    phases = filter_json.get("phases", [])
    if phases:
        placeholders = ",".join("?" * len(phases))
        clauses.append(f"attack_phase IN ({placeholders})")
        params.extend(phases)
    date_from = filter_json.get("date_from", "")
    if date_from:
        clauses.append("timestamp_utc >= ?")
        params.append(date_from)
    date_to = filter_json.get("date_to", "")
    if date_to:
        clauses.append("timestamp_utc <= ?")
        params.append(date_to)
    source_types = filter_json.get("source_types", [])
    if source_types:
        placeholders = ",".join("?" * len(source_types))
        clauses.append(f"source_type IN ({placeholders})")
        params.extend(source_types)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _count_project_events(project_id: str, project_type: str, filter_json: dict, db_path_override: str = "") -> int:
    if project_type == "dataset":
        p = Path(db_path_override) if db_path_override else _project_db_path(project_id)
        if not p.exists():
            return 0
        try:
            con = sqlite3.connect(str(p))
            row = con.execute("SELECT COUNT(*) FROM events").fetchone()
            con.close()
            return row[0] if row else 0
        except Exception:
            return 0
    else:
        where, params = _build_project_query(filter_json)
        row = q(f"SELECT COUNT(*) n FROM events {where}", params)
        return row[0]["n"] if row else 0


@app.post("/api/projects/upload", status_code=201)
async def upload_project(
    name: str = Form(...),
    attacker_ips: str = Form(""),
    file: UploadFile = File(...),
):
    """Create a dataset project from an uploaded archive (.zip/.tar/.tar.gz) and trigger ingest."""
    import tempfile, subprocess

    fname = (file.filename or "").lower()
    if not fname.endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')):
        raise HTTPException(400, "Only .zip, .tar, .tar.gz, .tgz, or .tar.bz2 archives are accepted")

    upload_base = DB_PATH.parent / "uploads"
    upload_base.mkdir(exist_ok=True)

    project_id = str(uuid.uuid4())[:8]
    dest = upload_base / f"dataset_{project_id}"

    # Save archive to a temp file matching its extension, then extract via shared helper
    suffix = '.zip' if fname.endswith('.zip') else (
        '.tar.gz' if fname.endswith(('.tar.gz', '.tgz')) else (
        '.tar.bz2' if fname.endswith(('.tar.bz2', '.tbz2')) else '.tar'))
    content = await file.read()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    try:
        _os.write(tmp_fd, content)
        _os.close(tmp_fd)
        try:
            dest = _extract_archive(Path(tmp_path), dest)
        except Exception as e:
            shutil.rmtree(str(dest), ignore_errors=True)
            raise HTTPException(400, f"Invalid or corrupt archive: {e}")
    finally:
        try: _os.unlink(tmp_path)
        except Exception as e: _logger.warning("upload_project temp cleanup failed: %s", e)

    now = datetime.now(timezone.utc).isoformat()
    db_path_str = str(_project_db_path(project_id))

    con = sqlite3.connect(str(DB_PATH))
    con.execute(
        """INSERT INTO projects
           (project_id, name, description, project_type, data_path, filter_json,
            db_path, attacker_ips, created_at, updated_at, event_count, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,0,'ingesting')""",
        (project_id, name, "", "dataset", str(dest), "{}", db_path_str, attacker_ips, now, now),
    )
    con.commit()
    con.close()

    ingest_script = str(Path(__file__).parent.parent / "ingest_v2.py")
    cmd = [sys.executable, ingest_script, "--data-dir", str(dest), "--db", db_path_str,
           "--project-id", project_id, "--main-db", str(DB_PATH)]
    if attacker_ips:
        cmd += ["--attacker-ips", attacker_ips]

    pipeline_script = str(Path(__file__).parent.parent / "import_manager.py")
    pipeline_cmd = [sys.executable, pipeline_script,
                    "--data-root", str(dest), "--db", db_path_str,
                    "--project-id", project_id, "--main-db", str(DB_PATH)]
    if attacker_ips:
        pipeline_cmd += ["--attacker-ips", attacker_ips]

    def _pipeline_then_sync():
        try:
            subprocess.run(pipeline_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            _logger.warning(f"Pipeline subprocess failed for {project_id}: {exc}")
            return
        try:
            sync_media_for_project(project_id)
        except Exception as exc:
            _logger.warning(f"Post-pipeline media sync failed for {project_id}: {exc}")

    threading.Thread(target=_pipeline_then_sync, daemon=True).start()

    return {"project_id": project_id, "name": name, "status": "ingesting"}


@app.get("/api/projects/{project_id}/status")
def project_status(project_id: str):
    """Poll project status and current event count."""
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try: fj = json.loads(row["filter_json"] or "{}")
    except Exception: pass
    cnt = _count_project_events(row["project_id"], row["project_type"], fj, row["db_path"])
    # Auto-mark ready once ingest finishes (process gone and DB has events)
    status = row["status"]
    if status == "ingesting" and cnt > 0:
        try:
            ucon = sqlite3.connect(str(DB_PATH))
            ucon.execute("UPDATE projects SET status='ready', event_count=?, updated_at=? WHERE project_id=?",
                         (cnt, datetime.now(timezone.utc).isoformat(), project_id))
            ucon.commit()
            ucon.close()
            status = "ready"
        except Exception:
            pass
    return {"project_id": project_id, "status": status, "event_count": cnt, "data_path": row["data_path"]}


@app.get("/api/projects")
def list_projects():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
    except sqlite3.OperationalError:
        con.close()
        return []
    con.close()
    result = []
    for r in rows:
        fj = {}
        try:
            fj = json.loads(r["filter_json"] or "{}")
        except Exception:
            pass
        cnt = _count_project_events(r["project_id"], r["project_type"], fj, r["db_path"])
        result.append({
            "project_id": r["project_id"],
            "name": r["name"],
            "description": r["description"],
            "project_type": r["project_type"],
            "data_path": r["data_path"],
            "filter_json": fj,
            "db_path": r["db_path"],
            "attacker_ips": r["attacker_ips"] or "",
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "event_count": cnt,
            "status": r["status"],
        })
    return result


@app.post("/api/projects", status_code=201)
def create_project(body: ProjectCreate):
    if body.project_type not in ("dataset", "filter"):
        raise HTTPException(400, "project_type must be 'dataset' or 'filter'")
    if body.project_type == "dataset" and not body.data_path:
        raise HTTPException(400, "data_path required for dataset projects")
    if body.attacker_ips:
        import re as _re
        for ip in body.attacker_ips.split(","):
            ip = ip.strip()
            if ip and not _re.match(r'^[\d.:a-fA-F/]+$', ip):
                raise HTTPException(400, f"Invalid IP: {ip}")

    pid = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).isoformat()
    data_path_final = body.data_path
    archive_to_extract = None  # set when data_path is an archive — extracted in background

    if body.project_type == "dataset" and body.data_path:
        try:
            normalized = _normalize_path_input(body.data_path)
            resolved = Path(normalized).resolve()
            if not resolved.exists():
                raise HTTPException(400, f"data_path does not exist: {resolved}")
            allowed_roots = _allowed_data_roots()
            if not _path_under_any(resolved, allowed_roots):
                roots_str = ", ".join(str(r) for r in allowed_roots)
                raise HTTPException(
                    400,
                    f"data_path must be under one of: {roots_str}. "
                    f"Set SANN_ALLOWED_DATA_ROOTS in .env to extend this list."
                )
            if resolved.is_file():
                if not _is_archive_path(resolved):
                    raise HTTPException(
                        400,
                        f"data_path must be a directory or a .zip/.tar/.tar.gz archive: {resolved.name}"
                    )
                # Don't extract in the request — large archives (GBs) can take minutes
                # and would block the response. Defer to a background thread.
                archive_to_extract = resolved
                data_path_final = str((DB_PATH.parent / "uploads" / f"dataset_{pid}").resolve())
            elif not resolved.is_dir():
                raise HTTPException(400, f"data_path is neither a directory nor a file: {resolved}")
            else:
                data_path_final = str(resolved)
        except HTTPException:
            raise
        except Exception as e:
            _logger.warning("create_project data_path validation failed: %s", e)
            raise HTTPException(400, f"Invalid data_path: {e}")

    db_path_str = ""
    if body.project_type == "dataset":
        db_path_str = str(_project_db_path(pid))

    initial_status = "extracting" if archive_to_extract else "ready"
    con = sqlite3.connect(str(DB_PATH))
    con.execute(
        """INSERT INTO projects
           (project_id, name, description, project_type, data_path, filter_json, db_path, attacker_ips, created_at, updated_at, event_count, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,0,?)""",
        (pid, body.name, body.description, body.project_type,
         data_path_final, json.dumps(body.filter_json), db_path_str, body.attacker_ips, now, now,
         initial_status),
    )
    con.commit()
    con.close()

    if archive_to_extract is not None:
        dest_dir = Path(data_path_final)
        src_archive = archive_to_extract

        def _extract_in_background():
            try:
                extracted = _extract_archive(src_archive, dest_dir)
                ucon = sqlite3.connect(str(DB_PATH))
                ucon.execute(
                    "UPDATE projects SET data_path=?, status='ready', updated_at=? WHERE project_id=?",
                    (str(extracted), datetime.now(timezone.utc).isoformat(), pid),
                )
                ucon.commit()
                ucon.close()
                _logger.info("project %s: archive extracted to %s", pid, extracted)
            except Exception as exc:
                _logger.warning("project %s: archive extraction failed: %s", pid, exc)
                shutil.rmtree(str(dest_dir), ignore_errors=True)
                try:
                    ecn = sqlite3.connect(str(DB_PATH))
                    ecn.execute(
                        "UPDATE projects SET status='error', updated_at=? WHERE project_id=?",
                        (datetime.now(timezone.utc).isoformat(), pid),
                    )
                    ecn.commit()
                    ecn.close()
                except Exception as upd_exc:
                    _logger.warning("project %s: could not mark status=error: %s", pid, upd_exc)

        threading.Thread(target=_extract_in_background, daemon=True).start()

    return {"project_id": pid, "status": initial_status}


@app.get("/api/projects/{project_id}")
def get_project(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try:
        fj = json.loads(row["filter_json"] or "{}")
    except Exception:
        pass
    cnt = _count_project_events(row["project_id"], row["project_type"], fj, row["db_path"])
    return {
        "project_id": row["project_id"],
        "name": row["name"],
        "description": row["description"],
        "project_type": row["project_type"],
        "data_path": row["data_path"],
        "filter_json": fj,
        "db_path": row["db_path"],
        "attacker_ips": row["attacker_ips"] or "",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "event_count": cnt,
        "status": row["status"],
    }


@app.delete("/api/projects/{project_id}", status_code=204)
def delete_project(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(404, "Project not found")
    db_path_str = row["db_path"]
    con.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
    con.execute("DELETE FROM events WHERE project_id=?", (project_id,))
    con.execute("DELETE FROM media_registry WHERE project_id=?", (project_id,))
    con.commit()
    con.close()
    if db_path_str:
        p = Path(db_path_str).resolve()
        allowed_dir = DB_PATH.parent.resolve()
        if p.exists() and str(p).startswith(str(allowed_dir)):
            p.unlink()


def _events_for_project(project_id: str, project_type: str, filter_json: dict, db_path_override: str = ""):
    """Return list-of-dicts of all events for a project."""
    if project_type == "dataset":
        p = Path(db_path_override) if db_path_override else _project_db_path(project_id)
        if not p.exists():
            return []
        con = sqlite3.connect(str(p))
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT * FROM events ORDER BY timestamp_utc").fetchall()
        con.close()
        return [dict(r) for r in rows]
    else:
        where, params = _build_project_query(filter_json)
        return q(f"SELECT * FROM events {where} ORDER BY timestamp_utc", params)


def _tree_from_events(events: list) -> list:
    """Build nested tree: participant > scenario > host > source_file."""
    tree: dict = {}
    for ev in events:
        pid = ev.get("participant_id") or "unknown"
        scen = ev.get("scenario_name") or "unknown"
        host = ev.get("source_host") or "unknown"
        sf = ev.get("source_file") or "unknown"
        tree.setdefault(pid, {})
        tree[pid].setdefault(scen, {})
        tree[pid][scen].setdefault(host, {})
        tree[pid][scen][host].setdefault(sf, 0)
        tree[pid][scen][host][sf] += 1

    result = []
    for pid, scenarios in tree.items():
        p_total = 0
        scen_nodes = []
        for scen, hosts in scenarios.items():
            scen_total = 0
            host_nodes = []
            for host, files in hosts.items():
                host_total = 0
                file_nodes = []
                for sf, cnt in sorted(files.items()):
                    file_nodes.append({"name": sf, "event_count": cnt})
                    host_total += cnt
                host_nodes.append({"name": host, "event_count": host_total, "files": file_nodes})
                scen_total += host_total
            scen_nodes.append({"name": scen, "event_count": scen_total, "hosts": host_nodes})
            p_total += scen_total
        result.append({"participant_id": pid, "event_count": p_total, "scenarios": scen_nodes})
    return result


@app.get("/api/projects/{project_id}/tree")
def project_tree(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try:
        fj = json.loads(row["filter_json"] or "{}")
    except Exception:
        pass
    events = _events_for_project(row["project_id"], row["project_type"], fj, row["db_path"])
    return {"project_id": project_id, "tree": _tree_from_events(events)}


@app.get("/api/tree")
def active_tree():
    """Data tree for the active sann.db."""
    events = q("SELECT participant_id, scenario_name, source_host, source_file FROM events ORDER BY timestamp_utc", [])
    return {"tree": _tree_from_events(events)}


@app.get("/api/projects/{project_id}/export/csv")
def export_csv(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try:
        fj = json.loads(row["filter_json"] or "{}")
    except Exception:
        pass
    events = _events_for_project(row["project_id"], row["project_type"], fj, row["db_path"])

    if not events:
        return StreamingResponse(iter([""]), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{project_id}.csv"'})

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(events[0].keys()))
    writer.writeheader()
    writer.writerows(events)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{project_id}.csv"'},
    )


@app.get("/api/projects/{project_id}/export/json")
def export_json(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try:
        fj = json.loads(row["filter_json"] or "{}")
    except Exception:
        pass
    events = _events_for_project(row["project_id"], row["project_type"], fj, row["db_path"])
    content = json.dumps(events, default=str)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{project_id}.json"'},
    )


@app.get("/api/projects/{project_id}/export/sqlite")
def export_sqlite(project_id: str):
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    fj = {}
    try:
        fj = json.loads(row["filter_json"] or "{}")
    except Exception:
        pass

    if row["project_type"] == "dataset":
        p = Path(row["db_path"]) if row["db_path"] else _project_db_path(project_id)
        if not p.exists():
            raise HTTPException(404, "Dataset DB not found — run ingest first")
        return FileResponse(str(p), media_type="application/octet-stream",
                            filename=f"{project_id}.sqlite")
    else:
        # Build a temp SQLite with just the filtered events
        import tempfile as _tempfile
        tmp_fd, tmp_path_str = _tempfile.mkstemp(suffix=".db", prefix=f"sann_export_{project_id}_")
        _os.close(tmp_fd)
        tmp_path = Path(tmp_path_str)
        src_con = sqlite3.connect(str(DB_PATH))
        dst_con = sqlite3.connect(str(tmp_path))
        # Copy schema
        schema = src_con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()
        if schema:
            dst_con.execute(schema[0])
        where, params = _build_project_query(fj)
        rows = src_con.execute(f"SELECT * FROM events {where}", params).fetchall()
        if rows:
            cols = len(rows[0])
            placeholders = ",".join(["?"] * cols)
            dst_con.executemany(f"INSERT INTO events VALUES ({placeholders})", rows)
        dst_con.commit()
        src_con.close()
        dst_con.close()
        return FileResponse(str(tmp_path), media_type="application/octet-stream",
                            filename=f"{project_id}.sqlite")


@app.post("/api/projects/{project_id}/ingest")
def ingest_project(project_id: str):
    """Trigger re-ingestion for a dataset-type project (async via subprocess)."""
    import subprocess
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    if not row:
        con.close()
        raise HTTPException(404, "Project not found")
    if row["project_type"] != "dataset":
        con.close()
        raise HTTPException(400, "Only dataset projects can be ingested")
    data_path = row["data_path"]
    db_path_str = row["db_path"] or str(_project_db_path(project_id))
    attacker_ips = row["attacker_ips"] or ""
    con.execute("UPDATE projects SET status='ingesting', updated_at=? WHERE project_id=?",
                (datetime.now(timezone.utc).isoformat(), project_id))
    con.commit()
    con.close()

    ingest_script = str(Path(__file__).parent.parent / "ingest_v2.py")
    cmd = [sys.executable, ingest_script, "--data-dir", data_path, "--db", db_path_str,
           "--project-id", project_id, "--main-db", str(DB_PATH)]
    if attacker_ips:
        cmd += ["--attacker-ips", attacker_ips]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"status": "ingesting", "project_id": project_id, "db_path": db_path_str}


@app.post("/api/projects/{project_id}/sync_media")
def sync_media_for_project(project_id: str):
    """Discover media files for a project and update the main media_registry."""
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
    con.close()
    if not row:
        raise HTTPException(404, "Project not found")
    if row["project_type"] != "dataset":
        raise HTTPException(400, "Only dataset projects have media")

    data_path = Path(row["data_path"])
    db_path_str = row["db_path"] or ""
    if not db_path_str or not Path(db_path_str).exists():
        raise HTTPException(400, "Project DB not found — run ingest first")

    # Get participants from the project's DB
    pcon = sqlite3.connect(db_path_str)
    pcon.row_factory = sqlite3.Row
    participants = pcon.execute(
        "SELECT DISTINCT participant_id, scenario_name FROM events "
        "WHERE participant_id != '' ORDER BY participant_id"
    ).fetchall()
    pcon.close()

    participants_list = [(r["participant_id"], r["scenario_name"]) for r in participants]
    rows = _discover_media(data_path, participants_list)
    _write_media_rows(rows, project_id=project_id)
    return {"discovered": len(rows), "participants": [p[0] for p in participants_list]}


# ---------------------------------------------------------------------------
# Timeline Sync API
# ---------------------------------------------------------------------------

@app.get("/api/timeline/sync")
async def timeline_sync(
    participant_id: Optional[str] = None,
    scenario: Optional[str] = None,
    project_id: str = "",
):
    """Get timeline sync data with all media items and markers"""
    conds = []
    params = []

    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)
    if scenario:
        conds.append("scenario_name = ?")
        params.append(scenario)
    if project_id:
        conds.append("project_id = ?")
        params.append(project_id)

    where = " AND ".join(conds) if conds else "1=1"

    # Get media items (media_registry lives in main DB — always use q())
    media_rows = q(f"""
        SELECT media_id, media_type, source_host,
               start_timestamp, start_unix, end_timestamp, end_unix,
               duration_seconds, panel
        FROM media_registry
        WHERE {where}
        ORDER BY start_unix
    """, tuple(params))
    
    if not media_rows:
        return {"media_items": [], "sync_markers": []}
    
    # Calculate time range — parse start_timestamp (ISO UTC) rather than
    # trusting start_unix which is a broken relative offset in old data.
    def _iso_to_epoch(iso: str) -> float:
        return datetime.fromisoformat(iso + 'Z').timestamp() if iso and not iso.endswith('Z') else datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()

    valid_starts = [_iso_to_epoch(m['start_timestamp']) for m in media_rows if m.get('start_timestamp')]
    valid_ends   = [_iso_to_epoch(m['end_timestamp'])   for m in media_rows if m.get('end_timestamp')]
    start_unix = min(valid_starts) if valid_starts else None
    end_unix   = max(valid_ends)   if valid_ends   else None
    duration = end_unix - start_unix if start_unix is not None and end_unix is not None else 0
    
    # Get event markers for timeline
    event_markers = qp(project_id, """
        SELECT timestamp_utc, attack_phase, action_name, command, source_type
        FROM events
        WHERE timestamp_utc IS NOT NULL AND timestamp_utc != ''
        AND participant_id = ?
        ORDER BY timestamp_utc
        LIMIT 500
    """, (participant_id,) if participant_id else ())
    
    # Convert to sync markers
    markers = []
    for ev in event_markers:
        try:
            ts = datetime.fromisoformat(ev['timestamp_utc'].replace('Z', '+00:00'))
            ts_unix = ts.timestamp()
            offset = ts_unix - start_unix if start_unix else 0
            
            markers.append({
                'timestamp': ev['timestamp_utc'],
                'offset_seconds': offset,
                'phase': ev['attack_phase'],
                'action': ev['action_name'],
                'command': ev.get('command', '')[:50],
                'type': ev['source_type']
            })
        except Exception:
            pass

    return {
        "participant_id": participant_id,
        "scenario": scenario,
        "time_range": {
            "start_unix": start_unix,
            "end_unix": end_unix,
            "start_timestamp": media_rows[0]['start_timestamp'] if media_rows else '',
            "end_timestamp": media_rows[-1]['end_timestamp'] if media_rows else '',
            "duration_seconds": duration
        },
        "media_items": media_rows,
        "sync_markers": markers[:200]
    }


@app.get("/api/timeline/cast/{media_id}")
async def timeline_cast(
    media_id: str,
    start_offset: Optional[float] = 0,
    end_offset: Optional[float] = None
):
    """Get terminal commands from cast file within time range"""
    row = q("SELECT * FROM media_registry WHERE media_id = ?", (media_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Media not found")
    
    media = row[0]
    
    # Get media start epoch from start_timestamp (start_unix is unreliable)
    media_start_ts = media.get('start_timestamp')
    media_start_epoch = None
    if media_start_ts:
        iso = media_start_ts if media_start_ts.endswith('Z') else media_start_ts + 'Z'
        media_start_epoch = datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()

    # Get commands in range — filter by timestamp_utc since offset_seconds does not exist
    conds = ["source_type = 'terminal_recording'", "source_file = ?"]
    params = [media['source_file']]

    if media_start_epoch is not None:
        if start_offset is not None:
            conds.append("timestamp_utc >= ?")
            params.append(datetime.fromtimestamp(media_start_epoch + start_offset, tz=timezone.utc).replace(tzinfo=None).isoformat())
        if end_offset is not None:
            conds.append("timestamp_utc <= ?")
            params.append(datetime.fromtimestamp(media_start_epoch + end_offset, tz=timezone.utc).replace(tzinfo=None).isoformat())

    where = " AND ".join(conds)
    commands = q(f"""
        SELECT timestamp_utc, command
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc
    """, tuple(params))

    return {
        "media_id": media_id,
        "start_offset": start_offset,
        "commands": commands
    }


@app.get("/api/timeline/uat/{media_id}")
async def timeline_uat(
    media_id: str,
    start_offset: Optional[float] = 0,
    end_offset: Optional[float] = None
):
    """Get keystrokes from UAT file within time range"""
    row = q("SELECT * FROM media_registry WHERE media_id = ?", (media_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Media not found")
    
    media = row[0]
    
    # Get media start epoch from start_timestamp (start_unix is unreliable)
    media_start_ts = media.get('start_timestamp')
    media_start_epoch = None
    if media_start_ts:
        iso = media_start_ts if media_start_ts.endswith('Z') else media_start_ts + 'Z'
        media_start_epoch = datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()

    # Get typed text in range — filter by timestamp_utc since offset_seconds does not exist
    conds = ["source_type = 'uat'", "source_file = ?"]
    params = [media['source_file']]

    if media_start_epoch is not None:
        if start_offset is not None:
            conds.append("timestamp_utc >= ?")
            params.append(datetime.fromtimestamp(media_start_epoch + start_offset, tz=timezone.utc).replace(tzinfo=None).isoformat())
        if end_offset is not None:
            conds.append("timestamp_utc <= ?")
            params.append(datetime.fromtimestamp(media_start_epoch + end_offset, tz=timezone.utc).replace(tzinfo=None).isoformat())

    where = " AND ".join(conds)
    keystrokes = q(f"""
        SELECT timestamp_utc, typed_text, tool, raw_data
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc
    """, tuple(params))

    return {
        "media_id": media_id,
        "start_offset": start_offset,
        "keystrokes": keystrokes
    }


@app.get("/api/timeline/pcap/{media_id}")
async def timeline_pcap(
    media_id: str,
    start_offset: Optional[float] = 0,
    end_offset: Optional[float] = None
):
    """Get network packets from PCAP within time range"""
    row = q("SELECT * FROM media_registry WHERE media_id = ?", (media_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Media not found")
    
    media = row[0]
    
    # Get network events in range — derive base epoch from start_timestamp (ISO UTC)
    # because start_unix is a broken relative offset in old data.
    conds = ["source_type IN ('zeek', 'suricata')", "participant_id = ?"]
    params = [media['participant_id']]

    media_start_ts = media.get('start_timestamp')
    if media_start_ts:
        iso = media_start_ts if media_start_ts.endswith('Z') else media_start_ts + 'Z'
        base_ts = datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()
        if start_offset is not None:
            ts_start = base_ts + start_offset
            conds.append("timestamp_utc >= ?")
            params.append(datetime.fromtimestamp(ts_start, tz=timezone.utc).replace(tzinfo=None).isoformat())
        if end_offset is not None:
            ts_end = base_ts + end_offset
            conds.append("timestamp_utc <= ?")
            params.append(datetime.fromtimestamp(ts_end, tz=timezone.utc).replace(tzinfo=None).isoformat())

    where = " AND ".join(conds)
    packets = q(f"""
        SELECT timestamp_utc, src_ip, dest_ip, protocol, dest_port, action_name
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc
        LIMIT 100
    """, tuple(params))

    return {
        "media_id": media_id,
        "start_offset": start_offset,
        "packets": packets
    }


@app.get("/api/timeline/events")
async def timeline_events(
    participant_id: Optional[str] = None,
    start_offset: Optional[float] = None,
    end_offset: Optional[float] = None,
    source_type: Optional[str] = None,
    limit: int = 1000,
    project_id: str = "",
):
    """Get events within time range with offset_seconds"""
    conds = []
    params = []

    if participant_id:
        conds.append("participant_id = ?")
        params.append(participant_id)

    if source_type:
        conds.append("source_type = ?")
        params.append(source_type)

    where = " AND ".join(conds) if conds else "1=1"
    limit = min(limit, 10000)

    # Get all events for participant first, then filter by offset
    rows = qp(project_id, f"""
        SELECT timestamp_utc, source_type, action_name, command, typed_text, user,
               source_host, attack_phase, src_ip, dest_ip, dest_port, protocol
        FROM events
        WHERE {where}
        ORDER BY timestamp_utc
        LIMIT ?
    """, tuple(params + [limit]))

    # Get media start time for this participant using start_timestamp (start_unix unreliable)
    media_start = q("""
        SELECT MIN(start_timestamp) as start_ts
        FROM media_registry
        WHERE participant_id = ?
    """, (participant_id,))
    
    base_offset_ts = media_start[0]['start_ts'] if media_start else None
    base_offset = 0
    if base_offset_ts:
        try:
            iso = base_offset_ts if base_offset_ts.endswith('Z') else base_offset_ts + 'Z'
            base_offset = datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp()
        except Exception:
            base_offset = 0
    
    # Filter and add relative offset
    filtered = []
    for row in rows:
        # Calculate offset from timestamp_utc relative to media start
        offset = 0.0
        try:
            ts_str = row['timestamp_utc']
            if ts_str:
                dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                offset = (dt.timestamp() - base_offset) if base_offset else 0.0
        except Exception:
            offset = 0.0
        
        # Filter by offset range if provided
        if start_offset is not None and offset < start_offset:
            continue
        if end_offset is not None and offset > end_offset:
            continue
            
        row['offset_seconds'] = offset
        filtered.append(row)
    
    return {"events": filtered, "base_offset": base_offset}


@app.get("/api/timeline/playback")
async def timeline_playback(
    participant_id: str,
    offset_seconds: float = 0,
    project_id: str = "",
):
    """Get synchronized playback state at specific offset"""
    # Get all media for participant — use start_timestamp, not start_unix (broken in old data)
    media = q("""
        SELECT media_id, media_type, source_file, start_timestamp, duration_seconds, panel
        FROM media_registry
        WHERE participant_id = ?
        ORDER BY start_timestamp
    """, (participant_id,))
    
    result = {
        "participant_id": participant_id,
        "offset_seconds": offset_seconds,
        "timestamp": None,
        "video": {"available": False},
        "terminal": {"available": False, "commands": []},
        "keylogger": {"available": False, "text": ""},
        "network": {"available": False, "connections": []},
        "logs": {"available": False, "events": []},
        "alerts": {"available": False, "events": []}
    }
    
    if not media:
        return result

    def _iso_epoch(iso: str) -> float:
        s = iso if iso.endswith('Z') else iso + 'Z'
        return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()

    # Calculate absolute timestamp from media[0] start_timestamp
    base_unix = _iso_epoch(media[0]['start_timestamp'])
    result['timestamp'] = base_unix + offset_seconds
    
    for m in media:
        panel = m['panel']
        media_start = _iso_epoch(m['start_timestamp'])
        media_dur = m['duration_seconds'] or 3600
        media_end = media_start + media_dur
        
        if offset_seconds >= (media_start - base_unix) and offset_seconds <= (media_end - base_unix):
            if panel == 'video':
                result['video'] = {
                    "available": True,
                    "media_id": m['media_id'],
                    "source_file": m['source_file'],
                    "seek_to": offset_seconds - (media_start - base_unix)
                }
            elif panel == 'terminal':
                cmd_abs_ts = datetime.fromtimestamp(base_unix + offset_seconds, tz=timezone.utc).replace(tzinfo=None).isoformat()
                cmds = qp(project_id, """
                    SELECT command, timestamp_utc
                    FROM events
                    WHERE source_type = 'terminal_recording'
                    AND source_file = ?
                    AND timestamp_utc <= ?
                    ORDER BY timestamp_utc DESC
                    LIMIT 1
                """, (m['source_file'], cmd_abs_ts))
                result['terminal'] = {
                    "available": True,
                    "media_id": m['media_id'],
                    "current_command": cmds[0]['command'] if cmds else "",
                    "command_timestamp": cmds[0]['timestamp_utc'] if cmds else ""
                }
            elif panel == 'keylogger':
                kd_abs_ts = datetime.fromtimestamp(base_unix + offset_seconds, tz=timezone.utc).replace(tzinfo=None).isoformat()
                kd = qp(project_id, """
                    SELECT typed_text, timestamp_utc
                    FROM events
                    WHERE source_type = 'uat'
                    AND source_file = ?
                    AND timestamp_utc <= ?
                    ORDER BY timestamp_utc DESC
                    LIMIT 1
                """, (m['source_file'], kd_abs_ts))
                result['keylogger'] = {
                    "available": True,
                    "media_id": m['media_id'],
                    "text": kd[0]['typed_text'] if kd else ""
                }
            elif panel == 'network':
                result['network']['available'] = True

    # Get logs at this time
    ts = datetime.fromtimestamp(result['timestamp'], tz=timezone.utc).replace(tzinfo=None).isoformat()
    logs = qp(project_id, """
        SELECT timestamp_utc, source_type, action_name, command
        FROM events
        WHERE participant_id = ?
        AND timestamp_utc <= ?
        ORDER BY timestamp_utc DESC
        LIMIT 10
    """, (participant_id, ts))
    if logs:
        result['logs'] = {"available": True, "events": logs}

    # Get alerts
    alerts = qp(project_id, """
        SELECT timestamp_utc, alert_type, alert_severity, src_ip
        FROM events
        WHERE participant_id = ?
        AND alert_type != '' AND alert_type IS NOT NULL
        AND timestamp_utc <= ?
        ORDER BY timestamp_utc DESC
        LIMIT 5
    """, (participant_id, ts))
    if alerts:
        result['alerts'] = {"available": True, "events": alerts}
    
    return result


@app.get("/api/timeline/phases")
async def timeline_phases(
    participant_id: str,
    buckets: int = 200,
    from_ts: str | None = None,
    to_ts: str | None = None,
    project_id: str = "",
):
    """
    Return a bucketed timeline of event counts per attack_phase.
    Used to render the scrubber heatmap.
    Each bucket covers (total_duration / buckets) seconds.

    from_ts / to_ts (ISO UTC strings) pin the bucket grid to the caller's
    desired time range (e.g. the media span).  Events outside the range are
    ignored; the grid always spans exactly [from_ts, to_ts].
    """
    def parse(ts: str) -> float:
        """Parse an ISO timestamp string as UTC epoch.  Strings without a
        timezone suffix are treated as UTC (not local time)."""
        try:
            s = ts.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            elif "+" not in s and not s.endswith("Z") and len(s) <= 26:
                # naive string — assume UTC
                s = s + "+00:00"
            return datetime.fromisoformat(s).timestamp()
        except Exception:
            return 0.0

    # Build query with optional time filter
    sql = """SELECT timestamp_utc, attack_phase
             FROM events
             WHERE participant_id = ? AND timestamp_utc != '' AND timestamp_utc IS NOT NULL"""
    params: list = [participant_id]
    if from_ts:
        sql += " AND timestamp_utc >= ?"
        params.append(from_ts)
    if to_ts:
        sql += " AND timestamp_utc <= ?"
        params.append(to_ts)
    sql += " ORDER BY timestamp_utc"

    rows = qp(project_id, sql, tuple(params))

    if not rows:
        return {"buckets": [], "start_ts": from_ts, "end_ts": to_ts,
                "start_unix": parse(from_ts) if from_ts else None,
                "end_unix": parse(to_ts) if to_ts else None,
                "duration_seconds": 0}

    # Anchor the bucket grid to the requested range (if given), so the heatmap
    # covers exactly the scrubber span regardless of actual event distribution.
    t0 = parse(from_ts) if from_ts else parse(rows[0]["timestamp_utc"])
    t1 = parse(to_ts)   if to_ts   else parse(rows[-1]["timestamp_utc"])
    if t1 <= t0:
        t1 = t0 + 1
    duration = t1 - t0
    bucket_size = duration / buckets

    # phase → color mapping (Palantir palette)
    PHASE_COLORS = {
        "recon": "#4FC3F7",
        "reconnaissance": "#4FC3F7",
        "initial_access": "#FFB74D",
        "execution": "#FF8A65",
        "persistence": "#A5D6A7",
        "privilege_escalation": "#CE93D8",
        "defense_evasion": "#80CBC4",
        "credential_access": "#F48FB1",
        "discovery": "#B0BEC5",
        "lateral_movement": "#FFCC02",
        "command_and_control": "#EF5350",
        "collection": "#26C6DA",
        "exfiltration": "#FF1744",
        "impact": "#D32F2F",
        "unknown": "#424242",
        "": "#424242",
    }

    # Build bucket array — clip events that fall outside [t0, t1]
    bucket_data: list = [{"idx": i, "start": t0 + i * bucket_size, "phases": {}, "total": 0} for i in range(buckets)]

    for ev in rows:
        t = parse(ev["timestamp_utc"])
        if t < t0 or t > t1:
            continue
        idx = min(int((t - t0) / bucket_size), buckets - 1)
        phase = ev["attack_phase"] or "unknown"
        bucket_data[idx]["phases"][phase] = bucket_data[idx]["phases"].get(phase, 0) + 1
        bucket_data[idx]["total"] += 1

    # Determine dominant phase per bucket
    result = []
    for b in bucket_data:
        dominant = max(b["phases"], key=lambda k: b["phases"][k]) if b["phases"] else "unknown"
        result.append({
            "idx": b["idx"],
            "offset_seconds": round(b["start"] - t0, 2),
            "total": b["total"],
            "dominant_phase": dominant,
            "color": PHASE_COLORS.get(dominant, "#424242"),
            "phases": b["phases"],
        })

    def epoch_to_iso(e: float) -> str:
        return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    return {
        "buckets": result,
        "start_ts": epoch_to_iso(t0),
        "end_ts": epoch_to_iso(t1),
        "start_unix": t0,
        "end_unix": t1,
        "duration_seconds": round(duration, 2),
        "bucket_size_seconds": round(bucket_size, 2),
    }


@app.get("/api/stats/participant")
async def participant_stats(participant_id: str, project_id: str = ""):
    """Summary stats for a participant — counts, top IPs, top hosts, top commands."""
    base_rows = qp(
        project_id,
        """SELECT COUNT(*) total,
                  COUNT(DISTINCT source_host) hosts,
                  COUNT(DISTINCT user) users,
                  COUNT(DISTINCT attack_phase) phases,
                  MIN(NULLIF(timestamp_utc,'')) first_ts,
                  MAX(timestamp_utc) last_ts
           FROM events WHERE participant_id=?""",
        (participant_id,),
    )
    base = base_rows[0] if base_rows else {
        "total": 0, "hosts": 0, "users": 0, "phases": 0,
        "first_ts": None, "last_ts": None,
    }

    source_counts = qp(
        project_id,
        "SELECT source_type, COUNT(*) n FROM events WHERE participant_id=? GROUP BY source_type ORDER BY n DESC",
        (participant_id,),
    )
    phase_counts = qp(
        project_id,
        "SELECT attack_phase, COUNT(*) n FROM events WHERE participant_id=? GROUP BY attack_phase ORDER BY n DESC",
        (participant_id,),
    )
    top_commands = qp(
        project_id,
        """SELECT command, COUNT(*) n FROM events
           WHERE participant_id=? AND command != '' AND command IS NOT NULL
           GROUP BY command ORDER BY n DESC LIMIT 10""",
        (participant_id,),
    )
    top_src_ips = qp(
        project_id,
        """SELECT src_ip, COUNT(*) n FROM events
           WHERE participant_id=? AND src_ip != '' AND src_ip IS NOT NULL
           GROUP BY src_ip ORDER BY n DESC LIMIT 10""",
        (participant_id,),
    )
    top_dest_ips = qp(
        project_id,
        """SELECT dest_ip, COUNT(*) n FROM events
           WHERE participant_id=? AND dest_ip != '' AND dest_ip IS NOT NULL
           GROUP BY dest_ip ORDER BY n DESC LIMIT 10""",
        (participant_id,),
    )
    top_hosts = qp(
        project_id,
        "SELECT source_host, COUNT(*) n FROM events WHERE participant_id=? GROUP BY source_host ORDER BY n DESC LIMIT 10",
        (participant_id,),
    )
    alerts = qp(
        project_id,
        """SELECT alert_type, alert_severity, COUNT(*) n FROM events
           WHERE participant_id=? AND alert_type != '' AND alert_type IS NOT NULL
           GROUP BY alert_type, alert_severity ORDER BY n DESC LIMIT 10""",
        (participant_id,),
    )

    return {
        "participant_id": participant_id,
        "summary": base,
        "source_counts": source_counts,
        "phase_counts": phase_counts,
        "top_commands": top_commands,
        "top_src_ips": top_src_ips,
        "top_dest_ips": top_dest_ips,
        "top_hosts": top_hosts,
        "alerts": alerts,
    }


# ---------------------------------------------------------------------------
# Media endpoints — serve .ogv, .cast, .tsv for synchronized player
# ---------------------------------------------------------------------------


@app.get("/api/media/cast_raw/{media_id}")
async def media_cast_raw(media_id: str):
    """Serve the raw .cast file directly for asciinema-player."""
    rows = q(
        "SELECT source_file FROM media_registry WHERE media_id = ?",
        (media_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Media not found")
    path = Path(rows[0]["source_file"])
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Cast file not found: {path}")
    return FileResponse(str(path), media_type="text/plain", headers={
        "Cache-Control": "no-cache",
        "Access-Control-Allow-Origin": "*",
    })


@app.get("/api/media/stream/{media_id}")
async def media_stream(media_id: str, request: Request):
    """Stream any media file (video, cast, etc.) with Range support."""
    rows = q(
        "SELECT source_file, media_type FROM media_registry WHERE media_id = ?",
        (media_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Media not found")
    path = Path(rows[0]["source_file"])
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    media_type = "video/ogg" if rows[0]["media_type"] == "video" else "application/octet-stream"
    return FileResponse(str(path), media_type=media_type, headers={
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-cache",
    })


@app.get("/api/media/list")
async def media_list(participant_id: str, project_id: str = ""):
    """Return all media registry entries for a participant."""
    conds = ["participant_id = ?"]
    params: list = [participant_id]
    if project_id:
        conds.append("project_id = ?")
        params.append(project_id)
    rows = q(
        f"SELECT media_id, participant_id, source_host, media_type, start_timestamp, end_timestamp, duration_seconds, panel FROM media_registry WHERE {' AND '.join(conds)} ORDER BY start_timestamp",
        tuple(params),
    )
    return {"media": rows}


@app.get("/api/media/video/{participant_id}")
async def media_video(participant_id: str, t: float = 0.0):
    """Stream video with browser-compatible codec. Prefers pre-transcoded .webm; otherwise
    stream-transcodes OGV/Theora → VP8 WebM via ffmpeg (Chrome/Edge dropped Theora support).
    The ?t= parameter seeks to a specific second offset before streaming starts."""
    rows = q(
        "SELECT source_file FROM media_registry WHERE participant_id = ? AND media_type = 'video' LIMIT 1",
        (participant_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="No video found for participant")
    path = Path(rows[0]["source_file"])

    # Prefer pre-transcoded .webm — supports full native seeking
    webm_path = path.with_suffix(".webm")
    if webm_path.exists():
        return FileResponse(str(webm_path), media_type="video/webm", headers={
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-cache",
        })

    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Video file not found: {path}")

    # Native .webm — serve directly
    if path.suffix.lower() == ".webm":
        return FileResponse(str(path), media_type="video/webm", headers={
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-cache",
        })

    # OGV/Theora: transcode on-the-fly to VP8 WebM so Chrome/Edge can play it.
    # -ss before -i enables fast stream seek (key-frame seek in Theora).
    # -deadline realtime / -cpu-used 8 trades quality for real-time throughput.
    seek_offset = max(0.0, t)

    async def transcode_stream():
        cmd = [
            "ffmpeg",
            "-ss", str(seek_offset),
            "-i", str(path),
            "-c:v", "libvpx",
            "-deadline", "realtime",
            "-cpu-used", "8",
            "-b:v", "800k",
            "-c:a", "libvorbis",
            "-b:a", "96k",
            "-f", "webm",
            "pipe:1",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            try:
                proc.kill()
            except Exception:
                pass
            await proc.wait()

    return StreamingResponse(
        transcode_stream(),
        media_type="video/webm",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/media/cast")
async def media_cast(participant_id: str, media_id: Optional[str] = None):
    """Return a .cast file as JSON {header, frames:[offset, type, data]}."""
    if media_id:
        rows = q(
            "SELECT source_file, start_unix FROM media_registry WHERE media_id = ? AND participant_id = ?",
            (media_id, participant_id),
        )
    else:
        rows = q(
            "SELECT source_file, start_unix FROM media_registry WHERE participant_id = ? AND media_type = 'terminal' ORDER BY start_timestamp LIMIT 1",
            (participant_id,),
        )
    if not rows:
        raise HTTPException(status_code=404, detail="No cast file found")
    path = Path(rows[0]["source_file"])
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Cast file not found: {path}")

    frames = []
    header = {}
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if i == 0:
                header = parsed
            else:
                frames.append(parsed)

    return {
        "media_id": media_id,
        "source_file": str(path),
        "start_unix": rows[0]["start_unix"],
        "header": header,
        "frames": frames,
    }


@app.get("/api/media/cast_list")
async def media_cast_list(participant_id: str):
    """Return list of all cast files for participant (id, filename, start_unix, duration)."""
    rows = q(
        """SELECT media_id, source_file, start_timestamp, start_unix, duration_seconds
           FROM media_registry
           WHERE participant_id = ? AND media_type = 'terminal'
           ORDER BY start_timestamp""",
        (participant_id,),
    )
    result = []
    for r in rows:
        result.append({
            "media_id": r["media_id"],
            "filename": Path(r["source_file"]).name,
            "start_timestamp": r["start_timestamp"],
            "start_unix": r["start_unix"],
            "duration_seconds": r["duration_seconds"],
        })
    return {"casts": result}


@app.get("/api/media/keylogger")
async def media_keylogger(
    participant_id: str,
    from_ts: Optional[float] = None,
    to_ts: Optional[float] = None,
    limit: int = 500,
):
    """Parse the .tsv keylogger file and return rows in the given unix-ms window."""
    rows = q(
        "SELECT source_file FROM media_registry WHERE participant_id = ? AND media_type = 'keylogger' LIMIT 1",
        (participant_id,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="No keylogger file found")
    path = Path(rows[0]["source_file"])
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Keylogger file not found: {path}")

    events = []
    with open(path, "r", errors="replace") as f:
        reader = csv.reader(f, delimiter="\t")
        for row in reader:
            if len(row) < 6:
                continue
            try:
                ts_ms = float(row[0])
            except ValueError:
                continue
            ts_s = ts_ms / 1000.0
            if from_ts is not None and ts_s < from_ts:
                continue
            if to_ts is not None and ts_s > to_ts:
                continue
            events.append({
                "ts_ms": ts_ms,
                "ts_unix": ts_s,
                "window_id": row[1] if len(row) > 1 else "",
                "app_name": row[2] if len(row) > 2 else "",
                "window_title": row[3] if len(row) > 3 else "",
                "event_type": row[4] if len(row) > 4 else "",
                "key_info": row[5] if len(row) > 5 else "",
                "app_name2": row[6] if len(row) > 6 else "",
            })
            if len(events) >= limit:
                break

    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    index = FRONTEND_PATH / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text())
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


@app.get("/timeline")
async def timeline():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/threat", status_code=301)


@app.get("/threat", response_class=HTMLResponse)
async def threat():
    f = FRONTEND_PATH / "palantir.html"
    if f.exists():
        return HTMLResponse(content=f.read_text())
    return HTMLResponse("<h1>palantir.html not found</h1>", status_code=404)


@app.get("/favicon.ico")
async def favicon():
    """Return a minimal transparent 1x1 favicon to suppress 404s."""
    import base64
    # Minimal 1x1 transparent ICO (46 bytes)
    ico_b64 = (
        "AAABAAEAAQEAAAEAGAAoAAAAFgAAACgAAAABAAAAAgAAAAEAGAAAAAAA"
        "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8AAAA="
    )
    ico_bytes = base64.b64decode(ico_b64)
    from fastapi.responses import Response
    return Response(content=ico_bytes, media_type="image/x-icon")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
