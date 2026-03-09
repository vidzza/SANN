#!/usr/bin/env python3
"""
GOD EYE - Dataset Import Manager
=================================
Run this after every ingest (or instead of raw ingest_v2.py) to ensure:
  1. media_registry is rebuilt correctly from filesystem
  2. Suricata timestamps are converted from local-tz to UTC
  3. syslog/auth timestamps use the correct year (inferred from cast headers)
  4. Post-import validation confirms all panels have data in expected windows

Usage:
    python3 import_manager.py [--data-root PATH] [--db PATH] [--skip-ingest]

    --skip-ingest   Skip running ingest_v2.py (use existing DB, just fix + validate)
"""

import argparse
import json
import logging
import re
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('import_manager')

# Rutas configurables via variables de entorno o .env
def _load_env_file():
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, _, v = line.partition('=')
                import os
                os.environ.setdefault(k.strip(), v.strip())

_load_env_file()

import os as _os
_REPO_ROOT = Path(__file__).parent
DB_PATH    = Path(_os.environ.get('GODEYE_DB_PATH',
                  str(_REPO_ROOT / 'data' / 'godeye_v2.db')))
DATA_ROOT  = Path(_os.environ.get('GODEYE_DATA_ROOT', '/tmp/obsidian_full/P003'))
INGEST_SCRIPT = _REPO_ROOT / 'ingest_v2.py'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def unix_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')

def iso_to_unix(s: str) -> float:
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    elif '+' not in s and len(s) >= 19:
        s += '+00:00'
    return datetime.fromisoformat(s).timestamp()

def get_cast_header_ts(cast_file: Path) -> float | None:
    """Return the unix timestamp from a .cast file header."""
    try:
        with open(cast_file, 'r', errors='ignore') as f:
            header = json.loads(f.readline())
        return float(header.get('timestamp', 0)) or None
    except Exception:
        return None

def get_video_duration(webm: Path) -> float | None:
    """Return duration of a webm file via ffprobe."""
    try:
        result = subprocess.run(
            ['ffprobe', '-v', 'quiet', '-print_format', 'json',
             '-show_format', str(webm)],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        return float(data['format']['duration'])
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Step 1 — Run ingest_v2.py
# ---------------------------------------------------------------------------

def run_ingest(data_root: Path, db_path: Path):
    log.info("Running ingest_v2.py ...")
    result = subprocess.run(
        [sys.executable, str(INGEST_SCRIPT)],
        timeout=600
    )
    if result.returncode != 0:
        raise RuntimeError(f"ingest_v2.py exited with code {result.returncode}")
    log.info("Ingest complete.")

# ---------------------------------------------------------------------------
# Step 2 — Fix suricata timestamps (local-tz → UTC)
# ---------------------------------------------------------------------------

def fix_suricata_timestamps(con: sqlite3.Connection, data_root: Path):
    """
    Detect and fix suricata eve.json timestamps that were stored as local time.

    The ingest script calls:
        datetime.fromisoformat(ts_raw.replace('Z', '+00:00')).replace(tzinfo=None).isoformat()
    This converts aware datetime to naive BUT correctly in Python — fromisoformat
    preserves the offset, then .replace(tzinfo=None) just strips it, leaving UTC.

    HOWEVER: Python < 3.11 fromisoformat() does NOT parse '-0400' offset notation
    (only '+HH:MM' form). Timestamps like '2025-08-15T11:25:23.826914-0400' will
    FAIL fromisoformat in Python < 3.11 and fall through to the bare ts_raw string.

    We detect this by checking whether stored suricata timestamps fall outside the
    expected UTC window for a participant (determined from cast headers), then
    compute and apply the correct UTC offset.
    """
    log.info("Checking suricata timestamps ...")

    participants = [r[0] for r in con.execute(
        "SELECT DISTINCT participant_id FROM events WHERE source_type='suricata' "
        "AND participant_id NOT LIKE '%.%' AND participant_id != ''"
    )]

    for pid in participants:
        # Get expected UTC window from cast files
        cast_files = list((data_root / pid).rglob('*.cast'))
        if not cast_files:
            log.warning(f"  {pid}: no cast files found, skipping suricata fix")
            continue

        cast_starts = [get_cast_header_ts(c) for c in cast_files]
        cast_starts = [t for t in cast_starts if t]
        if not cast_starts:
            continue

        expected_start_utc = min(cast_starts)
        expected_end_utc   = max(cast_starts) + 86400  # generous upper bound

        # Check actual stored suricata range
        row = con.execute(
            "SELECT MIN(timestamp_utc), MAX(timestamp_utc), COUNT(*) "
            "FROM events WHERE participant_id=? AND source_type='suricata'",
            (pid,)
        ).fetchone()

        if not row or not row[0]:
            log.info(f"  {pid}: no suricata events")
            continue

        stored_min = iso_to_unix(row[0])
        stored_max = iso_to_unix(row[1])
        count = row[2]

        log.info(f"  {pid}: {count} suricata events  stored={row[0]}..{row[1]}")

        # Are stored timestamps within expected window?
        if stored_min >= expected_start_utc - 86400 and stored_max <= expected_end_utc:
            log.info(f"  {pid}: suricata timestamps look correct, no fix needed")
            continue

        # Detect offset from raw eve.json files
        eve_files = list(data_root.rglob(f'{pid}/**/eve.json'))
        if not eve_files:
            log.warning(f"  {pid}: cannot find eve.json to detect offset")
            continue

        detected_offset_hours = None
        with open(eve_files[0], 'r', errors='ignore') as f:
            for line in f:
                try:
                    ts_raw = json.loads(line.strip()).get('timestamp', '')
                    if not ts_raw:
                        continue
                    # Try to parse with Python 3.11+ fromisoformat or manual parse
                    # Detect offset suffix like -0400 or +0530
                    m = re.search(r'([+-])(\d{2}):?(\d{2})$', ts_raw)
                    if m:
                        sign = 1 if m.group(1) == '+' else -1
                        h = int(m.group(2))
                        mn = int(m.group(3))
                        offset_seconds = sign * (h * 3600 + mn * 60)
                        detected_offset_hours = -offset_seconds / 3600  # correction needed
                        break
                    elif ts_raw.endswith('Z'):
                        detected_offset_hours = 0
                        break
                except Exception:
                    continue

        if detected_offset_hours is None:
            log.warning(f"  {pid}: could not detect timezone offset from eve.json")
            continue

        if detected_offset_hours == 0:
            log.info(f"  {pid}: eve.json timestamps are UTC, no fix needed")
            continue

        log.info(f"  {pid}: applying {detected_offset_hours:+.1f}h correction to {count} suricata rows ...")
        sign = '+' if detected_offset_hours >= 0 else '-'
        abs_h = int(abs(detected_offset_hours))
        abs_m = int((abs(detected_offset_hours) % 1) * 60)
        interval = f"{sign}{abs_h} hours"
        if abs_m:
            interval += f", {sign}{abs_m} minutes"

        con.execute(
            f"""UPDATE events
               SET timestamp_utc = strftime('%Y-%m-%dT%H:%M:%f',
                                   datetime(timestamp_utc, '{sign}{abs_h} hours'))
               WHERE participant_id=? AND source_type='suricata'""",
            (pid,)
        )
        con.commit()

        # Verify
        row2 = con.execute(
            "SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM events "
            "WHERE participant_id=? AND source_type='suricata'", (pid,)
        ).fetchone()
        log.info(f"  {pid}: suricata after fix: {row2[0]} .. {row2[1]}")

# ---------------------------------------------------------------------------
# Step 3 — Rebuild media_registry
# ---------------------------------------------------------------------------

def rebuild_media_registry(con: sqlite3.Connection, data_root: Path):
    """
    Auto-detect all media (video + cast) from filesystem and rebuild
    media_registry. Derives start_timestamp from:
      - .cast files: header 'timestamp' field (authoritative unix epoch)
      - .webm files: ffprobe duration + cast header for start time
    """
    log.info("Rebuilding media_registry ...")

    con.execute("""
        CREATE TABLE IF NOT EXISTS media_registry (
            media_id        TEXT PRIMARY KEY,
            participant_id  TEXT,
            scenario_name   TEXT,
            media_type      TEXT,
            source_file     TEXT,
            source_host     TEXT,
            start_timestamp TEXT,
            start_unix      REAL,
            end_timestamp   TEXT,
            end_unix        REAL,
            duration_seconds REAL,
            panel           TEXT
        )
    """)
    con.execute("DELETE FROM media_registry")
    con.commit()

    rows = []

    # Find all participants from DB
    participants = con.execute(
        "SELECT DISTINCT participant_id, scenario_name FROM events "
        "WHERE participant_id NOT LIKE '%.%' AND participant_id != ''"
    ).fetchall()

    for pid, scenario in participants:
        pid_dir = data_root / pid
        if not pid_dir.exists():
            log.warning(f"  {pid}: directory not found at {pid_dir}")
            continue

        # ---- Cast files ----
        cast_files = sorted(pid_dir.rglob('*.cast'))
        cast_entries = []
        for c in cast_files:
            ts = get_cast_header_ts(c)
            if not ts:
                log.warning(f"  {pid}: could not read cast header: {c.name}")
                continue
            # Duration from last frame offset in cast
            dur = _cast_duration(c)
            host = c.parent.name
            cast_entries.append((c, ts, dur, host))

        # ---- Video file ----
        # webm preferred over ogv
        webm_files = list(pid_dir.rglob('recording.webm'))
        ogv_files  = list(pid_dir.rglob('recording.ogv'))
        video_file = webm_files[0] if webm_files else (ogv_files[0] if ogv_files else None)

        if video_file:
            # Video start = earliest cast start (they start together)
            if cast_entries:
                video_start_unix = min(e[1] for e in cast_entries)
            else:
                video_start_unix = video_file.stat().st_mtime
                log.warning(f"  {pid}: no casts found, using file mtime for video start")

            video_dur = get_video_duration(video_file)
            if video_dur is None:
                log.warning(f"  {pid}: ffprobe failed, estimating duration from casts")
                if cast_entries:
                    last = max(cast_entries, key=lambda e: e[1] + e[2])
                    video_dur = (last[1] + last[2]) - video_start_unix
                else:
                    video_dur = 0

            # Stable media_id: hash of participant + media_type
            media_id = _stable_id(pid + ':video')
            rows.append({
                'media_id':        media_id,
                'participant_id':  pid,
                'scenario_name':   scenario,
                'media_type':      'video',
                'source_file':     str(video_file),
                'source_host':     video_file.parent.name,
                'start_timestamp': unix_to_iso(video_start_unix),
                'start_unix':      video_start_unix,
                'end_timestamp':   unix_to_iso(video_start_unix + video_dur),
                'end_unix':        video_start_unix + video_dur,
                'duration_seconds': video_dur,
                'panel':           'video',
            })
            log.info(f"  {pid}: video {unix_to_iso(video_start_unix)}  dur={video_dur:.0f}s")

        # ---- Cast rows ----
        for c, ts, dur, host in cast_entries:
            media_id = _stable_id(pid + ':cast:' + c.name)
            rows.append({
                'media_id':        media_id,
                'participant_id':  pid,
                'scenario_name':   scenario,
                'media_type':      'terminal',
                'source_file':     str(c),
                'source_host':     host,
                'start_timestamp': unix_to_iso(ts),
                'start_unix':      ts,
                'end_timestamp':   unix_to_iso(ts + dur),
                'end_unix':        ts + dur,
                'duration_seconds': dur,
                'panel':           'terminal',
            })
            log.info(f"  {pid}: cast  {c.name}  {unix_to_iso(ts)}  dur={dur:.0f}s")

    con.executemany("""
        INSERT OR REPLACE INTO media_registry
        (media_id, participant_id, scenario_name, media_type, source_file, source_host,
         start_timestamp, start_unix, end_timestamp, end_unix, duration_seconds, panel)
        VALUES (:media_id, :participant_id, :scenario_name, :media_type, :source_file,
                :source_host, :start_timestamp, :start_unix, :end_timestamp, :end_unix,
                :duration_seconds, :panel)
    """, rows)
    con.commit()
    log.info(f"media_registry: inserted {len(rows)} rows")
    return rows


def _cast_duration(cast_file: Path) -> float:
    """Return duration in seconds from last frame timestamp in cast file."""
    last_ts = 0.0
    try:
        with open(cast_file, 'r', errors='ignore') as f:
            next(f)  # skip header
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    frame = json.loads(line)
                    if isinstance(frame, list) and len(frame) >= 1:
                        t = float(frame[0])
                        if t > last_ts:
                            last_ts = t
                except Exception:
                    continue
    except Exception:
        pass
    return last_ts


def _stable_id(seed: str) -> str:
    """Generate a stable 8-char hex ID from a seed string."""
    import hashlib
    return hashlib.sha1(seed.encode()).hexdigest()[:8]

# ---------------------------------------------------------------------------
# Step 4 — Fix syslog/auth year inference
# ---------------------------------------------------------------------------

def fix_syslog_years(con: sqlite3.Connection, data_root: Path):
    """
    syslog/auth.log timestamps are 'Aug 15 HH:MM:SS' — no year.
    ingest_v2.py uses file mtime year which can be wrong if files are copied.
    We verify by checking whether stored timestamps fall within ±1 day of
    the cast-derived session start, and fix if not.
    """
    log.info("Checking syslog/auth year ...")

    participants = [r[0] for r in con.execute(
        "SELECT DISTINCT participant_id FROM events "
        "WHERE source_type IN ('syslog','auth') AND participant_id NOT LIKE '%.%' AND participant_id != ''"
    )]

    for pid in participants:
        cast_files = list((data_root / pid).rglob('*.cast'))
        cast_starts = [get_cast_header_ts(c) for c in cast_files]
        cast_starts = [t for t in cast_starts if t]
        if not cast_starts:
            continue

        expected_start = datetime.fromtimestamp(min(cast_starts), tz=timezone.utc)
        expected_year  = expected_start.year

        row = con.execute(
            "SELECT MIN(timestamp_utc) FROM events "
            "WHERE participant_id=? AND source_type='syslog'", (pid,)
        ).fetchone()
        if not row or not row[0]:
            continue

        stored_year = int(row[0][:4])
        if stored_year == expected_year:
            log.info(f"  {pid}: syslog year={stored_year} correct")
            continue

        diff_years = expected_year - stored_year
        log.info(f"  {pid}: syslog year mismatch stored={stored_year} expected={expected_year}, fixing {diff_years:+d} year(s)")

        for src in ('syslog', 'auth'):
            count = con.execute(
                "SELECT COUNT(*) FROM events WHERE participant_id=? AND source_type=?",
                (pid, src)
            ).fetchone()[0]
            if count == 0:
                continue
            con.execute(
                f"""UPDATE events
                    SET timestamp_utc = substr(timestamp_utc, 1, 0) ||
                        CAST(CAST(substr(timestamp_utc, 1, 4) AS INTEGER) + ? AS TEXT) ||
                        substr(timestamp_utc, 5)
                    WHERE participant_id=? AND source_type=?""",
                (diff_years, pid, src)
            )
            log.info(f"  {pid}: fixed {count} {src} rows")

    con.commit()

# ---------------------------------------------------------------------------
# Step 5 — Validate
# ---------------------------------------------------------------------------

PANEL_SOURCES = {
    'terminal': 'terminal_recording',
    'auth':     'auth',
    'syslog':   'syslog',
    'network':  'suricata,bt_jsonl',
    'keylogger':'uat',
    'pcap':     'zeek,sensor',
}

def validate(con: sqlite3.Connection) -> bool:
    """
    For each participant with a video entry in media_registry, verify that
    at least some panel source types have events within the video window.
    Returns True if all participants pass minimum bar.
    """
    log.info("Running validation ...")
    ok = True

    videos = con.execute(
        "SELECT participant_id, start_timestamp, end_timestamp, duration_seconds "
        "FROM media_registry WHERE media_type='video' AND participant_id NOT LIKE '%.%' AND participant_id != ''"
    ).fetchall()

    if not videos:
        log.error("FAIL: no video entries in media_registry")
        return False

    for pid, start_ts, end_ts, dur in videos:
        log.info(f"\n  {pid}  video: {start_ts} → {end_ts}  ({dur:.0f}s)")
        panel_ok = 0

        for panel, sources in PANEL_SOURCES.items():
            src_list = sources.split(',')
            placeholders = ','.join('?' * len(src_list))
            # Check first 10 minutes of video
            window_end_unix = iso_to_unix(start_ts) + 600
            window_end_ts   = unix_to_iso(window_end_unix)

            count = con.execute(
                f"SELECT COUNT(*) FROM events "
                f"WHERE participant_id=? AND source_type IN ({placeholders}) "
                f"AND timestamp_utc >= ? AND timestamp_utc <= ?",
                [pid] + src_list + [start_ts, window_end_ts]
            ).fetchone()[0]

            status = 'OK' if count > 0 else 'EMPTY'
            if count > 0:
                panel_ok += 1
            log.info(f"    {panel:12s} ({sources:30s}): {count:5d} events  [{status}]")

        # Pass = at least 2 panels have data (some participants lack network/zeek)
        if panel_ok < 2:
            log.error(f"  FAIL: {pid} only {panel_ok}/6 panels have data in video window")
            ok = False
        else:
            log.info(f"  PASS: {pid} {panel_ok}/6 panels have data")

    # Cross-check: terminal events should start within 60s of video start
    log.info("\n  Checking cast/video alignment ...")
    for pid, start_ts, end_ts, dur in videos:
        video_start = iso_to_unix(start_ts)
        first_terminal = con.execute(
            "SELECT MIN(timestamp_utc) FROM events "
            "WHERE participant_id=? AND source_type='terminal_recording'", (pid,)
        ).fetchone()[0]
        if first_terminal:
            delta = abs(iso_to_unix(first_terminal) - video_start)
            status = 'OK' if delta < 120 else 'WARN'
            log.info(f"    {pid}: first terminal event {delta:.0f}s from video start  [{status}]")
            if delta > 300:
                log.warning(f"    {pid}: terminal events may not align with video (delta={delta:.0f}s)")

    return ok

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='GOD EYE Dataset Import Manager')
    parser.add_argument('--data-root', type=Path, default=DATA_ROOT)
    parser.add_argument('--db',        type=Path, default=DB_PATH)
    parser.add_argument('--skip-ingest', action='store_true',
                        help='Skip ingest_v2.py, just fix and validate existing DB')
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("GOD EYE Import Manager")
    log.info(f"  data-root : {args.data_root}")
    log.info(f"  db        : {args.db}")
    log.info("=" * 60)

    # Step 1 — Ingest
    if not args.skip_ingest:
        run_ingest(args.data_root, args.db)
    else:
        log.info("Skipping ingest (--skip-ingest)")

    con = sqlite3.connect(str(args.db))
    con.row_factory = sqlite3.Row

    # Step 2 — Fix suricata TZ
    fix_suricata_timestamps(con, args.data_root)

    # Step 3 — Rebuild media_registry
    rebuild_media_registry(con, args.data_root)

    # Step 4 — Fix syslog/auth year
    fix_syslog_years(con, args.data_root)

    # Step 5 — Validate
    passed = validate(con)

    con.close()

    log.info("=" * 60)
    if passed:
        log.info("Import complete — ALL CHECKS PASSED")
    else:
        log.error("Import complete — SOME CHECKS FAILED (see above)")
        sys.exit(1)


if __name__ == '__main__':
    main()
